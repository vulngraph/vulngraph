package aws

import (
	"context"
	"slices"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

// This file holds the per-bucket reads the exposure grade shares (the
// bucket's own Block Public Access, its policy document, its object ownership
// and ACL — each read once and handed to every grade that needs it) and the
// grades built on them: public read vs public write (FSBP S3.2/S3.3), the
// bucket-level block (S3.8), ACL use (S3.12) and lifecycle rules (S3.13).

const (
	s3AllUsersURI      = "http://acs.amazonaws.com/groups/global/AllUsers"
	s3AuthenticatedURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// s3PublicReadActions / s3PublicWriteActions classify what a public bucket
// policy grant lets anyone do: read (list or fetch objects) or write
// (create, overwrite or delete objects, or rewrite who may access them).
var (
	s3PublicReadActions  = []string{"s3:getobject", "s3:getobjectversion", "s3:listbucket", "s3:listbucketversions"}
	s3PublicWriteActions = []string{
		"s3:putobject", "s3:deleteobject", "s3:deleteobjectversion", "s3:putobjectacl", "s3:putobjectversionacl",
		"s3:putbucketpolicy", "s3:deletebucketpolicy", "s3:putbucketacl", "s3:deletebucket",
	}
)

// bucketBlock is the bucket's OWN Block Public Access configuration. observed
// is true for a read answer and for NoSuchPublicAccessBlockConfiguration (no
// block: cfg nil).
type bucketBlock struct {
	cfg      *s3types.PublicAccessBlockConfiguration
	observed bool
}

func readBucketBlock(ctx context.Context, client s3API, bucket string, opt func(*s3.Options)) bucketBlock {
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: awssdk.String(bucket)}, opt)
	if err != nil {
		return bucketBlock{observed: isNoPublicAccessBlockErr(err)}
	}
	if out == nil {
		return bucketBlock{observed: true}
	}
	return bucketBlock{cfg: out.PublicAccessBlockConfiguration, observed: true}
}

// allEnabled is the S3.8 verdict on the bucket's own four flags, "" unread.
func (b bucketBlock) allEnabled() string {
	if !b.observed {
		return ""
	}
	return strconv.FormatBool(b.cfg != nil && fullyBlocked(b.cfg))
}

// bucketPolicyDoc is the bucket policy document; NoSuchBucketPolicy is an
// observed empty document.
type bucketPolicyDoc struct {
	doc      string
	observed bool
}

func readBucketPolicy(ctx context.Context, client s3API, bucket string, opt func(*s3.Options)) bucketPolicyDoc {
	out, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: awssdk.String(bucket)}, opt)
	switch {
	case err == nil && out != nil:
		return bucketPolicyDoc{doc: awssdk.ToString(out.Policy), observed: true}
	case err != nil && awsErrCode(err) == "NoSuchBucketPolicy":
		return bucketPolicyDoc{observed: true}
	}
	return bucketPolicyDoc{}
}

// bucketACL is the bucket's object ownership setting and ACL. With
// BucketOwnerEnforced, ACLs are disabled and carry no access at all, so the
// ACL itself is not read.
type bucketACL struct {
	ownership         string // ObjectOwnership; "" when no ownership controls are set
	ownershipObserved bool
	grants            []s3types.Grant
	ownerID           string
	aclObserved       bool
}

func readBucketACL(ctx context.Context, client s3API, bucket string, opt func(*s3.Options)) bucketACL {
	var b bucketACL
	oc, err := client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: awssdk.String(bucket)}, opt)
	switch {
	case err == nil && oc != nil:
		b.ownershipObserved = true
		if oc.OwnershipControls != nil && len(oc.OwnershipControls.Rules) > 0 {
			b.ownership = string(oc.OwnershipControls.Rules[0].ObjectOwnership)
		}
	case err != nil && awsErrCode(err) == "OwnershipControlsNotFoundError":
		// No controls at all: the pre-2023 default, ACLs enabled.
		b.ownershipObserved = true
	}
	if b.aclsDisabled() {
		b.aclObserved = true
		return b
	}
	acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: awssdk.String(bucket)}, opt)
	if err != nil || acl == nil {
		return b
	}
	b.aclObserved = true
	b.grants = acl.Grants
	if acl.Owner != nil {
		b.ownerID = awssdk.ToString(acl.Owner.ID)
	}
	return b
}

func (b bucketACL) aclsDisabled() bool {
	return b.ownership == string(s3types.ObjectOwnershipBucketOwnerEnforced)
}

func isPublicGrantee(g s3types.Grant) bool {
	if g.Grantee == nil {
		return false
	}
	switch awssdk.ToString(g.Grantee.URI) {
	case s3AllUsersURI, s3AuthenticatedURI:
		return true
	}
	return false
}

// hasPublicGrantee reports any grant, of any permission, to AllUsers or
// AuthenticatedUsers (any AWS account): the confirmed-public ACL tier.
func (b bucketACL) hasPublicGrantee() bool {
	return slices.ContainsFunc(b.grants, isPublicGrantee)
}

// publicGrants reports which public permissions the ACL hands AllUsers or
// AuthenticatedUsers, as read / write. READ_ACP only discloses the ACL.
func (b bucketACL) publicGrants() (read, write bool) {
	for _, g := range b.grants {
		if !isPublicGrantee(g) {
			continue
		}
		switch g.Permission {
		case s3types.PermissionRead:
			read = true
		case s3types.PermissionWrite, s3types.PermissionWriteAcp:
			write = true
		case s3types.PermissionFullControl:
			read, write = true, true
		}
	}
	return read, write
}

// nonOwnerGrants counts ACL grants to anyone but the bucket owner: the "ACL
// used for user access" FSBP S3.12 fails. "" when the ACL was not read.
func (b bucketACL) nonOwnerGrants() string {
	if !b.aclObserved || !b.ownershipObserved {
		return ""
	}
	n := 0
	for _, g := range b.grants {
		if g.Grantee == nil {
			continue
		}
		if g.Grantee.Type == s3types.TypeCanonicalUser && b.ownerID != "" && awssdk.ToString(g.Grantee.ID) == b.ownerID {
			continue
		}
		n++
	}
	return strconv.Itoa(n)
}

// policyPublicGrants classifies a policy AWS reports as public into read /
// write grants to an open-ended principal set (reachesAnyone) that no
// unconditional Deny takes back. Unconditioned statements are read first.
// Only when none of them grants a data action are conditioned ones counted —
// AWS called the policy public on a condition it does not consider
// restricting (e.g. aws:UserAgent) — and then only those whose condition
// names no restricting key (aws:SourceVpc, aws:PrincipalOrgID, …): a
// VPC-scoped GetObject beside a public GetBucketAcl is not public read.
// known is false when neither pass finds a data grant: the public part of
// the policy is something the split cannot name, and the bucket stays with
// aws-s3-public-bucket.
func policyPublicGrants(doc string) (read, write, known bool) {
	stmts := resourcePolicyStatements(doc)
	grants := func(include func(resourcePolicyStatement) bool) (r, w bool) {
		for _, s := range stmts {
			if !strings.EqualFold(s.Effect, "Allow") || !s.reachesAnyone() || !include(s) {
				continue
			}
			for _, a := range s.grantedActions(s3PublicReadActions) {
				if !resourceActionDenied(stmts, a) {
					r = true
				}
			}
			for _, a := range s.grantedActions(s3PublicWriteActions) {
				if !resourceActionDenied(stmts, a) {
					w = true
				}
			}
		}
		return r, w
	}
	if read, write = grants(func(s resourcePolicyStatement) bool { return !awspolicy.HasCondition(s.Condition) }); read || write {
		return read, write, true
	}
	read, write = grants(func(s resourcePolicyStatement) bool {
		return awspolicy.HasCondition(s.Condition) && !awspolicy.RestrictsCaller(s.Condition)
	})
	return read, write, read || write
}

// bucketLifecycleRules counts the bucket's enabled lifecycle rules (FSBP
// S3.13). NoSuchLifecycleConfiguration is an observed zero; any other error
// is unknown.
func bucketLifecycleRules(ctx context.Context, client s3API, bucket string, opt func(*s3.Options)) (string, bool) {
	return lifecycleRuleCount(client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: awssdk.String(bucket)}, opt))
}

// lifecycleRuleCount is one GetBucketLifecycleConfiguration answer as an
// enabled-rule count; the bool is false when nothing was observed.
func lifecycleRuleCount(out *s3.GetBucketLifecycleConfigurationOutput, err error) (string, bool) {
	if err != nil {
		return "0", awsErrCode(err) == "NoSuchLifecycleConfiguration"
	}
	if out == nil {
		return "", false
	}
	n := 0
	for _, r := range out.Rules {
		if r.Status == s3types.ExpirationStatusEnabled {
			n++
		}
	}
	return strconv.Itoa(n), true
}
