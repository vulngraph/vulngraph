package correlate

import (
	"iter"
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// EdgeHasRole is the edge type linking an EC2 instance to the IAM role it runs
// as via its instance profile. Blast-radius BFS traverses this to answer "what
// can an attacker do if they compromise this instance?".
const EdgeHasRole = "has_role"

// EC2InstanceProfile links each EC2 instance to the IAM role inside its
// instance profile. The collector resolves the profile's actual role from the
// profile's role list (iam:ListInstanceProfiles) and stamps
// Metadata["iam_role_arn"]; that is the only source used.
//
// There is deliberately no fallback that derives the role ARN from the profile
// ARN: the profile name matches the role name only when both were created
// together (the console default). Terraform, CDK and eksctl commonly name them
// differently, so the guess either finds nothing or — worse — finds an
// unrelated role that happens to share the profile's name. When the collector
// could not resolve the profile (it omits iam_role_arn), the role is unknown
// and no edge is emitted.
type EC2InstanceProfile struct{}

func (EC2InstanceProfile) Name() string { return "ec2_instance_profile" }

func (EC2InstanceProfile) InterestedIn() []string {
	return []string{"ec2_instance", "iam_role"}
}

func (r EC2InstanceProfile) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (EC2InstanceProfile) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {

		// Role membership is checked once per instance against a set built once per
		// run, rather than scanning IAMRoles() per instance (O(instances × roles)).
		roleIDs := make(map[string]struct{}, len(g.IAMRoles()))
		for _, role := range g.IAMRoles() {
			roleIDs[role.ID] = struct{}{}
		}
		// Use ALL EC2 instances — private instances carry instance profiles too, and
		// an attacker inside the VPC (or via assumed role) can reach them.
		for _, inst := range g.AllEC2Instances() {
			roleARN := inst.Metadata["iam_role_arn"]
			if roleARN == "" {
				continue
			}
			// Only emit the edge if the role is actually in our inventory — avoids
			// dangling stubs for roles in accounts we haven't synced yet.
			if _, ok := roleIDs[roleARN]; !ok {
				continue
			}
			if !yield(asset.Edge{
				SrcID: inst.ID, SrcType: "ec2_instance",
				DstID: roleARN, DstType: "iam_role",
				EdgeType: EdgeHasRole,
				Properties: map[string]string{
					"origin": edgeOrigin,
					"rule":   "ec2_instance_profile",
				},
			}) {
				return
			}
		}
	}
}
