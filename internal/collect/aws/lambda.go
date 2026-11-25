package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type lambdaAPI interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetFunctionUrlConfig(context.Context, *lambda.GetFunctionUrlConfigInput, ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error)
	GetPolicy(context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// collectLambda lists the region's Lambda functions and enriches each with its
// function URL when one exists. A function URL with AuthType=NONE is a direct
// public HTTPS endpoint, flagged exposed_internet=true. Regional
// service, called once per region.
func collectLambda(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectLambda: %w", err)
	}
	return collectLambdaFunctions(ctx, lambda.NewFromConfig(awsCfg), region, accountID, now)
}

func collectLambdaFunctions(ctx context.Context, client lambdaAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		marker *string
	)
	unreadable := 0
	for {
		out, err := client.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("collectLambdaFunctions: %w", err)
		}
		for _, fn := range out.Functions {
			name := awssdk.ToString(fn.FunctionName)

			vpcID, subnetIDs := "", ""
			if fn.VpcConfig != nil {
				vpcID = awssdk.ToString(fn.VpcConfig.VpcId)
				subnetIDs = strings.Join(fn.VpcConfig.SubnetIds, ",")
			}

			a := asset.Asset{
				ID:        awssdk.ToString(fn.FunctionArn),
				Name:      name,
				Type:      "lambda_function",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Metadata: map[string]string{
					"runtime": string(fn.Runtime),
					"handler": awssdk.ToString(fn.Handler),
					"public":  "false",
					// Execution role ARN — the IAM role the function runs as. Present
					// in the ListFunctions response (no extra call). Drives the
					// executes_as edge (workload → role) in correlation.
					"exec_role": awssdk.ToString(fn.Role),
					"timeout":   strconv.Itoa(int(awssdk.ToInt32(fn.Timeout))),
					"vpc_id":    vpcID,
					// Joined to the subnets' zones after collection (stampLambdaAZCount).
					"subnet_ids": subnetIDs,
				},
				DiscoveredAt: now,
				LastSeen:     now,
			}

			// Best-effort: fetch the function URL if one exists. A missing URL
			// (ResourceNotFoundException) is normal and is recorded as an empty
			// url_auth_type so a finding for a since-removed URL can close; any
			// other error leaves the key absent (unknown).
			urlOut, urlErr := client.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
				FunctionName: &name,
			})
			var noURL *lambdatypes.ResourceNotFoundException
			if errors.As(urlErr, &noURL) {
				a.Metadata["url_auth_type"] = ""
			}
			if urlErr == nil {
				fnURL := awssdk.ToString(urlOut.FunctionUrl)
				if fnURL != "" {
					a.Endpoint = fnURL
					a.Domain = urlDomain(fnURL)
					// AuthType NONE = unauthenticated internet access.
					// AWS_IAM = signed requests only — still reachable but requires creds.
					a.Metadata["public"] = fmt.Sprintf("%t", urlOut.AuthType == lambdatypes.FunctionUrlAuthTypeNone)
					a.Metadata["url_auth_type"] = string(urlOut.AuthType)
				}
			}

			// Check the resource-based policy for an open-ended principal set. An
			// Allow with Principal "*" or a NotPrincipal, under no condition that
			// pins the caller, means any unauthenticated caller can invoke — the
			// confirmed tier of the shared public_access vocabulary.
			//
			// The NEGATIVE result is recorded too. Writing the key only on a hit
			// would make "we read the policy and it grants nothing" identical to "we
			// never got an answer", and aws-lambda-public-access reads exactly this
			// key: its silence would score as a pass in both cases, and a role
			// without lambda:GetPolicy would look exactly like a clean account.
			switch lambdaPublicAccess(ctx, client, name) {
			case lambdaPolicyPublic:
				a.Metadata["public_access"] = asset.PublicAccessConfirmed
			case lambdaPolicyNotPublic:
				a.Metadata["public_access"] = asset.PublicAccessNone
			case lambdaPolicyUnreadable:
				unreadable++
			}

			assets = append(assets, a)
		}
		if out.NextMarker == nil {
			if unreadable > 0 {
				log.FromContext(ctx).Warn().Int("unreadable", unreadable).Int("functions", len(assets)).
					Str("region", region).
					Msg("lambda: resource policy unreadable for some functions; public_access omitted (check the collector role's lambda:GetPolicy)")
			}
			return assets, nil
		}
		marker = out.NextMarker
	}
}

// lambdaPolicyVerdict is the outcome of reading one function's resource policy.
// Three values, not two, because "no policy exists" and "the call was refused"
// are opposite facts that the AWS SDK reports through the same error return.
type lambdaPolicyVerdict int

const (
	// lambdaPolicyUnreadable — the call failed for a reason other than "absent".
	// An AccessDenied from a collector role without lambda:GetPolicy lands here,
	// and must never be graded as "not public".
	lambdaPolicyUnreadable lambdaPolicyVerdict = iota
	// lambdaPolicyNotPublic — the policy was read (or definitively does not
	// exist) and grants nothing to the public. An OBSERVATION.
	lambdaPolicyNotPublic
	// lambdaPolicyPublic — an open-ended principal set holds an invoke action
	// (publicResourceAccess).
	lambdaPolicyPublic
)

// lambdaPublicAccess reads a function's resource-based policy and grades it.
//
// A missing policy is ResourceNotFoundException and is a real observation: the
// function has no resource policy, so nothing is granted to anyone. Any OTHER
// error is a failed read. Collapsing the two — returning "" for every error —
// would make a collector role missing lambda:GetPolicy report the entire
// estate as not-public, in exactly the shape a healthy estate has.
func lambdaPublicAccess(ctx context.Context, client lambdaAPI, functionName string) lambdaPolicyVerdict {
	out, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: &functionName})
	if err != nil {
		var notFound *lambdatypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return lambdaPolicyNotPublic // no policy at all: nothing is granted
		}
		return lambdaPolicyUnreadable
	}

	// Only an invoke-capable grant makes the function callable by anyone: a
	// public grant of e.g. lambda:GetFunctionConfiguration is metadata
	// disclosure, not unauthenticated execution. A Function URL with auth type
	// NONE carries exactly the condition lambda:FunctionUrlAuthType = NONE,
	// which pins no caller, so it grades public.
	if publicResourceAccess(awssdk.ToString(out.Policy), lambdaInvokeActions) == asset.PublicAccessConfirmed {
		return lambdaPolicyPublic
	}
	return lambdaPolicyNotPublic
}

// lambdaInvokeActions are the actions that make a function callable. Enumerated
// rather than prefix-matched so a Deny can be checked against each one
// individually — a Deny covering only lambda:InvokeFunction leaves a function URL
// grant (lambda:InvokeFunctionUrl) fully open.
var lambdaInvokeActions = []string{
	"lambda:invokefunction",
	"lambda:invokefunctionurl",
	"lambda:invokeasync",
}

// urlDomain extracts the hostname from an HTTPS URL (strips scheme and path).
func urlDomain(url string) string {
	s := strings.TrimPrefix(url, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
