package aws

import (
	"context"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// lambdaWithPolicy serves one fixed resource-based policy document.
type lambdaWithPolicy struct{ policy string }

func (l lambdaWithPolicy) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{}, nil
}

func (l lambdaWithPolicy) GetFunctionUrlConfig(context.Context, *lambda.GetFunctionUrlConfigInput, ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error) {
	return nil, fmt.Errorf("ResourceNotFoundException")
}

// GetPolicy returns the TYPED ResourceNotFoundException AWS actually sends when
// a function has no resource policy. A plain fmt.Errorf here would have hidden
// the distinction the collector now draws between "absent" and "refused".
func (l lambdaWithPolicy) GetPolicy(context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	if l.policy == "" {
		return nil, &lambdatypes.ResourceNotFoundException{Message: awssdk.String("no policy")}
	}
	return &lambda.GetPolicyOutput{Policy: awssdk.String(l.policy)}, nil
}

// lambdaPolicyDenied refuses every GetPolicy the way a collector role without
// lambda:GetPolicy does.
type lambdaPolicyDenied struct{ lambdaWithPolicy }

func (lambdaPolicyDenied) GetPolicy(context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return nil, fmt.Errorf("AccessDeniedException: not authorized to perform lambda:GetPolicy")
}

var _ lambdaAPI = lambdaWithPolicy{}

func publicAccessOf(t *testing.T, policy string) lambdaPolicyVerdict {
	t.Helper()
	return lambdaPublicAccess(context.Background(), lambdaWithPolicy{policy: policy}, "fn")
}

// The core regression: an explicit Deny on the wildcard principal is the very
// thing that makes a function NOT public. The statement struct had no Effect
// field at all, so the lockdown statement was read as a grant and the function
// was graded PublicAccessConfirmed — a critical false positive on a function
// that had been deliberately locked down.
func TestLambdaPublicAccess_ExplicitDenyIsNotAGrant(t *testing.T) {
	require.Equal(t, lambdaPolicyNotPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction"}]}`))

	// A Deny wins wherever it sits relative to the Allow.
	require.Equal(t, lambdaPolicyNotPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"},
		{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction"}]}`))
}

// A genuine public grant must still be caught.
func TestLambdaPublicAccess_WildcardAllowIsPublic(t *testing.T) {
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"}]}`))
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"lambda:InvokeFunctionUrl"}]}`))
}

// AWS accepts Statement as a single object as well as an array. Declaring it as
// an array alone made the whole unmarshal fail, so lambdaPublicAccess returned
// "" ("no policy at all") and a genuinely public function was silently cleared.
func TestLambdaPublicAccess_SingleObjectStatement(t *testing.T) {
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t,
		`{"Statement":{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"}}`))
	require.Equal(t, lambdaPolicyNotPublic, publicAccessOf(t,
		`{"Statement":{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction"}}`))
}

// A wildcard principal scoped by a Condition (SourceArn/SourceAccount — the
// standard service-invocation pattern) is not open to the internet.
func TestLambdaPublicAccess_ConditionScopedWildcardIsNotPublic(t *testing.T) {
	require.Equal(t, lambdaPolicyNotPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction",
		 "Condition":{"StringEquals":{"AWS:SourceAccount":"111122223333"}}}]}`))
}

// A Function URL with auth type NONE is invocable by anyone: its condition
// names the URL's auth type, not a caller. NotPrincipal reaches everyone it
// does not list.
func TestLambdaPublicAccess_NonRestrictingConditionAndNotPrincipal(t *testing.T) {
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl",
		 "Condition":{"StringEquals":{"lambda:FunctionUrlAuthType":"NONE"}}}]}`))
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:role/ops"},"Action":"lambda:InvokeFunction"}]}`))
}

// A public grant of a non-invoke action is metadata disclosure, not
// unauthenticated execution, and must not be graded as open invocation.
func TestLambdaPublicAccess_NonInvokeActionIsNotPublicInvocation(t *testing.T) {
	require.Equal(t, lambdaPolicyNotPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"lambda:GetFunctionConfiguration"}]}`))

	// An action list containing an invoke action still counts.
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*",
		 "Action":["lambda:GetFunctionConfiguration","lambda:InvokeFunction"]}]}`))

	// A wildcard action covers invocation.
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"*"}]}`))
}

// No policy at all is an OBSERVATION: nothing is granted to anyone, so the
// function is not public. What must stay distinguishable is the REFUSED read —
// see TestLambdaPublicAccess_DeniedReadIsNotAnObservation.
func TestLambdaPublicAccess_NoPolicyIsNotPublic(t *testing.T) {
	require.Equal(t, lambdaPolicyNotPublic, publicAccessOf(t, ""))
}

// A Deny naming a different, non-invoke action must not clear a real public
// invoke grant.
func TestLambdaPublicAccess_UnrelatedDenyDoesNotClearPublicInvoke(t *testing.T) {
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"},
		{"Effect":"Deny","Principal":"*","Action":"lambda:GetFunctionConfiguration"}]}`))
}

// Adversary emulation: a decoy Deny on ONE invoke action must not clear a public
// grant of a DIFFERENT one. Short-circuiting on any qualifying Deny anywhere in
// the document let "Deny * on lambda:InvokeFunction" alongside "Allow * on
// lambda:InvokeFunctionUrl" grade the function non-public while its function URL
// stayed open to the internet.
func TestLambdaPublicAccess_DecoyDenyOnDifferentInvokeAction(t *testing.T) {
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Sid":"Lockdown","Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction"},
		{"Sid":"URLPublic","Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl"}]}`))
}

// A Deny that genuinely covers every invoke action the Allow confers does clear it.
func TestLambdaPublicAccess_DenyCoveringAllInvokeActionsClears(t *testing.T) {
	require.Equal(t, lambdaPolicyNotPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Deny","Principal":"*","Action":"lambda:*"},
		{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl"}]}`))

	require.Equal(t, lambdaPolicyNotPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunctionUrl"},
		{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl"}]}`))
}

// A wildcard Allow confers every invoke action, so a Deny on just one leaves the
// others public.
func TestLambdaPublicAccess_WildcardAllowSurvivesPartialDeny(t *testing.T) {
	require.Equal(t, lambdaPolicyPublic, publicAccessOf(t, `{"Statement":[
		{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeAsync"},
		{"Effect":"Allow","Principal":"*","Action":"*"}]}`))
}

// A refused GetPolicy is not evidence of anything. Returning "" for every error
// made an AccessDenied — a collector role without lambda:GetPolicy — read
// exactly like a healthy estate: no function graded public, no key written, no
// complaint. aws-lambda-public-access reads that key, so its silence was scored
// as a pass on data nobody had.
func TestLambdaPublicAccess_DeniedReadIsNotAnObservation(t *testing.T) {
	got := lambdaPublicAccess(context.Background(), lambdaPolicyDenied{}, "fn")
	require.Equal(t, lambdaPolicyUnreadable, got,
		"an AccessDenied must be unreadable, never graded not-public")
}

// The observation reaches the asset: a function whose policy was read and grants
// nothing carries public_access=none, so an absent key means "not read" and
// nothing else.
func TestCollectLambda_RecordsTheNegativeObservation(t *testing.T) {
	client := lambdaListing{
		lambdaWithPolicy: lambdaWithPolicy{policy: `{"Statement":[
			{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"lambda:InvokeFunction"}]}`},
		names: []string{"fn-a"},
	}
	assets, err := collectLambdaFunctions(context.Background(), client, "eu-west-1", "123456789012", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, asset.PublicAccessNone, assets[0].Metadata["public_access"])
}

// And a function whose policy could not be read carries NO key, so the check
// sees missing data rather than a clean result.
func TestCollectLambda_UnreadablePolicyOmitsTheKey(t *testing.T) {
	client := lambdaDeniedListing{names: []string{"fn-a"}}
	assets, err := collectLambdaFunctions(context.Background(), client, "eu-west-1", "123456789012", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.NotContains(t, assets[0].Metadata, "public_access")
}

// lambdaListing lists the named functions and serves one fixed policy for each.
type lambdaListing struct {
	lambdaWithPolicy
	names []string
}

func (l lambdaListing) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: lambdaFns(l.names)}, nil
}

type lambdaDeniedListing struct {
	lambdaPolicyDenied
	names []string
}

func (l lambdaDeniedListing) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: lambdaFns(l.names)}, nil
}

func lambdaFns(names []string) []lambdatypes.FunctionConfiguration {
	out := make([]lambdatypes.FunctionConfiguration, 0, len(names))
	for _, n := range names {
		out = append(out, lambdatypes.FunctionConfiguration{
			FunctionName: awssdk.String(n),
			FunctionArn:  awssdk.String("arn:aws:lambda:eu-west-1:123456789012:function:" + n),
			Role:         awssdk.String("arn:aws:iam::123456789012:role/r"),
		})
	}
	return out
}
