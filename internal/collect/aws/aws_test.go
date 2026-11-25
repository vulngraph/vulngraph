package aws

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// fakeEC2 serves canned, optionally paginated, responses.
type fakeEC2 struct {
	instancePages    []*ec2.DescribeInstancesOutput
	sgPages          []*ec2.DescribeSecurityGroupsOutput
	regionsOut       *ec2.DescribeRegionsOutput
	regionsErr       error // when set, DescribeRegions fails
	volumes          []ec2types.Volume
	vpcs             []ec2types.Vpc
	subnets          []ec2types.Subnet
	snapshots        []ec2types.Snapshot
	snapshotPublic   bool  // the RestorableByUserIds=["all"] listing returns the snapshots when true
	snapErr          error // when set, DescribeSnapshots fails (e.g. missing permission)
	snapPubErr       error // when set, only the public (RestorableByUserIds) listing fails
	images           []ec2types.Image
	instErr, sgErr   error
	instCall, sgCall int
	// instSleep/volSleep delay DescribeInstances/DescribeVolumes, for exercising
	// the slow-collector timing warns.
	instSleep, volSleep time.Duration
	// vpcsPanic makes DescribeVpcs panic, for exercising the regional fan-out's
	// panic recovery.
	vpcsPanic bool
	// routeTablePages are served one per DescribeRouteTables call;
	// routeTablesErr fails the call (e.g. a missing permission).
	routeTablePages [][]ec2types.RouteTable
	routeTablesErr  error
	routeTableCall  int
	// vpcEndpoints is served by DescribeVpcEndpoints; vpcEndpointsErr fails it.
	vpcEndpoints    []ec2types.VpcEndpoint
	vpcEndpointsErr error
	flowLogs        []ec2types.FlowLog
	flowLogsErr     error
	enis            map[string]int // vpc id → network interface count
}

func (f *fakeEC2) DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	if f.vpcEndpointsErr != nil {
		return nil, f.vpcEndpointsErr
	}
	return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: f.vpcEndpoints}, nil
}

func (f *fakeEC2) DescribeFlowLogs(context.Context, *ec2.DescribeFlowLogsInput, ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
	if f.flowLogsErr != nil {
		return nil, f.flowLogsErr
	}
	return &ec2.DescribeFlowLogsOutput{FlowLogs: f.flowLogs}, nil
}

func (f *fakeEC2) DescribeNetworkInterfaces(_ context.Context, in *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	out := &ec2.DescribeNetworkInterfacesOutput{}
	for range f.enis[in.Filters[0].Values[0]] {
		out.NetworkInterfaces = append(out.NetworkInterfaces, ec2types.NetworkInterface{})
	}
	return out, nil
}

func (f *fakeEC2) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	if f.routeTablesErr != nil {
		return nil, f.routeTablesErr
	}
	if f.routeTableCall >= len(f.routeTablePages) {
		return &ec2.DescribeRouteTablesOutput{}, nil
	}
	out := &ec2.DescribeRouteTablesOutput{RouteTables: f.routeTablePages[f.routeTableCall]}
	f.routeTableCall++
	if f.routeTableCall < len(f.routeTablePages) {
		out.NextToken = awssdk.String("next")
	}
	return out, nil
}

func (f *fakeEC2) DescribeSnapshots(_ context.Context, in *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if f.snapErr != nil {
		return nil, f.snapErr
	}
	if len(in.RestorableByUserIds) > 0 { // the public-snapshot listing
		if f.snapPubErr != nil {
			return nil, f.snapPubErr
		}
		if f.snapshotPublic {
			return &ec2.DescribeSnapshotsOutput{Snapshots: f.snapshots}, nil
		}
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	return &ec2.DescribeSnapshotsOutput{Snapshots: f.snapshots}, nil
}

func (f *fakeEC2) DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return &ec2.DescribeImagesOutput{Images: f.images}, nil
}

func (f *fakeEC2) DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if f.vpcsPanic {
		panic("simulated panic in DescribeVpcs")
	}
	return &ec2.DescribeVpcsOutput{Vpcs: f.vpcs}, nil
}

func (f *fakeEC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if f.regionsErr != nil {
		return nil, f.regionsErr
	}
	if f.regionsOut != nil {
		return f.regionsOut, nil
	}
	return &ec2.DescribeRegionsOutput{}, nil // empty → caller falls back to the single base region
}

func (f *fakeEC2) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if f.volSleep > 0 {
		time.Sleep(f.volSleep)
	}
	return &ec2.DescribeVolumesOutput{Volumes: f.volumes}, nil
}

func (f *fakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if f.instSleep > 0 {
		time.Sleep(f.instSleep)
	}
	if f.instErr != nil {
		return nil, f.instErr
	}
	out := f.instancePages[f.instCall]
	f.instCall++
	return out, nil
}

func (f *fakeEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if f.sgErr != nil {
		return nil, f.sgErr
	}
	out := f.sgPages[f.sgCall]
	f.sgCall++
	return out, nil
}

func (f *fakeEC2) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return &ec2.DescribeSubnetsOutput{Subnets: f.subnets}, nil
}

func (f *fakeEC2) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{}, nil
}

func (f *fakeEC2) DescribeVpcPeeringConnections(context.Context, *ec2.DescribeVpcPeeringConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcPeeringConnectionsOutput, error) {
	return &ec2.DescribeVpcPeeringConnectionsOutput{}, nil
}

func withFake(f *fakeEC2) *Collector {
	return &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return f, "eu-west-1", nil
	}}
}

func TestCollect_InstancesSecurityGroupsAndEdges(t *testing.T) {
	fake := &fakeEC2{
		vpcs: []ec2types.Vpc{{VpcId: awssdk.String("vpc-1"), CidrBlock: awssdk.String("10.0.0.0/16")}},
		sgPages: []*ec2.DescribeSecurityGroupsOutput{{
			SecurityGroups: []ec2types.SecurityGroup{
				{GroupId: awssdk.String("sg-1"), GroupName: awssdk.String("web-sg"),
					VpcId: awssdk.String("vpc-1"), Description: awssdk.String("web"),
					IpPermissions: []ec2types.IpPermission{{
						IpProtocol: awssdk.String("tcp"),
						FromPort:   awssdk.Int32(22), ToPort: awssdk.Int32(22),
						IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
					}}},
			},
		}},
		instancePages: []*ec2.DescribeInstancesOutput{{
			Reservations: []ec2types.Reservation{{
				Instances: []ec2types.Instance{{
					InstanceId:       awssdk.String("i-123"),
					InstanceType:     ec2types.InstanceTypeT3Micro,
					PublicIpAddress:  awssdk.String("1.2.3.4"),
					PrivateIpAddress: awssdk.String("10.0.0.1"),
					VpcId:            awssdk.String("vpc-1"),
					State:            &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					Tags:             []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("web-1")}},
					SecurityGroups:   []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-1")}},
				}},
			}},
		}},
	}

	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	byID := map[string]asset.Asset{}
	for _, a := range res.Assets {
		byID[a.ID] = a
	}
	require.Len(t, res.Assets, 3) // instance + security group + vpc

	inst := byID["i-123"]
	require.Equal(t, "ec2_instance", inst.Type)
	require.Equal(t, asset.ProviderAWS, inst.Provider)
	require.Equal(t, "web-1", inst.Name) // from the Name tag
	require.Equal(t, "1.2.3.4", inst.PublicIP)
	require.Equal(t, "t3.micro", inst.Metadata["instance_type"])
	require.Equal(t, "running", inst.Metadata["state"])

	sg := byID["sg-1"]
	require.Equal(t, "security_group", sg.Type)
	require.Equal(t, "web-sg", sg.Name)
	require.Contains(t, sg.Metadata["ingress"], "0.0.0.0/0") // ingress serialized for reachability

	vpc := byID["vpc-1"]
	require.Equal(t, "vpc", vpc.Type)
	require.Equal(t, "10.0.0.0/16", vpc.Metadata["cidr_block"])

	// protected_by (instance→sg) plus in_vpc edges from the instance and the SG.
	require.ElementsMatch(t, []asset.Edge{
		{SrcID: "i-123", SrcType: "ec2_instance", DstID: "sg-1", DstType: "security_group", EdgeType: "protected_by"},
		{SrcID: "i-123", SrcType: "ec2_instance", DstID: "vpc-1", DstType: "vpc", EdgeType: "in_vpc"},
		{SrcID: "sg-1", SrcType: "security_group", DstID: "vpc-1", DstType: "vpc", EdgeType: "in_vpc"},
	}, res.Edges)
}

// Terminated/shutting-down instances linger in DescribeInstances output with
// stale metadata and generated false-positive findings
// (aws-ec2-no-iam-role, aws-ec2-imdsv2-not-required, …). They must be dropped
// from inventory so the sync deletion path auto-resolves their findings;
// running/stopped/pending instances are real inventory and stay.
func TestCollect_DropsTerminatedInstances(t *testing.T) {
	state := func(n ec2types.InstanceStateName) *ec2types.InstanceState {
		return &ec2types.InstanceState{Name: n}
	}
	fake := &fakeEC2{
		sgPages: []*ec2.DescribeSecurityGroupsOutput{{}},
		instancePages: []*ec2.DescribeInstancesOutput{{
			Reservations: []ec2types.Reservation{{
				Instances: []ec2types.Instance{
					{InstanceId: awssdk.String("i-running"), State: state(ec2types.InstanceStateNameRunning)},
					{InstanceId: awssdk.String("i-stopped"), State: state(ec2types.InstanceStateNameStopped)},
					{InstanceId: awssdk.String("i-pending"), State: state(ec2types.InstanceStateNamePending)},
					{InstanceId: awssdk.String("i-terminated"), State: state(ec2types.InstanceStateNameTerminated)},
					{InstanceId: awssdk.String("i-shutting"), State: state(ec2types.InstanceStateNameShuttingDown)},
				},
			}},
		}},
	}

	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	got := map[string]bool{}
	for _, a := range res.Assets {
		got[a.ID] = true
	}
	require.True(t, got["i-running"], "running instance is kept")
	require.True(t, got["i-stopped"], "stopped instance is kept (still real inventory)")
	require.True(t, got["i-pending"], "pending instance is kept")
	require.False(t, got["i-terminated"], "terminated instance is dropped")
	require.False(t, got["i-shutting"], "shutting-down instance is dropped")

	// Deliberate exclusion, not a collection failure — must not flag Partial, or the
	// sync deletion reconciliation would never run and the FP findings never resolve.
	require.False(t, res.Partial, "dropping terminated instances is not a partial collection")
}

func TestCollect_PaginatesBothCalls(t *testing.T) {
	fake := &fakeEC2{
		sgPages: []*ec2.DescribeSecurityGroupsOutput{
			{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-1")}}, NextToken: awssdk.String("p2")},
			{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-2")}}},
		},
		instancePages: []*ec2.DescribeInstancesOutput{
			{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{}}}}}, NextToken: awssdk.String("p2")},
			{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-2"), State: &ec2types.InstanceState{}}}}}},
		},
	}

	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, 2, fake.instCall, "both instance pages fetched")
	require.Equal(t, 2, fake.sgCall, "both SG pages fetched")
	require.Len(t, res.Assets, 4) // 2 instances + 2 SGs
}

func TestCollect_NoResources(t *testing.T) {
	fake := &fakeEC2{
		sgPages:       []*ec2.DescribeSecurityGroupsOutput{{}},
		instancePages: []*ec2.DescribeInstancesOutput{{}},
	}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, res.Assets)
	require.Empty(t, res.Edges)
}

// A per-region describe error (here: security groups) is best-effort — it must
// not fail the whole account sync; the rest of the region's inventory still lands.
func TestCollect_DescribeError_IsBestEffort(t *testing.T) {
	fake := &fakeEC2{
		sgErr:         errors.New("access denied"),
		instancePages: []*ec2.DescribeInstancesOutput{{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{}}}}}}},
	}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err, "a security-group permission error must not sink the account")
	var gotInstance bool
	for _, a := range res.Assets {
		if a.ID == "i-1" {
			gotInstance = true
		}
	}
	require.True(t, gotInstance, "instances still collected despite the SG error")
	require.True(t, res.Partial, "a best-effort skip marks the result partial so sync skips deletion reconciliation")
}

// The clean path must NOT be marked partial — otherwise deletion reconciliation
// would never run and findings could never auto-resolve.
func TestCollect_CleanCollectionIsNotPartial(t *testing.T) {
	fake := &fakeEC2{
		sgPages:       []*ec2.DescribeSecurityGroupsOutput{{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-1")}}}},
		instancePages: []*ec2.DescribeInstancesOutput{{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{}}}}}}},
	}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, res.Partial, "a fully successful collection is not partial")
}

// completedScopes indexes a result's proven-complete enumerations by scope key.
func completedScopes(res collect.Result) map[string]collect.ScopeEnumeration {
	out := map[string]collect.ScopeEnumeration{}
	for _, se := range res.CompletedEnumerations {
		out[se.Scope] = se
	}
	return out
}

// A paginated listing that read every page and swallowed nothing is the ONLY
// basis on which absence can later be read as deletion. The scope key is
// region-qualified because EC2 is regional: one region completing says nothing
// about the other twenty.
func TestCollect_CompleteListingsDeclareTheirScope(t *testing.T) {
	fake := &fakeEC2{
		vpcs: []ec2types.Vpc{{VpcId: awssdk.String("vpc-1")}},
		sgPages: []*ec2.DescribeSecurityGroupsOutput{
			{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-1")}}, NextToken: awssdk.String("p2")},
			{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-2")}}},
		},
		instancePages: []*ec2.DescribeInstancesOutput{
			{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{}}}}}, NextToken: awssdk.String("p2")},
			{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-2"), State: &ec2types.InstanceState{}}}}}},
		},
	}

	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	got := completedScopes(res)
	inst, ok := got["eu-west-1/ec2:instances"]
	require.True(t, ok, "a fully-paginated DescribeInstances proves its scope complete")
	require.Equal(t, []string{"ec2_instance"}, inst.Types)
	require.Equal(t, 2, inst.Count, "the count is what the complete listing found, across pages")

	sg, ok := got["eu-west-1/ec2:security-groups"]
	require.True(t, ok)
	require.Equal(t, 2, sg.Count)

	for _, scope := range []string{"eu-west-1/ec2:vpcs", "eu-west-1/ec2:subnets", "eu-west-1/ec2:addresses"} {
		require.Contains(t, got, scope)
	}
}

// TestCollectSubnets_RegionNotAvailabilityZone pins a fix: a
// subnet's Region must be the AWS region being collected, not its
// AvailabilityZone. Otherwise ec2:subnets could never be added to
// forget's enforceableFamilies (internal/app/forget/domain.go): the scope key
// declares completeness per REGION ("eu-west-1"), and a stored Region holding
// one of several AZs ("eu-west-1a"/"eu-west-1b"/"eu-west-1c") means a region's
// population could never be selected by an exact match on its own scope key.
// The AZ is not lost, only relocated: it now lives in
// Metadata["availability_zone"].
func TestCollectSubnets_RegionNotAvailabilityZone(t *testing.T) {
	fake := &fakeEC2{
		subnets: []ec2types.Subnet{
			{SubnetId: awssdk.String("subnet-1"), VpcId: awssdk.String("vpc-1"), AvailabilityZone: awssdk.String("eu-west-1a")},
			{SubnetId: awssdk.String("subnet-2"), VpcId: awssdk.String("vpc-1"), AvailabilityZone: awssdk.String("eu-west-1b")},
		},
		// Empty-but-present pages for the other regional families this test does
		// not exercise, so DescribeInstances/DescribeSecurityGroups don't index an
		// empty slice and trip the (harmlessly recovered, but noisy) panic guard.
		instancePages: []*ec2.DescribeInstancesOutput{{}},
		sgPages:       []*ec2.DescribeSecurityGroupsOutput{{}},
	}

	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	byID := map[string]asset.Asset{}
	for _, a := range res.Assets {
		if a.Type == "subnet" {
			byID[a.ID] = a
		}
	}
	require.Len(t, byID, 2)
	for id, az := range map[string]string{"subnet-1": "eu-west-1a", "subnet-2": "eu-west-1b"} {
		a, ok := byID[id]
		require.True(t, ok, "subnet %s", id)
		require.Equal(t, "eu-west-1", a.Region,
			"subnet Region must be the collected region, not its availability zone")
		require.Equal(t, az, a.Metadata["availability_zone"],
			"the availability zone is preserved, just relocated to metadata")
	}

	// And the scope's own population must now be selectable by the region it
	// declares completeness for — the exact property the old AZ-in-Region bug
	// made impossible.
	scope := completedScopes(res)["eu-west-1/ec2:subnets"]
	require.Equal(t, 2, scope.Count)
	for _, a := range res.Assets {
		if a.Type != "subnet" {
			continue
		}
		require.Equal(t, "eu-west-1", a.Region,
			"every subnet this scope claims complete must actually carry that region")
	}
}

// The load-bearing half: a family that was skipped must leave NO completeness
// claim, while its siblings keep theirs. That per-scope survival is the whole
// point — today one failed family sets the single Partial boolean and erases
// every other scope's evidence for the entire connector.
func TestCollect_SkippedFamilyDeclaresNothingButSiblingsSurvive(t *testing.T) {
	fake := &fakeEC2{
		sgErr: errors.New("access denied"),
		instancePages: []*ec2.DescribeInstancesOutput{{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
			{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{}}}}}}},
	}

	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, res.Partial, "the aggregate still reports the skip")

	got := completedScopes(res)
	require.NotContains(t, got, "eu-west-1/ec2:security-groups",
		"a skipped listing must never leave a completeness claim behind")
	require.Contains(t, got, "eu-west-1/ec2:instances",
		"one family's permission gap must not erase what another family proved")
}

// A panicking regional collector routes through skip(); it must not reach
// complete() either. A panic mid-listing is the least trustworthy possible
// basis for declaring a scope enumerated.
func TestCollect_PanickingTaskDeclaresNoScope(t *testing.T) {
	fake := &fakeEC2{vpcsPanic: true}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, res.Partial)
	require.NotContains(t, completedScopes(res), "eu-west-1/ec2:vpcs")
}

// An empty region is fully enumerated, not unmeasured: zero instances after a
// clean listing is exactly the reading that makes every stored instance in that
// region a deletion candidate, so the scope must still be declared.
func TestCollect_EmptyRegionStillDeclaresCompleteness(t *testing.T) {
	fake := &fakeEC2{
		sgPages:       []*ec2.DescribeSecurityGroupsOutput{{}},
		instancePages: []*ec2.DescribeInstancesOutput{{}},
	}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	inst, ok := completedScopes(res)["eu-west-1/ec2:instances"]
	require.True(t, ok, "an empty but complete listing is still a complete listing")
	require.Equal(t, 0, inst.Count)
}

// Scopes are per region, so a multi-region account produces one claim per
// region — and a region that fails leaves only its own scope missing.
func TestCollect_ScopesArePerRegion(t *testing.T) {
	// One page per region: the fake serves DescribeInstances calls in order, and
	// each region issues exactly one.
	fake := &fakeEC2{
		instancePages: []*ec2.DescribeInstancesOutput{
			{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{}}}}}},
			{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-2"), State: &ec2types.InstanceState{}}}}}},
		},
	}
	c := &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return fake, "eu-west-1", nil
	}}

	res, err := c.Collect(context.Background(), map[string]string{"regions": "eu-west-1,us-east-1"})
	require.NoError(t, err)

	got := completedScopes(res)
	require.Contains(t, got, "eu-west-1/ec2:instances")
	require.Contains(t, got, "us-east-1/ec2:instances")
}

// A missing ec2:DescribeSnapshots permission must NOT sink the whole account sync
// (best-effort, like Lambda/RDS/EKS) — the instance/SG inventory still lands.
func TestCollect_SnapshotErrorIsBestEffort(t *testing.T) {
	fake := &fakeEC2{
		snapErr:       errors.New("UnauthorizedOperation: ec2:DescribeSnapshots"),
		sgPages:       []*ec2.DescribeSecurityGroupsOutput{{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-1")}}}},
		instancePages: []*ec2.DescribeInstancesOutput{{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{}}}}}}},
	}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err, "a snapshot permission error must not fail the sync")
	ids := map[string]bool{}
	for _, a := range res.Assets {
		ids[a.ID] = true
	}
	require.True(t, ids["i-1"] && ids["sg-1"], "core inventory still collected despite the snapshot error")
}

// noNetworkCfg returns AWS SDK env vars that make every global-service client
// (IAM/Route53/S3/...) fail its API call near-instantly instead of retrying
// against real AWS endpoints or the EC2 instance-metadata service — needed
// because collectAll's global-service collectors (hasCreds path) build their
// own real aws-sdk-go-v2 clients from cfg and are not injectable like ec2API.
func noNetworkCfg(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
}

// The SSO access graph emits grants_access_to/grants_admin
// edges pointing at "aws:<accountID>" cloud_account nodes. An account with zero
// EC2 instances in every region must still get that anchor node, or those
// edges point at a nonexistent asset and never traverse.
func TestCollect_EmitsCloudAccountAnchor_EvenWithNoInstances(t *testing.T) {
	noNetworkCfg(t)
	fake := &fakeEC2{
		sgPages:       []*ec2.DescribeSecurityGroupsOutput{{}},
		instancePages: []*ec2.DescribeInstancesOutput{{}},
	}
	cfg := map[string]string{"role_arn": "arn:aws:iam::123456789012:role/graph"}

	res, err := withFake(fake).Collect(context.Background(), cfg)
	require.NoError(t, err)

	var accounts []asset.Asset
	for _, a := range res.Assets {
		if a.Type == "cloud_account" {
			accounts = append(accounts, a)
		}
	}
	require.Len(t, accounts, 1, "exactly one cloud_account anchor per synced account")
	require.Equal(t, "aws:123456789012", accounts[0].ID)
	require.Equal(t, "123456789012", accounts[0].AccountID)
	require.Equal(t, "123456789012", accounts[0].Name, "falls back to account ID when no alias is configured")
	// LastSeen MUST be set — a zero LastSeen makes the row instantly TTL-eligible
	// (assets TTL = last_seen + 180 DAY) so the anchor is purged before it renders.
	require.False(t, accounts[0].LastSeen.IsZero(), "LastSeen must be set or the anchor is TTL-purged")
	require.False(t, accounts[0].DiscoveredAt.IsZero(), "DiscoveredAt must be set")
}

// Regression guard: the anchor must not be duplicated when the account spans
// multiple regions (each region's collectInstances used to try to emit it).
func TestCollect_CloudAccountAnchor_NotDuplicatedAcrossRegions(t *testing.T) {
	noNetworkCfg(t)
	fake := &fakeEC2{
		sgPages: []*ec2.DescribeSecurityGroupsOutput{{}, {}},
		instancePages: []*ec2.DescribeInstancesOutput{
			{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}}}}}},
			{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-2"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}}}}}},
		},
		regionsOut: &ec2.DescribeRegionsOutput{Regions: []ec2types.Region{
			{RegionName: awssdk.String("eu-west-1")}, {RegionName: awssdk.String("us-east-1")},
		}},
	}
	cfg := map[string]string{"role_arn": "arn:aws:iam::123456789012:role/graph"}

	res, err := withFake(fake).Collect(context.Background(), cfg)
	require.NoError(t, err)

	var accounts []asset.Asset
	for _, a := range res.Assets {
		if a.Type == "cloud_account" {
			accounts = append(accounts, a)
		}
	}
	require.Len(t, accounts, 1, "one anchor node regardless of how many regions were scanned")
}

func TestCollect_ClientBuildError(t *testing.T) {
	c := &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return nil, "", errors.New("region is required")
	}}
	_, err := c.Collect(context.Background(), nil)
	require.ErrorContains(t, err, "region is required")
}

func TestDefaultClient_RequiresRegion(t *testing.T) {
	_, _, err := defaultClient(context.Background(), map[string]string{})
	require.ErrorContains(t, err, "region is required")
}

// A connector must supply either role_arn (OIDC) or aws_access_key_id (static
// migration path) — region alone is not enough.
func TestDefaultClient_RequiresCredential(t *testing.T) {
	_, _, err := defaultClient(context.Background(), map[string]string{"region": "eu-west-1"})
	require.ErrorContains(t, err, "aws_access_key_id is required")
}

// TestCollect_SlowCollectorIsLogged is the regression guard for the
// diagnostics added to root-cause the "whole account sync times out before
// global services run" bug (see the comment above the region
// loop in aws.go): a single collector call taking longer than
// slowCollectorThreshold must be logged with its region/elapsed/count, so a
// future large or throttled account shows up in logs instead of a silent
// "context deadline exceeded" with no indication which call ate the budget.
func TestCollect_SlowCollectorIsLogged(t *testing.T) {
	orig := slowCollectorThreshold
	slowCollectorThreshold = 5 * time.Millisecond
	t.Cleanup(func() { slowCollectorThreshold = orig })

	fake := &fakeEC2{
		instSleep: 10 * time.Millisecond,
		sgPages:   []*ec2.DescribeSecurityGroupsOutput{{}},
		instancePages: []*ec2.DescribeInstancesOutput{{
			Reservations: []ec2types.Reservation{{
				Instances: []ec2types.Instance{{
					InstanceId: awssdk.String("i-slow"),
					State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				}},
			}},
		}},
	}
	var buf bytes.Buffer
	origLogger := zlog.Logger
	// SyncWriter, not a bare bytes.Buffer: production's default os.File writer
	// is documented thread-safe, but this test now exercises a genuinely
	// concurrent regional fan-out (see aws.go's regionConcurrency), and
	// unsynchronized concurrent writes to an unwrapped test buffer race under
	// -race.
	zlog.Logger = zerolog.New(zerolog.SyncWriter(&buf))
	t.Cleanup(func() { zlog.Logger = origLogger })

	_, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "collectInstances took longer than expected")
	require.Contains(t, out, `"region":"eu-west-1"`)
	require.Contains(t, out, `"count":1`)
	// The per-region and all-regions summaries fire too — the fake's single
	// region trips both thresholds with the same sleep.
	require.Contains(t, out, "region collection took longer than expected")
	require.Contains(t, out, "all-regions collection took longer than expected")
}

// TestCollect_PanicInRegionalTaskMarksResultPartial is the regression guard
// for a panic-recovery gap: if the regional fan-out's panic-recovery goroutine
// only logged and returned — unlike every OTHER failure path in this function
// (which all go through skip() and therefore set result.Partial) — the
// silent, non-partial result after a one-region panic would make the sync
// worker's deletion reconciliation read that region's missing assets as legitimately
// gone and auto-resolve their findings — a crash silently deleting inventory.
// The recovered panic is routed through skip() like everything else.
func TestCollect_PanicInRegionalTaskMarksResultPartial(t *testing.T) {
	fake := &fakeEC2{
		vpcsPanic: true,
		sgPages:   []*ec2.DescribeSecurityGroupsOutput{{}},
		instancePages: []*ec2.DescribeInstancesOutput{{
			Reservations: []ec2types.Reservation{{
				Instances: []ec2types.Instance{{
					InstanceId: awssdk.String("i-survives"),
					State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				}},
			}},
		}},
	}

	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err, "a panicking collector must not fail the whole sync — it's recovered and skipped, same as any other best-effort collector error")
	require.True(t, res.Partial, "a region with a panicking collector must be marked Partial, or its missing assets read as deleted")

	// The panic must not take down sibling tasks in the same region's fan-out.
	byID := map[string]asset.Asset{}
	for _, a := range res.Assets {
		byID[a.ID] = a
	}
	_, survived := byID["i-survives"]
	require.True(t, survived, "a panic in one regional task must not prevent other tasks in the same region from completing")
}
