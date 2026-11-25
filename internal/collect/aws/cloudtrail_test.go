package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stretchr/testify/require"
)

type fakeCloudTrail struct {
	trails        []cttypes.Trail
	shadowsAsked  bool
	statusRegions map[string]string // trail ARN -> region the status call was signed for
	statusErr     map[string]bool
	// selectors answers GetEventSelectors per trail ARN; a missing entry errors.
	selectors       map[string]*cloudtrail.GetEventSelectorsOutput
	selectorRegions map[string]string
}

func (f *fakeCloudTrail) GetEventSelectors(_ context.Context, in *cloudtrail.GetEventSelectorsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	o := cloudtrail.Options{Region: "eu-west-1"}
	for _, fn := range opts {
		fn(&o)
	}
	arn := awssdk.ToString(in.TrailName)
	if f.selectorRegions != nil {
		f.selectorRegions[arn] = o.Region
	}
	if out, ok := f.selectors[arn]; ok {
		return out, nil
	}
	return nil, apiErr{code: "AccessDeniedException"}
}

func (f *fakeCloudTrail) DescribeTrails(_ context.Context, in *cloudtrail.DescribeTrailsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	f.shadowsAsked = awssdk.ToBool(in.IncludeShadowTrails)
	return &cloudtrail.DescribeTrailsOutput{TrailList: f.trails}, nil
}

func (f *fakeCloudTrail) GetTrailStatus(_ context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	o := cloudtrail.Options{Region: "eu-west-1"} // the client's base region
	for _, fn := range opts {
		fn(&o)
	}
	arn := awssdk.ToString(in.Name)
	f.statusRegions[arn] = o.Region
	if f.statusErr[arn] {
		return nil, apiErr{code: "TrailNotFoundException"}
	}
	return &cloudtrail.GetTrailStatusOutput{IsLogging: awssdk.Bool(true)}, nil
}

// A multi-region trail homed outside the base region is returned as a shadow
// (possibly more than once): it must be collected once, with its status read
// from its home region.
func TestCollectCloudTrailTrails_ShadowsDedupedHomeRegionStatus(t *testing.T) {
	const homed = "arn:aws:cloudtrail:us-east-1:111:trail/org"
	const local = "arn:aws:cloudtrail:eu-west-1:111:trail/local"
	f := &fakeCloudTrail{
		trails: []cttypes.Trail{
			{TrailARN: awssdk.String(homed), Name: awssdk.String("org"), HomeRegion: awssdk.String("us-east-1"), IsMultiRegionTrail: awssdk.Bool(true)},
			{TrailARN: awssdk.String(homed), Name: awssdk.String("org"), HomeRegion: awssdk.String("us-east-1"), IsMultiRegionTrail: awssdk.Bool(true)},
			{TrailARN: awssdk.String(local), Name: awssdk.String("local"), HomeRegion: awssdk.String("eu-west-1")},
		},
		statusRegions: map[string]string{},
		statusErr:     map[string]bool{local: true},
	}
	got, err := collectCloudTrailTrails(context.Background(), f, "global", "111", time.Now())
	require.NoError(t, err)
	require.True(t, f.shadowsAsked, "shadow trails must be requested")
	require.Len(t, got, 2, "a trail listed twice is one trail")
	require.Equal(t, "us-east-1", f.statusRegions[homed], "status is read from the trail's home region")

	byID := map[string]map[string]string{}
	for _, a := range got {
		byID[a.ID] = a.Metadata
	}
	require.Equal(t, "true", byID[homed]["is_logging"])
	_, present := byID[local]["is_logging"]
	require.False(t, present, "a failed status read is unknown, not 'not logging'")
}
