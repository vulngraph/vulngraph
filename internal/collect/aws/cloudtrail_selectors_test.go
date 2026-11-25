package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestCollectCloudTrailTrails_SelectorsReadInHomeRegion(t *testing.T) {
	const homed = "arn:aws:cloudtrail:us-east-1:111:trail/org"
	const unread = "arn:aws:cloudtrail:eu-west-1:111:trail/unread"
	f := &fakeCloudTrail{
		trails: []cttypes.Trail{
			{TrailARN: awssdk.String(homed), Name: awssdk.String("org"), HomeRegion: awssdk.String("us-east-1"), IsMultiRegionTrail: awssdk.Bool(true)},
			{TrailARN: awssdk.String(unread), Name: awssdk.String("unread"), HomeRegion: awssdk.String("eu-west-1")},
		},
		statusRegions:   map[string]string{},
		selectorRegions: map[string]string{},
		selectors: map[string]*cloudtrail.GetEventSelectorsOutput{
			homed: {EventSelectors: []cttypes.EventSelector{{IncludeManagementEvents: awssdk.Bool(true), ReadWriteType: cttypes.ReadWriteTypeAll}}},
		},
	}
	got, err := collectCloudTrailTrails(context.Background(), f, "global", "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "us-east-1", f.selectorRegions[homed], "selectors are read from the trail's home region")
	byID := map[string]map[string]string{}
	for _, a := range got {
		byID[a.ID] = a.Metadata
	}
	require.Equal(t, "all", byID[homed]["management_events"])
	require.Equal(t, "none", byID[homed]["s3_data_events"])
	_, present := byID[unread]["management_events"]
	require.False(t, present, "an unread selector set is unknown, not a trail recording nothing")
	_, present = byID[unread]["s3_data_events"]
	require.False(t, present)
}

func TestEventSelectorMeta(t *testing.T) {
	f := func(field string, equals ...string) cttypes.AdvancedFieldSelector {
		return cttypes.AdvancedFieldSelector{Field: awssdk.String(field), Equals: equals}
	}
	basic := func(sels ...cttypes.EventSelector) cloudtrail.GetEventSelectorsOutput {
		return cloudtrail.GetEventSelectorsOutput{EventSelectors: sels}
	}
	advanced := func(fields ...cttypes.AdvancedFieldSelector) cloudtrail.GetEventSelectorsOutput {
		return cloudtrail.GetEventSelectorsOutput{AdvancedEventSelectors: []cttypes.AdvancedEventSelector{{FieldSelectors: fields}}}
	}
	s3Values := func(values ...string) []cttypes.DataResource {
		return []cttypes.DataResource{{Type: awssdk.String("AWS::S3::Object"), Values: values}}
	}
	tests := []struct {
		name       string
		out        cloudtrail.GetEventSelectorsOutput
		mgmt, s3Ev string
	}{
		{"empty answer records nothing", cloudtrail.GetEventSelectorsOutput{}, "none", "none"},
		{"basic selector with API defaults: all management events", basic(cttypes.EventSelector{}), "all", "none"},
		{"basic read-only management",
			basic(cttypes.EventSelector{IncludeManagementEvents: awssdk.Bool(true), ReadWriteType: cttypes.ReadWriteTypeReadOnly}), "read", "none"},
		{"read-only plus write-only selectors cover both", basic(
			cttypes.EventSelector{IncludeManagementEvents: awssdk.Bool(true), ReadWriteType: cttypes.ReadWriteTypeReadOnly},
			cttypes.EventSelector{IncludeManagementEvents: awssdk.Bool(true), ReadWriteType: cttypes.ReadWriteTypeWriteOnly}), "all", "none"},
		{"management excluded",
			basic(cttypes.EventSelector{IncludeManagementEvents: awssdk.Bool(false), ReadWriteType: cttypes.ReadWriteTypeAll}), "none", "none"},
		{"basic S3 every bucket, write-only", basic(cttypes.EventSelector{IncludeManagementEvents: awssdk.Bool(true),
			ReadWriteType: cttypes.ReadWriteTypeWriteOnly, DataResources: s3Values("arn:aws:s3")}), "write", "write"},
		{"basic S3 every bucket, trailing-colons form, other partition",
			basic(cttypes.EventSelector{ReadWriteType: cttypes.ReadWriteTypeAll, DataResources: s3Values("arn:aws-us-gov:s3:::")}), "all", "all"},
		{"basic S3 scoped to one bucket is not every bucket",
			basic(cttypes.EventSelector{ReadWriteType: cttypes.ReadWriteTypeAll, DataResources: s3Values("arn:aws:s3:::logs/")}), "all", "none"},
		{"advanced management, no readOnly field: all", advanced(f("eventCategory", "Management")), "all", "none"},
		{"advanced management excluding KMS events leaves those unlogged", advanced(f("eventCategory", "Management"),
			cttypes.AdvancedFieldSelector{Field: awssdk.String("eventSource"), NotEquals: []string{"kms.amazonaws.com"}}), "none", "none"},
		{"basic management excluding an event source", basic(cttypes.EventSelector{IncludeManagementEvents: awssdk.Bool(true),
			ReadWriteType: cttypes.ReadWriteTypeAll, ExcludeManagementEventSources: []string{"kms.amazonaws.com"}}), "none", "none"},
		{"advanced management narrowed to one event source",
			advanced(f("eventCategory", "Management"), f("eventSource", "iam.amazonaws.com")), "none", "none"},
		{"advanced write-only management", advanced(f("eventCategory", "Management"), f("readOnly", "false")), "write", "none"},
		{"advanced readOnly NotEquals true is write-only", advanced(f("eventCategory", "Management"),
			cttypes.AdvancedFieldSelector{Field: awssdk.String("readOnly"), NotEquals: []string{"true"}}), "write", "none"},
		{"advanced S3 data, every bucket, reads only",
			advanced(f("eventCategory", "Data"), f("resources.type", "AWS::S3::Object"), f("readOnly", "true")), "none", "read"},
		{"advanced S3 data excluding a bucket does not cover every bucket", advanced(f("eventCategory", "Data"), f("resources.type", "AWS::S3::Object"),
			cttypes.AdvancedFieldSelector{Field: awssdk.String("resources.ARN"), NotStartsWith: []string{"arn:aws:s3:::trail-logs/"}}), "none", "none"},
		{"advanced S3 data with a StartsWith on the bare S3 prefix", advanced(f("eventCategory", "Data"), f("resources.type", "AWS::S3::Object"),
			cttypes.AdvancedFieldSelector{Field: awssdk.String("resources.ARN"), StartsWith: []string{"arn:aws:s3:::"}}), "none", "all"},
		{"advanced S3 data on one bucket prefix", advanced(f("eventCategory", "Data"), f("resources.type", "AWS::S3::Object"),
			cttypes.AdvancedFieldSelector{Field: awssdk.String("resources.ARN"), StartsWith: []string{"arn:aws:s3:::payroll/"}}), "none", "none"},
		{"advanced data for another resource type",
			advanced(f("eventCategory", "Data"), f("resources.type", "AWS::Lambda::Function")), "none", "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventSelectorMeta(&tt.out)
			require.Equal(t, tt.mgmt, got["management_events"])
			require.Equal(t, tt.s3Ev, got["s3_data_events"])
		})
	}
}

func metaAsset(kv ...string) asset.Asset {
	md := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		md[kv[i]] = kv[i+1]
	}
	return asset.Asset{Metadata: md}
}

func TestTrailSelectorRollup(t *testing.T) {
	good := metaAsset("multi_region", "true", "is_logging", "true", "management_events", "all", "s3_data_events", "all")
	tests := []struct {
		name   string
		trails []asset.Asset
		want   map[string]string
	}{
		{"no trail: nothing logs S3; management left to the no-trail check", nil,
			map[string]string{"cloudtrail_s3_write_events": "false", "cloudtrail_s3_read_events": "false"}},
		{"qualifying trail", []asset.Asset{good},
			map[string]string{"cloudtrail_multi_region_mgmt_all": "true", "cloudtrail_s3_write_events": "true", "cloudtrail_s3_read_events": "true"}},
		{"logging multi-region trail records management reads only",
			[]asset.Asset{metaAsset("multi_region", "true", "is_logging", "true", "management_events", "read", "s3_data_events", "write")},
			map[string]string{"cloudtrail_multi_region_mgmt_all": "false", "cloudtrail_s3_write_events": "true", "cloudtrail_s3_read_events": "false"}},
		{"single-region trail does not count",
			[]asset.Asset{metaAsset("multi_region", "false", "is_logging", "true", "management_events", "all", "s3_data_events", "all")},
			map[string]string{"cloudtrail_s3_write_events": "false", "cloudtrail_s3_read_events": "false"}},
		{"stopped multi-region trail does not count",
			[]asset.Asset{metaAsset("multi_region", "true", "is_logging", "false", "management_events", "all", "s3_data_events", "all")},
			map[string]string{"cloudtrail_s3_write_events": "false", "cloudtrail_s3_read_events": "false"}},
		{"unread selectors leave every key unknown",
			[]asset.Asset{metaAsset("multi_region", "true", "is_logging", "true")}, map[string]string{}},
		{"unread logging status leaves every key unknown",
			[]asset.Asset{metaAsset("multi_region", "true", "management_events", "all", "s3_data_events", "all")}, map[string]string{}},
		{"an unread trail does not unsettle what a good one proves",
			[]asset.Asset{metaAsset("multi_region", "true", "is_logging", "true"), good},
			map[string]string{"cloudtrail_multi_region_mgmt_all": "true", "cloudtrail_s3_write_events": "true", "cloudtrail_s3_read_events": "true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, trailSelectorRollup(tt.trails))
		})
	}
}
