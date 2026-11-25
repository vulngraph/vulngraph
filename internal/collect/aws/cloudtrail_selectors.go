package aws

// cloudtrail_selectors.go — what a trail records, from cloudtrail:GetEventSelectors.
//
// A trail can log and still miss what the benchmarks ask for: CIS AWS 4.1 and
// FSBP CloudTrail.1 want read AND write management events on a multi-region
// trail, CIS 4.8/4.9 want S3 object-level write/read data events for every
// bucket. Both selector shapes are read — basic EventSelectors and
// AdvancedEventSelectors (a trail carries one or the other) — and reduced to
// the two per-trail keys below, so the account rollup never re-parses them.

import (
	"slices"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Values of the per-trail management_events and s3_data_events keys: which
// halves of read/write the trail records. "none" is an observation (the
// selectors were read and exclude them).
const (
	recordsAll   = "all"
	recordsRead  = "read"
	recordsWrite = "write"
	recordsNone  = "none"
)

// rwCoverage accumulates which halves of read/write some selector records.
type rwCoverage struct{ read, write bool }

func (c *rwCoverage) add(read, write bool) {
	c.read = c.read || read
	c.write = c.write || write
}

func (c rwCoverage) value() string {
	switch {
	case c.read && c.write:
		return recordsAll
	case c.read:
		return recordsRead
	case c.write:
		return recordsWrite
	}
	return recordsNone
}

// eventSelectorMeta reduces a GetEventSelectors answer to the trail's
// management_events and s3_data_events keys. s3_data_events counts only
// selectors that cover every bucket: a selector scoped to named buckets
// leaves the rest unlogged, which is what CIS 4.8/4.9 test.
func eventSelectorMeta(out *cloudtrail.GetEventSelectorsOutput) map[string]string {
	var mgmt, s3 rwCoverage
	for _, sel := range out.EventSelectors {
		read, write := basicReadWrite(sel.ReadWriteType)
		// IncludeManagementEvents defaults to true when a selector is created
		// without it, and the API echoes that default back. Excluded event
		// sources (KMS, RDS Data API) leave those management events unlogged.
		if (sel.IncludeManagementEvents == nil || *sel.IncludeManagementEvents) && len(sel.ExcludeManagementEventSources) == 0 {
			mgmt.add(read, write)
		}
		for _, dr := range sel.DataResources {
			if awssdk.ToString(dr.Type) == "AWS::S3::Object" && coversAllBuckets(dr.Values) {
				s3.add(read, write)
			}
		}
	}
	for _, sel := range out.AdvancedEventSelectors {
		advancedCoverage(sel.FieldSelectors, &mgmt, &s3)
	}
	return map[string]string{
		"management_events": mgmt.value(),
		"s3_data_events":    s3.value(),
	}
}

func basicReadWrite(t cttypes.ReadWriteType) (read, write bool) {
	switch t {
	case cttypes.ReadWriteTypeReadOnly:
		return true, false
	case cttypes.ReadWriteTypeWriteOnly:
		return false, true
	}
	// All, and the empty default (the API's default is All).
	return true, true
}

// coversAllBuckets reports whether a basic S3 data resource names every
// bucket: the bare "arn:<partition>:s3" or "arn:<partition>:s3:::" prefix.
func coversAllBuckets(values []string) bool {
	for _, v := range values {
		if isAllBucketsARN(v) {
			return true
		}
	}
	return false
}

func isAllBucketsARN(v string) bool {
	parts := strings.Split(v, ":")
	if len(parts) < 3 || parts[0] != "arn" || parts[2] != "s3" {
		return false
	}
	rest := strings.Join(parts[3:], ":")
	return len(parts) == 3 || rest == "::"
}

// advancedCoverage folds one advanced selector into the coverage. An advanced
// selector is an AND of its field selectors; beside the category, readOnly and
// resource type, any other condition — an event name, an excluded event
// source, a bucket ARN prefix or an excluded bucket — leaves part of what the
// control needs unlogged, so the selector does not count as covering it.
func advancedCoverage(fields []cttypes.AdvancedFieldSelector, mgmt, s3 *rwCoverage) {
	var category, resourceType string
	read, write := true, true
	narrowed := false
	for _, f := range fields {
		switch awssdk.ToString(f.Field) {
		case "eventCategory":
			if len(f.Equals) == 1 {
				category = f.Equals[0]
			}
		case "resources.type":
			if len(f.Equals) == 1 {
				resourceType = f.Equals[0]
			} else {
				narrowed = true
			}
		case "readOnly":
			switch {
			case slices.Contains(f.Equals, "true") || slices.Contains(f.NotEquals, "false"):
				write = false
			case slices.Contains(f.Equals, "false") || slices.Contains(f.NotEquals, "true"):
				read = false
			}
		case "resources.ARN":
			if !allBucketsPrefix(f) {
				narrowed = true
			}
		default:
			narrowed = true
		}
	}
	if narrowed {
		return
	}
	switch {
	case category == "Management":
		mgmt.add(read, write)
	case category == "Data" && resourceType == "AWS::S3::Object":
		s3.add(read, write)
	}
}

// allBucketsPrefix reports whether a resources.ARN field selector leaves
// every bucket in scope: only a StartsWith on the bare S3 ARN prefix.
func allBucketsPrefix(f cttypes.AdvancedFieldSelector) bool {
	if len(f.Equals) > 0 || len(f.EndsWith) > 0 || len(f.NotEquals) > 0 || len(f.NotStartsWith) > 0 || len(f.NotEndsWith) > 0 {
		return false
	}
	for _, p := range f.StartsWith {
		if !isAllBucketsARN(p) {
			return false
		}
	}
	return true
}

// trailSelectorRollup answers CIS 4.1 / FSBP CloudTrail.1's selector half and
// CIS 4.8/4.9 for the account, over the multi-region trails that are logging:
//
//   - cloudtrail_multi_region_mgmt_all: one of them records read and write
//     management events. Written only when such a trail exists; with none,
//     aws-cloudtrail-no-multiregion-trail already reports the account.
//   - cloudtrail_s3_write_events / cloudtrail_s3_read_events: one of them
//     records S3 object-level writes / reads for every bucket.
//
// A trail whose logging status or selectors could not be read leaves a key
// absent unless another trail already settles it. Called only with a
// successful trail listing.
func trailSelectorRollup(trails []asset.Asset) map[string]string {
	var logging, unread bool
	var mgmt, s3w, s3r bool
	for _, t := range trails {
		if t.Metadata["multi_region"] != "true" {
			continue
		}
		switch t.Metadata["is_logging"] {
		case "true":
		case "":
			unread = true
			continue
		default:
			continue
		}
		logging = true
		m, okM := t.Metadata["management_events"]
		s, okS := t.Metadata["s3_data_events"]
		if !okM || !okS {
			unread = true
			continue
		}
		mgmt = mgmt || m == recordsAll
		s3w = s3w || s == recordsAll || s == recordsWrite
		s3r = s3r || s == recordsAll || s == recordsRead
	}
	out := map[string]string{}
	settle := func(key string, ok bool) {
		if ok || !unread {
			out[key] = strconv.FormatBool(ok)
		}
	}
	if logging {
		settle("cloudtrail_multi_region_mgmt_all", mgmt)
	}
	settle("cloudtrail_s3_write_events", s3w)
	settle("cloudtrail_s3_read_events", s3r)
	return out
}
