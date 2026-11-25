package aws

import "github.com/vulngraph/vulngraph/internal/app/asset"

// stampTrailBucketLogging copies the server-access-logging state of each
// trail's destination bucket onto the trail as s3_bucket_logging, so
// aws-cloudtrail-bucket-no-access-logging can grade it. CSPM checks see one
// asset at a time and run over exactly this sweep's collector output, so the
// join has to happen here: a correlate annotation would neither reach the
// check run nor survive the trail's next re-ingest.
//
// The key is written only when the bucket is in this sweep's inventory AND its
// logging state was observed. An organization trail delivering to a
// log-archive account, or a bucket whose GetBucketLogging failed, leaves the
// key absent — unknown, never "disabled".
func stampTrailBucketLogging(assets []asset.Asset) {
	logging := map[string]string{}
	for _, a := range assets {
		if a.Type != "s3_bucket" {
			continue
		}
		if v, ok := a.Metadata["logging"]; ok {
			logging[a.ID] = v // a bucket's asset ID is its name
		}
	}
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_cloudtrail" {
			continue
		}
		if v, ok := logging[a.Metadata["s3_bucket"]]; ok {
			a.Metadata["s3_bucket_logging"] = v
		}
	}
}

// stampTrailBucketMFADelete copies the MFA Delete state of each trail's
// destination bucket onto the trail as s3_bucket_mfa_delete, under the same
// rule as stampTrailBucketLogging: written only when the bucket is in this
// sweep's inventory and its versioning state was observed.
func stampTrailBucketMFADelete(assets []asset.Asset) {
	mfaDelete := map[string]string{}
	for _, a := range assets {
		if a.Type != "s3_bucket" {
			continue
		}
		if v, ok := a.Metadata["mfa_delete"]; ok {
			mfaDelete[a.ID] = v
		}
	}
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_cloudtrail" {
			continue
		}
		if v, ok := mfaDelete[a.Metadata["s3_bucket"]]; ok {
			a.Metadata["s3_bucket_mfa_delete"] = v
		}
	}
}
