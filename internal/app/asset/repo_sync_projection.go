package asset

import (
	"fmt"
	"strings"
)

// Project before latest-row aggregation and native-protocol encoding, so the
// database and driver do not retain discarded policy blobs. Preserve raw JSON
// values and duplicates; malformed or non-string maps still use the existing
// Go decoder's all-or-nothing behavior.
const syncMetadataProjection = `if(isValidJSON(metadata) AND
 arrayAll(x -> startsWith(x.2,'"'), JSONExtractKeysAndValuesRaw(metadata)),
 concat('{',arrayStringConcat(arrayMap(x -> concat(toJSONString(x.1),':',x.2),
 arrayFilter(x -> has(?,x.1),JSONExtractKeysAndValuesRaw(metadata))),','),'}'),metadata)`

func syncAssetQuery(proj SyncProjection) (string, []any) {
	if len(proj.MetadataKeys) == 0 && !proj.SkipTags {
		return listAllForSyncQ, nil
	}
	tags, metadata := "tags", "metadata"
	var args []any
	if proj.SkipTags {
		tags = "CAST(map(),'Map(String,String)')"
	}
	if len(proj.MetadataKeys) > 0 {
		metadata = syncMetadataProjection
		args = append(args, proj.MetadataKeys)
	}
	query := strings.Replace(listAllForSyncQ, "tags,metadata,risk_score",
		fmt.Sprintf("%s,%s,risk_score", tags, metadata), 1)
	return query + ", aggregation_in_order_max_block_bytes=4194304", args
}
