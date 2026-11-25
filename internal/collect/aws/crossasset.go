package aws

import "github.com/vulngraph/vulngraph/internal/app/asset"

// joinCrossAssetFacts stamps onto single assets the facts that live on a
// related asset, for CSPM checks that can only see one asset at a time. It
// runs after every collector has returned, regional and global, because each
// join reads both sides from the same sweep.
func joinCrossAssetFacts(assets []asset.Asset) {
	stampTrailBucketLogging(assets)
	stampTrailBucketMFADelete(assets)
	stampInstanceNodeFacts(assets)
	stampLambdaAZCount(assets)
	stampSageMakerNotebookVPC(assets)
	stampRedshiftPortWorldOpen(assets)
}
