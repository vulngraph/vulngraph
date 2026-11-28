package correlate

import (
	"iter"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// edgeStreamer permits a staged consumer to stop before a rule accumulates its
// full fanout. The legacy Rule surface remains available to existing callers.
// A staged caller must reject rules without this boundary; wrapping Correlate's
// completed slice would leave the same unbounded transient allocation.
type edgeStreamer interface {
	Edges(Graph) iter.Seq[asset.Edge]
}

type annotationStreamer interface {
	Annotations(Graph) iter.Seq[asset.Annotation]
}
