// Package operations holds the request/response envelopes the stand-in exposes.
package operations

import "github.com/censys/censys-sdk-go/models/components"

type V3GlobaldataSearchQueryRequest struct {
	SearchQueryInputBody components.SearchQueryInputBody
}

type V3GlobaldataSearchQueryResponse struct {
	ResponseEnvelopeSearchQueryResponse *components.ResponseEnvelopeSearchQueryResponse
}
