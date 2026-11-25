// Package components holds the request/response shapes the stand-in exposes.
package components

type SearchQueryInputBody struct {
	PageSize  *int64
	Query     string
	PageToken *string
}

type HTTP struct {
	URI *string
}

type Endpoint struct {
	IP       *string `json:"ip,omitempty"`
	Hostname *string `json:"hostname,omitempty"`
	Port     *int    `json:"port,omitempty"`
	HTTP     *HTTP   `json:"http,omitempty"`
}

type WebpropertyResource struct {
	Endpoints []Endpoint
}

type Webproperty struct {
	Resource WebpropertyResource
}

type SearchQueryHit struct {
	WebpropertyV1 *Webproperty
}

type SearchQueryResponse struct {
	Hits          []SearchQueryHit
	NextPageToken string
}

type ResponseEnvelopeSearchQueryResponse struct {
	Result *SearchQueryResponse
}
