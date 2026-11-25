package awspolicy

import (
	"encoding/json"
	"net/url"
)

// NormalizeDocument accepts plain JSON and one URL-encoded IAM document layer.
// Already-valid JSON is preserved byte-for-byte, including literal + and %XX
// sequences. Only a decode that yields JSON is accepted, making normalization
// idempotent even for malformed or doubly encoded inputs; callers still perform
// their own policy-shape validation.
//
// IAM specifies RFC 3986 encoding, where + is literal. For compatibility with
// form-encoded imports, query decoding is tried only if percent decoding does
// not produce JSON. Ambiguous + inside a string therefore stays literal.
// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html
func NormalizeDocument(doc string) string {
	if json.Valid([]byte(doc)) {
		return doc
	}
	if decoded, err := url.PathUnescape(doc); err == nil && json.Valid([]byte(decoded)) {
		return decoded
	}
	if decoded, err := url.QueryUnescape(doc); err == nil && json.Valid([]byte(decoded)) {
		return decoded
	}
	return doc
}
