package awspolicy

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeDocument(t *testing.T) {
	const plain = `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::111122223333:role/Ops+Admin"}}`
	const literals = " {\n\"text\":\"é + %2B %25 %ZZ % \\u96ea\"\n} \t"
	const form = `{ "text": "space + percent%2B é" }`
	for _, tt := range []struct {
		name, input, want string
	}{
		{"plain", plain, plain},
		{"plain literal escapes and whitespace", literals, literals},
		{"RFC3986 encoded", strings.ReplaceAll(url.QueryEscape(literals), "+", "%20"), literals},
		{"encoded with literal plus", url.PathEscape(plain), plain},
		{"form encoded with syntax spaces", url.QueryEscape(form), form},
		{"ambiguous plus is literal RFC3986", `%7B%22text%22%3A%22a+b%22%7D`, `{"text":"a+b"}`},
		{"empty", "", ""},
		{"malformed escape", "%7B%GG%7D", "%7B%GG%7D"},
		{"encoded malformed JSON", "%7B%22Statement%22%3A", "%7B%22Statement%22%3A"},
		{"plain malformed JSON", `{"text":"+%2B"`, `{"text":"+%2B"`},
		{"double encoded", url.QueryEscape(url.QueryEscape(plain)), url.QueryEscape(url.QueryEscape(plain))},
		{"JSON string is not transport", `"%7B%22Statement%22%3A%5B%5D%7D"`, `"%7B%22Statement%22%3A%5B%5D%7D"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, NormalizeDocument(tt.input))
			require.Equal(t, tt.want, NormalizeDocument(NormalizeDocument(tt.input)))
		})
	}
}

func FuzzNormalizeDocumentIdempotent(f *testing.F) {
	for _, seed := range []string{"", "%", "%GG", "%25257B", `{"value":"+%2F"}`, `%7B%22value%22%3A%22%252F%2B%22%7D`, `%7B+%22value%22%3A+%22a%2Bb%22+%7D`, `{"value":"é雪"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got := NormalizeDocument(input)
		if json.Valid([]byte(input)) {
			require.Equal(t, input, got)
		}
		if got != input {
			require.True(t, json.Valid([]byte(got)))
		}
		require.Equal(t, got, NormalizeDocument(got))
	})
}

func FuzzNormalizeDocumentRoundTrip(f *testing.F) {
	for _, seed := range []string{"Ops+Admin", "a b", "%", "%2F", "%252F", "%GG", "é雪", "quote\" and slash\\", "+ %2B %25 %ZZ"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		data, err := json.MarshalIndent(map[string]string{"value": value}, "", "  ")
		require.NoError(t, err)
		doc := string(data)
		for _, input := range []string{doc, url.PathEscape(doc), url.QueryEscape(doc), strings.ReplaceAll(url.QueryEscape(doc), "+", "%20")} {
			require.Equal(t, doc, NormalizeDocument(input))
		}
	})
}
