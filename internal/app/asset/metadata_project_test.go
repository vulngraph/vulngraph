package asset

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func keepSet(keys ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}

// filterFull is the definition decodeMapKeep must satisfy: decode everything the
// trusted way, then drop what was not asked for. The whole point of decodeMapKeep is
// to reach this answer without allocating the discarded values, so any divergence is
// a bug in the fast path — silently wrong graph columns, not a crash.
func filterFull(s string, keep map[string]struct{}) map[string]string {
	full := decodeMap(s)
	if full == nil {
		return nil
	}
	var out map[string]string
	for k, v := range full {
		if _, want := keep[k]; !want {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(keep))
		}
		out[k] = v
	}
	return out
}

func TestDecodeMapKeepMatchesDecodeMap(t *testing.T) {
	keep := keepSet("public", "encryption", "trust_entry")

	cases := []struct {
		name string
		in   string
	}{
		{"empty string", ""},
		{"empty object", "{}"},
		{"empty object with space", "{ }"},
		{"single wanted", `{"public":"true"}`},
		{"single unwanted", `{"permissions":"s3:*"}`},
		{"mixed", `{"permissions":"s3:*","public":"true","region":"eu-west-1"}`},
		{"all unwanted", `{"a":"1","b":"2"}`},
		{"whitespace everywhere", "{ \"public\" : \"true\" , \"x\" : \"y\" }"},
		{"newlines and tabs", "{\n\t\"public\":\t\"true\"\n}"},
		{"escaped quote in value", `{"public":"a\"b"}`},
		{"escaped backslash in value", `{"public":"a\\b"}`},
		{"escaped chars in unwanted value", `{"blob":"line1\nline2\t\"q\"","public":"true"}`},
		{"unicode escape in wanted value", `{"public":"café"}`},
		{"unicode escape in key", `{"public":"true"}`},
		{"empty value", `{"public":""}`},
		{"empty key", `{"":"x","public":"true"}`},
		{"value containing braces", `{"blob":"{\"nested\":\"json\"}","public":"true"}`},
		{"value containing comma and colon", `{"blob":"a,b:c","public":"true"}`},
		{"duplicate keys last wins", `{"public":"false","public":"true"}`},
		// Shapes that must fall back rather than be mis-parsed.
		{"nested object value", `{"policy":{"a":"b"},"public":"true"}`},
		{"array value", `{"tags":["a","b"],"public":"true"}`},
		{"number value", `{"count":3,"public":"true"}`},
		{"bool value", `{"flag":true,"public":"true"}`},
		{"null value", `{"x":null,"public":"true"}`},
		// Malformed: both paths must agree (decodeMap returns nil).
		{"truncated", `{"public":"tru`},
		{"not an object", `["public"]`},
		{"bare string", `"public"`},
		{"trailing garbage", `{"public":"true"} trailing`},
		{"missing colon", `{"public" "true"}`},
		{"trailing comma", `{"public":"true",}`},
		{"unclosed", `{"public":"true"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, filterFull(tc.in, keep), decodeMapKeep(tc.in, keep),
				"projected decode disagrees with decode-then-filter for %q", tc.in)
		})
	}
}

func TestDecodeMapKeepEmptyKeepSet(t *testing.T) {
	// No keys wanted means nothing to decode — and must not be confused with "all
	// keys", which is what a nil keep set means one layer up in scanAssetKeep.
	require.Nil(t, decodeMapKeep(`{"public":"true"}`, nil))
	require.Nil(t, decodeMapKeep(`{"public":"true"}`, keepSet()))
}

// TestDecodeMapKeepSkipsWithoutAllocating is the performance claim as a test: the
// discarded value must never be copied. A 512KiB blob (large
// gcp_service_account metadata can run to hundreds of KiB) is skipped and the result must hold only the
// small wanted value, sharing no memory with the blob.
func TestDecodeMapKeepSkipsWithoutAllocating(t *testing.T) {
	blob := strings.Repeat("x", 512*1024)
	in := `{"permissions":"` + blob + `","public":"true"}`
	got := decodeMapKeep(in, keepSet("public"))
	require.Equal(t, map[string]string{"public": "true"}, got)
	require.NotContains(t, got, "permissions")

	allocs := testingAllocsPerRun(func() {
		_ = decodeMapKeep(in, keepSet("public"))
	})
	// The wanted value slices the input; the map and keep set are the only real
	// allocations. Well under the ~512KiB an unmarshal-then-filter would copy.
	require.Less(t, allocs, int64(64*1024),
		"skipping a 512KiB value allocated %d bytes — the fast path is copying what it discards", allocs)
}

// TestScanFlatStringMapRejectsNonFlat pins that the fast path REFUSES shapes it cannot
// handle rather than returning a partial answer. A partial answer here would be a
// silently truncated metadata map, which is the failure mode this design avoids by
// falling back.
func TestScanFlatStringMapRejectsNonFlat(t *testing.T) {
	for _, in := range []string{
		`{"policy":{"a":"b"}}`,
		`{"tags":["a"]}`,
		`{"n":1}`,
		`{"b":true}`,
		`{"z":null}`,
		`[]`,
		`{`,
		`{"a":"b"} x`,
	} {
		_, ok := scanFlatStringMap(in, keepSet("a", "policy", "tags", "n", "b", "z"))
		require.False(t, ok, "scanFlatStringMap accepted a non-flat/invalid document: %q", in)
	}
}

// FuzzDecodeMapKeep asserts the equivalence on arbitrary input. The fast path is
// hand-rolled JSON scanning, which is exactly the kind of code that is correct on
// every case an author thinks of and wrong on the one they do not.
func FuzzDecodeMapKeep(f *testing.F) {
	seeds := []string{
		`{}`, `{"public":"true"}`, `{"a":"1","public":"2"}`,
		`{"blob":"{\"x\":1}","public":"true"}`, `{"p":{"n":"v"}}`,
		`{"n":1}`, `{"public":"café"}`, `{"a":"\\"}`, `{"":""}`,
		`{"public":"true"} `, `  {"public":"true"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	keep := keepSet("public", "encryption", "a")
	f.Fuzz(func(t *testing.T, s string) {
		got := decodeMapKeep(s, keep)
		want := filterFull(s, keep)
		require.Equal(t, want, got, "divergence on %q", s)

		// Whatever comes back must be a subset of a full decode, with identical
		// values — the projection may narrow, never alter.
		if got != nil {
			full := decodeMap(s)
			for k, v := range got {
				fv, ok := full[k]
				require.True(t, ok, "projected key %q absent from full decode of %q", k, s)
				require.Equal(t, fv, v, "projected value for %q differs from full decode", k)
			}
		}
		// Sanity: a correct-but-always-falling-back implementation would pass every
		// assertion above while saving nothing, so pin that the fast path really does
		// handle the real-world shape — a valid-UTF-8 flat map of string to string.
		//
		// Invalid UTF-8 is deliberately excluded: encoding/json accepts it by
		// substituting U+FFFD, and scanFlatStringMap defers rather than reproducing
		// that rewrite. Correctness is unaffected (the equality assertion above still
		// holds via the fallback) and collector metadata is valid UTF-8, so the
		// deferral costs nothing real.
		var probe map[string]string
		if utf8.ValidString(s) && json.Unmarshal([]byte(s), &probe) == nil && len(probe) > 0 {
			_, ok := scanFlatStringMap(s, keep)
			require.True(t, ok,
				"json accepts %q as a flat map[string]string but the fast path refused it — "+
					"the projection would fall back on real collector metadata and save nothing", s)
		}
	})
}

// testingAllocsPerRun reports bytes allocated by one call to fn, measured over a few
// runs to smooth GC noise. testing.AllocsPerRun counts allocation COUNT, not size, and
// the claim here is about the 512KiB copy that must not happen.
func testingAllocsPerRun(fn func()) int64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const runs = 5
	for i := 0; i < runs; i++ {
		fn()
	}
	runtime.ReadMemStats(&after)
	return int64((after.TotalAlloc - before.TotalAlloc) / runs)
}

// realisticMetadata builds a metadata document shaped like a worst case:
// a gcp_service_account carrying a large permissions blob plus the handful of small
// keys the graph loader actually reads.
func realisticMetadata(blobKiB int) string {
	var b strings.Builder
	b.WriteString(`{"permissions":"`)
	b.WriteString(strings.Repeat("iam.serviceAccounts.actAs,", blobKiB*1024/26))
	b.WriteString(`","policies":"`)
	b.WriteString(strings.Repeat("roles/editor,", 512))
	b.WriteString(`","project":"example-prod","email":"sa@example-prod.iam.gserviceaccount.com",`)
	b.WriteString(`"trust_entry":"serviceAccount:sa@example-prod.iam","grants_admin":"true",`)
	b.WriteString(`"public":"false","disabled":"false"}`)
	return b.String()
}

func BenchmarkDecodeMapFull(b *testing.B) {
	in := realisticMetadata(70)
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if m := decodeMap(in); len(m) == 0 {
			b.Fatal("expected a decoded map")
		}
	}
}

func BenchmarkDecodeMapKeepProjected(b *testing.B) {
	in := realisticMetadata(70)
	keep := keepSet("trust_entry", "grants_admin", "public")
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if m := decodeMapKeep(in, keep); len(m) != 3 {
			b.Fatalf("expected 3 keys, got %d", len(m))
		}
	}
}

// TestDecodeMapKeepDoesNotPinTheSourceDocument is the test that was missing.
//
// The projection's whole purpose is to not retain the bytes it discards. But a Go
// substring shares its backing array, so returning `quoted[1:len-1]` for an unescaped
// value made every kept key/value pin the ENTIRE raw document — silently undoing the
// win while every existing test still passed, because an aliased string compares equal
// to a cloned one and the live-heap breakdown measures maps decoded from a gob snapshot
// where the aliasing path never runs.
//
// This asserts the property directly: keep one tiny value out of a document dominated
// by a huge discarded one, and the result must not be backed by that document. Compared
// via unsafe.StringData, because equality cannot distinguish the two.
func TestDecodeMapKeepDoesNotPinTheSourceDocument(t *testing.T) {
	blob := strings.Repeat("p", 512*1024) // stands in for an iam_role's policy blobs
	doc := `{"permissions":"` + blob + `","trust_entry":"arn:aws:iam::1:root"}`

	got := decodeMapKeep(doc, keepSet("trust_entry"))
	require.Equal(t, map[string]string{"trust_entry": "arn:aws:iam::1:root"}, got)

	kept := got["trust_entry"]
	docStart := uintptr(unsafe.Pointer(unsafe.StringData(doc)))
	keptStart := uintptr(unsafe.Pointer(unsafe.StringData(kept)))
	require.False(t, keptStart >= docStart && keptStart < docStart+uintptr(len(doc)),
		"the kept value points INTO the source document (offset %d of %d bytes), so it pins "+
			"the whole thing — including the %d-byte value the projection was meant to discard. "+
			"unquoteJSONString must strings.Clone the no-escape path.",
		keptStart-docStart, len(doc), len(blob))

	// The escaped path already allocates via strconv.Unquote; assert it too so a future
	// "optimisation" cannot reintroduce aliasing there.
	esc := `{"permissions":"` + blob + `","trust_entry":"a\"b"}`
	got2 := decodeMapKeep(esc, keepSet("trust_entry"))
	require.Equal(t, `a"b`, got2["trust_entry"])
	k2 := uintptr(unsafe.Pointer(unsafe.StringData(got2["trust_entry"])))
	e2 := uintptr(unsafe.Pointer(unsafe.StringData(esc)))
	require.False(t, k2 >= e2 && k2 < e2+uintptr(len(esc)),
		"escaped path aliases the source document")
}
