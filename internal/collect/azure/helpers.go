package azure

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// publicAccessUnknown is the `public_access` value written when the response
// carried no properties to grade public exposure from; the "public" key is then
// left out, so the resource's public check is not evaluable. Same string as
// graphstore.PublicAccessUnknown, duplicated because a collector must not
// import graphstore; graphstore's TestPublicAccessUnknownLiteral pins the pair.
const publicAccessUnknown = "unknown"

// publicPossibleIf returns the possible public-access tier when public is set
// and "" otherwise — for signals that prove network reachability but not
// unauthenticated access.
func publicPossibleIf(public bool) string {
	if public {
		return asset.PublicAccessPossible
	}
	return ""
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func boolStr(b bool) string {
	return fmt.Sprintf("%t", b)
}

func httpsURL(host string) string {
	if host == "" {
		return ""
	}
	return "https://" + host
}

// resourceGroup extracts the resource group name from an Azure resource ID.
// /subscriptions/{sub}/resourceGroups/{rg}/providers/...
func resourceGroup(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// nicName extracts the NIC resource name from its full resource ID.
func nicName(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func azTags(tags map[string]*string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		if v != nil {
			out[k] = *v
		}
	}
	return out
}

func parseInt32(s string) int32 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 32)
	return int32(n)
}

func marshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// countTypes counts the assets whose Type is one of types — used to size a
// collect.Result.MarkComplete call from a slice already known (by the
// caller's own error handling) to be a complete enumeration, without every
// collector function needing to return per-type counts separately.
func countTypes(assets []asset.Asset, types ...string) int {
	want := make(map[string]bool, len(types))
	for _, t := range types {
		want[t] = true
	}
	n := 0
	for _, a := range assets {
		if want[a.Type] {
			n++
		}
	}
	return n
}
