package aws

import (
	"encoding/json"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

// IPv6 ranges land in the same cidrs list checks and correlate already parse
// (both match ::/0 as the world); prefix lists are kept as references.
func TestSGIngress_IPv6AndPrefixLists(t *testing.T) {
	raw := sgIngress([]ec2types.IpPermission{{
		IpProtocol: awssdk.String("tcp"),
		FromPort:   awssdk.Int32(22), ToPort: awssdk.Int32(22),
		IpRanges:      []ec2types.IpRange{{CidrIp: awssdk.String("10.0.0.0/8")}},
		Ipv6Ranges:    []ec2types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}},
		PrefixListIds: []ec2types.PrefixListId{{PrefixListId: awssdk.String("pl-0abc")}},
	}})

	var rules []map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &rules))
	require.Len(t, rules, 1)
	require.ElementsMatch(t, []any{"10.0.0.0/8", "::/0"}, rules[0]["cidrs"])
	require.Equal(t, []any{"pl-0abc"}, rules[0]["prefix_lists"])
}
