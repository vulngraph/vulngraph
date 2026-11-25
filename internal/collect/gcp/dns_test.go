package gcp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/api/dns/v1"
)

func TestZoneMetadata_DNSSEC(t *testing.T) {
	on := zoneMetadata(&dns.ManagedZone{Name: "z", Visibility: "public", DnssecConfig: &dns.ManagedZoneDnsSecConfig{
		State: "on",
		DefaultKeySpecs: []*dns.DnsKeySpec{
			{KeyType: "keySigning", Algorithm: "RSASHA1"},
			{KeyType: "zoneSigning", Algorithm: "ecdsap256sha256"},
			nil,
		},
	}})
	require.Equal(t, "on", on["dnssec_state"])
	require.Equal(t, "rsasha1", on["dnssec_ksk_algorithms"])
	require.Equal(t, "ecdsap256sha256", on["dnssec_zsk_algorithms"])
	require.Equal(t, "public", on["visibility"])

	bare := zoneMetadata(&dns.ManagedZone{Name: "z"})
	require.Equal(t, "public", bare["visibility"], "visibility defaults to public")
	require.Equal(t, "off", bare["dnssec_state"], "an omitted dnssecConfig on a public zone is the default, off")

	private := zoneMetadata(&dns.ManagedZone{Name: "p", Visibility: "private"})
	require.Equal(t, "private", private["visibility"])
	require.NotContains(t, private, "dnssec_state", "private zones have no DNSSEC to grade")
}
