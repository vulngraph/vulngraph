package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const maxSnapshotTimeout = 15 * time.Second

// SnapshotData is the captured state of an asset at a point in time.
type SnapshotData struct {
	TLSVersion      string            `json:"tls_version,omitempty"`
	CertExpiryDays  int               `json:"cert_expiry_days,omitempty"`
	OpenPorts       []int             `json:"open_ports,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ServerHeader    string            `json:"server_header,omitempty"`
	StatusCode      int               `json:"status_code,omitempty"`
	ContentLength   int64             `json:"content_length,omitempty"`
	CapturedAt      time.Time         `json:"captured_at"`
}

// CaptureHTTP issues a HEAD (falling back to GET) against endpoint and returns
// a SnapshotData populated from the response. timeout is capped at 15s.
//
// The client blocks private, loopback, link-local and metadata addresses at
// dial time (safenet.New). allowInternal — pass AllowInternalTargets(), never a
// hard-coded true — opens ordinary private space only: link-local and the cloud
// metadata endpoints stay blocked (snapshotClient).
func CaptureHTTP(ctx context.Context, endpoint string, timeout time.Duration, allowInternal bool) (SnapshotData, error) {
	if endpoint == "" {
		return SnapshotData{}, fmt.Errorf("CaptureHTTP: endpoint must not be empty")
	}

	if timeout <= 0 || timeout > maxSnapshotTimeout {
		timeout = maxSnapshotTimeout
	}

	client, err := snapshotClient(timeout, allowInternal)
	if err != nil {
		return SnapshotData{}, fmt.Errorf("CaptureHTTP: %w", err)
	}

	snap, err := doCapture(ctx, client, endpoint)
	if err != nil {
		return SnapshotData{}, fmt.Errorf("CaptureHTTP %s: %w", endpoint, err)
	}
	return snap, nil
}

// internalAllowPrefixes is the private space AllowInternalTargetsEnv opens for
// snapshots. It deliberately leaves out link-local and the NAT64/6to4/Teredo
// translation prefixes (safenet.ParseAllowPrefixes refuses both), and the
// guarded transport refuses the metadata addresses inside these ranges
// (fd00:ec2::254, 100.100.100.200, 192.0.0.192) whatever the allow list says.
const internalAllowPrefixes = "0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,172.16.0.0/12," +
	"192.0.0.0/24,192.168.0.0/16,198.18.0.0/15,::/96,::1/128,fc00::/7"

// snapshotClient is safenet.New, or with allowInternal a guarded transport that
// reaches internalAllowPrefixes but never link-local or cloud metadata.
func snapshotClient(timeout time.Duration, allowInternal bool) (*http.Client, error) {
	if !allowInternal {
		return safenet.New(timeout), nil
	}
	allow, err := safenet.ParseAllowPrefixes(internalAllowPrefixes)
	if err != nil {
		return nil, fmt.Errorf("snapshotClient: %w", err)
	}
	return safenet.NewWithTransport(timeout, safenet.NewGuardedTransport(timeout, allow)), nil
}

// doCapture performs the actual HEAD→GET request sequence and populates the snapshot.
func doCapture(ctx context.Context, client *http.Client, endpoint string) (SnapshotData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return SnapshotData{}, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// HEAD rejected by some servers — fall back to GET.
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err2 != nil {
			return SnapshotData{}, fmt.Errorf("build GET fallback request: %w", err2)
		}
		resp, err = client.Do(req2)
		if err != nil {
			return SnapshotData{}, fmt.Errorf("request failed: %w", err)
		}
	}
	defer resp.Body.Close() //nolint:errcheck // body drained by transport

	snap := SnapshotData{
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		CapturedAt:    time.Now().UTC(),
	}

	// Response headers — lowercase keys, first value only.
	if len(resp.Header) > 0 {
		snap.ResponseHeaders = make(map[string]string, len(resp.Header))
		for k, vv := range resp.Header {
			if len(vv) > 0 {
				snap.ResponseHeaders[strings.ToLower(k)] = vv[0]
			}
		}
	}

	snap.ServerHeader = resp.Header.Get("Server")

	// TLS state.
	if resp.TLS != nil {
		snap.TLSVersion = tlsVersionName(resp.TLS.Version)

		if len(resp.TLS.PeerCertificates) > 0 {
			leaf := resp.TLS.PeerCertificates[0]
			days := int(time.Until(leaf.NotAfter).Hours() / 24)
			if days < 0 {
				days = 0
			}
			snap.CertExpiryDays = days
		}
	}

	return snap, nil
}

// tlsVersionName converts a tls.VersionXxx constant to a human-readable label.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}
