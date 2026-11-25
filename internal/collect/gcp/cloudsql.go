package gcp

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// cloudSQLInstance is a provider-neutral view of a Cloud SQL instance — the
// security-relevant fields only (public exposure, SSL enforcement, backups).
type cloudSQLInstance struct {
	Name                      string
	Region                    string
	Version                   string
	PublicIP                  string // first PRIMARY public address, "" if none
	HasPublic                 bool   // ipv4 (public) IP enabled
	RequireSSL                bool
	Backups                   bool
	DeletionProtectionEnabled bool
	StorageAutoResize         bool
	BinaryLogEnabled          bool
	// SSLMode is ipConfiguration.sslMode, which supersedes the legacy requireSsl:
	// an instance enforcing TLS through ENCRYPTED_ONLY reports requireSsl=false.
	SSLMode string
	// AuthorizedNetworks are the CIDRs allowed to reach the public IP.
	AuthorizedNetworks []string
	// Flags are settings.databaseFlags, name → lower-cased value.
	Flags map[string]string

	// SettingsObserved / BackupObserved record whether the API actually returned
	// the sub-object each group of flags is read from. Without them every bool
	// above is a Go zero value on a nil Settings or nil BackupConfiguration, and
	// `false` is the precise value gcp-cloudsql-no-backup and
	// gcp-cloudsql-deletion-protection-disabled fire on — the collector would
	// hand the checks the violation they require evidence
	// for. Unobserved settings are omitted from the metadata entirely.
	SettingsObserved bool
	BackupObserved   bool
	// IPConfigObserved records whether ipConfiguration itself came back. Without
	// it HasPublic is a Go zero value on a nil IpConfiguration and the collector
	// reports "observed, not public" for an instance it never read — which is what
	// let the DSPM public tile treat a measurement gap as a fact.
	IPConfigObserved bool
}

// cloudSQLAPI is the slice of the Cloud SQL Admin API the collector needs.
type cloudSQLAPI interface {
	ListInstances(ctx context.Context, projectID string) ([]cloudSQLInstance, error)
}

// collectCloudSQL maps Cloud SQL instances to assets. A public-IP instance is a
// real internet entry point, so the reachability rule treats it as
// exposed; SSL/backup flags drive posture checks.
func collectCloudSQL(ctx context.Context, client cloudSQLAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	instances, err := client.ListInstances(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectCloudSQL: %w", err)
	}
	var assets []asset.Asset
	for _, in := range instances {
		if in.Name == "" {
			continue
		}
		md := map[string]string{
			"version": in.Version,
			// public stays unconditional: an unobserved instance reads as
			// not-public, which suppresses an exposure edge rather than inventing
			// one. Only the settings that a check turns INTO a finding are gated.
			"public": fmt.Sprintf("%t", in.HasPublic),
			// A public IPv4 is network reachability only — DB credentials are
			// always required (and authorized-networks may be empty), so
			// exposure is possible, never confirmed.
			//
			// When the API returned no ipConfiguration at all, HasPublic is a Go
			// zero value, not an answer. Reporting "" there would make an unobserved
			// instance indistinguishable from an observed-private one, and the DSPM
			// public tile would count the difference as fact. The tier says
			// unknown, which graphstore grades as publicTierUnknown (a coverage
			// gap) rather than folding it into either population.
			"public_access": cloudSQLPublicTier(in),
		}
		// require_ssl, ssl_mode and the authorized networks are all read from
		// ipConfiguration, so they are evidence only when it came back; gating
		// require_ssl on Settings alone wrote a Go zero "false" for an instance
		// whose ipConfiguration was never returned.
		if in.IPConfigObserved {
			md["require_ssl"] = fmt.Sprintf("%t", in.RequireSSL)
			md["ssl_mode"] = in.SSLMode
			md["authorized_networks"] = strings.Join(in.AuthorizedNetworks, ",")
			md["authorized_networks_world"] = fmt.Sprintf("%t", worldAuthorizedNetwork(in.AuthorizedNetworks))
		}
		if in.SettingsObserved {
			maps.Copy(md, dbFlagMetadata(in.Version, in.Flags))
			md["deletion_protection_enabled"] = fmt.Sprintf("%t", in.DeletionProtectionEnabled)
			md["storage_auto_resize"] = fmt.Sprintf("%t", in.StorageAutoResize)
		}
		if in.BackupObserved {
			md["backups"] = fmt.Sprintf("%t", in.Backups)
			md["log_bin"] = boolToEnabledStr(in.BinaryLogEnabled)
		}
		assets = append(assets, asset.Asset{
			ID:           projectID + "/cloudsql/" + in.Name,
			Name:         in.Name,
			Type:         "cloudsql_instance",
			Provider:     asset.ProviderGCP,
			Region:       in.Region,
			AccountID:    projectID,
			PublicIP:     in.PublicIP,
			Metadata:     md,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

// newCloudSQLClient builds a real Cloud SQL Admin-backed client via ADC.
func newCloudSQLClient(ctx context.Context) (cloudSQLAPI, error) {
	svc, err := sqladmin.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newCloudSQLClient: %w", err)
	}
	return &realCloudSQL{svc: svc}, nil
}

type realCloudSQL struct {
	svc *sqladmin.Service
}

func (r *realCloudSQL) ListInstances(ctx context.Context, projectID string) ([]cloudSQLInstance, error) {
	var out []cloudSQLInstance
	pageToken := ""
	for {
		call := r.svc.Instances.List(projectID).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("ListInstances: %w", err)
		}
		for _, in := range resp.Items {
			out = append(out, toNeutralCloudSQL(in))
		}
		// Paginate: an instance past page 1 would otherwise never become an
		// asset, leaving an exposed Cloud SQL instance invisible to the graph.
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return out, nil
}

// publicAccessUnknown is the `public_access` value a GCP collector writes when
// public exposure was never observed: a Cloud SQL instance returned without an
// ipConfiguration, or a bucket, image or snapshot whose IAM policy could not be
// read. Same string as graphstore.PublicAccessUnknown, duplicated because a
// collector must not import graphstore and the asset package does not define
// it; graphstore's TestPublicAccessUnknownLiteral pins the pair.
const publicAccessUnknown = "unknown"

// cloudSQLPublicTier grades a Cloud SQL instance's public exposure:
// possible when a public IPv4 is enabled (network reachability, credentials still
// required — never confirmed), none when the ipConfiguration was read and no
// public IP is enabled, unknown when the ipConfiguration was not returned at all.
func cloudSQLPublicTier(in cloudSQLInstance) string {
	if !in.IPConfigObserved {
		return publicAccessUnknown
	}
	if in.HasPublic {
		return asset.PublicAccessPossible
	}
	return asset.PublicAccessNone
}

// boolToEnabledStr returns "true" when b is true and "" otherwise. Used for
// fields where the absence of a value is semantically distinct from false (e.g.
// log_bin: unset means the engine does not support it).
func boolToEnabledStr(b bool) string {
	if b {
		return "true"
	}
	return ""
}

func toNeutralCloudSQL(in *sqladmin.DatabaseInstance) cloudSQLInstance {
	c := cloudSQLInstance{
		Name:    in.Name,
		Region:  in.Region,
		Version: in.DatabaseVersion,
	}
	if s := in.Settings; s != nil {
		c.SettingsObserved = true
		if s.IpConfiguration != nil {
			c.IPConfigObserved = true
			c.HasPublic = s.IpConfiguration.Ipv4Enabled
			c.RequireSSL = s.IpConfiguration.RequireSsl
			c.SSLMode = s.IpConfiguration.SslMode
			for _, n := range s.IpConfiguration.AuthorizedNetworks {
				if n != nil && strings.TrimSpace(n.Value) != "" {
					c.AuthorizedNetworks = append(c.AuthorizedNetworks, strings.TrimSpace(n.Value))
				}
			}
		}
		if s.BackupConfiguration != nil {
			c.BackupObserved = true
			c.Backups = s.BackupConfiguration.Enabled
			c.BinaryLogEnabled = s.BackupConfiguration.BinaryLogEnabled
		}
		c.DeletionProtectionEnabled = s.DeletionProtectionEnabled
		c.Flags = map[string]string{}
		for _, f := range s.DatabaseFlags {
			if f != nil && f.Name != "" {
				c.Flags[f.Name] = strings.ToLower(strings.TrimSpace(f.Value))
			}
		}
		if s.StorageAutoResize != nil {
			c.StorageAutoResize = *s.StorageAutoResize
		}
	}
	for _, ip := range in.IpAddresses {
		if strings.EqualFold(ip.Type, "PRIMARY") && ip.IpAddress != "" {
			c.PublicIP = ip.IpAddress
			break
		}
	}
	return c
}
