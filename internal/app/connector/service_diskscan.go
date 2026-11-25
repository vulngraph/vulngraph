package connector

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

// SetDiskScanMode changes a connector's disk-scan opt-in. The change is the
// standing approval for reading VM disks (and, in create_snapshots mode,
// creating short-lived tagged snapshots with the dedicated role), so the
// service itself refuses anything but an admin session: API keys never
// qualify, however they were scoped.
//
// Enabling needs the typed DiskScanConfirmation. create_snapshots also needs
// the disk-scan role key set; whenever a role is set it must differ from the
// connector's collection, read-only and execute roles. Every change writes a
// connector.disk_scan_change audit row.
func (s *Service) SetDiskScanMode(ctx context.Context, id string, mode diskscan.DiskScanMode, confirmation string, actor DiskScanActor) error {
	if !actor.Admin || actor.ViaAPIKey {
		return fmt.Errorf("SetDiskScanMode: %w", ErrDiskScanForbidden)
	}
	if !mode.Valid() {
		return fmt.Errorf("SetDiskScanMode: %w: %q", ErrDiskScanInvalidMode, mode)
	}
	c, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("SetDiskScanMode: %w", err)
	}
	if !DiskScanSupported(c.Type) {
		return fmt.Errorf("SetDiskScanMode: %w: %s", ErrDiskScanUnsupported, c.Type)
	}
	role, others := DiskScanRoles(c.Type, c.Config)
	if mode.Enabled() {
		if confirmation != DiskScanConfirmation {
			return fmt.Errorf("SetDiskScanMode: %w", ErrDiskScanConfirmation)
		}
		if diskScanRoleRequired(c.Type, mode) && role == "" {
			return fmt.Errorf("SetDiskScanMode: %w", ErrDiskScanRoleMissing)
		}
		if role != "" && slices.Contains(others, role) {
			return fmt.Errorf("SetDiskScanMode: %w", ErrDiskScanRoleShared)
		}
	}
	at := s.now().UTC()
	before, err := s.repo.SetDiskScan(ctx, id, mode, actor.ID, at)
	if err != nil {
		return fmt.Errorf("SetDiskScanMode: %w", err)
	}
	s.record(ctx, AuditActionDiskScanChange, id, map[string]any{
		"before": diskScanModeName(before),
		"after":  diskScanModeName(mode),
		"role":   role,
		"actor":  actor.ID,
		"at":     at.Format(time.RFC3339),
	})
	return nil
}

// diskScanRoleRequired reports whether the mode needs the dedicated principal.
// create_snapshots always does. Azure existing_snapshots does too: reading a
// snapshot needs a read SAS, which only the disk-scan principal may be granted.
// AWS and GCP read existing snapshots with the collection role.
func diskScanRoleRequired(t Type, mode diskscan.DiskScanMode) bool {
	switch mode {
	case diskscan.DiskScanModeCreateSnapshots:
		return true
	case diskscan.DiskScanModeExistingSnapshots:
		return t == TypeAzure
	}
	return false
}

// DiskScanSettings returns one connector's disk-scan mode and role
// identifiers, decrypting its config server-side only.
func (s *Service) DiskScanSettings(ctx context.Context, id string) (DiskScanSettings, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return DiskScanSettings{}, fmt.Errorf("DiskScanSettings: %w", err)
	}
	return diskScanSettingsOf(c), nil
}

// DiskScanEnabled returns the settings of every enabled connector whose
// disk-scan mode is not off.
func (s *Service) DiskScanEnabled(ctx context.Context) ([]DiskScanSettings, error) {
	list, err := s.repo.List(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("DiskScanEnabled: %w", err)
	}
	var out []DiskScanSettings
	for _, sc := range list {
		if !sc.DiskScanMode.Enabled() || !DiskScanSupported(sc.Type) {
			continue
		}
		c, err := s.Get(ctx, sc.ID)
		if err != nil {
			return nil, fmt.Errorf("DiskScanEnabled: %w", err)
		}
		out = append(out, diskScanSettingsOf(c))
	}
	return out, nil
}

func diskScanSettingsOf(c Connector) DiskScanSettings {
	role, others := DiskScanRoles(c.Type, c.Config)
	return DiskScanSettings{ConnectorID: c.ID, Type: c.Type, Mode: c.DiskScanMode, Role: role, OtherRoles: others}
}

func diskScanModeName(m diskscan.DiskScanMode) string {
	if m == diskscan.DiskScanModeOff {
		return diskScanOff
	}
	return string(m)
}
