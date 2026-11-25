package diskscan

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// ModeView is the scanner pod's ConnectorSource. That pod holds no grant on
// connectors, whose config column carries every credential; it reads only the
// disk_scan_connector_modes view (connector id and disk-scan mode). Role
// identifiers are not in the view: they travel in the sealed envelope each
// volume job carries.
type ModeView struct {
	q *sqlcgen.Queries
}

var _ ConnectorSource = (*ModeView)(nil)

func NewModeView(pool *pgxpool.Pool) *ModeView { return &ModeView{q: sqlcgen.New(pool)} }

// DiskScanSettings returns the connector's current mode. A connector that no
// longer exists reads as off.
func (v *ModeView) DiskScanSettings(ctx context.Context, connectorID string) (ConnectorSettings, error) {
	mode, err := v.q.GetDiskScanConnectorMode(ctx, connectorID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ConnectorSettings{ConnectorID: connectorID}, nil
		}
		return ConnectorSettings{}, fmt.Errorf("DiskScanSettings: %w", err)
	}
	set := ConnectorSettings{ConnectorID: connectorID, Mode: DiskScanMode(mode)}
	if mode == "off" {
		set.Mode = DiskScanModeOff
	}
	return set, nil
}

// DiskScanEnabled is not available on the scanner pod, which never plans.
func (v *ModeView) DiskScanEnabled(context.Context) ([]ConnectorSettings, error) {
	return nil, fmt.Errorf("DiskScanEnabled: the connector list is not readable on this pod: %w", ErrInvalid)
}
