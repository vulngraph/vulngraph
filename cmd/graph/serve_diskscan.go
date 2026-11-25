package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

// serveDiskScan builds the serve pod's disk-scan service. It only reads runs
// and results; the connector source is never asked for settings here, so the
// mode view is enough.
func serveDiskScan(pool *pgxpool.Pool) *diskscan.Service {
	return diskscan.NewService(diskscan.NewPGRepo(pool), diskscan.NewModeView(pool))
}

// diskScanControl adapts the connector service to the handler's
// ConnectorControl. It is the only place connector sentinels meet diskscan's.
type diskScanControl struct{ svc *connector.Service }

var _ diskscan.ConnectorControl = diskScanControl{}

func (a diskScanControl) Info(ctx context.Context, id string) (diskscan.ConnectorInfo, error) {
	c, err := a.svc.Get(ctx, id)
	if err != nil {
		return diskscan.ConnectorInfo{}, fmt.Errorf("Info: %w", mapConnectorErr(err))
	}
	role, _ := connector.DiskScanRoles(c.Type, c.Config)
	info := diskscan.ConnectorInfo{
		ConnectorID: c.ID, Type: string(c.Type), Mode: c.DiskScanMode, Role: role,
		EnabledBy: c.DiskScanEnabledBy, Confirmation: connector.DiskScanConfirmation,
	}
	if c.DiskScanEnabledAt != nil {
		info.EnabledAt = *c.DiskScanEnabledAt
	}
	return info, nil
}

func (a diskScanControl) SetMode(ctx context.Context, id string, mode diskscan.DiskScanMode, confirmation string, actor diskscan.Actor) error {
	err := a.svc.SetDiskScanMode(ctx, id, mode, confirmation,
		connector.DiskScanActor{ID: actor.ID, Admin: actor.Admin, ViaAPIKey: actor.ViaAPIKey})
	if err != nil {
		return fmt.Errorf("SetMode: %w", mapConnectorErr(err))
	}
	return nil
}

// mapConnectorErr rewrites a connector refusal as the diskscan sentinel the
// handler maps to a status. Anything else passes through and becomes a 500.
func mapConnectorErr(err error) error {
	switch {
	case errors.Is(err, connector.ErrNotFound):
		return diskscan.ErrNotFound
	case errors.Is(err, connector.ErrDiskScanForbidden):
		return diskscan.ErrForbidden
	case errors.Is(err, connector.ErrDiskScanInvalidMode):
		return diskscan.ErrInvalid
	case errors.Is(err, connector.ErrDiskScanConfirmation):
		return diskscan.ErrConfirmation
	case errors.Is(err, connector.ErrDiskScanUnsupported):
		return diskscan.ErrUnsupported
	case errors.Is(err, connector.ErrDiskScanRoleMissing):
		return diskscan.ErrRoleMissing
	case errors.Is(err, connector.ErrDiskScanRoleShared):
		return diskscan.ErrRoleShared
	}
	return err
}

// diskScanStamps reads the disk_scan state the sync overlay stamped on a VM.
type diskScanStamps struct{ assets *asset.Service }

var _ diskscan.AssetStamps = diskScanStamps{}

func (a diskScanStamps) DiskScanStamp(ctx context.Context, id string) (state, gap string, err error) {
	as, err := a.assets.Get(ctx, id)
	if err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			return "", "", diskscan.ErrNotFound
		}
		return "", "", fmt.Errorf("DiskScanStamp: %w", err)
	}
	return as.Metadata[asset.MetaDiskScan], as.Metadata[asset.MetaDiskScanGap], nil
}

// newDiskScanHandler wires the disk-scan HTTP handler for the serve pod.
func newDiskScanHandler(svc *diskscan.Service, connectors *connector.Service, assets *asset.Service) *diskscan.Handler {
	return diskscan.NewHandler(svc, diskScanStamps{assets: assets}, diskScanControl{svc: connectors}, diskScanActor)
}

// diskScanActor builds the actor from what RequireAuth attached. A request with
// neither a session user nor a key yields an actor that is not an admin.
func diskScanActor(ctx context.Context) diskscan.Actor {
	_, viaKey := auth.APIKeyFromContext(ctx)
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return diskscan.Actor{ViaAPIKey: viaKey}
	}
	return diskscan.Actor{ID: u.ID, Admin: u.Role == auth.RoleAdmin, ViaAPIKey: viaKey}
}
