//go:build integration

package httpsrv

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

// diskScanControl is the read half of cmd/graph's adapter over the connector
// service: enough for the contract test to see the real connector row.
type diskScanControl struct{ svc *connector.Service }

func (a diskScanControl) Info(ctx context.Context, id string) (diskscan.ConnectorInfo, error) {
	c, err := a.svc.Get(ctx, id)
	if errors.Is(err, connector.ErrNotFound) {
		return diskscan.ConnectorInfo{}, diskscan.ErrNotFound
	}
	if err != nil {
		return diskscan.ConnectorInfo{}, fmt.Errorf("Info: %w", err)
	}
	return diskscan.ConnectorInfo{
		ConnectorID: c.ID, Type: string(c.Type), Mode: c.DiskScanMode, Confirmation: connector.DiskScanConfirmation,
	}, nil
}

func (a diskScanControl) SetMode(context.Context, string, diskscan.DiskScanMode, string, diskscan.Actor) error {
	return diskscan.ErrForbidden
}

// noAssets reports every asset as unknown, so the asset route answers 404.
type noAssets struct{}

func (noAssets) DiskScanStamp(context.Context, string) (string, string, error) {
	return "", "", diskscan.ErrNotFound
}
