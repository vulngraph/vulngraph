package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/app/diskscan/envelope"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// diskScanEnvelopeKeyEnv names the key that seals a connector's disk-scan
// credentials for the scanner pod. It opens nothing else: the scanner never
// holds GRAPH_SECRET_KEY, and this is not derived from it on the pod.
const diskScanEnvelopeKeyEnv = "DISK_SCAN_ENVELOPE_KEY"

// diskScanConnectors adapts the connector service to the disk-scan service's
// ConnectorSource. Only the worker builds it: it decrypts connector config.
type diskScanConnectors struct{ svc *connector.Service }

var _ diskscan.ConnectorSource = diskScanConnectors{}

func settingsOf(s connector.DiskScanSettings) diskscan.ConnectorSettings {
	return diskscan.ConnectorSettings{
		ConnectorID: s.ConnectorID, Type: string(s.Type), Mode: s.Mode, Role: s.Role, OtherRoles: s.OtherRoles,
	}
}

func (a diskScanConnectors) DiskScanSettings(ctx context.Context, connectorID string) (diskscan.ConnectorSettings, error) {
	s, err := a.svc.DiskScanSettings(ctx, connectorID)
	if err != nil {
		return diskscan.ConnectorSettings{}, fmt.Errorf("DiskScanSettings: %w", err)
	}
	return settingsOf(s), nil
}

func (a diskScanConnectors) DiskScanEnabled(ctx context.Context) ([]diskscan.ConnectorSettings, error) {
	all, err := a.svc.DiskScanEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("DiskScanEnabled: %w", err)
	}
	out := make([]diskscan.ConnectorSettings, len(all))
	for i, s := range all {
		out[i] = settingsOf(s)
	}
	return out, nil
}

// diskScanOn reports whether DISK_SCAN_ENABLED is set, and the envelope key
// that must then be present on both the worker and the scanner pod.
func diskScanOn(getenv func(string) string) (bool, envelope.Key, error) {
	on, err := jobs.SwitchFromEnv(getenv, jobs.DiskScanEnabledEnv)
	if err != nil || !on {
		return false, envelope.Key{}, err
	}
	key, err := envelope.ParseKey(getenv(diskScanEnvelopeKeyEnv))
	if err != nil {
		return false, envelope.Key{}, fmt.Errorf("diskScanOn: %s is required with %s: %w", diskScanEnvelopeKeyEnv, jobs.DiskScanEnabledEnv, err)
	}
	return true, key, nil
}

// workerDiskScan builds the worker's disk scan wiring when DISK_SCAN_ENABLED is
// on, else nil (no workers, no periodics, no rows). Connectors still opt in one
// by one; this only decides whether the jobs exist.
func workerDiskScan(ctx context.Context, getenv func(string) string, pool *pgxpool.Pool,
	connectors *connector.Service, feeds jobs.Feeds) (*jobs.DiskScanDeps, error) {
	on, key, err := diskScanOn(getenv)
	if err != nil || !on {
		return nil, err
	}
	log.FromContext(ctx).Info().Msg("worker: disk scanning enabled (each connector still opts in)")
	return &jobs.DiskScanDeps{
		Service:  diskscan.NewService(diskscan.NewPGRepo(pool), diskScanConnectors{svc: connectors}),
		Clouds:   &diskClouds{key: key, connectors: connectors},
		Advisory: feeds.AdvisorySources(),
	}, nil
}

// scannerDiskScan builds the scanner pod's wiring. That pod reads no connector:
// the mode comes from the disk_scan_connector_modes view and the credentials
// from the envelope each volume job carries.
func scannerDiskScan(ctx context.Context, getenv func(string) string, pool *pgxpool.Pool) (*jobs.DiskScanDeps, error) {
	on, key, err := diskScanOn(getenv)
	if err != nil || !on {
		return nil, err
	}
	feeds, err := jobs.FeedsFromEnv(getenv)
	if err != nil {
		return nil, fmt.Errorf("scannerDiskScan: %w", err)
	}
	log.FromContext(ctx).Info().Msg("scanner: disk scan volume jobs enabled")
	return &jobs.DiskScanDeps{
		Service:  diskscan.NewService(diskscan.NewPGRepo(pool), diskscan.NewModeView(pool)),
		Clouds:   &diskClouds{key: key},
		Advisory: feeds.AdvisorySources(),
	}, nil
}
