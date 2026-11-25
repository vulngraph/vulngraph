package gcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	bigquery "google.golang.org/api/bigquery/v2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// bigQueryAPI is the slice of BigQuery the dataset posture needs (CIS GCP 7).
type bigQueryAPI interface {
	DatasetIDs(ctx context.Context, projectID string) ([]string, error)
	Dataset(ctx context.Context, projectID, datasetID string) (*bigquery.Dataset, error)
	// TableIDs lists the dataset's tables that hold data (type TABLE or
	// MATERIALIZED_VIEW); views and external tables have no storage to encrypt.
	TableIDs(ctx context.Context, projectID, datasetID string) ([]string, error)
	// TableKMSKey returns the table's encryptionConfiguration.kmsKeyName, "" if
	// it uses Google-managed encryption.
	TableKMSKey(ctx context.Context, projectID, datasetID, tableID string) (string, error)
}

// bigQueryTableLimit caps the per-table reads (tables.get) one sweep makes
// per project. The budget is spent in dataset-ID order, so the same datasets
// are graded every sweep; past it a dataset's table key stays absent.
const bigQueryTableLimit = 2000

// maxListedTables bounds the table names one dataset's evidence names.
const maxListedTables = 20

// bqDataset is one dataset's read: its asset metadata and its data tables.
type bqDataset struct {
	ds     *bigquery.Dataset
	md     map[string]string
	tables []string
	// listed: the table list was read (an empty list is a dataset with no tables).
	listed bool
}

// collectBigQuery inventories datasets: public access entries (CIS GCP 7.1),
// the default CMEK (7.3), and the tables encrypted with Google-managed keys
// (7.2) — every table carries its own key, whatever the dataset default.
// Reads happen in three steps so the table budget is deterministic: the
// datasets and their table lists (fanned out), the budget (in sorted order),
// then the table reads (fanned out).
func collectBigQuery(ctx context.Context, client bigQueryAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	ids, err := client.DatasetIDs(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectBigQuery: %w", err)
	}
	slices.Sort(ids)
	read := make([]*bqDataset, len(ids))
	var errs []error
	idx := make([]int, len(ids))
	for i := range idx {
		idx[i] = i
	}
	errs = append(errs, fanOut(ctx, "gcp bigquery dataset", idx, func(i int) error {
		ds, err := client.Dataset(ctx, projectID, ids[i])
		if err != nil {
			return err
		}
		d := &bqDataset{ds: ds, md: datasetMetadata(ds)}
		read[i] = d
		tables, err := client.TableIDs(ctx, projectID, ids[i])
		if err != nil {
			return err
		}
		d.tables, d.listed = tables, true
		return nil
	}))

	budget := bigQueryTableLimit
	var graded []int
	for i, d := range read {
		if d == nil || !d.listed {
			continue
		}
		if len(d.tables) > budget {
			log.FromContext(ctx).Warn().Str("dataset", ids[i]).Int("tables", len(d.tables)).
				Msg("gcp bigquery table read budget exhausted; table encryption not graded this sweep")
			budget = 0
			continue
		}
		budget -= len(d.tables)
		graded = append(graded, i)
	}
	// Over budget the key stays absent (unknown): a bounded read, not a
	// failed one — the dataset itself was enumerated, so not partial.
	errs = append(errs, fanOut(ctx, "gcp bigquery tables", graded, func(i int) error {
		return tablesWithoutCMEK(ctx, client, projectID, ids[i], read[i])
	}))

	var assets []asset.Asset
	for i, d := range read {
		if d == nil {
			continue
		}
		assets = append(assets, asset.Asset{
			ID: projectID + "/bigquery/" + ids[i], Name: ids[i], Type: "gcp_bigquery_dataset", Provider: asset.ProviderGCP,
			Region: strings.ToLower(d.ds.Location), AccountID: projectID, Tags: d.ds.Labels, Metadata: d.md,
			DiscoveredAt: now, LastSeen: now,
		})
	}
	if err := errors.Join(errs...); err != nil {
		return assets, fmt.Errorf("collectBigQuery: %w", err)
	}
	return assets, nil
}

// datasetMetadata records a dataset's public access entries and default key.
// Dataset ACLs grant the public through specialGroup allAuthenticatedUsers or
// an iamMember of allUsers / allAuthenticatedUsers.
func datasetMetadata(ds *bigquery.Dataset) map[string]string {
	var public []string
	for _, e := range ds.Access {
		if e == nil {
			continue
		}
		switch {
		case e.SpecialGroup == "allAuthenticatedUsers":
			public = append(public, "allAuthenticatedUsers="+e.Role)
		case e.IamMember == "allUsers" || e.IamMember == "allAuthenticatedUsers":
			public = append(public, e.IamMember+"="+e.Role)
		}
	}
	md := map[string]string{"public_access_entries": strings.Join(public, ","), "default_cmek": ""}
	if c := ds.DefaultEncryptionConfiguration; c != nil {
		md["default_cmek"] = c.KmsKeyName
	}
	return md
}

// tablesWithoutCMEK stamps tables_without_cmek_count (and up to
// maxListedTables names) on a dataset. A failed table read leaves the count
// absent unless a table was already seen without CMEK. Only this dataset's
// own map is written, so concurrent datasets never share state.
func tablesWithoutCMEK(ctx context.Context, client bigQueryAPI, projectID, datasetID string, d *bqDataset) error {
	var bad []string
	var errs []error
	for _, t := range d.tables {
		key, err := client.TableKMSKey(ctx, projectID, datasetID, t)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if key == "" {
			bad = append(bad, t)
		}
	}
	if len(bad) > 0 || len(errs) == 0 {
		d.md["tables_without_cmek_count"] = strconv.Itoa(len(bad))
		d.md["tables_without_cmek"] = strings.Join(bad[:min(len(bad), maxListedTables)], ",")
	}
	return errors.Join(errs...)
}

// newBigQueryClient builds the real bigQueryAPI via ADC.
func newBigQueryClient(ctx context.Context) (bigQueryAPI, error) {
	svc, err := bigquery.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newBigQueryClient: %w", err)
	}
	return &realBigQuery{svc: svc}, nil
}

type realBigQuery struct{ svc *bigquery.Service }

func (r *realBigQuery) DatasetIDs(ctx context.Context, projectID string) ([]string, error) {
	var out []string
	if err := r.svc.Datasets.List(projectID).All(true).Pages(ctx, func(p *bigquery.DatasetList) error {
		for _, d := range p.Datasets {
			if d != nil && d.DatasetReference != nil {
				out = append(out, d.DatasetReference.DatasetId)
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("DatasetIDs: %w", err)
	}
	return out, nil
}

func (r *realBigQuery) Dataset(ctx context.Context, projectID, datasetID string) (*bigquery.Dataset, error) {
	ds, err := r.svc.Datasets.Get(projectID, datasetID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("Dataset %s: %w", datasetID, err)
	}
	return ds, nil
}

func (r *realBigQuery) TableIDs(ctx context.Context, projectID, datasetID string) ([]string, error) {
	var out []string
	if err := r.svc.Tables.List(projectID, datasetID).Pages(ctx, func(p *bigquery.TableList) error {
		for _, t := range p.Tables {
			if t != nil && t.TableReference != nil && (t.Type == "TABLE" || t.Type == "MATERIALIZED_VIEW") {
				out = append(out, t.TableReference.TableId)
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("TableIDs %s: %w", datasetID, err)
	}
	return out, nil
}

func (r *realBigQuery) TableKMSKey(ctx context.Context, projectID, datasetID, tableID string) (string, error) {
	t, err := r.svc.Tables.Get(projectID, datasetID, tableID).View("BASIC").Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("TableKMSKey %s.%s: %w", datasetID, tableID, err)
	}
	if t.EncryptionConfiguration == nil {
		return "", nil
	}
	return t.EncryptionConfiguration.KmsKeyName, nil
}
