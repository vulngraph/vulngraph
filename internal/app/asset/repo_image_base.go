package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const (
	insertImageBases = `INSERT INTO image_bases
		(image_id, base_image, base_image_digest, base_image_source, base_os, scanned_at)`

	// selectImageBases reads every recorded identity, one row per image. A
	// full-table read (the table holds one row per digest scanned inside its
	// 30-day TTL, a few thousand at most), collapsed with argMax rather than
	// FINAL so a version that lands mid-read cannot duplicate an image.
	selectImageBases = `SELECT image_id,
		argMax(base_image, scanned_at), argMax(base_image_digest, scanned_at),
		argMax(base_image_source, scanned_at), argMax(base_os, scanned_at),
		max(scanned_at)
		FROM image_bases
		GROUP BY image_id`

	imageBaseTimeout = 20 * time.Second
)

// UpsertImageBases records the base identity of scanned images.
func (r *CHRepo) UpsertImageBases(ctx context.Context, bases []ImageBase) error {
	if len(bases) == 0 {
		return nil
	}
	qCtx, cancel := context.WithTimeout(ctx, imageBaseTimeout)
	defer cancel()
	err := r.ch.Batch(qCtx, insertImageBases, func(b driver.Batch) error {
		for _, ib := range bases {
			if err := b.Append(ib.ImageID, ib.BaseImage, ib.BaseImageDigest,
				ib.BaseImageSource, ib.BaseOS, ib.ScannedAt); err != nil {
				return fmt.Errorf("append image base %s: %w", ib.ImageID, err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("UpsertImageBases: %w", err)
	}
	return nil
}

// ImageBases returns every recorded image base identity.
func (r *CHRepo) ImageBases(ctx context.Context) ([]ImageBase, error) {
	qCtx, cancel := context.WithTimeout(ctx, imageBaseTimeout)
	defer cancel()
	var out []ImageBase
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var ib ImageBase
			if err := rows.Scan(&ib.ImageID, &ib.BaseImage, &ib.BaseImageDigest,
				&ib.BaseImageSource, &ib.BaseOS, &ib.ScannedAt); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, ib)
		}
		return nil
	}, selectImageBases)
	if err != nil {
		return nil, fmt.Errorf("ImageBases: %w", err)
	}
	return out, nil
}
