-- name: GetEnrichmentSweepProgress :one
SELECT cursor_value, pass_before, revision FROM enrichment_sweep_progress WHERE id;

-- name: AdvanceEnrichmentSweepProgress :execrows
UPDATE enrichment_sweep_progress
SET cursor_value = @cursor_value, pass_before = sqlc.narg(pass_before), revision = revision + 1
WHERE id AND revision = @expected_revision;
