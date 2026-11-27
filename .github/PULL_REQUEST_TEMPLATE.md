## What and why

## Testing

- [ ] `go vet ./... && golangci-lint run`
- [ ] `go test ./...`
- [ ] `go test -tags=integration -p 1 -count=1 ./...` after `go run ./cmd/graph migrate` (if this touches storage/graph/jobs)
- [ ] `cd frontend && bun run lint && bun run test && bun run build` (if this touches the frontend)

## Checklist

- [ ] Tests land in this PR, not a follow-up
- [ ] Touches an existing ADR's territory (`docs/adr/`)? Linked it, or added a
      new ADR that supersedes it if the decision changed
- [ ] Larger change? Linked the ADR or spec it follows (see `CONTRIBUTING.md`)
- [ ] Every commit is signed off (`git commit -s`, see `CONTRIBUTING.md`)
- [ ] Changes an API request or response shape? Updated the matching
      `openapi/domains/*.yaml` in the same PR and ran `cd frontend && bun run gen:api`
- [ ] Regenerated any generated file whose source changed (table in `CONTRIBUTING.md`)
- [ ] No secrets, internal hostnames, or credentials in code, tests, or
      commit messages

## Performance impact

- Affected workload family IDs from `docs/performance/workloads.json` (or explain
  why this changes no workload):
- Registration/service/journey changes reconciled with `go run ./cmd/perf-inventory -check`:
- For a cost change: matched baseline/candidate source, fixture, hardware and raw
  evidence; exact correctness and query/read-byte/memory/request/cardinality gates:
- Evidence invalidated by code/schema/dependency/profile changes, and remaining
  native/aged/mixed/recovery scenarios (unmeasured is not a pass):
