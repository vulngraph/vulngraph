# Governance

Vulngraph uses a lightweight, maintainer-led model (a "benevolent dictator"
structure) suitable for a young project. It will be revisited as the
contributor base grows.

## Roles

- **Lead maintainer** -- [@Flipmonster](https://github.com/Flipmonster). Has
  final say when consensus cannot be reached, and owns releases and repository
  settings.
- **Maintainers** -- listed in [`MAINTAINERS.md`](MAINTAINERS.md). Review and
  merge PRs, triage issues.
- **Contributors** -- anyone who opens an issue, PR, or discussion.

## How decisions are made

- Day-to-day changes: a PR approved by one maintainer (not the author) may be
  merged. While the lead maintainer is the only maintainer, they may merge
  their own PRs once CI is green.
- **Today there is one maintainer** ([`MAINTAINERS.md`](MAINTAINERS.md)), so
  in practice no second person reviews a change or a release before it ships:
  CI is the only check besides the author. Weigh that when you decide what
  access to give a deployment.
- Larger changes (features, connectors, data model, API contract) start with
  an ADR ([`docs/adr/`](docs/adr/README.md)) or a spec
  ([`docs/specs/`](docs/specs/README.md)); discussion happens in that PR.
- We aim for lazy consensus: if no maintainer objects within a reasonable
  review window, the proposal proceeds. Disagreements are resolved by
  discussion first, then by the lead maintainer.
- Security reports are handled privately per [`SECURITY.md`](SECURITY.md).

## Becoming a maintainer

Contributors who have made sustained, high-quality contributions (code,
review, triage, docs) and follow the [Code of Conduct](CODE_OF_CONDUCT.md)
may be nominated by any maintainer. The nomination is approved if the lead
maintainer and a majority of existing maintainers agree. New maintainers are
added to `MAINTAINERS.md` and the GitHub team.

Maintainers who are inactive for an extended period may be moved to emeritus
status; they are welcome back on request.

## Changes to governance

Via a PR to this file, approved by the lead maintainer.
