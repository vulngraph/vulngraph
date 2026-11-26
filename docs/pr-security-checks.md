# Keeping security checks enforced on pull requests

The `CI required` job in `.github/workflows/ci.yaml` aggregates every applicable
job. It runs even when upstream jobs fail, refuses missing results and rejects
failed, cancelled or unexpectedly skipped jobs. The release workflow calls the
same CI workflow before publishing an image. The CI concurrency group includes
the calling workflow and event so release verification does not cancel normal CI.

Repository settings are separate from these files. After this workflow has run
on a pull request, configure the public `vulngraph/vulngraph` repository's main
branch rule to:

- Require a pull request and the `CI required` status check before merging.
- Require the branch to be current, or use the supported merge-group workflow.
- Apply the rule to administrators and keep the bypass list empty unless an
  explicit emergency process needs it.
- Disallow force pushes and branch deletion; require resolved conversations.
- For security-sensitive changes, obtain independent review when a reviewer is
  available. A sole maintainer cannot supply independent review of their own patch.

See GitHub's [protected branch documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).
Adding the YAML does not enable branch protection. Verify the live rule in
Settings and on a test pull request before treating merge enforcement as active.

Security fixes belong with regression tests. Authentication and executor packages
also run under the race detector. Goose parser tests and real-database integration
tests cover fresh installation, upgrade, reruns and rollback behavior; the migration
numbering job rejects changes to already-published migrations. The mutation suite
checks that structural guards fail when their protected behavior is deliberately
broken. These checks reduce regressions; they do not prove that a change contains
no security flaw. Workflow, permission and test changes require review too.
