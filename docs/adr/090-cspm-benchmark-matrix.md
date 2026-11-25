# ADR 090 — CSPM coverage is measured control by control against public benchmarks

**Status:** accepted (2026-10-09)

## Context

CSPM coverage needs a measure someone outside the project can check. A vendor's own rule
catalogue cannot be that measure, so coverage is measured against public benchmarks: the CIS
Foundations benchmarks for AWS, GCP and Azure, AWS Foundational Security Best Practices
(Security Hub FSBP), and the CIS Kubernetes, EKS and GKE benchmarks.

Before this, coverage was a number nobody could check. The compliance view
(`internal/app/compliance`) mapped checks to graph's own control labels ("CIS-AWS-4.1" and
so on, which NOTICE says are not CIS recommendation numbers). Several controls rolled up
under the CIS framework for checks that implement no CIS recommendation at all.

## Decision

- **One matrix per benchmark version**, `internal/checks/benchmarks/<benchmark>.yaml`,
  listing every control: id, a paraphrased title of 10 words or fewer, service, status
  (`covered`, `partial`, `missing`, `not_applicable`, `manual`), the registry check IDs that
  evidence it, a reason, and a severity hint. `partial` names what is missing. `missing`
  names the data a collector must gather. `not_applicable` covers what an API-driven scanner
  cannot see, such as node-level files that need host access. A check `covers` a control only
  if it evaluates the same condition, not just a related one.
- **Version pinning.** Each matrix tracks the newest benchmark version that has a public,
  machine-readable control list: Prowler's compliance JSON, kube-bench's cfg, or AWS's
  Security Hub docs. A control list typed in by hand from a PDF cannot be checked against
  the source, so it doesn't qualify. As of 2026-10, four matrices are behind the newest
  release:

  | Benchmark | Newest release | Pinned to | Why |
  |---|---|---|---|
  | CIS AWS Foundations | 7.1.0 | 7.0.0 | No public list for 7.1.0 (Prowler stops at 7.0) |
  | CIS Kubernetes | 2.1.0 | 2.0.1 | Neither Prowler nor kube-bench has 2.1.0 |
  | CIS EKS | 2.0.0 | 1.8.0 | kube-bench stops at eks-1.8.0, Prowler has no EKS list, and the control IDs aren't published anywhere |
  | CIS AKS | 2.0.0 | 1.8.0 | kube-bench stops at aks-1.8 and Prowler has no AKS list |

  CIS GCP 5.0.0, CIS Azure 6.0.0, CIS GKE 2.0.0 and FSBP are on their newest releases. For
  GKE 2.0.0, the IDs come from Tenable's public audit listing, cross-checked against
  kube-bench gke-1.9.0. Bump a matrix when its newest version gets a public list.
- **Licensing.** CIS benchmark text is CC BY-NC-SA. The matrices hold only control IDs and
  titles written in our own words. FSBP IDs and titles come from AWS's public documentation.
- **Enforced by tests, not by a percentage.** `TestBenchmarkMatricesAreWellFormed` fails on
  a missing status or reason, a check ID that is not registered, or a check from the wrong
  provider. `TestCISControlsAgreeWithBenchmarkMatrix` fails when a compliance control that
  rolls up under CIS maps a check that no CIS matrix lists as `covered` or `partial` for that
  provider. No test asserts a coverage threshold: a threshold would invite reclassifying
  controls to pass it.
- **Published, and regenerated.** `go run ./cmd/cspm-coverage` renders
  `docs/cspm-coverage.md`, with per-benchmark totals and the missing and partial controls
  grouped by service. `TestCoverageDocIsCurrent` and a CI diff step fail on drift.
- Compliance control IDs stay graph's own labels. Deriving the compliance view from the
  matrices would replace about 30 curated controls with hundreds, all with framework tags
  for SOC 2, PCI and HIPAA that nobody has reviewed. The consistency test gets the
  correctness benefit without that change.

## Consequences

- "How much of a benchmark is covered?" now has a per-benchmark answer that changes in the
  same pull request as the checks behind it, and the gap list is the input to new checks.
- Adding a check is not enough to claim coverage. The matrix row must be updated, and the
  reviewer reads the claim next to the benchmark ID.
- Compliance controls whose checks back no CIS recommendation no longer count toward CIS.
  They keep their other framework tags.

### Residual risk: Kubernetes RBAC platform suppression

The CIS Kubernetes RBAC controls skip objects the distribution ships
(`internal/collect/kubernetes/rbac_stock.go`). Two gaps are accepted:

- A forged `kube-system/kubeadm-config` ConfigMap on a cluster that is not kubeadm makes
  kubeadm's stock bindings count as the platform's, which silences them. Forging it takes
  ConfigMap write in kube-system. Exploiting it also needs an identity those bindings name,
  such as a node-bootstrap token or a CSR-signed user. kubeadm's bindings grant no more than
  node bootstrap, and `kubeadm:cluster-admins` still reports at Info.
- Role baselines are per capability category, not per rule. A rule added inside a category
  the stock role already holds is not reported. Two examples: a second Secret for a role that
  reads Secrets by design, or a workload write in another API group. A per-rule check would
  report every Kubernetes upgrade that adds a harmless rule. Widening a scoped grant
  (`resourceNames`) to an unscoped one is reported.
