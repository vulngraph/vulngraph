# Roadmap

Where Vulngraph is heading. This is direction, not a promise: there are no dates, one maintainer sets the
order, and items move as people use it. What exists today is in [`docs/capabilities.md`](docs/capabilities.md)
and what it gets wrong is in [`docs/known-limitations.md`](docs/known-limitations.md). To weigh in, open a
[discussion](https://github.com/vulngraph/vulngraph/discussions) or an issue.

## Where it is aiming

The goal is the useful core of a cloud-native application protection platform (CNAPP) that you can run
yourself and inspect: one graph joining inventory, identity, vulnerabilities, exposure and code, with risk
ranked by what an attacker can reach. It has no goal of being a copy of any vendor's product, and it will say
plainly where it falls short.

| Area | Today | Gap to close |
|---|---|---|
| Posture (CSPM) | About 850 checks across AWS, GCP, Azure and Kubernetes, mapped to CIS and AWS FSBP | Broader Azure and GCP service coverage |
| Identity (CIEM) | 66 escalation techniques, Okta and Google Workspace | Fewer over-counted paths ([limitation](docs/known-limitations.md)) |
| Vulnerabilities | Packages from VM inventories, SBOMs and container images, matched to OSV, KEV and EPSS. Opt-in disk scanning of Linux VMs on AWS and Azure (ext4 and XFS), or packages sent by your own agent | Disk scanning on GCP, more filesystems and layouts, data volumes |
| Attack paths | Internet exposure, identity, supply chain | Network reachability beyond security groups: ACLs, Azure NSGs, GCP firewall policies |
| Data (DSPM) | Sensitive-store ranking by exposure | Deeper classification |
| Code to cloud | Repository to service to image to package | More deployment sources |
| Freshness | Scheduled, GitHub webhook, API-triggered sync, drift analysis of what changed | Native AWS and GCP event sources |
| Agents | MCP endpoint, scoped keys, live verification, advisory drift analysis | OAuth for MCP clients, agents proposing fixes into the approval queue |
| AI | Plain-English queries, chat, drafted Nuclei templates, fix proposals a person approves | Measure quality beyond small golden sets |

## Next

- **Network reachability.** Apply network ACLs, Azure NSGs and GCP firewall policies so "exposed" is confirmed
  at more layers than security groups.
- **EKS Pod Identity.** Collect associations so attack paths continue from a pod to its role.
- **LadybugDB upgrade.** Move to the first upstream release that fixes the multi-hop gap, then drop the
  warning.
- **Native event sources.** An EventBridge and Pub/Sub path so cloud changes sync without a schedule or a
  hand-built trigger.
- **Disk scanning, second pass.** GCP existing snapshots, an image-baseline scan shared by instances from one
  image, LVM, and data volumes. The first pass is documented in [`docs/capabilities.md`](docs/capabilities.md).

## Later

- **Runtime context from sensors you already run.** Accept events from Falco, Tetragon or Tracee through a
  signed webhook and use "this package is actually loaded" as a reachability signal in scoring.
- **OAuth for MCP.** Let an MCP client that requires the standard OAuth flow connect, validating tokens from
  your identity provider, as an opt-in beside scoped API keys.
- **Agents that propose.** An MCP tool that lets an agent submit a proposed fix into the approval queue, so a
  person still decides.
- **More identity sources** beyond Okta and Google Workspace.
- **Contextual scan template selection** from an asset's type, ports and technology. Today scans use fixed
  tag lists.
- **Quality measurement** for the model's proposals: larger evaluation sets, run in CI.

## Not planned

- **A host agent or runtime sensor of our own.** It reads cloud APIs and, where you opt in, disk snapshots.
  It does not watch syscalls.
- **Autonomous remediation.** Fixes stay proposals that a person approves.
