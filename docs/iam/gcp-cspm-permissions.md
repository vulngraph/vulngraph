# GCP permissions for the CIS GCP / GKE posture reads

Vulngraph's GCP collector (`internal/collect/gcp`) evaluates CIS Google Cloud
Platform Foundation 5.0 and CIS GKE 2.0 from read-only API calls. The
collector's identity needs two predefined roles on each project, or on the
folder or organization above it:

- **Viewer** (`roles/viewer`), or the narrower
  [collector role](#a-custom-role-instead-of-viewer) below
- **Security Reviewer** (`roles/iam.securityReviewer`): the `*.getIamPolicy`
  reads.

Viewer is a basic role: it covers the project inventory reads, and much more,
including data-plane reads Vulngraph never makes (for example, project viewers
are readers of every BigQuery dataset, so they can read table data). Google
recommends predefined or custom roles over basic ones. The custom role below
holds only the reads the collector calls.

The organization-level controls need one more grant: a custom role on the
organization (see [the organization role](#the-organization-role)). It is
optional. When it is missing, the reads it covers are denied, and those
controls stay ungraded: the metadata key is absent, so the check is silent.
The sweep is not marked partial, and the result never reads as compliant.

GCS public-access prevention also needs `orgpolicy.policies.get` on the project
and on any folders or organization whose policy it must read. Add this permission
to the relevant collector roles (the examples below include it). The Organization
Policy API must be enabled for the caller. Denied reads leave inherited prevention
and exposure unknown; a disabled API is not evidence that prevention is disabled.
Bucket-specific tag conditions are not evaluated, so conditional inherited policies
also stay unknown. A bucket with prevention explicitly `enforced` needs no ancestor read.

> Vulngraph never grants this itself: no code path grants IAM permissions to Vulngraph or
> anyone else. Its only IAM writes are human-approved key actions through the executor
> (disabling or deleting an AWS access key, disabling a GCP service-account key), run
> with the connector's separate execution role.
> Grant them through your usual IAM process.

## Every call, and the permission behind it

| Read | Permission | Granted by | Controls |
|---|---|---|---|
| `compute.networks.list`, `compute.subnetworks.aggregatedList` | `compute.networks.list`, `compute.subnetworks.list` | Viewer | GCP 3.1, 3.2, 3.10, GKE 5.6.1 |
| `dns.policies.list` | `dns.policies.list` | Viewer | GCP 2.13 |
| `compute.backendServices.aggregatedList`, `instanceGroups.listInstances`, `regionInstanceGroups.listInstances` | `compute.backendServices.list`, `compute.instanceGroups.list` (zonal and regional groups) | Viewer | GCP 2.17, 3.12 |
| `compute.targetHttpsProxies.aggregatedList`, `targetSslProxies.list`, `sslPolicies.aggregatedList` | `compute.targetHttpsProxies.list`, `compute.targetSslProxies.list`, `compute.sslPolicies.list` | Viewer | GCP 3.11, GKE 5.6.7 |
| `compute.regions.list`, `dataproc.regions.clusters.list` | `compute.regions.list`, `dataproc.clusters.list` | Viewer | GCP 8.1 |
| `container.clusters.list` (raw REST body) | `container.clusters.list` | Viewer | GKE 5.x |
| `logging.sinks.list` (project) | `logging.sinks.list` | Viewer | GCP 2.3, 2.4 |
| `logging.sinks.list` (folders, organization) | `logging.sinks.list` | **Organization role** | GCP 2.3 |
| `logging.projects.metrics.list` | `logging.logMetrics.list` | Viewer | GCP 2.5-2.12 |
| `monitoring.projects.alertPolicies.list` | `monitoring.alertPolicies.list` | Viewer | GCP 2.5-2.12 |
| `storage.buckets.get` (log sink destinations) | `storage.buckets.get` | Viewer on the bucket's project (a central log bucket in another project needs it there; denied is ungraded, not partial) | GCP 2.4 |
| `orgpolicy.projects/folders/organizations.policies.get` | `orgpolicy.policies.get` | Collector role on the project and ancestors read | GCS public-access prevention and exposure |
| `cloudkms.locations.list`, `keyRings.list`, `cryptoKeys.list` | `cloudkms.locations.list`, `cloudkms.keyRings.list`, `cloudkms.cryptoKeys.list` | Viewer | GCP 1.11 |
| `cloudkms.keyRings.getIamPolicy`, `cryptoKeys.getIamPolicy` | `cloudkms.keyRings.getIamPolicy`, `cloudkms.cryptoKeys.getIamPolicy` | Security Reviewer | GCP 1.10 |
| `apikeys.keys.list` | `apikeys.keys.list` | Viewer | GCP 1.13-1.16 |
| `bigquery.datasets.list/get`, `tables.list/get` | `bigquery.datasets.get`, `bigquery.tables.list`, `bigquery.tables.get` | Viewer | GCP 7.1-7.3 |
| `appengine.apps.services.list`, `versions.list` | `appengine.services.list`, `appengine.versions.list` | Viewer | GCP 4.10 |
| `artifactregistry.locations.list`, `repositories.list` | `artifactregistry.repositories.list` | Viewer | GKE 5.1.1 |
| `artifactregistry.repositories.getIamPolicy` | `artifactregistry.repositories.getIamPolicy` | Security Reviewer | GKE 5.1.2 |
| `binaryauthorization.projects.getPolicy` (only with an enforcing cluster) | `binaryauthorization.policy.get` | Viewer | GKE 5.1.3 |
| `serviceusage.services.get` (cloudasset.googleapis.com) | `serviceusage.services.get` | Viewer | GCP 2.14 |
| `accessapproval.projects.getAccessApprovalSettings` | `accessapproval.settings.get` | Viewer | GCP 2.16 |
| `essentialcontacts.projects.contacts.compute` | `essentialcontacts.contacts.list` | Viewer | GCP 1.17 |
| `essentialcontacts.organizations.contacts.compute`, `accessapproval.organizations.getAccessApprovalSettings` | `essentialcontacts.contacts.list`, `accessapproval.settings.get` (on the organization) | **Organization role** | GCP 1.17, 2.16 |
| `cloudresourcemanager.projects.get` / `getAncestry` | `resourcemanager.projects.get` | Viewer | GCP 2.3, 3.8 |
| `cloudresourcemanager.organizations.get` | `resourcemanager.organizations.get` | **Organization role** | GCP 1.2 |
| `accesscontextmanager.accessPolicies.list`, `servicePerimeters.list` | `accesscontextmanager.policies.list`, `accesscontextmanager.servicePerimeters.list` | **Organization role** | GCP 3.8 |
| `cloudfunctions.functions.list`, `run.services.list` (environment variables) | already granted for the function and Cloud Run inventory | Viewer / [Cloud Run](gcp-cloud-run-permissions.md) | GCP 1.18 |
| `osconfig.inventories.list` (available packages) | already granted for VM software inventory | see [vm-software-inventory.md](vm-software-inventory.md) | GCP 4.12 |
| Admin SDK Directory `users.list` (`isEnrolledIn2Sv`) | the Workspace connector's existing `admin.directory.user.readonly` scope | Workspace connector | GCP 1.3 |

## A custom role instead of Viewer

These are the reads `internal/collect/gcp` makes, other than the
`*.getIamPolicy` calls that Security Reviewer covers: the inventory as well as
the CIS posture reads in the table above. Keep Security Reviewer alongside it.

```sh
PERMS="compute.projects.get,compute.instances.list,compute.firewalls.list,\
compute.networks.list,compute.subnetworks.list,compute.regions.list,\
compute.images.list,compute.snapshots.list,compute.forwardingRules.list,\
compute.globalForwardingRules.list,compute.backendServices.list,\
compute.regionBackendServices.list,compute.instanceGroups.list,\
compute.sslCertificates.list,compute.regionSslCertificates.list,\
compute.sslPolicies.list,compute.regionSslPolicies.list,\
compute.targetHttpsProxies.list,compute.regionTargetHttpsProxies.list,\
compute.targetSslProxies.list,dns.managedZones.list,\
dns.resourceRecordSets.list,dns.policies.list,storage.buckets.list,\
storage.buckets.get,bigquery.datasets.get,bigquery.tables.list,\
bigquery.tables.get,appengine.services.list,appengine.versions.list,\
cloudkms.locations.list,cloudkms.keyRings.list,cloudkms.cryptoKeys.list,\
apikeys.keys.list,artifactregistry.locations.list,\
artifactregistry.repositories.list,binaryauthorization.policy.get,\
serviceusage.services.get,accessapproval.settings.get,\
essentialcontacts.contacts.list,resourcemanager.projects.get,orgpolicy.policies.get,\
logging.sinks.list,logging.logMetrics.list,monitoring.alertPolicies.list,\
container.clusters.list,cloudfunctions.functions.list,run.services.list,\
run.revisions.get,cloudsql.instances.list,dataproc.clusters.list,\
secretmanager.secrets.list,iam.serviceAccounts.list,\
iam.serviceAccountKeys.list,iam.roles.get,\
policyanalyzer.serviceAccountLastAuthenticationActivities.query,\
policyanalyzer.serviceAccountKeyLastAuthenticationActivities.query,\
osconfig.inventories.list"
gcloud iam roles create graphCollectorReader --organization=<ORG_ID> \
  --title="Vulngraph collector reader" --stage=GA --permissions="$PERMS"
```

Create it on the organization (as here) to bind it on the organization,
folders or projects, or with `--project=<PROJECT>` to bind it in that one
project only. Bind it where you would have bound Viewer:

```sh
gcloud projects add-iam-policy-binding <TARGET_PROJECT> \
  --member="serviceAccount:graph-collector@<PROJECT>.iam.gserviceaccount.com" \
  --role=organizations/<ORG_ID>/roles/graphCollectorReader
```

With this role, a read Vulngraph adds in a later release is denied until you
add its permission. A denied read never reads as an empty or clean project,
but it does not always mark the sync partial:

- most reads mark the sync partial and log the denial
  (`internal/collect/gcp/gcp.go` `bestEffort`);
- a denied `osconfig.inventories.list` stamps each instance in the zone with
  the `osconfig_access_denied` package-inventory gap (no software inventory,
  not a clean one);
- denied project ancestry (`resourcemanager.projects.get`), log-sink bucket
  (`storage.buckets.get`) and organization reads are logged and leave the
  affected keys unknown, so those controls stay ungraded, without marking the
  sync partial (`internal/collect/gcp/target.go` `optionalRead`).
- unreadable GCS prevention policy or ancestry leaves its effective-prevention
  and public-access metadata unknown, without dropping the bucket inventory or
  marking the sync partial.

Check the release notes for new permissions when you upgrade. Viewer avoids
that maintenance at the cost of the wider grant. The table above maps each
permission to the controls that need it; the rest feed the inventory
(instances, firewalls, buckets, Cloud SQL, Cloud Run, Cloud Functions, GKE,
secrets, service accounts and their keys, VM software inventory, images and
snapshots). The two `policyanalyzer` permissions read service-account and key
last-authentication times.

## The organization role

The organization-wide reads (1.2, 1.17, 2.3, 2.16, 3.8) need these
permissions on the organization. Use a custom role, not
`roles/logging.viewer` (which also grants `logging.logEntries.list`, so it
could read every log entry in the organization) and not organization-wide
Viewer:

```sh
gcloud iam roles create graphCspmOrgReader --organization=<ORG_ID> \
  --title="Vulngraph CSPM organization reader" --stage=GA \
  --permissions=resourcemanager.organizations.get,logging.sinks.list,essentialcontacts.contacts.list,accessapproval.settings.get,accesscontextmanager.policies.list,accesscontextmanager.servicePerimeters.list,orgpolicy.policies.get
gcloud organizations add-iam-policy-binding <ORG_ID> \
  --member="serviceAccount:graph-collector@<PROJECT>.iam.gserviceaccount.com" \
  --role=organizations/<ORG_ID>/roles/graphCspmOrgReader
```

Bind the same role on folders too, if some projects should count an
aggregated sink set on a folder. Without the role:

- Consumer (gmail.com) accounts are still reported, but members on other
  corporate domains are not graded (1.2).
- Essential Contacts and Access Approval are graded per project, on the
  effective settings each project resolves (1.17, 2.16).
- A project with no catch-all sink of its own is left ungraded (2.3).
- The perimeter check stays silent (3.8).

## APIs a project has not enabled

When a project has never enabled an API (Cloud KMS, BigQuery, Dataproc, App
Engine, Artifact Registry, API Keys), the call returns `SERVICE_DISABLED`.
That means the service has no resources in the project, so the sweep is not
marked partial. This applies only when the error names the swept project. If
an API is disabled on the collector's own quota project instead, every call
fails the same way, and that counts as a failed sweep.

Three disabled APIs are themselves the answer:

- Cloud Monitoring disabled means no alert policy can exist (CIS GCP 2.5-2.12).
- Cloud DNS disabled means no DNS logging policy exists (CIS GCP 2.13).
- Access Approval disabled means nothing can be enrolled (CIS GCP 2.16).

Essential Contacts is the exception. Contacts set on the organization are
unreadable from a project with the API disabled, so that project's 1.17 is
unknown.
