# Granting Vulngraph Cloud Run read access

Vulngraph's GCP collector (`internal/collect/gcp/cloudrun.go`) reads every Cloud Run
service in a project for three things:

1. **The service itself**: its ingress setting, URL and runtime service account.
   An `ingress=all` service is an internet entry point.
2. **The images it runs.** It links each revision that is serving traffic to the
   resolved image digest (`container_image` asset plus a `runs_image` edge). The
   image-vuln sweep then scans that digest, and an image CVE on an exposed
   service can reach must-fix through the same chain a Kubernetes pod uses.
3. **Whether unauthenticated callers can invoke it.** The collector checks for a
   `roles/run.invoker` binding to `allUsers`/`allAuthenticatedUsers`. Together
   with `ingress=all`, that binding is what makes exposure *confirmed*.

> Vulngraph never grants this itself: no code path grants IAM permissions to Vulngraph or
> anyone else. Its only IAM writes are human-approved key actions through the executor
> (disabling or deleting an AWS access key, disabling a GCP service-account key), run
> with the connector's separate execution role.
> Grant it through whatever IAM process your organization already uses.

## The grant

All three permissions are in the predefined **`roles/run.viewer`** role. Grant
that role to the collector's identity on each project (or on the folder/org):

| Permission | Used for |
|---|---|
| `run.services.list` | listing services (ingress, URL, traffic, service account) |
| `run.revisions.list` | resolving the image digest each serving revision runs |
| `run.services.getIamPolicy` | the `allUsers` invoker check, called only for `ingress=all` services |

All three are read-only and change nothing.

## What happens when one is missing

The collector never fails silently. Each gap below logs a warning, and the
first two also mark the sweep partial:

- **No `run.services.list`**: no Cloud Run services are collected at all.
- **No `run.revisions.list`**: services are still collected, but none gets a
  `runs_image` edge. Their images are not scanned, and image CVEs cannot reach
  must-fix through Cloud Run.
- **No `run.services.getIamPolicy`**: an `ingress=all` service keeps
  `public_access=possible`. An unreadable policy is treated as *unknown*, never
  as confirmed and never as safe. The `gcp-cloudrun-unauthenticated` check then
  stays dormant for that service, and the low-severity `gcp-cloudrun-public`
  check still fires. When the policy was read, the asset carries
  `invoker_public=true|false`. A missing key means the policy was not read.
