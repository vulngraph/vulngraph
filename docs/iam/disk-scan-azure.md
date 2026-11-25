# Azure VM disk scanning (opt-in)

Vulngraph can inventory the packages installed on an Azure VM by reading a snapshot
of its managed disk, for VMs that have no software inventory from another source. It
is **off by default**. A connector that does not enable it reports its VMs as
"disk scan not enabled", which is a distinct state: never "clean", and never an error.

Nothing is installed in the VM and nothing runs inside the guest. Vulngraph reads the
package databases (dpkg, apk, rpm) from the disk image and matches them against the
same advisory sources as every other package inventory.

## Two modes

| Mode | What Vulngraph does | Azure writes |
|---|---|---|
| `existing_snapshots` | Reads snapshots of the disk that already exist (backups, your own policy). | None to your disks or snapshots. It does request a short-lived read SAS on a snapshot (see below), with the disk-scan principal, which is required in this mode. |
| `create_snapshots` | Creates a tagged **incremental** snapshot, reads it, and deletes it. | Creates and deletes snapshots in one resource group you name. |

There is also a bring-your-own-agent ingest mode, for customers who want to keep
snapshot permissions away from Vulngraph entirely; it needs no role on this page.

Reading a snapshot over HTTPS requires a read SAS, which Azure issues through the
`beginGetAccess` action on the snapshot. That action is the only way to read snapshot
bytes, so both modes need it, and both need the disk-scan principal. The grant is authorized
by its own read opt-in, valid in both modes and only for a principal that differs from the
collection and executor principals; it covers the grant and revoke pair and never creating or
deleting a snapshot, which needs the `create_snapshots` opt-in. Vulngraph revokes the SAS (`endGetAccess`)
as soon as the scan ends, whether it succeeded or failed. The SAS is never logged or
stored.

## Required role

Use a **separate service principal** for disk scanning. It must not be the collection
principal (`client_id`) or the executor principal (`execute_client_id`); Vulngraph
refuses to enable the feature when they match.

### `existing_snapshots`: read access only

```json
{
  "Name": "Vulngraph Disk Scan (read)",
  "IsCustom": true,
  "Description": "Read existing snapshots over a short-lived SAS for Vulngraph disk scanning.",
  "Actions": [
    "Microsoft.Compute/snapshots/read",
    "Microsoft.Compute/snapshots/beginGetAccess/action",
    "Microsoft.Compute/snapshots/endGetAccess/action"
  ],
  "NotActions": [],
  "AssignableScopes": ["/subscriptions/<subscription-id>"]
}
```

Assign it to the disk-scan principal at the scope of each resource group (or the
subscription) that holds snapshots you want read. No other action is needed or used.

### `create_snapshots`: adds create and delete

Create a custom role and assign it at the scope of **one resource group** that holds
(or will hold) the scan snapshots, plus `disks/read` where the disks live:

```json
{
  "Name": "Vulngraph Disk Scan",
  "IsCustom": true,
  "Description": "Create, read and delete tagged incremental snapshots for Vulngraph disk scanning.",
  "Actions": [
    "Microsoft.Compute/snapshots/read",
    "Microsoft.Compute/snapshots/write",
    "Microsoft.Compute/snapshots/delete",
    "Microsoft.Compute/snapshots/beginGetAccess/action",
    "Microsoft.Compute/snapshots/endGetAccess/action",
    "Microsoft.Compute/disks/read"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/<subscription-id>/resourceGroups/<snapshot-resource-group>"
  ]
}
```

Assign it to the disk-scan principal on the snapshot resource group. If the VM disks
live in other resource groups, also assign a role containing only
`Microsoft.Compute/disks/read` there, so Vulngraph can read the source disk and create
a snapshot from it (creating a snapshot from a disk also needs read access to that
disk). This role includes the read-mode actions, so a `create_snapshots` connector needs
only this one.

No `Microsoft.Compute/disks/write`, `virtualMachines/*`, or any other write is needed
or used.

## Enable it on the connector

1. Create the service principal and assign the role above.
2. In **Connectors**, open the Azure connector, choose the disk-scan mode, and enter:
   - `disk_scan_client_id` and `disk_scan_client_secret`: the principal above;
   - the snapshot resource group.
3. Confirm the typed prompt. An admin, signed in as a person (not an API key), must
   confirm the cost and the permission. That confirmation is the standing approval for
   creating snapshots, and it is recorded in the audit log with the before and after
   mode, the principal, who changed it and when.

Disabling the mode, or removing the role, stops all disk-scan calls. If a permission is
missing at run time, the affected VMs show the reason (`permission_denied`) and are not
retried in a loop.

## What the scanner pod holds

Unlike AWS, Azure has no short-lived credential Vulngraph can mint for you: the scanner pod
receives the disk-scan principal's `disk_scan_client_secret` itself, sealed in the run's volume
jobs, and it stays valid until you rotate it. Give the principal only the role above. A
compromised scanner can use that secret while you have not rotated it, not only while a run is live
([threat 18](../threat-model.md)).

## Safety properties

- Snapshots Vulngraph creates are tagged `vulngraph-disk-scan=<run id>`. Deletion
  re-reads the live tags first and refuses any snapshot without that tag, so a snapshot
  of yours is never deleted.
- Every scan revokes its read SAS and deletes its snapshot on every exit path. A
  sweeper deletes tagged snapshots older than the snapshot TTL, even if the database
  record is lost.
- Snapshots are incremental, so successive scans of one disk store only the changed
  pages, and Vulngraph reads only the changed ranges when it can.
- The read SAS is fetched with Vulngraph's SSRF-guarded HTTP client.
- Disks under Azure Disk Encryption are reported as "encrypted, no key" rather than as
  empty. Platform-managed and customer-managed server-side encryption are read
  transparently by Azure.

## Cost

You pay Azure for the snapshots while they exist: incremental snapshot storage (only
changed pages beyond the first snapshot) and the read transfer from the snapshot. With
the default time-to-live of about six hours and a daily snapshot cap, the cost is
bounded and shown on the connector page before you confirm. Existing-snapshots mode
adds no snapshot storage.

## What "not enabled" means

If the feature is off, or the role is missing, VMs without another package inventory
show **disk scan: not enabled**. Vulngraph does not treat them as clean or as having
no packages; their vulnerability coverage is unknown, as it is for any VM without an
inventory.
