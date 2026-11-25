# Bring your own agent: submit a VM's package inventory

Vulngraph reads a VM's installed packages from the cloud's inventory service
([VM software inventory](vm-software-inventory.md)) or, where you opt in, from a disk snapshot
([disk scan](disk-scan-aws.md)). If you would rather keep every snapshot permission out of Vulngraph,
run your own scanner with its own cloud permissions and **submit the package list**. This page covers
that path.

An inventory is facts about one existing VM. It is never a finding, and Vulngraph never takes your
word that the machine is clean: it matches the packages against its own advisory sources, and it
decides for itself whether the list is believed.

| If your tool emits | Use |
| --- | --- |
| CVE findings (OpenVAS, Qualys, Burp, your own) | `POST /api/scans/import` ([capabilities](../capabilities.md#scanning)). Admin session only. |
| Installed packages of a VM | This page: `PUT /api/assets/{id}/package-inventory`. |

## Create the key

Only an admin can create an `inventory` key, from **Settings → API keys** (scope `inventory`) or
`POST /api/keys` from a session. The key:

- may call the two inventory routes and the MCP tool `submit_package_inventory`, and nothing else:
  every other route answers 403, and `tools/list` shows only the one tool;
- stops working if its owner is demoted below admin or disabled, and expires like any key
  (`API_KEY_MAX_LIFETIME_DAYS`);
- cannot create or delete keys, and a session (even an admin's) is refused on these routes: the
  inventory belongs to a key, so the audit trail and the replace rule below have someone to name.

Create one key per scanning agent. The key id is part of where the inventory is stored, so one key
cannot overwrite what another submitted.

## Submit an inventory

The VM must already exist in the inventory (a connector has collected it), be live and not deleted. The
call never creates an asset.

```sh
curl -sS -X PUT "$VULNGRAPH/api/assets/i-0abc123def456/package-inventory" \
  -H "Authorization: Bearer $INVENTORY_KEY" \
  -H "Content-Type: application/json" \
  --data @inventory.json
```

`inventory.json`:

```json
{
  "os": { "id": "ubuntu", "version_id": "22.04", "name": "Ubuntu" },
  "observed_at": "2026-11-25T09:30:00Z",
  "scanner": { "name": "acme-agent", "version": "1.4.2" },
  "complete": true,
  "covered": [{ "volume_id": "vol-0123456789abcdef0" }],
  "packages": [
    { "name": "libssl3", "version": "3.0.2-0ubuntu1.10", "source_name": "openssl" },
    { "name": "bash", "version": "5.1-6ubuntu1", "source_name": "bash" },
    { "purl": "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.15", "source_name": "curl" },
    { "ecosystem": "npm", "name": "left-pad", "version": "1.3.0" }
  ]
}
```

`PUT /api/package-inventory` takes the same body with `cloud_resource_id` set to the VM's id; on the
asset route the path wins. The id is matched exactly against asset ids, so it names at most one asset
(404 otherwise).

The response says what the server made of it:

```json
{
  "accepted": true,
  "asset_id": "i-0abc123def456",
  "source": "byoa:6f1c…:acme-agent",
  "scanner": { "name": "acme-agent", "version": "1.4.2" },
  "observed_at": "2026-11-25T09:30:00Z",
  "complete": true,
  "package_count": 4,
  "inventory_known": true,
  "cve_matchable_known": true,
  "gap": ""
}
```

Over MCP the same call is the tool `submit_package_inventory`, with the same arguments:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": { "name": "submit_package_inventory",
              "arguments": { "cloud_resource_id": "i-0abc123def456", "observed_at": "2026-11-25T09:30:00Z",
                             "scanner": { "name": "acme-agent", "version": "1.4.2" }, "complete": true,
                             "os": { "id": "ubuntu", "version_id": "22.04" },
                             "packages": [{ "name": "bash", "version": "5.1-6ubuntu1", "source_name": "bash" }] } } }
```

### Fields

- `os.id` and `os.version_id` are the `ID` and `VERSION_ID` of `/etc/os-release`. They pick the OSV
  ecosystem. Without a recognised OS the result is a gap (`unknown_release`).
- A package is a `purl` (`pkg:deb|rpm|apk/<distro>/name@version`, or `npm`, `pypi`, `golang`, `maven`,
  `cargo`, `gem`; no qualifiers) or `name` and `version`, with `ecosystem` either `os` (the default, taken
  from the OS block) or `npm`, `PyPI`, `Go`, `Maven`, `crates.io`, `RubyGems`. A purl whose distro does not
  match the OS block, or whose type contradicts the stated ecosystem, is refused.
- Send `source_name` for Debian, Ubuntu, Rocky and SUSE packages: their advisories are keyed by source
  package, and an inventory without any is a gap (`no_source_package_names`). For rpm, `epoch` and
  `release` are accepted and combined into the version rpm compares.
- `complete: true` claims the list is the machine's whole OS package set. It defaults to false.
- `covered` says which volumes or paths you read. It is recorded, not trusted.
- Unknown fields are refused, so a body cannot carry findings or its own verdict.

## What the server decides

You send a claim; Vulngraph records it with its provenance (key, scanner, version, observed time) and
decides known-ness itself:

| Result | When | Effect |
| --- | --- | --- |
| `inventory_known: true` | `complete` is true **and** `observed_at` is under 7 days old **and** the OS resolves to an advisory source that is switched on | The packages become `runs_package` edges of that VM and are matched like any other inventory |
| `gap: byoa_incomplete` | `complete` is false or absent | No edges. The VM reads as unknown |
| `gap: byoa_stale` | `observed_at` is 7 or more days old | No edges. The VM reads as unknown |
| `gap: unknown_release`, `no_advisory_source`, `advisory_source_disabled`, `eol_distro`, `no_source_package_names` | The OS cannot be matched to a usable advisory source | No edges. The VM reads as unknown |

A VM is never shown as clean because of a gap, an empty list or a missing submission. A source that stops
reporting goes stale; it never turns into a clean bill of health. Where several inventories exist for one
VM (SSM, OS Config, a disk scan, your agent), the freshest known one is used. The UI shows the source,
the scanner and version, the observed date and "reported complete by `<scanner>`".

**Replace by source.** Each (key, scanner name, asset) stores one inventory. A later submission replaces
it. The same body twice changes nothing. A submission whose `observed_at` is older than the stored one is
refused with 409. Edges are never deleted: those from an earlier submission lapse by the same freshness
rule as every other inventory (48 hours), so submit at least daily.

## Limits

| Limit | Value |
| --- | --- |
| Body | 4 MiB |
| Packages | 10,000 per submission (the same cap as the SSM path, which records such a host as `over_package_cap`); over it is refused, never truncated |
| `observed_at` | at most 5 minutes in the future and 30 days old |
| Rate | 60 requests an hour per key and asset (429 with `Retry-After`) |
| Strings | printable ASCII, length-capped, no newline; `scanner.name` is a slug (`a-z 0-9 . _ -`) |

Every submission, accepted or rejected, writes an `inventory.submit` audit row with the key id, asset,
scanner, package count, `complete` and the outcome.

## What this does not protect against

A scanner that lies, with a fresh `complete: true` list that omits a vulnerable package, is believed until
that list goes stale (7 days at most; sooner if the agent submits again). See
[known limitations](../known-limitations.md) and [threat 16](../threat-model.md). Keep the key to one
agent, expire it, and revoke it when the agent is retired: revoking a key deletes its inventories, so they
read as unknown.
