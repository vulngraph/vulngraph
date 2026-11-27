# Your own frameworks

Vulngraph ships one requirement framework, NIST SP 800-53 Rev. 5. To check your estate against another one
(HIPAA, FedRAMP, an internal standard), put a mapping file in a directory and point `FRAMEWORKS_DIR` at it.
Each file is listed in the Framework requirements section next to NIST, with its file name as the source.

The files here are examples to copy and adapt: [HIPAA Security Rule](hipaa_security_rule.yaml),
[ISO/IEC 27001 Annex A](iso_27001_2022.yaml), [PCI DSS 4.0.1](pci_dss_4.0.yaml) and
[SOC 2](soc2_2017.yaml). They were machine-generated from public mappings and most of their requirements
cannot be assessed from cloud configuration alone ([coverage](../cspm-coverage.md#requirement-frameworks)).
A mapping is only as good as whoever wrote it: Vulngraph checks that the file is well formed and that every
control exists, not that the mapping is right for your audit.

## Format

```yaml
framework: acme-baseline        # unique id; must not match a built-in or another file
name: "Acme baseline"
version: "1"
sources:                        # where the mapping comes from, shown for attribution
  - "Acme security team"
requirements:
  - {id: "A.1", title: "Rotate access keys", controls: ["cis-aws-foundations/2.3"]}
  - {id: "A.2", title: "Written incident plan", controls: []}
```

- **`id`** is the requirement's ID in the standard. It must be unique within the file.
- **`title`** is a short paraphrase, 1 to 12 words. Do not paste copyrighted standard text.
- **`controls`** lists benchmark controls as `benchmark/control`, for example `cis-aws-foundations/2.3` or
  `aws-fsbp/IAM.6`. The benchmarks are in [`internal/checks/benchmarks`](../../internal/checks/benchmarks)
  and their coverage is in [CSPM coverage](../cspm-coverage.md). Controls name benchmark rows, never checks:
  a check added to a row reaches every requirement that maps it.
- A requirement with no controls is shown as needing human evidence. It never passes by itself.
- `unjoined` is optional. It counts evidence in your source that maps to no control, and a requirement
  with `unjoined` above zero can fail or show unknown but never pass.

## Loading

`FRAMEWORKS_DIR` is read by `serve` when it starts. Every `*.yaml` file in the directory is loaded, and serve
refuses to start if one cannot be parsed, names a control that does not exist, or reuses a framework `id`.
The error names the file. Changing a file takes a restart.

- **Docker Compose:** mount the directory into `serve` and set the variable
  (see `deploy/docker-compose/docker-compose.yml`).
- **Helm:** create a ConfigMap from your files and set `config.frameworksConfigMap` to its name
  (`kubectl create configmap my-frameworks --from-file=acme.yaml`).
