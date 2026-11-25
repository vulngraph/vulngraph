{{- define "graph.labels" -}}
app.kubernetes.io/name: graph
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.extraLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
avoidSpotPodLabels on the pod templates of the workloads avoidSpotNodes pins
(paired with offSpotAffinity on each), only while avoidSpotNodes is on. Values
are quoted: a label value is a string.
*/}}
{{- define "graph.offSpotLabels" -}}
{{- if .Values.avoidSpotNodes }}
{{- range $k, $v := .Values.avoidSpotPodLabels }}
{{ $k }}: {{ toString $v | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
ClickHouse max_concurrent_queries: clickhouse.tuning.maxConcurrentQueries when
set, else every graph pod's client-side cap (CH_MAX_CONCURRENT, default 8 —
internal/db defaultCHMaxConcurrent) summed over the replicas that run, plus 8
for migrate, CLI and operator sessions.
*/}}
{{- define "graph.clickhouseMaxConcurrentQueries" -}}
{{- if .Values.clickhouse.tuning.maxConcurrentQueries -}}
{{ .Values.clickhouse.tuning.maxConcurrentQueries }}
{{- else -}}
{{- $perPod := int (default "8" .Values.config.chMaxConcurrent) -}}
{{- $pods := int .Values.serve.replicas -}}
{{- if .Values.worker.enabled }}{{ $pods = add $pods .Values.worker.replicas }}{{ end -}}
{{- if .Values.scanner.enabled }}{{ $pods = add $pods .Values.scanner.replicas }}{{ end -}}
{{ add (mul $pods $perPod) 8 }}
{{- end -}}
{{- end -}}

{{/*
Azure Workload Identity opt-in label, for the pods that call cloud APIs (serve
and worker). Kept off every other pod so the webhook injects no token there.
*/}}
{{- define "graph.azureWorkloadIdentityLabel" -}}
{{- if .Values.serviceAccount.azureWorkloadIdentity }}
azure.workload.identity/use: "true"
{{- end }}
{{- end -}}

{{/*
offSpotAffinity's spot values: avoidSpotNodeLabelValues when set, else the
values that mark spot capacity under a key whose cloud values.yaml lists. Any
other key fails the render without values: a guessed value that no node
carries would leave every spot node eligible.
*/}}
{{- define "graph.offSpotAffinity" -}}
{{- if .Values.avoidSpotNodes }}
{{- $key := .Values.avoidSpotNodeLabelKey }}
{{- $known := dict
  "cloud.google.com/gke-spot" (list "true")
  "eks.amazonaws.com/capacityType" (list "SPOT")
  "karpenter.sh/capacity-type" (list "spot")
  "kubernetes.azure.com/scalesetpriority" (list "spot") }}
{{- $values := .Values.avoidSpotNodeLabelValues | default (get $known ($key | default "")) }}
{{- if not (and $key $values) }}
{{- fail (printf "avoidSpotNodes needs avoidSpotNodeLabelKey and, for a key values.yaml does not list, avoidSpotNodeLabelValues: the values of that node label that mark spot capacity (key %q)" ($key | default "")) }}
{{- end }}
affinity:
  nodeAffinity:
    # Keep this pod off preemptible/spot nodes. The worker holds the in-memory Ladybug
    # graph (minutes to rebuild) and Postgres/ClickHouse are stateful — a spot
    # preemption is a real outage + reschedule storm, not a cheap restart.
    # NotIn admits a node without the label and a node whose value is not
    # listed, so one rule serves a key every node carries (EKS, Karpenter) and
    # one only spot nodes carry (GKE, AKS). values.yaml lists each cloud's.
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: {{ $key }}
              operator: NotIn
              values:
                {{- range $values }}
                - {{ toString . | quote }}
                {{- end }}
{{- end }}
{{- end -}}

{{/*
Pod annotations that make the cluster's vmagent scrape this pod's /metrics.

The kubernetes-pods scrape job keys entirely off these three annotations, so they
are the whole collection path — there is no Service and no ServiceMonitor
involved. Pair with graph.metricsPort (the container port declaration) on every
pod that sets them: the same job drops targets whose container port number is
empty, so annotations without a declared port scrape nothing.
*/}}
{{- define "graph.metricsAnnotations" -}}
{{- if .Values.metrics.enabled }}
prometheus.io/scrape: "true"
prometheus.io/port: {{ .Values.metrics.port | quote }}
prometheus.io/path: {{ .Values.metrics.path | quote }}
{{- end }}
{{- end -}}

{{/*
Pod labels the vmagent maps onto every sample from this pod. Its labelmap keeps
`app` and `component` but NOT app.kubernetes.io/component (the regex is fully
anchored), so without these two the worker's and the serve pod's series are
indistinguishable — and they must be distinguished, because serve registers only
a subset of the metric sources and reports a structural graph_ladybug_node_count of
0 that would otherwise be aggregated against the worker's real one.
Call with (dict "component" "<name>" "Values" .Values).
*/}}
{{- define "graph.metricsLabels" -}}
{{- if .Values.metrics.enabled }}
app: graph
component: {{ .component }}
{{- end }}
{{- end -}}

{{/*
The metrics container port. Declared as a real port because the scrape job drops
any target with an empty container port number, not because anything connects to
it by name — the listener is pod-internal (no Service, no Ingress).
*/}}
{{- define "graph.metricsPort" -}}
{{- if .Values.metrics.enabled }}
- name: metrics
  containerPort: {{ .Values.metrics.port }}
  protocol: TCP
{{- end }}
{{- end -}}

{{/*
NetworkPolicy ingress rule for the metrics port of a pod that declares one
(graph.metricsPort), only with metrics.enabled. networkPolicy.metricsNamespace
names the scraper's namespace; empty admits every source on that port, since a
scraper that is not a pod (hostNetwork, a node agent) matches no namespace.
*/}}
{{- define "graph.networkPolicyMetricsIngress" -}}
{{- if .Values.metrics.enabled }}
- ports:
    - protocol: TCP
      port: {{ .Values.metrics.port }}
  {{- with .Values.networkPolicy.metricsNamespace }}
  from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ . }}
  {{- end }}
{{- end }}
{{- end -}}

{{/*
The graph image every graph container runs: repository@digest when
image.digest is set (the tag is then ignored, since a digest names exactly one
image), else repository:tag, with the tag defaulting to the chart's appVersion.
*/}}
{{- define "graph.image" -}}
{{- with .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .) -}}
{{- fail (printf "image.digest must be sha256:<64 lowercase hex characters>, got %q" .) -}}
{{- end -}}
{{ $.Values.image.repository }}@{{ . }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "graph.selectorLabels" -}}
app.kubernetes.io/name: graph
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Component label only. Pod templates already get app.kubernetes.io/name from
graph.labels, so they add just the component here — emitting selectorLabels too
would duplicate the name key, which the kustomize post-renderer rejects.
*/}}
{{- define "graph.componentLabels" -}}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
"true" when serve runs as its own ServiceAccount (serviceAccount.serveName set
and different from serviceAccount.name), else empty.
*/}}
{{- define "graph.serveServiceAccountSplit" -}}
{{- with .Values.serviceAccount.serveName }}{{ if ne . $.Values.serviceAccount.name }}true{{ end }}{{ end }}
{{- end -}}

{{/* The ServiceAccount the serve pod runs as. */}}
{{- define "graph.serveServiceAccountName" -}}
{{- if include "graph.serveServiceAccountSplit" . }}{{ .Values.serviceAccount.serveName }}{{ else }}{{ .Values.serviceAccount.name }}{{ end }}
{{- end -}}

{{/*
RBAC subject for the Kubernetes API grants (collector, policy-engine and
node-posture log reads): the worker's ServiceAccount only. The worker is the
one pod that calls the Kubernetes API (internal/collect/kubernetes, built only
by cmd/graph/worker.go); serve mounts no API token, and the scanner and the
node-posture reader run as ServiceAccounts of their own without one.
*/}}
{{- define "graph.workerServiceAccountSubjects" -}}
- kind: ServiceAccount
  name: {{ .Values.serviceAccount.name }}
  namespace: {{ .Release.Namespace }}
{{- end -}}

{{/* ServiceAccount metadata with the cloud identity annotations. */}}
{{- define "graph.serviceAccountMeta" -}}
metadata:
  name: {{ .name }}
  labels:
    {{- include "graph.labels" .root | nindent 4 }}
  {{- with .root.Values.serviceAccount }}
  {{- if or .gcpServiceAccount .annotations }}
  annotations:
    {{- if .gcpServiceAccount }}
    # GCP Workload Identity — keyless connector credentials (preferred over a
    # mounted key.json).
    iam.gke.io/gcp-service-account: {{ .gcpServiceAccount | quote }}
    {{- end }}
    {{- with .annotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- end }}
  {{- end }}
{{- end -}}

{{- define "graph.podEnv" -}}
{{- if .Values.metrics.enabled }}
# One switch for the whole metrics path: the listener, the scrape annotations,
# the container port and the pod labels the alert rules select on all derive from
# metrics.enabled. A per-component value would be a second source of truth for
# "is this pod observable".
- name: METRICS_PORT
  value: {{ .Values.metrics.port | quote }}
{{- end }}
- name: ADDR
  value: ":{{ .Values.service.port }}"
{{- if .Values.config.sccOrgId }}
- name: SCC_ORG_ID
  value: {{ .Values.config.sccOrgId | quote }}
- name: SCC_QUOTA_PROJECT
  value: {{ .Values.config.sccQuotaProject | quote }}
{{- end }}
{{- if .Values.config.adjudicatorEnabled }}
# LLM severity adjudicator. The worker builds it, and the scanner reads the
# flag to schedule the adjudicate sweep (PeriodicConfigFromEnv), so both pods
# need it; serve ignores it. Recurring LLM cost, bounded by the moderate posture
# (a per-sweep adjudication cap, N-cascade). ADJUDICATOR_MODEL overrides the
# model, e.g. to a cheaper tier once one is confirmed available in your
# deployment; empty uses the LLM provider's default model (llm.model / LLM_MODEL).
- name: ADJUDICATOR_ENABLED
  value: "1"
{{- if .Values.config.adjudicatorModel }}
- name: ADJUDICATOR_MODEL
  value: {{ .Values.config.adjudicatorModel | quote }}
{{- end }}
{{- end }}
{{- if .Values.config.driftAnalysisEnabled }}
# Advisory LLM drift analysis. The worker builds it, and the scanner reads the
# flag to schedule the drift sweep (PeriodicConfigFromEnv), so both pods need
# it; serve ignores it. It never starts a scan. DRIFT_ANALYSIS_MODEL overrides
# the model; empty uses the LLM provider's default (llm.model / LLM_MODEL).
- name: DRIFT_ANALYSIS_ENABLED
  value: "1"
{{- if .Values.config.driftAnalysisModel }}
- name: DRIFT_ANALYSIS_MODEL
  value: {{ .Values.config.driftAnalysisModel | quote }}
{{- end }}
{{- end }}
{{- if .Values.config.diskScanEnabled }}
# Agentless VM disk scanning. The worker plans and sweeps, the scanner reads the
# disks, and the scanner reads the flag to schedule the same periodics
# (PeriodicConfigFromEnv); serve ignores both. Each connector still opts in. The
# envelope key seals a connector's disk-scan credentials into the volume jobs so
# the scanner never needs GRAPH_SECRET_KEY; it opens nothing else.
- name: DISK_SCAN_ENABLED
  value: "1"
- name: DISK_SCAN_ENVELOPE_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: disk-scan-envelope-key } }
{{- end }}
{{- if .Values.scanner.scanInterval }}
# In podEnv, not the scanner's env: the worker and the scanner are both
# leader-electable River clients and whichever holds leadership enqueues the
# periodic jobs, so both must build the same schedule (internal/jobs/periodic.go).
- name: SCAN_INTERVAL
  value: {{ .Values.scanner.scanInterval | quote }}
{{- end }}
{{- if .Values.config.syncInterval }}
- name: SYNC_INTERVAL
  value: {{ .Values.config.syncInterval | quote }}
{{- end }}
{{- if .Values.config.correlateInterval }}
- name: CORRELATE_INTERVAL
  value: {{ .Values.config.correlateInterval | quote }}
{{- end }}
{{- if .Values.config.enrichInterval }}
- name: ENRICH_INTERVAL
  value: {{ .Values.config.enrichInterval | quote }}
{{- end }}
{{- if .Values.config.chMaxConcurrent }}
- name: CH_MAX_CONCURRENT
  value: {{ .Values.config.chMaxConcurrent | quote }}
{{- end }}
{{- if .Values.config.pgMaxConnsWorker }}
- name: PG_MAX_CONNS_WORKER
  value: {{ .Values.config.pgMaxConnsWorker | quote }}
{{- end }}
{{- if .Values.config.pgMaxConnsServe }}
- name: PG_MAX_CONNS_SERVE
  value: {{ .Values.config.pgMaxConnsServe | quote }}
{{- end }}
{{- if .Values.config.pgMaxConnsScanner }}
- name: PG_MAX_CONNS_SCANNER
  value: {{ .Values.config.pgMaxConnsScanner | quote }}
{{- end }}
{{- if .Values.config.githubMaxPages }}
- name: GITHUB_MAX_PAGES
  value: {{ .Values.config.githubMaxPages | quote }}
{{- end }}
{{- if .Values.config.oktaMaxPages }}
- name: OKTA_MAX_PAGES
  value: {{ .Values.config.oktaMaxPages | quote }}
{{- end }}
{{- if .Values.config.googleMaxPages }}
- name: GOOGLE_MAX_PAGES
  value: {{ .Values.config.googleMaxPages | quote }}
{{- end }}
{{- if .Values.ladybug.enabled }}
- name: LADYBUG_RPC_URL
  value: http://graph-ladybug-internal:8090
- name: LADYBUG_RPC_SECRET
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: ladybug-rpc-secret } }
{{- end }}
{{- if .Values.serveLadybug.enabled }}
- name: SERVE_LADYBUG_ENABLED
  value: "true"
- name: SERVE_LADYBUG_BUFFER_MB
  value: {{ .Values.serveLadybug.bufferMB | default 512 | quote }}
{{- end }}
{{- if .Values.config.oauth2Proxy }}
{{- if not (and .Values.networkPolicy.enabled .Values.networkPolicy.ingressNamespace) }}
{{- fail "config.oauth2Proxy requires networkPolicy.enabled and networkPolicy.ingressNamespace: the X-Auth-Request-Email path is only as private as serve's port, which accepts every source until ingressNamespace limits it to the ingress controller (and networkPolicy.nodeCIDRs)." }}
{{- end }}
- name: OAUTH2_PROXY
  value: "true"
{{- with .Values.config.oauth2ProxyOidcIssuer }}
# Verify the IdP-signed ID token oauth2-proxy forwards (--set-authorization-header).
- name: OAUTH2_PROXY_OIDC_ISSUER
  value: {{ . | quote }}
- name: OAUTH2_PROXY_OIDC_AUDIENCE
  value: {{ required "config.oauth2ProxyOidcAudience (the oauth2-proxy client id) is required with config.oauth2ProxyOidcIssuer" $.Values.config.oauth2ProxyOidcAudience | quote }}
{{- end }}
{{- if .Values.config.oauth2ProxyTrustGroups }}
- name: OAUTH2_PROXY_TRUST_GROUPS
  value: "true"
{{- end }}
{{- if .Values.config.oauth2ProxyOidcAllowUnverifiedEmail }}
- name: OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL
  value: "true"
{{- end }}
{{- if .Values.config.oauth2ProxyAllowedDomains }}
- name: OAUTH2_PROXY_ALLOWED_DOMAINS
  value: {{ .Values.config.oauth2ProxyAllowedDomains | quote }}
{{- end }}
{{- if .Values.config.oauth2ProxyAllowAnyDomain }}
- name: OAUTH2_PROXY_ALLOW_ANY_DOMAIN
  value: "true"
{{- end }}
{{- end }}
{{- if .Values.config.iapAudience }}
- name: IAP_AUDIENCE
  value: {{ .Values.config.iapAudience | quote }}
{{- if not (or .Values.config.iapAllowedDomains .Values.config.iapAllowAnyDomain) }}
{{- fail "config.iapAudience is set but config.iapAllowedDomains is empty: serve would refuse every IAP sign-in. Set iapAllowedDomains (or iapAllowAnyDomain=true deliberately)." }}
{{- end }}
{{- if .Values.config.iapAllowedDomains }}
- name: IAP_ALLOWED_DOMAINS
  value: {{ .Values.config.iapAllowedDomains | quote }}
{{- end }}
{{- if .Values.config.iapAllowAnyDomain }}
- name: IAP_ALLOW_ANY_DOMAIN
  value: "true"
{{- end }}
{{- end }}
{{- if .Values.config.clientIpHeader }}
{{- if not .Values.config.trustedProxyCidrs }}
{{- fail "config.clientIpHeader is set but config.trustedProxyCidrs is empty: serve would ignore the header. Set trustedProxyCidrs to the ingress controller's pod/node ranges." }}
{{- end }}
- name: CLIENT_IP_HEADER
  value: {{ .Values.config.clientIpHeader | quote }}
- name: TRUSTED_PROXY_CIDRS
  value: {{ .Values.config.trustedProxyCidrs | quote }}
{{- end }}
{{- with .Values.config.adminEmails }}
- name: ADMIN_EMAILS
  value: {{ . | quote }}
{{- end }}
{{- with .Values.config.oidcAdminGroups }}
- name: OIDC_ADMIN_GROUPS
  value: {{ . | quote }}
{{- end }}
{{- with .Values.config.oidcAnalystGroups }}
- name: OIDC_ANALYST_GROUPS
  value: {{ . | quote }}
{{- end }}
{{- with .Values.config.oidcRequiredGroups }}
- name: OIDC_REQUIRED_GROUPS
  value: {{ . | quote }}
{{- end }}
{{- if .Values.forget.mode }}
# Only the worker builds forget.Service (cmd/graph/worker_deps.go); the
# serve/scanner pods ignore both vars entirely. shadow is also forget.ParseMode's
# own zero-value default, but naming it here makes your values override the one place
# that says which mode is live, rather than an absent key meaning the same thing
# as an explicit "shadow" by coincidence.
- name: FORGET_MODE
  value: {{ .Values.forget.mode | quote }}
{{- end }}
{{- if .Values.forget.enforceTypes }}
# Comma-separated asset types (e.g. "security_group,vpc") FORGET_MODE=enforce is
# allowed to tombstone; every other audited type stays shadow-only regardless of
# mode. Unset (the default) enforces NOTHING under enforce mode; a type outside
# forget.TombstoneEligibleTypes stops the worker at startup — see
# forget.ParseEnforceTypes. Deliberately only
# emitted when non-empty: an empty FORGET_ENFORCE_TYPES="" and an absent env var
# reach forget.ParseEnforceTypes identically (both parse to a nil allow-list), so
# there is no behavioural difference, and omitting it keeps `helm template`'s
# diff clean when this value is unset.
- name: FORGET_ENFORCE_TYPES
  value: {{ .Values.forget.enforceTypes | quote }}
{{- end }}
{{- end -}}

{{/*
The datastore DSNs. serve and the worker connect as the app users
(database-url, clickhouse-url). The migrate init container takes
clickhouse-migrate-url, the ClickHouse user that may change the schema; on
Postgres it is the app role, which owns the database (River's reindexing needs
the owner). The scanner takes scanner-database-url and scanner-clickhouse-url,
its own users with only what the scan jobs use.
Usage: {{ include "graph.datastoreEnv" (dict "migrate" true "Values" .Values) }}
       {{ include "graph.datastoreEnv" (dict "scanner" true "Values" .Values) }}
*/}}
{{- define "graph.datastoreEnv" -}}
- name: DATABASE_URL
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: {{ ternary "scanner-database-url" "database-url" (.scanner | default false) }} } }
- name: CLICKHOUSE_URL
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: {{ ternary "scanner-clickhouse-url" (ternary "clickhouse-migrate-url" "clickhouse-url" (.migrate | default false)) (.scanner | default false) }} } }
{{- end -}}

{{/*
Application secrets: the credential master key (connector configs, alert
channels, TOTP seeds, the second-admin grant key), the LLM provider and the
approval / decision-webhook signing secrets. serve, migrate and worker get
them; the scanner does not, because it decrypts nothing, calls no LLM and signs
nothing (cmd/graph/scanner.go). Keeping them out of the pod that parses
untrusted scan responses is the point (docs/security-hardening.md).
*/}}
{{- define "graph.appSecretEnv" -}}
- name: GRAPH_SECRET_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: secret-key } }
# Previous keys, trusted for reads only while `graph keys rewrap` re-seals the
# stored credentials under secret-key (deploy/README.md, "Rotating").
- name: GRAPH_RETIRED_SECRET_KEYS
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: retired-secret-keys, optional: true } }
# LLM provider (optional — every LLM feature degrades without one). The key
# refs are optional so a Secret managed out of band (secret.create=false) may
# carry either the provider-neutral llm-api-key or the legacy anthropic-api-key.
- name: LLM_API_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: llm-api-key, optional: true } }
- name: ANTHROPIC_API_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: anthropic-api-key, optional: true } }
{{- with .Values.llm }}
{{- if .provider }}
- name: LLM_PROVIDER
  value: {{ .provider | quote }}
{{- end }}
{{- if .baseURL }}
- name: LLM_BASE_URL
  value: {{ .baseURL | quote }}
{{- end }}
{{- if .model }}
- name: LLM_MODEL
  value: {{ .model | quote }}
{{- end }}
{{- if .fastModel }}
- name: LLM_FAST_MODEL
  value: {{ .fastModel | quote }}
{{- end }}
{{- if .reasoningEffort }}
- name: LLM_REASONING_EFFORT
  value: {{ .reasoningEffort | quote }}
{{- end }}
{{- end }}
{{- if .Values.config.decisionWebhookUrl }}
- name: DECISION_WEBHOOK_URL
  value: {{ .Values.config.decisionWebhookUrl | quote }}
# Worker-only: signs the webhook. Optional so an externally managed Secret
# without the key still starts; the worker then refuses to send unless
# config.decisionWebhookAllowUnsigned is set.
- name: DECISION_WEBHOOK_SECRET
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: decision-webhook-secret, optional: true } }
{{- if .Values.config.decisionWebhookAllowUnsigned }}
- name: DECISION_WEBHOOK_ALLOW_UNSIGNED
  value: "true"
{{- end }}
{{- end }}
{{- if or .Values.config.smtpHost .Values.secret.approvalTokenSecret }}
# Email approval links: the worker signs them, serve verifies them, so both
# pods must read the same value.
- name: APPROVAL_TOKEN_SECRET
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: approval-token-secret, optional: true } }
{{- end }}
{{- if .Values.config.approvalWebhookUrl }}
- name: APPROVAL_WEBHOOK_URL
  value: {{ .Values.config.approvalWebhookUrl | quote }}
# Serve refuses to start with the URL and no secret unless
# config.approvalWebhookAllowUnsigned is true.
- name: APPROVAL_WEBHOOK_SECRET
  valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: approval-webhook-secret, optional: true } }
{{- if .Values.config.approvalWebhookAllowUnsigned }}
- name: APPROVAL_WEBHOOK_ALLOW_UNSIGNED
  value: "true"
{{- end }}
{{- end }}
{{- end -}}

{{/*
Pod-level security context.

The image already runs as uid 65532 (Dockerfile: USER nonroot), but nothing in
the manifest SAID so, which means nothing enforced it: a rebuilt or swapped
image running as root would have been admitted silently. runAsNonRoot makes the
kubelet refuse such an image outright.

fsGroup is passed in by the caller because only the two pods with a PVC need it
(it makes the Ladybug snapshot file group-writable by the nonroot user); adding it
where there is no volume changes nothing but reads as though it does.

Usage: {{- include "graph.podSecurityContext" (dict "fsGroup" 65532 "Values" .Values) | nindent 6 }}
*/}}
{{- define "graph.podSecurityContext" -}}
{{- if .Values.securityContext.enabled }}
securityContext:
  runAsNonRoot: true
  runAsUser: {{ .Values.securityContext.runAsUser }}
  runAsGroup: {{ .Values.securityContext.runAsUser }}
  {{- if .fsGroup }}
  fsGroup: {{ .fsGroup }}
  {{- end }}
  seccompProfile:
    type: RuntimeDefault
{{- else if .fsGroup }}
securityContext:
  fsGroup: {{ .fsGroup }}
{{- end }}
{{- end -}}

{{/*
Container-level security context.

readOnlyRootFilesystem is the load-bearing one and the one with a real failure
mode: the binary DOES write outside its volumes — the worker stages Ladybug COPY
CSVs in os.TempDir() when /dev/shm has no headroom (graphstore/copy_load.go
copyTmpDir), and nuclei template validation writes os.CreateTemp files
(scanner/nuclei/template_service.go). Every deployment that uses this helper
therefore also mounts graph.tmpVolume at /tmp; a read-only root without that
mount turns a graph rebuild into a crash loop.

Paths the app writes, and where they come from:
  /tmp              emptyDir (graph.tmpVolume) — worker CSV staging, nuclei temp files
  /home/nonroot     emptyDir (graph.tmpVolume) — nuclei config and template download
  /dev/shm          provided by the container runtime, unaffected by this flag
  /data/ladybug        PVC, group-owned via fsGroup
  /data/serve-ladybug  PVC, group-owned via fsGroup

securityContext.readOnlyRootFilesystem is a separate value from
securityContext.enabled so it can be turned off alone if a future writer is
discovered later, without also giving up runAsNonRoot and the dropped
capabilities.
*/}}
{{- define "graph.containerSecurityContext" -}}
{{- if .Values.securityContext.enabled }}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: {{ .Values.securityContext.readOnlyRootFilesystem }}
  capabilities:
    drop: ["ALL"]
{{- end }}
{{- end -}}

{{/*
The writable scratch volume that makes readOnlyRootFilesystem survivable.
Disk-backed (not tmpfs) because the worker's CSV staging can be large; capped so
a runaway write cannot fill the node's ephemeral storage.
*/}}
{{- define "graph.tmpVolume" -}}
- name: tmp
  emptyDir:
    sizeLimit: {{ .Values.securityContext.tmpSizeLimit }}
# nuclei writes its template config to $HOME/.config/nuclei on first run, and
# the pinned nuclei-templates release is downloaded into
# $HOME/nuclei-templates-<version>-<sha256> unless NUCLEI_TEMPLATES_DIR is set, so
# homeSizeLimit must hold the whole template set.
# It does not fall back to a temp dir. Under readOnlyRootFilesystem without this volume
# it logs:
#
#   failed to create config directory at /home/nonroot/.config/nuclei got:
#   mkdir /home/nonroot/.config: read-only file system
#
# Non-fatal — the pod stays ready — but the scanner cannot persist template
# state, which is exactly the kind of quiet degradation that reads as "nuclei is
# just quiet". A separate volume rather than HOME=/tmp: HOME is read by more than
# nuclei, and redirecting it to a shared scratch dir is a wider blast radius than
# the problem.
- name: home
  emptyDir:
    sizeLimit: {{ .Values.securityContext.homeSizeLimit | default "1Gi" }}
{{- end -}}

{{/*
The bundled Postgres's CA certificate (ca.crt of postgres.tlsSecret), mounted
into every graph container when postgres.sslMode is verify-ca or verify-full so
the DSN's sslrootcert can name it. Only that one key is projected: the
server's private key never reaches the graph pods.
*/}}
{{- define "graph.postgresVerifies" -}}
{{- if and .Values.postgres.enabled .Values.postgres.tlsSecret (has (.Values.postgres.sslMode | default "prefer") (list "verify-ca" "verify-full")) }}true{{ end }}
{{- end -}}

{{- define "graph.dbCAVolume" -}}
{{- if include "graph.postgresVerifies" . }}
- name: postgres-ca
  secret:
    secretName: {{ .Values.postgres.tlsSecret }}
    items: [{ key: ca.crt, path: ca.crt }]
{{- end }}
{{- end -}}

{{- define "graph.dbCAVolumeMount" -}}
{{- if include "graph.postgresVerifies" . }}
- name: postgres-ca
  mountPath: /etc/graph/postgres-ca
  readOnly: true
{{- end }}
{{- end -}}

{{- define "graph.tmpVolumeMount" -}}
- name: tmp
  mountPath: /tmp
- name: home
  mountPath: /home/nonroot
{{- end -}}

{{/*
Name for an object outside the release namespace: a cluster-scoped one
(ClusterRole, ClusterRoleBinding) or the VMRule in the shared alerts.namespace.
Objects in the release namespace use fixed graph-* names (one release per
namespace), but these share one namespace across installs, so a second install
in another namespace would overwrite the first's. Prefixing with the namespace
and release keeps each install's objects its own.
Usage: {{ include "graph.clusterScopedName" (dict "suffix" "policy-engine-reader" "Release" .Release) }}
*/}}
{{- define "graph.clusterScopedName" -}}
{{ printf "%s-%s-%s" .Release.Namespace .Release.Name .suffix }}
{{- end -}}

{{/*
A graph container's env: the chart-set entries (.chart, a rendered YAML list)
plus operator-supplied extraEnv — chart-wide first, then the component's own
(serve.extraEnv, worker.extraEnv, scanner.extraEnv). The scanner takes only its
own: it runs nuclei and holds no app secret, so a chart-wide entry carrying
GRAPH_SECRET_KEY or the LLM key must not reach it. Every name is emitted once:
an extraEnv entry replaces a chart-set entry of the same name, and a component
entry replaces a chart-wide one, so the operator's value is the only one in the
pod spec rather than a duplicate whose winner depends on kubelet ordering.
Usage: {{- include "graph.env" (dict "component" "serve" "Values" .Values "chart" (include "graph.chartEnv.serve" .)) | nindent 12 }}
*/}}
{{- define "graph.env" -}}
{{- $component := index .Values .component | default dict -}}
{{- $global := ternary list (.Values.extraEnv | default list) (eq .component "scanner") -}}
{{- $extra := concat $global ($component.extraEnv | default list) -}}
{{- $chart := fromYamlArray (.chart | default "[]") | default list -}}
{{- if and $chart (kindIs "string" (first $chart)) -}}
{{- fail (printf "graph.env: chart env for %s is not a YAML list: %s" .component (first $chart)) -}}
{{- end -}}
{{- $names := list -}}
{{- $byName := dict -}}
{{- range $extra -}}
{{- $name := required "every extraEnv entry needs a name" .name -}}
{{- if not (hasKey $byName $name) -}}
{{- $names = append $names $name -}}
{{- end -}}
{{- $_ := set $byName $name . -}}
{{- end -}}
{{- $out := list -}}
{{- range $chart -}}
{{- if not (hasKey $byName .name) -}}
{{- $out = append $out . -}}
{{- end -}}
{{- end -}}
{{- range $names -}}
{{- $out = append $out (get $byName .) -}}
{{- end -}}
{{- with $out }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
envFrom for a graph container: chart-wide extraEnvFrom plus the component's
own, except the scanner, which takes only scanner.extraEnvFrom (see graph.env).
Emits nothing when both are empty.
Usage: {{- include "graph.envFrom" (dict "component" "serve" "Values" .Values) | nindent 10 }}
*/}}
{{- define "graph.envFrom" -}}
{{- $component := index .Values .component | default dict -}}
{{- $global := ternary list (.Values.extraEnvFrom | default list) (eq .component "scanner") -}}
{{- $from := concat $global ($component.extraEnvFrom | default list) -}}
{{- with $from }}
envFrom:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
AWS web-identity federation (aws.enabled). The worker's collectors and the
serve pod's connector "Test" button (internal/app/connector) both call AWS, so
both pods project the token and carry the AWS_* environment.
*/}}
{{- define "graph.awsVolume" -}}
{{- if .Values.aws.enabled }}
- name: aws-token
  projected:
    sources:
      - serviceAccountToken:
          audience: {{ .Values.aws.audience | quote }}
          expirationSeconds: {{ .Values.aws.tokenExpirationSeconds }}
          path: token
{{- end }}
{{- end -}}

{{- define "graph.awsVolumeMount" -}}
{{- if .Values.aws.enabled }}
- name: aws-token
  mountPath: /var/run/secrets/aws
  readOnly: true
{{- end }}
{{- end -}}

{{- define "graph.awsEnv" -}}
{{- if .Values.aws.enabled }}
- name: AWS_ROLE_ARN
  value: {{ required "aws.roleArn is required when aws.enabled" .Values.aws.roleArn | quote }}
- name: AWS_WEB_IDENTITY_TOKEN_FILE
  value: /var/run/secrets/aws/token
- name: AWS_REGION
  value: {{ .Values.aws.region | quote }}
- name: AWS_STS_REGIONAL_ENDPOINTS
  value: regional
{{- end }}
{{- end -}}

{{/*
graph.checkSecretKey fails the render unless .key is what the binary's
GRAPH_SECRET_KEY parser accepts: standard padded base64 of exactly 32 bytes
(44 characters; line breaks are ignored, as Go's decoder ignores them).
*/}}
{{- define "graph.checkSecretKey" -}}
{{- $k := .key | replace "\n" "" | replace "\r" "" -}}
{{- if not (regexMatch "^[A-Za-z0-9+/]{43}=$" $k) -}}
{{- fail (printf "%s must be base64 of exactly 32 bytes (generate one with: openssl rand -base64 32)" .name) -}}
{{- end -}}
{{- end -}}
