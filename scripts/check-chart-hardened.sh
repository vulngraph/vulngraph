#!/usr/bin/env bash
# Renders the hardened overlay with the operator's values, then makes one
# change at a time and fails unless hardened: true (templates/checks/hardened.yaml)
# refuses the render and names the gap. TestHardenedScriptCoversEveryCheck
# keeps a case here for every check there.
#
#   scripts/check-chart-hardened.sh <chart> <overlay>
set -euo pipefail
chart="$1"; overlay="$2"

# secretKey must be base64 of 32 bytes (the chart checks it): 32 zero bytes.
secrets=secret.secretKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,secret.postgresPassword=ci-pg,secret.postgresSuperuserPassword=ci-pg-su,secret.clickhousePassword=ci-ch,secret.clickhouseMigratePassword=ci-ch-migrate,secret.postgresScannerPassword=ci-pg-scan,secret.clickhouseScannerPassword=ci-ch-scan
digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
# Strings and lists only: Helm applies --set-json before --set-string, so a
# case overrides one of these with the same flag, and a bool with --set.
operator=(
  --set config.diskScanEnabled=true
  --set-string "image.digest=$digest,ingress.host=graph.example.com"
  --set-string "networkPolicy.ingressNamespace=ingress-nginx,networkPolicy.metricsNamespace=monitoring"
  --set-string "config.trustedProxyCidrs=10.244.0.0/16,postgres.tlsSecret=pg-tls,clickhouse.tlsSecret=ch-tls"
  --set-json 'networkPolicy.nodeCIDRs=["10.0.0.0/16"]'
)
external=(--set postgres.enabled=false --set clickhouse.enabled=false
  --set-string 'secret.databaseUrl=postgres://u:p@db:5432/graph?sslmode=verify-full'
  --set-string 'secret.clickhouseUrl=clickhouse://u:p@ch:9440/graph?secure=true'
  --set-string 'secret.scannerDatabaseUrl=postgres://s:p@db:5432/graph?sslmode=verify-full'
  --set-string 'secret.scannerClickhouseUrl=clickhouse://s:p@ch:9440/graph?secure=true')

render() { helm template graph "$chart" -f "$overlay" --set-string "$secrets" "${operator[@]}" "$@"; }

failed=0
# renders <what> <args...>: the overlay renders with these changes.
renders() {
  local what="$1"; shift
  if ! render "$@" > /dev/null; then
    echo "FAIL: the hardened overlay did not render with $what" >&2; failed=1
  fi
}
# refuses <gap> <args...>: hardened: true refuses the render, naming <gap>.
refuses() {
  local want="$1" err; shift
  if err=$(render "$@" 2>&1 > /dev/null); then
    echo "FAIL: rendered, want a refusal naming: $want" >&2; failed=1; return
  fi
  if ! grep -q 'hardened: true refuses to render' <<<"$err" || ! grep -qF -- "$want" <<<"$err"; then
    echo "FAIL: want a hardened refusal naming: $want; got:" >&2; echo "$err" >&2; failed=1
  fi
}

helm lint --strict "$chart" -f "$overlay" --set-string "$secrets" "${operator[@]}" > /dev/null
renders "the operator's values"
serve=$(render --show-only templates/deployment-serve.yaml)
for env in REQUIRE_ADMIN_TOTP TLS_PROXY; do
  if ! grep -A1 "name: $env\$" <<<"$serve" | grep -q 'value: "true"'; then
    echo "FAIL: the hardened overlay did not set $env=true on serve" >&2; failed=1
  fi
done

err=$(helm template graph "$chart" -f "$overlay" --set-string "$secrets" 2>&1 > /dev/null || true)
for gap in image.digest ingress.host networkPolicy.ingressNamespace networkPolicy.nodeCIDRs \
  networkPolicy.metricsNamespace config.trustedProxyCidrs postgres.tlsSecret clickhouse.tlsSecret; do
  if ! grep -qF "$gap" <<<"$err"; then
    echo "FAIL: the overlay alone rendered, or its refusal does not name $gap" >&2; failed=1
  fi
done

refuses image.digest --set-string image.digest=
refuses securityContext.readOnlyRootFilesystem --set securityContext.readOnlyRootFilesystem=false
refuses securityContext.enabled --set securityContext.enabled=false
refuses scanner.enabled --set scanner.enabled=false
refuses worker.pprofPort --set-string worker.pprofPort=6060
refuses 'networkPolicy.enabled must be true' --set networkPolicy.enabled=false
refuses networkPolicy.ingressNamespace --set-string networkPolicy.ingressNamespace=
refuses networkPolicy.nodeCIDRs --set-json 'networkPolicy.nodeCIDRs=[]'
# A range wider than its family allows is refused: /8 for IPv4, /32 for IPv6,
# /7 inside fc00::/7. auth.ParseTrustedProxies reads an
# IPv4-mapped range of /96 or longer as the IPv4 range of 96 bits fewer, in
# any spelling, so ::ffff:0:0/96 is 0.0.0.0/0.
wide=(0.0.0.0/0 ::/0 0.0.0.0/1 128.0.0.0/1 0.0.0.0/7 2000::/3 ::ffff:0:0/96 ::FFFF:0.0.0.0/96 ::0:ffff:0:0/100
  0:0:0:0:0:ffff:0:0/103 0000:0::ffff:0.0.0.0/96 1.2.3.4/x 2000::/8 2001::/16 fd::/8)
narrow=(10.0.0.0/8 10.0.0.0/16 10.1.2.3 fd00::/8 fc00::/7 fd00:10::/32 2001:db8::/32 ::ffff:0:0/104 ::ffff:10.0.0.0/104 ::ffff:0:0/80
  2001:db8:ffff::/96)
for cidr in "${wide[@]}"; do
  refuses "networkPolicy.nodeCIDRs holds $cidr, a range too wide" --set-json "networkPolicy.nodeCIDRs=[\"10.0.0.0/16\",\"$cidr\"]"
  refuses "config.trustedProxyCidrs holds $cidr, a range too wide" --set-string "config.trustedProxyCidrs=10.244.0.0/16\, $cidr"
done
for cidr in "${narrow[@]}"; do
  renders "networkPolicy.nodeCIDRs $cidr" --set-json "networkPolicy.nodeCIDRs=[\"$cidr\"]"
  renders "config.trustedProxyCidrs $cidr" --set-string "config.trustedProxyCidrs=$cidr"
done
refuses networkPolicy.metricsNamespace --set-string networkPolicy.metricsNamespace=
refuses ingress.host --set-string ingress.host=
refuses 'ingress.enabled and ingress.host' --set ingress.enabled=false
refuses config.tlsProxy --set config.tlsProxy=false
refuses config.trustedProxyCidrs --set-string config.trustedProxyCidrs=
refuses config.clientIpHeader --set-string config.clientIpHeader=
refuses config.requireAdminTotp --set config.requireAdminTotp=false

# SSO: no first-sign-in bootstrap admin, ID-token verification behind
# oauth2-proxy, and https redirect URLs.
oidc=(--set-string "config.oauth2ProxyOidcIssuer=https://idp.example.com,config.oauth2ProxyOidcAudience=graph")
refuses config.adminEmails --set config.oauth2Proxy=true "${oidc[@]}"
# serve's splitCSV trims every unicode.IsSpace rune (tab, vertical tab, NEL,
# no-break space, ideographic space ...), so a value of only those is unset.
for blank in ' \, ' "$(printf '\t\v\f\r')" "$(printf '\xc2\x85')" "$(printf '\xc2\xa0')" "$(printf '\xe3\x80\x80')" \
  "$(printf '\xe2\x80\xa8')"; do
  refuses config.adminEmails --set config.oauth2Proxy=true "${oidc[@]}" --set-string "config.adminEmails=$blank"
done
renders "oauth2Proxy, ID-token verification and adminEmails" --set config.oauth2Proxy=true "${oidc[@]}" \
  --set-string config.adminEmails=admin@example.com
renders "oauth2Proxy with analyst groups only (no bootstrap admin)" --set config.oauth2Proxy=true "${oidc[@]}" \
  --set-string config.oidcAnalystGroups=analysts
refuses config.oauth2ProxyOidcIssuer --set config.oauth2Proxy=true --set-string config.oidcAdminGroups=admins
for idp in google okta; do
  refuses "sso.$idp.redirectUrl must be an https:// URL" --set-string "sso.$idp.clientId=graph" \
    --set-string "sso.$idp.redirectUrl=http://graph.example.com/api/auth/$idp/callback" \
    --set-string config.adminEmails=admin@example.com
done

# Every chart value that weakens a check, and every dangerous flag in every
# extraEnv list.
for key in config.oauth2ProxyAllowAnyDomain config.oauth2ProxyTrustGroups config.oauth2ProxyOidcAllowUnverifiedEmail \
  config.iapAllowAnyDomain sso.google.allowAnyDomain sso.okta.allowAnyDomain \
  config.decisionWebhookAllowUnsigned config.approvalWebhookAllowUnsigned config.smtpAllowPlaintext; do
  refuses "$key must be false" --set "$key=true"
done
for flag in BYPASS_AUTH BYPASS_AUTH_I_UNDERSTAND LADYBUG_RPC_INSECURE SCAN_ALLOW_INTERNAL_TARGETS COOKIE_INSECURE \
  OAUTH_REDIRECT_FROM_HOST OAUTH2_PROXY_ALLOW_ANY_DOMAIN OAUTH2_PROXY_TRUST_GROUPS \
  OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL GOOGLE_ALLOW_ANY_DOMAIN OKTA_ALLOW_ANY_DOMAIN IAP_ALLOW_ANY_DOMAIN \
  APPROVAL_WEBHOOK_ALLOW_UNSIGNED DECISION_WEBHOOK_ALLOW_UNSIGNED SMTP_ALLOW_PLAINTEXT \
  PASSWORD_LOGIN_BREAK_GLASS PPROF_PORT; do
  refuses "serve.extraEnv sets $flag" --set-string "serve.extraEnv[0].name=$flag,serve.extraEnv[0].value=true"
done
for list in extraEnv migrate.extraEnv worker.extraEnv scanner.extraEnv; do
  refuses "$list sets BYPASS_AUTH" --set-string "${list}[0].name=BYPASS_AUTH,${list}[0].value=true"
done

# extraEnv replaces a variable of the same name the chart sets (graph.env), so
# every chart-set name is refused on the components the list reaches, and the
# variables a check reads through a chart value are refused even unset.
for name in DATABASE_URL CLICKHOUSE_URL REQUIRE_ADMIN_TOTP TLS_PROXY CLIENT_IP_HEADER TRUSTED_PROXY_CIDRS \
  OAUTH2_PROXY OAUTH2_PROXY_SHARED_SECRET OAUTH2_PROXY_OIDC_ISSUER OAUTH2_PROXY_OIDC_AUDIENCE OAUTH2_PROXY_ALLOWED_DOMAINS \
  IAP_AUDIENCE IAP_ALLOWED_DOMAINS GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET GOOGLE_REDIRECT_URL GOOGLE_ALLOWED_DOMAINS \
  OKTA_CLIENT_ID OKTA_CLIENT_SECRET OKTA_DOMAIN OKTA_REDIRECT_URL OKTA_ALLOWED_DOMAINS \
  ADMIN_EMAILS OIDC_ADMIN_GROUPS OIDC_ANALYST_GROUPS OIDC_REQUIRED_GROUPS \
  DECISION_WEBHOOK_URL DECISION_WEBHOOK_SECRET APPROVAL_WEBHOOK_URL APPROVAL_WEBHOOK_SECRET \
  APPROVAL_TOKEN_SECRET APPROVAL_BASE_URL SMTP_HOST; do
  refuses "serve.extraEnv sets $name, which the chart sets" --set-string "serve.extraEnv[0].name=$name,serve.extraEnv[0].value=x"
done
refuses 'extraEnv sets DATABASE_URL, which the chart sets' \
  --set-string 'extraEnv[0].name=DATABASE_URL,extraEnv[0].value=postgres://u:p@db:5432/graph?sslmode=disable'
refuses 'extraEnv sets GRAPH_SECRET_KEY, which the chart sets' --set-string 'extraEnv[0].name=GRAPH_SECRET_KEY,extraEnv[0].value=x'
refuses 'migrate.extraEnv sets CLICKHOUSE_URL, which the chart sets' --set-string 'migrate.extraEnv[0].name=CLICKHOUSE_URL,migrate.extraEnv[0].value=x'
refuses 'worker.extraEnv sets SCAN_WORKER_DISABLED, which the chart sets' \
  --set-string 'worker.extraEnv[0].name=SCAN_WORKER_DISABLED,worker.extraEnv[0].value=false'
refuses 'scanner.extraEnv sets ADDR, which the chart sets' --set-string 'scanner.extraEnv[0].name=ADDR,scanner.extraEnv[0].value=:9'
for list in extraEnv serve.extraEnv worker.extraEnv scanner.extraEnv; do
  renders "$list OFFLINE_MODE" --set-string "${list}[0].name=OFFLINE_MODE,${list}[0].value=true"
done
renders "scanner.extraEnv GOMEMLIMIT (the chart sets none on the scanner)" \
  --set-string 'scanner.extraEnv[0].name=GOMEMLIMIT,scanner.extraEnv[0].value=2GiB'
for list in extraEnvFrom serve.extraEnvFrom migrate.extraEnvFrom worker.extraEnvFrom scanner.extraEnvFrom; do
  refuses "$list must be empty" --set-string "${list}[0].secretRef.name=graph-extra"
done

# Signed webhooks and approval links.
refuses secret.decisionWebhookSecret --set-string config.decisionWebhookUrl=https://hooks.example.com/decision
refuses secret.approvalWebhookSecret --set-string config.approvalWebhookUrl=https://hooks.example.com/approval
for hook in decision approval; do
  refuses "config.${hook}WebhookUrl must be an https:// URL" --set-string "config.${hook}WebhookUrl=http://hooks.example.com/$hook" \
    --set-string "secret.${hook}WebhookSecret=ci-$hook-signing-secret"
done
mail=(--set-string "config.smtpHost=smtp.example.com,config.smtpFrom=graph@example.com")
approval_secret=ci-approval-link-signing-secret-32b
refuses secret.approvalTokenSecret "${mail[@]}" --set-string config.approvalBaseUrl=https://graph.example.com \
  --set-string secret.approvalTokenSecret=short
refuses 'config.approvalBaseUrl must be an https:// URL' "${mail[@]}" \
  --set-string config.approvalBaseUrl=http://graph.example.com --set-string "secret.approvalTokenSecret=$approval_secret"

# Datastore TLS, bundled and external.
refuses 'secret.create must be true' --set secret.create=false
refuses postgres.tlsSecret --set-string postgres.tlsSecret=
refuses 'postgres.sslMode must be' --set-string postgres.sslMode=prefer
refuses clickhouse.tlsSecret --set-string clickhouse.tlsSecret=
refuses 'clickhouse.secure must be true' --set clickhouse.secure=false
renders "external datastores over TLS" "${external[@]}"
for dsn in 'postgresql://u:p@db:5432/graph?sslmode=require&sslrootcert=/etc/ca.crt' \
  'postgres://u:p@db:5432/graph?sslmode=verify-ca#primary'; do
  renders "secret.databaseUrl $dsn" "${external[@]}" --set-string "secret.databaseUrl=$dsn"
done
# pgx keeps the first sslmode, decodes percent escapes in keys, and reads a
# string that is not a postgres:// URL as keyword/value pairs.
for dsn in 'postgres://u:p@db:5432/graph' 'postgres://u:p@db:5432/graph?sslmode=disable' \
  'postgres://u:p@db:5432/graph?sslmode=allow' 'postgres://u:p@db:5432/graph?sslmode=prefer' \
  'postgres://u:p@db:5432/graph?sslmode=disable&sslmode=require' \
  'postgres://u:p@db:5432/graph?sslmod%65=disable&sslmode=require' \
  'postgres://u:p@db:5432/graph#?sslmode=require' 'host=db dbname=graph sslmode=require'; do
  refuses 'secret.databaseUrl must be a postgres:// URL' "${external[@]}" --set-string "secret.databaseUrl=$dsn"
done
for query in 'secure=1' 'secure=TRUE' 'secure' 'secure=t&dial_timeout=5s'; do
  renders "secret.clickhouseUrl ...?$query" "${external[@]}" \
    --set-string "secret.clickhouseUrl=clickhouse://u:p@ch:9440/graph?$query"
done
for query in '' '?secure=false' '?secure=0' '?secure=false&secure=true' '?secur%65=false&secure=true' \
  '?dial_timeout=5s' '?insecure=true'; do
  refuses 'secret.clickhouseUrl must carry secure=true' "${external[@]}" \
    --set-string "secret.clickhouseUrl=clickhouse://u:p@ch:9440/graph$query"
done
refuses 'secret.clickhouseMigrateUrl must carry secure=true' "${external[@]}" \
  --set-string 'secret.clickhouseMigrateUrl=clickhouse://m:p@ch:9440/graph?secure=false'
refuses 'secret.scannerDatabaseUrl must be a postgres:// URL' "${external[@]}" \
  --set-string 'secret.scannerDatabaseUrl=postgres://s:p@db:5432/graph?sslmode=disable'
refuses 'secret.scannerClickhouseUrl must carry secure=true' "${external[@]}" \
  --set-string 'secret.scannerClickhouseUrl=clickhouse://s:p@ch:9440/graph?secure=false'

if [ "$failed" -ne 0 ]; then exit 1; fi
echo "hardened: the overlay renders with the operator's values, and every check refuses its gap"
