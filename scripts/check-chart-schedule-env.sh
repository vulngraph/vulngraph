#!/usr/bin/env bash
# Fails when the rendered worker and scanner containers disagree on any env
# var internal/jobs.PeriodicConfigFromEnv reads. Both pods are leader-electable
# River clients and only the leader enqueues periodic jobs, so a var set on one
# pod only means the job runs or not depending on which pod holds leadership.
#
#   scripts/check-chart-schedule-env.sh <chart> [helm template args...]
set -euo pipefail
chart="$1"; shift
# Every key PeriodicConfigFromEnv reads, feed switches included;
# jobs.TestChartScheduleEnvCheckCoversPeriodicConfig keeps this list complete.
vars=(SYNC_INTERVAL CORRELATE_INTERVAL ENRICH_INTERVAL ADJUDICATOR_ENABLED DRIFT_ANALYSIS_ENABLED DISK_SCAN_ENABLED IMAGE_SCAN_DISABLED SCC_ORG_ID OFFLINE_MODE INTEL_KEV_DISABLED INTEL_EPSS_DISABLED INTEL_MALFEED_DISABLED INTEL_OSV_DISABLED INTEL_ALAS_DISABLED INTEL_ELSA_DISABLED DOMAIN_MONITOR_DISABLED)

env_of() {
  helm template graph "$chart" "$@" --show-only "templates/$tpl" |
    grep -A1 -E "^ *- name: ($(IFS='|'; echo "${vars[*]}"))$" | grep -v '^--$' | sed 's/^ *//' | paste - - | sort
}

tpl=deployment-worker.yaml; worker="$(env_of "$@")"
tpl=deployment-scanner.yaml; scanner="$(env_of "$@")"
if [ "$worker" != "$scanner" ]; then
  echo "worker and scanner render different schedule env:" >&2
  diff <(echo "$worker") <(echo "$scanner") >&2 || true
  exit 1
fi
if [ -z "$worker" ]; then
  echo "no schedule env rendered — pass values that set some, or the check proves nothing" >&2
  exit 1
fi
echo "schedule env matches on worker and scanner:"
echo "$worker"
