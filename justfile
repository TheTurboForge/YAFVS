# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later

set shell := ["bash", "-eo", "pipefail", "-c"]

turbovasctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl "$@"

forkctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/forkctl "$@"

status *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl status "$@"

inventory *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl inventory "$@"

native-tooling-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-tooling-state "$@"

rust-migration-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl rust-migration-state "$@"

doctor *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl doctor "$@"

branding-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl branding-state "$@"

license-report *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl license-report "$@"

license-public-release-gate *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl license-report --public-release "$@"

production-posture-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl production-posture-check "$@"

deps *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl deps "$@"

configure *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl configure "$@"

build *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl build "$@"

build-core-c *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl build-core-c "$@"

build-c-services *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl build-c-services "$@"

build-ui *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl build-ui "$@"

build-python *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl build-python "$@"

build-baseline *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl build-baseline "$@"

runtime-plan *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-plan "$@"

up *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl up "$@"

down *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl down "$@"

logs *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl logs "$@"

runtime-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-init "$@"

runtime-certs-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-certs-init "$@"

runtime-manager-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-manager-init "$@"

runtime-scanner-redis-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-scanner-redis-init "$@"

runtime-gmp-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-gmp-smoke "$@"

runtime-scanner-register *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-scanner-register "$@"

runtime-scanner-capability-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-scanner-capability-check "$@"

runtime-scanner-process-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-scanner-process-check "$@"

runtime-nmap-capability-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-nmap-capability-check "$@"

runtime-feed-keyring-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-feed-keyring-init "$@"

runtime-feed-import-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-feed-import-init "$@"

runtime-full-test-scan-preflight *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-full-test-scan-preflight "$@"

runtime-full-test-scan-start *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-full-test-scan-start "$@"

runtime-full-test-scan-status *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-full-test-scan-status "$@"

runtime-report-summary *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-report-summary "$@"

runtime-report-export *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-report-export "$@"

runtime-report-metrics *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-report-metrics "$@"

runtime-scope-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-scope-smoke "$@"

runtime-scope-report-summary *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-scope-report-summary "$@"

runtime-scope-report-metrics *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-scope-report-metrics "$@"

feed-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl feed-state "$@"

feed-cache-sync *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl feed-cache-sync "$@"

feed-copy-to-runtime *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl feed-copy-to-runtime "$@"

runtime-status *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-status "$@"

runtime-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-smoke "$@"

runtime-log-review *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-log-review "$@"

runtime-data-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-data-state "$@"

runtime-performance-snapshot *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-performance-snapshot "$@"

runtime-redis-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-redis-state "$@"

security-policy-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl security-policy-check "$@"

path-coupling-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl path-coupling-state "$@"

runtime-app-up *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-app-up "$@"

runtime-app-down *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-app-down "$@"

runtime-app-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-app-smoke "$@"

runtime-native-api-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-native-api-smoke "$@"

runtime-webui-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-webui-smoke "$@"

runtime-browser-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-browser-smoke "$@"

runtime-credential-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-credential-smoke "$@"

runtime-rbac-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-rbac-smoke "$@"

quality-gate *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl quality-gate "$@"

quality-gate-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl quality-gate-state "$@"

quality-gate-schedule *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl quality-gate-schedule "$@"

gvmd-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl gvmd-smoke "$@"
