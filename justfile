# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later

set shell := ["bash", "-eo", "pipefail", "-c"]

turbovasctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl "$@"

status *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl status "$@"

inventory *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl inventory "$@"

native-tooling-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-tooling-state "$@"

native-api-request *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-api-request "$@"

native-empty-trash *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-empty-trash "$@"

native-verify-scanners *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-verify-scanners "$@"

native-start-task *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-start-task "$@"

native-scan-new-system *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-scan-new-system "$@"

native-export-report-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-export-report-csv "$@"

native-export-report-bundle *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-export-report-bundle "$@"

native-delete-overrides-by-filter *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-delete-overrides-by-filter "$@"

native-bulk-modify-schedules *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-bulk-modify-schedules "$@"

native-stop-task *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-stop-task "$@"

native-update-task-target *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-update-task-target "$@"

native-stop-tasks-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-stop-tasks-from-csv "$@"

native-stop-all-tasks *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-stop-all-tasks "$@"

native-start-tasks-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-start-tasks-from-csv "$@"

native-tasks-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-tasks-from-csv "$@"

native-targets-from-host-list *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-targets-from-host-list "$@"

native-targets-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-targets-from-csv "$@"

native-targets-from-xml *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-targets-from-xml "$@"

native-tags-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-tags-from-csv "$@"

native-credentials-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-credentials-from-csv "$@"

native-alerts-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-alerts-from-csv "$@"

native-api-migration-matrix *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-api-migration-matrix "$@"

native-api-client-contract *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-api-client-contract "$@"

native-api-replacement-dashboard *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-api-replacement-dashboard "$@"

closeout-readiness *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl closeout-readiness "$@"

native-api-rust-test *filters:
    @set -- {{filters}}; \
      if [ "${1:-}" = "--" ]; then shift; fi; \
      if [ "$#" -eq 0 ]; then \
        cargo test --manifest-path services/turbovas-api/Cargo.toml --locked; \
      else \
        for filter in "$@"; do \
          cargo test --manifest-path services/turbovas-api/Cargo.toml --locked "$filter"; \
        done; \
      fi

gsa-vitest *args:
    @set -- {{args}}; \
      if [ "${1:-}" = "--" ]; then shift; fi; \
      if [ "$#" -eq 0 ]; then \
        echo "usage: just gsa-vitest -- <vitest-run-args>" >&2; \
        exit 2; \
      fi; \
      cd components/gsa && npm exec vitest -- run "$@"

rust-migration-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl rust-migration-state "$@"

doctor *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl doctor "$@"

branding-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl branding-state "$@"

license-report *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl license-report "$@"

license-precommit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl license-report --diff-scope staged --modified-imported-only --status-only "$@"

secret-precommit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; gitleaks protect --staged --redact --no-banner --log-level error --exit-code 7 --report-format json "$@"

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

runtime-certbund-report *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-certbund-report "$@"

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

runtime-db-introspect *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-db-introspect "$@"

runtime-performance-snapshot *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-performance-snapshot "$@"

runtime-redis-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-redis-state "$@"

security-policy-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl security-policy-check "$@"

native-api-cargo-audit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-api-cargo-audit "$@"

gsa-npm-audit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl gsa-npm-audit "$@"

osv-lockfile-audit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl osv-lockfile-audit "$@"

native-api-semgrep-audit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl native-api-semgrep-audit "$@"

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

runtime-native-api-direct-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-native-api-direct-smoke "$@"

runtime-native-api-direct-write-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-native-api-direct-write-smoke "$@"

runtime-native-api-direct-bootstrap *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-native-api-direct-bootstrap "$@"

runtime-native-api-direct-token *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-native-api-direct-token "$@"

runtime-native-api-rebuild *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-native-api-rebuild "$@"

runtime-webui-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-webui-smoke "$@"

runtime-browser-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-browser-smoke "$@"

runtime-browser-regression *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-browser-regression "$@"

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
