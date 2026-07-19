# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later

set shell := ["bash", "-eo", "pipefail", "-c"]

yafvsctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl "$@"

yafvsctl-rust *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- "$@"

yafvsctl-rust-test:
    cargo test --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml

status *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- status "$@"

inventory *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- inventory "$@"

native-tooling-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-tooling-state "$@"

native-api-request *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-api-request "$@"

native-empty-trash *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-empty-trash "$@"

native-verify-scanners *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-verify-scanners "$@"

native-start-task *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-start-task "$@"

native-nvt-diagnostic-scan *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-nvt-diagnostic-scan "$@"

native-scan-new-system *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-scan-new-system "$@"

native-scan-with-delivery *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-scan-with-delivery "$@"

native-export-report-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-export-report-csv "$@"

native-export-report-pdf *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-export-report-pdf "$@"

native-export-report-bundle *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-export-report-bundle "$@"

native-delete-overrides-by-filter *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-delete-overrides-by-filter "$@"

native-bulk-modify-schedules *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-bulk-modify-schedules "$@"

native-stop-task *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-stop-task "$@"

native-update-task-target *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-update-task-target "$@"

native-stop-tasks-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-stop-tasks-from-csv "$@"

native-stop-all-tasks *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-stop-all-tasks "$@"

native-start-tasks-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-start-tasks-from-csv "$@"

native-tasks-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-tasks-from-csv "$@"

native-targets-from-host-list *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-targets-from-host-list "$@"

native-targets-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-targets-from-csv "$@"

native-targets-from-xml *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-targets-from-xml "$@"

native-tags-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-tags-from-csv "$@"

native-credentials-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-credentials-from-csv "$@"

native-alerts-from-csv *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-alerts-from-csv "$@"

native-api-migration-matrix *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-api-migration-matrix "$@"

native-api-client-contract *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-api-client-contract "$@"

native-api-replacement-dashboard *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl native-api-replacement-dashboard "$@"

closeout-readiness *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl closeout-readiness "$@"

native-api-rust-test *filters:
    @set -- {{filters}}; \
      if [ "${1:-}" = "--" ]; then shift; fi; \
      if [ "$#" -eq 0 ]; then \
        cargo test --manifest-path services/yafvs-api/Cargo.toml --locked; \
      else \
        for filter in "$@"; do \
          cargo test --manifest-path services/yafvs-api/Cargo.toml --locked "$filter"; \
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
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- rust-migration-state "$@"

doctor *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- doctor "$@"

branding-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- branding-state "$@"

license-report *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- license-report "$@"

license-precommit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- license-report --diff-scope staged --modified-imported-only --status-only "$@"

secret-precommit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; gitleaks protect --staged --redact --no-banner --log-level error --exit-code 7 --report-format json "$@"

license-public-release-gate *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- license-report --public-release "$@"

production-posture-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- production-posture-check "$@"

deps *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- deps "$@"

configure *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl configure "$@"

build *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl build "$@"

build-core-c *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl build-core-c "$@"

build-c-services *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl build-c-services "$@"

c-hardening-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- c-hardening-check "$@"

build-ui *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl build-ui "$@"

build-python *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl build-python "$@"

build-baseline *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl build-baseline "$@"

runtime-plan *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-plan "$@"

up *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl up "$@"

down *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- down "$@"

logs *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- logs "$@"

runtime-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-init "$@"

runtime-certs-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-certs-init "$@"

runtime-manager-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-manager-init "$@"

runtime-scanner-redis-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-scanner-redis-init "$@"

runtime-gmp-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-gmp-smoke "$@"

runtime-scanner-register *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-scanner-register "$@"

runtime-scanner-capability-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-scanner-capability-check "$@"

runtime-scanner-process-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-scanner-process-check "$@"

runtime-nmap-capability-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-nmap-capability-check "$@"

runtime-feed-keyring-init *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-feed-keyring-init "$@"

runtime-full-test-scan-preflight *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-full-test-scan-preflight "$@"

runtime-full-test-scan-start *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-full-test-scan-start "$@"

runtime-full-test-scan-status *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-full-test-scan-status "$@"

runtime-report-summary *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-report-summary "$@"

runtime-report-export *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-report-export "$@"

runtime-certbund-report *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-certbund-report "$@"

runtime-report-metrics *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-report-metrics "$@"

runtime-scope-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-scope-smoke "$@"

runtime-scope-report-summary *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-scope-report-summary "$@"

runtime-scope-report-metrics *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-scope-report-metrics "$@"

feed-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- feed-state "$@"

feed-cache-sync *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl feed-cache-sync "$@"

feed-generation-stage *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- feed-generation-stage "$@"

feed-generation-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- feed-generation-state "$@"

feed-generation-activate *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- feed-generation-activate "$@"

feed-generation-rollback *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- feed-generation-rollback "$@"

runtime-status *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-status "$@"

runtime-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-smoke "$@"

runtime-log-review *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-log-review "$@"

runtime-data-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-data-state "$@"

runtime-db-introspect *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-db-introspect "$@"

runtime-performance-snapshot *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-performance-snapshot "$@"

runtime-redis-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-redis-state "$@"

security-policy-check *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- security-policy-check "$@"

native-api-cargo-audit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- native-api-cargo-audit "$@"

gsa-npm-audit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- gsa-npm-audit "$@"

osv-lockfile-audit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- osv-lockfile-audit "$@"

native-api-semgrep-audit *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- native-api-semgrep-audit "$@"

path-coupling-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- path-coupling-state "$@"

runtime-app-up *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-app-up "$@"

runtime-app-build *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-app-build "$@"

runtime-app-down *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-app-down "$@"

runtime-app-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-app-smoke "$@"

runtime-native-api-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-native-api-smoke "$@"

runtime-native-api-direct-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-native-api-direct-smoke "$@"

runtime-native-api-direct-write-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-native-api-direct-write-smoke "$@"

runtime-native-api-direct-bootstrap *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-native-api-direct-bootstrap "$@"

runtime-native-api-direct-token *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-native-api-direct-token "$@"

runtime-native-api-rebuild *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-native-api-rebuild "$@"

runtime-webui-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-webui-smoke "$@"

runtime-browser-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-browser-smoke "$@"

runtime-browser-regression *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl runtime-browser-regression "$@"

runtime-credential-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-credential-smoke "$@"

runtime-rbac-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- runtime-rbac-smoke "$@"

quality-gate *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl quality-gate "$@"

quality-gate-state *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- quality-gate-state "$@"

quality-gate-schedule *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- quality-gate-schedule "$@"

gvmd-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/yafvsctl gvmd-smoke "$@"
