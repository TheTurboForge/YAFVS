# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later

set shell := ["bash", "-eo", "pipefail", "-c"]

turbovasctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl "$@"

forkctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/forkctl "$@"

status:
    @tools/turbovasctl status

inventory:
    @tools/turbovasctl inventory

doctor:
    @tools/turbovasctl doctor

license-report *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl license-report "$@"

license-public-release-gate *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl license-report --public-release "$@"

deps component="":
    @if [ -n "{{component}}" ]; then tools/turbovasctl deps "{{component}}"; else tools/turbovasctl deps; fi

configure component:
    @tools/turbovasctl configure "{{component}}"

build component:
    @tools/turbovasctl build "{{component}}"

build-core-c:
    @tools/turbovasctl build-core-c

build-c-services:
    @tools/turbovasctl build-c-services

build-ui:
    @tools/turbovasctl build-ui

build-python:
    @tools/turbovasctl build-python

build-baseline:
    @tools/turbovasctl build-baseline

runtime-plan:
    @tools/turbovasctl runtime-plan

up:
    @tools/turbovasctl up

down:
    @tools/turbovasctl down

logs service="":
    @if [ -n "{{service}}" ]; then tools/turbovasctl logs "{{service}}"; else tools/turbovasctl logs; fi

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

runtime-app-up *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-app-up "$@"

runtime-app-down *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-app-down "$@"

runtime-app-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-app-smoke "$@"

runtime-webui-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-webui-smoke "$@"

runtime-browser-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-browser-smoke "$@"

runtime-credential-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-credential-smoke "$@"

runtime-rbac-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl runtime-rbac-smoke "$@"

gvmd-smoke *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl gvmd-smoke "$@"
