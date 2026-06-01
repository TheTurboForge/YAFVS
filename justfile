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

license-report:
    @tools/turbovasctl license-report

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

runtime-init:
    @tools/turbovasctl runtime-init

runtime-certs-init:
    @tools/turbovasctl runtime-certs-init

runtime-manager-init:
    @tools/turbovasctl runtime-manager-init

runtime-scanner-redis-init:
    @tools/turbovasctl runtime-scanner-redis-init

runtime-gmp-smoke:
    @tools/turbovasctl runtime-gmp-smoke

runtime-scanner-register:
    @tools/turbovasctl runtime-scanner-register

runtime-status:
    @tools/turbovasctl runtime-status

runtime-smoke:
    @tools/turbovasctl runtime-smoke

runtime-app-up:
    @tools/turbovasctl runtime-app-up

runtime-app-down:
    @tools/turbovasctl runtime-app-down

runtime-app-smoke:
    @tools/turbovasctl runtime-app-smoke

gvmd-smoke:
    @tools/turbovasctl gvmd-smoke
