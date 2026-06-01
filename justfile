set shell := ["bash", "-eo", "pipefail", "-c"]

forkctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/forkctl "$@"

status:
    @tools/forkctl status

inventory:
    @tools/forkctl inventory

doctor:
    @tools/forkctl doctor

license-report:
    @tools/forkctl license-report

deps component="":
    @if [ -n "{{component}}" ]; then tools/forkctl deps "{{component}}"; else tools/forkctl deps; fi

configure component:
    @tools/forkctl configure "{{component}}"

build component:
    @tools/forkctl build "{{component}}"

build-core-c:
    @tools/forkctl build-core-c

build-c-services:
    @tools/forkctl build-c-services

build-ui:
    @tools/forkctl build-ui

build-python:
    @tools/forkctl build-python

build-baseline:
    @tools/forkctl build-baseline

runtime-plan:
    @tools/forkctl runtime-plan

up:
    @tools/forkctl up

down:
    @tools/forkctl down

logs service="":
    @if [ -n "{{service}}" ]; then tools/forkctl logs "{{service}}"; else tools/forkctl logs; fi

runtime-status:
    @tools/forkctl runtime-status

runtime-smoke:
    @tools/forkctl runtime-smoke
