<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Upstream Sources

This file records the upstream source snapshots imported into the TurboVAS monorepo.

Import date: 2026-05-31
Import method: source snapshot from local upstream cache, excluding only upstream `.git/` directories.

`pg-gvm` was added on 2026-06-01 after identifying it as a required PostgreSQL extension for `gvmd` runtime work.

TurboVAS is an independent project and is not affiliated with, sponsored by, or endorsed by Greenbone AG. The Greenbone/OpenVAS repositories listed below are upstream source references for the imported components. For official Greenbone/OpenVAS vulnerability-management products, support, or services, contact Greenbone directly at https://www.greenbone.net/.

## Intentional Product Divergence

TurboVAS intentionally diverges from inherited OpenVAS behavior where doing so
supports a clearer operator workflow. One major planned divergence is
scope-based reporting: technical targets remain evidence-collection units,
while scopes become the operator-facing accountability, policy, and reporting
boundaries. This is intended to avoid tying reports directly to technical target
definitions when one operational population needs several targets because of
network boundaries, credentials, scan constraints, or scanner reachability.

TurboVAS also intentionally limits feed synchronization to the Greenbone
Community Feed. It does not support Greenbone Enterprise Feed subscription keys
or Enterprise Feed synchronization. Feed content is runtime state, not source
code, and must not be bundled, mirrored, packaged, or redistributed without a
separate feed-terms review.

See `docs/SCOPE_BASED_REPORTING.md` for the public model.

## Imported Components

| Component | Path | Upstream repository | Imported commit | Role |
| --- | --- | --- | --- | --- |
| OpenVAS Scanner | `components/openvas-scanner` | https://github.com/greenbone/openvas-scanner | `f039649` | Scanner engine and NASL/VT execution core; includes C scanner and Rust/openvasd-related code. |
| gvm-libs | `components/gvm-libs` | https://github.com/greenbone/gvm-libs | `f67e8b8` | Shared libraries for Greenbone services, protocols, scanner helpers, and utilities. |
| pg-gvm | `components/pg-gvm` | https://github.com/greenbone/pg-gvm | `878e125` | PostgreSQL extension used by `gvmd` for helper functions. |
| gvmd | `components/gvmd` | https://github.com/greenbone/gvmd | `39a51f6` | Central management daemon; stores configuration/results, exposes GMP, and controls scanners through OSP. |
| ospd-openvas | `components/ospd-openvas` | https://github.com/greenbone/ospd-openvas | `874c524` | OSP server implementation for controlling OpenVAS Scanner and Notus Scanner. |
| gsad | `components/gsad` | https://github.com/greenbone/gsad | `88ef642` | HTTP daemon connecting the browser UI to `gvmd`. |
| gsa | `components/gsa` | https://github.com/greenbone/gsa | `f1e8cbe` | React web UI for Greenbone vulnerability management. |
| openvas-smb | `components/openvas-smb` | https://github.com/greenbone/openvas-smb | `488c810` | SMB/WMI support module for authenticated Windows scanning. Its preserved README records Zenoss `wmi-1.3.14` and Samba-derived GPLv2 provenance. |
| notus-scanner | `components/notus-scanner` | https://github.com/greenbone/notus-scanner | `80681c6` | Python scanner for local security checks based on collected system information and Notus feed data. |
| greenbone-feed-sync | `components/greenbone-feed-sync` | https://github.com/greenbone/greenbone-feed-sync | `1be4adf` | Tool for downloading Greenbone Community Feed data. |

The archived standalone `greenbone/ospd` repository is not imported. Current `ospd-openvas` includes its own `ospd` package.

## Removed Imported Components

`python-gvm` (upstream commit `acf6ccf`) and `gvm-tools` (upstream commit
`f68027a`) were imported during initial shaping, then removed after retained
product, validation, and operator workflows moved to native HTTP/JSON. Their
source provenance remains in repository history; neither is a current TurboVAS
component or required dependency.
