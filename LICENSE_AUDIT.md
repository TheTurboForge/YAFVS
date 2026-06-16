<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# License Audit

This is the initial TurboVAS engineering license and provenance audit for the imported upstream source snapshots. It is not legal advice.

The import preserves upstream component boundaries under `components/`. Upstream license files, copyright notices, package manifests, documentation, tests, and source files are retained as imported source material.

TurboVAS is an independent project and is not affiliated with, sponsored by, or endorsed by Greenbone AG. Greenbone/OpenVAS component references in this audit are provenance records and do not imply Greenbone approval or support for TurboVAS.

Original TurboVAS-created root tooling and public documentation use `GPL-3.0-or-later` as the provisional project default unless a more specific compatible license is selected for a component-local file.

TurboVAS-created service code outside imported upstream component trees, including
`services/turbovas-api`, currently follows this provisional `GPL-3.0-or-later`
default. Third-party Rust crate dependencies recorded in
`services/turbovas-api/Cargo.lock` are external package dependencies, not
vendored source. Keep the lockfile tracked for reproducibility and run the
normal license/public-release gates before packaging, publishing, or distributing
artifacts that include the service.

## Component License Summary

| Component | Path | License declaration observed | Preserved license/provenance files | Notes |
| --- | --- | --- | --- | --- |
| OpenVAS Scanner | `components/openvas-scanner` | Main non-Rust module is GPL-2.0 only overall, with per-file GPL-2.0 and GPL-2.0-or-later details. Rust implementation is GPL-2.0-or-later with OpenSSL exception; some files are additionally MIT. | `COPYING`, `rust/COPYING`, `license-details.md`, `RELICENSE/` | Highest-complexity component. Do not rewrite or normalize headers. Preserve per-file license detail and relicensing material. |
| gvm-libs | `components/gvm-libs` | GPL-2.0-or-later. | `COPYING` | Shared library dependency for multiple services. |
| pg-gvm | `components/pg-gvm` | GPL-3.0-or-later. | `LICENSE` | PostgreSQL extension required by `gvmd`. Runtime packaging must preserve extension/source obligations. |
| gvmd | `components/gvmd` | AGPL-3.0-or-later. | `COPYING` | Network/server component. AGPL obligations matter for deployment and public access scenarios. |
| gsad | `components/gsad` | AGPL-3.0-or-later. | `LICENSE` | HTTP daemon. AGPL obligations matter for deployment and public access scenarios. |
| gsa | `components/gsa` | AGPL-3.0-or-later. | `LICENSE`, `package.json` license declaration | Web UI served over a network. AGPL obligations matter for deployment and public access scenarios. |
| ospd-openvas | `components/ospd-openvas` | AGPL-3.0-or-later. | `COPYING` | Includes its own `ospd` package. Preserve service/config documentation. |
| notus-scanner | `components/notus-scanner` | AGPL-3.0-or-later. | `LICENSE`, `pyproject.toml` license declaration | Scanner service with feed and MQTT integration implications. |
| openvas-smb | `components/openvas-smb` | GPL-2.0-or-later. | `COPYING` | README notes Samba-derived/forked GPLv2 basis. Requires deeper provenance review before public release or distribution. |
| greenbone-feed-sync | `components/greenbone-feed-sync` | GPL-3.0-or-later. | `LICENSE`, `pyproject.toml` license declaration | Source license does not determine Greenbone Community Feed data terms. Treat feed data/signature/use terms separately. |
| python-gvm | `components/python-gvm` | GPL-3.0-or-later. | `LICENSE`, `pyproject.toml` license declaration | Protocol library for GMP and OSP. |
| gvm-tools | `components/gvm-tools` | GPL-3.0-or-later. | `LICENSE`, `pyproject.toml` license declaration | Depends on `python-gvm`; useful for CLI/operator tooling and smoke tests. |

## Standing License Rules

- Preserve upstream license files and copyright notices.
- Do not rewrite, remove, or normalize license headers during routine changes.
- Record source provenance for every imported component, vendored dependency, generated source addition, or substantial source replacement.
- Update this file whenever source scope, component provenance, dependency scope, packaging, distribution, or release behavior changes.
- Preserve existing attribution and modification history when changing imported source files.
- Add TurboVAS modification notices to imported source files when they are changed.
- Add explicit license information to new TurboVAS-created files.
- Treat feed content terms separately from source code licensing.
- Treat development feed caches and runtime feed copies as local, untracked runtime state; do not commit, bundle, package, or redistribute feed content without a separate feed-terms review.
- Mark ambiguous cases for human/legal review before public release or distribution.
- Run `just license-report` during license-sensitive work. The report checks expected component license files, TurboVAS modification notices on modified imported source files, SPDX headers on new TurboVAS-created files, explicit handling for modified imported files that cannot carry comments, accidental tracking of runtime feed/cache content, and public-release review gate state.
- Run `just license-public-release-gate` before any public repository, release artifact, publication, packaging, or distribution step. The gate fails until public-release license review items are closed.

## Modification Notice Policy

When modifying an imported upstream file, preserve all existing copyright notices,
license headers, SPDX identifiers, warranty notices, and attribution text. Do not
replace an upstream header with a TurboVAS-only header.

For GPL- or AGPL-covered files, add a concise prominent TurboVAS modification
notice near the existing license header or another established file-level notice
location. Use the file's existing comment style. A typical form is:

`Modified by TurboVAS contributors, 2026.`

If a file already has a structured modification history, add the TurboVAS entry
there instead of creating a duplicate header block. TurboVAS modifications remain
under the file's existing license unless a more specific compatible notice is
reviewed and documented.

New TurboVAS-created files should include an SPDX license identifier and copyright
notice. Prefer the license already governing the component or subdirectory where
the file lives. If the governing license is unclear, especially in mixed-license
areas such as `components/openvas-scanner`, stop and review before adding the file.
Root-level TurboVAS-only tooling and public documentation currently use
`GPL-3.0-or-later` as the provisional default.

Some modified imported data or generated files do not safely support comments,
for example JSON locale/package files or test snapshots. These paths are tracked
in the deterministic `just license-report` manifest instead of receiving
syntactically invalid file-level comments. A new no-comment modified file fails
the report until the file can receive a notice or the manifest records the
reason it cannot.

## Review Items

- Confirm whether TurboVAS should preserve upstream git history in a later archival/import refinement, or whether explicit source snapshots plus `UPSTREAMS.md` are sufficient.
- Review `components/openvas-scanner/license-details.md` before changing scanner/NASL/Rust license-sensitive files.
- Revisit the provisional `GPL-3.0-or-later` root tooling/documentation default before public release and before adding substantial original application code.
- Review `components/openvas-smb` Samba-derived provenance before public release or distribution.
- Review Greenbone Community Feed terms before bundling, redistributing, mirroring, or packaging feed content.
- Review third-party Rust crate license and security posture for
  `services/turbovas-api` before public release, packaging, or distribution.
- Define release-time source publication and attribution procedures before making this repository public.
