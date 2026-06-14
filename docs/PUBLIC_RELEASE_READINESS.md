<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Public Release Readiness Checklist

TurboVAS must not be published, packaged, distributed, or promoted as a public
project until the release-readiness gate is explicitly satisfied.

## Required Before Public Release

- `just license-public-release-gate` passes.
- Upstream provenance in `UPSTREAMS.md` is current.
- `LICENSE_AUDIT.md` has no unresolved publication blockers.
- Greenbone non-affiliation wording is present in public-facing entry points.
- Feed-content terms are reviewed for the planned release/distribution model.
- No feed content, runtime cache, secrets, certificates, or credentials are
  committed or packaged.
- Visible product branding says TurboVAS outside provenance/historical context.
- `docs/USER_MANUAL.md`, `docs/CHANGES_FROM_UPSTREAM.md`, and setup docs match
  implemented behavior.
- Development credentials are clearly documented as development-only.
- CI/source quality gate and server-side runtime gate are green or documented
  with explicit release-owner acceptance.
- Browser/user-perspective smoke covers the main operator routes.

## Not Sufficient

The routine engineering gate `just license-report --json` is necessary during
development, but it is not sufficient for public release. Publication requires
the stricter public-release gate and human review of legal/provenance decisions.
