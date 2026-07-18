<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Public Release Readiness Checklist

YAFVS uses mode-specific publication gates. Public source visibility is a
narrower mode than publishing packages, containers, hosted services, feed
mirrors, feed bundles, or feed-derived data.

For source repository visibility, run:

```sh
just license-public-release-gate --json --mode source-public
```

For later release modes, use the stricter mode-specific gates:

```sh
just license-public-release-gate --json --mode binary
just license-public-release-gate --json --mode container
just license-public-release-gate --json --mode hosted
just license-public-release-gate --json --mode feed-redistribution
```

The stricter modes remain blocked until their own source-offer, packaging,
runtime, security, and feed-term procedures are complete.

## Required Before Public Release

- `just license-public-release-gate --mode source-public` passes.
- Upstream provenance in `UPSTREAMS.md` is current.
- `LICENSE_AUDIT.md` has no unresolved publication blockers.
- Greenbone non-affiliation wording is present in public-facing entry points.
- Greenbone trademark/non-affiliation wording and residual OpenVAS/Greenbone
  branding have been reviewed for public presentation.
- Image assets, icons, favicons, banners, splash images, screenshots, and other
  binary or SVG visual files have been reviewed for inherited OpenVAS,
  Greenbone, GSA, Enterprise, or other misleading product identity.
- YAFVS is clearly documented as Greenbone Community Feed-only; Greenbone
  Enterprise Feed subscription-key support is absent from live feed-sync source
  and public docs.
- Feed-content terms are reviewed for the planned release/distribution model.
- No feed content, runtime cache, secrets, certificates, or credentials are
  committed or packaged.
- Visible product branding says YAFVS outside provenance/historical context.
- `docs/USER_MANUAL.md`, `docs/CHANGES_FROM_UPSTREAM.md`, and setup docs match
  implemented behavior.
- Development credentials are clearly documented as development-only.
- CI/source quality gate and server-side runtime gate are green or documented
  with explicit release-owner acceptance.
- Browser/user-perspective smoke covers the main operator routes.

## Not Sufficient

The routine engineering gate `just license-report --json` is necessary during
development, but it is not sufficient for any publication mode. Publication
requires the relevant mode-specific gate and human review of unresolved
legal/provenance decisions.
