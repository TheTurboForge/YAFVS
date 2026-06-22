<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Security Policy

TurboVAS is not production-ready. The current repository is source-readable for
transparency and development review, not as a supported product release.

## Reporting Security Issues

Do not put secrets, customer data, real scan results, exploit details for a
private environment, or sensitive infrastructure information into public issues
or pull requests.

At this stage, TurboVAS does not offer a public vulnerability disclosure program
or response-time commitment. If a security-relevant issue is found, report only
the minimum non-sensitive technical description needed to understand the class
of problem. Maintainers may request a safer reporting path before discussing
details.

## Development Runtime Warning

The Docker runtime, `admin` / `admin` development credentials, development TLS,
and LAN/Tailscale access patterns documented in this repository are for private
development only. They are not production deployment guidance.

Run these checks before relying on a checkout for development work:

```sh
just license-report --json
just production-posture-check --json
just security-policy-check --json
```

`production-posture-check` is expected to fail until production authentication,
trusted TLS, password rotation, and deployment controls are implemented.

## Relationship To Greenbone

TurboVAS is independent and is not affiliated with, sponsored by, or endorsed by
Greenbone AG. For official Greenbone products and services, visit
https://www.greenbone.net/.
