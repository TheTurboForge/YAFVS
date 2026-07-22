<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Security Policy

YAFVS is not production-ready. The current repository is source-readable for
transparency and development review, not as a supported product release.

## Reporting Security Issues

Do not put secrets, customer data, real scan results, exploit details for a
private environment, or sensitive infrastructure information into public issues
or pull requests.

At this stage, YAFVS does not offer a public vulnerability disclosure program
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

## Memory Safety

YAFVS uses an incremental Rust-first direction for new security-sensitive
backend functionality while retaining, hardening, removing, or replacing
inherited C according to exposure and consequence. Memory safety is one part of
the security posture and does not substitute for authentication, authorization,
input validation, scanner safety, dependency review, or deployment hardening.

See `docs/MEMORY_SAFETY.md` and `docs/C_HARDENING.md`.

## Relationship To Greenbone

YAFVS is independent and is not affiliated with, sponsored by, or endorsed by
Greenbone AG. For official Greenbone products and services, visit
https://www.greenbone.net/.
