<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Contributing

TurboVAS is currently an early-stage OpenVAS-derived project. Public source
visibility is intended for transparency and read access while the project is
still being shaped.

External contributions are not currently sought and are not guaranteed review.
Pull requests may remain technically available, but maintainers may close or
reimplement submissions through trusted local workflow instead of merging them
directly.

## Before Opening Anything

Do not submit:

- secrets, credentials, tokens, private keys, certificates, or passwords;
- customer, employer, or personal data;
- vulnerability scan reports or result exports from real environments;
- internal hostnames, private URLs, VPN details, tickets, chat logs, or private
  configuration;
- feed content, feed cache copies, or proprietary feed material.

If an issue or pull request contains sensitive material, assume it may need to
be removed and rotated outside normal public discussion.

## Pull Requests

Fork pull requests are treated as untrusted until reviewed. Workflow changes,
generated code, binary files, dependency changes, and scripts receive extra
scrutiny. The source quality workflow is intentionally restricted and does not
run scans, sync feeds, start the development runtime, or use repository secrets.

Useful ideas are welcome as design signal, but maintainers may choose a
different implementation to preserve TurboVAS direction, security boundaries,
license/provenance obligations, and validation standards.

## Memory Safety

New security-sensitive backend functionality should use Rust unless a narrow
change to an existing C subsystem is demonstrably the safer coherent option.
Do not introduce a broad rewrite, new FFI boundary, or mechanically translated
C-shaped Rust without characterization and focused validation.

See `docs/MEMORY_SAFETY.md` for the project direction and review criteria.

## Project Direction

TurboVAS intentionally diverges from upstream behavior. See
`docs/CHANGES_FROM_UPSTREAM.md` and `docs/USER_MANUAL.md` before assuming that
an inherited OpenVAS/GVM workflow should remain supported.

## Relationship To Greenbone

TurboVAS is independent and is not affiliated with, sponsored by, or endorsed by
Greenbone AG. For official Greenbone products and services, visit
https://www.greenbone.net/.
