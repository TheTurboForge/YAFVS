<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Contributing

YAFVS is currently an early-stage OpenVAS-derived project. Public source
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
different implementation to preserve YAFVS direction, security boundaries,
license/provenance obligations, and validation standards.

## License And Provenance

Every commit after the project's DCO policy epoch must carry a Developer
Certificate of Origin sign-off. Use `git commit --signoff`; the sign-off states
that you have the right to submit the work under the licenses governing its
destination. The Quality Gate rejects unsigned new commits.

New source files must carry SPDX copyright and license headers and a derivation
classification near the top of the file:

```text
YAFVS-Derivation: original
```

The other accepted values are `behavioral-reimplementation`, `adaptation`, and
`translation`. Any value other than `original` must also identify the exact
source in a `YAFVS-Source-Provenance:` marker, including the upstream project,
commit or release, path, and source license. Do not describe adapted or
translated source as an original or behavioral reimplementation.

Destination directories have machine-readable allowed-license rules in
`policy/license-boundaries.toml`. In particular, GPL-3.0 or AGPL-3.0 code must
not be linked into the GPL-2.0-only scanner artifact. Communicating separate
programs and linked code are recorded as different relationships; changing a
boundary requires updating the policy and providing build evidence, not merely
changing a label.

Original network-facing YAFVS services use `AGPL-3.0-or-later`. Original local
operator tooling uses `GPL-3.0-or-later`. Scanner-linked additions use only an
explicitly reviewed GPLv2-compatible license. Documentation, specifications,
and data are separate licensing decisions; do not infer their license from a
code default.

Dependencies, generated code, vendored material, copied tests, and translated
implementations all require source and license provenance. A dependency change
must preserve its lockfile and the applicable artifact's complete license/SBOM
closure. Feed data and other databases remain governed by their own source
terms and must not be treated as source-code dependencies.

## Memory Safety

New security-sensitive backend functionality should use Rust unless a narrow
change to an existing C subsystem is demonstrably the safer coherent option.
Do not introduce a broad rewrite, new FFI boundary, or mechanically translated
C-shaped Rust without characterization and focused validation.

See `docs/MEMORY_SAFETY.md` for the project direction and review criteria.

## Project Direction

YAFVS intentionally diverges from upstream behavior. See
`docs/CHANGES_FROM_UPSTREAM.md` and `docs/USER_MANUAL.md` before assuming that
an inherited OpenVAS/GVM workflow should remain supported.

## Relationship To Greenbone

YAFVS is independent and is not affiliated with, sponsored by, or endorsed by
Greenbone AG. For official Greenbone products and services, visit
https://www.greenbone.net/.
