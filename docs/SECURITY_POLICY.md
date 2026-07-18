<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Security-Sensitive Change Policy

YAFVS is a scanner and scanner-management system. Changes that look like
ordinary refactoring can affect parsing, authentication, scan execution,
feed trust, service exposure, or release obligations.

`docs/TRUST_BOUNDARIES.md` describes the current trust boundaries that motivate
this policy.

The path policy in `policy/security-sensitive-paths.toml` is the first small
guardrail: it identifies high-consequence areas and the checks that should be
considered when those areas change. It is intentionally practical rather than
ceremonial. A path should appear there when it changes how data crosses a trust
boundary, how scans execute, how runtime state is exposed, or how YAFVS is
published or described.

Run:

```sh
just security-policy-check --json
```

The command validates that the policy is present, parseable, and points at
existing paths. It does not replace human security review. It gives Codex and
human reviewers a deterministic starting point for deciding which validation
layers are relevant.

Current policy areas:

- protocol and XML parsing;
- authentication, session, and operator boundary;
- scanner execution and privileges;
- feed handling and signature boundaries;
- Docker runtime, exposed services, and persistent state;
- native HTTP/JSON API and DB-backed product data;
- public release, licensing, branding, and publication posture.

Future rule automation should consume this file rather than duplicating path
lists in prose. Add Semgrep or similar rules only when they produce concrete
signal for a defined area.
