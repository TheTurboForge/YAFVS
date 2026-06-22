<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Production Posture

TurboVAS is currently a private development project. The Docker runtime is a
development runtime, not production deployment guidance.

## Security Boundary

Any authenticated TurboVAS user can administer the scanner. Before production
use, operators must treat login, network exposure, TLS, backups, and host access
as the primary scanner administration boundary.

## Minimum Production Questions

- Are default development credentials disabled or rotated before exposure?
- Is a first-login or password-rotation bootstrap in place instead of relying
  on the development `admin` / `admin` account?
- Is GSA exposed only to authorized operator networks?
- If direct native API access is enabled outside loopback, has the separate
  production TLS/bootstrap/host-binding design landed? Until then,
  `production-posture-check` fails non-loopback direct native API exposure even
  when the bearer-token boundary is present.
- Is TLS configured with trusted certificates for the deployment context?
- Are runtime secrets stored outside git and outside public artifacts?
- Are feed terms understood for the chosen feed handling model?
- Is PostgreSQL state backed up and restorable?
- Are logs and artifacts retained according to local policy?
- Is a license/publication review complete before distribution or public
  release?

## Development Checks

Useful non-destructive checks:

- `just doctor --json`
- `just license-report --json`
- `just runtime-status --json`
- `just runtime-smoke --json`
- `just runtime-log-review --json`
- `just runtime-data-state --json`
- `just runtime-app-smoke`
- `just runtime-browser-smoke --json`
- `just runtime-browser-regression --json` for deeper route/link/pagination checks before demos or publication-facing UI review.

These checks help identify development-runtime drift. `production-posture-check`
is expected to fail while first-login/password rotation, trusted TLS, and other
deployment controls are not implemented. Passing routine development checks does
not make the deployment production-ready.
