<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Production Posture

TurboVAS is currently a private development project. The Docker runtime is a
development runtime, not production deployment guidance.

## Security Boundary

TurboVAS deliberately uses an operator-only console model instead of inherited
product RBAC. One installation is one trusted scanner-operator team and one
administrative trust domain. Anyone who can authenticate to the TurboVAS
console or an approved operator API surface can administer the shared scanner
estate. Individual operator accounts remain required for authentication,
attribution, revocation, preferences, and auditing; shared login credentials
are not the model.

People who should not administer the scanner should not receive TurboVAS
console or operator API access. Remediation stakeholders should receive
findings through controlled outbound workflows such as reports, exports,
notifications, ticket-system integrations, or future delivery integrations.

Hard tenant isolation is a deployment boundary. Groups that must not share
scanner control, data, runtime secrets, network reachability, or a failure
domain require separate, independently operated stacks. Row or UI permissions
inside one application are not equivalent. The current development Compose
runtime is not a production multi-stack isolation mechanism; the host,
virtualization, network, storage, backup, and identity boundaries must match the
deployment threat model.

Before production use, operators must therefore treat login, network exposure,
TLS, backups, host access, auditability, credential handling, and deployment
controls as the scanner administration boundary.

## Minimum Production Questions

- Are default development credentials disabled or rotated before exposure?
- Is a first-login or password-rotation bootstrap in place instead of relying
  on the development `admin` / `admin` account?
- Is GSA exposed only to authorized operator networks?
- Does this stack serve exactly one administrative trust domain, with separate
  stacks and appropriately independent infrastructure for groups that require
  tenant isolation?
- If direct native API access is enabled outside loopback, has the separate
  production TLS/bootstrap/host-binding design landed? Until then,
  `production-posture-check` fails non-loopback direct native API exposure even
  when the bearer-token boundary is present.
- If direct native API access is enabled at all, is bearer auth file-backed
  through the ignored runtime secret rather than passed through
  `TURBOVAS_API_BEARER_TOKEN` environment variables?
- Is TLS configured with trusted certificates for the deployment context?
- Are runtime secrets stored outside git and outside public artifacts?
- Are feed terms understood for the chosen feed handling model?
- Is PostgreSQL state backed up and restorable?
- Are logs and artifacts retained according to local policy?
- Do individual accounts and retained logs provide the required operator
  attribution and revocation behavior without relying on shared credentials?
- Is a license/publication review complete before distribution or public
  release?

## Development Checks

The application profile mounts source and build outputs read-only for `gvmd`,
`ospd-openvas`, `notus-scanner`, and `gsad`; runtime logs and manager state use
separate runtime mounts. The `dev-shell` profile remains writable for rebuilds.
The manager semaphore bind file uses a private runtime directory that is not
mounted into application containers. `runtime-app-up` validates the rendered
mount graph before startup; this detects drift but does not eliminate a
privileged host-side race before Docker performs the mounts.

Useful non-destructive checks:

- `just doctor --status-only --json`
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
