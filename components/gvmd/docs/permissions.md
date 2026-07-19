<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Operator Account Model

YAFVS does not expose the inherited Greenbone/OpenVAS role, group, or
permission administration model. The YAFVS console is an operator-only
scanner administration surface: any authenticated operator account can see and
manage all retained YAFVS resources.

This is an intentional trust-boundary decision, not an incomplete RBAC port or
a feature scheduled for restoration. One installation represents one trusted
scanner-operator team and one administrative trust domain. The number of assets
in the scanner estate does not change that boundary. Shared resource visibility
lets team members continue one another's work and cover for one another during
leave or other absences.

People who should not administer scans, targets, credentials, schedules,
reports, and scanner configuration should not receive YAFVS console accounts.
Their findings belong in outbound reports, exports, notifications, ticket-system
integrations, or future delivery workflows.

User accounts remain for login identity, authentication source, preferences, and
attribution. Owner fields are retained as metadata, not as access-control
boundaries. Product behavior must not depend on hidden roles, hidden groups,
resource sharing, or per-user host limits.

Operators use distinct accounts for authentication, attribution, revocation,
preferences, and auditing. Equal product authority does not imply shared login
credentials or automatic host, database, network, or deployment access.

Hard tenant isolation is provided by separate, independently operated stacks,
not by restoring resource-visibility rules inside one manager process and
database. Deployments that must not share administrative authority,
confidential data, scanner execution, runtime secrets, network reachability,
backups, or failure domains must isolate those resources at the deployment and
infrastructure layers.

This document intentionally replaces the inherited RBAC documentation. Legacy
Agent Controller functionality has been removed separately; future endpoint
evidence collection must be designed as new YAFVS behavior, not as hidden
RBAC or Agent Controller compatibility.
