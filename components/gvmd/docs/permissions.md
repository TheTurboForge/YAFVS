<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Operator Account Model

TurboVAS does not expose the inherited Greenbone/OpenVAS role, group, or
permission administration model. The TurboVAS console is an operator-only
scanner administration surface: any authenticated operator account can see and
manage all retained TurboVAS resources.

People who should not administer scans, targets, credentials, schedules,
reports, and scanner configuration should not receive TurboVAS console accounts.
Their findings belong in outbound reports, exports, notifications, ticket-system
integrations, or future delivery workflows.

User accounts remain for login identity, authentication source, preferences, and
attribution. Owner fields are retained as metadata, not as access-control
boundaries. Product behavior must not depend on hidden roles, hidden groups,
resource sharing, or per-user host limits.

This document intentionally replaces the inherited RBAC documentation. Legacy
Agent Controller functionality has been removed separately; future endpoint
evidence collection must be designed as new TurboVAS behavior, not as hidden
RBAC or Agent Controller compatibility.
