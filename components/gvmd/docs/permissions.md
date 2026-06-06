<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- Modified by TurboVAS contributors, 2026. -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Operator Account Model

TurboVAS does not expose the inherited Greenbone/OpenVAS role, group, or
permission administration model. Authentication is the administration boundary:
any authenticated operator account can see and manage all retained TurboVAS
resources.

User accounts remain for login identity, authentication source, preferences, and
attribution. Owner fields are retained as metadata, not as access-control
boundaries. Product behavior must not depend on hidden roles, hidden groups,
resource sharing, or per-user host limits.

This document intentionally replaces the inherited RBAC documentation. Agent
functionality, including `agent_groups`, is tracked separately and is not
changed by the operator-account model cleanup.
