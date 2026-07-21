/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL handlers for YAFVS reporting scopes.
 */

#ifndef _GVMD_MANAGE_SQL_SCOPES_H
#define _GVMD_MANAGE_SQL_SCOPES_H

#include "manage.h"

#include <glib.h>

/**
 * @brief A reporting scope row id.
 */
typedef resource_t scope_t;

/**
 * @brief A scope report row id.
 */
typedef resource_t scope_report_t;

int
ensure_organization_scope (void);

int
buffer_scopes_xml (GString *, const char *, int);

int
scope_count (const char *);

#endif /* not _GVMD_MANAGE_SQL_SCOPES_H */
