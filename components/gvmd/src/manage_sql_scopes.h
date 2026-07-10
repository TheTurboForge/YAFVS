/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL handlers for TurboVAS reporting scopes.
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
create_scope (const char *, const char *, const char *, const char *,
              const char *, char **);

int
modify_scope (const char *, const char *, const char *, const char *,
              const char *, const char *);

int
delete_scope (const char *);

int
delete_scope_report (const char *);

int
buffer_scopes_xml (GString *, const char *, int);

int
buffer_scope_reports_xml (GString *, const char *, const char *, int,
                          const char *, int *, int *, int *);

int
scope_count (const char *);

int
scope_report_count (const char *, const char *);

int
scope_report_count_filtered (const char *, const char *, const char *);

#endif /* not _GVMD_MANAGE_SQL_SCOPES_H */
