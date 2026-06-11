/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL handlers for TurboVAS report metrics.
 */

#ifndef _GVMD_MANAGE_SQL_METRICS_H
#define _GVMD_MANAGE_SQL_METRICS_H

#include "manage.h"

#include <glib.h>

int
rebuild_scope_report_metrics (resource_t, resource_t, int);

int
buffer_report_metrics_xml (GString *, const char *);

int
buffer_scope_report_metrics_xml (GString *, const char *);

#endif /* not _GVMD_MANAGE_SQL_METRICS_H */
