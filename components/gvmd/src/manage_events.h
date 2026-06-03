/* Copyright (C) 2025 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_EVENTS_H
#define _GVMD_MANAGE_EVENTS_H

#include "iterator.h"

/**
 * @brief Types of task events.
 */
typedef enum
{
  EVENT_ERROR,
  EVENT_TASK_RUN_STATUS_CHANGED,
  EVENT_NEW_SECINFO,
  EVENT_UPDATED_SECINFO
} event_t;

const char*
event_name (event_t);

gchar*
event_description (event_t, const void *, const char *);

event_t
event_from_name (const char*);

void
event (event_t, void *, resource_t, resource_t);

int
manage_alert (const char *, const char *, event_t, const void *, gchar **);

#endif /* not _GVMD_MANAGE_EVENTS_H */
