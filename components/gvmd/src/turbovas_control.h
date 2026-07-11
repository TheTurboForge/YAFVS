/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Private TurboVAS control listener.
 */

#ifndef _GVMD_TURBOVAS_CONTROL_H
#define _GVMD_TURBOVAS_CONTROL_H

#include <signal.h>

/*
 * Private one-line protocol:
 *
 * schedule-create <secret> <operator_uuid> <name_b64> <comment_b64>
 *                 <timezone_b64> <icalendar_b64>\n
 *
 * Standard base64 fields contain no spaces. Empty optional fields are encoded
 * as empty tokens between their delimiter spaces.
 */

void
turbovas_control_accept_and_fork (int, int, int, sigset_t *);

#endif /* not _GVMD_TURBOVAS_CONTROL_H */
