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

void
turbovas_control_accept_and_fork (int, int, int, sigset_t *);

#endif /* not _GVMD_TURBOVAS_CONTROL_H */
