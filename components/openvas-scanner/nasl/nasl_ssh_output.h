/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPENVAS_NASL_SSH_OUTPUT_H
#define OPENVAS_NASL_SSH_OUTPUT_H

#include <glib.h>

#define SSH_OUTPUT_MAX_SIZE (16U * 1024U * 1024U)

gboolean
nasl_ssh_output_append_with_limit (GString *, const GString *, const char *,
                                   gsize, gsize);

gboolean
nasl_ssh_output_append (GString *, const GString *, const char *, gsize);

#endif /* OPENVAS_NASL_SSH_OUTPUT_H */
