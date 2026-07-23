/* Copyright (C) 2009-2022 Greenbone AG
 * YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_CREDENTIAL_KEY_H
#define _GVMD_CREDENTIAL_KEY_H

#include <glib.h>

int
credential_ssh_key_create (const gchar *, gchar **);

#endif /* not _GVMD_CREDENTIAL_KEY_H */
