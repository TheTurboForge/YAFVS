/* SPDX-FileCopyrightText: 2009-2022 Greenbone AG
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * YAFVS-Derivation: adaptation
 * YAFVS-Source-Provenance: greenbone/gvmd commit 39a51f6ca6ad3d9383765436d2695d87e7dd8933, src/lsc_user.c and src/lsc_user.h, AGPL-3.0-or-later
 */

#ifndef _GVMD_CREDENTIAL_KEY_H
#define _GVMD_CREDENTIAL_KEY_H

#include <glib.h>

int
credential_ssh_key_create (const gchar *, gchar **);

#endif /* not _GVMD_CREDENTIAL_KEY_H */
