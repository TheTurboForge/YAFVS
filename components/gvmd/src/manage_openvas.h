/* Copyright (C) 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager OpenVAS scan handling headers.
 *
 * This contains functions common to setting up OSP and openvasd scans.
 */

#ifndef _GVMD_MANAGE_OPENVAS_H
#define _GVMD_MANAGE_OPENVAS_H

#include <gvm/osp/osp.h>
#include <glib.h>
#include "manage_resources_types.h"

void
add_user_scan_preferences (GHashTable *);

scan_credential_t *
target_openvas_ssh_credential_db (target_t);

scan_credential_t *
target_openvas_smb_credential_db (target_t);

scan_credential_t *
target_openvas_esxi_credential_db (target_t);

scan_credential_t *
target_openvas_snmp_credential_db (target_t);

scan_credential_t *
target_openvas_krb5_credential_db (target_t);

#endif /* not _GVMD_MANAGE_OPENVAS_H */
