/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file table_drive_lsc.h
 * @brief Header file for module table_driven_lsc.
 */

#ifndef MISC_TABLE_DRIVEN_LSC_H
#define MISC_TABLE_DRIVEN_LSC_H

#include <glib.h>
#include <gvm/util/kb.h> // for kb_t

#define TABLE_DRIVEN_LSC_MANIFEST_KEY "internal/yafvs.notus-manifest"
#define TABLE_DRIVEN_LSC_MANIFEST_FAILURE_KEY \
  "internal/yafvs.notus-manifest-failure"
#define TABLE_DRIVEN_LSC_MANIFEST_SEAL_KEY \
  "internal/yafvs.notus-manifest-seal"
#define TABLE_DRIVEN_LSC_ID_LENGTH 36
#define TABLE_DRIVEN_LSC_HOST_IP_MAX_LENGTH 45
#define TABLE_DRIVEN_LSC_SCAN_ID_MAX_LENGTH 128
#define TABLE_DRIVEN_LSC_START_FIELD_MAX_LENGTH 255
#define TABLE_DRIVEN_LSC_PACKAGE_MAX_BYTES 4096
#define TABLE_DRIVEN_LSC_PACKAGE_MAX_COUNT 10000
#define TABLE_DRIVEN_LSC_PACKAGE_LIST_MAX_BYTES (3 * 1024 * 1024)
#define TABLE_DRIVEN_LSC_START_PAYLOAD_MAX_BYTES ((4 * 1024 * 1024) - 1024)
void
set_lsc_flag (void);

int
lsc_has_run (void);

const char *
table_driven_lsc_transport_name (void);

int
run_table_driven_lsc (const char *, const char *, const char *, const char *,
                      const char *);

#endif // MISC_TABLE_DRIVEN_LSC_H
