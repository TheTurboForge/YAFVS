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

#define TABLE_DRIVEN_LSC_MANIFEST_KEY "internal/turbovas.notus-manifest"
#define TABLE_DRIVEN_LSC_MANIFEST_FAILURE_KEY \
  "internal/turbovas.notus-manifest-failure"
#define TABLE_DRIVEN_LSC_MANIFEST_SEAL_KEY \
  "internal/turbovas.notus-manifest-seal"
#define TABLE_DRIVEN_LSC_ID_LENGTH 36
#define TABLE_DRIVEN_LSC_HOST_IP_MAX_LENGTH 45
#define TABLE_DRIVEN_LSC_SCAN_ID_MAX_LENGTH 128
#define TABLE_DRIVEN_LSC_START_FIELD_MAX_LENGTH 255
#define TABLE_DRIVEN_LSC_PACKAGE_MAX_BYTES 4096
#define TABLE_DRIVEN_LSC_PACKAGE_MAX_COUNT 10000
#define TABLE_DRIVEN_LSC_PACKAGE_LIST_MAX_BYTES (3 * 1024 * 1024)
#define TABLE_DRIVEN_LSC_START_PAYLOAD_MAX_BYTES ((4 * 1024 * 1024) - 1024)
#define TABLE_DRIVEN_LSC_RESPONSE_MAX_BYTES (16 * 1024 * 1024)

/** @brief Fixed version format
 */
enum fixed_type
{
  UNKNOWN, // Unknown
  RANGE,   // Range of version which fixed the package
  SINGLE,  // A single version with a specifier (gt or lt)
};

enum advisory_type
{
  NOTUS,
  SKIRON,
};

typedef enum advisory_type advisory_type_t;

/** @brief Fixed version
 */
struct fixed_version
{
  char *version;   // a version
  char *specifier; // a lt or gt specifier
};
typedef struct fixed_version fixed_version_t;

/** @brief Specify a version range
 */
struct version_range
{
  char *start; // <= the version
  char *stop;  // >= the version
};
typedef struct version_range version_range_t;

/** @brief Define a vulnerable package
 */
struct vulnerable_pkg
{
  char *pkg_name;        // package name
  char *install_version; // installed version of the vulnerable package
  enum fixed_type type;  // fixed version type: range or single
  union
  {
    version_range_t *range;   // range of vulnerable versions
    fixed_version_t *version; // version and specifier for the fixed versions
  };
};

typedef struct vulnerable_pkg vuln_pkg_t;

/** brief define an advisory with a list of vulnerable packages
 */
struct notus_advisory
{
  char *oid;             // Advisory OID
  vuln_pkg_t *pkgs[100]; // list of vulnerable packages, installed version and
                         // fixed versions
  size_t count;          // Count of vulnerable packages this advisory has
};
typedef struct notus_advisory advisory_t;

struct skiron_advisory
{
  char *oid;
  char *message;
};

typedef struct skiron_advisory skiron_advisory_t;

/** brief define a advisories list
 */
struct advisories
{
  union
  {
    advisory_t **advisories;
    skiron_advisory_t **skiron_advisories;
  };
  advisory_type_t type;
  size_t count;
  size_t max_size;
};
typedef struct advisories advisories_t;

void
advisories_free (advisories_t *advisories);

void
set_lsc_flag (void);

int
lsc_has_run (void);

const char *
table_driven_lsc_transport_name (void);

int
run_table_driven_lsc (const char *, const char *, const char *, const char *,
                      const char *);

char *
lsc_get_response (const char *pkg_list, const char *os);

advisories_t *
lsc_process_response (const gchar *resp, const size_t len);

#endif // MISC_TABLE_DRIVEN_LSC_H
