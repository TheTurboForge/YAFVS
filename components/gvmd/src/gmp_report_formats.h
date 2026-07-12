/* Copyright (C) 2020-2022 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_GMP_REPORT_FORMATS_H
#define _GVMD_GMP_REPORT_FORMATS_H

#include "gmp_base.h"

#include <gvm/base/array.h>
#include <gvm/util/xmlutils.h>


void
params_options_free (array_t *);

void
parse_report_format_entity (entity_t, const char **, char **, char **,
                            char **, char **, char **, char **,
                            array_t **, array_t **, array_t **, char **,
                            char **);

#endif /* not _GVMD_GMP_REPORT_FORMATS_H */
