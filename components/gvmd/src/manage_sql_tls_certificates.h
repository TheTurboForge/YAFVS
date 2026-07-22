/* Copyright (C) 2019-2022 Greenbone AG
 * YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: TLS Certificates SQL headers
 *
 * Headers for TLS Certificates SQL for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H
#define _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H

#include "manage_tls_certificates.h"

const char**
tls_certificate_filter_columns ();

column_t*
tls_certificate_select_columns ();

gchar *
tls_certificate_extra_where (const char *);

void
delete_tls_certificates_user (user_t);

void
inherit_tls_certificates (user_t, user_t);

int
user_has_tls_certificate (tls_certificate_t, user_t);

int
add_tls_certificates_from_report_host (report_host_t,
                                       const char*,
                                       const char*);

int
cleanup_tls_certificate_encoding ();

#endif /* not _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H */
