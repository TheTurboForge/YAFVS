/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_native_api.h
 * @brief YAFVS native API proxy handling.
 */

#ifndef _GSAD_NATIVE_API_H
#define _GSAD_NATIVE_API_H

#include "gsad_http_handler.h"

gsad_http_result_t
gsad_http_handle_native_api_get (gsad_http_handler_t *, void *,
                                 gsad_http_connection_t *,
                                 gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_native_api_post (gsad_http_handler_t *, void *,
                                  gsad_http_connection_t *,
                                  gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_native_api_patch (gsad_http_handler_t *, void *,
                                   gsad_http_connection_t *,
                                   gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_native_api_put (gsad_http_handler_t *, void *,
                                 gsad_http_connection_t *,
                                 gsad_connection_info_t *, void *);

gsad_http_result_t
gsad_http_handle_native_api_delete (gsad_http_handler_t *, void *,
                                    gsad_http_connection_t *,
                                    gsad_connection_info_t *, void *);

#endif /* _GSAD_NATIVE_API_H */
