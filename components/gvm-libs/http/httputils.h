/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file httputils.h
 * @brief HTTP(S) utility API built on top of libcurl for the Greenbone
 * framework.
 *
 * This module provides a high-level wrapper around libcurl to simplify the
 * process of performing HTTP and HTTPS requests in both synchronous and
 * asynchronous (multi) modes. It offers abstractions for:
 *
 * - Sending requests with various HTTP methods (GET, POST, PUT, DELETE, etc.)
 * - Managing custom request headers
 * - SSL/TLS authentication with CA, client certificates, and private keys
 * - Accumulating and handling response data via callback streams
 * - Managing and cleaning up single and multi-handle CURL resources
 *
 * Core data structures:
 * - `gvm_http_t`: encapsulates a single HTTP request configuration and state
 * - `gvm_http_response_t`: represents the HTTP response including status, data,
 * and associated request
 * - `gvm_http_headers_t`: stores custom headers for use in requests
 * - `gvm_http_response_stream_t`: used internally for accumulating response
 * data during transfers
 * - `gvm_http_multi_t`: manages multiple concurrent transfers using libcurl's
 * multi interface
 */

#ifndef _GVM_HTTP_HTTPUTILS_H
#define _GVM_HTTP_HTTPUTILS_H

#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#include <glib.h>

#define GVM_HTTP_CONNECT_TIMEOUT_SECONDS 10L
#define GVM_HTTP_TOTAL_TIMEOUT_SECONDS 60L
#define GVM_HTTP_LOW_SPEED_LIMIT_BYTES 1024L
#define GVM_HTTP_LOW_SPEED_TIME_SECONDS 30L
#define GVM_HTTP_MAX_BODY_SIZE ((gsize) 8 * 1024 * 1024)
#define GVM_HTTP_MAX_HEADER_SIZE ((gsize) 64 * 1024)
#define GVM_HTTP_STREAM_TOTAL_TIMEOUT_SECONDS 900L
#define GVM_HTTP_MAX_STREAM_SIZE ((gsize) 512 * 1024 * 1024)

/**
 * @brief Request methods
 */
typedef enum
{
  GET,
  POST,
  PUT,
  DELETE,
  HEAD,
  PATCH
} gvm_http_method_t;

typedef enum
{
  GVM_HTTP_OK,
  GVM_HTTP_MULTI_BAD_HANDLE,
  GVM_HTTP_MULTI_FAILED,
  GVM_HTTP_MULTI_UNKNOWN_ERROR
} gvm_http_multi_result_t;

typedef struct gvm_http_headers
{
  struct curl_slist *custom_headers;

} gvm_http_headers_t;

/**
 * @brief Wraps a CURLM * handler and the custom headers.
 */
typedef struct gvm_http_multi
{
  void *handler; ///< Opaque pointer to the internal CURLM handle.

  gvm_http_headers_t *headers; ///< The wrapped headers type.

} gvm_http_multi_t;

/**
 * @brief Defines a struct for storing the response and http multi-handler.
 */
struct gvm_http_response_stream
{
  gchar *data; ///< Pointer to the accumulated response data buffer.

  size_t length; ///< Length of the response data buffer.

  gvm_http_multi_t *multi_handler; ///< Pointer to the associated http
                                   ///< multi-handle and headers.
};

typedef struct gvm_http_response_stream *gvm_http_response_stream_t;

typedef struct
{
  CURL *handler;

} gvm_http_t;

/**
 * @brief Represents the result of a http request.
 */
typedef struct
{
  gchar *data; ///< Exact response bytes followed by a trailing NUL sentinel.

  gsize size; ///< Authoritative response body size, excluding the sentinel.

  glong http_status; ///< HTTP status code returned by the server.

  gvm_http_t *http; ///< The HTTP request (easy handle wrapper).
} gvm_http_response_t;

void
gvm_http_free (gvm_http_t *http);

gvm_http_t *
gvm_http_new (const gchar *url, gvm_http_method_t method, const gchar *payload,
              gvm_http_headers_t *headers, const gchar *ca_cert,
              const gchar *client_cert, const gchar *client_key,
              gvm_http_response_stream_t res);

gvm_http_t *
gvm_http_new_streaming (const gchar *url, gvm_http_method_t method,
                        const gchar *payload, gvm_http_headers_t *headers,
                        const gchar *ca_cert, const gchar *client_cert,
                        const gchar *client_key,
                        gvm_http_response_stream_t res);

gvm_http_t *
gvm_http_new_unix (const gchar *url, gvm_http_method_t method,
                   const gchar *payload, gvm_http_headers_t *headers,
                   const gchar *ca_cert, const gchar *client_cert,
                   const gchar *client_key, const gchar *unix_socket_path,
                   gvm_http_response_stream_t res);

gvm_http_response_t *
gvm_http_request (const gchar *url, gvm_http_method_t method,
                  const gchar *payload, gvm_http_headers_t *headers,
                  const gchar *ca_cert, const gchar *client_cert,
                  const gchar *client_key, gvm_http_response_stream_t response);

gvm_http_response_t *
gvm_http_request_unix (const gchar *url, gvm_http_method_t method,
                       const gchar *payload, gvm_http_headers_t *headers,
                       const gchar *ca_cert, const gchar *client_cert,
                       const gchar *client_key, const gchar *unix_socket_path,
                       gvm_http_response_stream_t response);

gvm_http_headers_t *
gvm_http_headers_new (void);

gboolean
gvm_http_add_header (gvm_http_headers_t *headers, const gchar *header);

void
gvm_http_headers_free (gvm_http_headers_t *headers);

void
gvm_http_response_free (gvm_http_response_t *response);

gvm_http_multi_t *
gvm_http_multi_new (void);

gvm_http_multi_result_t
gvm_http_multi_add_handler (gvm_http_multi_t *multi, gvm_http_t *http);

gvm_http_multi_result_t
gvm_http_multi_perform (gvm_http_multi_t *multi, int *running_handles);

gvm_http_multi_result_t
gvm_http_multi_poll (gvm_http_multi_t *multi, int timeout);

void
gvm_http_multi_handler_free (gvm_http_multi_t *multi, gvm_http_t *http);

void
gvm_http_multi_free (gvm_http_multi_t *multi);

gvm_http_response_stream_t
gvm_http_response_stream_new (void);

void
gvm_http_response_stream_free (gvm_http_response_stream_t s);

void
gvm_http_response_stream_reset (gvm_http_response_stream_t s);

#endif /* not _GVM_HTTP_HTTPUTILS_H */
