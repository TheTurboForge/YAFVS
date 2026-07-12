/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file httputils.c
 * @brief HTTP utility functions built on libcurl.
 *
 * This module provides an abstraction layer over libcurl to simplify HTTP(S)
 * request handling. It supports:
 *
 * - Synchronous and asynchronous requests (via easy and multi handles).
 * - Custom HTTP methods, headers, and payloads.
 * - SSL/TLS configuration (CA certificates, client certs, private keys).
 * - Response buffering through a write callback.
 * - Encapsulation of libcurl handles in domain-specific types (e.g.,
 * gvm_http_t).
 */

#define _GNU_SOURCE

#include "httputils.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

typedef struct
{
  long connect_timeout;
  long total_timeout;
  long low_speed_limit;
  long low_speed_time;
  gsize body_limit;
  gsize header_limit;
} gvm_http_policy_t;

typedef struct
{
  gvm_http_t *owner;
  gvm_http_response_stream_t stream;
  gsize body_limit;
  gsize header_limit;
  gsize body_received;
  gsize header_length;
  gboolean failed;
  int ca_fd;
  int client_cert_fd;
  int client_key_fd;
} gvm_http_request_context_t;

typedef struct gvm_http_request_node
{
  gvm_http_t *http;
  struct gvm_http_request_node *next;
} gvm_http_request_node_t;

typedef struct
{
  CURLM *curl;
  gvm_http_request_node_t *requests;
} gvm_http_multi_internal_t;

static const gvm_http_policy_t buffered_policy = {
  GVM_HTTP_CONNECT_TIMEOUT_SECONDS, GVM_HTTP_TOTAL_TIMEOUT_SECONDS,
  GVM_HTTP_LOW_SPEED_LIMIT_BYTES,   GVM_HTTP_LOW_SPEED_TIME_SECONDS,
  GVM_HTTP_MAX_BODY_SIZE,           GVM_HTTP_MAX_HEADER_SIZE,
};

/*
 * VT metadata is consumed incrementally and routinely exceeds the buffered
 * response cap. Bound one cumulative stream to 512 MiB and 15 minutes while
 * retaining the same liveness floor; stream resets do not reset this counter.
 */
static const gvm_http_policy_t streaming_policy = {
  GVM_HTTP_CONNECT_TIMEOUT_SECONDS, GVM_HTTP_STREAM_TOTAL_TIMEOUT_SECONDS,
  GVM_HTTP_LOW_SPEED_LIMIT_BYTES,   GVM_HTTP_LOW_SPEED_TIME_SECONDS,
  GVM_HTTP_MAX_STREAM_SIZE,         GVM_HTTP_MAX_HEADER_SIZE,
};

/**
 * @brief Allocate gvm http multi handler
 *
 * @return gvm http multi handler.
 */
static gvm_http_multi_t *
gvm_http_multi_t_new (void)
{
  return (gvm_http_multi_t *) g_try_malloc0 (sizeof (struct gvm_http_multi));
}

static void
discard_response_data (gvm_http_request_context_t *context)
{
  if (!context || !context->stream)
    return;

  g_clear_pointer (&context->stream->data, g_free);
  context->stream->length = 0;
  context->failed = TRUE;
}

/**
 * @brief Callback function to store the response.
 *
 * @param ptr Pointer to the delivered data.
 * @param size Size of each data element.
 * @param nmemb Number of data elements.
 * @param userdata Pointer to the user-defined buffer or structure
 *                 where the data will be stored.
 *
 * @return The number of bytes actually handled.
 */
static size_t
store_response_data (void *ptr, size_t size, size_t nmemb, void *userdata)
{
  gvm_http_request_context_t *context = userdata;
  gvm_http_response_stream_t stream;
  size_t chunk_len;
  size_t new_len;
  gchar *temp_ptr;

  if (!context || !context->stream)
    return 0;
  stream = context->stream;
  if (size != 0 && nmemb > G_MAXSIZE / size)
    {
      discard_response_data (context);
      return 0;
    }

  chunk_len = size * nmemb;
  if (chunk_len > 0 && !ptr)
    {
      discard_response_data (context);
      return 0;
    }
  if (context->failed || context->body_received > context->body_limit
      || chunk_len > context->body_limit - context->body_received)
    {
      discard_response_data (context);
      return 0;
    }

  new_len = stream->length + chunk_len;
  if (new_len == G_MAXSIZE)
    {
      discard_response_data (context);
      return 0;
    }

  temp_ptr = g_try_realloc (stream->data, new_len + 1);
  if (!temp_ptr)
    {
      discard_response_data (context);
      return 0;
    }

  stream->data = temp_ptr;
  if (chunk_len > 0)
    memcpy (stream->data + stream->length, ptr, chunk_len);
  stream->data[new_len] = '\0';
  stream->length = new_len;
  context->body_received += chunk_len;

  return chunk_len;
}

static size_t
store_response_header (void *ptr, size_t size, size_t nmemb, void *userdata)
{
  gvm_http_request_context_t *context = userdata;
  size_t chunk_len;

  (void) ptr;
  if (!context || !context->stream)
    return 0;
  if (size != 0 && nmemb > G_MAXSIZE / size)
    {
      discard_response_data (context);
      return 0;
    }

  chunk_len = size * nmemb;
  if (context->failed || context->header_length > context->header_limit
      || chunk_len > context->header_limit - context->header_length)
    {
      discard_response_data (context);
      return 0;
    }

  context->header_length += chunk_len;
  return chunk_len;
}

static gboolean
pem_gap_is_valid (const gchar *start, const gchar *end)
{
  const gchar *cursor = start;

  while (cursor < end)
    {
      if (g_ascii_isspace (*cursor))
        cursor++;
      else if (*cursor == '#')
        {
          while (cursor < end && *cursor != '\n')
            cursor++;
        }
      else
        return FALSE;
    }
  return TRUE;
}

static gchar *
try_duplicate_data (const void *data, gsize length)
{
  gchar *duplicate;

  if (length == G_MAXSIZE)
    return NULL;
  duplicate = g_try_malloc (length + 1);
  if (!duplicate)
    return NULL;
  if (length > 0)
    memcpy (duplicate, data, length);
  duplicate[length] = '\0';
  return duplicate;
}

static gboolean
der_read_tlv (const guchar *der, gsize length, guchar expected_tag,
              const guchar **content, gsize *content_length, gsize *consumed)
{
  gsize value_length;
  gsize length_octets;
  gsize offset;
  gsize header_length;

  if (length < 2 || der[0] != expected_tag)
    return FALSE;

  if ((der[1] & 0x80) == 0)
    {
      header_length = 2;
      value_length = der[1];
    }
  else
    {
      length_octets = der[1] & 0x7f;
      if (length_octets == 0 || length_octets > sizeof (gsize)
          || length < 2 + length_octets || der[2] == 0)
        return FALSE;

      value_length = 0;
      for (offset = 0; offset < length_octets; offset++)
        {
          if (value_length > (G_MAXSIZE - der[2 + offset]) / 256)
            return FALSE;
          value_length = value_length * 256 + der[2 + offset];
        }
      header_length = 2 + length_octets;
    }

  if (value_length > length - header_length)
    return FALSE;
  *content = der + header_length;
  *content_length = value_length;
  *consumed = header_length + value_length;
  return TRUE;
}

static gboolean
der_certificate_is_well_formed (const guchar *der, gsize length)
{
  const guchar *certificate;
  const guchar *field;
  gsize certificate_length;
  gsize field_length;
  gsize consumed;
  gsize offset = 0;

  if (!der_read_tlv (der, length, 0x30, &certificate, &certificate_length,
                     &consumed)
      || consumed != length)
    return FALSE;

  if (!der_read_tlv (certificate, certificate_length, 0x30, &field,
                     &field_length, &consumed)
      || field_length == 0)
    return FALSE;
  offset += consumed;

  if (!der_read_tlv (certificate + offset, certificate_length - offset, 0x30,
                     &field, &field_length, &consumed)
      || field_length == 0)
    return FALSE;
  offset += consumed;

  if (!der_read_tlv (certificate + offset, certificate_length - offset, 0x03,
                     &field, &field_length, &consumed)
      || field_length < 2)
    return FALSE;
  offset += consumed;

  return offset == certificate_length;
}

static gboolean
pem_certificate_is_valid (const gchar *start, const gchar *end)
{
  gchar *encoded;
  gchar *read_cursor;
  gchar *write_cursor;
  gsize decoded_length;
  guint padding = 0;
  gboolean valid;
  gchar *first_padding;

  encoded = try_duplicate_data (start, end - start);
  if (!encoded)
    return FALSE;

  write_cursor = encoded;
  for (read_cursor = encoded; *read_cursor; read_cursor++)
    {
      if (g_ascii_isspace (*read_cursor))
        continue;
      if (!(g_ascii_isalnum (*read_cursor) || *read_cursor == '+'
            || *read_cursor == '/' || *read_cursor == '='))
        {
          g_free (encoded);
          return FALSE;
        }
      *write_cursor++ = *read_cursor;
    }
  *write_cursor = '\0';

  if (write_cursor == encoded || (write_cursor - encoded) % 4 != 0)
    {
      g_free (encoded);
      return FALSE;
    }

  while (write_cursor > encoded && write_cursor[-1] == '=')
    {
      padding++;
      write_cursor--;
    }
  first_padding = strchr (encoded, '=');
  if (padding > 2
      || (padding == 0 ? first_padding != NULL : first_padding != write_cursor))
    {
      g_free (encoded);
      return FALSE;
    }

  g_base64_decode_inplace (encoded, &decoded_length);
  valid =
    der_certificate_is_well_formed ((const guchar *) encoded, decoded_length);
  g_free (encoded);
  return valid;
}

static gboolean
pem_certificate_bundle_is_valid (const gchar *bundle)
{
  static const gchar begin_marker[] = "-----BEGIN CERTIFICATE-----";
  static const gchar end_marker[] = "-----END CERTIFICATE-----";
  const gchar *cursor = bundle;
  gboolean found_certificate = FALSE;

  if (!bundle || bundle[0] == '\0')
    return FALSE;

  while (*cursor)
    {
      const gchar *begin = strstr (cursor, begin_marker);
      const gchar *end;

      if (!begin)
        return found_certificate
               && pem_gap_is_valid (cursor, cursor + strlen (cursor));
      if (!pem_gap_is_valid (cursor, begin))
        return FALSE;
      begin += sizeof (begin_marker) - 1;
      end = strstr (begin, end_marker);
      if (!end || !pem_certificate_is_valid (begin, end))
        return FALSE;

      found_certificate = TRUE;
      cursor = end + sizeof (end_marker) - 1;
    }

  return found_certificate;
}

static const gchar *
http_method_name (gvm_http_method_t method)
{
  switch (method)
    {
    case POST:
      return "POST";
    case PUT:
      return "PUT";
    case DELETE:
      return "DELETE";
    case HEAD:
      return "HEAD";
    case PATCH:
      return "PATCH";
    case GET:
    default:
      return "GET";
    }
}

static int
write_anonymous_credential (const gchar *contents, const gchar *name)
{
  gsize length = strlen (contents);
  gsize written = 0;
  int fd =
    open (g_get_tmp_dir (), O_TMPFILE | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);

  (void) name;
  if (fd < 0)
    return -1;

  while (written < length)
    {
      ssize_t result = write (fd, contents + written, length - written);
      if (result < 0 && errno == EINTR)
        continue;
      if (result <= 0)
        goto fail;
      written += result;
    }
  if (lseek (fd, 0, SEEK_SET) < 0)
    goto fail;
  return fd;

fail:
  close (fd);
  return -1;
}

static void
close_credential (int *fd)
{
  if (!fd || *fd < 0)
    return;
  close (*fd);
  *fd = -1;
}

static gvm_http_request_context_t *
request_context_new (gvm_http_response_stream_t stream,
                     const gvm_http_policy_t *policy)
{
  gvm_http_request_context_t *context =
    g_try_malloc0 (sizeof (gvm_http_request_context_t));

  if (!context)
    return NULL;
  context->stream = stream;
  context->body_limit = policy->body_limit;
  context->header_limit = policy->header_limit;
  context->ca_fd = -1;
  context->client_cert_fd = -1;
  context->client_key_fd = -1;
  return context;
}

static void
request_context_free (gvm_http_request_context_t *context)
{
  if (!context)
    return;
  close_credential (&context->ca_fd);
  close_credential (&context->client_cert_fd);
  close_credential (&context->client_key_fd);
  g_free (context);
}

static gvm_http_request_context_t *
request_context_from_http (gvm_http_t *http)
{
  gvm_http_request_context_t *context = NULL;

  if (!http || !http->handler
      || curl_easy_getinfo (http->handler, CURLINFO_PRIVATE, &context)
           != CURLE_OK)
    return NULL;
  return context;
}

static gboolean
credential_descriptor_path (int fd, gchar *path, gsize path_size)
{
  int length = g_snprintf (path, path_size, "/proc/self/fd/%d", fd);

  return length > 0 && (gsize) length < path_size && access (path, R_OK) == 0;
}

static gboolean
url_protocol_is_allowed (const gchar *url)
{
  gchar *scheme = url ? g_uri_parse_scheme (url) : NULL;
  gboolean allowed = scheme
                     && (g_ascii_strcasecmp (scheme, "http") == 0
                         || g_ascii_strcasecmp (scheme, "https") == 0);

  g_free (scheme);
  return allowed;
}

static gboolean
configure_transport_defaults (CURL *curl, const gchar *url,
                              gvm_http_request_context_t *context,
                              const gvm_http_policy_t *policy)
{
  return curl_easy_setopt (curl, CURLOPT_URL, url) == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, store_response_data)
              == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_WRITEDATA, context) == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_HEADERFUNCTION,
                              store_response_header)
              == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_HEADERDATA, context) == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT,
                              policy->connect_timeout)
              == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_TIMEOUT, policy->total_timeout)
              == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_LOW_SPEED_LIMIT,
                              policy->low_speed_limit)
              == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_LOW_SPEED_TIME,
                              policy->low_speed_time)
              == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_MAXFILESIZE_LARGE,
                              (curl_off_t) policy->body_limit)
              == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 1L) == CURLE_OK
         && curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 2L) == CURLE_OK;
}

static gboolean
configure_http_method (CURL *curl, gvm_http_method_t method,
                       const gchar *payload)
{
  if (curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, http_method_name (method))
      != CURLE_OK)
    return FALSE;

  switch (method)
    {
    case POST:
    case PUT:
    case PATCH:
      return curl_easy_setopt (curl, CURLOPT_POSTFIELDS, payload ? payload : "")
               == CURLE_OK
             && curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE,
                                  payload ? (long) strlen (payload) : 0L)
                  == CURLE_OK;
    case HEAD:
      return curl_easy_setopt (curl, CURLOPT_NOBODY, 1L) == CURLE_OK;
    case DELETE:
    case GET:
    default:
      return TRUE;
    }
}

/**
 * @brief Allocates and initializes a gvm_http_t structure with a given CURL
 * handle.
 *
 * @param curl_handler  A valid libcurl easy handle to be wrapped. If NULL, the
 * function returns NULL.
 *
 * @return A pointer to an initialized `gvm_http_t` structure on success,
 *         or NULL if the input handle is invalid.
 */
static gvm_http_t *
gvm_http_t_new (CURL *curl_handler, gvm_http_request_context_t *context)
{
  if (!curl_handler || !context)
    {
      if (curl_handler)
        curl_easy_cleanup (curl_handler);
      request_context_free (context);
      return NULL;
    }

  gvm_http_t *http = g_try_malloc0 (sizeof (gvm_http_t));
  if (!http)
    {
      curl_easy_cleanup (curl_handler);
      request_context_free (context);
      return NULL;
    }
  http->handler = curl_handler;
  context->owner = http;
  if (curl_easy_setopt (curl_handler, CURLOPT_PRIVATE, context) != CURLE_OK)
    {
      curl_easy_cleanup (curl_handler);
      request_context_free (context);
      g_free (http);
      return NULL;
    }
  return http;
}

/**
 * @brief Internal helper to initialize and configure a gvm_http_t object.
 *
 * This function contains the shared implementation for creating HTTP requests
 * over either a normal network connection or a Unix domain socket.
 *
 * If @p unix_socket_path is non-NULL and non-empty, libcurl is configured to
 * connect through the given Unix domain socket path.
 *
 * @param url               The full request URL.
 * @param method            The HTTP method to use.
 * @param payload           Optional request body for POST/PUT/PATCH.
 * @param headers           Optional custom headers.
 * @param ca_cert           Optional CA certificate for server verification.
 * @param client_cert       Optional client certificate for mutual TLS.
 * @param client_key        Optional client private key for mutual TLS.
 * @param unix_socket_path  Optional Unix domain socket path. If NULL, a normal
 *                          network connection is used.
 * @param res               Response stream used as the write target.
 *
 * @return A configured gvm_http_t object on success, or NULL on failure.
 */
static gvm_http_t *
gvm_http_new_internal (const gchar *url, gvm_http_method_t method,
                       const gchar *payload, gvm_http_headers_t *headers,
                       const gchar *ca_cert, const gchar *client_cert,
                       const gchar *client_key, const gchar *unix_socket_path,
                       gvm_http_response_stream_t res,
                       const gvm_http_policy_t *policy)
{
  const gboolean has_client_cert = client_cert != NULL;
  const gboolean has_client_key = client_key != NULL;
  gchar descriptor_path[64];
  gvm_http_request_context_t *context = NULL;
  gvm_http_t *http;
  CURL *curl = curl_easy_init ();
  if (!curl || !url || !res || !policy || !url_protocol_is_allowed (url))
    {
      if (url && !url_protocol_is_allowed (url))
        g_warning ("%s: URL protocol must be HTTP or HTTPS", __func__);
      if (curl)
        curl_easy_cleanup (curl);
      return NULL;
    }

  if ((has_client_cert != has_client_key)
      || (has_client_cert && (client_cert[0] == '\0' || client_key[0] == '\0')))
    {
      g_warning ("%s: Client certificate and key must be a complete pair",
                 __func__);
      curl_easy_cleanup (curl);
      return NULL;
    }

  if (ca_cert && !pem_certificate_bundle_is_valid (ca_cert))
    {
      g_warning ("%s: Invalid CA certificate bundle", __func__);
      curl_easy_cleanup (curl);
      return NULL;
    }

  context = request_context_new (res, policy);
  if (!context)
    {
      curl_easy_cleanup (curl);
      return NULL;
    }

  if (!configure_transport_defaults (curl, url, context, policy))
    {
      g_warning ("%s: Failed to set transport defaults", __func__);
      request_context_free (context);
      curl_easy_cleanup (curl);
      return NULL;
    }

  /* Use Unix domain socket if configured */
  if (unix_socket_path && unix_socket_path[0] != '\0')
    {
      // ref: https://curl.se/libcurl/c/CURLOPT_UNIX_SOCKET_PATH.html
      if (curl_easy_setopt (curl, CURLOPT_UNIX_SOCKET_PATH, unix_socket_path)
          != CURLE_OK)
        {
          g_warning ("%s: Failed to set Unix socket path", __func__);
          request_context_free (context);
          curl_easy_cleanup (curl);
          return NULL;
        }
    }

  // Set HTTP headers if provided
  if (headers && headers->custom_headers)
    {
      if (curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers->custom_headers)
          != CURLE_OK)
        {
          g_warning ("%s: Failed to set HTTP headers", __func__);
          request_context_free (context);
          curl_easy_cleanup (curl);
          return NULL;
        }
    }

  if (ca_cert)
    {
      context->ca_fd = write_anonymous_credential (ca_cert, "ca");
      if (context->ca_fd < 0
          || !credential_descriptor_path (context->ca_fd, descriptor_path,
                                          sizeof (descriptor_path))
          || curl_easy_setopt (curl, CURLOPT_CAINFO, descriptor_path)
               != CURLE_OK)
        {
          g_warning ("%s: Failed to set CA certificate", __func__);
          request_context_free (context);
          curl_easy_cleanup (curl);
          return NULL;
        }
    }
  if (has_client_cert)
    {
      context->client_cert_fd =
        write_anonymous_credential (client_cert, "client-cert");
      context->client_key_fd =
        write_anonymous_credential (client_key, "client-key");
      if (context->client_cert_fd < 0 || context->client_key_fd < 0
          || !credential_descriptor_path (
            context->client_cert_fd, descriptor_path, sizeof (descriptor_path))
          || curl_easy_setopt (curl, CURLOPT_SSLCERT, descriptor_path)
               != CURLE_OK
          || !credential_descriptor_path (
            context->client_key_fd, descriptor_path, sizeof (descriptor_path))
          || curl_easy_setopt (curl, CURLOPT_SSLKEY, descriptor_path)
               != CURLE_OK)
        {
          g_warning ("%s: Failed to set client credentials", __func__);
          request_context_free (context);
          curl_easy_cleanup (curl);
          return NULL;
        }
    }

  if (!configure_http_method (curl, method, payload))
    {
      g_warning ("%s: Failed to set HTTP method", __func__);
      request_context_free (context);
      curl_easy_cleanup (curl);
      return NULL;
    }

  http = gvm_http_t_new (curl, context);
  if (!http)
    return NULL;
  return http;
}

/**
 * @brief Internal helper to send a synchronous HTTP request and capture
 * the response.
 *
 * If @p unix_socket_path is non-NULL and non-empty, libcurl is configured to
 * connect through the given Unix domain socket.
 *
 * @param url               The URL to send the request to.
 * @param method            HTTP method to use.
 * @param payload           Optional request payload.
 * @param headers           Optional custom headers.
 * @param ca_cert           Optional CA certificate for server verification.
 * @param client_cert       Optional client certificate for mutual TLS.
 * @param client_key        Optional client private key for mutual TLS.
 * @param unix_socket_path  Optional Unix domain socket path.
 * @param response          Optional response stream buffer; if NULL, one will
 *                          be created internally.
 *
 * @return A newly allocated gvm_http_response_t on success or failure.
 */
static gvm_http_response_t *
gvm_http_request_internal (const gchar *url, gvm_http_method_t method,
                           const gchar *payload, gvm_http_headers_t *headers,
                           const gchar *ca_cert, const gchar *client_cert,
                           const gchar *client_key,
                           const gchar *unix_socket_path,
                           gvm_http_response_stream_t response)
{
  static const gchar init_error[] =
    "{\"error\": \"Failed to initialize curl request\"}";
  static const gchar transfer_error[] = "{\"error\": \"CURL request failed\"}";
  gvm_http_response_t *http_response =
    g_try_malloc0 (sizeof (gvm_http_response_t));
  gboolean internal_stream_allocated = FALSE;

  if (!http_response)
    return NULL;

  if (response == NULL)
    {
      response = g_try_malloc0 (sizeof (struct gvm_http_response_stream));
      if (!response)
        {
          g_free (http_response);
          return NULL;
        }
      response->multi_handler = NULL;
      internal_stream_allocated = TRUE;
    }
  else
    gvm_http_response_stream_reset (response);

  gvm_http_t *http = gvm_http_new_internal (
    url, method, payload, headers, ca_cert, client_cert, client_key,
    unix_socket_path, response, &buffered_policy);
  if (!http)
    {
      http_response->http_status = -1;
      http_response->data =
        try_duplicate_data (init_error, sizeof (init_error) - 1);
      http_response->size = http_response->data ? sizeof (init_error) - 1 : 0;

      if (internal_stream_allocated)
        {
          g_free (response->data);
          g_free (response);
        }

      return http_response;
    }

  http_response->http = http;
  gvm_http_request_context_t *context = request_context_from_http (http);

  CURLcode result = curl_easy_perform (http->handler);
  if (result == CURLE_OK && context && !context->failed)
    {
      curl_easy_getinfo (http->handler, CURLINFO_RESPONSE_CODE,
                         &http_response->http_status);
      if (response->length == G_MAXSIZE)
        result = CURLE_WRITE_ERROR;
      else
        {
          http_response->data =
            try_duplicate_data (response->data, response->length);
          if (!http_response->data)
            result = CURLE_OUT_OF_MEMORY;
          else
            {
              http_response->size = response->length;
            }
        }
    }

  if (result != CURLE_OK || !context || context->failed)
    {
      g_debug ("%s: Error performing CURL request: %s", __func__,
               curl_easy_strerror (result));
      discard_response_data (context);
      http_response->http_status = -1;
      g_free (http_response->data);
      http_response->data =
        try_duplicate_data (transfer_error, sizeof (transfer_error) - 1);
      http_response->size =
        http_response->data ? sizeof (transfer_error) - 1 : 0;
    }

  if (internal_stream_allocated)
    {
      g_free (response->data);
      g_free (response);
    }

  return http_response;
}

/**
 * @brief Frees a gvm_http_t object and its associated CURL handle.
 *
 * @param http Pointer to the gvm_http_t structure to free. Safe to pass NULL.
 */
void
gvm_http_free (gvm_http_t *http)
{
  gvm_http_request_context_t *context;

  if (!http)
    return;
  context = request_context_from_http (http);
  if (http->handler)
    curl_easy_cleanup (http->handler);
  request_context_free (context);
  g_free (http);
}

/**
 * @brief Initializes and configures a gvm_http_t object for an HTTP(S) request.
 *
 * This function creates and configures a gvm_http_t structure, encapsulating
 * a libcurl easy handle. It sets the target URL, HTTP method, optional headers,
 * payload, and SSL/TLS credentials (CA certificate, client certificate, and
 * private key). It also registers a write callback to store the server's
 * response into a provided response stream buffer.
 *
 * Note: The returned object must be cleaned up by the caller using
 * `gvm_http_free()` to free all associated resources. The request is not
 * executed by this function.
 *
 * @param url           The full request URL.
 * @param method        The HTTP method to use (GET, POST, etc.).
 * @param payload       Optional request body for POST or PUT.
 * @param headers       Optional custom headers (gvm_http_headers_t).
 * @param ca_cert       Optional CA certificate for server verification.
 * @param client_cert   Optional client certificate for mutual TLS.
 * @param client_key    Optional client private key for mutual TLS.
 * @param res           Response stream used as the write target during the
 * request.
 *
 * @return A configured gvm_http_t object on success, or NULL on failure.
 */
gvm_http_t *
gvm_http_new (const gchar *url, gvm_http_method_t method, const gchar *payload,
              gvm_http_headers_t *headers, const gchar *ca_cert,
              const gchar *client_cert, const gchar *client_key,
              gvm_http_response_stream_t res)
{
  return gvm_http_new_internal (url, method, payload, headers, ca_cert,
                                client_cert, client_key, NULL, res,
                                &buffered_policy);
}

gvm_http_t *
gvm_http_new_streaming (const gchar *url, gvm_http_method_t method,
                        const gchar *payload, gvm_http_headers_t *headers,
                        const gchar *ca_cert, const gchar *client_cert,
                        const gchar *client_key, gvm_http_response_stream_t res)
{
  return gvm_http_new_internal (url, method, payload, headers, ca_cert,
                                client_cert, client_key, NULL, res,
                                &streaming_policy);
}

/**
 * @brief Initializes and configures a gvm_http_t object for an HTTP(S) request
 *        sent through a Unix domain socket.
 *
 * This function behaves like gvm_http_new(), but configures libcurl to connect
 * using the Unix domain socket specified by @p unix_socket_path.
 *
 * @param url               The request URL.
 * @param method            The HTTP method to use.
 * @param payload           Optional request body.
 * @param headers           Optional custom headers.
 * @param ca_cert           Optional CA certificate for server verification.
 * @param client_cert       Optional client certificate for mutual TLS.
 * @param client_key        Optional client private key for mutual TLS.
 * @param unix_socket_path  Path to the Unix domain socket to use.
 * @param res               Response stream used as the write target.
 *
 * @return A configured gvm_http_t object on success, or NULL on failure.
 */
gvm_http_t *
gvm_http_new_unix (const gchar *url, gvm_http_method_t method,
                   const gchar *payload, gvm_http_headers_t *headers,
                   const gchar *ca_cert, const gchar *client_cert,
                   const gchar *client_key, const gchar *unix_socket_path,
                   gvm_http_response_stream_t res)
{
  return gvm_http_new_internal (url, method, payload, headers, ca_cert,
                                client_cert, client_key, unix_socket_path, res,
                                &buffered_policy);
}

/** @brief Allocate the vt stream struct to hold the response
 *  and the curlm handler
 *
 *  @return The vt stream struct. Must be free with
 * gvm_http_response_stream_free().
 */
gvm_http_response_stream_t
gvm_http_response_stream_new (void)
{
  gvm_http_response_stream_t s;
  s = g_try_malloc0 (sizeof (struct gvm_http_response_stream));
  if (!s)
    return NULL;
  s->data = g_try_malloc0 (1);
  if (!s->data)
    {
      g_free (s);
      return NULL;
    }
  s->multi_handler = gvm_http_multi_t_new ();
  if (!s->multi_handler)
    {
      g_free (s->data);
      g_free (s);
      return NULL;
    }
  return s;
}

/** @brief Cleanup the string struct to hold the response and the
 *  curl multiperform handler
 *
 *  @param s The string struct to be freed
 */
void
gvm_http_response_stream_free (gvm_http_response_stream_t s)
{
  if (s == NULL)
    return;

  g_free (s->data);
  if (s->multi_handler)
    gvm_http_multi_free (s->multi_handler);

  g_free (s);
}

/**
 * @brief Sends a synchronous HTTP(S) request and captures the response.
 *
 * This function performs an HTTP request using libcurl, with the specified
 * method, headers, SSL/TLS credentials, and optional payload. It encapsulates
 * the CURL easy handle and configuration into a `gvm_http_t` structure, which
 * is used to execute the request. The server response is stored in a
 * `gvm_http_response_t` structure, which includes the HTTP status code and
 * response data.
 *
 * If no response stream is provided, an internal one will be allocated and
 * automatically cleaned up. If a stream is provided, the caller is responsible
 * for its cleanup.
 *
 * @param url           The URL to send the request to.
 * @param method        HTTP method to use (e.g., GET, POST, PUT, DELETE).
 * @param payload       Optional request payload for methods like POST or PUT.
 * @param headers       Optional custom headers (`gvm_http_headers_t`).
 * @param ca_cert       Optional CA certificate for server verification.
 * @param client_cert   Optional client certificate for mutual TLS.
 * @param client_key    Optional client private key for mutual TLS.
 * @param response      Optional response stream buffer; if NULL, one will be
 * created.
 *
 * @return A pointer to a `gvm_http_response_t` containing the response data and
 * status. Must be freed with `gvm_http_response_free()`.
 */
gvm_http_response_t *
gvm_http_request (const gchar *url, gvm_http_method_t method,
                  const gchar *payload, gvm_http_headers_t *headers,
                  const gchar *ca_cert, const gchar *client_cert,
                  const gchar *client_key, gvm_http_response_stream_t response)
{
  return gvm_http_request_internal (url, method, payload, headers, ca_cert,
                                    client_cert, client_key, NULL, response);
}

/**
 * @brief Sends a synchronous HTTP(S) request and captures the response.
 *
 * This function performs an HTTP request using libcurl, with the specified
 * method, headers, SSL/TLS credentials, and optional payload. It encapsulates
 * the CURL easy handle and configuration into a `gvm_http_t` structure, which
 * is used to execute the request. The server response is stored in a
 * `gvm_http_response_t` structure, which includes the HTTP status code and
 * response data.
 *
 * If `unix_socket_path` is provided, the request will be sent through the
 * specified Unix domain socket instead of a TCP/IP network connection.
 *
 * If no response stream is provided, an internal one will be allocated and
 * automatically cleaned up. If a stream is provided, the caller is responsible
 * for freeing it.
 *
 * @param url               The URL to send the request to.
 * @param method            HTTP method to use (e.g., GET, POST, PUT, DELETE).
 * @param payload           Optional request payload for methods like POST or
 *                          PUT.
 * @param headers           Optional custom headers (`gvm_http_headers_t`).
 * @param ca_cert           Optional CA certificate for server verification.
 * @param client_cert       Optional client certificate for mutual TLS.
 * @param client_key        Optional client private key for mutual TLS.
 * @param unix_socket_path  Path to the Unix domain socket to use.
 * @param response          Optional response stream buffer; if NULL, one will
 *                          be created.
 *
 * @return A pointer to a `gvm_http_response_t` containing the response data and
 *         status. Must be freed with `gvm_http_response_free()`.
 */
gvm_http_response_t *
gvm_http_request_unix (const gchar *url, gvm_http_method_t method,
                       const gchar *payload, gvm_http_headers_t *headers,
                       const gchar *ca_cert, const gchar *client_cert,
                       const gchar *client_key, const gchar *unix_socket_path,
                       gvm_http_response_stream_t response)
{
  return gvm_http_request_internal (url, method, payload, headers, ca_cert,
                                    client_cert, client_key, unix_socket_path,
                                    response);
}

/**
 * @brief Cleans up a gvm_http_response_t structure and associated resources.
 *
 * @param response Pointer to a `gvm_http_response_t` structure to clean up.
 *                 Can safely be NULL.
 */
void
gvm_http_response_free (gvm_http_response_t *response)
{
  if (!response)
    return;

  gvm_http_free (response->http);
  g_free (response->data);
  g_free (response);
}

/**
 * @brief Allocates and initializes a new gvm_http_headers_t structure.
 *
 * @return A pointer to a newly allocated `gvm_http_headers_t` structure.
 */
gvm_http_headers_t *
gvm_http_headers_new (void)
{
  gvm_http_headers_t *headers = g_try_malloc0 (sizeof (gvm_http_headers_t));
  if (!headers)
    return NULL;
  headers->custom_headers = NULL;
  return headers;
}

/**
 * @brief Adds a custom HTTP header to the headers structure.
 *
 * @param headers A pointer to a `gvm_http_headers_t` structure.
 * @param header The header string to add (e.g., "Content-Type:
 * application/json").
 *
 * @return TRUE if the header was successfully added, FALSE otherwise.
 */
gboolean
gvm_http_add_header (gvm_http_headers_t *headers, const gchar *header)
{
  if (!headers || !header)
    return FALSE;

  struct curl_slist *result =
    curl_slist_append (headers->custom_headers, header);
  if (!result)
    return FALSE;

  headers->custom_headers = result;
  return TRUE;
}

/**
 * @brief Frees memory associated with a gvm_http_headers_t structure.
 *
 * @param headers A pointer to the `gvm_http_headers_t` structure to free.
 *                Can be NULL.
 */
void
gvm_http_headers_free (gvm_http_headers_t *headers)
{
  if (!headers)
    return;

  if (headers->custom_headers)
    curl_slist_free_all (headers->custom_headers);

  g_free (headers);
}

/**
 * @brief Initializes a multi-handle for managing concurrent HTTP(S) requests.
 *
 * @return A pointer to the newly allocated `gvm_http_multi_t` structure,
 *         or NULL if initialization fails.
 */
gvm_http_multi_t *
gvm_http_multi_new ()
{
  gvm_http_multi_t *multi = g_try_malloc0 (sizeof (gvm_http_multi_t));
  gvm_http_multi_internal_t *internal;

  if (!multi)
    return NULL;
  internal = g_try_malloc0 (sizeof (gvm_http_multi_internal_t));
  if (!internal)
    {
      g_free (multi);
      return NULL;
    }
  internal->curl = curl_multi_init ();
  multi->handler = internal;
  multi->headers = gvm_http_headers_new ();
  if (!internal->curl || !multi->headers)
    {
      if (internal->curl)
        curl_multi_cleanup (internal->curl);
      gvm_http_headers_free (multi->headers);
      g_free (internal);
      g_free (multi);
      return NULL;
    }

  return multi;
}

static gvm_http_multi_internal_t *
multi_internal (gvm_http_multi_t *multi)
{
  return multi ? (gvm_http_multi_internal_t *) multi->handler : NULL;
}

static gvm_http_request_node_t **
multi_request_link (gvm_http_multi_internal_t *internal, gvm_http_t *http)
{
  gvm_http_request_node_t **link;

  if (!internal)
    return NULL;
  for (link = &internal->requests; *link; link = &(*link)->next)
    if ((*link)->http == http)
      return link;
  return NULL;
}

static gvm_http_request_node_t **
multi_request_link_for_easy (gvm_http_multi_internal_t *internal, CURL *easy)
{
  gvm_http_request_node_t **link;

  if (!internal)
    return NULL;
  for (link = &internal->requests; *link; link = &(*link)->next)
    if ((*link)->http && (*link)->http->handler == easy)
      return link;
  return NULL;
}

static gboolean
multi_process_messages (gvm_http_multi_internal_t *internal)
{
  gboolean failed = FALSE;
  int queued = 0;
  CURLMsg *message;

  while ((message = curl_multi_info_read (internal->curl, &queued)))
    {
      gvm_http_request_node_t **link;
      gvm_http_request_node_t *node;
      gvm_http_request_context_t *context;

      if (message->msg != CURLMSG_DONE)
        {
          failed = TRUE;
          continue;
        }
      link = multi_request_link_for_easy (internal, message->easy_handle);
      if (!link)
        {
          gvm_http_request_context_t *untracked_context = NULL;
          failed = TRUE;
          curl_multi_remove_handle (internal->curl, message->easy_handle);
          if (curl_easy_getinfo (message->easy_handle, CURLINFO_PRIVATE,
                                 &untracked_context)
                == CURLE_OK
              && untracked_context && untracked_context->owner
              && untracked_context->owner->handler == message->easy_handle)
            gvm_http_free (untracked_context->owner);
          else
            curl_easy_cleanup (message->easy_handle);
          continue;
        }

      node = *link;
      *link = node->next;
      context = request_context_from_http (node->http);
      if (message->data.result != CURLE_OK || !context || context->failed)
        {
          discard_response_data (context);
          failed = TRUE;
        }
      curl_multi_remove_handle (internal->curl, node->http->handler);
      gvm_http_free (node->http);
      g_free (node);
    }
  return failed;
}

/**
 * @brief Adds an HTTP request (easy handle) to a multi-handle session.
 *
 * @param multi The multi-handle session to add the request to.
 * @param http The HTTP request (easy handle wrapper) to add.
 *
 * @return A `gvm_http_multi_result_t` indicating the result of the operation.
 */
gvm_http_multi_result_t
gvm_http_multi_add_handler (gvm_http_multi_t *multi, gvm_http_t *http)
{
  gvm_http_multi_internal_t *internal = multi_internal (multi);
  gvm_http_request_node_t *node;
  CURLMcode result;

  if (!internal || !internal->curl || !http || !http->handler)
    return GVM_HTTP_MULTI_BAD_HANDLE;

  node = g_try_malloc0 (sizeof (gvm_http_request_node_t));
  if (!node)
    return GVM_HTTP_MULTI_FAILED;
  result = curl_multi_add_handle (internal->curl, http->handler);

  switch (result)
    {
    case CURLM_OK:
      node->http = http;
      node->next = internal->requests;
      internal->requests = node;
      return GVM_HTTP_OK;
    case CURLM_BAD_HANDLE:
      g_free (node);
      return GVM_HTTP_MULTI_BAD_HANDLE;
    case CURLM_INTERNAL_ERROR:
      g_free (node);
      return GVM_HTTP_MULTI_FAILED;
    default:
      g_free (node);
      return GVM_HTTP_MULTI_UNKNOWN_ERROR;
    }
}

/**
 * @brief Executes all pending transfers in the given multi-handle session.
 *
 * @param multi Pointer to the multi-handle wrapper structure.
 * @param running_handles Pointer to an integer to store the count of ongoing
 * transfers.
 *
 * @return A `gvm_http_multi_result_t` value indicating the status of the
 * operation.
 *         - GVM_HTTP_OK: Success.
 *         - GVM_HTTP_MULTI_BAD_HANDLE: Invalid or NULL multi-handle.
 *         - GVM_HTTP_MULTI_FAILED: Other failure occurred.
 */
gvm_http_multi_result_t
gvm_http_multi_perform (gvm_http_multi_t *multi, int *running_handles)
{
  gvm_http_multi_internal_t *internal = multi_internal (multi);
  CURLMcode result;

  if (!internal || !internal->curl || !running_handles)
    return GVM_HTTP_MULTI_BAD_HANDLE;

  result = curl_multi_perform (internal->curl, running_handles);
  if (result == CURLM_OK && multi_process_messages (internal))
    return GVM_HTTP_MULTI_FAILED;
  switch (result)
    {
    case CURLM_OK:
      return GVM_HTTP_OK;
    case CURLM_BAD_HANDLE:
      return GVM_HTTP_MULTI_BAD_HANDLE;
    default:
      return GVM_HTTP_MULTI_FAILED;
    }
}

/**
 * @brief Polls the multi-handle for activity, waiting up to the specified
 * timeout.
 *
 * @param multi Pointer to the `gvm_http_multi_t` structure containing the
 * multi-handle.
 * @param timeout Maximum time in milliseconds to wait for activity.
 *
 * @return A `gvm_http_multi_result_t` indicating the result of the poll
 * operation:
 *         - GVM_HTTP_OK: Polling succeeded.
 *         - GVM_HTTP_MULTI_BAD_HANDLE: Invalid or NULL multi-handle.
 *         - GVM_HTTP_MULTI_FAILED: Polling failed due to an error.
 */
gvm_http_multi_result_t
gvm_http_multi_poll (gvm_http_multi_t *multi, int timeout)
{
  gvm_http_multi_internal_t *internal = multi_internal (multi);

  if (!internal || !internal->curl)
    return GVM_HTTP_MULTI_BAD_HANDLE;

  CURLMcode poll_result =
    curl_multi_poll (internal->curl, NULL, 0, timeout, NULL);
  switch (poll_result)
    {
    case CURLM_OK:
      return GVM_HTTP_OK;
    case CURLM_BAD_HANDLE:
      return GVM_HTTP_MULTI_BAD_HANDLE;
    default:
      return GVM_HTTP_MULTI_FAILED;
    }
}

/**
 * @brief Removes a gvm_http_t handler from a multi-handle and frees its
 * resources.
 *
 * @param multi Pointer to the `gvm_http_multi_t` multi-handle session.
 * @param http Pointer to the `gvm_http_t` object to remove and free.
 */
void
gvm_http_multi_handler_free (gvm_http_multi_t *multi, gvm_http_t *http)
{
  gvm_http_multi_internal_t *internal = multi_internal (multi);
  gvm_http_request_node_t **link;

  if (!internal || !internal->curl || !http || !http->handler)
    {
      g_warning ("%s: Invalid multi-handle or http handle", __func__);
      return;
    }

  link = multi_request_link (internal, http);
  if (link)
    {
      gvm_http_request_node_t *node = *link;
      *link = node->next;
      g_free (node);
      curl_multi_remove_handle (internal->curl, http->handler);
    }
  gvm_http_free (http);
}

/**
 * @brief Cleans up a CURL multi-handle session and its associated resources.
 *
 * @param multi The multi-handle wrapper to clean up. If NULL or uninitialized,
 *        the function returns safely without performing any cleanup.
 */
void
gvm_http_multi_free (gvm_http_multi_t *multi)
{
  gvm_http_multi_internal_t *internal;

  if (!multi)
    return;

  internal = multi_internal (multi);
  if (internal)
    {
      while (internal->requests)
        {
          gvm_http_request_node_t *node = internal->requests;
          gvm_http_request_context_t *context =
            request_context_from_http (node->http);
          internal->requests = node->next;
          discard_response_data (context);
          if (internal->curl && node->http && node->http->handler)
            curl_multi_remove_handle (internal->curl, node->http->handler);
          gvm_http_free (node->http);
          g_free (node);
        }
      if (internal->curl)
        curl_multi_cleanup (internal->curl);
      g_free (internal);
      multi->handler = NULL;
    }

  if (multi->headers)
    {
      gvm_http_headers_free (multi->headers);
      multi->headers = NULL;
    }

  g_free (multi);
}

/** @brief Reinitialize the string struct to hold the response
 *
 *  @param s The string struct to be reset
 */
void
gvm_http_response_stream_reset (gvm_http_response_stream_t s)
{
  if (s)
    {
      g_free (s->data);
      s->length = 0;
      s->data = g_try_malloc0 (1);
    }
}
