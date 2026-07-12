/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "httputils.c"

#include <arpa/inet.h>
#include <cgreen/cgreen.h>
#include <curl/curl.h>
#include <glib/gstdio.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct
{
  int socket_fd;
  const gchar *response;
  gsize response_length;
  gchar request[4096];
  gsize request_length;
  guint delay_before_close_ms;
  GThread *thread;
} loopback_server_t;

static gpointer
serve_one_request (gpointer userdata);

static void
loopback_server_join (loopback_server_t *server);

static gboolean
send_all (int socket_fd, const gchar *data, gsize length)
{
  gsize sent = 0;

  while (sent < length)
    {
      ssize_t result =
        send (socket_fd, data + sent, length - sent, MSG_NOSIGNAL);
      if (result <= 0)
        return FALSE;
      sent += result;
    }
  return TRUE;
}

static gvm_http_response_t *
unix_socket_request (loopback_server_t *server, const gchar *wire_response,
                     gsize wire_response_length)
{
  struct sockaddr_un address = {0};
  GError *error = NULL;
  gchar *directory = g_dir_make_tmp ("httputils-unix-XXXXXX", &error);
  gchar *socket_path;
  gvm_http_response_t *response = NULL;

  g_clear_error (&error);
  if (!directory)
    return NULL;
  socket_path = g_build_filename (directory, "http.sock", NULL);
  if (strlen (socket_path) >= sizeof (address.sun_path))
    goto cleanup;

  memset (server, 0, sizeof (*server));
  server->socket_fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (server->socket_fd < 0)
    goto cleanup;
  address.sun_family = AF_UNIX;
  g_strlcpy (address.sun_path, socket_path, sizeof (address.sun_path));
  if (bind (server->socket_fd, (struct sockaddr *) &address, sizeof (address))
        != 0
      || listen (server->socket_fd, 1) != 0)
    {
      close (server->socket_fd);
      goto cleanup;
    }

  server->response = wire_response;
  server->response_length = wire_response_length;
  server->thread = g_thread_new ("httputils-unix", serve_one_request, server);
  if (!server->thread)
    {
      close (server->socket_fd);
      goto cleanup;
    }

  response = gvm_http_request_unix ("http://localhost/", GET, NULL, NULL, NULL,
                                    NULL, NULL, socket_path, NULL);
  loopback_server_join (server);

cleanup:
  g_unlink (socket_path);
  g_rmdir (directory);
  g_free (socket_path);
  g_free (directory);
  return response;
}

static gpointer
serve_one_request (gpointer userdata)
{
  loopback_server_t *server = userdata;
  int client_fd = accept (server->socket_fd, NULL, NULL);

  if (client_fd >= 0)
    {
      while (server->request_length < sizeof (server->request) - 1)
        {
          ssize_t received =
            recv (client_fd, server->request + server->request_length,
                  sizeof (server->request) - 1 - server->request_length, 0);
          if (received <= 0)
            break;
          server->request_length += received;
          server->request[server->request_length] = '\0';
          if (strstr (server->request, "\r\n\r\n"))
            break;
        }
      send_all (client_fd, server->response, server->response_length);
      if (server->delay_before_close_ms > 0)
        g_usleep ((gulong) server->delay_before_close_ms * 1000);
      close (client_fd);
    }
  close (server->socket_fd);
  return NULL;
}

static gboolean
loopback_server_start_delayed (loopback_server_t *server, const gchar *response,
                               gsize response_length,
                               guint delay_before_close_ms, guint16 *port)
{
  struct sockaddr_in address = {0};
  socklen_t address_length = sizeof (address);

  memset (server, 0, sizeof (*server));
  server->socket_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (server->socket_fd < 0)
    return FALSE;

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (server->socket_fd, (struct sockaddr *) &address, sizeof (address))
        != 0
      || listen (server->socket_fd, 1) != 0
      || getsockname (server->socket_fd, (struct sockaddr *) &address,
                      &address_length)
           != 0)
    {
      close (server->socket_fd);
      return FALSE;
    }

  server->response = response;
  server->response_length = response_length;
  server->delay_before_close_ms = delay_before_close_ms;
  *port = ntohs (address.sin_port);
  server->thread =
    g_thread_new ("httputils-loopback", serve_one_request, server);
  return server->thread != NULL;
}

static gboolean
loopback_server_start (loopback_server_t *server, const gchar *response,
                       gsize response_length, guint16 *port)
{
  return loopback_server_start_delayed (server, response, response_length, 0,
                                        port);
}

static void
loopback_server_join (loopback_server_t *server)
{
  if (server->thread)
    g_thread_join (server->thread);
}

static gvm_http_response_t *
loopback_request (loopback_server_t *server, const gchar *wire_response,
                  gsize wire_response_length, gvm_http_method_t method,
                  const gchar *payload, gvm_http_response_stream_t stream)
{
  guint16 port;
  gchar *url;
  gvm_http_response_t *response;

  if (!loopback_server_start (server, wire_response, wire_response_length,
                              &port))
    return NULL;
  url = g_strdup_printf ("http://127.0.0.1:%u/", port);
  response =
    gvm_http_request (url, method, payload, NULL, NULL, NULL, NULL, stream);
  g_free (url);
  loopback_server_join (server);
  return response;
}

static gboolean
reserve_loopback_port (guint16 *port)
{
  struct sockaddr_in address = {0};
  socklen_t address_length = sizeof (address);
  int socket_fd = socket (AF_INET, SOCK_STREAM, 0);

  if (socket_fd < 0)
    return FALSE;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (socket_fd, (struct sockaddr *) &address, sizeof (address)) != 0
      || getsockname (socket_fd, (struct sockaddr *) &address, &address_length)
           != 0)
    {
      close (socket_fd);
      return FALSE;
    }
  *port = ntohs (address.sin_port);
  close (socket_fd);
  return TRUE;
}

static gvm_http_multi_result_t
loopback_multi_request (loopback_server_t *server, const gchar *wire_response,
                        gsize wire_response_length, guint delay_before_close_ms,
                        const gvm_http_policy_t *policy,
                        gvm_http_response_stream_t stream)
{
  guint16 port;
  gchar *url;
  gvm_http_t *http;
  gvm_http_multi_t *multi;
  gvm_http_multi_result_t result;
  int running = 0;

  if (!loopback_server_start_delayed (server, wire_response,
                                      wire_response_length,
                                      delay_before_close_ms, &port))
    return GVM_HTTP_MULTI_FAILED;
  url = g_strdup_printf ("http://127.0.0.1:%u/", port);
  http = gvm_http_new_internal (url, GET, NULL, NULL, NULL, NULL, NULL, NULL,
                                stream, policy);
  g_free (url);
  multi = gvm_http_multi_new ();
  if (!http || !multi)
    {
      gvm_http_free (http);
      gvm_http_multi_free (multi);
      loopback_server_join (server);
      return GVM_HTTP_MULTI_FAILED;
    }
  result = gvm_http_multi_add_handler (multi, http);
  while (result == GVM_HTTP_OK)
    {
      result = gvm_http_multi_perform (multi, &running);
      if (result != GVM_HTTP_OK || running == 0)
        break;
      result = gvm_http_multi_poll (multi, 100);
    }
  loopback_server_join (server);
  gvm_http_multi_free (multi);
  return result;
}

static gboolean
credential_fd_is_anonymous (int fd)
{
  gchar descriptor_path[64];
  gchar *target;
  gboolean anonymous;

  if (!credential_descriptor_path (fd, descriptor_path,
                                   sizeof (descriptor_path)))
    return FALSE;
  target = g_file_read_link (descriptor_path, NULL);
  if (!target)
    return FALSE;
  anonymous = g_str_has_suffix (target, " (deleted)");
  g_free (target);
  return anonymous;
}

Describe (gvm_http);

BeforeEach (gvm_http)
{
}

AfterEach (gvm_http)
{
}

Ensure (gvm_http, add_header_returns_true_and_contains_header)
{
  const gchar *test_header = "Content-Type: application/json";
  gvm_http_headers_t *headers = gvm_http_headers_new ();

  gboolean added = gvm_http_add_header (headers, test_header);

  assert_that (added, is_true);
  assert_that (headers->custom_headers, is_not_null);
  assert_that (headers->custom_headers->data, is_equal_to_string (test_header));

  gvm_http_headers_free (headers);
}

Ensure (gvm_http, cleanup_headers_handles_null_safely)
{
  gvm_http_headers_free (NULL);
  assert_that (true, is_true);
}

Ensure (gvm_http, headers_new_initializes_empty_list)
{
  gvm_http_headers_t *headers = gvm_http_headers_new ();
  assert_that (headers, is_not_null);
  assert_that (headers->custom_headers, is_null);
  gvm_http_headers_free (headers);
}

Ensure (gvm_http, multi_init_returns_valid_object)
{
  gvm_http_multi_t *multi = gvm_http_multi_new ();

  assert_that (multi, is_not_null);
  assert_that (multi->handler, is_not_null);
  assert_that (multi->headers, is_not_null);

  gvm_http_multi_free (multi);
}

Ensure (gvm_http, multi_add_handler_with_null_returns_bad_handle)
{
  gvm_http_multi_result_t result = gvm_http_multi_add_handler (NULL, NULL);
  assert_that (result, is_equal_to (GVM_HTTP_MULTI_BAD_HANDLE));
}

Ensure (gvm_http, multi_perform_with_null_returns_bad_handle)
{
  int running = 0;
  gvm_http_multi_result_t result = gvm_http_multi_perform (NULL, &running);
  assert_that (result, is_equal_to (GVM_HTTP_MULTI_BAD_HANDLE));
}

Ensure (gvm_http, multi_handler_free_does_not_crash_on_null)
{
  gvm_http_multi_handler_free (NULL, NULL);
  assert_that (true, is_true);
}

Ensure (gvm_http, response_free_does_not_crash)
{
  gvm_http_response_t *res = g_malloc0 (sizeof (gvm_http_response_t));
  res->data = g_strdup ("mock");
  res->size = 100;
  res->http_status = 200;

  gvm_http_response_free (res);

  assert_that (true, is_true);
}

Ensure (gvm_http, response_stream_free_handles_null)
{
  gvm_http_response_stream_free (NULL);
  assert_that (true, is_true);
}

Ensure (gvm_http, response_stream_free_handles_valid_stream)
{
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  assert_that (stream, is_not_null);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, response_callback_limit_is_cumulative_across_stream_resets)
{
  const gvm_http_policy_t small_policy = {
    1, 5, 1, 1, 10, GVM_HTTP_MAX_HEADER_SIZE,
  };
  const gchar body[] = "123456";
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_request_context_t *context =
    request_context_new (stream, &small_policy);

  assert_that (store_response_data ((void *) body, 1, 6, context),
               is_equal_to (6));
  gvm_http_response_stream_reset (stream);
  assert_that (store_response_data ((void *) body, 1, 5, context),
               is_equal_to (0));
  assert_that (context->failed, is_true);
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_null);

  request_context_free (context);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, response_callback_preserves_binary_data_and_sentinel)
{
  const gchar body[] = {'a', '\0', 'b'};
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_request_context_t *context =
    request_context_new (stream, &buffered_policy);

  assert_that (store_response_data ((void *) body, 1, sizeof (body), context),
               is_equal_to (sizeof (body)));
  assert_that (stream->length, is_equal_to (sizeof (body)));
  assert_that (memcmp (stream->data, body, sizeof (body)), is_equal_to (0));
  assert_that (stream->data[sizeof (body)], is_equal_to ('\0'));
  assert_that (context->failed, is_false);

  request_context_free (context);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, response_callback_rejects_overflow_without_partial_body)
{
  const gchar body[] = "partial";
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_request_context_t *context =
    request_context_new (stream, &buffered_policy);

  assert_that (
    store_response_data ((void *) body, 1, sizeof (body) - 1, context),
    is_equal_to (sizeof (body) - 1));
  assert_that (store_response_data ((void *) body, G_MAXSIZE, 2, context),
               is_equal_to (0));
  assert_that (context->failed, is_true);
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_null);

  request_context_free (context);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, response_callback_enforces_body_limit)
{
  const gchar byte = 'x';
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_request_context_t *context =
    request_context_new (stream, &buffered_policy);
  context->body_received = GVM_HTTP_MAX_BODY_SIZE;

  assert_that (store_response_data ((void *) &byte, 1, 1, context),
               is_equal_to (0));
  assert_that (context->failed, is_true);
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_null);

  request_context_free (context);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, header_callback_enforces_aggregate_limit)
{
  const gchar byte = 'x';
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_request_context_t *context =
    request_context_new (stream, &buffered_policy);

  assert_that (store_response_header ((void *) &byte, 1,
                                      GVM_HTTP_MAX_HEADER_SIZE, context),
               is_equal_to (GVM_HTTP_MAX_HEADER_SIZE));
  assert_that (store_response_header ((void *) &byte, 1, 1, context),
               is_equal_to (0));
  assert_that (context->failed, is_true);
  assert_that (context->header_length, is_equal_to (GVM_HTTP_MAX_HEADER_SIZE));

  request_context_free (context);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, method_names_are_independent_of_payload)
{
  assert_that (http_method_name (GET), is_equal_to_string ("GET"));
  assert_that (http_method_name (POST), is_equal_to_string ("POST"));
  assert_that (http_method_name (PUT), is_equal_to_string ("PUT"));
  assert_that (http_method_name (DELETE), is_equal_to_string ("DELETE"));
  assert_that (http_method_name (HEAD), is_equal_to_string ("HEAD"));
  assert_that (http_method_name (PATCH), is_equal_to_string ("PATCH"));
}

Ensure (gvm_http, management_transport_defaults_are_bounded)
{
  assert_that (GVM_HTTP_CONNECT_TIMEOUT_SECONDS, is_equal_to (10));
  assert_that (GVM_HTTP_TOTAL_TIMEOUT_SECONDS, is_equal_to (60));
  assert_that (GVM_HTTP_LOW_SPEED_LIMIT_BYTES, is_equal_to (1024));
  assert_that (GVM_HTTP_LOW_SPEED_TIME_SECONDS, is_equal_to (30));
  assert_that (GVM_HTTP_MAX_BODY_SIZE, is_equal_to (8 * 1024 * 1024));
  assert_that (GVM_HTTP_MAX_HEADER_SIZE, is_equal_to (64 * 1024));
  assert_that (GVM_HTTP_STREAM_TOTAL_TIMEOUT_SECONDS, is_equal_to (900));
  assert_that (GVM_HTTP_MAX_STREAM_SIZE, is_equal_to (512 * 1024 * 1024));
}

Ensure (gvm_http, public_request_and_stream_layouts_remain_stable)
{
  assert_that (sizeof (gvm_http_t), is_equal_to (sizeof (CURL *)));
  assert_that (sizeof (struct gvm_http_response_stream),
               is_equal_to (sizeof (gchar *) + sizeof (size_t)
                            + sizeof (gvm_http_multi_t *)));
}

Ensure (gvm_http, rejects_non_http_protocols)
{
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_t *http;

  http = gvm_http_new ("ftp://localhost/resource", GET, NULL, NULL, NULL, NULL,
                       NULL, stream);
  assert_that (http, is_null);
  http = gvm_http_new ("file:///etc/passwd", GET, NULL, NULL, NULL, NULL, NULL,
                       stream);
  assert_that (http, is_null);
  http = gvm_http_new ("http://localhost/", GET, NULL, NULL, NULL, NULL, NULL,
                       stream);
  assert_that (http, is_not_null);
  gvm_http_free (http);

  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, rejects_empty_or_malformed_private_ca)
{
  const gchar malformed[] =
    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();

  assert_that (gvm_http_new ("https://localhost/", GET, NULL, NULL, "", NULL,
                             NULL, stream),
               is_null);
  assert_that (gvm_http_new ("https://localhost/", GET, NULL, NULL, malformed,
                             NULL, NULL, stream),
               is_null);

  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, rejects_incomplete_or_empty_client_credential_pairs)
{
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();

  assert_that (gvm_http_new ("https://localhost/", GET, NULL, NULL, NULL,
                             "certificate", NULL, stream),
               is_null);
  assert_that (gvm_http_new ("https://localhost/", GET, NULL, NULL, NULL, NULL,
                             "key", stream),
               is_null);
  assert_that (
    gvm_http_new ("https://localhost/", GET, NULL, NULL, NULL, "", "", stream),
    is_null);

  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, loopback_preserves_binary_non_2xx_response)
{
  static const gchar wire_response[] = {
    "HTTP/1.1 418 Teapot\r\nContent-Length: 3\r\n\r\na\0b"};
  const gchar expected[] = {'a', '\0', 'b'};
  loopback_server_t server;
  gvm_http_response_t *response = loopback_request (
    &server, wire_response, sizeof (wire_response) - 1, GET, NULL, NULL);

  assert_that (response, is_not_null);
  assert_that (response->http_status, is_equal_to (418));
  assert_that (response->size, is_equal_to (sizeof (expected)));
  assert_that (memcmp (response->data, expected, sizeof (expected)),
               is_equal_to (0));
  assert_that (response->data[response->size], is_equal_to ('\0'));

  gvm_http_response_free (response);
}

Ensure (gvm_http, streaming_multi_accepts_feed_body_larger_than_buffer_limit)
{
  const gsize body_length = GVM_HTTP_MAX_BODY_SIZE + 1024 * 1024;
  gchar *body = g_malloc (body_length);
  GString *wire_response;
  loopback_server_t server;
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_multi_result_t result;

  memset (body, 'v', body_length);
  wire_response = g_string_new (NULL);
  g_string_append_printf (wire_response,
                          "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n",
                          body_length);
  g_string_append_len (wire_response, body, body_length);
  result =
    loopback_multi_request (&server, wire_response->str, wire_response->len, 0,
                            &streaming_policy, stream);

  assert_that (result, is_equal_to (GVM_HTTP_OK));
  assert_that (stream->length, is_equal_to (body_length));
  assert_that (stream->data[0], is_equal_to ('v'));
  assert_that (stream->data[body_length - 1], is_equal_to ('v'));
  assert_that (stream->data[body_length], is_equal_to ('\0'));

  g_string_free (wire_response, TRUE);
  g_free (body);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, streaming_multi_rejects_oversized_content_length)
{
  gchar wire_response[160];
  loopback_server_t server;
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();

  g_snprintf (wire_response, sizeof (wire_response),
              "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n",
              GVM_HTTP_MAX_STREAM_SIZE + 1);
  assert_that (loopback_multi_request (&server, wire_response,
                                       strlen (wire_response), 0,
                                       &streaming_policy, stream),
               is_equal_to (GVM_HTTP_MULTI_FAILED));
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_null);

  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, streaming_multi_rejects_chunked_body_over_cumulative_limit)
{
  const gvm_http_policy_t small_streaming_policy = {
    1, 5, 1024, 1, 1024, GVM_HTTP_MAX_HEADER_SIZE,
  };
  gchar body[2048];
  GString *wire_response =
    g_string_new ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                  "800\r\n");
  loopback_server_t server;
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();

  memset (body, 'x', sizeof (body));
  g_string_append_len (wire_response, body, sizeof (body));
  g_string_append (wire_response, "\r\n0\r\n\r\n");
  assert_that (loopback_multi_request (&server, wire_response->str,
                                       wire_response->len, 0,
                                       &small_streaming_policy, stream),
               is_equal_to (GVM_HTTP_MULTI_FAILED));
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_null);

  g_string_free (wire_response, TRUE);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, streaming_multi_propagates_total_timeout)
{
  const gvm_http_policy_t timeout_policy = {
    1, 1, 1024, 30, 1024, GVM_HTTP_MAX_HEADER_SIZE,
  };
  static const gchar wire_response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n";
  loopback_server_t server;
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();

  assert_that (loopback_multi_request (&server, wire_response,
                                       sizeof (wire_response) - 1, 1500,
                                       &timeout_policy, stream),
               is_equal_to (GVM_HTTP_MULTI_FAILED));
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_null);

  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, streaming_multi_propagates_low_speed_timeout)
{
  const gvm_http_policy_t low_speed_policy = {
    1, 5, 1024, 1, 8192, GVM_HTTP_MAX_HEADER_SIZE,
  };
  static const gchar wire_response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nx";
  loopback_server_t server;
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();

  assert_that (loopback_multi_request (&server, wire_response,
                                       sizeof (wire_response) - 1, 1500,
                                       &low_speed_policy, stream),
               is_equal_to (GVM_HTTP_MULTI_FAILED));
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_null);

  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, unix_socket_http_remains_supported)
{
  static const gchar wire_response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nunix";
  loopback_server_t server;
  gvm_http_response_t *response =
    unix_socket_request (&server, wire_response, sizeof (wire_response) - 1);

  assert_that (response, is_not_null);
  assert_that (response->http_status, is_equal_to (200));
  assert_that (response->size, is_equal_to (4));
  assert_that (response->data, is_equal_to_string ("unix"));

  gvm_http_response_free (response);
}

Ensure (gvm_http, loopback_rejects_oversized_aggregate_headers)
{
  loopback_server_t server;
  GString *wire_response = g_string_new ("HTTP/1.1 200 OK\r\nX-Oversized: ");
  gvm_http_response_t *response;

  while (wire_response->len <= GVM_HTTP_MAX_HEADER_SIZE)
    g_string_append_c (wire_response, 'x');
  g_string_append (wire_response, "\r\nContent-Length: 0\r\n\r\n");
  response = loopback_request (&server, wire_response->str, wire_response->len,
                               GET, NULL, NULL);

  assert_that (response, is_not_null);
  assert_that (response->http_status, is_equal_to (-1));

  gvm_http_response_free (response);
  g_string_free (wire_response, TRUE);
}

Ensure (gvm_http, loopback_tls_uses_system_or_explicit_trust_and_checks_host)
{
  gchar *openssl = g_find_program_in_path ("openssl");
  GError *error = NULL;
  gchar *directory = g_dir_make_tmp ("httputils-tls-XXXXXX", &error);
  gchar *certificate_path;
  gchar *key_path;
  gchar *certificate = NULL;
  gchar *key = NULL;
  gchar *port_string;
  gchar *listen_address;
  gchar *localhost_url;
  gchar *address_url;
  gint command_status = 0;
  guint16 port = 0;
  GPid server_pid = 0;
  gvm_http_response_t *untrusted = NULL;
  gvm_http_response_t *wrong_host = NULL;
  gvm_http_response_t *trusted = NULL;
  gvm_http_response_t *missing_client = NULL;
  gboolean generated;
  gboolean spawned;

  assert_that (openssl, is_not_null);
  assert_that (directory, is_not_null);
  if (!openssl || !directory)
    {
      g_clear_error (&error);
      g_free (openssl);
      g_free (directory);
      return;
    }

  certificate_path = g_build_filename (directory, "certificate.pem", NULL);
  key_path = g_build_filename (directory, "key.pem", NULL);
  gchar *generate_argv[] = {
    openssl,
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-sha256",
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-keyout",
    key_path,
    "-out",
    certificate_path,
    NULL,
  };
  generated =
    g_spawn_sync (NULL, generate_argv, NULL,
                  G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL, NULL,
                  NULL, NULL, NULL, &command_status, &error);
  generated =
    generated && g_spawn_check_wait_status (command_status, &error)
    && g_file_get_contents (certificate_path, &certificate, NULL, &error)
    && g_file_get_contents (key_path, &key, NULL, &error)
    && reserve_loopback_port (&port);
  assert_that (generated, is_true);

  port_string = g_strdup_printf ("%u", port);
  listen_address = g_strdup_printf ("127.0.0.1:%u", port);
  localhost_url = g_strdup_printf ("https://localhost:%u/", port);
  address_url = g_strdup_printf ("https://127.0.0.1:%u/", port);
  gchar *server_argv[] = {
    openssl,          "s_server", "-quiet", "-accept", listen_address, "-cert",
    certificate_path, "-key",     key_path, "-www",    NULL,
  };
  spawned =
    generated
    && g_spawn_async (NULL, server_argv, NULL,
                      G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDOUT_TO_DEV_NULL
                        | G_SPAWN_STDERR_TO_DEV_NULL,
                      NULL, NULL, &server_pid, &error);
  assert_that (spawned, is_true);

  if (spawned)
    {
      g_usleep (250000);
      untrusted = gvm_http_request (localhost_url, GET, NULL, NULL, NULL, NULL,
                                    NULL, NULL);
      wrong_host = gvm_http_request (address_url, GET, NULL, NULL, certificate,
                                     NULL, NULL, NULL);
      trusted = gvm_http_request (localhost_url, GET, NULL, NULL, certificate,
                                  NULL, NULL, NULL);
      kill (server_pid, SIGTERM);
      waitpid (server_pid, NULL, 0);
      g_spawn_close_pid (server_pid);
    }

  assert_that (untrusted, is_not_null);
  assert_that (untrusted ? untrusted->http_status : 0, is_equal_to (-1));
  assert_that (wrong_host, is_not_null);
  assert_that (wrong_host ? wrong_host->http_status : 0, is_equal_to (-1));
  assert_that (trusted, is_not_null);
  assert_that (trusted ? trusted->http_status : 0, is_equal_to (200));
  gvm_http_request_context_t *trusted_context =
    trusted ? request_context_from_http (trusted->http) : NULL;
  int trusted_ca_fd = trusted_context ? trusted_context->ca_fd : -1;
  struct stat credential_stat;
  assert_that (trusted_ca_fd >= 0, is_true);
  assert_that (fstat (trusted_ca_fd, &credential_stat), is_equal_to (0));
  assert_that (credential_stat.st_mode & 0777, is_equal_to (0600));
  assert_that (credential_fd_is_anonymous (trusted_ca_fd), is_true);

  gvm_http_response_free (untrusted);
  gvm_http_response_free (wrong_host);
  gvm_http_response_free (trusted);
  assert_that (fcntl (trusted_ca_fd, F_GETFD), is_equal_to (-1));

  g_clear_pointer (&listen_address, g_free);
  g_clear_pointer (&localhost_url, g_free);
  assert_that (reserve_loopback_port (&port), is_true);
  listen_address = g_strdup_printf ("127.0.0.1:%u", port);
  localhost_url = g_strdup_printf ("https://localhost:%u/", port);
  gchar *mtls_server_argv[] = {
    openssl,
    "s_server",
    "-quiet",
    "-accept",
    listen_address,
    "-cert",
    certificate_path,
    "-key",
    key_path,
    "-CAfile",
    certificate_path,
    "-Verify",
    "1",
    "-verify_return_error",
    "-www",
    NULL,
  };
  spawned =
    g_spawn_async (NULL, mtls_server_argv, NULL,
                   G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDOUT_TO_DEV_NULL
                     | G_SPAWN_STDERR_TO_DEV_NULL,
                   NULL, NULL, &server_pid, &error);
  assert_that (spawned, is_true);
  if (spawned)
    {
      g_usleep (250000);
      missing_client = gvm_http_request (localhost_url, GET, NULL, NULL,
                                         certificate, NULL, NULL, NULL);
      gvm_http_request_context_t *missing_context =
        request_context_from_http (missing_client->http);
      int missing_ca_fd = missing_context->ca_fd;
      assert_that (missing_client->http_status, is_equal_to (-1));
      gvm_http_response_free (missing_client);
      assert_that (fcntl (missing_ca_fd, F_GETFD), is_equal_to (-1));

      gvm_http_response_t *malformed_client =
        gvm_http_request (localhost_url, GET, NULL, NULL, certificate,
                          "not a certificate", "not a key", NULL);
      gvm_http_request_context_t *malformed_context =
        request_context_from_http (malformed_client->http);
      int malformed_fds[] = {
        malformed_context->ca_fd,
        malformed_context->client_cert_fd,
        malformed_context->client_key_fd,
      };
      assert_that (malformed_client->http_status, is_equal_to (-1));
      gvm_http_response_free (malformed_client);
      for (guint index = 0; index < G_N_ELEMENTS (malformed_fds); index++)
        assert_that (fcntl (malformed_fds[index], F_GETFD), is_equal_to (-1));

      gvm_http_response_stream_t mtls_stream = gvm_http_response_stream_new ();
      gvm_http_t *mtls_http =
        gvm_http_new_streaming (localhost_url, GET, NULL, NULL, certificate,
                                certificate, key, mtls_stream);
      gvm_http_request_context_t *mtls_context =
        request_context_from_http (mtls_http);
      int mtls_fds[] = {mtls_context->ca_fd, mtls_context->client_cert_fd,
                        mtls_context->client_key_fd};
      gvm_http_multi_t *mtls_multi = gvm_http_multi_new ();
      int running = 0;
      gvm_http_multi_result_t multi_result =
        gvm_http_multi_add_handler (mtls_multi, mtls_http);

      for (guint index = 0; index < G_N_ELEMENTS (mtls_fds); index++)
        {
          assert_that (fstat (mtls_fds[index], &credential_stat),
                       is_equal_to (0));
          assert_that (credential_stat.st_mode & 0777, is_equal_to (0600));
          assert_that (credential_fd_is_anonymous (mtls_fds[index]), is_true);
        }
      while (multi_result == GVM_HTTP_OK)
        {
          multi_result = gvm_http_multi_perform (mtls_multi, &running);
          if (multi_result != GVM_HTTP_OK || running == 0)
            break;
          multi_result = gvm_http_multi_poll (mtls_multi, 100);
        }
      assert_that (multi_result, is_equal_to (GVM_HTTP_OK));
      assert_that (mtls_stream->length > 0, is_true);
      for (guint index = 0; index < G_N_ELEMENTS (mtls_fds); index++)
        assert_that (fcntl (mtls_fds[index], F_GETFD), is_equal_to (-1));
      gvm_http_multi_free (mtls_multi);
      gvm_http_response_stream_free (mtls_stream);

      kill (server_pid, SIGTERM);
      waitpid (server_pid, NULL, 0);
      g_spawn_close_pid (server_pid);
    }

  gvm_http_response_stream_t cancel_stream = gvm_http_response_stream_new ();
  gvm_http_t *cancel_http =
    gvm_http_new_streaming ("https://localhost:1/", GET, NULL, NULL,
                            certificate, certificate, key, cancel_stream);
  gvm_http_request_context_t *cancel_context =
    request_context_from_http (cancel_http);
  int cancel_fds[] = {cancel_context->ca_fd, cancel_context->client_cert_fd,
                      cancel_context->client_key_fd};
  gvm_http_multi_t *cancel_multi = gvm_http_multi_new ();
  assert_that (gvm_http_multi_add_handler (cancel_multi, cancel_http),
               is_equal_to (GVM_HTTP_OK));
  gvm_http_multi_free (cancel_multi);
  for (guint index = 0; index < G_N_ELEMENTS (cancel_fds); index++)
    assert_that (fcntl (cancel_fds[index], F_GETFD), is_equal_to (-1));
  assert_that (cancel_stream->length, is_equal_to (0));
  assert_that (cancel_stream->data, is_null);
  gvm_http_response_stream_free (cancel_stream);

  g_clear_error (&error);
  g_free (port_string);
  g_free (listen_address);
  g_free (localhost_url);
  g_free (address_url);
  g_free (certificate);
  g_free (key);
  g_remove (certificate_path);
  g_remove (key_path);
  g_rmdir (directory);
  g_free (certificate_path);
  g_free (key_path);
  g_free (directory);
  g_free (openssl);
}

Ensure (gvm_http, loopback_keeps_empty_body_methods_and_head_has_no_body)
{
  static const gchar wire_response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
  const gvm_http_method_t methods[] = {POST, PUT, PATCH, HEAD};
  const gchar *names[] = {"POST ", "PUT ", "PATCH ", "HEAD "};
  guint index;

  for (index = 0; index < G_N_ELEMENTS (methods); index++)
    {
      loopback_server_t server;
      gvm_http_response_t *response =
        loopback_request (&server, wire_response, sizeof (wire_response) - 1,
                          methods[index], "", NULL);

      assert_that (response, is_not_null);
      assert_that (g_str_has_prefix (server.request, names[index]), is_true);
      if (methods[index] == HEAD)
        assert_that (response->size, is_equal_to (0));
      gvm_http_response_free (response);
    }
}

Ensure (gvm_http, loopback_discards_partial_body_on_transport_failure)
{
  static const gchar wire_response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial";
  loopback_server_t server;
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_response_t *response = loopback_request (
    &server, wire_response, sizeof (wire_response) - 1, GET, NULL, stream);

  assert_that (response, is_not_null);
  assert_that (response->http_status, is_equal_to (-1));
  assert_that (request_context_from_http (response->http)->failed, is_true);
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_null);

  gvm_http_response_free (response);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, loopback_rejects_oversized_declared_body)
{
  static const gchar wire_response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n";
  loopback_server_t server;
  gvm_http_response_t *response = loopback_request (
    &server, wire_response, sizeof (wire_response) - 1, GET, NULL, NULL);

  assert_that (response, is_not_null);
  assert_that (response->http_status, is_equal_to (-1));

  gvm_http_response_free (response);
}

Ensure (gvm_http, response_stream_new_initializes_fields)
{
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  assert_that (stream, is_not_null);
  assert_that (stream->data, is_not_null);
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->multi_handler, is_not_null);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, http_new_returns_struct_with_valid_handler)
{
  CURL *curl = curl_easy_init ();
  assert_that (curl, is_not_null);
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_request_context_t *context =
    request_context_new (stream, &buffered_policy);

  gvm_http_t *http = gvm_http_t_new (curl, context);
  assert_that (http, is_not_null);
  assert_that (http->handler, is_equal_to (curl));

  gvm_http_free (http);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, http_new_returns_null_when_passed_null)
{
  gvm_http_t *http = gvm_http_t_new (NULL, NULL);
  assert_that (http, is_null);
}

Ensure (gvm_http, http_free_handles_null_safely)
{
  gvm_http_free (NULL);
  assert_that (true, is_true);
}

Ensure (gvm_http, http_free_frees_allocated_struct)
{
  CURL *curl = curl_easy_init ();
  assert_that (curl, is_not_null);
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  gvm_http_request_context_t *context =
    request_context_new (stream, &buffered_policy);

  gvm_http_t *http = gvm_http_t_new (curl, context);
  assert_that (http, is_not_null);
  assert_that (http->handler, is_equal_to (curl));

  gvm_http_free (http);
  gvm_http_response_stream_free (stream);
  // Cannot assert post-free directly, but reaching here means no crash
  assert_that (true, is_true);
}

Ensure (gvm_http, response_stream_reset_frees_and_resets_data)
{
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  assert_that (stream, is_not_null);

  g_free (stream->data);
  stream->data = g_strdup ("mock response");
  stream->length = strlen (stream->data);

  gvm_http_response_stream_reset (stream);

  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_not_null);
  assert_that (strlen (stream->data), is_equal_to (0));
  assert_that (stream->data[0], is_equal_to ('\0'));

  gvm_http_response_stream_free (stream);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gvm_http,
                         add_header_returns_true_and_contains_header);
  add_test_with_context (suite, gvm_http, cleanup_headers_handles_null_safely);
  add_test_with_context (suite, gvm_http, headers_new_initializes_empty_list);
  add_test_with_context (suite, gvm_http, multi_init_returns_valid_object);
  add_test_with_context (suite, gvm_http,
                         multi_add_handler_with_null_returns_bad_handle);
  add_test_with_context (suite, gvm_http,
                         multi_perform_with_null_returns_bad_handle);
  add_test_with_context (suite, gvm_http,
                         multi_handler_free_does_not_crash_on_null);
  add_test_with_context (suite, gvm_http, response_free_does_not_crash);
  add_test_with_context (suite, gvm_http, response_stream_free_handles_null);
  add_test_with_context (suite, gvm_http,
                         response_stream_free_handles_valid_stream);
  add_test_with_context (suite, gvm_http,
                         response_stream_new_initializes_fields);
  add_test_with_context (suite, gvm_http,
                         http_new_returns_struct_with_valid_handler);
  add_test_with_context (suite, gvm_http,
                         http_new_returns_null_when_passed_null);
  add_test_with_context (suite, gvm_http, http_free_handles_null_safely);
  add_test_with_context (suite, gvm_http, http_free_frees_allocated_struct);
  add_test_with_context (suite, gvm_http,
                         response_stream_reset_frees_and_resets_data);
  add_test_with_context (suite, gvm_http,
                         response_callback_preserves_binary_data_and_sentinel);
  add_test_with_context (
    suite, gvm_http, response_callback_rejects_overflow_without_partial_body);
  add_test_with_context (suite, gvm_http,
                         response_callback_enforces_body_limit);
  add_test_with_context (
    suite, gvm_http,
    response_callback_limit_is_cumulative_across_stream_resets);
  add_test_with_context (suite, gvm_http,
                         header_callback_enforces_aggregate_limit);
  add_test_with_context (suite, gvm_http,
                         method_names_are_independent_of_payload);
  add_test_with_context (suite, gvm_http,
                         management_transport_defaults_are_bounded);
  add_test_with_context (suite, gvm_http,
                         public_request_and_stream_layouts_remain_stable);
  add_test_with_context (suite, gvm_http, rejects_non_http_protocols);
  add_test_with_context (suite, gvm_http,
                         rejects_empty_or_malformed_private_ca);
  add_test_with_context (suite, gvm_http,
                         rejects_incomplete_or_empty_client_credential_pairs);
  add_test_with_context (suite, gvm_http,
                         loopback_preserves_binary_non_2xx_response);
  add_test_with_context (suite, gvm_http, unix_socket_http_remains_supported);
  add_test_with_context (
    suite, gvm_http, loopback_keeps_empty_body_methods_and_head_has_no_body);
  add_test_with_context (suite, gvm_http,
                         loopback_discards_partial_body_on_transport_failure);
  add_test_with_context (suite, gvm_http,
                         loopback_rejects_oversized_declared_body);
  add_test_with_context (
    suite, gvm_http,
    streaming_multi_accepts_feed_body_larger_than_buffer_limit);
  add_test_with_context (suite, gvm_http,
                         streaming_multi_rejects_oversized_content_length);
  add_test_with_context (
    suite, gvm_http,
    streaming_multi_rejects_chunked_body_over_cumulative_limit);
  add_test_with_context (suite, gvm_http,
                         streaming_multi_propagates_total_timeout);
  add_test_with_context (suite, gvm_http,
                         streaming_multi_propagates_low_speed_timeout);
  add_test_with_context (suite, gvm_http,
                         loopback_rejects_oversized_aggregate_headers);
  add_test_with_context (
    suite, gvm_http,
    loopback_tls_uses_system_or_explicit_trust_and_checks_host);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
