/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

// clang-format off
#include "nasl_http2.c"
// clang-format on

#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void
reset_handles (void)
{
  unsigned int slot;

  for (slot = 0; slot < MAX_HANDLES; slot++)
    destroy_handle (slot);
}

static struct handle_table_s *
test_handle (int handle_id)
{
  struct handle_table_s *entry = g_malloc0 (sizeof (*entry));

  entry->handle_id = handle_id;
  entry->handle = curl_easy_init ();
  g_assert_nonnull (entry->handle);
  return entry;
}

static void
test_find_handle_searches_sparse_table (void)
{
  struct handle_table_s *found;
  unsigned int slot = 0;

  reset_handles ();
  handle_table[2] = test_handle (9002);
  handle_table[7] = test_handle (9007);

  found = find_handle (9007, &slot);
  g_assert_true (found == handle_table[7]);
  g_assert_cmpuint (slot, ==, 7);
  g_assert_null (find_handle (9003, NULL));
  reset_handles ();
}

static void
test_destroy_handle_unregisters_owned_resources (void)
{
  reset_handles ();
  handle_table[4] = test_handle (9004);
  g_assert_cmpint (append_custom_header (handle_table[4], "X-One: 1"), ==,
                   CURLE_OK);
  g_assert_cmpint (append_custom_header (handle_table[4], "X-Two: 2"), ==,
                   CURLE_OK);

  destroy_handle (4);

  g_assert_null (handle_table[4]);
  g_assert_null (find_handle (9004, NULL));
}

static void
test_custom_headers_append_and_reapply_after_reset (void)
{
  struct handle_table_s *entry;

  reset_handles ();
  handle_table[1] = test_handle (9001);
  entry = handle_table[1];

  g_assert_cmpint (append_custom_header (entry, "X-One: 1"), ==, CURLE_OK);
  g_assert_cmpint (append_custom_header (entry, "X-Two: 2"), ==, CURLE_OK);
  g_assert_cmpstr (entry->custom_headers->data, ==, "X-One: 1");
  g_assert_cmpstr (entry->custom_headers->next->data, ==, "X-Two: 2");

  curl_easy_reset (entry->handle);
  g_assert_cmpint (apply_custom_headers (entry), ==, CURLE_OK);
  g_assert_cmpstr (entry->custom_headers->data, ==, "X-One: 1");
  g_assert_cmpstr (entry->custom_headers->next->data, ==, "X-Two: 2");
  reset_handles ();
}

static void
test_response_budget_is_shared_and_binary_safe (void)
{
  const unsigned char header_chunk[] = {'H', '\0', 'X'};
  const unsigned char body_chunk[] = {'B', '\0', 'Y'};
  const unsigned char expected[] = {'H', '\0', 'X', '\n', 'B', '\0', 'Y'};
  const unsigned char extra = '!';
  struct response_budget budget = {1, sizeof (expected)};
  struct string header = {0}, response = {0};
  unsigned char *complete;
  size_t complete_len = 0;

  g_assert_true (init_string (&header, &budget));
  g_assert_true (init_string (&response, &budget));
  g_assert_cmpuint (header_callback_fn ((char *) header_chunk, 1,
                                        sizeof (header_chunk), &header),
                    ==, sizeof (header_chunk));
  g_assert_cmpuint (response_callback_fn ((void *) body_chunk, 1,
                                          sizeof (body_chunk), &response),
                    ==, sizeof (body_chunk));
  g_assert_cmpuint (response_callback_fn ((void *) &extra, 1, 1, &response), ==,
                    0);

  complete = build_complete_response (&header, &response, &complete_len);
  g_assert_nonnull (complete);
  g_assert_cmpuint (complete_len, ==, sizeof (expected));
  g_assert_cmpmem (complete, complete_len, expected, sizeof (expected));
  g_assert_cmpuint (complete[complete_len], ==, '\0');

  g_free (complete);
  g_free (header.ptr);
  g_free (response.ptr);
}

static void
test_response_callback_rejects_size_overflow (void)
{
  const unsigned char byte = 1;
  struct response_budget budget = {1, HTTP2_RESPONSE_MAX_SIZE};
  struct string response = {0};

  g_assert_cmpuint (HTTP2_RESPONSE_MAX_SIZE, ==, 16U * 1024U * 1024U);
  g_assert_true (init_string (&response, &budget));
  g_assert_cmpuint (
    response_callback_fn ((void *) &byte, SIZE_MAX, 2, &response), ==, 0);
  g_assert_cmpuint (response.len, ==, 0);
  g_assert_cmpuint (budget.retained, ==, 1);

  g_free (response.ptr);
}

static void
assert_scoped_target (const char *schema, const char *hostname,
                      const char *target_ip, int port, const char *item,
                      const char *expected_url, const char *expected_connect_to)
{
  struct scoped_http2_target target = {0};

  g_assert_true (build_scoped_http2_target (schema, hostname, target_ip, port,
                                            item, &target));
  g_assert_nonnull (target.url);
  g_assert_nonnull (target.connect_to);
  g_assert_cmpstr (target.url->str, ==, expected_url);
  g_assert_cmpstr (target.connect_to->data, ==, expected_connect_to);
  g_assert_null (target.connect_to->next);
  scoped_http2_target_clear (&target);
}

static void
test_scoped_target_preserves_authority_and_pins_address (void)
{
  assert_scoped_target ("https", "app.example", "192.0.2.44", 8443,
                        "/status?full=1",
                        "https://app.example:8443/status?full=1",
                        "app.example:8443:192.0.2.44:8443");
  assert_scoped_target ("http", "app.example", "192.0.2.44", 80, "/",
                        "http://app.example/", "app.example:80:192.0.2.44:80");
  assert_scoped_target (NULL, "app.example", "2001:db8::44", 443, "/",
                        "https://app.example/",
                        "app.example:443:[2001:db8::44]:443");
  assert_scoped_target ("https", "2001:db8::55", "2001:db8::44", 9443, "/",
                        "https://[2001:db8::55]:9443/",
                        "[2001:db8::55]:9443:[2001:db8::44]:9443");
}

static void
test_scoped_target_rejects_authority_escape_inputs (void)
{
  struct scoped_http2_target target = {0};

  g_assert_false (build_scoped_http2_target ("file", "app.example",
                                             "192.0.2.44", 443, "/", &target));
  g_assert_false (build_scoped_http2_target ("https", "user@app.example",
                                             "192.0.2.44", 443, "/", &target));
  g_assert_false (build_scoped_http2_target ("https", "app.example/elsewhere",
                                             "192.0.2.44", 443, "/", &target));
  g_assert_false (build_scoped_http2_target (
    "https", "app.example", "192.0.2.44", 443, "https://elsewhere/", &target));
  g_assert_false (build_scoped_http2_target (
    "https", "app.example", "192.0.2.44", 443, "/line\nbreak", &target));
  g_assert_false (build_scoped_http2_target (
    "https", "app.example", "not-an-address", 443, "/", &target));
  g_assert_null (target.url);
  g_assert_null (target.connect_to);
}

static size_t
discard_response (void *data, size_t size, size_t nmemb, void *unused)
{
  (void) data;
  (void) unused;
  return size * nmemb;
}

static void
test_scoped_transport_reaches_only_pinned_loopback (void)
{
  const char response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
  struct scoped_http2_target target = {0};
  struct sockaddr_in address = {0};
  socklen_t address_length = sizeof (address);
  int listener;
  pid_t child;
  CURL *handle;
  CURLcode result;
  int child_status;

  listener = socket (AF_INET, SOCK_STREAM, 0);
  g_assert_cmpint (listener, >=, 0);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  address.sin_port = 0;
  g_assert_cmpint (
    bind (listener, (struct sockaddr *) &address, sizeof (address)), ==, 0);
  g_assert_cmpint (
    getsockname (listener, (struct sockaddr *) &address, &address_length), ==,
    0);
  g_assert_cmpint (listen (listener, 1), ==, 0);

  child = fork ();
  g_assert_cmpint (child, >=, 0);
  if (child == 0)
    {
      char request[4096] = {0};
      char expected_host[128];
      int client;
      ssize_t request_length;

      alarm (5);
      client = accept (listener, NULL, NULL);
      if (client < 0)
        _exit (2);
      request_length = read (client, request, sizeof (request) - 1);
      if (request_length <= 0)
        _exit (3);
      g_snprintf (expected_host, sizeof (expected_host),
                  "Host: unresolvable.invalid:%u",
                  (unsigned int) ntohs (address.sin_port));
      if (!strstr (request, expected_host))
        _exit (4);
      if (write (client, response, sizeof (response) - 1)
          != (ssize_t) sizeof (response) - 1)
        _exit (5);
      close (client);
      close (listener);
      _exit (0);
    }

  g_assert_true (
    build_scoped_http2_target ("http", "unresolvable.invalid", "127.0.0.1",
                               ntohs (address.sin_port), "/", &target));
  handle = curl_easy_init ();
  g_assert_nonnull (handle);
  g_assert_cmpint (configure_scoped_http2_transport (handle, &target), ==,
                   CURLE_OK);
  g_assert_cmpint (
    curl_easy_setopt (handle, CURLOPT_WRITEFUNCTION, discard_response), ==,
    CURLE_OK);
  g_assert_cmpint (curl_easy_setopt (handle, CURLOPT_TIMEOUT_MS, 3000L), ==,
                   CURLE_OK);
  result = curl_easy_perform (handle);
  if (result != CURLE_OK)
    kill (child, SIGKILL);
  g_assert_cmpint (waitpid (child, &child_status, 0), ==, child);
  g_assert_cmpint (result, ==, CURLE_OK);
  g_assert_true (WIFEXITED (child_status));
  g_assert_cmpint (WEXITSTATUS (child_status), ==, 0);

  curl_easy_cleanup (handle);
  scoped_http2_target_clear (&target);
  close (listener);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/nasl/http2/find-sparse",
                   test_find_handle_searches_sparse_table);
  g_test_add_func ("/nasl/http2/destroy-owned",
                   test_destroy_handle_unregisters_owned_resources);
  g_test_add_func ("/nasl/http2/custom-header-reset",
                   test_custom_headers_append_and_reapply_after_reset);
  g_test_add_func ("/nasl/http2/shared-binary-budget",
                   test_response_budget_is_shared_and_binary_safe);
  g_test_add_func ("/nasl/http2/size-overflow",
                   test_response_callback_rejects_size_overflow);
  g_test_add_func ("/nasl/http2/scoped-target",
                   test_scoped_target_preserves_authority_and_pins_address);
  g_test_add_func ("/nasl/http2/reject-authority-escape",
                   test_scoped_target_rejects_authority_escape_inputs);
  g_test_add_func ("/nasl/http2/pinned-loopback",
                   test_scoped_transport_reaches_only_pinned_loopback);

  return g_test_run ();
}
