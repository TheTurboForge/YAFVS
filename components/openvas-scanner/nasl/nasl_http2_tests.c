/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

// clang-format off
#include "nasl_http2.c"
// clang-format on

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

  return g_test_run ();
}
