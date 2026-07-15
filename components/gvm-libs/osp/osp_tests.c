/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "osp.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (osp);
BeforeEach (osp)
{
}

Ensure (osp, canonical_uuid_validation_rejects_command_injection)
{
  assert_that (osp_uuid_is_canonical (
                 "00000000-0000-4000-8000-000000000000"),
               is_true);
  assert_that (osp_uuid_is_canonical (
                 "00000000-0000-4000-8000-000000000000'/>"),
               is_false);
  assert_that (osp_uuid_is_canonical ("not-a-uuid"), is_false);
  assert_that (osp_uuid_is_canonical (NULL), is_false);
}

Ensure (osp, result_batch_id_is_required_for_nonempty_pop_response)
{
  entity_t scan;
  char *batch_id = NULL;
  char *error = NULL;

  assert_that (parse_entity (
                 "<scan><results><result/></results></scan>", &scan),
               is_equal_to (0));
  assert_that (osp_extract_result_batch_id (scan, 1, &batch_id, &error),
               is_equal_to (1));
  assert_that (batch_id, is_null);
  assert_that (error, is_not_null);
  g_free (error);
  free_entity (scan);
}

Ensure (osp, scan_progress_is_validated)
{
  entity_t scan;
  char *error = NULL;
  int progress = -1;

  assert_that (parse_entity ("<scan progress='100'/>", &scan),
               is_equal_to (0));
  assert_that (osp_extract_scan_progress (scan, &progress, &error),
               is_equal_to (0));
  assert_that (progress, is_equal_to (100));
  assert_that (error, is_null);
  free_entity (scan);

  assert_that (parse_entity ("<scan progress='done'/>", &scan),
               is_equal_to (0));
  assert_that (osp_extract_scan_progress (scan, &progress, &error),
               is_equal_to (1));
  assert_that (error, is_not_null);
  g_clear_pointer (&error, g_free);
  free_entity (scan);

  assert_that (parse_entity ("<scan/>", &scan), is_equal_to (0));
  assert_that (osp_extract_scan_progress (scan, &progress, &error),
               is_equal_to (1));
  assert_that (error, is_not_null);
  g_free (error);
  free_entity (scan);
}

Ensure (osp, result_batch_id_is_extracted_from_pop_response)
{
  entity_t scan;
  char *batch_id = NULL;
  char *error = NULL;
  const char *expected = "00000000-0000-4000-8000-000000000000";

  assert_that (parse_entity (
                 "<scan><results batch_id='"
                 "00000000-0000-4000-8000-000000000000'>"
                 "<result/></results></scan>",
                 &scan),
               is_equal_to (0));
  assert_that (osp_extract_result_batch_id (scan, 1, &batch_id, &error),
               is_equal_to (0));
  assert_that (batch_id, is_equal_to_string (expected));
  assert_that (error, is_null);
  g_free (batch_id);
  free_entity (scan);
}
AfterEach (osp)
{
}

Ensure (osp, osp_new_target_never_returns_null)
{
  osp_target_t *target;

  target = osp_target_new (NULL, NULL, NULL, 0, 0, 0);
  assert_that (target, is_not_null);
  osp_target_free (target);
}

Ensure (osp, osp_new_conn_ret_null)
{
  assert_that (osp_connection_new ("/my/socket", 0, NULL, NULL, NULL), is_null);
}

Ensure (osp, osp_get_vts_no_vts_ret_error)
{
  osp_connection_t *conn = g_malloc0 (sizeof (*conn));
  assert_that (osp_get_vts (conn, NULL), is_equal_to (1));
  g_free (conn);
}

Ensure (osp, osp_get_vts_no_conn_ret_error)
{
  assert_that (osp_get_vts (NULL, NULL), is_equal_to (1));
}

Ensure (osp, osp_target_add_alive_test_methods)
{
  osp_target_t *target;

  target = osp_target_new ("127.0.0.1", "123", NULL, 0, 0, 0);
  osp_target_add_alive_test_methods (target, TRUE, TRUE, TRUE, TRUE, TRUE);

  assert_true (target->icmp);
  assert_true (target->tcp_syn);
  assert_true (target->tcp_ack);
  assert_true (target->arp);
  assert_true (target->consider_alive);

  osp_target_free (target);
}

Ensure (osp, target_append_as_xml)
{
  osp_target_t *target;
  GString *target_xml;
  gchar *expected_xml_string;

  target = osp_target_new ("127.0.0.1", "123", NULL, 0, 0, 0);
  osp_target_add_alive_test_methods (target, TRUE, TRUE, TRUE, TRUE, FALSE);

  target_xml = g_string_sized_new (10240);

  target_append_as_xml (target, target_xml);
  expected_xml_string = "<target>"
                        "<hosts>127.0.0.1</hosts>"
                        "<exclude_hosts></exclude_hosts>"
                        "<finished_hosts></finished_hosts>"
                        "<ports>123</ports>"
                        "<alive_test_methods>"
                        "<icmp>1</icmp>"
                        "<tcp_syn>1</tcp_syn>"
                        "<tcp_ack>1</tcp_ack>"
                        "<arp>1</arp>"
                        "<consider_alive>0</consider_alive>"
                        "</alive_test_methods>"
                        "</target>";

  assert_that (target_xml->str, is_equal_to_string (expected_xml_string));

  osp_target_free (target);
  g_string_free (target_xml, TRUE);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, osp, osp_new_target_never_returns_null);
  add_test_with_context (suite, osp, osp_get_vts_no_conn_ret_error);
  add_test_with_context (suite, osp, osp_get_vts_no_vts_ret_error);
  add_test_with_context (suite, osp, osp_new_conn_ret_null);
  add_test_with_context (suite, osp, osp_target_add_alive_test_methods);
  add_test_with_context (suite, osp, target_append_as_xml);
  add_test_with_context (suite, osp,
                         canonical_uuid_validation_rejects_command_injection);
  add_test_with_context (
    suite, osp, result_batch_id_is_required_for_nonempty_pop_response);
  add_test_with_context (suite, osp,
                         result_batch_id_is_extracted_from_pop_response);
  add_test_with_context (suite, osp, scan_progress_is_validated);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
