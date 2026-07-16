/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "table_driven_lsc.c"

#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/mocks.h>
#include <sys/cdefs.h>

Describe (lsc);
BeforeEach (lsc)
{
}

Ensure (lsc, makes_distinct_bounded_start_ids)
{
  gchar *group_id = NULL;
  gchar *message_id = NULL;

  assert_that (make_notus_start_ids (&message_id, &group_id), is_true);
  assert_that (message_id, is_not_null);
  assert_that (group_id, is_not_null);
  assert_that (strlen (message_id), is_equal_to (TABLE_DRIVEN_LSC_ID_LENGTH));
  assert_that (strlen (group_id), is_equal_to (TABLE_DRIVEN_LSC_ID_LENGTH));
  assert_that (strcmp (message_id, group_id), is_not_equal_to (0));

  g_free (group_id);
  g_free (message_id);
}

Ensure (lsc, serializes_exact_bounded_manifest)
{
  const char *group_id = "11111111-1111-4111-8111-111111111111";
  const char *message_id = "22222222-2222-4222-8222-222222222222";
  const char *expected =
    "{\"run_id\":\"11111111-1111-4111-8111-111111111111\","
    "\"start_message_id\":\"22222222-2222-4222-8222-222222222222\","
    "\"host_ip\":\"2001:db8::1\"}";
  gchar *json;
  char oversized_ip[TABLE_DRIVEN_LSC_HOST_IP_MAX_LENGTH + 2];

  json = make_notus_manifest_json_str (group_id, message_id, "2001:db8::1");
  assert_that (json, is_not_null);
  assert_that (strcmp (json, expected), is_equal_to (0));
  g_free (json);

  memset (oversized_ip, 'a', sizeof (oversized_ip) - 1);
  oversized_ip[sizeof (oversized_ip) - 1] = '\0';
  assert_that (
    make_notus_manifest_json_str (group_id, message_id, oversized_ip), is_null);
  assert_that (
    make_notus_manifest_json_str ("11111111-1111-4111-8111-11111111111",
                                  message_id, "192.0.2.1"),
    is_null);
}

Ensure (lsc, start_payload_uses_explicit_ids)
{
  const char *group_id = "11111111-1111-4111-8111-111111111111";
  const char *message_id = "22222222-2222-4222-8222-222222222222";
  JsonObject *object;
  JsonParser *parser;
  gchar *json;

  json = make_table_driven_lsc_info_json_str (message_id, group_id, "scan-1",
                                              "192.0.2.1", NULL,
                                              "Example Linux", "pkg-1\n");
  assert_that (json, is_not_null);

  parser = json_parser_new ();
  assert_that (json_parser_load_from_data (parser, json, -1, NULL), is_true);
  object = json_node_get_object (json_parser_get_root (parser));
  assert_that (
    strcmp (json_object_get_string_member (object, "message_id"), message_id),
    is_equal_to (0));
  assert_that (
    strcmp (json_object_get_string_member (object, "group_id"), group_id),
    is_equal_to (0));
  assert_that (strcmp (json_object_get_string_member (object, "host_name"), ""),
               is_equal_to (0));
  assert_that (json_array_get_length (
                 json_object_get_array_member (object, "package_list")),
               is_equal_to (1));

  g_object_unref (parser);
  g_free (json);
}

Ensure (lsc, rejects_oversized_notus_start_input_before_json)
{
  const char *group_id = "11111111-1111-4111-8111-111111111111";
  const char *message_id = "22222222-2222-4222-8222-222222222222";
  GString *too_many_packages =
    g_string_sized_new (2 * (TABLE_DRIVEN_LSC_PACKAGE_MAX_COUNT + 1));
  gchar *packages = g_malloc0 (TABLE_DRIVEN_LSC_PACKAGE_LIST_MAX_BYTES + 2);
  size_t i;

  memset (packages, 'a', TABLE_DRIVEN_LSC_PACKAGE_LIST_MAX_BYTES + 1);
  assert_that (make_table_driven_lsc_info_json_str (
                 message_id, group_id, "scan-1", "192.0.2.1", "host",
                 "Example Linux", packages),
               is_null);
  assert_that (make_package_list_as_json_str (packages), is_null);
  g_free (packages);

  for (i = 0; i <= TABLE_DRIVEN_LSC_PACKAGE_MAX_COUNT; i++)
    g_string_append (too_many_packages, "p\n");
  assert_that (bounded_notus_package_list (too_many_packages->str), is_false);
  g_string_free (too_many_packages, TRUE);
}
AfterEach (lsc)
{
}

static char *resp_str = "{"
                        "\"1.3.6.1.4.1.25623.1.1.7.2.2023.0988598199100\": ["
                        "{"
                        "\"name\": \"grafana8\","
                        "\"installed_version\": \"8.5.23\","
                        "\"fixed_version\": {"
                        "\"version\": \"8.5.24\","
                        "\"specifier\": \">=\""
                        "}"
                        "},"
                        "{"
                        "\"name\": \"grafana9\","
                        "\"installed_version\": \"9.4.7\","
                        "\"fixed_version\": {"
                        "\"start\": \"9.4.0\","
                        "\"end\": \"9.4.9\""
                        "}"
                        "}"
                        "],"
                        "\"1.3.6.1.4.1.25623.1.1.7.2.2023.10089729899100\": ["
                        "{"
                        "\"name\": \"gitlab-ce\","
                        "\"installed_version\": \"16.0.1\","
                        "\"fixed_version\": {"
                        "\"start\": \"16.0.0\","
                        "\"end\": \"16.0.7\""
                        "}"
                        "}"
                        "]"
                        "}";

Ensure (lsc, make_pkg_in_json)
{
  char *pkglist = "pkg1.2.3\npkg4.5.6\nfoo-24\nbar-35\n";
  char *json = "[\"pkg1.2.3\",\"pkg4.5.6\",\"foo-24\",\"bar-35\"]";

  assert_that (strcmp (make_package_list_as_json_str (pkglist), json),
               is_equal_to (0));
}

Ensure (lsc, bounds_openvasd_response_before_reallocation)
{
  struct string response = {
    .ptr = g_malloc0 (1),
    .len = TABLE_DRIVEN_LSC_RESPONSE_MAX_BYTES,
  };

  assert_that (response_callback_fn ("x", 1, 1, &response), is_equal_to (0));
  assert_that (response.len, is_equal_to (TABLE_DRIVEN_LSC_RESPONSE_MAX_BYTES));
  g_free (response.ptr);
}

Ensure (lsc, process_resp)
{
  advisories_t *advisories = NULL;

  advisories = lsc_process_response (resp_str, strlen (resp_str));
  assert_that ((*advisories).count, is_equal_to (2));

  assert_that ((*advisories).advisories[0]->count, is_equal_to (2));
  assert_that ((*advisories).advisories[0]->pkgs[0]->type,
               is_equal_to (SINGLE));
  assert_that (
    strcmp ((*advisories).advisories[0]->pkgs[0]->pkg_name, "grafana8"),
    is_equal_to (0));
  assert_that (
    strcmp ((*advisories).advisories[0]->pkgs[0]->install_version, "8.5.23"),
    is_equal_to (0));
  assert_that (
    strcmp ((*advisories).advisories[0]->pkgs[1]->pkg_name, "grafana9"),
    is_equal_to (0));
  assert_that (
    strcmp ((*advisories).advisories[0]->pkgs[1]->install_version, "9.4.7"),
    is_equal_to (0));

  assert_that ((*advisories).advisories[0]->pkgs[1]->type, is_equal_to (RANGE));

  assert_that ((*advisories).advisories[1]->count, is_equal_to (1));
  assert_that ((*advisories).advisories[0]->pkgs[1]->type, is_equal_to (RANGE));

  advisories_free (advisories);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, lsc, process_resp);
  add_test_with_context (suite, lsc, make_pkg_in_json);
  add_test_with_context (suite, lsc,
                         bounds_openvasd_response_before_reallocation);
  add_test_with_context (suite, lsc, makes_distinct_bounded_start_ids);
  add_test_with_context (suite, lsc, serializes_exact_bounded_manifest);
  add_test_with_context (suite, lsc, start_payload_uses_explicit_ids);
  add_test_with_context (suite, lsc,
                         rejects_oversized_notus_start_input_before_json);
  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
