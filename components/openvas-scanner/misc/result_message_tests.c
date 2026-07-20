/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "result_message.h"

#include <glib.h>
#include <json-glib/json-glib.h>
#include <string.h>

static void
test_fields_round_trip_without_delimiter_semantics (void)
{
  const char *host_name = "host|||name.example";
  const char *value = "line one\nline ||| two \xE2\x98\x83";
  char *message =
    openvas_result_message_new ("ALARM", "192.0.2.1", host_name, "443/tcp",
                                "1.3.6.1", value, "/path|||fragment");
  JsonParser *parser = json_parser_new ();
  JsonObject *object;

  g_assert_true (json_parser_load_from_data (parser, message, -1, NULL));
  object = json_node_get_object (json_parser_get_root (parser));
  g_assert_cmpint (json_object_get_int_member (object, "version"), ==, 1);
  g_assert_cmpstr (json_object_get_string_member (object, "host_name"), ==,
                   host_name);
  g_assert_cmpstr (json_object_get_string_member (object, "value"), ==, value);
  g_assert_cmpstr (json_object_get_string_member (object, "uri"), ==,
                   "/path|||fragment");

  g_object_unref (parser);
  g_free (message);
}

static void
test_ascii_control_bytes_are_losslessly_json_escaped (void)
{
  char value[63];
  for (unsigned int byte = 1; byte <= 0x1f; byte++)
    {
      value[(byte - 1) * 2] = 'x';
      value[(byte - 1) * 2 + 1] = (char) byte;
    }
  value[G_N_ELEMENTS (value) - 1] = '\0';
  char *message = openvas_result_message_new ("LOG", "", "", "", "", value, "");
  JsonParser *parser = json_parser_new ();
  JsonObject *object;

  for (unsigned int byte = 1; byte <= 0x1f; byte++)
    g_assert_null (strchr (message, (int) byte));
  g_assert_nonnull (strstr (message, "\\u001f"));
  g_assert_true (json_parser_load_from_data (parser, message, -1, NULL));
  object = json_node_get_object (json_parser_get_root (parser));
  g_assert_cmpstr (json_object_get_string_member (object, "value"), ==, value);

  g_object_unref (parser);
  g_free (message);
}

static void
test_invalid_utf8_is_replaced_before_json_encoding (void)
{
  const char invalid[] = {'x', (char) 0xff, 'y', '\0'};
  char *message =
    openvas_result_message_new ("LOG", "", invalid, "", "", invalid, "");
  JsonParser *parser = json_parser_new ();
  JsonObject *object;

  g_assert_true (json_parser_load_from_data (parser, message, -1, NULL));
  object = json_node_get_object (json_parser_get_root (parser));
  g_assert_cmpstr (json_object_get_string_member (object, "host_name"), ==,
                   "x\xEF\xBF\xBDy");
  g_assert_cmpstr (json_object_get_string_member (object, "value"), ==,
                   "x\xEF\xBF\xBDy");

  g_object_unref (parser);
  g_free (message);
}

static void
test_null_fields_become_empty_strings (void)
{
  char *message =
    openvas_result_message_new (NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  JsonParser *parser = json_parser_new ();
  JsonObject *object;

  g_assert_true (json_parser_load_from_data (parser, message, -1, NULL));
  object = json_node_get_object (json_parser_get_root (parser));
  g_assert_cmpstr (json_object_get_string_member (object, "result_type"), ==,
                   "");
  g_assert_cmpstr (json_object_get_string_member (object, "value"), ==, "");

  g_object_unref (parser);
  g_free (message);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/result-message/round-trip",
                   test_fields_round_trip_without_delimiter_semantics);
  g_test_add_func ("/result-message/null-fields",
                   test_null_fields_become_empty_strings);
  g_test_add_func ("/result-message/invalid-utf8",
                   test_invalid_utf8_is_replaced_before_json_encoding);
  g_test_add_func ("/result-message/ascii-control",
                   test_ascii_control_bytes_are_losslessly_json_escaped);
  return g_test_run ();
}
