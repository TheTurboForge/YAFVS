/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "result_message.h"

#include <json-glib/json-glib.h>

static void
add_string_member (JsonBuilder *builder, const char *name, const char *value)
{
  GString *valid = g_string_new (NULL);
  const char *remaining = value ? value : "";
  const char *invalid;

  while (!g_utf8_validate (remaining, -1, &invalid))
    {
      g_string_append_len (valid, remaining, invalid - remaining);
      g_string_append (valid, "\xEF\xBF\xBD");
      remaining = invalid + 1;
    }
  g_string_append (valid, remaining);
  json_builder_set_member_name (builder, name);
  json_builder_add_string_value (builder, valid->str);
  g_string_free (valid, TRUE);
}

char *
openvas_result_message_new (const char *result_type, const char *host_ip,
                            const char *host_name, const char *port,
                            const char *oid, const char *value, const char *uri)
{
  JsonBuilder *builder = json_builder_new ();
  JsonNode *root;
  char *message;

  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "version");
  json_builder_add_int_value (builder, 1);
  add_string_member (builder, "result_type", result_type);
  add_string_member (builder, "host_ip", host_ip);
  add_string_member (builder, "host_name", host_name);
  add_string_member (builder, "port", port);
  add_string_member (builder, "oid", oid);
  add_string_member (builder, "value", value);
  add_string_member (builder, "uri", uri);
  json_builder_end_object (builder);

  root = json_builder_get_root (builder);
  message = json_to_string (root, FALSE);
  json_node_free (root);
  g_object_unref (builder);
  return message;
}
