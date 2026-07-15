/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "nasl_ssh_host_key_policy.h"

#include <gio/gio.h>
#include <json-glib/json-glib.h>
#include <string.h>

#define MAX_POLICY_BYTES (1024 * 1024)
#define MAX_HOST_KEY_PINS 4095

static gboolean
policy_required (const char *require_value, const char *pins_b64,
                 gboolean *valid)
{
  *valid = TRUE;
  if (require_value == NULL)
    return pins_b64 != NULL;
  if (g_str_equal (require_value, "1") || g_str_equal (require_value, "yes")
      || g_str_equal (require_value, "true"))
    return TRUE;
  if (g_str_equal (require_value, "0") || g_str_equal (require_value, "no")
      || g_str_equal (require_value, "false"))
    return pins_b64 != NULL;
  *valid = FALSE;
  return FALSE;
}

static gboolean
decode_canonical_base64 (const char *encoded, guchar **decoded,
                         gsize *decoded_length)
{
  gchar *canonical;
  gboolean matches;

  if (encoded == NULL)
    return FALSE;
  *decoded = g_base64_decode (encoded, decoded_length);
  if (*decoded == NULL)
    return FALSE;
  canonical = g_base64_encode (*decoded, *decoded_length);
  matches = g_str_equal (canonical, encoded);
  g_free (canonical);
  if (!matches)
    {
      g_free (*decoded);
      *decoded = NULL;
    }
  return matches;
}

static gboolean
decode_fingerprint (const char *fingerprint, guchar **digest,
                    gsize *digest_length)
{
  gchar *canonical, *padded, *unpadded;
  gboolean matches;

  if (fingerprint == NULL || !g_str_has_prefix (fingerprint, "SHA256:"))
    return FALSE;
  if (strlen (fingerprint + strlen ("SHA256:")) != 43)
    return FALSE;
  padded = g_strconcat (fingerprint + strlen ("SHA256:"), "=", NULL);
  *digest = g_base64_decode (padded, digest_length);
  g_free (padded);
  if (*digest == NULL || *digest_length != 32)
    {
      g_free (*digest);
      *digest = NULL;
      return FALSE;
    }
  canonical = g_base64_encode (*digest, *digest_length);
  unpadded = g_strndup (canonical, strcspn (canonical, "="));
  matches = g_str_equal (unpadded, fingerprint + strlen ("SHA256:"));
  g_free (unpadded);
  g_free (canonical);
  if (!matches)
    {
      g_free (*digest);
      *digest = NULL;
    }
  return matches;
}

nasl_ssh_host_key_policy_result_t
nasl_ssh_host_key_policy_verify (const char *require_value,
                                 const char *pins_b64, const char *host,
                                 const guchar *sha256_digest,
                                 gsize digest_length)
{
  gboolean valid, host_present = FALSE, digest_matches = FALSE;
  guchar *json_data = NULL;
  gsize json_length = 0;
  JsonParser *parser = NULL;
  JsonArray *pins;
  GInetAddress *target_address = NULL;
  GHashTable *seen = NULL;
  nasl_ssh_host_key_policy_result_t result =
    NASL_SSH_HOST_KEY_POLICY_INVALID;

  if (!policy_required (require_value, pins_b64, &valid))
    return valid ? NASL_SSH_HOST_KEY_POLICY_DISABLED
                 : NASL_SSH_HOST_KEY_POLICY_INVALID;
  if (pins_b64 == NULL || host == NULL || sha256_digest == NULL
      || digest_length != 32)
    return NASL_SSH_HOST_KEY_POLICY_MISSING;
  if (strlen (pins_b64) > MAX_POLICY_BYTES * 2
      || !decode_canonical_base64 (pins_b64, &json_data, &json_length)
      || json_length > MAX_POLICY_BYTES)
    goto cleanup;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, (const gchar *) json_data,
                                   json_length, NULL))
    goto cleanup;
  if (!JSON_NODE_HOLDS_ARRAY (json_parser_get_root (parser)))
    goto cleanup;
  pins = json_node_get_array (json_parser_get_root (parser));
  if (json_array_get_length (pins) == 0
      || json_array_get_length (pins) > MAX_HOST_KEY_PINS)
    goto cleanup;
  target_address = g_inet_address_new_from_string (host);
  if (target_address == NULL)
    goto cleanup;
  seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  for (guint i = 0; i < json_array_get_length (pins); i++)
    {
      JsonNode *node = json_array_get_element (pins, i);
      JsonObject *pin;
      GList *members;
      const char *pin_host, *fingerprint;
      GInetAddress *pin_address;
      guchar *pin_digest = NULL;
      gsize pin_digest_length = 0;
      gchar *identity, *normalized_host;

      if (!JSON_NODE_HOLDS_OBJECT (node))
        goto cleanup;
      pin = json_node_get_object (node);
      members = json_object_get_members (pin);
      if (g_list_length (members) != 2
          || !json_object_has_member (pin, "host")
          || !json_object_has_member (pin, "fingerprint"))
        {
          g_list_free (members);
          goto cleanup;
        }
      g_list_free (members);
      pin_host = json_object_get_string_member (pin, "host");
      fingerprint = json_object_get_string_member (pin, "fingerprint");
      if (pin_host == NULL || fingerprint == NULL)
        goto cleanup;
      pin_address = g_inet_address_new_from_string (pin_host);
      if (pin_address == NULL
          || !decode_fingerprint (fingerprint, &pin_digest,
                                  &pin_digest_length))
        {
          g_clear_object (&pin_address);
          g_free (pin_digest);
          goto cleanup;
        }
      normalized_host = g_inet_address_to_string (pin_address);
      identity = g_strdup_printf ("%s\n%s", normalized_host, fingerprint);
      g_free (normalized_host);
      if (!g_hash_table_add (seen, identity))
        {
          g_object_unref (pin_address);
          g_free (pin_digest);
          goto cleanup;
        }
      if (g_inet_address_equal (pin_address, target_address))
        {
          host_present = TRUE;
          if (memcmp (pin_digest, sha256_digest, 32) == 0)
            digest_matches = TRUE;
        }
      g_object_unref (pin_address);
      g_free (pin_digest);
    }

  result = digest_matches
             ? NASL_SSH_HOST_KEY_POLICY_MATCH
             : (host_present ? NASL_SSH_HOST_KEY_POLICY_MISMATCH
                             : NASL_SSH_HOST_KEY_POLICY_MISSING);

cleanup:
  g_clear_pointer (&seen, g_hash_table_unref);
  g_clear_object (&target_address);
  g_clear_object (&parser);
  g_free (json_data);
  return result;
}
