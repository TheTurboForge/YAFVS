/* Copyright (C) 2020-2022 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#include <cgreen/cgreen.h>
#pragma GCC diagnostic pop

Describe (manage_sql);
BeforeEach (manage_sql) {}
AfterEach (manage_sql) {}

/* truncate_text */

#define PASS(port) assert_that (validate_results_port (port), is_equal_to (0))
#define FAIL(port) assert_that (validate_results_port (port), is_equal_to (1))

Ensure (manage_sql, validate_results_port_validates)
{
  PASS ("cpe:/a:.joomclan:com_joomclip");
  PASS ("cpe:two");
  PASS ("general/tcp");
  PASS ("general/udp");
  PASS ("general/Host_Details");
  PASS ("20/udp");
  PASS ("20/UDP");
  PASS ("20/dccp");
  PASS ("1/tcp");
  PASS ("8080/tcp");
  PASS ("65535/tcp");
  PASS ("package");

  FAIL (NULL);
  FAIL ("cpe:/a:.joomclan:com_joomclip cpe:two");
  FAIL ("0/tcp");
  FAIL ("65536/tcp");
  FAIL ("20/tcp (IANA: ftp-data)");
  FAIL ("20/tcp,21/tcp");
  FAIL ("20/tcp;21/tcp");
  FAIL ("20/tcp 21/tcp");
  FAIL ("20-21/tcp");
  FAIL ("20/tcp-21/tcp");
  FAIL ("-1/tcp");
  FAIL ("ftp-data (20/tcp)");
  FAIL ("80");
  FAIL ("ftp-data");
  FAIL ("udp");
}

Ensure (manage_sql, osp_report_structure_validation_is_strict)
{
  entity_t entity;

  assert_that (parse_entity (
                 "<scan><results><result type='Log' name='name' severity='0.0'"
                 " host='192.0.2.1' hostname='' test_id='id' port='' qod='0'"
                 " uri=''>value</result></results></scan>",
                 &entity),
               is_equal_to (0));
  assert_that (validate_osp_report_entity (entity), is_equal_to (0));
  free_entity (entity);

  assert_that (parse_entity (
                 "<scan><results><result type='Log' name='name'"
                 " host='192.0.2.1'>value</result></results></scan>",
                 &entity),
               is_equal_to (0));
  assert_that (validate_osp_report_entity (entity), is_equal_to (1));
  free_entity (entity);

  assert_that (parse_entity ("<scan/>", &entity), is_equal_to (0));
  assert_that (validate_osp_report_entity (entity), is_equal_to (1));
  free_entity (entity);
}

Ensure (manage_sql, auth_settings_certificate_metadata_is_bounded)
{
  gchar *oversized_issuer =
    g_strnfill (MANAGE_AUTH_SETTINGS_CERT_ISSUER_MAX_BYTES + 1, 'a');

  assert_that (manage_auth_settings_certificate_metadata_is_valid (
                 "AA:BB", "issuer", "2026-01-01T00:00:00Z",
                 "2027-01-01T00:00:00Z", "valid"),
               is_true);
  assert_that (manage_auth_settings_certificate_metadata_is_valid (
                 "AA:BB", oversized_issuer, NULL, NULL, NULL),
               is_false);
  g_free (oversized_issuer);
}

/* ensure_term_has_qod_and_overrides */

Ensure (manage_sql, ensure_term_has_qod_and_overrides_adds_defaults)
{
  gchar *term;

  // Test with NULL input
  term = ensure_term_has_qod_and_overrides (NULL);
  assert_that (term, contains_string ("min_qod="));
  assert_that (term, contains_string ("apply_overrides="));
  g_free (term);

  // Test with empty string
  term = ensure_term_has_qod_and_overrides (g_strdup (""));
  assert_that (term, contains_string ("min_qod="));
  assert_that (term, contains_string ("apply_overrides="));
  g_free (term);

  // Test with existing filter but no min_qod or apply_overrides
  term = ensure_term_has_qod_and_overrides (g_strdup ("severity>5"));
  assert_that (term, contains_string ("min_qod="));
  assert_that (term, contains_string ("apply_overrides="));
  assert_that (term, contains_string ("severity>5"));
  g_free (term);

  // Test with existing min_qod but no apply_overrides
  term = ensure_term_has_qod_and_overrides (g_strdup ("min_qod=50"));
  assert_that (term, contains_string ("min_qod=50"));
  assert_that (term, contains_string ("apply_overrides="));
  g_free (term);

  // Test with existing apply_overrides but no min_qod
  term = ensure_term_has_qod_and_overrides (g_strdup ("apply_overrides=1"));
  assert_that (term, contains_string ("apply_overrides=1"));
  assert_that (term, contains_string ("min_qod="));
  g_free (term);

  // Test with both min_qod and apply_overrides already present
  term = g_strdup ("min_qod=70 apply_overrides=0");
  term = ensure_term_has_qod_and_overrides (term);
  assert_that (term, contains_string ("min_qod=70"));
  assert_that (term, contains_string ("apply_overrides=0"));
  // Should not add defaults again
  assert_that (term, is_equal_to_string ("min_qod=70 apply_overrides=0"));
  g_free (term);
}

/* print_report_clean_filter */

static int
dummy_setting_value (const char *uuid, char **value)
{
  if (value == NULL || uuid == NULL)
    return -1;

  *value = g_strdup ("abc");
  return 0;
}

static int
dummy_setting_value_int (const char *uuid, int *value)
{
  if (value == NULL || uuid == NULL)
    return -1;

  *value = 10;
  return 0;
}

Ensure (manage_sql, print_report_clean_filter_handles_null_term)
{
  get_data_t get;
  gchar *term;

  init_manage_settings_funcs (dummy_setting_value, dummy_setting_value_int);

  // Test with NULL term and NULL get->filter
  get.filter = NULL;
  get.ignore_max_rows_per_page = 0;
  term = NULL;
  print_report_clean_filter (&term, &get);
  assert_that (term, is_not_equal_to (NULL));
  g_free (term);

  // Test with NULL term but valid get->filter
  get.filter = "severity>5";
  term = NULL;
  print_report_clean_filter (&term, &get);
  assert_that (term, is_not_equal_to (NULL));
  assert_that (term, contains_string ("severity>5"));
  g_free (term);
}

/* Authentication settings */

Ensure (manage_sql, auth_settings_text_validation_is_strict_and_bounded)
{
  gchar *oversized = g_malloc0 (MANAGE_AUTH_SETTINGS_HOST_MAX_BYTES + 2);

  memset (oversized, 'a', MANAGE_AUTH_SETTINGS_HOST_MAX_BYTES + 1);
  assert_that (manage_auth_settings_text_is_valid (
                 "", MANAGE_AUTH_SETTINGS_HOST_MAX_BYTES, TRUE, FALSE),
               is_true);
  assert_that (manage_auth_settings_text_is_valid (
                 "", MANAGE_AUTH_SETTINGS_RADIUS_SECRET_MAX_BYTES, FALSE,
                 FALSE), is_false);
  assert_that (manage_auth_settings_text_is_valid (
                 "host\n", MANAGE_AUTH_SETTINGS_HOST_MAX_BYTES, TRUE, FALSE),
               is_false);
  assert_that (manage_auth_settings_text_is_valid (
                 "-----BEGIN CERTIFICATE-----\nvalue\n"
                 "-----END CERTIFICATE-----\n",
                 MANAGE_AUTH_SETTINGS_CERT_MAX_BYTES, FALSE, TRUE), is_true);
  assert_that (manage_auth_settings_text_is_valid (
                 oversized, MANAGE_AUTH_SETTINGS_HOST_MAX_BYTES, TRUE, FALSE),
               is_false);
  manage_auth_settings_secure_clear (
    oversized, MANAGE_AUTH_SETTINGS_HOST_MAX_BYTES + 1);
  g_free (oversized);
}

Ensure (manage_sql, auth_settings_validation_fails_before_mutation)
{
  int previous_disable_encryption = disable_encrypted_credentials;

  if (gvm_auth_ldap_enabled ())
    {
      assert_that (manage_auth_settings_write_ldap (
                     1, "", "", 0, 1, NULL),
                   is_equal_to (MANAGE_AUTH_SETTINGS_INVALID_AUTH_DN));
      assert_that (manage_auth_settings_write_ldap (
                     1, "", "uid=%s,dc=example,dc=test", 0, 1,
                     "not a certificate"),
                   is_equal_to (MANAGE_AUTH_SETTINGS_INVALID_CERTIFICATE));
    }
  else
    assert_that (manage_auth_settings_write_ldap (
                   1, "", "", 0, 1, NULL),
                 is_equal_to (MANAGE_AUTH_SETTINGS_PROVIDER_UNAVAILABLE));

  if (gvm_auth_radius_enabled ())
    {
      assert_that (manage_auth_settings_write_radius (1, "host\n", NULL),
                   is_equal_to (MANAGE_AUTH_SETTINGS_INTERNAL_ERROR));
      disable_encrypted_credentials = 1;
      assert_that (manage_auth_settings_write_radius (1, "", "secret"),
                   is_equal_to (MANAGE_AUTH_SETTINGS_ENCRYPTION_FAILED));
    }
  else
    assert_that (manage_auth_settings_write_radius (1, "", "secret"),
                 is_equal_to (MANAGE_AUTH_SETTINGS_PROVIDER_UNAVAILABLE));
  disable_encrypted_credentials = previous_disable_encryption;
}

Ensure (manage_sql, clears_auth_settings_snapshot)
{
  manage_auth_settings_t settings = {
    .ldap_available = 1,
    .ldap_host = g_strdup ("ldap"),
    .ldap_authdn = g_strdup ("uid=%s"),
    .ldap_cert_sha256 = g_strdup ("sha256"),
    .ldap_cert_issuer = g_strdup ("issuer"),
    .ldap_cert_activation = g_strdup ("activation"),
    .ldap_cert_expiration = g_strdup ("expiration"),
    .ldap_cert_time_status = g_strdup ("valid"),
    .radius_available = 1,
    .radius_host = g_strdup ("radius"),
  };

  manage_auth_settings_clear (&settings);
  assert_that (settings.ldap_available, is_equal_to (0));
  assert_that (settings.ldap_host, is_null);
  assert_that (settings.ldap_authdn, is_null);
  assert_that (settings.ldap_cert_sha256, is_null);
  assert_that (settings.radius_available, is_equal_to (0));
  assert_that (settings.radius_host, is_null);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_sql, validate_results_port_validates);
  add_test_with_context (suite, manage_sql,
                         ensure_term_has_qod_and_overrides_adds_defaults);
  add_test_with_context (suite, manage_sql,
                         print_report_clean_filter_handles_null_term);
  add_test_with_context (suite, manage_sql,
                         osp_report_structure_validation_is_strict);
  add_test_with_context (
    suite, manage_sql,
    auth_settings_text_validation_is_strict_and_bounded);
  add_test_with_context (
    suite, manage_sql, auth_settings_validation_fails_before_mutation);
  add_test_with_context (
    suite, manage_sql, auth_settings_certificate_metadata_is_bounded);
  add_test_with_context (suite, manage_sql, clears_auth_settings_snapshot);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
