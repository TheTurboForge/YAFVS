/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_connection_info.h"
#include "gsad_credentials.h"
#include "gsad_http.h"
#include "gsad_params.h"
#include "gsad_user.h"

#include <cgreen/cgreen.h>
#include <glib.h>
#include <microhttpd.h>
#include <string.h>

extern gboolean
gsad_native_api_test_pdf_download_target (const gchar *path,
                                          const gchar *report_format_id,
                                          gchar **target);
extern gboolean
gsad_native_api_test_parse_pdf_response (const guint8 *data, gsize length,
                                         guint *status_code, GBytes **body,
                                         gchar **content_disposition);
extern gboolean
gsad_native_api_test_browser_credentials_are_session_bound (
  gsad_credentials_t *credentials);
extern gboolean
gsad_native_api_test_post_path_is_allowed (const gchar *path);
extern gboolean
gsad_native_api_test_get_path_is_allowed (const gchar *path);
extern gboolean
gsad_native_api_test_patch_path_is_allowed (const gchar *path);
extern gboolean
gsad_native_api_test_put_path_is_allowed (const gchar *path);
extern gboolean
gsad_native_api_test_delete_path_is_allowed (const gchar *path);

/* Handler dependencies are not part of this parser-focused unit target. */
gsad_user_t *
gsad_credentials_get_user (gsad_credentials_t *credentials)
{
  return credentials == (gsad_credentials_t *) GINT_TO_POINTER (1)
           ? (gsad_user_t *) GINT_TO_POINTER (1)
           : NULL;
}

void
gsad_credentials_free (gsad_credentials_t *credentials)
{
  (void) credentials;
}

const gchar *
gsad_user_get_username (gsad_user_t *user)
{
  return user == (gsad_user_t *) GINT_TO_POINTER (1) ? "operator" : NULL;
}

Describe (gsad_native_api);

Ensure (gsad_native_api,
        should_only_allow_canonical_alert_definition_get_and_put)
{
  const gchar *valid =
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/definition";
  const gchar *rejected[] = {
    "/api/v1/alerts/not-a-uuid/definition",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/definition/extra",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/definition?x=1",
  };
  const gchar *alert = "/api/v1/alerts/12345678-1234-1234-1234-123456789abc";

  assert_that (gsad_native_api_test_get_path_is_allowed (valid), is_true);
  assert_that (gsad_native_api_test_put_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    {
      assert_that (gsad_native_api_test_get_path_is_allowed (rejected[index]),
                   is_false);
      assert_that (gsad_native_api_test_put_path_is_allowed (rejected[index]),
                   is_false);
    }

  assert_that (gsad_native_api_test_get_path_is_allowed (alert), is_true);
  assert_that (gsad_native_api_test_put_path_is_allowed (alert), is_false);
}

Ensure (gsad_native_api, should_only_allow_canonical_alert_test_posts)
{
  const gchar *valid =
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/test";
  const gchar *rejected[] = {
    "/api/v1/alerts/not-a-uuid/test",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/test/extra",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/test?unexpected=query",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/test/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                 is_false);
}

Ensure (gsad_native_api, should_only_allow_canonical_alert_report_delivery_posts)
{
  const gchar *valid =
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/deliver-report";
  const gchar *rejected[] = {
    "/api/v1/alerts/not-a-uuid/deliver-report",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/deliver-report/extra",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/deliver-report?unexpected=query",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/deliver-report/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                 is_false);
}

Ensure (gsad_native_api, should_require_a_session_user_for_browser_reads)
{
  assert_that (
    gsad_native_api_test_browser_credentials_are_session_bound (NULL),
    is_false);
  assert_that (gsad_native_api_test_browser_credentials_are_session_bound (
                 (gsad_credentials_t *) GINT_TO_POINTER (2)),
               is_false);
  assert_that (gsad_native_api_test_browser_credentials_are_session_bound (
                 (gsad_credentials_t *) GINT_TO_POINTER (1)),
               is_true);
}

Ensure (gsad_native_api, should_only_allow_canonical_task_clone_posts)
{
  const gchar *valid =
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/clone";
  const gchar *rejected[] = {
    "/api/v1/tasks/not-a-uuid/clone",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/clone/extra",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/clone?unexpected=query",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/clone/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                 is_false);
}

Ensure (gsad_native_api,
        should_only_allow_canonical_task_configuration_replacement_posts)
{
  const gchar *valid =
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/replace-configuration";
  const gchar *rejected[] = {
    "/api/v1/tasks/not-a-uuid/replace-configuration",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/replace-configuration/extra",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/replace-configuration?unexpected=query",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/replace-configuration/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                 is_false);
}

Ensure (gsad_native_api, should_allow_scanner_create_post)
{
  assert_that (
    gsad_native_api_test_post_path_is_allowed ("/api/v1/scanners"), is_true);
  assert_that (
    gsad_native_api_test_post_path_is_allowed ("/api/v1/scanners/"),
    is_false);
  assert_that (
    gsad_native_api_test_post_path_is_allowed (
      "/api/v1/scanners?unexpected=query"),
    is_false);
}

Ensure (gsad_native_api,
        should_only_allow_canonical_scanner_configuration_replacement_posts)
{
  const gchar *valid =
    "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/replace-configuration";
  const gchar *rejected[] = {
    "/api/v1/scanners/not-a-uuid/replace-configuration",
    "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/replace-configuration/extra",
    "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/replace-configuration?unexpected=query",
    "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/replace-configuration/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                 is_false);
}

Ensure (gsad_native_api, should_only_allow_canonical_override_mutations)
{
  const gchar *id = "12345678-1234-1234-1234-123456789abc";
  gchar *detail = g_strdup_printf ("/api/v1/overrides/%s", id);
  gchar *clone = g_strdup_printf ("%s/clone", detail);
  gchar *restore = g_strdup_printf ("%s/restore", detail);
  gchar *trash = g_strdup_printf ("%s/trash", detail);

  assert_that (
    gsad_native_api_test_post_path_is_allowed ("/api/v1/overrides"), is_true);
  assert_that (gsad_native_api_test_post_path_is_allowed (clone), is_true);
  assert_that (gsad_native_api_test_post_path_is_allowed (restore), is_true);
  assert_that (gsad_native_api_test_patch_path_is_allowed (detail), is_true);
  assert_that (gsad_native_api_test_delete_path_is_allowed (detail), is_true);
  assert_that (gsad_native_api_test_delete_path_is_allowed (trash), is_true);

  assert_that (
    gsad_native_api_test_post_path_is_allowed ("/api/v1/overrides/"), is_false);
  assert_that (
    gsad_native_api_test_post_path_is_allowed ("/api/v1/overrides/not-a-uuid/clone"),
    is_false);
  assert_that (
    gsad_native_api_test_patch_path_is_allowed ("/api/v1/overrides/not-a-uuid"),
    is_false);
  assert_that (
    gsad_native_api_test_delete_path_is_allowed (
      "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/trash?force=true"),
    is_false);

  g_free (trash);
  g_free (restore);
  g_free (clone);
  g_free (detail);
}

const gchar *
params_value (params_t *params, const gchar *name)
{
  (void) params;
  (void) name;
  return NULL;
}

const gchar *
gsad_connection_info_get_url (const gsad_connection_info_t *connection_info)
{
  (void) connection_info;
  return NULL;
}

params_t *
gsad_connection_info_get_params (const gsad_connection_info_t *connection_info)
{
  (void) connection_info;
  return NULL;
}

const gchar *
gsad_connection_info_get_raw_body (
  const gsad_connection_info_t *connection_info, gsize *length)
{
  (void) connection_info;
  *length = 0;
  return NULL;
}

gsad_http_result_t
gsad_http_send_response_for_content (gsad_http_connection_t *connection,
                                     const gchar *content, int status_code,
                                     const gchar *sid,
                                     content_type_t content_type,
                                     const gchar *content_disposition,
                                     size_t content_length)
{
  (void) connection;
  (void) content;
  (void) status_code;
  (void) sid;
  (void) content_type;
  (void) content_disposition;
  (void) content_length;
  return MHD_NO;
}

BeforeEach (gsad_native_api)
{
}

AfterEach (gsad_native_api)
{
}

Ensure (gsad_native_api, should_only_forward_the_canonical_pdf_format)
{
  const gchar *path =
    "/api/v1/reports/12345678-1234-1234-1234-123456789abc/download";
  gchar *target = NULL;

  assert_that (gsad_native_api_test_pdf_download_target (
                 path, "c402cc3e-b531-11e1-9163-406186ea4fc5", &target),
               is_true);
  assert_that (
    target,
    is_equal_to_string (
      "/api/v1/reports/12345678-1234-1234-1234-123456789abc/"
      "download?report_format_id=c402cc3e-b531-11e1-9163-406186ea4fc5"));
  g_free (target);
  target = NULL;

  assert_that (gsad_native_api_test_pdf_download_target (
                 path, "a3810a62-1f62-11e1-9219-406186ea4fc5", &target),
               is_false);
  assert_that (target, is_null);
  assert_that (gsad_native_api_test_pdf_download_target (
                 "/api/v1/reports/not-a-uuid/download",
                 "c402cc3e-b531-11e1-9163-406186ea4fc5", &target),
               is_false);
}

Ensure (gsad_native_api, should_preserve_embedded_nul_in_pdf_response)
{
  static const gchar header[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 9\r\n"
    "Content-Type: application/pdf\r\n"
    "Content-Disposition: attachment; filename=\"report.pdf\"\r\n"
    "\r\n";
  static const guint8 pdf[] = {'%', 'P', 'D', 'F', '-', 0, 'x', 'y', 'z'};
  GByteArray *raw = g_byte_array_new ();
  GBytes *body = NULL;
  gchar *content_disposition = NULL;
  guint status_code = 0;
  gsize body_length;
  const guint8 *body_data;
  gboolean parsed;

  g_byte_array_append (raw, (const guint8 *) header, sizeof (header) - 1);
  g_byte_array_append (raw, pdf, sizeof (pdf));
  parsed = gsad_native_api_test_parse_pdf_response (
    raw->data, raw->len, &status_code, &body, &content_disposition);
  assert_that (parsed, is_true);
  if (!parsed)
    {
      g_byte_array_unref (raw);
      return;
    }
  body_data = g_bytes_get_data (body, &body_length);
  assert_that (status_code, is_equal_to (MHD_HTTP_OK));
  assert_that (body_length, is_equal_to (sizeof (pdf)));
  assert_that (memcmp (body_data, pdf, sizeof (pdf)), is_equal_to (0));
  assert_that (content_disposition,
               is_equal_to_string ("attachment; filename=\"report.pdf\""));

  g_bytes_unref (body);
  g_free (content_disposition);
  g_byte_array_unref (raw);
}

Ensure (gsad_native_api, should_reject_non_pdf_or_unsafe_pdf_response_headers)
{
  static const gchar wrong_type[] = "HTTP/1.1 200 OK\r\nContent-Length: "
                                    "5\r\nContent-Type: text/html\r\n\r\n%PDF-";
  static const gchar wrong_signature[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: "
    "application/pdf\r\n\r\nHELLO";
  static const gchar unsafe_disposition[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: application/pdf\r\n"
    "Content-Disposition: form-data; name=\"report\"\r\n\r\n%PDF-";
  GBytes *body = NULL;
  gchar *content_disposition = NULL;
  guint status_code = 0;

  assert_that (gsad_native_api_test_parse_pdf_response (
                 (const guint8 *) wrong_type, sizeof (wrong_type) - 1,
                 &status_code, &body, &content_disposition),
               is_false);
  assert_that (gsad_native_api_test_parse_pdf_response (
                 (const guint8 *) wrong_signature, sizeof (wrong_signature) - 1,
                 &status_code, &body, &content_disposition),
               is_false);
  assert_that (gsad_native_api_test_parse_pdf_response (
                 (const guint8 *) unsafe_disposition,
                 sizeof (unsafe_disposition) - 1, &status_code, &body,
                 &content_disposition),
               is_false);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();
  int ret;

  add_test_with_context (suite, gsad_native_api,
                         should_only_forward_the_canonical_pdf_format);
  add_test_with_context (suite, gsad_native_api,
                         should_require_a_session_user_for_browser_reads);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_alert_definition_get_and_put);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_canonical_task_clone_posts);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_canonical_alert_test_posts);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_alert_report_delivery_posts);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_task_configuration_replacement_posts);
  add_test_with_context (suite, gsad_native_api,
                         should_allow_scanner_create_post);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_scanner_configuration_replacement_posts);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_canonical_override_mutations);
  add_test_with_context (suite, gsad_native_api,
                         should_preserve_embedded_nul_in_pdf_response);
  add_test_with_context (suite, gsad_native_api,
                         should_reject_non_pdf_or_unsafe_pdf_response_headers);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
