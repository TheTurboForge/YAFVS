/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_connection_info.h"
#include "gsad_credentials.h"
#include "gsad_http.h"
#include "gsad_params.h"
#include "gsad_settings.h"
#include "gsad_user.h"
#include "gsad_user_session.h"

#include <cgreen/cgreen.h>
#include <glib.h>
#include <microhttpd.h>
#include <string.h>

extern gboolean
gsad_native_api_test_pdf_download_target (const gchar *path,
                                          const gchar *report_format_id,
                                          gchar **target);
extern gboolean
gsad_native_api_test_request_target (const gchar *path, params_t *params,
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
gsad_native_api_test_get_path_requires_operator (const gchar *path);
extern gboolean
gsad_native_api_test_patch_path_is_allowed (const gchar *path);
extern gboolean
gsad_native_api_test_put_path_is_allowed (const gchar *path);
extern gboolean
gsad_native_api_test_delete_path_is_allowed (const gchar *path);
extern gboolean
gsad_native_api_test_user_management_delete_target (const gchar *path,
                                                     const gchar *inheritor_id,
                                                     gchar **target);
extern gboolean
gsad_native_api_test_parse_user_password_change_request (
  const gchar *body, gsize body_length, gchar **new_password);
extern gboolean
gsad_native_api_test_extract_self_user_management_password (
  const gchar *method, const gchar *path, const gchar *session_uuid,
  const gchar *body, gsize body_length, gchar **new_password);
extern gboolean
gsad_native_api_test_update_sessions_after_native_success (
  gsad_credentials_t *credentials, const gchar *method, const gchar *path,
  const gchar *operator_uuid, const gchar *new_password, guint status_code);
extern const gchar *
gsad_native_api_test_affected_session_uuid (const gchar *method,
                                            const gchar *path,
                                            const gchar *operator_uuid);
extern void
gsad_native_api_test_revoke_sessions_after_indeterminate_native_mutation (
  const gchar *method, const gchar *path, const gchar *operator_uuid,
  gboolean mutation_outcome_indeterminate);
extern gboolean
gsad_native_api_test_mutation_response_may_have_committed (
  const gchar *method, guint status_code, const gchar *body);

Describe (gsad_native_api);

static guint password_update_count;
static guint session_revoke_count;
static guint session_replace_count;
static const gchar *updated_password;
static const gchar *revoked_session_keep_id;
static const gchar *revoked_session_uuid;

Ensure (gsad_native_api, should_forward_typed_filters_for_collection_reads)
{
  gchar *target = NULL;

  assert_that (gsad_native_api_test_request_target (
                 "/api/v1/reports", (params_t *) GINT_TO_POINTER (5), &target),
               is_true);
  assert_that (
    target,
    is_equal_to_string (
      "/api/v1/reports?page=2&task_id=12345678-1234-1234-1234-123456789abc"
      "&nvt_oid=1.3.6.1.4.1.25623.1.0.900001"
      "&vulnerability_id=1.3.6.1.4.1.25623.1.0.900001"
      "&name=192.0.2.10&predefined=1&credential_type=up"));
  g_free (target);
}

Ensure (gsad_native_api, should_only_allow_canonical_credential_restore_posts)
{
  const gchar *valid =
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/restore";
  const gchar *rejected[] = {
    "/api/v1/credentials/not-a-uuid/restore",
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/restore/extra",
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/restore?unexpected=query",
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/restore/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                 is_false);
}

Ensure (gsad_native_api, should_only_allow_canonical_credential_trash_delete)
{
  const gchar *valid =
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/trash";
  const gchar *rejected[] = {
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc",
    "/api/v1/credentials/not-a-uuid/trash",
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/trash/extra",
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/trash?force=true",
    "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/trash/",
  };

  assert_that (gsad_native_api_test_delete_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (
      gsad_native_api_test_delete_path_is_allowed (rejected[index]),
      is_false);
}

Ensure (gsad_native_api, should_only_allow_canonical_task_restore_posts)
{
  const gchar *valid =
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/restore";
  const gchar *rejected[] = {
    "/api/v1/tasks/not-a-uuid/restore",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/restore/extra",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/restore?unexpected=query",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/restore/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                 is_false);
}

Ensure (gsad_native_api, should_only_allow_canonical_task_trash_delete)
{
  const gchar *valid =
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/trash";
  const gchar *rejected[] = {
    "/api/v1/tasks/not-a-uuid/trash",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/trash/extra",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/trash?force=true",
    "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/trash/",
  };

  assert_that (gsad_native_api_test_delete_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (
      gsad_native_api_test_delete_path_is_allowed (rejected[index]),
      is_false);
}

Ensure (gsad_native_api, should_only_allow_canonical_alert_trash_lifecycle)
{
  const gchar *restore =
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/restore";
  const gchar *trash =
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/trash";
  const gchar *rejected[] = {
    "/api/v1/alerts/not-a-uuid/restore",
    "/api/v1/alerts/not-a-uuid/trash",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/restore/extra",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/trash?force=true",
    "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/trash/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (restore), is_true);
  assert_that (gsad_native_api_test_delete_path_is_allowed (trash), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    {
      assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                   is_false);
      assert_that (
        gsad_native_api_test_delete_path_is_allowed (rejected[index]),
        is_false);
    }
}

Ensure (gsad_native_api, should_only_allow_canonical_scanner_lifecycle_paths)
{
  const gchar *id = "12345678-1234-1234-1234-123456789abc";
  gchar *detail = g_strdup_printf ("/api/v1/scanners/%s", id);
  gchar *clone = g_strdup_printf ("%s/clone", detail);
  gchar *restore = g_strdup_printf ("%s/restore", detail);
  gchar *trash = g_strdup_printf ("%s/trash", detail);
  const gchar *rejected[] = {
    "/api/v1/scanners/not-a-uuid/clone",
    "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/clone/extra",
    "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/restore?unexpected=query",
    "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/trash/",
  };

  assert_that (gsad_native_api_test_post_path_is_allowed (clone), is_true);
  assert_that (gsad_native_api_test_post_path_is_allowed (restore), is_true);
  assert_that (gsad_native_api_test_delete_path_is_allowed (detail), is_true);
  assert_that (gsad_native_api_test_delete_path_is_allowed (trash), is_true);

  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    {
      assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                   is_false);
      assert_that (
        gsad_native_api_test_delete_path_is_allowed (rejected[index]),
        is_false);
    }

  g_free (trash);
  g_free (restore);
  g_free (clone);
  g_free (detail);
}

/* Handler dependencies are not part of this parser-focused unit target. */
gsad_user_t *
gsad_credentials_get_user (gsad_credentials_t *credentials)
{
  if (credentials == (gsad_credentials_t *) GINT_TO_POINTER (1)
      || credentials == (gsad_credentials_t *) GINT_TO_POINTER (3)
      || credentials == (gsad_credentials_t *) GINT_TO_POINTER (4))
    return (gsad_user_t *) credentials;
  return NULL;
}

Ensure (gsad_native_api,
        should_allow_authentication_settings_read_and_provider_writes)
{
  assert_that (gsad_native_api_test_get_path_is_allowed (
                 "/api/v1/authentication-settings"),
               is_true);
  assert_that (gsad_native_api_test_get_path_requires_operator (
                 "/api/v1/authentication-settings"),
               is_true);
  assert_that (gsad_native_api_test_put_path_is_allowed (
                 "/api/v1/authentication-settings/ldap"),
               is_true);
  assert_that (gsad_native_api_test_put_path_is_allowed (
                 "/api/v1/authentication-settings/radius"),
               is_true);
  assert_that (gsad_native_api_test_get_path_is_allowed (
                 "/api/v1/authentication-settings/ldap"),
               is_false);
  assert_that (gsad_native_api_test_put_path_is_allowed (
                 "/api/v1/authentication-settings"),
               is_false);
  assert_that (gsad_native_api_test_put_path_is_allowed (
                 "/api/v1/authentication-settings/ldap/extra"),
               is_false);
  assert_that (gsad_native_api_test_put_path_is_allowed (
                 "/api/v1/authentication-settings/radius?x=1"),
               is_false);
  assert_that (gsad_native_api_test_get_path_requires_operator (
                 "/api/v1/cves"),
               is_false);
}

Ensure (gsad_native_api,
        should_only_allow_exact_current_user_setting_paths)
{
  const gchar *setting =
    "/api/v1/users/current/settings/"
    "12345678-1234-1234-1234-123456789abc";

  assert_that (
    gsad_native_api_test_get_path_is_allowed (
      "/api/v1/users/current/settings"),
    is_true);
  assert_that (gsad_native_api_test_get_path_is_allowed (setting), is_true);
  assert_that (gsad_native_api_test_put_path_is_allowed (setting), is_true);
  assert_that (
    gsad_native_api_test_put_path_is_allowed (
      "/api/v1/users/current/timezone"),
    is_true);
  assert_that (
    gsad_native_api_test_put_path_is_allowed (
      "/api/v1/users/current/settings"),
    is_false);
  assert_that (
    gsad_native_api_test_get_path_is_allowed (
      "/api/v1/users/current/timezone"),
    is_false);
  assert_that (
    gsad_native_api_test_get_path_is_allowed (
      "/api/v1/users/current/settings/not-a-uuid"),
    is_false);
  assert_that (
    gsad_native_api_test_put_path_is_allowed (
      "/api/v1/users/current/settings/"
      "12345678-1234-1234-1234-123456789abc/extra"),
    is_false);
}

gsad_settings_t *
gsad_settings_get_global_settings (void)
{
  return (gsad_settings_t *) GINT_TO_POINTER (1);
}

int
gsad_settings_get_session_timeout (const gsad_settings_t *settings)
{
  return settings == (gsad_settings_t *) GINT_TO_POINTER (1) ? 15 : 0;
}

const time_t
gsad_user_session_get_timeout (gsad_user_t *user)
{
  return user == (gsad_user_t *) GINT_TO_POINTER (1) ? 1234567890 : 0;
}

void
gsad_user_session_renew_timeout (gsad_user_t *user)
{
  (void) user;
}

Ensure (gsad_native_api,
        should_only_allow_canonical_scan_config_backup_and_import_paths)
{
  const gchar *backup =
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/backup";
  const gchar *import = "/api/v1/scan-configs/import";
  const gchar *rejected_gets[] = {
    "/api/v1/scan-configs/not-a-uuid/backup",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/backup/extra",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/backup?x=1",
  };
  const gchar *rejected_posts[] = {
    "/api/v1/scan-configs/import/",
    "/api/v1/scan-configs/import?x=1",
    "/api/v1/scan-configs/not-import",
  };

  assert_that (gsad_native_api_test_get_path_is_allowed (backup), is_true);
  assert_that (gsad_native_api_test_post_path_is_allowed (import), is_true);
  assert_that (gsad_native_api_test_get_path_is_allowed (import), is_false);
  assert_that (gsad_native_api_test_post_path_is_allowed (backup), is_false);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected_gets); index++)
    assert_that (gsad_native_api_test_get_path_is_allowed (
                   rejected_gets[index]),
                 is_false);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected_posts); index++)
    assert_that (gsad_native_api_test_post_path_is_allowed (
                   rejected_posts[index]),
                 is_false);
}

const gchar *
gsad_user_get_token (gsad_user_t *user)
{
  return user == (gsad_user_t *) GINT_TO_POINTER (1) ? "token" : NULL;
}

void
gsad_user_set_password (gsad_user_t *user, const gchar *password)
{
  (void) user;
  password_update_count++;
  updated_password = password;
}

void
gsad_session_remove_sessions_by_uuid (const gchar *keep_id, const gchar *uuid)
{
  session_revoke_count++;
  revoked_session_keep_id = keep_id;
  revoked_session_uuid = uuid;
}

void
gsad_session_replace_user_if_exists (gsad_user_t *user)
{
  (void) user;
  session_replace_count++;
}

void
gsad_credentials_free (gsad_credentials_t *credentials)
{
  (void) credentials;
}

Ensure (gsad_native_api,
        should_only_allow_exact_session_ping_and_renew_paths)
{
  assert_that (
    gsad_native_api_test_get_path_is_allowed ("/api/v1/session/ping"),
    is_true);
  assert_that (
    gsad_native_api_test_post_path_is_allowed ("/api/v1/session/renew"),
    is_true);
  assert_that (
    gsad_native_api_test_post_path_is_allowed ("/api/v1/session/ping"),
    is_false);
  assert_that (
    gsad_native_api_test_get_path_is_allowed ("/api/v1/session/renew"),
    is_false);
  assert_that (
    gsad_native_api_test_get_path_is_allowed ("/api/v1/session/ping/"),
    is_false);
  assert_that (
    gsad_native_api_test_post_path_is_allowed ("/api/v1/session/renew?x=1"),
    is_false);
}

Ensure (gsad_native_api,
        should_only_allow_strict_current_user_password_change_posts)
{
  const gchar *valid_path = "/api/v1/users/current/password";
  const gchar *valid_body =
    "{\"old_password\":\"old secret\",\"new_password\":\"new secret\"}";
  const gchar *invalid_bodies[] = {
    "{}",
    "{\"old_password\":\"\",\"new_password\":\"new secret\"}",
    "{\"old_password\":\"old secret\",\"new_password\":\"\"}",
    "{\"old_password\":\"old secret\",\"new_password\":\"new secret\","
    "\"extra\":true}",
    "{\"old_password\":\"old\\nsecret\",\"new_password\":\"new secret\"}",
  };
  gchar *new_password = NULL;

  assert_that (gsad_native_api_test_post_path_is_allowed (valid_path), is_true);
  assert_that (gsad_native_api_test_delete_path_is_allowed (valid_path),
               is_false);
  assert_that (gsad_native_api_test_post_path_is_allowed (
                 "/api/v1/users/current/password/"),
               is_false);
  assert_that (gsad_native_api_test_post_path_is_allowed (
                 "/api/v1/users/current/password?unexpected=query"),
               is_false);
  assert_that (gsad_native_api_test_parse_user_password_change_request (
                 valid_body, strlen (valid_body), &new_password),
               is_true);
  assert_that (new_password, is_equal_to_string ("new secret"));
  memset (new_password, 0, strlen (new_password));
  g_clear_pointer (&new_password, g_free);

  for (gsize index = 0; index < G_N_ELEMENTS (invalid_bodies); index++)
    {
      assert_that (gsad_native_api_test_parse_user_password_change_request (
                     invalid_bodies[index], strlen (invalid_bodies[index]),
                     &new_password),
                   is_false);
      assert_that (new_password, is_null);
    }
}

Ensure (gsad_native_api,
        should_only_capture_password_for_self_user_management_patch)
{
  const gchar *uuid = "12345678-1234-1234-1234-123456789abc";
  const gchar *self_path =
    "/api/v1/user-management/users/"
    "12345678-1234-1234-1234-123456789abc";
  const gchar *other_path =
    "/api/v1/user-management/users/"
    "abcdefab-cdef-cdef-cdef-abcdefabcdef";
  const gchar *with_password =
    "{\"name\":\"operator\",\"comment\":\"\","
    "\"auth_method\":\"password\",\"password\":\"new secret\"}";
  const gchar *without_password =
    "{\"name\":\"operator\",\"comment\":\"\","
    "\"auth_method\":\"password\"}";
  gchar *new_password = NULL;

  assert_that (gsad_native_api_test_extract_self_user_management_password (
                 "PATCH", self_path, uuid, with_password,
                 strlen (with_password), &new_password),
               is_true);
  assert_that (new_password, is_equal_to_string ("new secret"));
  memset (new_password, 0, strlen (new_password));
  g_clear_pointer (&new_password, g_free);

  assert_that (gsad_native_api_test_extract_self_user_management_password (
                 "PATCH", self_path, uuid, without_password,
                 strlen (without_password), &new_password),
               is_true);
  assert_that (new_password, is_null);

  assert_that (gsad_native_api_test_extract_self_user_management_password (
                 "PATCH", other_path, uuid, with_password,
                 strlen (with_password), &new_password),
               is_true);
  assert_that (new_password, is_null);

  assert_that (gsad_native_api_test_extract_self_user_management_password (
                 "PATCH", self_path, uuid,
                 "{\"password\":\"bad\\nsecret\"}",
                 strlen ("{\"password\":\"bad\\nsecret\"}"), &new_password),
               is_false);
  assert_that (new_password, is_null);
}

Ensure (gsad_native_api, should_revoke_affected_sessions_by_uuid)
{
  gsad_credentials_t *credentials =
    (gsad_credentials_t *) GINT_TO_POINTER (1);
  const gchar *operator_uuid = "12345678-1234-1234-1234-123456789abc";
  const gchar *other_path =
    "/api/v1/user-management/users/"
    "abcdefab-cdef-cdef-cdef-abcdefabcdef";

  password_update_count = 0;
  session_revoke_count = 0;
  session_replace_count = 0;
  updated_password = NULL;
  revoked_session_keep_id = NULL;
  revoked_session_uuid = NULL;

  assert_that (gsad_native_api_test_update_sessions_after_native_success (
                 credentials, "POST", "/api/v1/users/current/password",
                 operator_uuid, "new secret", MHD_HTTP_BAD_REQUEST),
               is_true);
  assert_that (password_update_count, is_equal_to (0));
  assert_that (session_revoke_count, is_equal_to (0));
  assert_that (session_replace_count, is_equal_to (0));

  assert_that (gsad_native_api_test_update_sessions_after_native_success (
                 credentials, "POST", "/api/v1/users/current/password",
                 operator_uuid, "new secret", MHD_HTTP_OK),
               is_true);
  assert_that (password_update_count, is_equal_to (1));
  assert_that (session_revoke_count, is_equal_to (1));
  assert_that (session_replace_count, is_equal_to (1));
  assert_that (updated_password, is_equal_to_string ("new secret"));
  assert_that (revoked_session_keep_id, is_equal_to_string ("token"));
  assert_that (revoked_session_uuid, is_equal_to_string (operator_uuid));

  assert_that (gsad_native_api_test_update_sessions_after_native_success (
                 credentials, "PATCH", other_path, operator_uuid, NULL,
                 MHD_HTTP_OK),
               is_true);
  assert_that (password_update_count, is_equal_to (1));
  assert_that (session_revoke_count, is_equal_to (2));
  assert_that (session_replace_count, is_equal_to (1));
  assert_that (revoked_session_keep_id, is_null);
  assert_that (revoked_session_uuid,
               is_equal_to_string ("abcdefab-cdef-cdef-cdef-abcdefabcdef"));
  assert_that (gsad_native_api_test_affected_session_uuid (
                 "DELETE", other_path, operator_uuid),
               is_equal_to_string ("abcdefab-cdef-cdef-cdef-abcdefabcdef"));
  assert_that (gsad_native_api_test_affected_session_uuid (
                 "POST", "/api/v1/user-management/users", operator_uuid),
               is_null);

  assert_that (gsad_native_api_test_update_sessions_after_native_success (
                 (gsad_credentials_t *) GINT_TO_POINTER (2), "POST",
                 "/api/v1/users/current/password", operator_uuid,
                 "new secret", MHD_HTTP_NO_CONTENT),
               is_false);
  assert_that (password_update_count, is_equal_to (1));
}

Ensure (gsad_native_api,
        should_fail_closed_for_indeterminate_user_authentication_mutations)
{
  const gchar *operator_uuid = "12345678-1234-1234-1234-123456789abc";
  const gchar *other_path =
    "/api/v1/user-management/users/"
    "abcdefab-cdef-cdef-cdef-abcdefabcdef";

  session_revoke_count = 0;
  revoked_session_keep_id = NULL;
  revoked_session_uuid = NULL;

  gsad_native_api_test_revoke_sessions_after_indeterminate_native_mutation (
    "POST", "/api/v1/users/current/password", operator_uuid, FALSE);
  assert_that (session_revoke_count, is_equal_to (0));

  gsad_native_api_test_revoke_sessions_after_indeterminate_native_mutation (
    "POST", "/api/v1/users/current/password", operator_uuid, TRUE);
  assert_that (session_revoke_count, is_equal_to (1));
  assert_that (revoked_session_keep_id, is_null);
  assert_that (revoked_session_uuid, is_equal_to_string (operator_uuid));

  gsad_native_api_test_revoke_sessions_after_indeterminate_native_mutation (
    "PATCH", other_path, operator_uuid, TRUE);
  assert_that (session_revoke_count, is_equal_to (2));
  assert_that (revoked_session_keep_id, is_null);
  assert_that (revoked_session_uuid,
               is_equal_to_string ("abcdefab-cdef-cdef-cdef-abcdefabcdef"));
}

Ensure (gsad_native_api,
        should_recognize_complete_indeterminate_mutation_responses)
{
  const gchar *committed =
    "{\"error\":{\"code\":\"committed_response_unavailable\","
    "\"message\":\"verify state\"}}";
  const gchar *indeterminate =
    "{\"error\":{\"code\":\"mutation_outcome_indeterminate\","
    "\"message\":\"verify state\"}}";
  const gchar *rejected =
    "{\"error\":{\"code\":\"bad_request\",\"message\":\"no\"}}";

  assert_that (gsad_native_api_test_mutation_response_may_have_committed (
                 "PATCH", MHD_HTTP_BAD_GATEWAY, committed),
               is_true);
  assert_that (gsad_native_api_test_mutation_response_may_have_committed (
                 "DELETE", MHD_HTTP_BAD_GATEWAY, indeterminate),
               is_true);
  assert_that (gsad_native_api_test_mutation_response_may_have_committed (
                 "PATCH", MHD_HTTP_BAD_GATEWAY, rejected),
               is_false);
  assert_that (gsad_native_api_test_mutation_response_may_have_committed (
                 "GET", MHD_HTTP_BAD_GATEWAY, committed),
               is_false);
  assert_that (gsad_native_api_test_mutation_response_may_have_committed (
                 "PATCH", MHD_HTTP_CONFLICT, committed),
               is_false);
}

const gchar *
gsad_user_get_username (gsad_user_t *user)
{
  return user == (gsad_user_t *) GINT_TO_POINTER (1)
             || user == (gsad_user_t *) GINT_TO_POINTER (3)
             || user == (gsad_user_t *) GINT_TO_POINTER (4)
           ? "operator"
           : NULL;
}

const gchar *
gsad_user_get_uuid (gsad_user_t *user)
{
  if (user == (gsad_user_t *) GINT_TO_POINTER (1))
    return "12345678-1234-1234-1234-123456789abc";
  if (user == (gsad_user_t *) GINT_TO_POINTER (4))
    return "not-a-uuid";
  return NULL;
}

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

Ensure (gsad_native_api,
        should_only_allow_canonical_scan_config_family_nvt_gets)
{
  const gchar *valid =
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port%20scanners/nvts";
  const gchar *rejected[] = {
    "/api/v1/scan-configs/not-a-uuid/families/Port%20scanners/nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port/scanners/nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port%2Fscanners/nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/../nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port%20scanners/nvts?x=1",
  };

  assert_that (gsad_native_api_test_get_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_get_path_is_allowed (rejected[index]),
                 is_false);
}

Ensure (gsad_native_api,
        should_only_allow_canonical_scan_config_family_nvt_patches)
{
  const gchar *valid =
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port%20scanners/nvts";
  const gchar *rejected[] = {
    "/api/v1/scan-configs/not-a-uuid/families/Port%20scanners/nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port/scanners/nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port%2Fscanners/nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/../nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/%2E%2E/nvts",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port%20scanners/nvts?x=1",
    "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port%20scanners/nvts/",
  };

  assert_that (gsad_native_api_test_patch_path_is_allowed (valid), is_true);
  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    assert_that (gsad_native_api_test_patch_path_is_allowed (rejected[index]),
                 is_false);
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
  assert_that (gsad_native_api_test_browser_credentials_are_session_bound (
                 (gsad_credentials_t *) GINT_TO_POINTER (3)),
               is_false);
  assert_that (gsad_native_api_test_browser_credentials_are_session_bound (
                 (gsad_credentials_t *) GINT_TO_POINTER (4)),
               is_false);
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

Ensure (gsad_native_api, should_only_allow_exact_user_management_paths)
{
  const gchar *id = "12345678-1234-1234-1234-123456789abc";
  gchar *detail = g_strdup_printf ("/api/v1/user-management/users/%s", id);
  gchar *clone = g_strdup_printf ("%s/clone", detail);
  gchar *target = NULL;
  const gchar *rejected[] = {
    "/api/v1/user-management/users/",
    "/api/v1/user-management/users/not-a-uuid",
    "/api/v1/user-management/users/12345678-1234-1234-1234-123456789abc/extra",
    "/api/v1/user-management/users/12345678-1234-1234-1234-123456789abc?unexpected=query",
  };

  assert_that (gsad_native_api_test_get_path_is_allowed (
                 "/api/v1/user-management/users"),
               is_true);
  assert_that (gsad_native_api_test_get_path_is_allowed (detail), is_true);
  assert_that (gsad_native_api_test_post_path_is_allowed (
                 "/api/v1/user-management/users"),
               is_true);
  assert_that (gsad_native_api_test_post_path_is_allowed (clone), is_true);
  assert_that (gsad_native_api_test_patch_path_is_allowed (detail), is_true);
  assert_that (gsad_native_api_test_delete_path_is_allowed (detail), is_true);
  assert_that (gsad_native_api_test_post_path_is_allowed (detail), is_false);
  assert_that (gsad_native_api_test_patch_path_is_allowed (
                 "/api/v1/user-management/users"),
               is_false);
  assert_that (gsad_native_api_test_delete_path_is_allowed (
                 "/api/v1/user-management/users"),
               is_false);

  for (gsize index = 0; index < G_N_ELEMENTS (rejected); index++)
    {
      assert_that (gsad_native_api_test_get_path_is_allowed (rejected[index]),
                   is_false);
      assert_that (gsad_native_api_test_post_path_is_allowed (rejected[index]),
                   is_false);
      assert_that (gsad_native_api_test_patch_path_is_allowed (rejected[index]),
                   is_false);
      assert_that (
        gsad_native_api_test_delete_path_is_allowed (rejected[index]),
        is_false);
    }

  assert_that (gsad_native_api_test_user_management_delete_target (
                 detail, "abcdefab-cdef-cdef-cdef-abcdefabcdef", &target),
               is_true);
  assert_that (target, is_equal_to_string (
                        "/api/v1/user-management/users/"
                        "12345678-1234-1234-1234-123456789abc"
                        "?inheritor_id=abcdefab-cdef-cdef-cdef-abcdefabcdef"));
  g_free (target);
  target = NULL;

  assert_that (gsad_native_api_test_user_management_delete_target (
                 detail, "not-a-uuid", &target),
               is_false);
  assert_that (gsad_native_api_test_user_management_delete_target (
                 detail, NULL, &target),
               is_true);
  assert_that (target, is_equal_to_string (detail));
  g_free (target);
  g_free (clone);
  g_free (detail);
}

const gchar *
params_value (params_t *params, const gchar *name)
{
  if (params == (params_t *) GINT_TO_POINTER (5))
    {
      if (g_strcmp0 (name, "page") == 0)
        return "2";
      if (g_strcmp0 (name, "task_id") == 0)
        return "12345678-1234-1234-1234-123456789abc";
      if (g_strcmp0 (name, "nvt_oid") == 0)
        return "1.3.6.1.4.1.25623.1.0.900001";
      if (g_strcmp0 (name, "vulnerability_id") == 0)
        return "1.3.6.1.4.1.25623.1.0.900001";
      if (g_strcmp0 (name, "name") == 0)
        return "192.0.2.10";
      if (g_strcmp0 (name, "predefined") == 0)
        return "1";
      if (g_strcmp0 (name, "credential_type") == 0)
        return "up";
    }
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
  add_test_with_context (
    suite, gsad_native_api,
    should_forward_typed_filters_for_collection_reads);
  add_test_with_context (suite, gsad_native_api,
                         should_require_a_session_user_for_browser_reads);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_alert_definition_get_and_put);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_scan_config_family_nvt_gets);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_scan_config_backup_and_import_paths);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_scan_config_family_nvt_patches);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_canonical_task_clone_posts);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_canonical_task_restore_posts);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_canonical_task_trash_delete);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_credential_restore_posts);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_credential_trash_delete);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_canonical_alert_test_posts);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_alert_trash_lifecycle);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_strict_current_user_password_change_posts);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_capture_password_for_self_user_management_patch);
  add_test_with_context (
    suite, gsad_native_api,
    should_revoke_affected_sessions_by_uuid);
  add_test_with_context (
    suite, gsad_native_api,
    should_fail_closed_for_indeterminate_user_authentication_mutations);
  add_test_with_context (
    suite, gsad_native_api,
    should_recognize_complete_indeterminate_mutation_responses);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_exact_session_ping_and_renew_paths);
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_exact_current_user_setting_paths);
  add_test_with_context (
    suite, gsad_native_api,
    should_allow_authentication_settings_read_and_provider_writes);
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
  add_test_with_context (
    suite, gsad_native_api,
    should_only_allow_canonical_scanner_lifecycle_paths);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_canonical_override_mutations);
  add_test_with_context (suite, gsad_native_api,
                         should_only_allow_exact_user_management_paths);
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
