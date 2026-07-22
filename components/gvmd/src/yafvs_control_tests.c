/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define copy_user yafvs_control_test_copy_user
#define g_log_structured yafvs_control_test_log_structured
#define manage_auth_settings_clear \
  yafvs_control_test_manage_auth_settings_clear
#define manage_auth_settings_read yafvs_control_test_manage_auth_settings_read
#define manage_auth_settings_write_ldap \
  yafvs_control_test_manage_auth_settings_write_ldap
#define manage_auth_settings_write_radius \
  yafvs_control_test_manage_auth_settings_write_radius
#include "yafvs_control.c"
#undef manage_auth_settings_write_radius
#undef manage_auth_settings_write_ldap
#undef manage_auth_settings_read
#undef manage_auth_settings_clear
#undef g_log_structured
#undef copy_user

#include <cgreen/cgreen.h>
#include <stdarg.h>
#include <string.h>

#define TEST_CONTROL_SECRET "0123456789abcdef0123456789abcdef"
#define TEST_TRASH_SNAPSHOT_DIGEST \
  "0000000000000000000000000000000000000000000000000000000000000000"
#define TEST_DIAGNOSTIC_NMAP_OID "1.3.6.1.4.1.25623.1.0.14259"
#define TEST_DIAGNOSTIC_PING_OID "1.3.6.1.4.1.25623.1.0.100315"
#define TEST_DIAGNOSTIC_PREREQUISITE_FAMILY "Port scanners"

Describe (yafvs_control);
BeforeEach (yafvs_control) {}
AfterEach (yafvs_control) {}

static int cleanup_calls;
static int alert_test_calls;
static int alert_test_result;
static int alert_test_audit_fail_calls;
static int alert_test_audit_success_calls;
static int alert_delivery_calls;
static int alert_delivery_result;
static int alert_delivery_audit_fail_calls;
static int alert_delivery_audit_success_calls;
static gboolean alert_delivery_active;
static gboolean alert_delivery_alert_exists;
static gboolean alert_delivery_report_exists;
static gboolean alert_delivery_filter_exists;
static alert_method_t alert_delivery_method;
static int create_alert_calls;
static int create_alert_result;
static int create_user_calls;
static int create_user_result;
static int clone_user_calls;
static int clone_user_result;
static int clone_user_audit_fail_calls;
static int clone_user_audit_success_calls;
static int delete_user_calls;
static int delete_user_result;
static int create_schedule_calls;
static int create_credential_calls;
static int create_credential_result;
static int create_schedule_result;
static int diagnostic_audit_fail_calls;
static int diagnostic_audit_success_calls;
static int diagnostic_control_calls;
static int diagnostic_control_result;
static gboolean diagnostic_control_changed;
static gboolean diagnostic_control_committed;
static int modify_schedule_calls;
static int modify_schedule_result;
static int modify_user_calls;
static int modify_user_result;
static int modify_setting_calls;
static modify_setting_result_t modify_setting_result;
static int modify_tag_calls;
static int modify_tag_result;
static int tag_audit_fail_calls;
static int tag_audit_success_calls;
static int reinit_calls;
static int session_init_calls;
static int stop_task_calls;
static int clone_task_calls;
static int clone_task_result;
static gboolean task_uuid_lookup_fails;
static int task_audit_fail_calls;
static int task_audit_success_calls;
static int trash_empty_calls;
static int trash_empty_result;
static gint64 trash_empty_actual;
static gint64 trash_empty_expected;
static int trash_empty_audit_fail_calls;
static int trash_empty_audit_success_calls;
static int trash_empty_structured_audit_calls;
static int audit_fail_calls;
static int audit_success_calls;
static int auth_settings_read_calls;
static int auth_settings_read_result;
static int auth_settings_ldap_write_calls;
static int auth_settings_ldap_write_result;
static int auth_settings_radius_write_calls;
static int auth_settings_radius_write_result;
static int received_auth_enabled;
static int received_auth_allow_plaintext;
static int received_auth_ldaps_only;
static gchar *received_auth_host;
static gchar *received_authdn;
static gchar *received_auth_cacert;
static gchar *received_radius_secret;
static const char *alert_test_script_message;
static const char *mock_operator_name;
static const char *mock_target_auth_method;
static const char *mock_target_name;
static gboolean user_uuid_lookup_fails;
static gboolean alert_uuid_lookup_fails;
static alert_condition_t received_alert_condition;
static alert_method_t received_alert_method;
static event_t received_alert_event;
static gchar *received_active;
static gchar *received_event_status;
static gchar *received_from_address;
static gchar *received_message;
static gchar *received_notice;
static gchar *received_recipient_credential;
static gchar *received_report_format;
static gchar *received_atomic_report_format;
static gchar *received_subject;
static gchar *received_start_task_uuid;
static gchar *received_to_address;
static gchar *received_smb_credential;
static gchar *received_smb_file_path;
static gchar *received_smb_max_protocol;
static gchar *received_smb_share_path;
static gchar *received_scp_credential;
static gchar *received_scp_host;
static gchar *received_scp_port;
static gchar *received_scp_known_hosts;
static gchar *received_scp_path;
static gchar *received_snmp_agent;
static gchar *received_snmp_community;
static gchar *received_snmp_message;
static gchar *received_syslog_submethod;
static gchar *received_audit_uuid;
static gchar *received_alert_test_uuid;
static gchar *received_alert_delivery_uuid;
static gchar *received_alert_delivery_report_uuid;
static gchar *received_alert_delivery_filter;
static gchar *received_alert_delivery_filter_uuid;
static gchar *received_credential_type;
static gchar *received_comment;
static gchar *received_icalendar;
static gchar *received_key_private;
static gchar *received_login;
static gchar *received_name;
static gchar *received_secret;
static gchar *received_schedule_uuid;
static gchar *received_setting_name;
static gchar *received_setting_uuid;
static gchar *received_setting_value_64;
static gchar *received_tag_uuid;
static gchar *received_tag_resource_type;
static gchar *received_tag_resource_filter;
static gchar *received_tag_resources_action;
static gchar *received_tag_active;
static gchar *received_tag_first_resource_id;
static gchar *received_timezone;
static gchar *received_user_inheritor_uuid;
static gchar *received_user_method;
static gchar *received_user_target_uuid;
static gchar *received_diagnostic_config_uuid;
static gchar *received_diagnostic_nvt_oid;
static gchar *trash_empty_audit_actual_total;
static gchar *trash_empty_audit_expected_total;
static gchar *trash_empty_audit_message;
static gchar *trash_empty_audit_operator_uuid;
static gchar *trash_empty_audit_outcome;
static gboolean auth_settings_empty_required;

manage_auth_settings_result_t
yafvs_control_test_manage_auth_settings_read (
  manage_auth_settings_t *settings)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  auth_settings_read_calls++;
  if (auth_settings_read_result != MANAGE_AUTH_SETTINGS_OK)
    return auth_settings_read_result;

  memset (settings, 0, sizeof (*settings));
  settings->ldap_available = 1;
  settings->ldap_enabled = 1;
  settings->ldap_host =
    g_strdup (auth_settings_empty_required ? "" : "ldap.example.test");
  settings->ldap_authdn = g_strdup (
    auth_settings_empty_required ? "" : "uid=%s,dc=example,dc=test");
  settings->ldap_allow_plaintext = 0;
  settings->ldap_ldaps_only = 1;
  settings->ldap_cert_present = 1;
  settings->ldap_cert_sha256 = g_strdup ("A1B2C3");
  settings->ldap_cert_issuer = g_strdup ("CN=Example CA");
  settings->ldap_cert_activation = g_strdup ("2026-01-01T00:00:00Z");
  settings->ldap_cert_expiration = g_strdup ("2027-01-01T00:00:00Z");
  settings->ldap_cert_time_status = g_strdup ("valid");
  settings->radius_available = 1;
  settings->radius_enabled = 0;
  settings->radius_host =
    g_strdup (auth_settings_empty_required ? "" : "radius.example.test");
  settings->radius_secret_configured = 1;
  return MANAGE_AUTH_SETTINGS_OK;
}

void
yafvs_control_test_manage_auth_settings_clear (
  manage_auth_settings_t *settings)
{
  g_clear_pointer (&settings->ldap_host, g_free);
  g_clear_pointer (&settings->ldap_authdn, g_free);
  g_clear_pointer (&settings->ldap_cert_sha256, g_free);
  g_clear_pointer (&settings->ldap_cert_issuer, g_free);
  g_clear_pointer (&settings->ldap_cert_activation, g_free);
  g_clear_pointer (&settings->ldap_cert_expiration, g_free);
  g_clear_pointer (&settings->ldap_cert_time_status, g_free);
  g_clear_pointer (&settings->radius_host, g_free);
  memset (settings, 0, sizeof (*settings));
}

manage_auth_settings_result_t
yafvs_control_test_manage_auth_settings_write_ldap (
  int enabled, const gchar *host, const gchar *authdn, int allow_plaintext,
  int ldaps_only, const gchar *cacert)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  auth_settings_ldap_write_calls++;
  received_auth_enabled = enabled;
  received_auth_allow_plaintext = allow_plaintext;
  received_auth_ldaps_only = ldaps_only;
  g_free (received_auth_host);
  g_free (received_authdn);
  g_free (received_auth_cacert);
  received_auth_host = g_strdup (host);
  received_authdn = g_strdup (authdn);
  received_auth_cacert = g_strdup (cacert);
  return auth_settings_ldap_write_result;
}

manage_auth_settings_result_t
yafvs_control_test_manage_auth_settings_write_radius (
  int enabled, const gchar *host, const gchar *secret)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  auth_settings_radius_write_calls++;
  received_auth_enabled = enabled;
  g_free (received_auth_host);
  g_free (received_radius_secret);
  received_auth_host = g_strdup (host);
  received_radius_secret = g_strdup (secret);
  return auth_settings_radius_write_result;
}

static void
assert_trash_empty_audit_operator_session (void)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  assert_that (cleanup_calls, is_equal_to (0));
}

modify_setting_result_t
__wrap_modify_setting (const gchar *uuid, const gchar *name,
                       const gchar *value_64, gchar **error_description)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  modify_setting_calls++;
  g_free (received_setting_uuid);
  g_free (received_setting_name);
  g_free (received_setting_value_64);
  received_setting_uuid = g_strdup (uuid);
  received_setting_name = g_strdup (name);
  received_setting_value_64 = g_strdup (value_64);
  if (error_description)
    *error_description = modify_setting_result == MODIFY_SETTING_RESULT_ERROR
                           ? g_strdup ("private setting error")
                           : NULL;
  return modify_setting_result;
}

void
yafvs_control_test_log_structured (const gchar *log_domain,
                                      GLogLevelFlags log_level, ...)
{
  const gchar *format;
  const gchar *field_name;
  const gchar *message;
  const gchar *operator_uuid;
  const gchar *outcome;
  const gchar *next_field;
  const gchar *terminator;
  gint64 actual_total;
  gint64 expected_total;
  va_list args;

  assert_trash_empty_audit_operator_session ();
  assert_that (log_domain, is_equal_to_string (G_LOG_DOMAIN));
  assert_that (log_level, is_equal_to (G_LOG_LEVEL_MESSAGE));
  va_start (args, log_level);
  field_name = va_arg (args, const gchar *);
  assert_that (field_name, is_equal_to_string ("MESSAGE"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%s"));
  message = va_arg (args, const gchar *);
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("YAFVS_AUDIT_ACTION"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%s"));
  assert_that (va_arg (args, const gchar *), is_equal_to_string ("trash-empty"));
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("YAFVS_OPERATOR_UUID"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%s"));
  operator_uuid = va_arg (args, const gchar *);
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("YAFVS_OUTCOME"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%s"));
  outcome = va_arg (args, const gchar *);
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("YAFVS_EXPECTED_TOTAL"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%" G_GINT64_FORMAT));
  expected_total = va_arg (args, gint64);
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("YAFVS_ACTUAL_TOTAL"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%" G_GINT64_FORMAT));
  actual_total = va_arg (args, gint64);
  terminator = va_arg (args, const gchar *);
  va_end (args);
  assert_that (terminator, is_null);

  trash_empty_structured_audit_calls++;
  g_free (trash_empty_audit_message);
  g_free (trash_empty_audit_operator_uuid);
  g_free (trash_empty_audit_outcome);
  g_free (trash_empty_audit_expected_total);
  g_free (trash_empty_audit_actual_total);
  trash_empty_audit_message = g_strdup (message);
  trash_empty_audit_operator_uuid = g_strdup (operator_uuid);
  trash_empty_audit_outcome = g_strdup (outcome);
  trash_empty_audit_expected_total =
    g_strdup_printf ("%" G_GINT64_FORMAT, expected_total);
  trash_empty_audit_actual_total =
    g_strdup_printf ("%" G_GINT64_FORMAT, actual_total);
}

static void
reset_trash_empty_audit (void)
{
  trash_empty_audit_fail_calls = 0;
  trash_empty_audit_success_calls = 0;
  trash_empty_structured_audit_calls = 0;
  g_clear_pointer (&trash_empty_audit_message, g_free);
  g_clear_pointer (&trash_empty_audit_operator_uuid, g_free);
  g_clear_pointer (&trash_empty_audit_outcome, g_free);
  g_clear_pointer (&trash_empty_audit_expected_total, g_free);
  g_clear_pointer (&trash_empty_audit_actual_total, g_free);
}

gchar *
__wrap_user_name (const char *uuid)
{
  return strcmp (uuid, "123e4567-e89b-12d3-a456-426614174000") == 0
           ? mock_operator_name ? g_strdup (mock_operator_name) : NULL
           : mock_target_name ? g_strdup (mock_target_name) : NULL;
}

gchar *
__wrap_user_auth_method (const char *uuid)
{
  (void) uuid;
  return mock_target_auth_method ? g_strdup (mock_target_auth_method) : NULL;
}

char *
__wrap_user_uuid (user_t user)
{
  return user == 11 && !user_uuid_lookup_fails
           ? g_strdup ("123e4567-e89b-12d3-a456-426614174003") : NULL;
}

int
__wrap_create_user (const gchar *name, const gchar *password,
                    const gchar *comment, const array_t *allowed_methods,
                    gchar **error_description, user_t *user)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  create_user_calls++;
  g_free (received_name);
  g_free (received_comment);
  g_free (received_user_method);
  received_name = g_strdup (name);
  received_comment = g_strdup (comment);
  received_user_method = g_strdup (g_ptr_array_index (allowed_methods, 0));
  assert_that (password, is_equal_to_string (""));
  assert_that (allowed_methods->len, is_equal_to (2));
  assert_that (g_ptr_array_index (allowed_methods, 1), is_null);
  assert_that (error_description, is_null);
  *user = 11;
  return create_user_result;
}

int
yafvs_control_test_copy_user (const char *name, const char *comment,
                                 const char *user_id, user_t *new_user)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  clone_user_calls++;
  g_free (received_user_target_uuid);
  received_user_target_uuid = g_strdup (user_id);
  assert_that (name, is_null);
  assert_that (comment, is_null);
  *new_user = 11;
  return clone_user_result;
}

Ensure (yafvs_control,
        reports_committed_user_create_when_uuid_lookup_fails)
{
  yafvs_control_user_create_request_t create = {0};
  char created_uuid[37];

  create_user_result = 0;
  mock_operator_name = "operator";
  user_uuid_lookup_fails = TRUE;
  g_strlcpy (create.method, "ldap_connect", sizeof (create.method));
  create.name = g_strdup ("created");
  create.comment = g_strdup ("comment");

  assert_that (yafvs_control_create_user (
                 "123e4567-e89b-12d3-a456-426614174000", &create,
                 created_uuid), is_equal_to (-3));
  assert_that (created_uuid, is_equal_to_string (""));

  user_uuid_lookup_fails = FALSE;
  yafvs_control_user_create_request_clear (&create);
}

int
__wrap_modify_user (const gchar *user_id, gchar **name, const gchar *new_name,
                    const gchar *password, const gchar *comment,
                    const array_t *allowed_methods, gchar **error_description)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  modify_user_calls++;
  g_free (received_user_target_uuid);
  g_free (received_name);
  g_free (received_comment);
  g_free (received_user_method);
  received_user_target_uuid = g_strdup (user_id);
  received_name = g_strdup (new_name);
  received_comment = g_strdup (comment);
  received_user_method = g_strdup (g_ptr_array_index (allowed_methods, 0));
  assert_that (
    *name,
    is_equal_to_string (
      strcmp (user_id, "123e4567-e89b-12d3-a456-426614174000") == 0
        ? mock_operator_name
        : mock_target_name));
  assert_that (password, is_null);
  assert_that (allowed_methods->len, is_equal_to (2));
  assert_that (g_ptr_array_index (allowed_methods, 1), is_null);
  assert_that (error_description, is_null);
  return modify_user_result;
}

int
__wrap_delete_user (const char *user_id, const char *name,
                    int forbid_super_admin, const char *inheritor_id,
                    const char *inheritor_name)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  delete_user_calls++;
  g_free (received_user_target_uuid);
  g_free (received_user_inheritor_uuid);
  received_user_target_uuid = g_strdup (user_id);
  received_user_inheritor_uuid = g_strdup (inheritor_id);
  assert_that (name, is_null);
  assert_that (forbid_super_admin, is_equal_to (1));
  assert_that (inheritor_name, is_null);
  return delete_user_result;
}

static const char *
test_alert_data_value (GPtrArray *array, const char *name)
{
  guint index;

  for (index = 0; index < array->len; index++)
    {
      const char *item = g_ptr_array_index (array, index);

      if (item && strcmp (item, name) == 0)
        return item + strlen (item) + 1;
    }
  return NULL;
}

int
__wrap_create_alert_email_with_report_refs
  (const char *name, const char *comment, const char *active,
   GPtrArray *event_data, GPtrArray *condition_data, GPtrArray *method_data,
   const char *recipient_credential_id, const char *report_format_id,
   alert_t *alert)
{
  (void) name;
  (void) comment;
  create_alert_calls++;
  received_alert_event = EVENT_TASK_RUN_STATUS_CHANGED;
  received_alert_condition = ALERT_CONDITION_ALWAYS;
  received_alert_method = ALERT_METHOD_EMAIL;
  g_free (received_active);
  g_free (received_event_status);
  g_free (received_to_address);
  g_free (received_from_address);
  g_free (received_subject);
  g_free (received_notice);
  g_free (received_recipient_credential);
  g_free (received_report_format);
  g_free (received_atomic_report_format);
  g_free (received_message);
  received_active = g_strdup (active);
  received_event_status = g_strdup (test_alert_data_value (event_data,
                                                            "status"));
  received_to_address = g_strdup (test_alert_data_value (method_data,
                                                         "to_address"));
  received_from_address = g_strdup (test_alert_data_value (method_data,
                                                           "from_address"));
  received_subject = g_strdup (test_alert_data_value (method_data, "subject"));
  received_notice = g_strdup (test_alert_data_value (method_data, "notice"));
  received_recipient_credential =
    g_strdup (test_alert_data_value (method_data, "recipient_credential"));
  received_report_format =
    g_strdup (test_alert_data_value (method_data, "notice_report_format"));
  if (received_report_format == NULL)
    received_report_format =
      g_strdup (test_alert_data_value (method_data, "notice_attach_format"));
  received_message = g_strdup (test_alert_data_value (method_data, "message"));
  received_atomic_report_format = g_strdup (report_format_id);
  assert_that (
    recipient_credential_id,
    is_equal_to_string (received_recipient_credential
                          ? received_recipient_credential : ""));
  assert_that (condition_data->len, is_equal_to (1));
  assert_that (g_ptr_array_index (condition_data, 0), is_null);
  *alert = 9;
  return create_alert_result;
}

int
__wrap_create_alert_task_status_changed (
  const char *name, const char *comment, const char *active,
  GPtrArray *event_data, GPtrArray *condition_data, alert_method_t method,
  GPtrArray *method_data, alert_t *alert)
{
  (void) name;
  (void) comment;
  create_alert_calls++;
  received_alert_event = EVENT_TASK_RUN_STATUS_CHANGED;
  received_alert_condition = ALERT_CONDITION_ALWAYS;
  received_alert_method = method;
  g_free (received_active);
  g_free (received_event_status);
  g_free (received_syslog_submethod);
  g_free (received_snmp_agent);
  g_free (received_snmp_community);
  g_free (received_snmp_message);
  received_active = g_strdup (active);
  received_event_status =
    g_strdup (test_alert_data_value (event_data, "status"));
  received_syslog_submethod =
    g_strdup (test_alert_data_value (method_data, "submethod"));
  received_snmp_agent =
    g_strdup (test_alert_data_value (method_data, "snmp_agent"));
  received_snmp_community =
    g_strdup (test_alert_data_value (method_data, "snmp_community"));
  received_snmp_message =
    g_strdup (test_alert_data_value (method_data, "snmp_message"));
  assert_that (condition_data->len, is_equal_to (1));
  assert_that (g_ptr_array_index (condition_data, 0), is_null);
  *alert = 9;
  return create_alert_result;
}

int
__wrap_create_alert_start_task_with_task_ref (
  const char *name, const char *comment, const char *active,
  GPtrArray *event_data, GPtrArray *condition_data, const char *task_id,
  alert_t *alert)
{
  (void) name;
  (void) comment;
  create_alert_calls++;
  received_alert_event = EVENT_TASK_RUN_STATUS_CHANGED;
  received_alert_condition = ALERT_CONDITION_ALWAYS;
  received_alert_method = ALERT_METHOD_START_TASK;
  g_free (received_active);
  g_free (received_event_status);
  g_free (received_start_task_uuid);
  received_active = g_strdup (active);
  received_event_status =
    g_strdup (test_alert_data_value (event_data, "status"));
  received_start_task_uuid = g_strdup (task_id);
  assert_that (task_id, is_equal_to_string (received_start_task_uuid));
  assert_that (condition_data->len, is_equal_to (1));
  assert_that (g_ptr_array_index (condition_data, 0), is_null);
  *alert = 9;
  return create_alert_result;
}

int
__wrap_create_alert_smb_with_report_refs (
  const char *name, const char *comment, const char *active,
  GPtrArray *event_data, GPtrArray *condition_data, GPtrArray *method_data,
  const char *smb_credential_id, const char *report_format_id, alert_t *alert)
{
  (void) name;
  (void) comment;
  create_alert_calls++;
  received_alert_event = EVENT_TASK_RUN_STATUS_CHANGED;
  received_alert_condition = ALERT_CONDITION_ALWAYS;
  received_alert_method = ALERT_METHOD_SMB;
  g_free (received_active);
  g_free (received_event_status);
  g_free (received_smb_credential);
  g_free (received_smb_share_path);
  g_free (received_smb_file_path);
  g_free (received_report_format);
  g_free (received_atomic_report_format);
  g_free (received_smb_max_protocol);
  received_active = g_strdup (active);
  received_event_status =
    g_strdup (test_alert_data_value (event_data, "status"));
  received_smb_credential =
    g_strdup (test_alert_data_value (method_data, "smb_credential"));
  received_smb_share_path =
    g_strdup (test_alert_data_value (method_data, "smb_share_path"));
  received_smb_file_path =
    g_strdup (test_alert_data_value (method_data, "smb_file_path"));
  received_report_format =
    g_strdup (test_alert_data_value (method_data, "smb_report_format"));
  received_smb_max_protocol =
    g_strdup (test_alert_data_value (method_data, "smb_max_protocol"));
  received_atomic_report_format = g_strdup (report_format_id);
  assert_that (smb_credential_id, is_equal_to_string (received_smb_credential));
  assert_that (condition_data->len, is_equal_to (1));
  assert_that (g_ptr_array_index (condition_data, 0), is_null);
  *alert = 9;
  return create_alert_result;
}

int
__wrap_create_alert_scp_with_report_refs (
  const char *name, const char *comment, const char *active,
  GPtrArray *event_data, GPtrArray *condition_data, GPtrArray *method_data,
  const char *scp_credential_id, const char *report_format_id, alert_t *alert)
{
  (void) name;
  (void) comment;
  create_alert_calls++;
  received_alert_event = EVENT_TASK_RUN_STATUS_CHANGED;
  received_alert_condition = ALERT_CONDITION_ALWAYS;
  received_alert_method = ALERT_METHOD_SCP;
  g_free (received_active);
  g_free (received_event_status);
  g_free (received_scp_credential);
  g_free (received_scp_host);
  g_free (received_scp_port);
  g_free (received_scp_known_hosts);
  g_free (received_scp_path);
  g_free (received_report_format);
  g_free (received_atomic_report_format);
  received_active = g_strdup (active);
  received_event_status =
    g_strdup (test_alert_data_value (event_data, "status"));
  received_scp_credential =
    g_strdup (test_alert_data_value (method_data, "scp_credential"));
  received_scp_host = g_strdup (test_alert_data_value (method_data, "scp_host"));
  received_scp_port = g_strdup (test_alert_data_value (method_data, "scp_port"));
  received_scp_known_hosts =
    g_strdup (test_alert_data_value (method_data, "scp_known_hosts"));
  received_scp_path = g_strdup (test_alert_data_value (method_data, "scp_path"));
  received_report_format =
    g_strdup (test_alert_data_value (method_data, "scp_report_format"));
  received_atomic_report_format = g_strdup (report_format_id);
  assert_that (scp_credential_id, is_equal_to_string (received_scp_credential));
  assert_that (condition_data->len, is_equal_to (1));
  assert_that (g_ptr_array_index (condition_data, 0), is_null);
  *alert = 9;
  return create_alert_result;
}

char *
__wrap_alert_uuid (alert_t alert)
{
  return alert == 9 && !alert_uuid_lookup_fails
         ? g_strdup ("123e4567-e89b-12d3-a456-426614174004") : NULL;
}

void
__wrap_log_event (const char *resource, const char *resource_name,
                  const char *uuid, const char *action)
{
  if (strcmp (resource, "config") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Scan Config"));
      assert_that (uuid,
                   is_equal_to_string (
                     "123e4567-e89b-12d3-a456-426614174001"));
      assert_that (action, is_equal_to_string ("modified"));
      diagnostic_audit_success_calls++;
    }
  else if (strcmp (resource, "alert") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Alert"));
      if (strcmp (action, "created") == 0)
        {
          audit_success_calls++;
          g_free (received_audit_uuid);
          received_audit_uuid = g_strdup (uuid);
        }
      else if (strcmp (action, "delivered") == 0)
        {
          assert_that (uuid,
                       is_equal_to_string (received_alert_delivery_uuid));
          alert_delivery_audit_success_calls++;
        }
      else
        {
          assert_that (action, is_equal_to_string ("tested"));
          assert_that (uuid, is_equal_to_string (received_alert_test_uuid));
          alert_test_audit_success_calls++;
        }
    }
  else if (strcmp (resource, "tag") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Tag"));
      assert_that (action, is_equal_to_string ("modified"));
      tag_audit_success_calls++;
      g_free (received_audit_uuid);
      received_audit_uuid = g_strdup (uuid);
    }
  else if (strcmp (resource, "task") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Task"));
      assert_that (action, is_equal_to_string ("created"));
      task_audit_success_calls++;
      g_free (received_audit_uuid);
      received_audit_uuid = g_strdup (uuid);
    }
  else if (strcmp (resource, "user") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("User"));
      if (strcmp (action, "created") == 0)
        {
          clone_user_audit_success_calls++;
          g_free (received_audit_uuid);
          received_audit_uuid = g_strdup (uuid);
        }
      else
        assert_that (action, is_equal_to_string ("password changed"));
    }
  else
    {
      assert_trash_empty_audit_operator_session ();
      assert_that (resource, is_equal_to_string ("trashcan"));
      assert_that (resource_name, is_equal_to_string ("Trashcan"));
      assert_that (uuid, is_null);
      assert_that (action, is_equal_to_string ("emptied"));
      trash_empty_audit_success_calls++;
    }
}

void
__wrap_log_event_fail (const char *resource, const char *resource_name,
                       const char *uuid, const char *action)
{
  if (strcmp (resource, "config") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Scan Config"));
      assert_that (uuid,
                   is_equal_to_string (
                     "123e4567-e89b-12d3-a456-426614174001"));
      assert_that (action, is_equal_to_string ("modified"));
      diagnostic_audit_fail_calls++;
    }
  else if (strcmp (resource, "alert") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Alert"));
      if (strcmp (action, "created") == 0)
        {
          assert_that (uuid, is_null);
          audit_fail_calls++;
        }
      else if (strcmp (action, "delivered") == 0)
        {
          assert_that (uuid,
                       is_equal_to_string (received_alert_delivery_uuid));
          alert_delivery_audit_fail_calls++;
        }
      else
        {
          assert_that (action, is_equal_to_string ("tested"));
          assert_that (uuid, is_equal_to_string (received_alert_test_uuid));
          alert_test_audit_fail_calls++;
        }
    }
  else if (strcmp (resource, "tag") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Tag"));
      assert_that (strcmp (action, "created") == 0
                     || strcmp (action, "modified") == 0,
                   is_true);
      tag_audit_fail_calls++;
      g_free (received_audit_uuid);
      received_audit_uuid = g_strdup (uuid);
    }
  else if (strcmp (resource, "task") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Task"));
      assert_that (action, is_equal_to_string ("created"));
      task_audit_fail_calls++;
      g_free (received_audit_uuid);
      received_audit_uuid = g_strdup (uuid);
    }
  else if (strcmp (resource, "user") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("User"));
      if (strcmp (action, "created") == 0)
        {
          clone_user_audit_fail_calls++;
          g_free (received_audit_uuid);
          received_audit_uuid = g_strdup (uuid);
        }
      else
        assert_that (action, is_equal_to_string ("password changed"));
    }
  else
    {
      assert_trash_empty_audit_operator_session ();
      assert_that (resource, is_equal_to_string ("trashcan"));
      assert_that (resource_name, is_equal_to_string ("Trashcan"));
      assert_that (uuid, is_null);
      assert_that (action, is_equal_to_string ("emptied"));
      trash_empty_audit_fail_calls++;
    }
}

void
__wrap_reinit_manage_process ()
{
  reinit_calls++;
}

int
__wrap_create_schedule (const char *name, const char *comment,
                        const char *icalendar, const char *timezone,
                        schedule_t *schedule, gchar **error_out)
{
  create_schedule_calls++;
  g_free (received_name);
  g_free (received_comment);
  g_free (received_timezone);
  g_free (received_icalendar);
  received_name = g_strdup (name);
  received_comment = g_strdup (comment);
  received_timezone = g_strdup (timezone);
  received_icalendar = g_strdup (icalendar);
  *schedule = 7;
  *error_out = NULL;
  return create_schedule_result;
}

char *
__wrap_schedule_uuid (schedule_t schedule)
{
  return schedule == 7
         ? g_strdup ("123e4567-e89b-12d3-a456-426614174002") : NULL;
}

int
__wrap_modify_schedule (const char *schedule_uuid, const char *name,
                        const char *comment, const char *icalendar,
                        const char *timezone, gchar **error_out)
{
  modify_schedule_calls++;
  g_free (received_schedule_uuid);
  g_free (received_name);
  g_free (received_comment);
  g_free (received_timezone);
  g_free (received_icalendar);
  received_schedule_uuid = g_strdup (schedule_uuid);
  received_name = g_strdup (name);
  received_comment = g_strdup (comment);
  received_timezone = g_strdup (timezone);
  received_icalendar = g_strdup (icalendar);
  *error_out = NULL;
  return modify_schedule_result;
}

int
__wrap_create_tag (const char *name, const char *comment, const char *value,
                   const char *resource_type, array_t *resource_ids,
                   const char *resources_filter, const char *active,
                   tag_t *tag, gchar **error_extra)
{
  (void) name;
  (void) comment;
  (void) value;
  (void) resource_type;
  (void) resource_ids;
  (void) resources_filter;
  (void) active;
  *tag = 10;
  *error_extra = NULL;
  return 0;
}

char *
__wrap_tag_uuid (tag_t tag)
{
  return tag == 10
           ? g_strdup ("123e4567-e89b-12d3-a456-426614174005") : NULL;
}

int
__wrap_modify_tag (const char *tag_uuid, const char *name,
                   const char *comment, const char *value,
                   const char *resource_type, array_t *resource_ids,
                   const char *resources_filter,
                   const char *resources_action, const char *active,
                   gchar **error_extra)
{
  modify_tag_calls++;
  g_free (received_tag_uuid);
  g_free (received_name);
  g_free (received_comment);
  g_free (received_secret);
  g_free (received_tag_resource_type);
  g_free (received_tag_resource_filter);
  g_free (received_tag_resources_action);
  g_free (received_tag_active);
  g_free (received_tag_first_resource_id);
  received_tag_uuid = g_strdup (tag_uuid);
  received_name = g_strdup (name);
  received_comment = g_strdup (comment);
  received_secret = g_strdup (value);
  received_tag_resource_type = g_strdup (resource_type);
  received_tag_resource_filter = g_strdup (resources_filter);
  received_tag_resources_action = g_strdup (resources_action);
  received_tag_active = g_strdup (active);
  received_tag_first_resource_id =
    resource_ids && g_ptr_array_index (resource_ids, 0)
      ? g_strdup (g_ptr_array_index (resource_ids, 0)) : NULL;
  *error_extra = NULL;
  return modify_tag_result;
}

int
__wrap_create_credential
  (const char *name, const char *comment, const char *login,
   const char *given_password, const char *key_private, const char *key_public,
   const char *certificate, const char *community, const char *auth_algorithm,
   const char *privacy_password, const char *privacy_algorithm,
   const char *kdc, array_t *kdcs, const char *realm,
   const char *given_type, const char *allow_insecure,
   credential_t *credential)
{
  (void) key_public;
  (void) certificate;
  (void) community;
  (void) auth_algorithm;
  (void) privacy_password;
  (void) privacy_algorithm;
  (void) kdc;
  (void) kdcs;
  (void) realm;
  (void) allow_insecure;
  create_credential_calls++;
  g_free (received_name);
  g_free (received_comment);
  g_free (received_login);
  g_free (received_secret);
  g_free (received_key_private);
  g_free (received_credential_type);
  received_name = g_strdup (name);
  received_comment = g_strdup (comment);
  received_login = g_strdup (login);
  received_secret = g_strdup (given_password);
  received_key_private = g_strdup (key_private);
  received_credential_type = g_strdup (given_type);
  *credential = 8;
  return create_credential_result;
}

char *
__wrap_credential_uuid (credential_t credential)
{
  return credential == 8
         ? g_strdup ("123e4567-e89b-12d3-a456-426614174003") : NULL;
}

void
__wrap_manage_session_init (const char *uuid)
{
  (void) uuid;
  session_init_calls++;
}

int
__wrap_manage_empty_trashcan_confirmed (long long int expected_total,
                                        const char *expected_snapshot_digest,
                                        long long int *actual_total)
{
  (void) expected_snapshot_digest;
  trash_empty_calls++;
  trash_empty_expected = (gint64) expected_total;
  *actual_total = (long long int) trash_empty_actual;
  return trash_empty_result;
}

int
__wrap_manage_configure_diagnostic_nvt (const char *config_uuid,
                                        const char *nvt_oid,
                                        gboolean *changed,
                                        gboolean *committed)
{
  diagnostic_control_calls++;
  g_free (received_diagnostic_config_uuid);
  g_free (received_diagnostic_nvt_oid);
  received_diagnostic_config_uuid = g_strdup (config_uuid);
  received_diagnostic_nvt_oid = g_strdup (nvt_oid);
  *changed = diagnostic_control_changed;
  *committed = diagnostic_control_committed;
  return diagnostic_control_result;
}

int
__wrap_manage_test_alert (const char *alert_uuid, gchar **script_message)
{
  alert_test_calls++;
  g_free (received_alert_test_uuid);
  received_alert_test_uuid = g_strdup (alert_uuid);
  *script_message = alert_test_script_message
                      ? g_strdup (alert_test_script_message) : NULL;
  return alert_test_result;
}

gboolean
__wrap_find_alert_with_permission (const char *uuid, alert_t *alert,
                                   const char *permission)
{
  assert_that (alert_delivery_active, is_true);
  assert_that (uuid, is_equal_to_string (received_alert_delivery_uuid));
  assert_that (permission, is_equal_to_string ("get_alerts"));
  *alert = alert_delivery_alert_exists ? 17 : 0;
  return FALSE;
}

gboolean
__wrap_find_report_with_permission (const char *uuid, report_t *report,
                                    const char *permission)
{
  assert_that (alert_delivery_active, is_true);
  assert_that (uuid,
               is_equal_to_string (received_alert_delivery_report_uuid));
  assert_that (permission, is_equal_to_string ("get_reports"));
  *report = alert_delivery_report_exists ? 19 : 0;
  return FALSE;
}

gboolean
__wrap_find_filter_with_permission (const char *uuid, filter_t *filter,
                                    const char *permission)
{
  assert_that (alert_delivery_active, is_true);
  assert_that (uuid,
               is_equal_to_string (received_alert_delivery_filter_uuid));
  assert_that (permission, is_equal_to_string ("get_filters"));
  *filter = alert_delivery_filter_exists ? 23 : 0;
  return FALSE;
}

char *
__wrap_filter_term (const char *uuid)
{
  assert_that (alert_delivery_active, is_true);
  assert_that (uuid,
               is_equal_to_string (received_alert_delivery_filter_uuid));
  return g_strdup ("first=1 rows=5");
}

alert_method_t
__wrap_alert_method (alert_t alert)
{
  assert_that (alert_delivery_active, is_true);
  assert_that (alert, is_equal_to (17));
  return alert_delivery_method;
}

int
__wrap_manage_send_report (
  report_t report, report_format_t report_format, const get_data_t *get,
  int overrides_details, int result_tags, int ignore_pagination, int lean,
  int base64,
  gboolean (*send) (const char *, int (*) (const char *, void *), void *),
  int (*send_data_1) (const char *, void *), void *send_data_2,
  const char *alert_id, const gchar *prefix)
{
  assert_that (alert_delivery_active, is_true);
  assert_that (report, is_equal_to (19));
  assert_that (report_format, is_equal_to (-1));
  assert_that (get->details, is_equal_to (1));
  assert_that (get->ignore_pagination, is_equal_to (0));
  assert_that (get->filter,
               is_equal_to_string (received_alert_delivery_filter));
  if (received_alert_delivery_filter_uuid)
    assert_that (get->filt_id,
                 is_equal_to_string (received_alert_delivery_filter_uuid));
  else
    assert_that (get->filt_id, is_null);
  assert_that (overrides_details, is_equal_to (0));
  assert_that (result_tags, is_equal_to (0));
  assert_that (ignore_pagination, is_equal_to (1));
  assert_that (lean, is_equal_to (0));
  assert_that (base64, is_equal_to (0));
  assert_that (send, is_null);
  assert_that (send_data_1, is_null);
  assert_that (send_data_2, is_null);
  assert_that (alert_id,
               is_equal_to_string (received_alert_delivery_uuid));
  assert_that (prefix, is_null);
  alert_delivery_calls++;
  return alert_delivery_result;
}

enum trash_empty_db_event
{
  TRASH_EMPTY_DB_BEGIN,
  TRASH_EMPTY_DB_USERS_LOCK,
  TRASH_EMPTY_DB_USER_LOCK,
  TRASH_EMPTY_DB_ACL,
  TRASH_EMPTY_DB_COUNT,
  TRASH_EMPTY_DB_DELETE,
  TRASH_EMPTY_DB_ROLLBACK,
  TRASH_EMPTY_DB_COMMIT,
};

static enum trash_empty_db_event trash_empty_db_events[16];
static size_t trash_empty_db_event_count;
static long long int trash_empty_db_count;
static int trash_empty_db_acl;
static const char *trash_empty_count_sql;

enum alert_smb_db_event
{
  ALERT_SMB_DB_BEGIN,
  ALERT_SMB_DB_ACL,
  ALERT_SMB_DB_OWNER_LOCK,
  ALERT_SMB_DB_CREDENTIAL_RESOLVE,
  ALERT_SMB_DB_CREDENTIAL_LOCK,
  ALERT_SMB_DB_CREDENTIAL_TYPE,
  ALERT_SMB_DB_FORMAT_RESOLVE,
  ALERT_SMB_DB_FORMAT_LOCK,
  ALERT_SMB_DB_BODY_INSERT,
  ALERT_SMB_DB_METHOD_INSERT,
  ALERT_SMB_DB_ROLLBACK,
  ALERT_SMB_DB_COMMIT,
};

enum alert_start_task_db_event
{
  ALERT_START_TASK_DB_BEGIN,
  ALERT_START_TASK_DB_ACL,
  ALERT_START_TASK_DB_OWNER_LOCK,
  ALERT_START_TASK_DB_TASK_RESOLVE,
  ALERT_START_TASK_DB_TASK_LOCK,
  ALERT_START_TASK_DB_BODY_INSERT,
  ALERT_START_TASK_DB_METHOD_INSERT,
  ALERT_START_TASK_DB_ROLLBACK,
  ALERT_START_TASK_DB_COMMIT,
};

static enum alert_start_task_db_event alert_start_task_db_events[24];
static size_t alert_start_task_db_event_count;
static gboolean alert_start_task_db_active;
static gboolean alert_start_task_db_acl;
static gboolean alert_start_task_db_owner_exists;
static gboolean alert_start_task_db_task_readable;
static gboolean alert_start_task_db_task_owned;
static gboolean alert_start_task_db_duplicate_name;
static unsigned int alert_start_task_db_method_inserts;

static enum alert_smb_db_event alert_smb_db_events[32];
static size_t alert_smb_db_event_count;
static gboolean alert_smb_db_active;
static gboolean alert_smb_db_acl;
static gboolean alert_smb_db_owner_exists;
static gboolean alert_smb_db_credential_readable;
static gboolean alert_smb_db_credential_owned;
static const char *alert_smb_db_credential_type;
static const char *alert_smb_db_credential_username;
static gboolean alert_smb_db_format_readable;
static gboolean alert_smb_db_format_lock_exists;
static const char *alert_smb_db_report_format_uuid;
static unsigned int alert_smb_db_method_inserts;
static unsigned int alert_smb_db_credential_resolves;

enum diagnostic_db_event
{
  DIAGNOSTIC_DB_BEGIN,
  DIAGNOSTIC_DB_RESOURCE_LOCK,
  DIAGNOSTIC_DB_NVT_LOCK,
  DIAGNOSTIC_DB_DELETE,
  DIAGNOSTIC_DB_INSERT,
  DIAGNOSTIC_DB_CACHE,
  DIAGNOSTIC_DB_ROLLBACK,
  DIAGNOSTIC_DB_COMMIT,
  DIAGNOSTIC_DB_POSTVERIFY,
};

static enum diagnostic_db_event diagnostic_db_events[32];
static size_t diagnostic_db_event_count;
static gboolean diagnostic_db_active;
static gboolean diagnostic_db_acl;
static gboolean diagnostic_db_owner_exists;
static gboolean diagnostic_db_config_exists;
static gboolean diagnostic_db_owned;
static gboolean diagnostic_db_predefined;
static gboolean diagnostic_db_in_use;
static long long int diagnostic_db_selector_refs;
static gboolean diagnostic_db_nvt_exists;
static const char *diagnostic_db_nvt_family;
static gboolean diagnostic_db_nmap_exists;
static gboolean diagnostic_db_ping_exists;
static gboolean diagnostic_db_state_matches;
static gboolean diagnostic_db_postcommit_matches;
static gboolean diagnostic_db_commit_seen;
static unsigned int diagnostic_db_inserts;
static unsigned int diagnostic_db_cache_updates;
static const char *diagnostic_db_requested_oid;

static void
diagnostic_record_db_event (enum diagnostic_db_event event)
{
  assert_that (
    diagnostic_db_event_count < G_N_ELEMENTS (diagnostic_db_events), is_true);
  diagnostic_db_events[diagnostic_db_event_count++] = event;
}

static void
reset_diagnostic_db (const char *requested_oid)
{
  diagnostic_db_event_count = 0;
  diagnostic_db_active = TRUE;
  alert_start_task_db_active = FALSE;
  alert_smb_db_active = FALSE;
  diagnostic_db_acl = TRUE;
  diagnostic_db_owner_exists = TRUE;
  diagnostic_db_config_exists = TRUE;
  diagnostic_db_owned = TRUE;
  diagnostic_db_predefined = FALSE;
  diagnostic_db_in_use = FALSE;
  diagnostic_db_selector_refs = 1;
  diagnostic_db_nvt_exists = TRUE;
  diagnostic_db_nvt_family = "General";
  diagnostic_db_nmap_exists = TRUE;
  diagnostic_db_ping_exists = TRUE;
  diagnostic_db_state_matches = FALSE;
  diagnostic_db_postcommit_matches = TRUE;
  diagnostic_db_commit_seen = FALSE;
  diagnostic_db_inserts = 0;
  diagnostic_db_cache_updates = 0;
  diagnostic_db_requested_oid = requested_oid;
}

static void
alert_start_task_record_db_event (enum alert_start_task_db_event event)
{
  assert_that (alert_start_task_db_event_count
                 < G_N_ELEMENTS (alert_start_task_db_events),
               is_true);
  alert_start_task_db_events[alert_start_task_db_event_count++] = event;
}

static void
reset_alert_start_task_db (void)
{
  diagnostic_db_active = FALSE;
  alert_smb_db_active = FALSE;
  alert_start_task_db_active = TRUE;
  alert_start_task_db_event_count = 0;
  alert_start_task_db_acl = TRUE;
  alert_start_task_db_owner_exists = TRUE;
  alert_start_task_db_task_readable = TRUE;
  alert_start_task_db_task_owned = TRUE;
  alert_start_task_db_duplicate_name = FALSE;
  alert_start_task_db_method_inserts = 0;
}

static void
alert_smb_record_db_event (enum alert_smb_db_event event)
{
  assert_that (alert_smb_db_event_count < G_N_ELEMENTS (alert_smb_db_events),
               is_true);
  alert_smb_db_events[alert_smb_db_event_count++] = event;
}

static void
reset_alert_smb_db (void)
{
  diagnostic_db_active = FALSE;
  alert_start_task_db_active = FALSE;
  alert_smb_db_event_count = 0;
  alert_smb_db_active = TRUE;
  alert_smb_db_acl = TRUE;
  alert_smb_db_owner_exists = TRUE;
  alert_smb_db_credential_readable = TRUE;
  alert_smb_db_credential_owned = TRUE;
  alert_smb_db_credential_type = "up";
  alert_smb_db_credential_username = "operator";
  alert_smb_db_format_readable = TRUE;
  alert_smb_db_format_lock_exists = TRUE;
  alert_smb_db_report_format_uuid = "123e4567-e89b-12d3-a456-426614174011";
  alert_smb_db_method_inserts = 0;
  alert_smb_db_credential_resolves = 0;
}

static void
trash_empty_record_db_event (enum trash_empty_db_event event)
{
  assert_that (
    trash_empty_db_event_count < G_N_ELEMENTS (trash_empty_db_events),
    is_true);
  trash_empty_db_events[trash_empty_db_event_count++] = event;
}

void
__wrap_sql_begin_immediate (void)
{
  if (diagnostic_db_active)
    diagnostic_record_db_event (DIAGNOSTIC_DB_BEGIN);
  else if (alert_start_task_db_active)
    alert_start_task_record_db_event (ALERT_START_TASK_DB_BEGIN);
  else if (alert_smb_db_active)
    alert_smb_record_db_event (ALERT_SMB_DB_BEGIN);
  else
    trash_empty_record_db_event (TRASH_EMPTY_DB_BEGIN);
}

int
__wrap_sql_int64 (long long int *value, const char *statement, ...)
{
  if (diagnostic_db_active)
    {
      if (strstr (statement, "SELECT id FROM users") != NULL)
        {
          if (!diagnostic_db_owner_exists)
            return 1;
          *value = 42;
          return 0;
        }
      if (strstr (statement, "SELECT id FROM configs WHERE uuid") != NULL)
        {
          if (!diagnostic_db_config_exists)
            return 1;
          *value = 51;
          return 0;
        }
      if (strstr (statement, "owner =") != NULL)
        {
          *value = diagnostic_db_owned ? 1 : 0;
          return 0;
        }
      if (strstr (statement, "SELECT predefined") != NULL)
        {
          *value = diagnostic_db_predefined ? 1 : 0;
          return 0;
        }
      if (strstr (statement, "FROM tasks") != NULL)
        {
          *value = diagnostic_db_in_use ? 1 : 0;
          return 0;
        }
      if (strstr (statement, "SELECT ((SELECT count(*) FROM configs")
          != NULL)
        {
          *value = diagnostic_db_selector_refs;
          return 0;
        }
      if (strstr (statement, "FROM nvts") != NULL
          && strstr (statement, TEST_DIAGNOSTIC_NMAP_OID) != NULL)
        {
          *value = diagnostic_db_nmap_exists ? 1 : 0;
          return 0;
        }
      if (strstr (statement, "FROM nvts") != NULL
          && strstr (statement, TEST_DIAGNOSTIC_PING_OID) != NULL)
        {
          *value = diagnostic_db_ping_exists ? 1 : 0;
          return 0;
        }
      if (strstr (statement, "FROM nvts WHERE oid") != NULL)
        {
          *value = diagnostic_db_nvt_exists ? 1 : 0;
          return 0;
        }
      if (strstr (statement,
                  "SELECT count(*) FROM nvt_selectors WHERE name")
            != NULL
          && strstr (statement, "exclude =") == NULL)
        {
          if (diagnostic_db_commit_seen)
            diagnostic_record_db_event (DIAGNOSTIC_DB_POSTVERIFY);
          *value =
            diagnostic_db_state_matches
              ? 1
                  + (strcmp (diagnostic_db_requested_oid,
                             TEST_DIAGNOSTIC_NMAP_OID)
                     != 0)
                  + (strcmp (diagnostic_db_requested_oid,
                             TEST_DIAGNOSTIC_PING_OID)
                     != 0)
              : 0;
          return 0;
        }
      if (strstr (statement, "family_or_nvt =") != NULL)
        {
          *value = diagnostic_db_state_matches ? 1 : 0;
          return 0;
        }
      if (strstr (statement, "family_count =") != NULL)
        {
          *value = diagnostic_db_state_matches ? 1 : 0;
          return 0;
        }
      return -1;
    }

  if (alert_start_task_db_active)
    {
      if (strstr (statement, "SELECT id FROM users") != NULL)
        {
          alert_start_task_record_db_event (ALERT_START_TASK_DB_OWNER_LOCK);
          if (!alert_start_task_db_owner_exists)
            return 1;
          *value = 42;
          return 0;
        }
      if (strstr (statement, "SELECT tasks.id FROM tasks") != NULL)
        {
          alert_start_task_record_db_event (ALERT_START_TASK_DB_TASK_LOCK);
          if (!alert_start_task_db_task_owned)
            return 1;
          *value = 71;
          return 0;
        }
      return -1;
    }

  if (alert_smb_db_active)
    {
      if (strstr (statement, "SELECT id FROM users") != NULL)
        {
          alert_smb_record_db_event (ALERT_SMB_DB_OWNER_LOCK);
          if (!alert_smb_db_owner_exists)
            return 1;
          *value = 42;
          return 0;
        }
      if (strstr (statement, "SELECT credentials.id") != NULL)
        {
          alert_smb_record_db_event (ALERT_SMB_DB_CREDENTIAL_LOCK);
          if (!alert_smb_db_credential_owned)
            return 1;
          *value = 51;
          return 0;
        }
      if (strstr (statement, "FROM report_formats") != NULL)
        {
          alert_smb_record_db_event (ALERT_SMB_DB_FORMAT_LOCK);
          if (!alert_smb_db_format_lock_exists)
            return 1;
          *value = 61;
          return 0;
        }
      return -1;
    }

  if (strstr (statement, "SELECT id FROM users") != NULL)
    {
      trash_empty_record_db_event (TRASH_EMPTY_DB_USER_LOCK);
      *value = 42;
      return 0;
    }
  if (strstr (statement, "SELECT ((SELECT count(*)") != NULL)
    {
      trash_empty_record_db_event (TRASH_EMPTY_DB_COUNT);
      trash_empty_count_sql = statement;
      *value = trash_empty_db_count;
      return 0;
    }

  return -1;
}

char *
__wrap_sql_string (const char *statement, ...)
{
  assert_that (diagnostic_db_active, is_true);

  if (strstr (statement, "SELECT nvt_selector FROM configs") != NULL)
    return g_strdup ("123e4567-e89b-12d3-a456-426614174099");
  if (strstr (statement, "SELECT family FROM nvts") != NULL)
    return diagnostic_db_nvt_family
             ? g_strdup (diagnostic_db_nvt_family) : NULL;
  return NULL;
}

void
__wrap_sql (const char *statement, ...)
{
  if (diagnostic_db_active)
    {
      if (strstr (statement, "LOCK TABLE configs") != NULL)
        diagnostic_record_db_event (DIAGNOSTIC_DB_RESOURCE_LOCK);
      else if (strstr (statement, "LOCK TABLE nvts") != NULL)
        diagnostic_record_db_event (DIAGNOSTIC_DB_NVT_LOCK);
      else if (strstr (statement, "DELETE FROM nvt_selectors") != NULL)
        diagnostic_record_db_event (DIAGNOSTIC_DB_DELETE);
      else if (strstr (statement, "INSERT INTO nvt_selectors") != NULL)
        {
          diagnostic_db_inserts++;
          diagnostic_record_db_event (DIAGNOSTIC_DB_INSERT);
        }
      else if (strstr (statement, "UPDATE configs") != NULL
               && strstr (statement, "SET family_count") != NULL)
        {
          diagnostic_db_cache_updates++;
          diagnostic_record_db_event (DIAGNOSTIC_DB_CACHE);
        }
      return;
    }

  if (alert_start_task_db_active)
    {
      if (strstr (statement, "INSERT INTO alerts") != NULL)
        alert_start_task_record_db_event (ALERT_START_TASK_DB_BODY_INSERT);
      else if (strstr (statement, "INSERT INTO alert_method_data") != NULL)
        {
          va_list args;
          const char *name;
          const char *data;

          va_start (args, statement);
          (void) va_arg (args, unsigned long long);
          name = va_arg (args, const char *);
          data = va_arg (args, const char *);
          va_end (args);
          assert_that (name, is_equal_to_string ("start_task_task"));
          assert_that (
            data, is_equal_to_string ("123e4567-e89b-12d3-a456-426614174020"));
          alert_start_task_db_method_inserts++;
          alert_start_task_record_db_event (ALERT_START_TASK_DB_METHOD_INSERT);
        }
      return;
    }

  if (alert_smb_db_active)
    {
      if (strstr (statement, "INSERT INTO alerts") != NULL)
        alert_smb_record_db_event (ALERT_SMB_DB_BODY_INSERT);
      return;
    }

  if (strcmp (statement, "LOCK TABLE users IN EXCLUSIVE MODE;") == 0)
    trash_empty_record_db_event (TRASH_EMPTY_DB_USERS_LOCK);
  else if (g_str_has_prefix (statement, "DELETE FROM")
           || g_str_has_prefix (statement, "UPDATE "))
    trash_empty_record_db_event (TRASH_EMPTY_DB_DELETE);
}

void
__wrap_sql_ps_sensitive (const char *statement, ...)
{
  assert_that (alert_smb_db_active, is_true);
  assert_that (strstr (statement, "INSERT INTO alert_method_data"),
               is_not_null);
  assert_that (strstr (statement, "fileserver"), is_null);
  assert_that (strstr (statement, "report.pdf"), is_null);
  alert_smb_db_method_inserts++;
  alert_smb_record_db_event (ALERT_SMB_DB_METHOD_INSERT);
}

resource_t
__wrap_sql_last_insert_id (void)
{
  assert_that (alert_smb_db_active || alert_start_task_db_active, is_true);
  return 9;
}

void
__wrap_sql_rollback (void)
{
  if (diagnostic_db_active)
    diagnostic_record_db_event (DIAGNOSTIC_DB_ROLLBACK);
  else if (alert_start_task_db_active)
    alert_start_task_record_db_event (ALERT_START_TASK_DB_ROLLBACK);
  else if (alert_smb_db_active)
    alert_smb_record_db_event (ALERT_SMB_DB_ROLLBACK);
  else
    trash_empty_record_db_event (TRASH_EMPTY_DB_ROLLBACK);
}

void
__wrap_sql_commit (void)
{
  if (diagnostic_db_active)
    {
      diagnostic_record_db_event (DIAGNOSTIC_DB_COMMIT);
      diagnostic_db_commit_seen = TRUE;
      if (diagnostic_db_inserts)
        diagnostic_db_state_matches = diagnostic_db_postcommit_matches;
    }
  else if (alert_start_task_db_active)
    alert_start_task_record_db_event (ALERT_START_TASK_DB_COMMIT);
  else if (alert_smb_db_active)
    alert_smb_record_db_event (ALERT_SMB_DB_COMMIT);
  else
    trash_empty_record_db_event (TRASH_EMPTY_DB_COMMIT);
}

int
__wrap_acl_user_may (const char *operation)
{
  if (diagnostic_db_active)
    {
      assert_that (operation, is_equal_to_string ("modify_config"));
      return diagnostic_db_acl;
    }

  if (alert_start_task_db_active)
    {
      assert_that (operation, is_equal_to_string ("create_alert"));
      alert_start_task_record_db_event (ALERT_START_TASK_DB_ACL);
      return alert_start_task_db_acl;
    }

  if (alert_smb_db_active)
    {
      assert_that (operation, is_equal_to_string ("create_alert"));
      alert_smb_record_db_event (ALERT_SMB_DB_ACL);
      return alert_smb_db_acl;
    }

  assert_that (operation, is_equal_to_string ("empty_trashcan"));
  trash_empty_record_db_event (TRASH_EMPTY_DB_ACL);
  return trash_empty_db_acl;
}

gboolean
__wrap_find_task_with_permission (const char *uuid, task_t *task,
                                  const char *permission)
{
  assert_that (alert_start_task_db_active, is_true);
  assert_that (uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174020"));
  assert_that (permission, is_equal_to_string ("start_task"));
  alert_start_task_record_db_event (ALERT_START_TASK_DB_TASK_RESOLVE);
  *task = alert_start_task_db_task_readable ? 71 : 0;
  return FALSE;
}

gboolean
__wrap_find_credential_with_permission (const char *uuid,
                                        credential_t *credential,
                                        const char *permission)
{
  assert_that (alert_smb_db_active, is_true);
  assert_that (uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174010"));
  assert_that (permission, is_equal_to_string ("get_credentials"));
  if (alert_smb_db_credential_resolves++ == 0)
    alert_smb_record_db_event (ALERT_SMB_DB_CREDENTIAL_RESOLVE);
  *credential = alert_smb_db_credential_readable ? 51 : 0;
  return FALSE;
}

char *
__wrap_credential_type (credential_t credential)
{
  assert_that (alert_smb_db_active, is_true);
  assert_that (credential, is_equal_to (51));
  alert_smb_record_db_event (ALERT_SMB_DB_CREDENTIAL_TYPE);
  return strdup (alert_smb_db_credential_type);
}

gchar *
__wrap_credential_value (credential_t credential, const char *name)
{
  assert_that (alert_smb_db_active, is_true);
  assert_that (credential, is_equal_to (51));
  assert_that (name, is_equal_to_string ("username"));
  return g_strdup (alert_smb_db_credential_username);
}

gboolean
__wrap_find_report_format_with_permission (const char *uuid,
                                           report_format_t *report_format,
                                           const char *permission)
{
  assert_that (alert_smb_db_active, is_true);
  assert_that (uuid, is_equal_to_string (alert_smb_db_report_format_uuid));
  assert_that (permission, is_equal_to_string ("get_report_formats"));
  alert_smb_record_db_event (ALERT_SMB_DB_FORMAT_RESOLVE);
  *report_format = alert_smb_db_format_readable ? 61 : 0;
  return FALSE;
}

int
__wrap_resource_with_name_exists (const char *name, const char *type,
                                  resource_t exclude)
{
  assert_that (alert_smb_db_active || alert_start_task_db_active, is_true);
  if (alert_start_task_db_active)
    assert_that (name, is_equal_to_string ("Start follow-up"));
  else
    assert_that (name, is_equal_to_string ("SMB alert"));
  assert_that (type, is_equal_to_string ("alert"));
  assert_that (exclude, is_equal_to (0));
  return alert_start_task_db_active && alert_start_task_db_duplicate_name;
}

int
__real_manage_empty_trashcan_confirmed (long long int, const char *,
                                        long long int *);

int
__real_create_alert_smb_with_report_refs (const char *, const char *,
                                          const char *, GPtrArray *,
                                          GPtrArray *, GPtrArray *,
                                          const char *, const char *, alert_t *);

int
__real_create_alert_start_task_with_task_ref (const char *, const char *,
                                              const char *, GPtrArray *,
                                              GPtrArray *, const char *,
                                              alert_t *);

static ssize_t
dispatch_trash_empty_request (const char *request,
                              char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES])
{
  int sockets[2];
  ssize_t response_len;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (write (sockets[0], request, strlen (request)),
               is_equal_to ((ssize_t) strlen (request)));
  assert_that (shutdown (sockets[0], SHUT_WR), is_equal_to (0));
  yafvs_control_serve_client (sockets[1]);
  response_len = read (sockets[0], response,
                       YAFVS_CONTROL_MAX_RESPONSE_BYTES - 1);
  close (sockets[0]);
  close (sockets[1]);

  return response_len;
}

static ssize_t
dispatch_auth_settings_request (
  const char *request,
  char response[YAFVS_CONTROL_AUTH_SETTINGS_MAX_RESPONSE_BYTES])
{
  int sockets[2];
  ssize_t response_len;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (write (sockets[0], request, strlen (request)),
               is_equal_to ((ssize_t) strlen (request)));
  assert_that (shutdown (sockets[0], SHUT_WR), is_equal_to (0));
  yafvs_control_serve_client (sockets[1]);
  response_len =
    read (sockets[0], response,
          YAFVS_CONTROL_AUTH_SETTINGS_MAX_RESPONSE_BYTES - 1);
  close (sockets[0]);
  close (sockets[1]);
  return response_len;
}

static void
reset_auth_settings_test (void)
{
  auth_settings_read_calls = 0;
  auth_settings_read_result = MANAGE_AUTH_SETTINGS_OK;
  auth_settings_ldap_write_calls = 0;
  auth_settings_ldap_write_result = MANAGE_AUTH_SETTINGS_OK;
  auth_settings_radius_write_calls = 0;
  auth_settings_radius_write_result = MANAGE_AUTH_SETTINGS_OK;
  auth_settings_empty_required = FALSE;
  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  g_clear_pointer (&received_auth_host, g_free);
  g_clear_pointer (&received_authdn, g_free);
  g_clear_pointer (&received_auth_cacert, g_free);
  g_clear_pointer (&received_radius_secret, g_free);
  mock_operator_name = "operator";
}

Ensure (yafvs_control, parses_strict_auth_settings_frames)
{
  const char *read_request =
    "auth-settings-read " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000\n";
  const char *empty_ldap_request =
    "auth-settings-ldap-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 0 - - 1 0 -\n";
  const char *empty_radius_request =
    "auth-settings-radius-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 - -\n";
  const char *radius_request =
    "auth-settings-radius-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 "
    "cmFkaXVzLmV4YW1wbGU= c2VjcmV0\n";
  yafvs_control_auth_settings_ldap_request_t ldap = {0};
  yafvs_control_auth_settings_radius_request_t radius = {0};
  char operator_uuid[37];

  assert_that (yafvs_control_parse_auth_settings_read_request (
                 read_request, strlen (read_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid), is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));

  assert_that (yafvs_control_parse_auth_settings_ldap_write_request (
                 empty_ldap_request, strlen (empty_ldap_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &ldap), is_true);
  assert_that (ldap.enabled, is_equal_to (0));
  assert_that (ldap.host, is_equal_to_string (""));
  assert_that (ldap.authdn, is_equal_to_string (""));
  assert_that (ldap.allow_plaintext, is_equal_to (1));
  assert_that (ldap.ldaps_only, is_equal_to (0));
  assert_that (ldap.cacert, is_null);
  yafvs_control_auth_settings_ldap_request_clear (&ldap);

  assert_that (yafvs_control_parse_auth_settings_radius_write_request (
                 empty_radius_request, strlen (empty_radius_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &radius), is_true);
  assert_that (radius.host, is_equal_to_string (""));
  assert_that (radius.secret, is_null);
  yafvs_control_auth_settings_radius_request_clear (&radius);

  assert_that (yafvs_control_parse_auth_settings_radius_write_request (
                 radius_request, strlen (radius_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &radius),
               is_true);
  assert_that (radius.host, is_equal_to_string ("radius.example"));
  assert_that (radius.secret, is_equal_to_string ("secret"));
  yafvs_control_auth_settings_radius_request_clear (&radius);
}

Ensure (yafvs_control, rejects_malformed_auth_settings_frames)
{
  static const char *requests[] = {
    "auth-settings-read " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 \n",
    "auth-settings-ldap-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 2 - - 0 0 -\n",
    "auth-settings-ldap-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 aG9zdAo= "
    "dWlkPSVzLGRjPWV4YW1wbGU= 0 0 -\n",
    "auth-settings-radius-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 cmFkaXVz c2VjcmV0 extra\n",
    "auth-settings-radius-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 cmFkaXVz= c2VjcmV0\n",
  };
  yafvs_control_auth_settings_ldap_request_t ldap = {0};
  yafvs_control_auth_settings_radius_request_t radius = {0};
  char operator_uuid[37];

  assert_that (yafvs_control_parse_auth_settings_read_request (
                 requests[0], strlen (requests[0]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid), is_false);
  assert_that (yafvs_control_parse_auth_settings_ldap_write_request (
                 requests[1], strlen (requests[1]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &ldap),
               is_false);
  assert_that (yafvs_control_parse_auth_settings_ldap_write_request (
                 requests[2], strlen (requests[2]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &ldap),
               is_false);
  assert_that (yafvs_control_parse_auth_settings_radius_write_request (
                 requests[3], strlen (requests[3]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &radius),
               is_false);
  assert_that (yafvs_control_parse_auth_settings_radius_write_request (
                 requests[4], strlen (requests[4]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &radius),
               is_false);
}

Ensure (yafvs_control, maps_auth_settings_responses)
{
  manage_auth_settings_t empty = {
    .ldap_host = "",
    .ldap_authdn = "",
    .radius_host = "",
  };
  gchar *read_response;

  read_response = yafvs_control_auth_settings_read_response (&empty);
  assert_that (
    read_response,
    is_equal_to_string (
      "0 settings 0 0 - - 0 0 0 - - - - - 0 0 - 0\n"));
  yafvs_control_secure_free (read_response);

  assert_that (yafvs_control_auth_settings_response (0),
               is_equal_to_string ("0 updated\n"));
  assert_that (yafvs_control_auth_settings_response (1),
               is_equal_to_string ("1 invalid-auth-dn\n"));
  assert_that (yafvs_control_auth_settings_response (2),
               is_equal_to_string ("2 invalid-certificate\n"));
  assert_that (yafvs_control_auth_settings_response (3),
               is_equal_to_string ("3 provider-unavailable\n"));
  assert_that (yafvs_control_auth_settings_response (4),
               is_equal_to_string ("4 encryption-failed\n"));
  assert_that (yafvs_control_auth_settings_response (99),
               is_equal_to_string ("99 permission-denied\n"));
  assert_that (yafvs_control_auth_settings_response (-2),
               is_equal_to_string ("-2 invalid-request\n"));
  assert_that (yafvs_control_auth_settings_response (-1),
               is_equal_to_string ("-1 internal-error\n"));
}

Ensure (yafvs_control, runs_auth_settings_in_authorized_operator_session)
{
  yafvs_control_auth_settings_ldap_request_t ldap = {
    .enabled = 1,
    .host = "ldap.example",
    .authdn = "uid=%s,dc=example",
    .allow_plaintext = 0,
    .ldaps_only = 1,
    .cacert = "certificate",
  };
  yafvs_control_auth_settings_radius_request_t radius = {
    .enabled = 0,
    .host = "radius.example",
    .secret = "secret",
  };
  gchar *response = NULL;

  reset_auth_settings_test ();
  assert_that (yafvs_control_read_auth_settings (
                 "123e4567-e89b-12d3-a456-426614174000", &response),
               is_equal_to (MANAGE_AUTH_SETTINGS_OK));
  assert_that (auth_settings_read_calls, is_equal_to (1));
  assert_that (response, contains_string ("0 settings 1 1 "));
  assert_that (strstr (response, "certificate"), is_null);
  assert_that (strstr (response, "secret"), is_null);
  yafvs_control_secure_free (response);

  assert_that (yafvs_control_write_ldap_auth_settings (
                 "123e4567-e89b-12d3-a456-426614174000", &ldap),
               is_equal_to (MANAGE_AUTH_SETTINGS_OK));
  assert_that (auth_settings_ldap_write_calls, is_equal_to (1));
  assert_that (received_auth_host, is_equal_to_string ("ldap.example"));
  assert_that (received_authdn, is_equal_to_string ("uid=%s,dc=example"));
  assert_that (received_auth_cacert, is_equal_to_string ("certificate"));

  assert_that (yafvs_control_write_radius_auth_settings (
                 "123e4567-e89b-12d3-a456-426614174000", &radius),
               is_equal_to (MANAGE_AUTH_SETTINGS_OK));
  assert_that (auth_settings_radius_write_calls, is_equal_to (1));
  assert_that (received_radius_secret, is_equal_to_string ("secret"));
  assert_that (cleanup_calls, is_equal_to (3));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
  reset_auth_settings_test ();
}

Ensure (yafvs_control, round_trips_empty_auth_settings_fields)
{
  const char *ldap_request =
    "auth-settings-ldap-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 - - 0 1 -\n";
  const char *read_request =
    "auth-settings-read " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000\n";
  char response[YAFVS_CONTROL_AUTH_SETTINGS_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  reset_auth_settings_test ();
  auth_settings_ldap_write_result = MANAGE_AUTH_SETTINGS_INVALID_AUTH_DN;
  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_auth_settings_request (ldap_request, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("1 invalid-auth-dn\n"));
  assert_that (received_auth_host, is_equal_to_string (""));
  assert_that (received_authdn, is_equal_to_string (""));

  auth_settings_empty_required = TRUE;
  response_len = dispatch_auth_settings_request (read_request, response);
  response[response_len] = '\0';
  assert_that (g_str_has_prefix (response,
                                 "0 settings 1 1 - - 0 1 1 "), is_true);
  assert_that (g_str_has_suffix (response, " 1 0 - 1\n"), is_true);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  reset_auth_settings_test ();
}

Ensure (yafvs_control, rejects_unknown_auth_settings_operator_and_malformed_frame)
{
  const char *read_request =
    "auth-settings-read " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000\n";
  const char *malformed =
    "auth-settings-radius-write " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 bad= -\n";
  char response[YAFVS_CONTROL_AUTH_SETTINGS_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  reset_auth_settings_test ();
  mock_operator_name = NULL;
  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_auth_settings_request (read_request, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("99 permission-denied\n"));
  assert_that (auth_settings_read_calls, is_equal_to (0));

  mock_operator_name = "operator";
  response_len = dispatch_auth_settings_request (malformed, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("-2 invalid-request\n"));
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  reset_auth_settings_test ();
}

static void
assert_trash_empty_structured_audit (const char *message, const char *outcome,
                                     const char *expected_total,
                                     const char *actual_total)
{
  assert_that (trash_empty_structured_audit_calls, is_equal_to (1));
  assert_that (trash_empty_audit_message, is_equal_to_string (message));
  assert_that (trash_empty_audit_operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (trash_empty_audit_outcome, is_equal_to_string (outcome));
  assert_that (trash_empty_audit_expected_total,
               is_equal_to_string (expected_total));
  assert_that (trash_empty_audit_actual_total,
               is_equal_to_string (actual_total));
  assert_that (strstr (trash_empty_audit_message, TEST_CONTROL_SECRET),
               is_null);
}

Ensure (yafvs_control, accepts_strict_bounded_trash_empty_request)
{
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 9223372036854775807 "
    TEST_TRASH_SNAPSHOT_DIGEST "\n";
  char operator_uuid[37];
  char expected_snapshot_digest[65];
  gint64 expected_total = -1;

  assert_that (yafvs_control_parse_trash_empty_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 &expected_total, expected_snapshot_digest),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (expected_total, is_equal_to (G_MAXINT64));
  assert_that (expected_snapshot_digest,
               is_equal_to_string (TEST_TRASH_SNAPSHOT_DIGEST));
}

Ensure (yafvs_control, rejects_malformed_trash_empty_requests)
{
  const char *invalid[] = {
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 -1\n",
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 +1\n",
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 9223372036854775808\n",
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 extra\n",
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000  1\n",
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-42661417400z 1\n",
  };
  char operator_uuid[37];
  char expected_snapshot_digest[65];
  gint64 expected_total;
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (invalid); index++)
    assert_that (yafvs_control_parse_trash_empty_request (
                   invalid[index], strlen (invalid[index]),
                   TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                   operator_uuid, &expected_total, expected_snapshot_digest),
                 is_false);
}

Ensure (yafvs_control, maps_trash_empty_contract_responses)
{
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (yafvs_control_trash_empty_response (0, 7, response),
               is_equal_to_string ("0 emptied 7\n"));
  assert_that (yafvs_control_trash_empty_response (1, 8, response),
               is_equal_to_string ("1 expected-snapshot-mismatch 8\n"));
  assert_that (yafvs_control_trash_empty_response (2, 0, response),
               is_equal_to_string ("2 forbidden\n"));
  assert_that (yafvs_control_trash_empty_response (3, 0, response),
               is_equal_to_string ("3 operator-not-found\n"));
  assert_that (yafvs_control_trash_empty_response (-1, 0, response),
               is_equal_to_string ("-1 error\n"));
}

Ensure (yafvs_control, dispatches_trash_count_mismatch)
{
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 4 "
    TEST_TRASH_SNAPSHOT_DIGEST "\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  trash_empty_calls = 0;
  trash_empty_result = 1;
  trash_empty_actual = 5;
  trash_empty_expected = -1;
  mock_operator_name = "operator";
  reset_trash_empty_audit ();

  assert_that (g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
                         TRUE),
               is_true);
  response_len = dispatch_trash_empty_request (request, response);

  assert_that (response_len,
               is_equal_to (
                 (ssize_t) strlen ("1 expected-snapshot-mismatch 5\n")));
  assert_that (response,
               is_equal_to_string ("1 expected-snapshot-mismatch 5\n"));
  assert_that (trash_empty_calls, is_equal_to (1));
  assert_that (trash_empty_expected, is_equal_to (4));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
  assert_that (trash_empty_audit_success_calls, is_equal_to (0));
  assert_that (trash_empty_audit_fail_calls, is_equal_to (0));
  assert_trash_empty_structured_audit ("Trashcan empty request rejected",
                                       "expected-snapshot-mismatch", "4", "5");

  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  reset_trash_empty_audit ();
}

Ensure (yafvs_control, audits_successful_trash_empty)
{
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 5 "
    TEST_TRASH_SNAPSHOT_DIGEST "\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  trash_empty_calls = 0;
  trash_empty_result = 0;
  trash_empty_actual = 5;
  trash_empty_expected = -1;
  mock_operator_name = "operator";
  reset_trash_empty_audit ();

  assert_that (g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
                         TRUE),
               is_true);
  response_len = dispatch_trash_empty_request (request, response);

  assert_that (response_len,
               is_equal_to ((ssize_t) strlen ("0 emptied 5\n")));
  assert_that (response, is_equal_to_string ("0 emptied 5\n"));
  assert_that (trash_empty_calls, is_equal_to (1));
  assert_that (trash_empty_expected, is_equal_to (5));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
  assert_that (trash_empty_audit_success_calls, is_equal_to (1));
  assert_that (trash_empty_audit_fail_calls, is_equal_to (0));
  assert_trash_empty_structured_audit ("Trashcan emptied", "emptied", "5",
                                       "5");

  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  reset_trash_empty_audit ();
}

Ensure (yafvs_control, audits_trash_empty_failures)
{
  static const struct
  {
    int result;
    const char *response;
    const char *outcome;
  } cases[] = {
    {2, "2 forbidden\n", "forbidden"},
    {-1, "-1 error\n", "error"},
  };
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 5 "
    TEST_TRASH_SNAPSHOT_DIGEST "\n";
  size_t index;

  assert_that (g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
                         TRUE),
               is_true);

  for (index = 0; index < G_N_ELEMENTS (cases); index++)
    {
      char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
      ssize_t response_len;

      cleanup_calls = 0;
      reinit_calls = 0;
      session_init_calls = 0;
      trash_empty_calls = 0;
      trash_empty_result = cases[index].result;
      trash_empty_actual = 0;
      trash_empty_expected = -1;
      mock_operator_name = "operator";
      reset_trash_empty_audit ();

      response_len = dispatch_trash_empty_request (request, response);

      assert_that (response_len,
                   is_equal_to ((ssize_t) strlen (cases[index].response)));
      assert_that (response, is_equal_to_string (cases[index].response));
      assert_that (trash_empty_calls, is_equal_to (1));
      assert_that (trash_empty_expected, is_equal_to (5));
      assert_that (reinit_calls, is_equal_to (1));
      assert_that (session_init_calls, is_equal_to (1));
      assert_that (cleanup_calls, is_equal_to (1));
      assert_that (current_credentials.uuid, is_null);
      assert_that (current_credentials.username, is_null);
      assert_that (trash_empty_audit_success_calls, is_equal_to (0));
      assert_that (trash_empty_audit_fail_calls, is_equal_to (1));
      assert_trash_empty_structured_audit ("Trashcan empty request failed",
                                           cases[index].outcome, "5", "0");
      reset_trash_empty_audit ();
    }

  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
}

Ensure (yafvs_control, does_not_audit_missing_trash_operator)
{
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 5 "
    TEST_TRASH_SNAPSHOT_DIGEST "\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  trash_empty_calls = 0;
  mock_operator_name = NULL;
  reset_trash_empty_audit ();

  assert_that (g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
                         TRUE),
               is_true);
  response_len = dispatch_trash_empty_request (request, response);

  assert_that (response_len,
               is_equal_to ((ssize_t) strlen ("3 operator-not-found\n")));
  assert_that (response, is_equal_to_string ("3 operator-not-found\n"));
  assert_that (trash_empty_calls, is_equal_to (0));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
  assert_that (trash_empty_audit_success_calls, is_equal_to (0));
  assert_that (trash_empty_audit_fail_calls, is_equal_to (0));
  assert_that (trash_empty_structured_audit_calls, is_equal_to (0));

  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  reset_trash_empty_audit ();
}

Ensure (yafvs_control, locks_before_count_and_skips_delete_on_mismatch)
{
  static const char *base_tables[] = {
    "alerts_trash", "configs_trash", "credentials_trash", "filters_trash",
    "overrides_trash", "port_lists_trash", "report_formats_trash",
    "scanners_trash", "schedules_trash",
    "tags_trash", "targets_trash", "tasks",
  };
  long long int actual_total = -1;
  size_t index;

  trash_empty_db_event_count = 0;
  trash_empty_db_count = 6;
  trash_empty_db_acl = 1;
  trash_empty_count_sql = NULL;
  current_credentials.uuid =
    (gchar *) "123e4567-e89b-12d3-a456-426614174000";

  assert_that (__real_manage_empty_trashcan_confirmed (
                 5, TEST_TRASH_SNAPSHOT_DIGEST, &actual_total),
               is_equal_to (1));
  assert_that (actual_total, is_equal_to (6));
  assert_that (trash_empty_db_event_count, is_equal_to (6));
  assert_that (trash_empty_db_events[0], is_equal_to (TRASH_EMPTY_DB_BEGIN));
  assert_that (trash_empty_db_events[1],
               is_equal_to (TRASH_EMPTY_DB_USERS_LOCK));
  assert_that (trash_empty_db_events[2],
               is_equal_to (TRASH_EMPTY_DB_USER_LOCK));
  assert_that (trash_empty_db_events[3],
               is_equal_to (TRASH_EMPTY_DB_ACL));
  assert_that (trash_empty_db_events[4], is_equal_to (TRASH_EMPTY_DB_COUNT));
  assert_that (trash_empty_db_events[5],
               is_equal_to (TRASH_EMPTY_DB_ROLLBACK));

  for (index = 0; index < G_N_ELEMENTS (base_tables); index++)
    {
      gchar *count_fragment;

      count_fragment = g_strdup_printf ("FROM %s ", base_tables[index]);
      assert_that (strstr (trash_empty_count_sql, count_fragment),
                   is_not_null);
      g_free (count_fragment);
    }
  assert_that (strstr (trash_empty_count_sql, "hidden = 2"), is_not_null);

  current_credentials.uuid = NULL;
}

Ensure (yafvs_control, accepts_canonical_schedule_create_request)
{
  const char *calendar = "BEGIN:VCALENDAR\nEND:VCALENDAR\n";
  const char *timezone = "Europe/Berlin";
  gchar *calendar_b64 = g_base64_encode ((const guchar *) calendar,
                                         strlen (calendar));
  gchar *timezone_b64 = g_base64_encode ((const guchar *) timezone,
                                         strlen (timezone));
  gchar *request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "TmlnaHRseQ==  %s %s\n", timezone_b64, calendar_b64);
  char operator_uuid[37];
  yafvs_control_schedule_create_request_t schedule = {0};

  assert_that (yafvs_control_parse_schedule_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (schedule.name, is_equal_to_string ("Nightly"));
  assert_that (schedule.comment, is_equal_to_string (""));
  assert_that (schedule.timezone, is_equal_to_string (timezone));
  assert_that (schedule.icalendar, is_equal_to_string (calendar));

  yafvs_control_schedule_create_request_clear (&schedule);
  g_free (request);
  g_free (timezone_b64);
  g_free (calendar_b64);
}

Ensure (yafvs_control, accepts_maximum_schedule_fields)
{
  gchar *name = g_strnfill (YAFVS_CONTROL_SCHEDULE_NAME_MAX_BYTES, 'n');
  gchar *icalendar = g_strnfill (
    YAFVS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES, 'i');
  gchar *name_b64 = g_base64_encode ((const guchar *) name, strlen (name));
  gchar *icalendar_b64 = g_base64_encode ((const guchar *) icalendar,
                                           strlen (icalendar));
  gchar *request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "%s   %s\n", name_b64, icalendar_b64);
  char operator_uuid[37];
  yafvs_control_schedule_create_request_t schedule = {0};

  assert_that (yafvs_control_parse_schedule_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_true);
  assert_that (strlen (schedule.name),
               is_equal_to (YAFVS_CONTROL_SCHEDULE_NAME_MAX_BYTES));
  assert_that (strlen (schedule.icalendar),
               is_equal_to (YAFVS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES));

  yafvs_control_schedule_create_request_clear (&schedule);
  g_free (request);
  g_free (icalendar_b64);
  g_free (name_b64);
  g_free (icalendar);
  g_free (name);
}

Ensure (yafvs_control, rejects_noncanonical_or_oversized_schedule_fields)
{
  gchar *oversized_name = g_strnfill (
    YAFVS_CONTROL_SCHEDULE_NAME_MAX_BYTES + 1, 'a');
  gchar *oversized_icalendar = g_strnfill (
    YAFVS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES + 1, 'i');
  gchar *oversized_name_b64 = g_base64_encode ((const guchar *) oversized_name,
                                                strlen (oversized_name));
  gchar *oversized_icalendar_b64 = g_base64_encode (
    (const guchar *) oversized_icalendar, strlen (oversized_icalendar));
  gchar *invalid_request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "Nightly   QkVHSU46VkNBTEVOREFSCg==\n");
  gchar *oversized_request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "%s   QkVHSU46VkNBTEVOREFSCg==\n", oversized_name_b64);
  gchar *oversized_icalendar_request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "TmlnaHRseQ==   %s\n", oversized_icalendar_b64);
  gchar *overlong_request = g_strnfill (
    YAFVS_CONTROL_MAX_REQUEST_BYTES + 1, 'x');
  char operator_uuid[37];
  yafvs_control_schedule_create_request_t schedule = {0};

  assert_that (yafvs_control_parse_schedule_create_request (
                 invalid_request, strlen (invalid_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_create_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_create_request (
                 oversized_icalendar_request,
                 strlen (oversized_icalendar_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_create_request (
                 overlong_request, YAFVS_CONTROL_MAX_REQUEST_BYTES + 1,
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &schedule),
               is_false);

  g_free (overlong_request);
  g_free (oversized_icalendar_request);
  g_free (oversized_request);
  g_free (invalid_request);
  g_free (oversized_icalendar_b64);
  g_free (oversized_name_b64);
  g_free (oversized_icalendar);
  g_free (oversized_name);
}

Ensure (yafvs_control, creates_schedule_in_operator_session)
{
  const yafvs_control_schedule_create_request_t request = {
    .name = "Nightly",
    .comment = "",
    .timezone = "Europe/Berlin",
    .icalendar = "BEGIN:VCALENDAR\nEND:VCALENDAR\n",
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_schedule_calls = 0;
  create_schedule_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_create_schedule (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174002"));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (create_schedule_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (received_name, is_equal_to_string (request.name));
  assert_that (received_comment, is_equal_to_string (request.comment));
  assert_that (received_timezone, is_equal_to_string (request.timezone));
  assert_that (received_icalendar, is_equal_to_string (request.icalendar));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

static gchar *
test_alert_email_create_request (const char *active, const char *name,
                                 const char *comment, const char *status,
                                 const char *to_address,
                                 const char *from_address,
                                 const char *subject, const char *notice,
                                 const char *recipient_credential_uuid,
                                 const char *report_format_uuid,
                                 const char *unused,
                                 const char *message)
{
  gchar *fields[9];
  gchar *request;
  size_t index;

  (void) unused;

  fields[0] = g_base64_encode ((const guchar *) name, strlen (name));
  fields[1] = g_base64_encode ((const guchar *) comment, strlen (comment));
  fields[2] = g_base64_encode ((const guchar *) status, strlen (status));
  fields[3] = g_base64_encode ((const guchar *) to_address,
                               strlen (to_address));
  fields[4] = g_base64_encode ((const guchar *) from_address,
                               strlen (from_address));
  fields[5] = g_base64_encode ((const guchar *) subject, strlen (subject));
  fields[6] = g_base64_encode ((const guchar *) recipient_credential_uuid,
                               strlen (recipient_credential_uuid));
  fields[7] = g_base64_encode ((const guchar *) report_format_uuid,
                               strlen (report_format_uuid));
  fields[8] = g_base64_encode ((const guchar *) message, strlen (message));
  request = g_strdup_printf (
    "alert-email-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 %s %s %s %s %s %s %s %s %s %s "
    "%s\n",
    active, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
    notice, fields[6], fields[7], fields[8]);
  for (index = 0; index < G_N_ELEMENTS (fields); index++)
    g_free (fields[index]);
  return request;
}

static gchar *
test_alert_start_task_create_request (const char *active, const char *name,
                                      const char *comment, const char *status,
                                      const char *task_uuid)
{
  const char *values[] = {name, comment, status};
  gchar *fields[G_N_ELEMENTS (values)];
  gchar *request;
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (values); index++)
    fields[index] =
      g_base64_encode ((const guchar *) values[index], strlen (values[index]));
  request =
    g_strdup_printf ("alert-start-task-create " TEST_CONTROL_SECRET " "
                     "123e4567-e89b-12d3-a456-426614174000 %s %s %s %s %s\n",
                     active, fields[0], fields[1], fields[2], task_uuid);
  for (index = 0; index < G_N_ELEMENTS (fields); index++)
    g_free (fields[index]);
  return request;
}

static gchar *
test_alert_scp_create_request (const char *active, const char *name,
                               const char *comment, const char *status,
                               const char *credential_uuid, const char *host,
                               const char *port, const char *known_hosts,
                               const char *path,
                               const char *report_format_uuid)
{
  const char *values[] = {
    name, comment, status, credential_uuid, host,
    port, known_hosts, path, report_format_uuid,
  };
  gchar *fields[G_N_ELEMENTS (values)];
  gchar *request;
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (values); index++)
    fields[index] =
      g_base64_encode ((const guchar *) values[index], strlen (values[index]));
  request = g_strdup_printf (
    "alert-scp-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 %s %s %s %s %s %s %s %s %s %s\n",
    active, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
    fields[6], fields[7], fields[8]);
  for (index = 0; index < G_N_ELEMENTS (fields); index++)
    g_free (fields[index]);
  return request;
}

static gchar *
test_alert_syslog_create_request (const char *active, const char *name,
                                  const char *comment, const char *status)
{
  const char *values[] = { name, comment, status };
  gchar *fields[G_N_ELEMENTS (values)];
  gchar *request;
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (values); index++)
    fields[index] =
      g_base64_encode ((const guchar *) values[index], strlen (values[index]));
  request = g_strdup_printf (
    "alert-syslog-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 %s %s %s %s\n",
    active, fields[0], fields[1], fields[2]);
  for (index = 0; index < G_N_ELEMENTS (fields); index++)
    g_free (fields[index]);
  return request;
}

static gchar *
test_alert_snmp_create_request (const char *active, const char *name,
                                const char *comment, const char *status,
                                const char *agent, const char *community,
                                const char *message)
{
  const char *values[] = { name, comment, status, agent, community, message };
  gchar *fields[G_N_ELEMENTS (values)];
  gchar *request;
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (values); index++)
    fields[index] =
      g_base64_encode ((const guchar *) values[index], strlen (values[index]));
  request = g_strdup_printf (
    "alert-snmp-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 %s %s %s %s %s %s %s\n",
    active, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]);
  for (index = 0; index < G_N_ELEMENTS (fields); index++)
    g_free (fields[index]);
  return request;
}

static gchar *
test_alert_smb_create_request (const char *active, const char *name,
                               const char *comment, const char *status,
                               const char *credential_uuid,
                               const char *share_path, const char *file_path,
                               const char *report_format_uuid,
                               const char *unused,
                               const char *max_protocol)
{
  const char *values[] = {
    name,
    comment,
    status,
    credential_uuid,
    share_path,
    file_path,
    report_format_uuid,
    max_protocol,
  };
  gchar *fields[G_N_ELEMENTS (values)];
  gchar *request;
  size_t index;

  (void) unused;

  for (index = 0; index < G_N_ELEMENTS (values); index++)
    fields[index] =
      g_base64_encode ((const guchar *) values[index], strlen (values[index]));
  request = g_strdup_printf (
    "alert-smb-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 %s %s %s %s %s %s %s %s %s\n",
    active, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
    fields[6], fields[7]);
  for (index = 0; index < G_N_ELEMENTS (fields); index++)
    g_free (fields[index]);
  return request;
}

Ensure (yafvs_control, parses_canonical_bounded_alert_email_request)
{
  static const char *statuses[] = {
    "Delete Requested", "Ultimate Delete Requested",
    "Ultimate Delete Waiting", "Delete Waiting", "Done", "New", "Requested",
    "Running", "Queued", "Stop Requested", "Stop Waiting", "Stopped",
    "Processing", "Interrupted",
  };
  const char *recipient = "123e4567-e89b-12d3-a456-426614174010";
  const char *format = "123e4567-e89b-12d3-a456-426614174011";
  char operator_uuid[37];
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (statuses); index++)
    {
      gchar *request = test_alert_email_create_request (
        "1", "Email alert", "comment", statuses[index], "ops@example.com",
        "sender@example.com", "subject", "0", recipient, format,
        "", "Line one\nLine two");
      yafvs_control_alert_email_create_request_t alert = {0};

      assert_that (yafvs_control_parse_alert_email_create_request (
                     request, strlen (request), TEST_CONTROL_SECRET,
                     strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
                   is_true);
      assert_that (operator_uuid,
                   is_equal_to_string
                     ("123e4567-e89b-12d3-a456-426614174000"));
      assert_that (alert.active, is_true);
      assert_that (alert.notice, is_equal_to (0));
      assert_that (alert.status, is_equal_to_string (statuses[index]));
      assert_that (alert.to_address,
                   is_equal_to_string ("ops@example.com"));
      assert_that (alert.recipient_credential_uuid,
                   is_equal_to_string (recipient));
      assert_that (alert.report_format_uuid, is_equal_to_string (format));
      assert_that (alert.message,
                   is_equal_to_string ("Line one\nLine two"));
      yafvs_control_alert_email_create_request_clear (&alert);
      g_free (request);
    }
}

Ensure (yafvs_control, enforces_alert_email_notice_mode_semantics)
{
  const char *format = "123e4567-e89b-12d3-a456-426614174011";
  const char *report_notices[] = {"0", "2"};
  gchar *request;
  gchar *invalid[5];
  char operator_uuid[37];
  size_t index;
  yafvs_control_alert_email_create_request_t alert = {0};

  request = test_alert_email_create_request (
    "1", "Simple", "", "Running", "ops@example.com", "", "subject", "1",
    "", "", "", "simple message");
  assert_that (yafvs_control_parse_alert_email_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
               is_true);
  assert_that (alert.message, is_equal_to_string ("simple message"));
  yafvs_control_alert_email_create_request_clear (&alert);
  g_free (request);

  for (index = 0; index < G_N_ELEMENTS (report_notices); index++)
    {
      request = test_alert_email_create_request (
        "1", "Report", "", "Running", "ops@example.com", "", "subject",
        report_notices[index], "", format, "", "");
      assert_that (yafvs_control_parse_alert_email_create_request (
                     request, strlen (request), TEST_CONTROL_SECRET,
                     strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
                   is_true);
      yafvs_control_alert_email_create_request_clear (&alert);
      g_free (request);
    }

  invalid[0] = test_alert_email_create_request (
    "1", "Missing subject", "", "Running", "ops@example.com", "", "", "0",
    "", format, "", "");
  invalid[1] = test_alert_email_create_request (
    "1", "Simple format", "", "Running", "ops@example.com", "", "subject",
    "1", "", format, "", "");
  invalid[2] = test_alert_email_create_request (
    "1", "Simple format duplicate", "", "Running", "ops@example.com", "",
    "subject", "1", "", format, "", "");
  invalid[3] = test_alert_email_create_request (
    "1", "Include no format", "", "Running", "ops@example.com", "",
    "subject", "0", "", "", "", "");
  invalid[4] = test_alert_email_create_request (
    "1", "Attach no format", "", "Running", "ops@example.com", "",
    "subject", "2", "", "", "", "");
  for (index = 0; index < G_N_ELEMENTS (invalid); index++)
    {
      assert_that (yafvs_control_parse_alert_email_create_request (
                     invalid[index], strlen (invalid[index]),
                     TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                     operator_uuid, &alert),
                   is_false);
      g_free (invalid[index]);
    }
}

Ensure (yafvs_control, returns_malformed_for_truncated_alert_frame)
{
  const char *partial = "alert-email-create " TEST_CONTROL_SECRET " partial";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  int sockets[2];
  ssize_t response_len;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
                         TRUE),
               is_true);
  assert_that (write (sockets[0], partial, strlen (partial)),
               is_equal_to ((ssize_t) strlen (partial)));
  assert_that (shutdown (sockets[0], SHUT_WR), is_equal_to (0));
  yafvs_control_serve_client (sockets[1]);
  response_len = read (sockets[0], response, sizeof (response) - 1);
  assert_that (response_len, is_equal_to ((ssize_t) strlen ("-2 malformed\n")));
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  close (sockets[0]);
  close (sockets[1]);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
}

Ensure (yafvs_control, enforces_alert_email_canonicalization_and_bounds)
{
  gchar *max_name = g_strnfill (YAFVS_CONTROL_ALERT_NAME_MAX_BYTES, 'n');
  gchar *max_comment =
    g_strnfill (YAFVS_CONTROL_ALERT_COMMENT_MAX_BYTES, 'c');
  gchar *max_to = g_strnfill (YAFVS_CONTROL_ALERT_ADDRESS_MAX_BYTES, 't');
  gchar *max_from =
    g_strnfill (YAFVS_CONTROL_ALERT_ADDRESS_MAX_BYTES, 'f');
  gchar *max_subject =
    g_strnfill (YAFVS_CONTROL_ALERT_SUBJECT_MAX_BYTES, 's');
  gchar *max_message =
    g_strnfill (YAFVS_CONTROL_ALERT_MESSAGE_MAX_BYTES, 'm');
  gchar *oversized_name =
    g_strnfill (YAFVS_CONTROL_ALERT_NAME_MAX_BYTES + 1, 'n');
  gchar *oversized_subject =
    g_strnfill (YAFVS_CONTROL_ALERT_SUBJECT_MAX_BYTES + 1, 's');
  gchar *oversized_message =
    g_strnfill (YAFVS_CONTROL_ALERT_MESSAGE_MAX_BYTES + 1, 'm');
  gchar *requests[6];
  char full_frame[YAFVS_CONTROL_MAX_REQUEST_BYTES];
  char operator_uuid[37];
  size_t index;
  yafvs_control_alert_email_create_request_t alert = {0};

  requests[0] = test_alert_email_create_request (
    "0", max_name, max_comment, "Running", max_to, max_from, max_subject, "2",
    "", "123e4567-e89b-12d3-a456-426614174011",
    "123e4567-e89b-12d3-a456-426614174012", max_message);
  assert_that (strlen (requests[0]),
               is_less_than (YAFVS_CONTROL_MAX_REQUEST_BYTES));
  assert_that (yafvs_control_parse_alert_email_create_request (
                 requests[0], strlen (requests[0]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
               is_true);
  yafvs_control_alert_email_create_request_clear (&alert);

  requests[1] = test_alert_email_create_request (
    "0", oversized_name, "", "Running", "ops@example.com", "", "", "1", "",
    "", "", "");
  requests[2] = test_alert_email_create_request (
    "0", "name", "", "Running", "ops@example.com", "", oversized_subject,
    "1", "", "", "", "");
  requests[3] = test_alert_email_create_request (
    "0", "name", "", "Running", "ops@example.com", "", "", "1", "", "", "",
    oversized_message);
  requests[4] = test_alert_email_create_request (
    "2", "name", "", "Not a status", "ops@example.com", "", "", "3",
    "not-a-uuid", "", "", "");
  requests[5] = g_strdup (
    "alert-email-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 1 QQ Q29tbWVudA== UnVubmluZw== "
    "b3BzQGV4YW1wbGUuY29t   1    \n");
  for (index = 1; index < G_N_ELEMENTS (requests); index++)
    assert_that (yafvs_control_parse_alert_email_create_request (
                   requests[index], strlen (requests[index]),
                   TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                   operator_uuid, &alert),
                 is_false);
  memset (full_frame, 'x', sizeof (full_frame));
  memcpy (full_frame, YAFVS_CONTROL_ALERT_EMAIL_CREATE_COMMAND,
          YAFVS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH);
  full_frame[sizeof (full_frame) - 1] = '\n';
  assert_that (yafvs_control_parse_alert_email_create_request (
                 full_frame, sizeof (full_frame), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
               is_false);

  for (index = 0; index < G_N_ELEMENTS (requests); index++)
    g_free (requests[index]);
  g_free (max_name);
  g_free (max_comment);
  g_free (max_to);
  g_free (max_from);
  g_free (max_subject);
  g_free (max_message);
  g_free (oversized_name);
  g_free (oversized_subject);
  g_free (oversized_message);
}

Ensure (yafvs_control, maps_alert_email_arrays_session_and_success_audit)
{
  const yafvs_control_alert_email_create_request_t request = {
    .name = "Email alert",
    .comment = "comment",
    .status = "Running",
    .to_address = "ops@example.com",
    .from_address = "sender@example.com",
    .subject = "subject",
    .recipient_credential_uuid = "123e4567-e89b-12d3-a456-426614174010",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .message = "selected include message",
    .active = TRUE,
    .notice = 0,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  create_alert_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174004"));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (received_alert_event,
               is_equal_to (EVENT_TASK_RUN_STATUS_CHANGED));
  assert_that (received_alert_condition, is_equal_to (ALERT_CONDITION_ALWAYS));
  assert_that (received_alert_method, is_equal_to (ALERT_METHOD_EMAIL));
  assert_that (received_active, is_equal_to_string ("1"));
  assert_that (received_event_status, is_equal_to_string ("Running"));
  assert_that (received_to_address, is_equal_to_string ("ops@example.com"));
  assert_that (received_from_address,
               is_equal_to_string ("sender@example.com"));
  assert_that (received_subject, is_equal_to_string ("subject"));
  assert_that (received_notice, is_equal_to_string ("0"));
  assert_that (received_recipient_credential,
               is_equal_to_string (request.recipient_credential_uuid));
  assert_that (received_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_atomic_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_message, is_equal_to_string (request.message));
  assert_that (audit_success_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (received_audit_uuid, is_equal_to_string (created_uuid));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, maps_selected_attach_message_and_failure_audit)
{
  const yafvs_control_alert_email_create_request_t request = {
    .name = "Attach alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .message = "selected attach message", .active = FALSE, .notice = 2,
  };
  char created_uuid[37];

  create_alert_calls = 0;
  create_alert_result = 2;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (2));
  assert_that (received_active, is_equal_to_string ("0"));
  assert_that (received_notice, is_equal_to_string ("2"));
  assert_that (received_from_address, is_null);
  assert_that (received_recipient_credential, is_null);
  assert_that (received_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_message, is_equal_to_string (request.message));
  assert_that (audit_success_calls, is_equal_to (0));
  assert_that (audit_fail_calls, is_equal_to (1));
}

Ensure (yafvs_control, maps_simple_notice_without_report_selectors)
{
  const yafvs_control_alert_email_create_request_t request = {
    .name = "Simple alert", .comment = "", .status = "Stopped",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "", .report_format_uuid = "",
    .message = "simple message",
    .active = TRUE, .notice = 1,
  };
  char created_uuid[37];

  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";
  assert_that (yafvs_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (received_notice, is_equal_to_string ("1"));
  assert_that (received_report_format, is_null);
  assert_that (received_atomic_report_format, is_equal_to_string (""));
  assert_that (received_from_address, is_null);
  assert_that (received_recipient_credential, is_null);
  assert_that (received_message, is_equal_to_string (request.message));
  assert_that (audit_success_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (0));
}

Ensure (yafvs_control, omits_empty_optional_report_method_data)
{
  const yafvs_control_alert_email_create_request_t request = {
    .name = "Include alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .message = "", .active = TRUE, .notice = 0,
  };
  char created_uuid[37];

  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";
  assert_that (yafvs_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (received_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_from_address, is_null);
  assert_that (received_recipient_credential, is_null);
  assert_that (received_message, is_null);
}

Ensure (yafvs_control, rejects_missing_alert_operator_before_authority)
{
  const yafvs_control_alert_email_create_request_t request = {
    .name = "Email alert", .comment = "", .status = "Running",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "", .report_format_uuid = "",
    .message = "", .active = TRUE, .notice = 1,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  audit_fail_calls = 0;
  mock_operator_name = NULL;
  assert_that (yafvs_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (99));
  assert_that (create_alert_calls, is_equal_to (0));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
}

Ensure (yafvs_control, maps_atomic_unavailable_alert_report_format)
{
  const yafvs_control_alert_email_create_request_t request = {
    .name = "Include alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .message = "delivery payload",
    .active = TRUE, .notice = 0,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  audit_fail_calls = 0;
  create_alert_result = 90;
  mock_operator_name = "operator";

  assert_that (yafvs_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (90));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (received_atomic_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (audit_fail_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, reports_postcommit_alert_uuid_failure_without_failed_audit)
{
  const yafvs_control_alert_email_create_request_t request = {
    .name = "Simple alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "", .report_format_uuid = "",
    .message = "delivery payload",
    .active = TRUE, .notice = 1,
  };
  char created_uuid[37];

  alert_uuid_lookup_fails = TRUE;
  cleanup_calls = 0;
  create_alert_calls = 0;
  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (-3));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (audit_success_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (received_audit_uuid, is_null);
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
  alert_uuid_lookup_fails = FALSE;
}

Ensure (yafvs_control, rejects_missing_alert_smb_operator_before_authority)
{
  const yafvs_control_alert_smb_create_request_t request = {
    .name = "SMB alert",
    .comment = "",
    .status = "Done",
    .credential_uuid = "123e4567-e89b-12d3-a456-426614174010",
    .share_path = "\\\\fileserver\\reports",
    .file_path = "scan/report.pdf",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .max_protocol = "",
    .active = TRUE,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  audit_fail_calls = 0;
  mock_operator_name = NULL;
  assert_that (
    yafvs_control_create_alert_smb ("123e4567-e89b-12d3-a456-426614174000",
                                       &request, created_uuid),
    is_equal_to (99));
  assert_that (create_alert_calls, is_equal_to (0));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, maps_every_alert_create_response)
{
  static const struct
  {
    int result;
    const char *response;
  } cases[] = {
    {1, "1 exists\n"}, {2, "2 invalid_email\n"},
    {3, "3 filter_not_found\n"}, {4, "4 invalid_filter_type\n"},
    {5, "5 invalid_condition_name\n"}, {6, "6 invalid_condition_data\n"},
    {7, "7 subject_too_long\n"}, {8, "8 message_too_long\n"},
    {9, "9 condition_filter_not_found\n"}, {15, "15 invalid_scp_host\n"},
    {16, "16 invalid_scp_port\n"},
    {17, "17 scp_format_not_found\n"},
    {18, "18 invalid_scp_credential\n"}, {19, "19 invalid_scp_path\n"},
    {20, "20 method_event_mismatch\n"},
    {21, "21 condition_event_mismatch\n"},
    {31, "31 invalid_event_name\n"}, {32, "32 invalid_event_data\n"},
    {40, "40 invalid_smb_credential\n"}, {41, "41 invalid_smb_share\n"},
    {42, "42 invalid_smb_path\n"}, {43, "43 dotted_smb_path\n"},
    {60, "60 recipient_credential_not_found\n"},
    {61, "61 invalid_recipient_credential\n"},
    {90, "90 report_format_not_found\n"}, {99, "99 forbidden\n"},
    {-3, "-3 committed_indeterminate\n"}, {-2, "-2 malformed\n"},
    {-1, "-1 internal\n"},
  };
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];
  size_t index;

  assert_that (
    yafvs_control_alert_create_response (
      0, "123e4567-e89b-12d3-a456-426614174004", response),
    is_equal_to_string ("0 created 123e4567-e89b-12d3-a456-426614174004\n"));
  assert_that (yafvs_control_alert_create_response (0, NULL, response),
               is_equal_to_string ("-1 internal\n"));
  for (index = 0; index < G_N_ELEMENTS (cases); index++)
    {
      assert_that (strlen (cases[index].response),
                   is_less_than (YAFVS_CONTROL_MAX_RESPONSE_BYTES));
      assert_that (yafvs_control_alert_create_response (cases[index].result,
                                                           NULL, response),
                   is_equal_to_string (cases[index].response));
    }
}

Ensure (yafvs_control, parses_syslog_and_required_snmp_alert_requests)
{
  gchar *syslog_request = test_alert_syslog_create_request (
    "1", "Syslog alert", "retained", "Done");
  gchar *snmp_request = test_alert_snmp_create_request (
    "0", "SNMP alert", "retained", "Running", "snmp.example.test",
    "private-community", "Task {{status}}");
  char operator_uuid[37];
  yafvs_control_alert_syslog_create_request_t syslog_alert = {0};
  yafvs_control_alert_snmp_create_request_t snmp_alert = {0};

  assert_that (yafvs_control_parse_alert_syslog_create_request (
                 syslog_request, strlen (syslog_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &syslog_alert),
               is_true);
  assert_that (syslog_alert.active, is_true);
  assert_that (syslog_alert.name, is_equal_to_string ("Syslog alert"));
  assert_that (syslog_alert.status, is_equal_to_string ("Done"));
  yafvs_control_alert_syslog_create_request_clear (&syslog_alert);

  assert_that (yafvs_control_parse_alert_snmp_create_request (
                 snmp_request, strlen (snmp_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &snmp_alert),
               is_true);
  assert_that (snmp_alert.active, is_false);
  assert_that (snmp_alert.agent, is_equal_to_string ("snmp.example.test"));
  assert_that (snmp_alert.community,
               is_equal_to_string ("private-community"));
  assert_that (snmp_alert.message,
               is_equal_to_string ("Task {{status}}"));
  yafvs_control_alert_snmp_create_request_clear (&snmp_alert);
  g_free (syslog_request);
  g_free (snmp_request);
}

Ensure (yafvs_control, rejects_malformed_or_empty_snmp_alert_payloads)
{
  gchar *invalid[] = {
    test_alert_snmp_create_request (
      "2", "SNMP alert", "", "Done", "snmp.example.test",
      "private-community", "Task {{status}}"),
    test_alert_snmp_create_request (
      "1", "SNMP alert", "", "Done", "", "private-community",
      "Task {{status}}"),
    test_alert_snmp_create_request (
      "1", "SNMP alert", "", "Done", "snmp.example.test", "",
      "Task {{status}}"),
    test_alert_snmp_create_request (
      "1", "SNMP alert", "", "Done", "snmp.example.test",
      "private-community", ""),
    test_alert_snmp_create_request (
      "1", "SNMP alert", "", "Done", "snmp.example.test",
      "private-community", "unsupported\x01" "control"),
    g_strdup ("alert-snmp-create " TEST_CONTROL_SECRET " "
              "123e4567-e89b-12d3-a456-426614174000 1 QQ==\n"),
  };
  char operator_uuid[37];
  size_t index;
  yafvs_control_alert_snmp_create_request_t alert = {0};

  for (index = 0; index < G_N_ELEMENTS (invalid); index++)
    {
      assert_that (yafvs_control_parse_alert_snmp_create_request (
                     invalid[index], strlen (invalid[index]),
                     TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                     operator_uuid, &alert),
                   is_false);
      g_free (invalid[index]);
    }
}

Ensure (yafvs_control, maps_fixed_syslog_and_snmp_alert_creation)
{
  const yafvs_control_alert_syslog_create_request_t syslog_request = {
    .name = "Syslog alert", .comment = "retained", .status = "Done",
    .active = TRUE,
  };
  const yafvs_control_alert_snmp_create_request_t snmp_request = {
    .name = "SNMP alert", .comment = "retained", .status = "Running",
    .agent = "snmp.example.test", .community = "private-community",
    .message = "Task {{status}}", .active = FALSE,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_create_alert_syslog (
                 "123e4567-e89b-12d3-a456-426614174000", &syslog_request,
                 created_uuid),
               is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174004"));
  assert_that (received_alert_event,
               is_equal_to (EVENT_TASK_RUN_STATUS_CHANGED));
  assert_that (received_alert_condition, is_equal_to (ALERT_CONDITION_ALWAYS));
  assert_that (received_alert_method, is_equal_to (ALERT_METHOD_SYSLOG));
  assert_that (received_active, is_equal_to_string ("1"));
  assert_that (received_event_status, is_equal_to_string ("Done"));
  assert_that (received_syslog_submethod, is_equal_to_string ("syslog"));
  assert_that (audit_success_calls, is_equal_to (1));

  assert_that (yafvs_control_create_alert_snmp (
                 "123e4567-e89b-12d3-a456-426614174000", &snmp_request,
                 created_uuid),
               is_equal_to (0));
  assert_that (received_alert_method, is_equal_to (ALERT_METHOD_SNMP));
  assert_that (received_active, is_equal_to_string ("0"));
  assert_that (received_event_status, is_equal_to_string ("Running"));
  assert_that (received_snmp_agent,
               is_equal_to_string ("snmp.example.test"));
  assert_that (received_snmp_community,
               is_equal_to_string ("private-community"));
  assert_that (received_snmp_message,
               is_equal_to_string ("Task {{status}}"));
  assert_that (create_alert_calls, is_equal_to (2));
  assert_that (audit_success_calls, is_equal_to (2));
  assert_that (audit_fail_calls, is_equal_to (0));
}

Ensure (yafvs_control, rejects_missing_snmp_owner_and_maps_alert_errors)
{
  const yafvs_control_alert_snmp_create_request_t request = {
    .name = "SNMP alert", .comment = "", .status = "Done",
    .agent = "snmp.example.test", .community = "private-community",
    .message = "Task {{status}}", .active = TRUE,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  audit_fail_calls = 0;
  mock_operator_name = NULL;
  assert_that (yafvs_control_create_alert_snmp (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (99));
  assert_that (create_alert_calls, is_equal_to (0));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));

  create_alert_result = 99;
  audit_fail_calls = 0;
  mock_operator_name = "operator";
  assert_that (yafvs_control_create_alert_snmp (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (99));
  assert_that (audit_fail_calls, is_equal_to (1));
  create_alert_result = 0;
}

Ensure (yafvs_control, parses_strict_start_task_alert_frame)
{
  gchar *request = test_alert_start_task_create_request (
    "1", "Start follow-up", "operator-only", "Done",
    "123e4567-e89b-12d3-a456-426614174020");
  char operator_uuid[37];
  yafvs_control_alert_start_task_create_request_t alert = {0};

  assert_that (ALERT_METHOD_START_TASK, is_equal_to (4));
  assert_that (yafvs_control_parse_alert_start_task_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (alert.active, is_true);
  assert_that (alert.name, is_equal_to_string ("Start follow-up"));
  assert_that (alert.comment, is_equal_to_string ("operator-only"));
  assert_that (alert.status, is_equal_to_string ("Done"));
  assert_that (alert.task_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174020"));
  yafvs_control_alert_start_task_create_request_clear (&alert);
  g_free (request);
}

Ensure (yafvs_control, rejects_bad_uuid_and_malformed_start_task_alerts)
{
  gchar *oversized =
    g_strnfill (YAFVS_CONTROL_ALERT_NAME_MAX_BYTES + 1, 'x');
  gchar *requests[] = {
    test_alert_start_task_create_request ("1", "Start follow-up", "", "Done",
                                          "not-a-task-uuid"),
    test_alert_start_task_create_request (
      "2", "Start follow-up", "", "Done",
      "123e4567-e89b-12d3-a456-426614174020"),
    test_alert_start_task_create_request (
      "1", "Start follow-up", "", "Invalid",
      "123e4567-e89b-12d3-a456-426614174020"),
    test_alert_start_task_create_request (
      "1", oversized, "", "Done", "123e4567-e89b-12d3-a456-426614174020"),
    g_strdup ("alert-start-task-create " TEST_CONTROL_SECRET " "
              "123e4567-e89b-12d3-a456-426614174000 1 QQ==  RG9uZQ== "
              "123e4567-e89b-12d3-a456-426614174020 extra\n"),
  };
  char operator_uuid[37];
  yafvs_control_alert_start_task_create_request_t alert = {0};

  for (size_t index = 0; index < G_N_ELEMENTS (requests); index++)
    {
      assert_that (yafvs_control_parse_alert_start_task_create_request (
                     requests[index], strlen (requests[index]),
                     TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                     operator_uuid, &alert),
                   is_false);
      g_free (requests[index]);
    }
  g_free (oversized);
}

Ensure (yafvs_control, maps_start_task_alert_creation_and_commit_status)
{
  const yafvs_control_alert_start_task_create_request_t request = {
    .name = "Start follow-up",
    .comment = "operator-only",
    .status = "Done",
    .task_uuid = "123e4567-e89b-12d3-a456-426614174020",
    .active = TRUE,
  };
  char created_uuid[37];

  alert_uuid_lookup_fails = FALSE;
  cleanup_calls = 0;
  create_alert_calls = 0;
  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (
    yafvs_control_create_alert_start_task (
      "123e4567-e89b-12d3-a456-426614174000", &request, created_uuid),
    is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174004"));
  assert_that (received_alert_event,
               is_equal_to (EVENT_TASK_RUN_STATUS_CHANGED));
  assert_that (received_alert_condition, is_equal_to (ALERT_CONDITION_ALWAYS));
  assert_that (received_alert_method, is_equal_to (ALERT_METHOD_START_TASK));
  assert_that (received_active, is_equal_to_string ("1"));
  assert_that (received_event_status, is_equal_to_string ("Done"));
  assert_that (received_start_task_uuid,
               is_equal_to_string (request.task_uuid));
  assert_that (audit_success_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));

  alert_uuid_lookup_fails = TRUE;
  assert_that (
    yafvs_control_create_alert_start_task (
      "123e4567-e89b-12d3-a456-426614174000", &request, created_uuid),
    is_equal_to (-3));
  assert_that (audit_success_calls, is_equal_to (2));
  assert_that (audit_fail_calls, is_equal_to (0));
  alert_uuid_lookup_fails = FALSE;
}

static void
capture_control_log (const gchar *domain, GLogLevelFlags level,
                     const gchar *message, gpointer user_data)
{
  unsigned int *calls = user_data;
  (void) domain;
  (void) level;
  (*calls)++;
  assert_that (strstr (message, TEST_CONTROL_SECRET), is_null);
  assert_that (strstr (message, "alert-start-task-create"), is_null);
}

Ensure (yafvs_control, classifies_start_task_frames_without_logging_them)
{
  const char *request =
    "alert-start-task-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 private-control-frame\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  unsigned int log_calls = 0;
  guint handler;
  ssize_t response_len;

  handler = g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_MASK,
                               capture_control_log, &log_calls);
  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_trash_empty_request (request, response);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  g_log_remove_handler (G_LOG_DOMAIN, handler);

  assert_that (response_len, is_equal_to (strlen ("-2 malformed\n")));
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  assert_that (log_calls, is_equal_to (0));
  assert_that (strstr (response, TEST_CONTROL_SECRET), is_null);
  assert_that (strstr (response, "private-control-frame"), is_null);
}

static int
call_real_alert_start_task_create (void)
{
  array_t *condition_data = make_array ();
  array_t *event_data = make_array ();
  alert_t alert = 0;
  int result;

  current_credentials.uuid = g_strdup ("123e4567-e89b-12d3-a456-426614174000");
  current_credentials.username = g_strdup ("operator");
  yafvs_control_array_add_data (event_data, "status", "Done");
  array_terminate (condition_data);
  array_terminate (event_data);

  result = __real_create_alert_start_task_with_task_ref (
    "Start follow-up", "operator-only", "1", event_data, condition_data,
    "123e4567-e89b-12d3-a456-426614174020", &alert);
  yafvs_control_secure_array_free (condition_data);
  yafvs_control_secure_array_free (event_data);
  g_clear_pointer (&current_credentials.uuid, g_free);
  g_clear_pointer (&current_credentials.username, g_free);
  alert_start_task_db_active = FALSE;
  return result;
}

Ensure (yafvs_control, locks_start_task_reference_and_commits_atomically)
{
  static const enum alert_start_task_db_event expected[] = {
    ALERT_START_TASK_DB_BEGIN,         ALERT_START_TASK_DB_ACL,
    ALERT_START_TASK_DB_OWNER_LOCK,    ALERT_START_TASK_DB_TASK_RESOLVE,
    ALERT_START_TASK_DB_TASK_LOCK,     ALERT_START_TASK_DB_BODY_INSERT,
    ALERT_START_TASK_DB_METHOD_INSERT, ALERT_START_TASK_DB_COMMIT,
  };

  reset_alert_start_task_db ();
  assert_that (call_real_alert_start_task_create (), is_equal_to (0));
  assert_that (alert_start_task_db_method_inserts, is_equal_to (1));
  assert_that (alert_start_task_db_event_count,
               is_equal_to (G_N_ELEMENTS (expected)));
  assert_that (memcmp (alert_start_task_db_events, expected, sizeof (expected)),
               is_equal_to (0));
}

Ensure (yafvs_control, rejects_unauthorized_missing_and_duplicate_start_task)
{
  reset_alert_start_task_db ();
  alert_start_task_db_acl = FALSE;
  assert_that (call_real_alert_start_task_create (), is_equal_to (99));
  assert_that (alert_start_task_db_events[alert_start_task_db_event_count - 1],
               is_equal_to (ALERT_START_TASK_DB_ROLLBACK));

  reset_alert_start_task_db ();
  alert_start_task_db_task_readable = FALSE;
  assert_that (call_real_alert_start_task_create (), is_equal_to (3));
  assert_that (alert_start_task_db_events[alert_start_task_db_event_count - 1],
               is_equal_to (ALERT_START_TASK_DB_ROLLBACK));

  reset_alert_start_task_db ();
  alert_start_task_db_task_owned = FALSE;
  assert_that (call_real_alert_start_task_create (), is_equal_to (3));
  assert_that (alert_start_task_db_events[alert_start_task_db_event_count - 1],
               is_equal_to (ALERT_START_TASK_DB_ROLLBACK));

  reset_alert_start_task_db ();
  alert_start_task_db_duplicate_name = TRUE;
  assert_that (call_real_alert_start_task_create (), is_equal_to (1));
  assert_that (alert_start_task_db_events[alert_start_task_db_event_count - 1],
               is_equal_to (ALERT_START_TASK_DB_ROLLBACK));
  assert_that (alert_start_task_db_method_inserts, is_equal_to (0));
}

Ensure (yafvs_control, maps_start_task_alert_responses)
{
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (
    yafvs_control_alert_start_task_create_response (
      0, "123e4567-e89b-12d3-a456-426614174004", response),
    is_equal_to_string ("0 created 123e4567-e89b-12d3-a456-426614174004\n"));
  assert_that (
    yafvs_control_alert_start_task_create_response (1, NULL, response),
    is_equal_to_string ("1 exists\n"));
  assert_that (
    yafvs_control_alert_start_task_create_response (3, NULL, response),
    is_equal_to_string ("3 task_not_found\n"));
  assert_that (
    yafvs_control_alert_start_task_create_response (99, NULL, response),
    is_equal_to_string ("99 forbidden\n"));
  assert_that (
    yafvs_control_alert_start_task_create_response (-3, NULL, response),
    is_equal_to_string ("-3 committed_indeterminate\n"));
  assert_that (
    yafvs_control_alert_start_task_create_response (-2, NULL, response),
    is_equal_to_string ("-2 malformed\n"));
}

Ensure (yafvs_control, maps_schedule_create_responses)
{
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (yafvs_control_schedule_create_response (
                 0, "123e4567-e89b-12d3-a456-426614174002", response),
               is_equal_to_string ("0 created 123e4567-e89b-12d3-a456-426614174002\n"));
  assert_that (yafvs_control_schedule_create_response (1, NULL, response),
               is_equal_to_string ("1 exists\n"));
  assert_that (yafvs_control_schedule_create_response (3, NULL, response),
               is_equal_to_string ("3 invalid_ical\n"));
  assert_that (yafvs_control_schedule_create_response (4, NULL, response),
               is_equal_to_string ("4 invalid_timezone\n"));
  assert_that (yafvs_control_schedule_create_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_schedule_create_response (-1, NULL, response),
               is_equal_to_string ("-1 internal\n"));
}

Ensure (yafvs_control, accepts_username_password_credential_create_request)
{
  const char *request =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 up "
    "Q1NWIG9wZXJhdG9y QnVsayBpbXBvcnQ= cm9iZXJ0 c2VjcmV0IA== \n";
  char operator_uuid[37];
  yafvs_control_credential_create_request_t credential = {0};

  assert_that (yafvs_control_parse_credential_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (credential.credential_type, is_equal_to_string ("up"));
  assert_that (credential.name, is_equal_to_string ("CSV operator"));
  assert_that (credential.comment, is_equal_to_string ("Bulk import"));
  assert_that (credential.login, is_equal_to_string ("robert"));
  assert_that (credential.secret, is_equal_to_string ("secret "));
  assert_that (credential.private_key, is_equal_to_string (""));

  yafvs_control_credential_create_request_clear (&credential);
}

Ensure (yafvs_control, accepts_ssh_key_credential_create_request)
{
  const char *request =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 usk "
    "U1NIIG9wZXJhdG9y  cm9iZXJ0  "
    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCg==\n";
  char operator_uuid[37];
  yafvs_control_credential_create_request_t credential = {0};

  assert_that (yafvs_control_parse_credential_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_true);
  assert_that (credential.credential_type, is_equal_to_string ("usk"));
  assert_that (credential.name, is_equal_to_string ("SSH operator"));
  assert_that (credential.comment, is_equal_to_string (""));
  assert_that (credential.login, is_equal_to_string ("robert"));
  assert_that (credential.secret, is_equal_to_string (""));
  assert_that (credential.private_key,
               is_equal_to_string ("-----BEGIN PRIVATE KEY-----\n"));

  yafvs_control_credential_create_request_clear (&credential);
}

Ensure (yafvs_control, rejects_malformed_credential_create_requests)
{
  const char *bad_type =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 snmp "
    "TmFtZQ==  cm9iZXJ0 c2VjcmV0IA== \n";
  const char *missing_password =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 up "
    "TmFtZQ==  cm9iZXJ0  \n";
  const char *up_with_key =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 up "
    "TmFtZQ==  cm9iZXJ0 c2VjcmV0IA== a2V5\n";
  const char *ssh_without_key =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 usk "
    "TmFtZQ==  cm9iZXJ0  \n";
  char operator_uuid[37];
  yafvs_control_credential_create_request_t credential = {0};

  assert_that (yafvs_control_parse_credential_create_request (
                 bad_type, strlen (bad_type), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_false);
  assert_that (yafvs_control_parse_credential_create_request (
                 missing_password, strlen (missing_password),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &credential),
               is_false);
  assert_that (yafvs_control_parse_credential_create_request (
                 up_with_key, strlen (up_with_key), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_false);
  assert_that (yafvs_control_parse_credential_create_request (
                 ssh_without_key, strlen (ssh_without_key),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &credential),
               is_false);
}

Ensure (yafvs_control, creates_credential_in_operator_session)
{
  const yafvs_control_credential_create_request_t request = {
    .credential_type = "usk",
    .name = "SSH operator",
    .comment = "Bulk import",
    .login = "robert",
    .secret = "passphrase",
    .private_key = "-----BEGIN PRIVATE KEY-----\n",
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_credential_calls = 0;
  create_credential_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_create_credential (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174003"));
  assert_that (create_credential_calls, is_equal_to (1));
  assert_that (received_credential_type, is_equal_to_string ("usk"));
  assert_that (received_name, is_equal_to_string (request.name));
  assert_that (received_comment, is_equal_to_string (request.comment));
  assert_that (received_login, is_equal_to_string (request.login));
  assert_that (received_secret, is_equal_to_string (request.secret));
  assert_that (received_key_private,
               is_equal_to_string (request.private_key));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, maps_credential_create_responses)
{
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (yafvs_control_credential_create_response (
                 0, "123e4567-e89b-12d3-a456-426614174003", response),
               is_equal_to_string
                 ("0 created 123e4567-e89b-12d3-a456-426614174003\n"));
  assert_that (yafvs_control_credential_create_response (1, NULL, response),
               is_equal_to_string ("1 exists\n"));
  assert_that (yafvs_control_credential_create_response (2, NULL, response),
               is_equal_to_string ("2 invalid_login\n"));
  assert_that (yafvs_control_credential_create_response (3, NULL, response),
               is_equal_to_string ("3 invalid_key\n"));
  assert_that (yafvs_control_credential_create_response (5, NULL, response),
               is_equal_to_string ("5 login_required\n"));
  assert_that (yafvs_control_credential_create_response (6, NULL, response),
               is_equal_to_string ("6 password_required\n"));
  assert_that (yafvs_control_credential_create_response (7, NULL, response),
               is_equal_to_string ("7 key_required\n"));
  assert_that (yafvs_control_credential_create_response (-2, NULL, response),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (yafvs_control_credential_create_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
}

Ensure (yafvs_control, tracks_partial_request_length_and_clears_secrets)
{
  const char *partial = "credential-create partial-secret cGFzc3dvcmQ=";
  char request[YAFVS_CONTROL_MAX_REQUEST_BYTES + 1] = {0};
  gchar *sensitive = g_strdup ("secret-copy");
  size_t request_len = 999;
  int sockets[2];
  size_t i;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (write (sockets[0], partial, strlen (partial)),
               is_equal_to ((ssize_t) strlen (partial)));
  close (sockets[0]);
  assert_that (yafvs_control_read_request (sockets[1], request,
                                               &request_len),
               is_false);
  close (sockets[1]);
  assert_that (request_len, is_equal_to (strlen (partial)));
  assert_that (memcmp (request, partial, request_len), is_equal_to (0));

  yafvs_control_secure_clear (request, request_len);
  for (i = 0; i < request_len; i++)
    assert_that (request[i], is_equal_to (0));

  yafvs_control_secure_clear (sensitive, strlen (sensitive));
  for (i = 0; i < strlen ("secret-copy"); i++)
    assert_that (sensitive[i], is_equal_to (0));
  g_free (sensitive);
}

Ensure (yafvs_control, rejects_nonexistent_credential_operator_before_create)
{
  const yafvs_control_credential_create_request_t request = {
    .credential_type = "up",
    .name = "Operator",
    .comment = "",
    .login = "operator",
    .secret = "password",
    .private_key = "",
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_credential_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  mock_operator_name = NULL;

  assert_that (yafvs_control_create_credential (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (99));
  assert_that (create_credential_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
}

Ensure (yafvs_control, accepts_schedule_modify_presence_and_empty_tokens)
{
  const char *calendar = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
  gchar *calendar_b64 = g_base64_encode ((const guchar *) calendar,
                                         strlen (calendar));
  gchar *request = g_strdup_printf (
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "+TmV3IG5hbWU= + - +%s\n", calendar_b64);
  char operator_uuid[37];
  char schedule_uuid[37];
  yafvs_control_schedule_modify_request_t schedule = {0};

  assert_that (yafvs_control_parse_schedule_modify_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (schedule_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (schedule.name, is_equal_to_string ("New name"));
  assert_that (schedule.comment, is_equal_to_string (""));
  assert_that (schedule.timezone, is_null);
  assert_that (schedule.icalendar, is_equal_to_string (calendar));

  yafvs_control_schedule_modify_request_clear (&schedule);
  g_free (request);
  g_free (calendar_b64);
}

Ensure (yafvs_control, rejects_malformed_or_unauthenticated_schedule_modify)
{
  const char *extra =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "- - - +QQ== extra\n";
  const char *bare_base64 =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "TmlnaHRseQ== - - +QQ==\n";
  const char *noncanonical_base64 =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "+TQ= - - +QQ==\n";
  const char *wrong_secret =
    "schedule-modify fedcba9876543210fedcba9876543210 "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "- - - +QQ==\n";
  const char *invalid_uuid =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z "
    "- - - +QQ==\n";
  const char *all_absent =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "- - - -\n";
  gchar *control_name_b64;
  gchar *control_name_request;
  char operator_uuid[37];
  char schedule_uuid[37];
  yafvs_control_schedule_modify_request_t schedule = {0};

  control_name_b64 = g_base64_encode ((const guchar *) "line\nname", 9);
  control_name_request = g_strdup_printf (
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 +%s - - +QQ==\n",
    control_name_b64);

  assert_that (yafvs_control_parse_schedule_modify_request (
                 extra, strlen (extra), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 bare_base64, strlen (bare_base64), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 noncanonical_base64, strlen (noncanonical_base64),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 wrong_secret, strlen (wrong_secret), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 invalid_uuid, strlen (invalid_uuid), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 all_absent, strlen (all_absent), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 control_name_request, strlen (control_name_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);

  g_free (control_name_request);
  g_free (control_name_b64);
}

Ensure (yafvs_control, rejects_invalid_schedule_modify_field_bytes)
{
  const char *prefix =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 ";
  const gchar invalid_utf8[] = {(gchar) 0xc3};
  gchar *nul_b64 = g_base64_encode ((const guchar *) "\0", 1);
  gchar *invalid_utf8_b64 = g_base64_encode ((const guchar *) invalid_utf8,
                                              sizeof (invalid_utf8));
  gchar *oversized_name = g_strnfill (
    YAFVS_CONTROL_SCHEDULE_NAME_MAX_BYTES + 1, 'n');
  gchar *oversized_name_b64 = g_base64_encode (
    (const guchar *) oversized_name, strlen (oversized_name));
  gchar *nul_request = g_strdup_printf ("%s+%s - - +QQ==\n", prefix,
                                        nul_b64);
  gchar *invalid_utf8_request = g_strdup_printf ("%s+%s - - +QQ==\n",
                                                 prefix, invalid_utf8_b64);
  gchar *oversized_request = g_strdup_printf ("%s+%s - - +QQ==\n", prefix,
                                               oversized_name_b64);
  gchar *calendar_control_request = g_strdup_printf ("%s- - - +AQ==\n",
                                                      prefix);
  char operator_uuid[37];
  char schedule_uuid[37];
  yafvs_control_schedule_modify_request_t schedule = {0};

  assert_that (yafvs_control_parse_schedule_modify_request (
                 nul_request, strlen (nul_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 invalid_utf8_request, strlen (invalid_utf8_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (yafvs_control_parse_schedule_modify_request (
                 calendar_control_request, strlen (calendar_control_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);

  g_free (calendar_control_request);
  g_free (oversized_request);
  g_free (invalid_utf8_request);
  g_free (nul_request);
  g_free (oversized_name_b64);
  g_free (oversized_name);
  g_free (invalid_utf8_b64);
  g_free (nul_b64);
}

Ensure (yafvs_control, distinguishes_absent_and_empty_schedule_modify_calendar)
{
  const char *absent_request =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 - +bWV0YWRhdGE= - -\n";
  const char *empty_request =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 - +bWV0YWRhdGE= - +\n";
  char operator_uuid[37];
  char schedule_uuid[37];
  yafvs_control_schedule_modify_request_t absent = {0};
  yafvs_control_schedule_modify_request_t empty = {0};

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  modify_schedule_calls = 0;
  modify_schedule_result = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_parse_schedule_modify_request (
                 absent_request, strlen (absent_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &absent),
               is_true);
  assert_that (absent.comment, is_equal_to_string ("metadata"));
  assert_that (absent.icalendar, is_null);
  assert_that (yafvs_control_modify_schedule (operator_uuid, schedule_uuid,
                                                 &absent),
               is_equal_to (0));
  assert_that (received_icalendar, is_null);

  modify_schedule_result = 6;
  assert_that (yafvs_control_parse_schedule_modify_request (
                 empty_request, strlen (empty_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &empty),
               is_true);
  assert_that (empty.comment, is_equal_to_string ("metadata"));
  assert_that (empty.icalendar, is_equal_to_string (""));
  assert_that (yafvs_control_modify_schedule (operator_uuid, schedule_uuid,
                                                 &empty),
               is_equal_to (6));
  assert_that (received_icalendar, is_equal_to_string (""));
  assert_that (reinit_calls, is_equal_to (2));
  assert_that (session_init_calls, is_equal_to (2));
  assert_that (modify_schedule_calls, is_equal_to (2));
  assert_that (cleanup_calls, is_equal_to (2));

  yafvs_control_schedule_modify_request_clear (&empty);
  yafvs_control_schedule_modify_request_clear (&absent);
}

Ensure (yafvs_control, modifies_schedule_in_operator_session)
{
  const yafvs_control_schedule_modify_request_t request = {
    .name = NULL,
    .comment = "",
    .timezone = "Europe/Berlin",
    .icalendar = "BEGIN:VCALENDAR\nEND:VCALENDAR\n",
  };

  cleanup_calls = 0;
  modify_schedule_calls = 0;
  modify_schedule_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_modify_schedule (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001", &request),
               is_equal_to (0));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (modify_schedule_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (received_schedule_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (received_name, is_null);
  assert_that (received_comment, is_equal_to_string (request.comment));
  assert_that (received_timezone, is_equal_to_string (request.timezone));
  assert_that (received_icalendar, is_equal_to_string (request.icalendar));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, maps_schedule_modify_responses)
{
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (yafvs_control_schedule_modify_response (0, response),
               is_equal_to_string ("0 modified\n"));
  assert_that (yafvs_control_schedule_modify_response (1, response),
               is_equal_to_string ("1 not_found\n"));
  assert_that (yafvs_control_schedule_modify_response (2, response),
               is_equal_to_string ("2 duplicate\n"));
  assert_that (yafvs_control_schedule_modify_response (6, response),
               is_equal_to_string ("6 invalid_ical\n"));
  assert_that (yafvs_control_schedule_modify_response (7, response),
               is_equal_to_string ("7 invalid_timezone\n"));
  assert_that (yafvs_control_schedule_modify_response (99, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_schedule_modify_response (-2, response),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (yafvs_control_schedule_modify_response (-1, response),
               is_equal_to_string ("-1 internal\n"));
}

int
__wrap_stop_task (const char *task_uuid)
{
  (void) task_uuid;
  stop_task_calls++;
  return 0;
}

int
__wrap_copy_task (const char *name, const char *comment,
                  const char *source_task_uuid, int alterable, task_t *new_task)
{
  assert_that (name, is_null);
  assert_that (comment, is_null);
  assert_that (source_task_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (alterable, is_equal_to (-1));
  clone_task_calls++;
  *new_task = 11;
  return clone_task_result;
}

int
__wrap_task_uuid (task_t task, char **uuid)
{
  *uuid = task == 11 && !task_uuid_lookup_fails
            ? g_strdup ("123e4567-e89b-12d3-a456-426614174006")
            : NULL;
  return 0;
}

Ensure (yafvs_control, parses_canonical_task_clone_request)
{
  const char *request = "task-clone " TEST_CONTROL_SECRET " "
                        "123e4567-e89b-12d3-a456-426614174000 "
                        "123e4567-e89b-12d3-a456-426614174001\n";
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (yafvs_control_parse_task_clone_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, task_uuid),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (task_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
}

Ensure (yafvs_control, rejects_malformed_task_clone_requests)
{
  const char *extra = "task-clone " TEST_CONTROL_SECRET " "
                      "123e4567-e89b-12d3-a456-426614174000 "
                      "123e4567-e89b-12d3-a456-426614174001 extra\n";
  const char *wrong_secret = "task-clone fedcba9876543210fedcba9876543210 "
                             "123e4567-e89b-12d3-a456-426614174000 "
                             "123e4567-e89b-12d3-a456-426614174001\n";
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (yafvs_control_parse_task_clone_request (
                 extra, strlen (extra), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, task_uuid),
               is_false);
  assert_that (yafvs_control_parse_task_clone_request (
                 wrong_secret, strlen (wrong_secret), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, task_uuid),
               is_false);
}

Ensure (yafvs_control, clones_task_in_operator_session_and_audits)
{
  char created_uuid[37] = {0};

  mock_operator_name = "operator";
  clone_task_calls = 0;
  clone_task_result = 0;
  task_uuid_lookup_fails = FALSE;
  task_audit_success_calls = 0;
  task_audit_fail_calls = 0;
  cleanup_calls = 0;
  session_init_calls = 0;
  reinit_calls = 0;
  g_clear_pointer (&received_audit_uuid, g_free);

  assert_that (yafvs_control_clone_task (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001", created_uuid),
               is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174006"));
  assert_that (clone_task_calls, is_equal_to (1));
  assert_that (task_audit_success_calls, is_equal_to (1));
  assert_that (task_audit_fail_calls, is_equal_to (0));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);

  clone_task_result = 2;
  assert_that (yafvs_control_clone_task (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001", created_uuid),
               is_equal_to (2));
  assert_that (task_audit_fail_calls, is_equal_to (1));

  clone_task_result = 0;
  task_uuid_lookup_fails = TRUE;
  assert_that (yafvs_control_clone_task (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001", created_uuid),
               is_equal_to (-3));
  assert_that (task_audit_success_calls, is_equal_to (2));
  assert_that (task_audit_fail_calls, is_equal_to (1));
}

Ensure (yafvs_control, maps_task_clone_responses)
{
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (
    yafvs_control_task_clone_response (
      0, "123e4567-e89b-12d3-a456-426614174006", response),
    is_equal_to_string ("0 created 123e4567-e89b-12d3-a456-426614174006\n"));
  assert_that (yafvs_control_task_clone_response (1, NULL, response),
               is_equal_to_string ("1 duplicate\n"));
  assert_that (yafvs_control_task_clone_response (2, NULL, response),
               is_equal_to_string ("2 not_found\n"));
  assert_that (yafvs_control_task_clone_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_task_clone_response (-3, NULL, response),
               is_equal_to_string ("-3 committed_indeterminate\n"));
  assert_that (yafvs_control_task_clone_response (-2, NULL, response),
               is_equal_to_string ("-2 malformed\n"));
}

void
__wrap_cleanup_manage_process (gboolean full)
{
  (void) full;
  cleanup_calls++;
}

Ensure (yafvs_control, accepts_exact_authenticated_stop_request)
{
  const char *request =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (yafvs_control_parse_request (request, strlen (request),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (task_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
}

Ensure (yafvs_control, rejects_noncanonical_or_extra_requests)
{
  const char *extra =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 extra\n";
  const char *invalid_uuid =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z\n";
  char request[YAFVS_CONTROL_MAX_REQUEST_BYTES + 1];
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (yafvs_control_parse_request (extra, strlen (extra),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_false);
  assert_that (yafvs_control_parse_request (invalid_uuid,
                                               strlen (invalid_uuid),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_false);
  memset (request, 'x', sizeof (request));
  assert_that (yafvs_control_parse_request (
                 request, sizeof (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, task_uuid),
               is_false);
}

Ensure (yafvs_control, rejects_missing_weak_or_incorrect_secrets)
{
  const char *request =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (yafvs_control_secret_is_valid (NULL, 0), is_false);
  assert_that (yafvs_control_secret_is_valid ("too-short", 9), is_false);
  assert_that (yafvs_control_secret_is_valid (TEST_CONTROL_SECRET,
                                                 strlen (TEST_CONTROL_SECRET)),
               is_true);
  assert_that (yafvs_control_secret_is_valid (
                 "0123456789abcdef0123456789abcde!", 32),
               is_false);
  assert_that (yafvs_control_parse_request (
                 request, strlen (request), NULL, 0,
                 operator_uuid, task_uuid),
               is_false);
  assert_that (yafvs_control_parse_request (
                 request, strlen (request), "too-short", 9,
                 operator_uuid, task_uuid),
               is_false);
  assert_that (yafvs_control_parse_request (
                 request, strlen (request),
                 "fedcba9876543210fedcba9876543210", 32,
                 operator_uuid, task_uuid),
               is_false);
}

Ensure (yafvs_control, maps_only_protocol_responses)
{
  assert_that (yafvs_control_response (0), is_equal_to_string ("0 stopped\n"));
  assert_that (yafvs_control_response (2),
               is_equal_to_string ("2 inactive\n"));
  assert_that (yafvs_control_response (1),
               is_equal_to_string ("1 requested\n"));
  assert_that (yafvs_control_response (3),
               is_equal_to_string ("3 not_found\n"));
  assert_that (yafvs_control_response (99),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_response (-1),
               is_equal_to_string ("-1 internal\n"));
  assert_that (yafvs_control_response (-2),
               is_equal_to_string ("-2 scanner_status\n"));
  assert_that (yafvs_control_response (-3),
               is_equal_to_string ("-3 scanner_stop\n"));
  assert_that (yafvs_control_response (-4),
               is_equal_to_string ("-4 scanner_delete\n"));
  assert_that (yafvs_control_response (-5),
               is_equal_to_string ("-5 scanner_verify\n"));
}

Ensure (yafvs_control, parses_canonical_bounded_alert_smb_requests)
{
  static const char *protocols[] = {"", "NT1", "SMB2", "SMB3"};
  char operator_uuid[37];
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (protocols); index++)
    {
      gchar *request = test_alert_smb_create_request (
        "1", "SMB alert", "private delivery", "Done",
        "123e4567-e89b-12d3-a456-426614174010", "\\\\fileserver\\reports",
        "scan/report.pdf", "123e4567-e89b-12d3-a456-426614174011",
        index ? "123e4567-e89b-12d3-a456-426614174012" : "", protocols[index]);
      yafvs_control_alert_smb_create_request_t alert = {0};

      assert_that (yafvs_control_parse_alert_smb_create_request (
                     request, strlen (request), TEST_CONTROL_SECRET,
                     strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
                   is_true);
      assert_that (operator_uuid,
                   is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
      assert_that (alert.name, is_equal_to_string ("SMB alert"));
      assert_that (alert.comment, is_equal_to_string ("private delivery"));
      assert_that (alert.status, is_equal_to_string ("Done"));
      assert_that (alert.credential_uuid,
                   is_equal_to_string ("123e4567-e89b-12d3-a456-426614174010"));
      assert_that (alert.share_path,
                   is_equal_to_string ("\\\\fileserver\\reports"));
      assert_that (alert.file_path, is_equal_to_string ("scan/report.pdf"));
      assert_that (alert.max_protocol, is_equal_to_string (protocols[index]));
      assert_that (alert.active, is_true);
      yafvs_control_alert_smb_create_request_clear (&alert);
      g_free (request);
    }
}

Ensure (yafvs_control, rejects_malformed_or_oversized_alert_smb_requests)
{
  gchar *oversized_path =
    g_strnfill (YAFVS_CONTROL_ALERT_SMB_PATH_MAX_BYTES + 1, 'x');
  gchar *requests[8];
  char operator_uuid[37];
  size_t index;
  yafvs_control_alert_smb_create_request_t alert = {0};

  requests[0] = test_alert_smb_create_request (
    "2", "SMB alert", "", "Done", "123e4567-e89b-12d3-a456-426614174010",
    "\\\\fileserver\\reports", "scan/report.pdf",
    "123e4567-e89b-12d3-a456-426614174011", "", "SMB3");
  requests[1] = test_alert_smb_create_request (
    "1", "SMB alert", "", "Invalid", "123e4567-e89b-12d3-a456-426614174010",
    "\\\\fileserver\\reports", "scan/report.pdf",
    "123e4567-e89b-12d3-a456-426614174011", "", "SMB3");
  requests[2] = test_alert_smb_create_request (
    "1", "SMB alert", "", "Done", "not-a-uuid", "\\\\fileserver\\reports",
    "scan/report.pdf", "123e4567-e89b-12d3-a456-426614174011", "", "SMB3");
  requests[3] = test_alert_smb_create_request (
    "1", "SMB alert", "", "Done", "123e4567-e89b-12d3-a456-426614174010",
    "\\\\fileserver\\reports", "scan/report.pdf", "not-a-uuid", "", "SMB3");
  requests[4] = test_alert_smb_create_request (
    "1", "SMB alert", "", "Done", "123e4567-e89b-12d3-a456-426614174010",
    oversized_path, "scan/report.pdf", "123e4567-e89b-12d3-a456-426614174011",
    "", "SMB3");
  requests[5] = test_alert_smb_create_request (
    "1", "SMB alert", "", "Done", "123e4567-e89b-12d3-a456-426614174010",
    "\\\\fileserver\\reports", "scan/report.pdf",
    "123e4567-e89b-12d3-a456-426614174011", "", "SMB1");
  requests[6] =
    g_strdup ("alert-smb-create " TEST_CONTROL_SECRET " "
              "123e4567-e89b-12d3-a456-426614174000 1 QQ== extra\n");
  requests[7] = test_alert_smb_create_request (
    "1", "SMB\nalert", "", "Done", "123e4567-e89b-12d3-a456-426614174010",
    "\\\\fileserver\\reports", "scan/report.pdf",
    "123e4567-e89b-12d3-a456-426614174011", "", "");

  for (index = 0; index < G_N_ELEMENTS (requests); index++)
    {
      assert_that (yafvs_control_parse_alert_smb_create_request (
                     requests[index], strlen (requests[index]),
                     TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                     operator_uuid, &alert),
                   is_false);
      g_free (requests[index]);
    }
  g_free (oversized_path);
}

Ensure (yafvs_control, maps_alert_smb_arrays_session_and_success_audit)
{
  const yafvs_control_alert_smb_create_request_t request = {
    .name = "SMB alert",
    .comment = "private delivery",
    .status = "Done",
    .credential_uuid = "123e4567-e89b-12d3-a456-426614174010",
    .share_path = "\\\\fileserver\\reports",
    .file_path = "scan/report.pdf",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .max_protocol = "SMB3",
    .active = TRUE,
  };
  char created_uuid[37];

  alert_uuid_lookup_fails = FALSE;
  cleanup_calls = 0;
  create_alert_calls = 0;
  create_alert_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (
    yafvs_control_create_alert_smb ("123e4567-e89b-12d3-a456-426614174000",
                                       &request, created_uuid),
    is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174004"));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (received_alert_event,
               is_equal_to (EVENT_TASK_RUN_STATUS_CHANGED));
  assert_that (received_alert_condition, is_equal_to (ALERT_CONDITION_ALWAYS));
  assert_that (received_alert_method, is_equal_to (ALERT_METHOD_SMB));
  assert_that (received_active, is_equal_to_string ("1"));
  assert_that (received_event_status, is_equal_to_string (request.status));
  assert_that (received_smb_credential,
               is_equal_to_string (request.credential_uuid));
  assert_that (received_smb_share_path,
               is_equal_to_string (request.share_path));
  assert_that (received_smb_file_path, is_equal_to_string (request.file_path));
  assert_that (received_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_smb_max_protocol,
               is_equal_to_string (request.max_protocol));
  assert_that (audit_success_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, audits_alert_smb_failure_and_cleans_session)
{
  const yafvs_control_alert_smb_create_request_t request = {
    .name = "SMB alert",
    .comment = "",
    .status = "Done",
    .credential_uuid = "123e4567-e89b-12d3-a456-426614174010",
    .share_path = "invalid",
    .file_path = "scan/report.pdf",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .max_protocol = "",
    .active = FALSE,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  create_alert_result = 41;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";
  assert_that (
    yafvs_control_create_alert_smb ("123e4567-e89b-12d3-a456-426614174000",
                                       &request, created_uuid),
    is_equal_to (41));
  assert_that (received_smb_max_protocol, is_null);
  assert_that (audit_success_calls, is_equal_to (0));
  assert_that (audit_fail_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, preserves_alert_smb_postcommit_indeterminate_audit)
{
  const yafvs_control_alert_smb_create_request_t request = {
    .name = "SMB alert",
    .comment = "",
    .status = "Done",
    .credential_uuid = "123e4567-e89b-12d3-a456-426614174010",
    .share_path = "\\\\fileserver\\reports",
    .file_path = "scan/report.pdf",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .max_protocol = "SMB2",
    .active = TRUE,
  };
  char created_uuid[37];

  alert_uuid_lookup_fails = TRUE;
  cleanup_calls = 0;
  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";
  assert_that (
    yafvs_control_create_alert_smb ("123e4567-e89b-12d3-a456-426614174000",
                                       &request, created_uuid),
    is_equal_to (-3));
  assert_that (audit_success_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (received_audit_uuid, is_null);
  assert_that (cleanup_calls, is_equal_to (1));
  alert_uuid_lookup_fails = FALSE;
}

static int
call_real_alert_smb_create (const char *share_path, const char *file_path,
                            const char *unused)
{
  array_t *condition_data = make_array ();
  array_t *event_data = make_array ();
  array_t *method_data = make_array ();
  alert_t alert = 0;
  int result;

  (void) unused;

  current_credentials.uuid = g_strdup ("123e4567-e89b-12d3-a456-426614174000");
  current_credentials.username = g_strdup ("operator");
  yafvs_control_array_add_data (event_data, "status", "Done");
  yafvs_control_array_add_data (method_data, "smb_credential",
                                   "123e4567-e89b-12d3-a456-426614174010");
  yafvs_control_array_add_data (method_data, "smb_share_path", share_path);
  yafvs_control_array_add_data (method_data, "smb_file_path", file_path);
  yafvs_control_array_add_data (method_data, "smb_report_format",
                                   "123e4567-e89b-12d3-a456-426614174011");
  yafvs_control_array_add_data (method_data, "smb_max_protocol", "SMB3");
  array_terminate (condition_data);
  array_terminate (event_data);
  array_terminate (method_data);

  result = __real_create_alert_smb_with_report_refs (
    "SMB alert", "private delivery", "1", event_data, condition_data,
    method_data, "123e4567-e89b-12d3-a456-426614174010",
    alert_smb_db_report_format_uuid, &alert);
  yafvs_control_secure_array_free (condition_data);
  yafvs_control_secure_array_free (event_data);
  yafvs_control_secure_array_free (method_data);
  g_clear_pointer (&current_credentials.uuid, g_free);
  g_clear_pointer (&current_credentials.username, g_free);
  alert_smb_db_active = FALSE;
  return result;
}

Ensure (yafvs_control, locks_alert_smb_references_and_commits_atomically)
{
  reset_alert_smb_db ();
  assert_that (
    call_real_alert_smb_create ("\\\\fileserver\\reports", "scan/report.pdf",
                                "123e4567-e89b-12d3-a456-426614174012"),
    is_equal_to (0));
  assert_that (alert_smb_db_events[0], is_equal_to (ALERT_SMB_DB_BEGIN));
  assert_that (alert_smb_db_events[1], is_equal_to (ALERT_SMB_DB_ACL));
  assert_that (alert_smb_db_events[2], is_equal_to (ALERT_SMB_DB_OWNER_LOCK));
  assert_that (alert_smb_db_events[3],
               is_equal_to (ALERT_SMB_DB_CREDENTIAL_RESOLVE));
  assert_that (alert_smb_db_events[4],
               is_equal_to (ALERT_SMB_DB_CREDENTIAL_LOCK));
  assert_that (alert_smb_db_events[5],
               is_equal_to (ALERT_SMB_DB_CREDENTIAL_TYPE));
  assert_that (alert_smb_db_events[6],
               is_equal_to (ALERT_SMB_DB_FORMAT_RESOLVE));
  assert_that (alert_smb_db_events[7], is_equal_to (ALERT_SMB_DB_FORMAT_LOCK));
  assert_that (alert_smb_db_events[8], is_equal_to (ALERT_SMB_DB_BODY_INSERT));
  assert_that (alert_smb_db_events[alert_smb_db_event_count - 1],
               is_equal_to (ALERT_SMB_DB_COMMIT));
  assert_that (alert_smb_db_method_inserts, is_equal_to (5));
}

Ensure (yafvs_control, rejects_alert_smb_reference_failures_atomically)
{
  reset_alert_smb_db ();
  alert_smb_db_acl = FALSE;
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (99));
  assert_that (alert_smb_db_events[2], is_equal_to (ALERT_SMB_DB_ROLLBACK));

  reset_alert_smb_db ();
  alert_smb_db_owner_exists = FALSE;
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (99));

  reset_alert_smb_db ();
  alert_smb_db_credential_readable = FALSE;
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (40));

  reset_alert_smb_db ();
  alert_smb_db_credential_owned = FALSE;
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (40));
  assert_that (alert_smb_db_events[alert_smb_db_event_count - 1],
               is_equal_to (ALERT_SMB_DB_ROLLBACK));

  reset_alert_smb_db ();
  alert_smb_db_credential_type = "usk";
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (40));

  reset_alert_smb_db ();
  alert_smb_db_report_format_uuid = "";
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (90));

  reset_alert_smb_db ();
  alert_smb_db_format_readable = FALSE;
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (90));

  reset_alert_smb_db ();
  alert_smb_db_format_lock_exists = FALSE;
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (90));

}

Ensure (yafvs_control, preserves_authoritative_alert_smb_validation)
{
  reset_alert_smb_db ();
  alert_smb_db_credential_username = "bad@name";
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (40));

  reset_alert_smb_db ();
  assert_that (
    call_real_alert_smb_create ("not-a-share", "scan/report.pdf", ""),
    is_equal_to (41));

  reset_alert_smb_db ();
  assert_that (
    call_real_alert_smb_create ("\\\\fileserver\\reports", "bad:path", ""),
    is_equal_to (42));

  reset_alert_smb_db ();
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "folder./report.pdf", ""),
               is_equal_to (43));
  assert_that (alert_smb_db_events[alert_smb_db_event_count - 1],
               is_equal_to (ALERT_SMB_DB_ROLLBACK));

  for (size_t index = 0; index < 5; index++)
    {
      static const char *unsafe_share_paths[] = {
        "\\\\fileserver\\reports\"; quit",
        "\\\\fileserver\\reports;quit",
        "\\\\fileserver\\reports|quit",
        "\\\\fileserver\\reports&&quit",
        "\\\\fileserver\\reports\r\nnext",
      };
      reset_alert_smb_db ();
      assert_that (call_real_alert_smb_create (unsafe_share_paths[index],
                                               "scan/report.pdf", ""),
                   is_equal_to (41));
    }

  for (size_t index = 0; index < 6; index++)
    {
      static const char *unsafe_file_paths[] = {
        "scan/report\".pdf", "scan/report;quit.pdf",
        "scan/report|quit.pdf", "scan/report&&quit.pdf",
        "scan/report$HOME.pdf", "scan/report\r\nnext.pdf",
      };
      reset_alert_smb_db ();
      assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                               unsafe_file_paths[index], ""),
                   is_equal_to (42));
    }

  reset_alert_smb_db ();
  alert_smb_db_credential_username = "operator\r\npassword = replacement";
  assert_that (call_real_alert_smb_create ("\\\\fileserver\\reports",
                                           "scan/report.pdf", ""),
               is_equal_to (40));

  reset_alert_smb_db ();
  assert_that (call_real_alert_smb_create ("//fileserver/team-reports",
                                           "archive/weekly report-%Y%m%d.pdf",
                                           ""),
               is_equal_to (0));
}

Ensure (yafvs_control, dispatches_malformed_alert_smb_without_payload)
{
  const char *request = "alert-smb-create " TEST_CONTROL_SECRET " "
                        "123e4567-e89b-12d3-a456-426614174000 private-path\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_trash_empty_request (request, response);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  assert_that (response_len, is_equal_to (strlen ("-2 malformed\n")));
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  assert_that (strstr (response, "private-path"), is_null);
}

Ensure (yafvs_control, parses_canonical_bounded_alert_scp_requests)
{
  gchar *request = test_alert_scp_create_request (
    "1", "SCP alert", "private delivery", "Done",
    "123e4567-e89b-12d3-a456-426614174010", "scp.example.test", "65535",
    "scp.example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
    "/var/reports/scan.pdf", "123e4567-e89b-12d3-a456-426614174011");
  char operator_uuid[37];
  yafvs_control_alert_scp_create_request_t alert = {0};

  assert_that (yafvs_control_parse_alert_scp_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (alert.name, is_equal_to_string ("SCP alert"));
  assert_that (alert.comment, is_equal_to_string ("private delivery"));
  assert_that (alert.status, is_equal_to_string ("Done"));
  assert_that (alert.credential_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174010"));
  assert_that (alert.host, is_equal_to_string ("scp.example.test"));
  assert_that (alert.port, is_equal_to_string ("65535"));
  assert_that (alert.known_hosts,
               is_equal_to_string (
                 "scp.example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"));
  assert_that (alert.path, is_equal_to_string ("/var/reports/scan.pdf"));
  assert_that (alert.report_format_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174011"));
  assert_that (alert.active, is_true);
  yafvs_control_alert_scp_create_request_clear (&alert);
  g_free (request);
}

Ensure (yafvs_control, rejects_malformed_or_oversized_alert_scp_requests)
{
  gchar *oversized =
    g_strnfill (YAFVS_CONTROL_ALERT_SCP_HOST_MAX_BYTES + 1, 'x');
  gchar *requests[] = {
    test_alert_scp_create_request (
      "2", "SCP alert", "", "Done",
      "123e4567-e89b-12d3-a456-426614174010", "scp.example.test", "22",
      "scp.example.test key", "/var/reports/scan.pdf",
      "123e4567-e89b-12d3-a456-426614174011"),
    test_alert_scp_create_request (
      "1", "SCP alert", "", "Invalid",
      "123e4567-e89b-12d3-a456-426614174010", "scp.example.test", "22",
      "scp.example.test key", "/var/reports/scan.pdf",
      "123e4567-e89b-12d3-a456-426614174011"),
    test_alert_scp_create_request (
      "1", "SCP alert", "", "Done", "not-a-uuid", "scp.example.test",
      "22", "scp.example.test key", "/var/reports/scan.pdf",
      "123e4567-e89b-12d3-a456-426614174011"),
    test_alert_scp_create_request (
      "1", "SCP alert", "", "Done",
      "123e4567-e89b-12d3-a456-426614174010", "scp.example.test", "0",
      "scp.example.test key", "/var/reports/scan.pdf",
      "123e4567-e89b-12d3-a456-426614174011"),
    test_alert_scp_create_request (
      "1", "SCP alert", "", "Done",
      "123e4567-e89b-12d3-a456-426614174010", "scp.example.test", "65536",
      "scp.example.test key", "/var/reports/scan.pdf",
      "123e4567-e89b-12d3-a456-426614174011"),
    test_alert_scp_create_request (
      "1", "SCP alert", "", "Done",
      "123e4567-e89b-12d3-a456-426614174010", "scp.example.test", "+22",
      "scp.example.test key", "/var/reports/scan.pdf",
      "123e4567-e89b-12d3-a456-426614174011"),
    test_alert_scp_create_request (
      "1", "SCP alert", "", "Done",
      "123e4567-e89b-12d3-a456-426614174010", oversized, "22",
      "scp.example.test key", "/var/reports/scan.pdf",
      "123e4567-e89b-12d3-a456-426614174011"),
    g_strdup ("alert-scp-create " TEST_CONTROL_SECRET " "
              "123e4567-e89b-12d3-a456-426614174000 1 QQ== extra\n"),
  };
  char operator_uuid[37];
  size_t index;
  yafvs_control_alert_scp_create_request_t alert = {0};

  for (index = 0; index < G_N_ELEMENTS (requests); index++)
    {
      assert_that (yafvs_control_parse_alert_scp_create_request (
                     requests[index], strlen (requests[index]),
                     TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                     operator_uuid, &alert),
                   is_false);
      g_free (requests[index]);
    }
  g_free (oversized);
}

Ensure (yafvs_control, maps_alert_scp_arrays_session_and_success_audit)
{
  const yafvs_control_alert_scp_create_request_t request = {
    .name = "SCP alert",
    .comment = "private delivery",
    .status = "Done",
    .credential_uuid = "123e4567-e89b-12d3-a456-426614174010",
    .host = "scp.example.test",
    .port = "22",
    .known_hosts = "scp.example.test ssh-ed25519 AAAAC3NzaTestKey",
    .path = "/var/reports/scan.pdf",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .active = TRUE,
  };
  char created_uuid[37];

  alert_uuid_lookup_fails = FALSE;
  cleanup_calls = 0;
  create_alert_calls = 0;
  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (
    yafvs_control_create_alert_scp ("123e4567-e89b-12d3-a456-426614174000",
                                       &request, created_uuid),
    is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174004"));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (received_alert_event,
               is_equal_to (EVENT_TASK_RUN_STATUS_CHANGED));
  assert_that (received_alert_condition, is_equal_to (ALERT_CONDITION_ALWAYS));
  assert_that (received_alert_method, is_equal_to (ALERT_METHOD_SCP));
  assert_that (received_active, is_equal_to_string ("1"));
  assert_that (received_event_status, is_equal_to_string (request.status));
  assert_that (received_scp_credential,
               is_equal_to_string (request.credential_uuid));
  assert_that (received_scp_host, is_equal_to_string (request.host));
  assert_that (received_scp_port, is_equal_to_string (request.port));
  assert_that (received_scp_known_hosts, is_equal_to_string (request.known_hosts));
  assert_that (received_scp_path, is_equal_to_string (request.path));
  assert_that (received_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_atomic_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (audit_success_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, dispatches_alert_scp_errors_without_secrets)
{
  gchar *request = test_alert_scp_create_request (
    "0", "SCP alert", "private delivery", "Done",
    "123e4567-e89b-12d3-a456-426614174010", "private-scp-host", "22",
    "private-known-host", "/private/path",
    "123e4567-e89b-12d3-a456-426614174011");
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  cleanup_calls = 0;
  create_alert_calls = 0;
  create_alert_result = 16;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";
  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_trash_empty_request (request, response);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  assert_that (response_len, is_equal_to (strlen ("16 invalid_scp_port\n")));
  assert_that (response, is_equal_to_string ("16 invalid_scp_port\n"));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (strstr (response, TEST_CONTROL_SECRET), is_null);
  assert_that (strstr (response, "private-scp-host"), is_null);
  assert_that (strstr (response, "private-known-host"), is_null);
  create_alert_result = 0;
  g_free (request);
}

Ensure (yafvs_control, dispatches_malformed_alert_scp_without_payload)
{
  const char *request = "alert-scp-create " TEST_CONTROL_SECRET " "
                        "123e4567-e89b-12d3-a456-426614174000 private-scp-path\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_trash_empty_request (request, response);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  assert_that (response_len, is_equal_to (strlen ("-2 malformed\n")));
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  assert_that (strstr (response, TEST_CONTROL_SECRET), is_null);
  assert_that (strstr (response, "private-scp-path"), is_null);
}

Ensure (yafvs_control, rejects_nonexistent_operator_before_session_setup)
{
  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  stop_task_calls = 0;
  mock_operator_name = NULL;

  assert_that (yafvs_control_stop_task (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001"),
               is_equal_to (99));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
  assert_that (stop_task_calls, is_equal_to (0));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, parses_bounded_diagnostic_nvt_request)
{
  const char *request =
    "scan-config-nvt-diagnostic " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "1.3.6.1.4.1.25623.1.0.900001\n";
  char operator_uuid[37];
  char config_uuid[37];
  char nvt_oid[YAFVS_CONTROL_NVT_OID_MAX_BYTES + 1];

  assert_that (yafvs_control_parse_scan_config_nvt_diagnostic_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, config_uuid,
                 nvt_oid),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (config_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (nvt_oid,
               is_equal_to_string ("1.3.6.1.4.1.25623.1.0.900001"));
}

Ensure (yafvs_control, rejects_malformed_diagnostic_nvt_requests)
{
  const char *requests[] = {
    "scan-config-nvt-diagnostic wrong-secret "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 1.3.6.1\n",
    "scan-config-nvt-diagnostic " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-42661417400z "
    "123e4567-e89b-12d3-a456-426614174001 1.3.6.1\n",
    "scan-config-nvt-diagnostic " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z 1.3.6.1\n",
    "scan-config-nvt-diagnostic " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 1..3\n",
    "scan-config-nvt-diagnostic " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 1.3.6.1 extra\n",
  };
  gchar *oversized_oid =
    g_strnfill (YAFVS_CONTROL_NVT_OID_MAX_BYTES + 1, '1');
  gchar *oversized_request = g_strdup_printf (
    "scan-config-nvt-diagnostic " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 %s\n",
    oversized_oid);
  char operator_uuid[37];
  char config_uuid[37];
  char nvt_oid[YAFVS_CONTROL_NVT_OID_MAX_BYTES + 1];
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (requests); index++)
    assert_that (yafvs_control_parse_scan_config_nvt_diagnostic_request (
                   requests[index], strlen (requests[index]),
                   TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                   operator_uuid, config_uuid, nvt_oid),
                 is_false);
  assert_that (yafvs_control_parse_scan_config_nvt_diagnostic_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, config_uuid, nvt_oid),
               is_false);

  g_free (oversized_request);
  g_free (oversized_oid);
}

Ensure (yafvs_control, maps_diagnostic_nvt_responses)
{
  static const struct
  {
    int result;
    const char *response;
  } cases[] = {
    {0, "0 configured\n"},
    {1, "1 in_use\n"},
    {2, "2 whole_only\n"},
    {3, "3 config_not_found\n"},
    {4, "4 nvt_not_found\n"},
    {5, "5 prerequisite_not_found\n"},
    {6, "6 shared_selector\n"},
    {99, "99 forbidden\n"},
    {-2, "-2 malformed\n"},
    {-3, "-3 committed_indeterminate\n"},
    {-1, "-1 internal\n"},
    {42, "-1 internal\n"},
  };
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (cases); index++)
    assert_that (
      yafvs_control_scan_config_nvt_diagnostic_response (
        cases[index].result),
      is_equal_to_string (cases[index].response));
}

Ensure (yafvs_control, runs_diagnostic_nvt_in_operator_session_and_audits)
{
  const char *operator_uuid = "123e4567-e89b-12d3-a456-426614174000";
  const char *config_uuid = "123e4567-e89b-12d3-a456-426614174001";
  const char *nvt_oid = "1.3.6.1.4.1.25623.1.0.900001";

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  diagnostic_control_calls = 0;
  diagnostic_audit_success_calls = 0;
  diagnostic_audit_fail_calls = 0;
  mock_operator_name = "operator";

  diagnostic_control_result = 0;
  diagnostic_control_changed = TRUE;
  diagnostic_control_committed = TRUE;
  assert_that (yafvs_control_configure_diagnostic_nvt (
                 operator_uuid, config_uuid, nvt_oid),
               is_equal_to (0));

  diagnostic_control_result = -3;
  diagnostic_control_committed = TRUE;
  assert_that (yafvs_control_configure_diagnostic_nvt (
                 operator_uuid, config_uuid, nvt_oid),
               is_equal_to (-3));

  diagnostic_control_result = 1;
  diagnostic_control_changed = FALSE;
  diagnostic_control_committed = FALSE;
  assert_that (yafvs_control_configure_diagnostic_nvt (
                 operator_uuid, config_uuid, nvt_oid),
               is_equal_to (1));

  assert_that (diagnostic_control_calls, is_equal_to (3));
  assert_that (diagnostic_audit_success_calls, is_equal_to (2));
  assert_that (diagnostic_audit_fail_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (3));
  assert_that (session_init_calls, is_equal_to (3));
  assert_that (cleanup_calls, is_equal_to (3));
  assert_that (received_diagnostic_config_uuid,
               is_equal_to_string (config_uuid));
  assert_that (received_diagnostic_nvt_oid, is_equal_to_string (nvt_oid));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (yafvs_control, dispatches_malformed_diagnostic_nvt_frame)
{
  const char *request =
    "scan-config-nvt-diagnostic " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 1..3\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];
  ssize_t response_len;

  diagnostic_control_calls = 0;
  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_trash_empty_request (request, response);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  assert_that (response_len, is_equal_to (strlen ("-2 malformed\n")));
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  assert_that (diagnostic_control_calls, is_equal_to (0));
}

int
__real_manage_configure_diagnostic_nvt (const char *, const char *,
                                        gboolean *, gboolean *);

static int
run_real_diagnostic_nvt (const char *nvt_oid, gboolean *changed,
                         gboolean *committed)
{
  int result;

  current_credentials.uuid =
    g_strdup ("123e4567-e89b-12d3-a456-426614174000");
  result = __real_manage_configure_diagnostic_nvt (
    "123e4567-e89b-12d3-a456-426614174001", nvt_oid, changed, committed);
  g_clear_pointer (&current_credentials.uuid, g_free);
  return result;
}

Ensure (yafvs_control, atomically_configures_diagnostic_nvt_and_cache)
{
  const char *nvt_oid = "1.3.6.1.4.1.25623.1.0.900001";
  static const enum diagnostic_db_event expected[] = {
    DIAGNOSTIC_DB_BEGIN,
    DIAGNOSTIC_DB_RESOURCE_LOCK,
    DIAGNOSTIC_DB_NVT_LOCK,
    DIAGNOSTIC_DB_DELETE,
    DIAGNOSTIC_DB_INSERT,
    DIAGNOSTIC_DB_INSERT,
    DIAGNOSTIC_DB_INSERT,
    DIAGNOSTIC_DB_CACHE,
    DIAGNOSTIC_DB_COMMIT,
    DIAGNOSTIC_DB_POSTVERIFY,
  };
  gboolean changed = FALSE;
  gboolean committed = FALSE;

  reset_diagnostic_db (nvt_oid);
  assert_that (run_real_diagnostic_nvt (nvt_oid, &changed, &committed),
               is_equal_to (0));
  assert_that (changed, is_true);
  assert_that (committed, is_true);
  assert_that (diagnostic_db_inserts, is_equal_to (3));
  assert_that (diagnostic_db_cache_updates, is_equal_to (1));
  assert_that (diagnostic_db_event_count, is_equal_to (G_N_ELEMENTS (expected)));
  assert_that (memcmp (diagnostic_db_events, expected, sizeof (expected)),
               is_equal_to (0));
  diagnostic_db_active = FALSE;
}

Ensure (yafvs_control, retries_identical_diagnostic_state_idempotently)
{
  const char *nvt_oid = "1.3.6.1.4.1.25623.1.0.900001";
  static const enum diagnostic_db_event expected[] = {
    DIAGNOSTIC_DB_BEGIN,
    DIAGNOSTIC_DB_RESOURCE_LOCK,
    DIAGNOSTIC_DB_NVT_LOCK,
    DIAGNOSTIC_DB_COMMIT,
  };
  gboolean changed = TRUE;
  gboolean committed = TRUE;

  reset_diagnostic_db (nvt_oid);
  diagnostic_db_state_matches = TRUE;
  assert_that (run_real_diagnostic_nvt (nvt_oid, &changed, &committed),
               is_equal_to (0));
  assert_that (changed, is_false);
  assert_that (committed, is_false);
  assert_that (diagnostic_db_inserts, is_equal_to (0));
  assert_that (diagnostic_db_cache_updates, is_equal_to (0));
  assert_that (diagnostic_db_event_count, is_equal_to (G_N_ELEMENTS (expected)));
  assert_that (memcmp (diagnostic_db_events, expected, sizeof (expected)),
               is_equal_to (0));
  diagnostic_db_active = FALSE;
}

Ensure (yafvs_control, deduplicates_requested_diagnostic_prerequisite)
{
  gboolean changed = FALSE;
  gboolean committed = FALSE;

  reset_diagnostic_db (TEST_DIAGNOSTIC_NMAP_OID);
  diagnostic_db_nvt_family = TEST_DIAGNOSTIC_PREREQUISITE_FAMILY;
  assert_that (run_real_diagnostic_nvt (
                 TEST_DIAGNOSTIC_NMAP_OID, &changed, &committed),
               is_equal_to (0));
  assert_that (diagnostic_db_inserts, is_equal_to (2));
  assert_that (diagnostic_db_cache_updates, is_equal_to (1));
  diagnostic_db_active = FALSE;
}

Ensure (yafvs_control, rejects_unsafe_diagnostic_config_states)
{
  const char *nvt_oid = "1.3.6.1.4.1.25623.1.0.900001";
  gboolean changed;
  gboolean committed;

#define ASSERT_DIAGNOSTIC_REJECTION(expected)                                \
  do                                                                         \
    {                                                                        \
      changed = TRUE;                                                        \
      committed = TRUE;                                                      \
      assert_that (run_real_diagnostic_nvt (nvt_oid, &changed, &committed),  \
                   is_equal_to (expected));                                  \
      assert_that (changed, is_false);                                       \
      assert_that (committed, is_false);                                     \
      assert_that (diagnostic_db_events[diagnostic_db_event_count - 1],      \
                   is_equal_to (DIAGNOSTIC_DB_ROLLBACK));                    \
    }                                                                        \
  while (0)

  reset_diagnostic_db (nvt_oid);
  diagnostic_db_acl = FALSE;
  ASSERT_DIAGNOSTIC_REJECTION (99);
  assert_that (diagnostic_db_event_count, is_equal_to (2));
  assert_that (diagnostic_db_events[0], is_equal_to (DIAGNOSTIC_DB_BEGIN));
  assert_that (diagnostic_db_events[1],
               is_equal_to (DIAGNOSTIC_DB_ROLLBACK));
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_owner_exists = FALSE;
  ASSERT_DIAGNOSTIC_REJECTION (99);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_config_exists = FALSE;
  ASSERT_DIAGNOSTIC_REJECTION (3);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_owned = FALSE;
  ASSERT_DIAGNOSTIC_REJECTION (99);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_predefined = TRUE;
  ASSERT_DIAGNOSTIC_REJECTION (99);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_in_use = TRUE;
  ASSERT_DIAGNOSTIC_REJECTION (1);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_selector_refs = 2;
  ASSERT_DIAGNOSTIC_REJECTION (6);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_nvt_exists = FALSE;
  ASSERT_DIAGNOSTIC_REJECTION (4);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_nvt_family = "Debian Local Security Checks";
  ASSERT_DIAGNOSTIC_REJECTION (2);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_nmap_exists = FALSE;
  ASSERT_DIAGNOSTIC_REJECTION (5);
  reset_diagnostic_db (nvt_oid);
  diagnostic_db_ping_exists = FALSE;
  ASSERT_DIAGNOSTIC_REJECTION (5);

#undef ASSERT_DIAGNOSTIC_REJECTION
  diagnostic_db_active = FALSE;
}

Ensure (yafvs_control, reports_indeterminate_after_diagnostic_commit)
{
  const char *nvt_oid = "1.3.6.1.4.1.25623.1.0.900001";
  gboolean changed = FALSE;
  gboolean committed = FALSE;

  reset_diagnostic_db (nvt_oid);
  diagnostic_db_postcommit_matches = FALSE;
  assert_that (run_real_diagnostic_nvt (nvt_oid, &changed, &committed),
               is_equal_to (-3));
  assert_that (changed, is_true);
  assert_that (committed, is_true);
  assert_that (diagnostic_db_cache_updates, is_equal_to (1));
  assert_that (diagnostic_db_events[diagnostic_db_event_count - 2],
               is_equal_to (DIAGNOSTIC_DB_COMMIT));
  assert_that (diagnostic_db_events[diagnostic_db_event_count - 1],
               is_equal_to (DIAGNOSTIC_DB_POSTVERIFY));
  diagnostic_db_active = FALSE;
}

static gchar *
test_tag_base64 (const char *value)
{
  return g_base64_encode ((const guchar *) value, strlen (value));
}

Ensure (yafvs_control, parses_atomic_tag_modify_and_empty_set)
{
  gchar *name = test_tag_base64 ("Renamed");
  gchar *resource_type = test_tag_base64 ("target");
  gchar *filter = test_tag_base64 ("rows=-1 name~production");
  gchar *request = g_strdup_printf (
    "tag-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 +%s + - 0 +%s set + +%s\n",
    name, resource_type, filter);
  gchar *clear_request = g_strdup_printf (
    "tag-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 - - - - - set + -\n");
  char operator_uuid[37];
  char tag_uuid[37];
  yafvs_control_tag_modify_request_t tag = {0};

  assert_that (yafvs_control_parse_tag_modify_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, tag_uuid,
                 &tag),
               is_true);
  assert_that (tag_uuid,
               is_equal_to_string (
                 "123e4567-e89b-12d3-a456-426614174001"));
  assert_that (tag.name, is_equal_to_string ("Renamed"));
  assert_that (tag.comment, is_equal_to_string (""));
  assert_that (tag.value, is_null);
  assert_that (tag.active, is_equal_to_string ("0"));
  assert_that (tag.resource_type, is_equal_to_string ("target"));
  assert_that (tag.resources_action, is_equal_to_string ("set"));
  assert_that (g_ptr_array_index (tag.resource_ids, 0), is_null);
  assert_that (tag.resource_filter,
               is_equal_to_string ("rows=-1 name~production"));
  yafvs_control_tag_modify_request_clear (&tag);

  assert_that (yafvs_control_parse_tag_modify_request (
                 clear_request, strlen (clear_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, tag_uuid,
                 &tag),
               is_true);
  assert_that (tag.resource_ids, is_not_null);
  assert_that (g_ptr_array_index (tag.resource_ids, 0), is_null);
  assert_that (tag.resource_filter, is_null);
  yafvs_control_tag_modify_request_clear (&tag);

  g_free (clear_request);
  g_free (request);
  g_free (filter);
  g_free (resource_type);
  g_free (name);
}

Ensure (yafvs_control, rejects_unsafe_tag_resource_type_mutation)
{
  gchar *resource_type = test_tag_base64 ("target");
  gchar *request = g_strdup_printf (
    "tag-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 - - - - +%s - - -\n",
    resource_type);
  char operator_uuid[37];
  char tag_uuid[37];
  yafvs_control_tag_modify_request_t tag = {0};

  assert_that (yafvs_control_parse_tag_modify_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, tag_uuid,
                 &tag),
               is_false);

  g_free (request);
  g_free (resource_type);
}

Ensure (yafvs_control, runs_tag_modify_in_operator_session_and_audits)
{
  array_t *resource_ids = make_array ();
  const yafvs_control_tag_modify_request_t modify_request = {
    .name = "Renamed",
    .resources_action = "set",
    .resource_ids = resource_ids,
    .resource_filter = "rows=-1 name~production",
  };
  array_terminate (resource_ids);
  cleanup_calls = 0;
  modify_tag_calls = 0;
  modify_tag_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  tag_audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (yafvs_control_modify_tag (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001", &modify_request),
               is_equal_to (0));
  assert_that (modify_tag_calls, is_equal_to (1));
  assert_that (tag_audit_success_calls, is_equal_to (1));
  assert_that (received_tag_resource_filter,
               is_equal_to_string (modify_request.resource_filter));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
  array_free (resource_ids);
}

Ensure (yafvs_control, maps_tag_modify_control_responses)
{
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (yafvs_control_tag_modify_response (0, response),
               is_equal_to_string ("0 modified\n"));
  assert_that (yafvs_control_tag_modify_response (4, response),
               is_equal_to_string ("4 resource_not_found\n"));
  assert_that (yafvs_control_tag_modify_response (-2, response),
               is_equal_to_string ("-2 malformed\n"));
}

Ensure (yafvs_control, parses_strict_authenticated_alert_test_frames)
{
  const char *request =
    "alert-test " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  const char *malformed[] = {
    "alert-test wrong-secret "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n",
    "alert-test " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-42661417400z "
    "123e4567-e89b-12d3-a456-426614174001\n",
    "alert-test " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z\n",
    "alert-test " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 extra\n",
  };
  char operator_uuid[37];
  char alert_uuid[37];
  size_t index;

  assert_that (yafvs_control_parse_alert_test_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, alert_uuid),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (alert_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));

  for (index = 0; index < G_N_ELEMENTS (malformed); index++)
    assert_that (yafvs_control_parse_alert_test_request (
                   malformed[index], strlen (malformed[index]),
                   TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                   operator_uuid, alert_uuid),
                 is_false);
}

Ensure (yafvs_control, maps_alert_test_responses_without_malformed_overlap)
{
  static const struct
  {
    int result;
    const char *response;
  } cases[] = {
    {0, "0 tested\n"},
    {1, "1 not_found\n"},
    {99, "99 forbidden\n"},
    {-2, "-2 report_format_not_found\n"},
    {-3, "-3 filter_not_found\n"},
    {-4, "-4 credential_not_found\n"},
    {-5, "-5 delivery_failed\n"},
    {2, "-1 internal\n"},
    {-1, "-1 internal\n"},
  };
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (cases); index++)
    assert_that (yafvs_control_alert_test_response (cases[index].result),
                 is_equal_to_string (cases[index].response));
}

Ensure (yafvs_control, parses_strict_alert_report_delivery_frames)
{
  const char *filter_request =
    "alert-deliver-report " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "123e4567-e89b-12d3-a456-426614174002 c2V2ZXJpdHk+Nw== -\n";
  const char *filter_id_request =
    "alert-deliver-report " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "123e4567-e89b-12d3-a456-426614174002 - "
    "123e4567-e89b-12d3-a456-426614174003\n";
  const char *malformed[] = {
    "alert-deliver-report " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "123e4567-e89b-12d3-a456-426614174002 c2V2ZXJpdHk+Nw== "
    "123e4567-e89b-12d3-a456-426614174003\n",
    "alert-deliver-report " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z "
    "123e4567-e89b-12d3-a456-426614174002 - -\n",
    "alert-deliver-report " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "123e4567-e89b-12d3-a456-426614174002 not-base64 -\n",
  };
  char operator_uuid[37];
  yafvs_control_alert_deliver_report_request_t delivery = {0};
  size_t index;

  assert_that (yafvs_control_parse_alert_deliver_report_request (
                 filter_request, strlen (filter_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &delivery),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (delivery.alert_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (delivery.report_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174002"));
  assert_that (delivery.filter, is_equal_to_string ("severity>7"));
  assert_that (delivery.filter_uuid, is_equal_to_string (""));
  yafvs_control_alert_deliver_report_request_clear (&delivery);

  assert_that (yafvs_control_parse_alert_deliver_report_request (
                 filter_id_request, strlen (filter_id_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &delivery),
               is_true);
  assert_that (delivery.filter, is_equal_to_string (""));
  assert_that (delivery.filter_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174003"));
  yafvs_control_alert_deliver_report_request_clear (&delivery);

  for (index = 0; index < G_N_ELEMENTS (malformed); index++)
    assert_that (yafvs_control_parse_alert_deliver_report_request (
                   malformed[index], strlen (malformed[index]),
                   TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                   operator_uuid, &delivery),
                 is_false);
}

Ensure (yafvs_control, maps_alert_report_delivery_responses)
{
  static const struct
  {
    int result;
    const char *response;
  } cases[] = {
    {0, "0 delivered\n"},
    {1, "1 alert_not_found\n"},
    {2, "2 report_not_found\n"},
    {3, "3 filter_not_found\n"},
    {99, "99 forbidden\n"},
    {-2, "-2 report_format_not_found\n"},
    {-3, "-3 delivery_failed\n"},
    {-4, "-1 internal\n"},
    {-1, "-1 internal\n"},
  };
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (cases); index++)
    assert_that (
      yafvs_control_alert_deliver_report_response (cases[index].result),
      is_equal_to_string (cases[index].response));
}

Ensure (yafvs_control, delivers_report_in_operator_session_and_audits)
{
  const char *operator_uuid = "123e4567-e89b-12d3-a456-426614174000";
  yafvs_control_alert_deliver_report_request_t delivery = {
    .alert_uuid = "123e4567-e89b-12d3-a456-426614174001",
    .report_uuid = "123e4567-e89b-12d3-a456-426614174002",
    .filter = "severity>7",
  };

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  alert_delivery_active = TRUE;
  alert_delivery_alert_exists = TRUE;
  alert_delivery_report_exists = TRUE;
  alert_delivery_filter_exists = TRUE;
  alert_delivery_method = ALERT_METHOD_EMAIL;
  alert_delivery_result = 0;
  alert_delivery_calls = 0;
  alert_delivery_audit_success_calls = 0;
  alert_delivery_audit_fail_calls = 0;
  mock_operator_name = "operator";
  g_clear_pointer (&received_alert_delivery_uuid, g_free);
  g_clear_pointer (&received_alert_delivery_report_uuid, g_free);
  g_clear_pointer (&received_alert_delivery_filter, g_free);
  g_clear_pointer (&received_alert_delivery_filter_uuid, g_free);
  received_alert_delivery_uuid = g_strdup (delivery.alert_uuid);
  received_alert_delivery_report_uuid = g_strdup (delivery.report_uuid);
  received_alert_delivery_filter = g_strdup ("severity>7 rows=1000");

  assert_that (
    yafvs_control_deliver_alert_report (operator_uuid, &delivery),
    is_equal_to (0));
  assert_that (alert_delivery_calls, is_equal_to (1));
  assert_that (alert_delivery_audit_success_calls, is_equal_to (1));
  assert_that (alert_delivery_audit_fail_calls, is_equal_to (0));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));

  g_strlcpy (delivery.filter_uuid,
             "123e4567-e89b-12d3-a456-426614174003",
             sizeof (delivery.filter_uuid));
  delivery.filter = "";
  g_free (received_alert_delivery_filter);
  received_alert_delivery_filter = g_strdup ("first=1 rows=5");
  received_alert_delivery_filter_uuid = g_strdup (delivery.filter_uuid);
  alert_delivery_result = -4;
  assert_that (
    yafvs_control_deliver_alert_report (operator_uuid, &delivery),
    is_equal_to (3));
  assert_that (alert_delivery_calls, is_equal_to (2));
  assert_that (alert_delivery_audit_fail_calls, is_equal_to (1));

  alert_delivery_report_exists = FALSE;
  g_clear_pointer (&received_alert_delivery_filter_uuid, g_free);
  assert_that (
    yafvs_control_deliver_alert_report (operator_uuid, &delivery),
    is_equal_to (2));
  assert_that (alert_delivery_calls, is_equal_to (2));
  assert_that (alert_delivery_audit_fail_calls, is_equal_to (2));

  mock_operator_name = NULL;
  assert_that (
    yafvs_control_deliver_alert_report (operator_uuid, &delivery),
    is_equal_to (99));
  assert_that (alert_delivery_calls, is_equal_to (2));
  alert_delivery_active = FALSE;
  g_clear_pointer (&received_alert_delivery_uuid, g_free);
  g_clear_pointer (&received_alert_delivery_report_uuid, g_free);
  g_clear_pointer (&received_alert_delivery_filter, g_free);
}

Ensure (yafvs_control, tests_alert_in_operator_session_audits_and_scrubs)
{
  const char *operator_uuid = "123e4567-e89b-12d3-a456-426614174000";
  const char *alert_uuid = "123e4567-e89b-12d3-a456-426614174001";

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  alert_test_calls = 0;
  alert_test_audit_success_calls = 0;
  alert_test_audit_fail_calls = 0;
  alert_test_result = 0;
  alert_test_script_message = "private alert script message";
  mock_operator_name = "operator";
  g_clear_pointer (&received_alert_test_uuid, g_free);

  assert_that (yafvs_control_test_alert (operator_uuid, alert_uuid),
               is_equal_to (0));
  assert_that (alert_test_calls, is_equal_to (1));
  assert_that (alert_test_audit_success_calls, is_equal_to (1));
  assert_that (alert_test_audit_fail_calls, is_equal_to (0));
  assert_that (received_alert_test_uuid, is_equal_to_string (alert_uuid));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);

  alert_test_result = -5;
  assert_that (yafvs_control_test_alert (operator_uuid, alert_uuid),
               is_equal_to (-5));
  assert_that (alert_test_calls, is_equal_to (2));
  assert_that (alert_test_audit_success_calls, is_equal_to (1));
  assert_that (alert_test_audit_fail_calls, is_equal_to (1));

  mock_operator_name = NULL;
  assert_that (yafvs_control_test_alert (operator_uuid, alert_uuid),
               is_equal_to (99));
  assert_that (alert_test_calls, is_equal_to (2));
  assert_that (alert_test_audit_fail_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (3));
  alert_test_script_message = NULL;
}

Ensure (yafvs_control, dispatches_alert_test_without_sensitive_response_data)
{
  const char *request =
    "alert-test " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  const char *malformed =
    "alert-test " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 extra\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  alert_test_calls = 0;
  alert_test_result = -5;
  alert_test_script_message = "private alert script message";
  alert_test_audit_fail_calls = 0;
  mock_operator_name = "operator";
  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_trash_empty_request (request, response);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  assert_that (response_len, is_equal_to (strlen ("-5 delivery_failed\n")));
  assert_that (response, is_equal_to_string ("-5 delivery_failed\n"));
  assert_that (alert_test_calls, is_equal_to (1));
  assert_that (alert_test_audit_fail_calls, is_equal_to (1));
  assert_that (strstr (response, TEST_CONTROL_SECRET), is_null);
  assert_that (strstr (response, "123e4567-e89b-12d3-a456-426614174000"),
               is_null);
  assert_that (strstr (response, "123e4567-e89b-12d3-a456-426614174001"),
               is_null);
  assert_that (strstr (response, alert_test_script_message), is_null);

  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  response_len = dispatch_trash_empty_request (malformed, response);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  assert_that (response_len, is_equal_to (strlen ("-2 malformed\n")));
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  assert_that (alert_test_calls, is_equal_to (1));
  alert_test_script_message = NULL;
}

Ensure (yafvs_control, parses_strict_user_setting_modify_frames)
{
  const char *id_request =
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-426614174001 ZmlsdGVy\n";
  const char *timezone_request =
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 timezone - "
    "RXVyb3BlL0Jlcmxpbg==\n";
  const char *empty_request =
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-426614174001 \n";
  char operator_uuid[37];
  yafvs_control_user_setting_modify_request_t setting = {0};

  assert_that (yafvs_control_parse_user_setting_modify_request (
                 id_request, strlen (id_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &setting),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (setting.timezone, is_false);
  assert_that (setting.setting_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (setting.value, is_equal_to_string ("filter"));
  yafvs_control_user_setting_modify_request_clear (&setting);

  assert_that (yafvs_control_parse_user_setting_modify_request (
                 timezone_request, strlen (timezone_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &setting),
               is_true);
  assert_that (setting.timezone, is_true);
  assert_that (setting.setting_uuid, is_equal_to_string (""));
  assert_that (setting.value, is_equal_to_string ("Europe/Berlin"));
  yafvs_control_user_setting_modify_request_clear (&setting);

  assert_that (yafvs_control_parse_user_setting_modify_request (
                 empty_request, strlen (empty_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &setting),
               is_true);
  assert_that (setting.value, is_equal_to_string (""));
  yafvs_control_user_setting_modify_request_clear (&setting);
}

Ensure (yafvs_control, rejects_malformed_user_setting_modify_frames)
{
  const char *invalid[] = {
    "user-setting-modify wrongsecretwrongsecretwrongsecret12 "
    "123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-426614174001 Zg==\n",
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 Password - Zg==\n",
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 other - Zg==\n",
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 timezone "
    "123e4567-e89b-12d3-a456-426614174001 Zg==\n",
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 id - Zg==\n",
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-42661417400z Zg==\n",
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-426614174001 Zh==\n",
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-426614174001 Zg== extra\n",
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-426614174001\n",
  };
  char operator_uuid[37];
  yafvs_control_user_setting_modify_request_t setting = {0};
  guchar *oversized_value;
  gchar *oversized_64;
  gchar *oversized_request;
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (invalid); index++)
    assert_that (yafvs_control_parse_user_setting_modify_request (
                   invalid[index], strlen (invalid[index]),
                   TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                   operator_uuid, &setting),
                 is_false);

  oversized_value = g_malloc (YAFVS_CONTROL_USER_SETTING_VALUE_MAX_BYTES
                              + 1);
  memset (oversized_value, 'x',
          YAFVS_CONTROL_USER_SETTING_VALUE_MAX_BYTES + 1);
  oversized_64 = g_base64_encode (
    oversized_value, YAFVS_CONTROL_USER_SETTING_VALUE_MAX_BYTES + 1);
  oversized_request = g_strdup_printf (
    "user-setting-modify %s 123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-426614174001 %s\n",
    TEST_CONTROL_SECRET, oversized_64);
  assert_that (yafvs_control_parse_user_setting_modify_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &setting),
               is_false);
  yafvs_control_secure_clear (oversized_value,
                                 YAFVS_CONTROL_USER_SETTING_VALUE_MAX_BYTES
                                   + 1);
  g_free (oversized_value);
  yafvs_control_secure_free (oversized_64);
  yafvs_control_secure_free (oversized_request);
}

Ensure (yafvs_control, maps_user_setting_modify_responses)
{
  assert_that (yafvs_control_user_setting_modify_response (
                 MODIFY_SETTING_RESULT_OK),
               is_equal_to_string ("0 modified\n"));
  assert_that (yafvs_control_user_setting_modify_response (
                 MODIFY_SETTING_RESULT_NOT_FOUND),
               is_equal_to_string ("1 not_found\n"));
  assert_that (yafvs_control_user_setting_modify_response (
                 MODIFY_SETTING_RESULT_SYNTAX_ERROR),
               is_equal_to_string ("2 invalid_value\n"));
  assert_that (yafvs_control_user_setting_modify_response (
                 MODIFY_SETTING_RESULT_FEATURE_DISABLED),
               is_equal_to_string ("3 feature_disabled\n"));
  assert_that (yafvs_control_user_setting_modify_response (
                 MODIFY_SETTING_RESULT_PERMISSION_DENIED),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_user_setting_modify_response (-2),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (yafvs_control_user_setting_modify_response (
                 MODIFY_SETTING_RESULT_ERROR),
               is_equal_to_string ("-1 internal\n"));
  assert_that (yafvs_control_user_setting_modify_response (55),
               is_equal_to_string ("-1 internal\n"));
}

Ensure (yafvs_control, modifies_user_settings_in_operator_session)
{
  yafvs_control_user_setting_modify_request_t request = {
    .timezone = FALSE,
    .setting_uuid = "123e4567-e89b-12d3-a456-426614174001",
    .value = "filter",
  };

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  modify_setting_calls = 0;
  modify_setting_result = MODIFY_SETTING_RESULT_OK;
  mock_operator_name = "operator";

  assert_that (yafvs_control_modify_user_setting (
                 "123e4567-e89b-12d3-a456-426614174000", &request),
               is_equal_to (MODIFY_SETTING_RESULT_OK));
  assert_that (modify_setting_calls, is_equal_to (1));
  assert_that (received_setting_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (received_setting_name, is_null);
  assert_that (received_setting_value_64, is_equal_to_string ("ZmlsdGVy"));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);

  request.timezone = TRUE;
  request.setting_uuid[0] = '\0';
  request.value = "Europe/Berlin";
  modify_setting_result = MODIFY_SETTING_RESULT_SYNTAX_ERROR;
  assert_that (yafvs_control_modify_user_setting (
                 "123e4567-e89b-12d3-a456-426614174000", &request),
               is_equal_to (MODIFY_SETTING_RESULT_SYNTAX_ERROR));
  assert_that (modify_setting_calls, is_equal_to (2));
  assert_that (received_setting_uuid, is_null);
  assert_that (received_setting_name, is_equal_to_string ("Timezone"));
  assert_that (received_setting_value_64,
               is_equal_to_string ("RXVyb3BlL0Jlcmxpbg=="));
  assert_that (cleanup_calls, is_equal_to (2));

  mock_operator_name = NULL;
  assert_that (yafvs_control_modify_user_setting (
                 "123e4567-e89b-12d3-a456-426614174000", &request),
               is_equal_to (MODIFY_SETTING_RESULT_PERMISSION_DENIED));
  assert_that (modify_setting_calls, is_equal_to (2));
  assert_that (cleanup_calls, is_equal_to (3));
}

Ensure (yafvs_control, dispatches_user_setting_results_and_rejects_bad_frames)
{
  static const struct
  {
    modify_setting_result_t result;
    const char *response;
  } cases[] = {
    {MODIFY_SETTING_RESULT_OK, "0 modified\n"},
    {MODIFY_SETTING_RESULT_NOT_FOUND, "1 not_found\n"},
    {MODIFY_SETTING_RESULT_SYNTAX_ERROR, "2 invalid_value\n"},
    {MODIFY_SETTING_RESULT_FEATURE_DISABLED, "3 feature_disabled\n"},
    {MODIFY_SETTING_RESULT_PERMISSION_DENIED, "99 forbidden\n"},
    {MODIFY_SETTING_RESULT_ERROR, "-1 internal\n"},
  };
  const char *request =
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 id "
    "123e4567-e89b-12d3-a456-426614174001 ZmlsdGVy\n";
  const char *malformed =
    "user-setting-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 Password - c2VjcmV0\n";
  size_t index;

  modify_setting_calls = 0;
  mock_operator_name = "operator";
  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);
  for (index = 0; index < G_N_ELEMENTS (cases); index++)
    {
      char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
      ssize_t response_len;

      modify_setting_result = cases[index].result;
      response_len = dispatch_trash_empty_request (request, response);
      assert_that (response_len,
                   is_equal_to ((ssize_t) strlen (cases[index].response)));
      response[response_len] = '\0';
      assert_that (response, is_equal_to_string (cases[index].response));
      assert_that (strstr (response, "filter"), is_null);
      assert_that (strstr (response, "private setting error"), is_null);
    }
  assert_that (modify_setting_calls,
               is_equal_to ((int) G_N_ELEMENTS (cases)));

  {
    char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
    ssize_t response_len = dispatch_trash_empty_request (malformed, response);
    response[response_len] = '\0';
    assert_that (response, is_equal_to_string ("-2 malformed\n"));
    assert_that (modify_setting_calls,
                 is_equal_to ((int) G_N_ELEMENTS (cases)));
  }

  mock_operator_name = NULL;
  {
    char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
    ssize_t response_len = dispatch_trash_empty_request (request, response);
    response[response_len] = '\0';
    assert_that (response, is_equal_to_string ("99 forbidden\n"));
    assert_that (modify_setting_calls,
                 is_equal_to ((int) G_N_ELEMENTS (cases)));
  }
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
  g_clear_pointer (&received_setting_uuid, g_free);
  g_clear_pointer (&received_setting_name, g_free);
  g_clear_pointer (&received_setting_value_64, g_free);
}

Ensure (yafvs_control, parses_bounded_user_management_frames)
{
  const char *clone_request =
    "user-clone " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  const char *create_request =
    "user-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 file VXNlcg== Q29tbWVudA== "
    "U2VjcmV0\n";
  const char *modify_request =
    "user-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 radius_connect VXNlcg== "
    "- -\n";
  const char *delete_request =
    "user-delete " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 -\n";
  char operator_uuid[37];
  char source_user_uuid[37];
  yafvs_control_user_create_request_t create = {0};
  yafvs_control_user_modify_request_t modify = {0};
  yafvs_control_user_delete_request_t delete_request_data = {0};

  assert_that (yafvs_control_parse_user_create_request (
                 create_request, strlen (create_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &create), is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (create.method, is_equal_to_string ("file"));
  assert_that (create.name, is_equal_to_string ("User"));
  assert_that (create.comment, is_equal_to_string ("Comment"));
  assert_that (create.password, is_equal_to_string ("Secret"));
  yafvs_control_user_create_request_clear (&create);

  assert_that (yafvs_control_parse_user_modify_request (
                 modify_request, strlen (modify_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &modify), is_true);
  assert_that (modify.target_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (modify.method, is_equal_to_string ("radius_connect"));
  assert_that (modify.comment, is_equal_to_string (""));
  assert_that (modify.password, is_null);
  yafvs_control_user_modify_request_clear (&modify);

  assert_that (yafvs_control_parse_user_delete_request (
                 delete_request, strlen (delete_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 &delete_request_data), is_true);
  assert_that (delete_request_data.target_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (delete_request_data.inheritor_uuid, is_equal_to_string (""));
  yafvs_control_secure_clear (&delete_request_data,
                                 sizeof (delete_request_data));

  assert_that (yafvs_control_parse_user_clone_request (
                 clone_request, strlen (clone_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 source_user_uuid), is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (source_user_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
}

Ensure (yafvs_control, rejects_malformed_or_unauthenticated_user_management_frames)
{
  const char *invalid[] = {
    "user-create badsecretbadsecretbadsecretbadsec "
    "123e4567-e89b-12d3-a456-426614174000 file VXNlcg== Qw== U2VjcmV0\n",
    "user-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 LDAP VXNlcg== Qw== -\n",
    "user-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 file VXNlcg== Qw== Zh==\n",
    "user-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z file VXNlcg== Qw== -\n",
    "user-delete " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 self\n",
    "user-delete " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 - extra\n",
    "user-clone badsecretbadsecretbadsecretbadsec "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n",
    "user-clone " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-42661417400z "
    "123e4567-e89b-12d3-a456-426614174001\n",
    "user-clone " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z\n",
    "user-clone " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 extra\n",
  };
  guchar *oversized_name;
  gchar *oversized_name_64;
  gchar *oversized_request;
  char operator_uuid[37];
  char source_user_uuid[37];
  yafvs_control_user_create_request_t create = {0};
  yafvs_control_user_modify_request_t modify = {0};
  yafvs_control_user_delete_request_t delete_request_data = {0};

  assert_that (yafvs_control_parse_user_create_request (
                 invalid[0], strlen (invalid[0]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &create), is_false);
  assert_that (yafvs_control_parse_user_create_request (
                 invalid[1], strlen (invalid[1]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &create), is_false);
  assert_that (yafvs_control_parse_user_create_request (
                 invalid[2], strlen (invalid[2]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &create), is_false);
  assert_that (yafvs_control_parse_user_modify_request (
                 invalid[3], strlen (invalid[3]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &modify), is_false);
  assert_that (yafvs_control_parse_user_delete_request (
                 invalid[4], strlen (invalid[4]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 &delete_request_data), is_false);
  assert_that (yafvs_control_parse_user_delete_request (
                 invalid[5], strlen (invalid[5]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 &delete_request_data), is_false);
  assert_that (yafvs_control_parse_user_clone_request (
                 invalid[6], strlen (invalid[6]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 source_user_uuid), is_false);
  assert_that (yafvs_control_parse_user_clone_request (
                 invalid[7], strlen (invalid[7]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 source_user_uuid), is_false);
  assert_that (yafvs_control_parse_user_clone_request (
                 invalid[8], strlen (invalid[8]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 source_user_uuid), is_false);
  assert_that (yafvs_control_parse_user_clone_request (
                 invalid[9], strlen (invalid[9]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 source_user_uuid), is_false);

  oversized_name = g_malloc (YAFVS_CONTROL_USER_NAME_MAX_BYTES + 1);
  memset (oversized_name, 'u', YAFVS_CONTROL_USER_NAME_MAX_BYTES + 1);
  oversized_name_64 = g_base64_encode (
    oversized_name, YAFVS_CONTROL_USER_NAME_MAX_BYTES + 1);
  oversized_request = g_strdup_printf (
    "user-create %s 123e4567-e89b-12d3-a456-426614174000 file %s Qw== -\\n",
    TEST_CONTROL_SECRET, oversized_name_64);
  assert_that (yafvs_control_parse_user_create_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &create), is_false);
  yafvs_control_secure_clear (oversized_name,
                                 YAFVS_CONTROL_USER_NAME_MAX_BYTES + 1);
  g_free (oversized_name);
  g_free (oversized_name_64);
  g_free (oversized_request);
}

Ensure (yafvs_control, maps_authoritative_user_management_responses)
{
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};

  assert_that (yafvs_control_user_create_response (
                 0, "123e4567-e89b-12d3-a456-426614174001", response),
               is_equal_to_string (
                 "0 created 123e4567-e89b-12d3-a456-426614174001\n"));
  assert_that (yafvs_control_user_create_response (1, NULL, response),
               is_equal_to_string ("1 exists\n"));
  assert_that (yafvs_control_user_create_response (2, NULL, response),
               is_equal_to_string ("2 invalid_name\n"));
  assert_that (yafvs_control_user_create_response (3, NULL, response),
               is_equal_to_string ("3 password_rejected\n"));
  assert_that (yafvs_control_user_create_response (4, NULL, response),
               is_equal_to_string ("4 invalid_method\n"));
  assert_that (yafvs_control_user_create_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_user_create_response (-3, NULL, response),
               is_equal_to_string ("-3 committed_indeterminate\n"));
  assert_that (yafvs_control_user_create_response (-2, NULL, response),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (yafvs_control_user_create_response (-1, NULL, response),
               is_equal_to_string ("-1 internal\n"));

  assert_that (yafvs_control_user_modify_response (0),
               is_equal_to_string ("0 modified\n"));
  assert_that (yafvs_control_user_modify_response (1),
               is_equal_to_string ("1 not_found\n"));
  assert_that (yafvs_control_user_modify_response (2),
               is_equal_to_string ("2 invalid_name\n"));
  assert_that (yafvs_control_user_modify_response (3),
               is_equal_to_string ("3 exists\n"));
  assert_that (yafvs_control_user_modify_response (4),
               is_equal_to_string ("4 password_rejected\n"));
  assert_that (yafvs_control_user_modify_response (5),
               is_equal_to_string ("5 password_required\n"));
  assert_that (yafvs_control_user_modify_response (6),
               is_equal_to_string ("6 self_mutation\n"));
  assert_that (yafvs_control_user_modify_response (7),
               is_equal_to_string ("7 invalid_method\n"));
  assert_that (yafvs_control_user_modify_response (99),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_user_modify_response (-3),
               is_equal_to_string ("-3 committed_indeterminate\n"));
  assert_that (yafvs_control_user_modify_response (-2),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (yafvs_control_user_modify_response (-1),
               is_equal_to_string ("-1 internal\n"));

  assert_that (yafvs_control_user_delete_response (0),
               is_equal_to_string ("0 deleted\n"));
  assert_that (yafvs_control_user_delete_response (1),
               is_equal_to_string ("1 not_found\n"));
  assert_that (yafvs_control_user_delete_response (2),
               is_equal_to_string ("2 current_user\n"));
  assert_that (yafvs_control_user_delete_response (3),
               is_equal_to_string ("3 inheritor_not_found\n"));
  assert_that (yafvs_control_user_delete_response (4),
               is_equal_to_string ("4 same_inheritor\n"));
  assert_that (yafvs_control_user_delete_response (5),
               is_equal_to_string ("5 last_user\n"));
  assert_that (yafvs_control_user_delete_response (99),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_user_delete_response (-2),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (yafvs_control_user_delete_response (-1),
               is_equal_to_string ("-1 internal\n"));

  assert_that (yafvs_control_user_clone_response (
                 0, "123e4567-e89b-12d3-a456-426614174001", response),
               is_equal_to_string (
                 "0 created 123e4567-e89b-12d3-a456-426614174001\n"));
  assert_that (yafvs_control_user_clone_response (1, NULL, response),
               is_equal_to_string ("1 duplicate\n"));
  assert_that (yafvs_control_user_clone_response (2, NULL, response),
               is_equal_to_string ("2 not_found\n"));
  assert_that (yafvs_control_user_clone_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (yafvs_control_user_clone_response (-3, NULL, response),
               is_equal_to_string ("-3 committed_indeterminate\n"));
  assert_that (yafvs_control_user_clone_response (-2, NULL, response),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (yafvs_control_user_clone_response (-1, NULL, response),
               is_equal_to_string ("-1 internal\n"));
}

Ensure (yafvs_control,
        clones_user_in_operator_session_and_reports_indeterminate_commit)
{
  const char *operator_uuid = "123e4567-e89b-12d3-a456-426614174000";
  const char *source_user_uuid = "123e4567-e89b-12d3-a456-426614174001";
  char created_uuid[37];

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  clone_user_calls = 0;
  clone_user_result = 0;
  clone_user_audit_fail_calls = 0;
  clone_user_audit_success_calls = 0;
  mock_operator_name = "operator";
  user_uuid_lookup_fails = FALSE;

  assert_that (yafvs_control_clone_user (operator_uuid, source_user_uuid,
                                             created_uuid), is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174003"));
  assert_that (clone_user_calls, is_equal_to (1));
  assert_that (received_user_target_uuid, is_equal_to_string (source_user_uuid));
  assert_that (clone_user_audit_success_calls, is_equal_to (1));
  assert_that (clone_user_audit_fail_calls, is_equal_to (0));
  assert_that (received_audit_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174003"));

  user_uuid_lookup_fails = TRUE;
  assert_that (yafvs_control_clone_user (operator_uuid, source_user_uuid,
                                             created_uuid), is_equal_to (-3));
  assert_that (created_uuid, is_equal_to_string (""));
  assert_that (clone_user_audit_success_calls, is_equal_to (2));
  assert_that (received_audit_uuid, is_null);

  user_uuid_lookup_fails = FALSE;
  clone_user_result = 2;
  assert_that (yafvs_control_clone_user (operator_uuid, source_user_uuid,
                                             created_uuid), is_equal_to (2));
  assert_that (clone_user_audit_fail_calls, is_equal_to (1));
  assert_that (received_audit_uuid, is_equal_to_string (source_user_uuid));
  assert_that (reinit_calls, is_equal_to (3));
  assert_that (session_init_calls, is_equal_to (3));
  assert_that (cleanup_calls, is_equal_to (3));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
  g_clear_pointer (&received_audit_uuid, g_free);
  g_clear_pointer (&received_user_target_uuid, g_free);
}

Ensure (yafvs_control, runs_native_user_management_in_operator_sessions)
{
  yafvs_control_user_create_request_t create = {0};
  yafvs_control_user_modify_request_t modify = {0};
  yafvs_control_user_delete_request_t delete_request_data = {0};
  char created_uuid[37];

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  create_user_calls = 0;
  modify_user_calls = 0;
  delete_user_calls = 0;
  create_user_result = 0;
  modify_user_result = 0;
  delete_user_result = 0;
  mock_operator_name = "operator";
  mock_target_name = "target";
  mock_target_auth_method = "ldap_connect";

  g_strlcpy (create.method, "ldap_connect", sizeof (create.method));
  create.name = g_strdup ("created");
  create.comment = g_strdup ("comment");
  assert_that (yafvs_control_create_user (
                 "123e4567-e89b-12d3-a456-426614174000", &create,
                 created_uuid), is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174003"));
  assert_that (create_user_calls, is_equal_to (1));
  assert_that (received_user_method, is_equal_to_string ("ldap_connect"));
  yafvs_control_user_create_request_clear (&create);

  g_strlcpy (modify.target_uuid, "123e4567-e89b-12d3-a456-426614174001",
             sizeof (modify.target_uuid));
  g_strlcpy (modify.method, "ldap_connect", sizeof (modify.method));
  modify.name = g_strdup ("target");
  modify.comment = g_strdup ("comment");
  assert_that (yafvs_control_modify_user (
                 "123e4567-e89b-12d3-a456-426614174000", &modify),
               is_equal_to (0));
  assert_that (modify_user_calls, is_equal_to (1));
  assert_that (received_name, is_null);
  assert_that (received_user_method, is_equal_to_string ("ldap_connect"));

  g_strlcpy (modify.method, "file", sizeof (modify.method));
  assert_that (yafvs_control_modify_user (
                 "123e4567-e89b-12d3-a456-426614174000", &modify),
               is_equal_to (0));
  assert_that (modify_user_calls, is_equal_to (2));
  g_strlcpy (modify.target_uuid, "123e4567-e89b-12d3-a456-426614174000",
             sizeof (modify.target_uuid));
  g_strlcpy (modify.method, "ldap_connect", sizeof (modify.method));
  g_free (modify.name);
  modify.name = g_strdup ("renamed");
  assert_that (yafvs_control_modify_user (
                 "123e4567-e89b-12d3-a456-426614174000", &modify),
               is_equal_to (6));
  g_free (modify.name);
  modify.name = g_strdup ("operator");
  assert_that (yafvs_control_modify_user (
                 "123e4567-e89b-12d3-a456-426614174000", &modify),
               is_equal_to (0));
  assert_that (modify_user_calls, is_equal_to (3));
  yafvs_control_user_modify_request_clear (&modify);

  g_strlcpy (delete_request_data.target_uuid,
             "123e4567-e89b-12d3-a456-426614174001",
             sizeof (delete_request_data.target_uuid));
  g_strlcpy (delete_request_data.inheritor_uuid,
             "123e4567-e89b-12d3-a456-426614174002",
             sizeof (delete_request_data.inheritor_uuid));
  assert_that (yafvs_control_delete_user (
                 "123e4567-e89b-12d3-a456-426614174000",
                 &delete_request_data), is_equal_to (0));
  assert_that (delete_user_calls, is_equal_to (1));
  assert_that (received_user_inheritor_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174002"));
  assert_that (reinit_calls, is_equal_to (6));
  assert_that (session_init_calls, is_equal_to (6));
  assert_that (cleanup_calls, is_equal_to (6));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
  g_clear_pointer (&received_user_inheritor_uuid, g_free);
  g_clear_pointer (&received_user_method, g_free);
  g_clear_pointer (&received_user_target_uuid, g_free);
  g_clear_pointer (&received_name, g_free);
  g_clear_pointer (&received_comment, g_free);
}

Ensure (yafvs_control,
        rejects_passwordless_file_transition_in_native_locked_update)
{
  yafvs_control_user_modify_request_t modify = {0};

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  modify_user_calls = 0;
  modify_user_result = MODIFY_USER_PASSWORD_REQUIRED;
  mock_operator_name = "operator";
  mock_target_name = "target";
  mock_target_auth_method = "ldap_connect";

  g_strlcpy (modify.target_uuid, "123e4567-e89b-12d3-a456-426614174001",
             sizeof (modify.target_uuid));
  g_strlcpy (modify.method, "file", sizeof (modify.method));
  modify.name = g_strdup ("target");
  modify.comment = g_strdup ("comment");

  assert_that (yafvs_control_modify_user (
                 "123e4567-e89b-12d3-a456-426614174000", &modify),
               is_equal_to (5));
  assert_that (modify_user_calls, is_equal_to (1));
  assert_that (received_user_method, is_equal_to_string ("file"));
  assert_that (received_name, is_null);

  yafvs_control_user_modify_request_clear (&modify);
  g_clear_pointer (&received_user_method, g_free);
  g_clear_pointer (&received_user_target_uuid, g_free);
  g_clear_pointer (&received_name, g_free);
  g_clear_pointer (&received_comment, g_free);
}

Ensure (yafvs_control, dispatches_user_management_results_without_secrets)
{
  const char *clone_request =
    "user-clone " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  const char *create_request =
    "user-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 ldap_connect VXNlcg== Qw== -\n";
  const char *bad_clone_secret =
    "user-clone badsecretbadsecretbadsecretbadsec "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  const char *modify_request =
    "user-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 ldap_connect dGFyZ2V0 Qw== -\n";
  const char *delete_request =
    "user-delete " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 -\n";
  const char *bad_secret =
    "user-create badsecretbadsecretbadsecretbadsec "
    "123e4567-e89b-12d3-a456-426614174000 ldap_connect VXNlcg== Qw== -\n";
  const char *invalid_create_method =
    "user-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 ldap VXNlcg== Qw== -\n";
  const char *invalid_modify_method =
    "user-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 ldap dGFyZ2V0 Qw== -\n";
  char response[YAFVS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  mock_operator_name = "operator";
  mock_target_name = "target";
  mock_target_auth_method = "ldap_connect";
  create_user_result = -2;
  clone_user_result = 2;
  modify_user_result = 8;
  delete_user_result = 9;
  assert_that (
    g_setenv (YAFVS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET, TRUE), is_true);

  response_len = dispatch_trash_empty_request (create_request, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("1 exists\n"));
  assert_that (strstr (response, TEST_CONTROL_SECRET), is_null);
  response_len = dispatch_trash_empty_request (modify_request, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("3 exists\n"));
  response_len = dispatch_trash_empty_request (delete_request, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("5 last_user\n"));
  response_len = dispatch_trash_empty_request (clone_request, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("2 not_found\n"));
  response_len = dispatch_trash_empty_request (invalid_create_method, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("4 invalid_method\n"));
  response_len = dispatch_trash_empty_request (invalid_modify_method, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("7 invalid_method\n"));
  response_len = dispatch_trash_empty_request (bad_secret, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  response_len = dispatch_trash_empty_request (bad_clone_secret, response);
  response[response_len] = '\0';
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  assert_that (strstr (response, "VXNlcg=="), is_null);
  g_unsetenv (YAFVS_CONTROL_SECRET_ENV);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, yafvs_control,
                         parses_strict_auth_settings_frames);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_auth_settings_frames);
  add_test_with_context (suite, yafvs_control,
                         maps_auth_settings_responses);
  add_test_with_context (
    suite, yafvs_control,
    runs_auth_settings_in_authorized_operator_session);
  add_test_with_context (suite, yafvs_control,
                         round_trips_empty_auth_settings_fields);
  add_test_with_context (
    suite, yafvs_control,
    rejects_unknown_auth_settings_operator_and_malformed_frame);
  add_test_with_context (suite, yafvs_control,
                         parses_strict_user_setting_modify_frames);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_user_setting_modify_frames);
  add_test_with_context (suite, yafvs_control,
                         maps_user_setting_modify_responses);
  add_test_with_context (suite, yafvs_control,
                         modifies_user_settings_in_operator_session);
  add_test_with_context (
    suite, yafvs_control,
    dispatches_user_setting_results_and_rejects_bad_frames);
  add_test_with_context (suite, yafvs_control,
                         parses_bounded_user_management_frames);
  add_test_with_context (
    suite, yafvs_control,
    rejects_malformed_or_unauthenticated_user_management_frames);
  add_test_with_context (suite, yafvs_control,
                         maps_authoritative_user_management_responses);
  add_test_with_context (
    suite, yafvs_control,
    clones_user_in_operator_session_and_reports_indeterminate_commit);
  add_test_with_context (suite, yafvs_control,
                         runs_native_user_management_in_operator_sessions);
  add_test_with_context (
    suite, yafvs_control,
    rejects_passwordless_file_transition_in_native_locked_update);
  add_test_with_context (
    suite, yafvs_control,
    reports_committed_user_create_when_uuid_lookup_fails);
  add_test_with_context (
    suite, yafvs_control,
    dispatches_user_management_results_without_secrets);

  add_test_with_context (suite, yafvs_control,
                         accepts_exact_authenticated_stop_request);
  add_test_with_context (suite, yafvs_control,
                         rejects_noncanonical_or_extra_requests);
  add_test_with_context (suite, yafvs_control,
                         rejects_missing_weak_or_incorrect_secrets);
  add_test_with_context (suite, yafvs_control,
                         maps_only_protocol_responses);
  add_test_with_context (suite, yafvs_control,
                         parses_canonical_task_clone_request);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_task_clone_requests);
  add_test_with_context (suite, yafvs_control,
                         clones_task_in_operator_session_and_audits);
  add_test_with_context (suite, yafvs_control, maps_task_clone_responses);
  add_test_with_context (suite, yafvs_control,
                         accepts_strict_bounded_trash_empty_request);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_trash_empty_requests);
  add_test_with_context (suite, yafvs_control,
                         maps_trash_empty_contract_responses);
  add_test_with_context (suite, yafvs_control,
                         dispatches_trash_count_mismatch);
  add_test_with_context (suite, yafvs_control,
                         audits_successful_trash_empty);
  add_test_with_context (suite, yafvs_control,
                         audits_trash_empty_failures);
  add_test_with_context (suite, yafvs_control,
                         does_not_audit_missing_trash_operator);
  add_test_with_context (suite, yafvs_control,
                         locks_before_count_and_skips_delete_on_mismatch);
  add_test_with_context (suite, yafvs_control,
                         accepts_canonical_schedule_create_request);
  add_test_with_context (suite, yafvs_control,
                         accepts_maximum_schedule_fields);
  add_test_with_context (suite, yafvs_control,
                         rejects_noncanonical_or_oversized_schedule_fields);
  add_test_with_context (suite, yafvs_control,
                         creates_schedule_in_operator_session);
  add_test_with_context (suite, yafvs_control,
                         maps_schedule_create_responses);
  add_test_with_context (suite, yafvs_control,
                         accepts_username_password_credential_create_request);
  add_test_with_context (suite, yafvs_control,
                         accepts_ssh_key_credential_create_request);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_credential_create_requests);
  add_test_with_context (suite, yafvs_control,
                         creates_credential_in_operator_session);
  add_test_with_context (suite, yafvs_control,
                         maps_credential_create_responses);
  add_test_with_context (suite, yafvs_control,
                         tracks_partial_request_length_and_clears_secrets);
  add_test_with_context (suite, yafvs_control,
                         rejects_nonexistent_credential_operator_before_create);
  add_test_with_context (suite, yafvs_control,
                         accepts_schedule_modify_presence_and_empty_tokens);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_or_unauthenticated_schedule_modify);
  add_test_with_context (suite, yafvs_control,
                         rejects_invalid_schedule_modify_field_bytes);
  add_test_with_context (suite, yafvs_control,
                         distinguishes_absent_and_empty_schedule_modify_calendar);
  add_test_with_context (suite, yafvs_control,
                         modifies_schedule_in_operator_session);
  add_test_with_context (suite, yafvs_control,
                         maps_schedule_modify_responses);
  add_test_with_context (suite, yafvs_control,
                         rejects_nonexistent_operator_before_session_setup);
  add_test_with_context (suite, yafvs_control,
                         parses_bounded_diagnostic_nvt_request);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_diagnostic_nvt_requests);
  add_test_with_context (suite, yafvs_control,
                         maps_diagnostic_nvt_responses);
  add_test_with_context (suite, yafvs_control,
                         runs_diagnostic_nvt_in_operator_session_and_audits);
  add_test_with_context (suite, yafvs_control,
                         dispatches_malformed_diagnostic_nvt_frame);
  add_test_with_context (suite, yafvs_control,
                         atomically_configures_diagnostic_nvt_and_cache);
  add_test_with_context (suite, yafvs_control,
                         retries_identical_diagnostic_state_idempotently);
  add_test_with_context (suite, yafvs_control,
                         deduplicates_requested_diagnostic_prerequisite);
  add_test_with_context (suite, yafvs_control,
                         rejects_unsafe_diagnostic_config_states);
  add_test_with_context (suite, yafvs_control,
                         reports_indeterminate_after_diagnostic_commit);
  add_test_with_context (suite, yafvs_control,
                         parses_atomic_tag_modify_and_empty_set);
  add_test_with_context (suite, yafvs_control,
                         rejects_unsafe_tag_resource_type_mutation);
  add_test_with_context (
    suite, yafvs_control,
    runs_tag_modify_in_operator_session_and_audits);
  add_test_with_context (suite, yafvs_control,
                         maps_tag_modify_control_responses);
  add_test_with_context (suite, yafvs_control,
                         parses_canonical_bounded_alert_email_request);
  add_test_with_context (suite, yafvs_control,
                         enforces_alert_email_notice_mode_semantics);
  add_test_with_context (suite, yafvs_control,
                         enforces_alert_email_canonicalization_and_bounds);
  add_test_with_context (suite, yafvs_control,
                         maps_alert_email_arrays_session_and_success_audit);
  add_test_with_context (suite, yafvs_control,
                         maps_selected_attach_message_and_failure_audit);
  add_test_with_context (suite, yafvs_control,
                         maps_simple_notice_without_report_selectors);
  add_test_with_context (suite, yafvs_control,
                         omits_empty_optional_report_method_data);
  add_test_with_context (suite, yafvs_control,
                         rejects_missing_alert_operator_before_authority);
  add_test_with_context (suite, yafvs_control,
                         maps_atomic_unavailable_alert_report_format);
  add_test_with_context (
    suite, yafvs_control,
    reports_postcommit_alert_uuid_failure_without_failed_audit);
  add_test_with_context (suite, yafvs_control,
                         maps_every_alert_create_response);
  add_test_with_context (suite, yafvs_control,
                         parses_syslog_and_required_snmp_alert_requests);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_or_empty_snmp_alert_payloads);
  add_test_with_context (suite, yafvs_control,
                         maps_fixed_syslog_and_snmp_alert_creation);
  add_test_with_context (suite, yafvs_control,
                         rejects_missing_snmp_owner_and_maps_alert_errors);
  add_test_with_context (suite, yafvs_control,
                         returns_malformed_for_truncated_alert_frame);
  add_test_with_context (suite, yafvs_control,
                         parses_canonical_bounded_alert_scp_requests);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_or_oversized_alert_scp_requests);
  add_test_with_context (suite, yafvs_control,
                         maps_alert_scp_arrays_session_and_success_audit);
  add_test_with_context (suite, yafvs_control,
                         dispatches_alert_scp_errors_without_secrets);
  add_test_with_context (suite, yafvs_control,
                         parses_strict_start_task_alert_frame);
  add_test_with_context (suite, yafvs_control,
                         rejects_bad_uuid_and_malformed_start_task_alerts);
  add_test_with_context (suite, yafvs_control,
                         maps_start_task_alert_creation_and_commit_status);
  add_test_with_context (suite, yafvs_control,
                         classifies_start_task_frames_without_logging_them);
  add_test_with_context (suite, yafvs_control,
                         locks_start_task_reference_and_commits_atomically);
  add_test_with_context (suite, yafvs_control,
                         rejects_unauthorized_missing_and_duplicate_start_task);
  add_test_with_context (suite, yafvs_control,
                         maps_start_task_alert_responses);
  add_test_with_context (suite, yafvs_control,
                         dispatches_malformed_alert_scp_without_payload);
  add_test_with_context (suite, yafvs_control,
                         parses_canonical_bounded_alert_smb_requests);
  add_test_with_context (suite, yafvs_control,
                         rejects_malformed_or_oversized_alert_smb_requests);
  add_test_with_context (suite, yafvs_control,
                         maps_alert_smb_arrays_session_and_success_audit);
  add_test_with_context (suite, yafvs_control,
                         audits_alert_smb_failure_and_cleans_session);
  add_test_with_context (suite, yafvs_control,
                         preserves_alert_smb_postcommit_indeterminate_audit);
  add_test_with_context (suite, yafvs_control,
                         rejects_missing_alert_smb_operator_before_authority);
  add_test_with_context (suite, yafvs_control,
                         locks_alert_smb_references_and_commits_atomically);
  add_test_with_context (suite, yafvs_control,
                         rejects_alert_smb_reference_failures_atomically);
  add_test_with_context (suite, yafvs_control,
                         preserves_authoritative_alert_smb_validation);
  add_test_with_context (suite, yafvs_control,
                         dispatches_malformed_alert_smb_without_payload);
  add_test_with_context (suite, yafvs_control,
                         parses_strict_authenticated_alert_test_frames);
  add_test_with_context (
    suite, yafvs_control,
    maps_alert_test_responses_without_malformed_overlap);
  add_test_with_context (
    suite, yafvs_control,
    parses_strict_alert_report_delivery_frames);
  add_test_with_context (suite, yafvs_control,
                         maps_alert_report_delivery_responses);
  add_test_with_context (
    suite, yafvs_control,
    delivers_report_in_operator_session_and_audits);
  add_test_with_context (suite, yafvs_control,
                         tests_alert_in_operator_session_audits_and_scrubs);
  add_test_with_context (
    suite, yafvs_control,
    dispatches_alert_test_without_sensitive_response_data);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
