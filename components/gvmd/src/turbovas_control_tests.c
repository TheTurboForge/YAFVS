/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define g_log_structured turbovas_control_test_log_structured
#include "turbovas_control.c"
#undef g_log_structured

#include <cgreen/cgreen.h>
#include <stdarg.h>
#include <string.h>

#define TEST_CONTROL_SECRET "0123456789abcdef0123456789abcdef"

Describe (turbovas_control);
BeforeEach (turbovas_control) {}
AfterEach (turbovas_control) {}

static int cleanup_calls;
static int create_alert_calls;
static int create_alert_result;
static int create_schedule_calls;
static int create_credential_calls;
static int create_credential_result;
static int create_schedule_result;
static int modify_schedule_calls;
static int modify_schedule_result;
static int reinit_calls;
static int session_init_calls;
static int stop_task_calls;
static int trash_empty_calls;
static int trash_empty_result;
static gint64 trash_empty_actual;
static gint64 trash_empty_expected;
static int trash_empty_audit_fail_calls;
static int trash_empty_audit_success_calls;
static int trash_empty_structured_audit_calls;
static int audit_fail_calls;
static int audit_success_calls;
static const char *mock_operator_name;
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
static gchar *received_report_config;
static gchar *received_report_format;
static gchar *received_atomic_report_config;
static gchar *received_atomic_report_format;
static gchar *received_subject;
static gchar *received_to_address;
static gchar *received_audit_uuid;
static gchar *received_credential_type;
static gchar *received_comment;
static gchar *received_icalendar;
static gchar *received_key_private;
static gchar *received_login;
static gchar *received_name;
static gchar *received_secret;
static gchar *received_schedule_uuid;
static gchar *received_timezone;
static gchar *trash_empty_audit_actual_total;
static gchar *trash_empty_audit_expected_total;
static gchar *trash_empty_audit_message;
static gchar *trash_empty_audit_operator_uuid;
static gchar *trash_empty_audit_outcome;

static void
assert_trash_empty_audit_operator_session (void)
{
  assert_that (current_credentials.uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (current_credentials.username, is_equal_to_string ("operator"));
  assert_that (cleanup_calls, is_equal_to (0));
}

void
turbovas_control_test_log_structured (const gchar *log_domain,
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
  assert_that (next_field, is_equal_to_string ("TURBOVAS_AUDIT_ACTION"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%s"));
  assert_that (va_arg (args, const gchar *), is_equal_to_string ("trash-empty"));
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("TURBOVAS_OPERATOR_UUID"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%s"));
  operator_uuid = va_arg (args, const gchar *);
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("TURBOVAS_OUTCOME"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%s"));
  outcome = va_arg (args, const gchar *);
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("TURBOVAS_EXPECTED_TOTAL"));
  format = va_arg (args, const gchar *);
  assert_that (format, is_equal_to_string ("%" G_GINT64_FORMAT));
  expected_total = va_arg (args, gint64);
  next_field = va_arg (args, const gchar *);
  assert_that (next_field, is_equal_to_string ("TURBOVAS_ACTUAL_TOTAL"));
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
  (void) uuid;
  return mock_operator_name ? g_strdup (mock_operator_name) : NULL;
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
   const char *report_config_id, alert_t *alert)
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
  g_free (received_report_config);
  g_free (received_atomic_report_format);
  g_free (received_atomic_report_config);
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
  received_report_config =
    g_strdup (test_alert_data_value (method_data, "notice_report_config"));
  if (received_report_config == NULL)
    received_report_config =
      g_strdup (test_alert_data_value (method_data, "notice_attach_config"));
  received_message = g_strdup (test_alert_data_value (method_data, "message"));
  received_atomic_report_format = g_strdup (report_format_id);
  received_atomic_report_config = g_strdup (report_config_id);
  assert_that (
    recipient_credential_id,
    is_equal_to_string (received_recipient_credential
                          ? received_recipient_credential : ""));
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
  if (strcmp (resource, "alert") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Alert"));
      assert_that (action, is_equal_to_string ("created"));
      audit_success_calls++;
      g_free (received_audit_uuid);
      received_audit_uuid = g_strdup (uuid);
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
  if (strcmp (resource, "alert") == 0)
    {
      assert_that (resource_name, is_equal_to_string ("Alert"));
      assert_that (uuid, is_null);
      assert_that (action, is_equal_to_string ("created"));
      audit_fail_calls++;
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
__wrap_create_credential
  (const char *name, const char *comment, const char *login,
   const char *given_password, const char *key_private, const char *key_public,
   const char *certificate, const char *community, const char *auth_algorithm,
   const char *privacy_password, const char *privacy_algorithm,
   const char *kdc, array_t *kdcs, const char *realm,
   const char *credential_store_id, const char *vault_id,
   const char *host_identifier, const char *privacy_host_identifier,
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
  (void) credential_store_id;
  (void) vault_id;
  (void) host_identifier;
  (void) privacy_host_identifier;
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
                                        long long int *actual_total)
{
  trash_empty_calls++;
  trash_empty_expected = (gint64) expected_total;
  *actual_total = (long long int) trash_empty_actual;
  return trash_empty_result;
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
  trash_empty_record_db_event (TRASH_EMPTY_DB_BEGIN);
}

int
__wrap_sql_int64 (long long int *value, const char *statement, ...)
{
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

void
__wrap_sql (const char *statement, ...)
{
  if (strcmp (statement, "LOCK TABLE users IN EXCLUSIVE MODE;") == 0)
    trash_empty_record_db_event (TRASH_EMPTY_DB_USERS_LOCK);
  else if (g_str_has_prefix (statement, "DELETE FROM")
           || g_str_has_prefix (statement, "UPDATE "))
    trash_empty_record_db_event (TRASH_EMPTY_DB_DELETE);
}

void
__wrap_sql_rollback (void)
{
  trash_empty_record_db_event (TRASH_EMPTY_DB_ROLLBACK);
}

void
__wrap_sql_commit (void)
{
  trash_empty_record_db_event (TRASH_EMPTY_DB_COMMIT);
}

int
__wrap_acl_user_may (const char *operation)
{
  assert_that (operation, is_equal_to_string ("empty_trashcan"));
  trash_empty_record_db_event (TRASH_EMPTY_DB_ACL);
  return trash_empty_db_acl;
}

int
__real_manage_empty_trashcan_confirmed (long long int, long long int *);

static ssize_t
dispatch_trash_empty_request (const char *request,
                              char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  int sockets[2];
  ssize_t response_len;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (write (sockets[0], request, strlen (request)),
               is_equal_to ((ssize_t) strlen (request)));
  assert_that (shutdown (sockets[0], SHUT_WR), is_equal_to (0));
  turbovas_control_serve_client (sockets[1]);
  response_len = read (sockets[0], response,
                       TURBOVAS_CONTROL_MAX_RESPONSE_BYTES - 1);
  close (sockets[0]);
  close (sockets[1]);

  return response_len;
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

Ensure (turbovas_control, accepts_strict_bounded_trash_empty_request)
{
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 9223372036854775807\n";
  char operator_uuid[37];
  gint64 expected_total = -1;

  assert_that (turbovas_control_parse_trash_empty_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid,
                 &expected_total),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (expected_total, is_equal_to (G_MAXINT64));
}

Ensure (turbovas_control, rejects_malformed_trash_empty_requests)
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
  gint64 expected_total;
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (invalid); index++)
    assert_that (turbovas_control_parse_trash_empty_request (
                   invalid[index], strlen (invalid[index]),
                   TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                   operator_uuid, &expected_total),
                 is_false);
}

Ensure (turbovas_control, maps_trash_empty_contract_responses)
{
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (turbovas_control_trash_empty_response (0, 7, response),
               is_equal_to_string ("0 emptied 7\n"));
  assert_that (turbovas_control_trash_empty_response (1, 8, response),
               is_equal_to_string ("1 expected-total-mismatch 8\n"));
  assert_that (turbovas_control_trash_empty_response (2, 0, response),
               is_equal_to_string ("2 forbidden\n"));
  assert_that (turbovas_control_trash_empty_response (3, 0, response),
               is_equal_to_string ("3 operator-not-found\n"));
  assert_that (turbovas_control_trash_empty_response (-1, 0, response),
               is_equal_to_string ("-1 error\n"));
}

Ensure (turbovas_control, dispatches_trash_count_mismatch)
{
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 4\n";
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES] = {0};
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

  assert_that (g_setenv (TURBOVAS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
                         TRUE),
               is_true);
  response_len = dispatch_trash_empty_request (request, response);

  assert_that (response_len,
               is_equal_to (
                 (ssize_t) strlen ("1 expected-total-mismatch 5\n")));
  assert_that (response,
               is_equal_to_string ("1 expected-total-mismatch 5\n"));
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
                                       "expected-total-mismatch", "4", "5");

  g_unsetenv (TURBOVAS_CONTROL_SECRET_ENV);
  reset_trash_empty_audit ();
}

Ensure (turbovas_control, audits_successful_trash_empty)
{
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 5\n";
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES] = {0};
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

  assert_that (g_setenv (TURBOVAS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
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

  g_unsetenv (TURBOVAS_CONTROL_SECRET_ENV);
  reset_trash_empty_audit ();
}

Ensure (turbovas_control, audits_trash_empty_failures)
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
    "123e4567-e89b-12d3-a456-426614174000 5\n";
  size_t index;

  assert_that (g_setenv (TURBOVAS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
                         TRUE),
               is_true);

  for (index = 0; index < G_N_ELEMENTS (cases); index++)
    {
      char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES] = {0};
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

  g_unsetenv (TURBOVAS_CONTROL_SECRET_ENV);
}

Ensure (turbovas_control, does_not_audit_missing_trash_operator)
{
  const char *request =
    "trash-empty " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 5\n";
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  ssize_t response_len;

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  trash_empty_calls = 0;
  mock_operator_name = NULL;
  reset_trash_empty_audit ();

  assert_that (g_setenv (TURBOVAS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
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

  g_unsetenv (TURBOVAS_CONTROL_SECRET_ENV);
  reset_trash_empty_audit ();
}

Ensure (turbovas_control, locks_before_count_and_skips_delete_on_mismatch)
{
  static const char *base_tables[] = {
    "alerts_trash", "configs_trash", "credentials_trash", "filters_trash",
    "overrides_trash", "port_lists_trash", "report_configs_trash",
    "report_formats_trash", "scanners_trash", "schedules_trash",
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

  assert_that (__real_manage_empty_trashcan_confirmed (5, &actual_total),
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

Ensure (turbovas_control, accepts_canonical_schedule_create_request)
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
  turbovas_control_schedule_create_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (schedule.name, is_equal_to_string ("Nightly"));
  assert_that (schedule.comment, is_equal_to_string (""));
  assert_that (schedule.timezone, is_equal_to_string (timezone));
  assert_that (schedule.icalendar, is_equal_to_string (calendar));

  turbovas_control_schedule_create_request_clear (&schedule);
  g_free (request);
  g_free (timezone_b64);
  g_free (calendar_b64);
}

Ensure (turbovas_control, accepts_maximum_schedule_fields)
{
  gchar *name = g_strnfill (TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES, 'n');
  gchar *icalendar = g_strnfill (
    TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES, 'i');
  gchar *name_b64 = g_base64_encode ((const guchar *) name, strlen (name));
  gchar *icalendar_b64 = g_base64_encode ((const guchar *) icalendar,
                                           strlen (icalendar));
  gchar *request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "%s   %s\n", name_b64, icalendar_b64);
  char operator_uuid[37];
  turbovas_control_schedule_create_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_true);
  assert_that (strlen (schedule.name),
               is_equal_to (TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES));
  assert_that (strlen (schedule.icalendar),
               is_equal_to (TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES));

  turbovas_control_schedule_create_request_clear (&schedule);
  g_free (request);
  g_free (icalendar_b64);
  g_free (name_b64);
  g_free (icalendar);
  g_free (name);
}

Ensure (turbovas_control, rejects_noncanonical_or_oversized_schedule_fields)
{
  gchar *oversized_name = g_strnfill (
    TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES + 1, 'a');
  gchar *oversized_icalendar = g_strnfill (
    TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES + 1, 'i');
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
    TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1, 'x');
  char operator_uuid[37];
  turbovas_control_schedule_create_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_create_request (
                 invalid_request, strlen (invalid_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_create_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_create_request (
                 oversized_icalendar_request,
                 strlen (oversized_icalendar_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_create_request (
                 overlong_request, TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1,
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

Ensure (turbovas_control, creates_schedule_in_operator_session)
{
  const turbovas_control_schedule_create_request_t request = {
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

  assert_that (turbovas_control_create_schedule (
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
                                 const char *report_config_uuid,
                                 const char *message)
{
  gchar *fields[10];
  gchar *request;
  size_t index;

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
  fields[8] = g_base64_encode ((const guchar *) report_config_uuid,
                               strlen (report_config_uuid));
  fields[9] = g_base64_encode ((const guchar *) message, strlen (message));
  request = g_strdup_printf (
    "alert-email-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 %s %s %s %s %s %s %s %s %s %s %s "
    "%s\n",
    active, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
    notice, fields[6], fields[7], fields[8], fields[9]);
  for (index = 0; index < G_N_ELEMENTS (fields); index++)
    g_free (fields[index]);
  return request;
}

Ensure (turbovas_control, parses_canonical_bounded_alert_email_request)
{
  static const char *statuses[] = {
    "Delete Requested", "Ultimate Delete Requested",
    "Ultimate Delete Waiting", "Delete Waiting", "Done", "New", "Requested",
    "Running", "Queued", "Stop Requested", "Stop Waiting", "Stopped",
    "Processing", "Interrupted",
  };
  const char *recipient = "123e4567-e89b-12d3-a456-426614174010";
  const char *format = "123e4567-e89b-12d3-a456-426614174011";
  const char *config = "123e4567-e89b-12d3-a456-426614174012";
  char operator_uuid[37];
  size_t index;

  for (index = 0; index < G_N_ELEMENTS (statuses); index++)
    {
      gchar *request = test_alert_email_create_request (
        "1", "Email alert", "comment", statuses[index], "ops@example.com",
        "sender@example.com", "subject", "0", recipient, format, config,
        "Line one\nLine two");
      turbovas_control_alert_email_create_request_t alert = {0};

      assert_that (turbovas_control_parse_alert_email_create_request (
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
      assert_that (alert.report_config_uuid, is_equal_to_string (config));
      assert_that (alert.message,
                   is_equal_to_string ("Line one\nLine two"));
      turbovas_control_alert_email_create_request_clear (&alert);
      g_free (request);
    }
}

Ensure (turbovas_control, enforces_alert_email_notice_mode_semantics)
{
  const char *format = "123e4567-e89b-12d3-a456-426614174011";
  const char *report_notices[] = {"0", "2"};
  gchar *request;
  gchar *invalid[5];
  char operator_uuid[37];
  size_t index;
  turbovas_control_alert_email_create_request_t alert = {0};

  request = test_alert_email_create_request (
    "1", "Simple", "", "Running", "ops@example.com", "", "subject", "1",
    "", "", "", "simple message");
  assert_that (turbovas_control_parse_alert_email_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
               is_true);
  assert_that (alert.message, is_equal_to_string ("simple message"));
  turbovas_control_alert_email_create_request_clear (&alert);
  g_free (request);

  for (index = 0; index < G_N_ELEMENTS (report_notices); index++)
    {
      request = test_alert_email_create_request (
        "1", "Report", "", "Running", "ops@example.com", "", "subject",
        report_notices[index], "", format, "", "");
      assert_that (turbovas_control_parse_alert_email_create_request (
                     request, strlen (request), TEST_CONTROL_SECRET,
                     strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
                   is_true);
      turbovas_control_alert_email_create_request_clear (&alert);
      g_free (request);
    }

  invalid[0] = test_alert_email_create_request (
    "1", "Missing subject", "", "Running", "ops@example.com", "", "", "0",
    "", format, "", "");
  invalid[1] = test_alert_email_create_request (
    "1", "Simple format", "", "Running", "ops@example.com", "", "subject",
    "1", "", format, "", "");
  invalid[2] = test_alert_email_create_request (
    "1", "Simple config", "", "Running", "ops@example.com", "", "subject",
    "1", "", "", "123e4567-e89b-12d3-a456-426614174012", "");
  invalid[3] = test_alert_email_create_request (
    "1", "Include no format", "", "Running", "ops@example.com", "",
    "subject", "0", "", "", "", "");
  invalid[4] = test_alert_email_create_request (
    "1", "Attach no format", "", "Running", "ops@example.com", "",
    "subject", "2", "", "", "", "");
  for (index = 0; index < G_N_ELEMENTS (invalid); index++)
    {
      assert_that (turbovas_control_parse_alert_email_create_request (
                     invalid[index], strlen (invalid[index]),
                     TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                     operator_uuid, &alert),
                   is_false);
      g_free (invalid[index]);
    }
}

Ensure (turbovas_control, returns_malformed_for_truncated_alert_frame)
{
  const char *partial = "alert-email-create " TEST_CONTROL_SECRET " partial";
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES] = {0};
  int sockets[2];
  ssize_t response_len;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (g_setenv (TURBOVAS_CONTROL_SECRET_ENV, TEST_CONTROL_SECRET,
                         TRUE),
               is_true);
  assert_that (write (sockets[0], partial, strlen (partial)),
               is_equal_to ((ssize_t) strlen (partial)));
  assert_that (shutdown (sockets[0], SHUT_WR), is_equal_to (0));
  turbovas_control_serve_client (sockets[1]);
  response_len = read (sockets[0], response, sizeof (response) - 1);
  assert_that (response_len, is_equal_to ((ssize_t) strlen ("-2 malformed\n")));
  assert_that (response, is_equal_to_string ("-2 malformed\n"));
  close (sockets[0]);
  close (sockets[1]);
  g_unsetenv (TURBOVAS_CONTROL_SECRET_ENV);
}

Ensure (turbovas_control, enforces_alert_email_canonicalization_and_bounds)
{
  gchar *max_name = g_strnfill (TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES, 'n');
  gchar *max_comment =
    g_strnfill (TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES, 'c');
  gchar *max_to = g_strnfill (TURBOVAS_CONTROL_ALERT_ADDRESS_MAX_BYTES, 't');
  gchar *max_from =
    g_strnfill (TURBOVAS_CONTROL_ALERT_ADDRESS_MAX_BYTES, 'f');
  gchar *max_subject =
    g_strnfill (TURBOVAS_CONTROL_ALERT_SUBJECT_MAX_BYTES, 's');
  gchar *max_message =
    g_strnfill (TURBOVAS_CONTROL_ALERT_MESSAGE_MAX_BYTES, 'm');
  gchar *oversized_name =
    g_strnfill (TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES + 1, 'n');
  gchar *oversized_subject =
    g_strnfill (TURBOVAS_CONTROL_ALERT_SUBJECT_MAX_BYTES + 1, 's');
  gchar *oversized_message =
    g_strnfill (TURBOVAS_CONTROL_ALERT_MESSAGE_MAX_BYTES + 1, 'm');
  gchar *requests[6];
  char full_frame[TURBOVAS_CONTROL_MAX_REQUEST_BYTES];
  char operator_uuid[37];
  size_t index;
  turbovas_control_alert_email_create_request_t alert = {0};

  requests[0] = test_alert_email_create_request (
    "0", max_name, max_comment, "Running", max_to, max_from, max_subject, "2",
    "", "123e4567-e89b-12d3-a456-426614174011",
    "123e4567-e89b-12d3-a456-426614174012", max_message);
  assert_that (strlen (requests[0]),
               is_less_than (TURBOVAS_CONTROL_MAX_REQUEST_BYTES));
  assert_that (turbovas_control_parse_alert_email_create_request (
                 requests[0], strlen (requests[0]), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &alert),
               is_true);
  turbovas_control_alert_email_create_request_clear (&alert);

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
    assert_that (turbovas_control_parse_alert_email_create_request (
                   requests[index], strlen (requests[index]),
                   TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                   operator_uuid, &alert),
                 is_false);
  memset (full_frame, 'x', sizeof (full_frame));
  memcpy (full_frame, TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND,
          TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH);
  full_frame[sizeof (full_frame) - 1] = '\n';
  assert_that (turbovas_control_parse_alert_email_create_request (
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

Ensure (turbovas_control, maps_alert_email_arrays_session_and_success_audit)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Email alert",
    .comment = "comment",
    .status = "Running",
    .to_address = "ops@example.com",
    .from_address = "sender@example.com",
    .subject = "subject",
    .recipient_credential_uuid = "123e4567-e89b-12d3-a456-426614174010",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .report_config_uuid = "123e4567-e89b-12d3-a456-426614174012",
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

  assert_that (turbovas_control_create_alert_email (
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
  assert_that (received_report_config,
               is_equal_to_string (request.report_config_uuid));
  assert_that (received_atomic_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_atomic_report_config,
               is_equal_to_string (request.report_config_uuid));
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

Ensure (turbovas_control, maps_selected_attach_message_and_failure_audit)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Attach alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .report_config_uuid = "123e4567-e89b-12d3-a456-426614174012",
    .message = "selected attach message", .active = FALSE, .notice = 2,
  };
  char created_uuid[37];

  create_alert_calls = 0;
  create_alert_result = 2;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";

  assert_that (turbovas_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (2));
  assert_that (received_active, is_equal_to_string ("0"));
  assert_that (received_notice, is_equal_to_string ("2"));
  assert_that (received_from_address, is_null);
  assert_that (received_recipient_credential, is_null);
  assert_that (received_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_report_config,
               is_equal_to_string (request.report_config_uuid));
  assert_that (received_message, is_equal_to_string (request.message));
  assert_that (audit_success_calls, is_equal_to (0));
  assert_that (audit_fail_calls, is_equal_to (1));
}

Ensure (turbovas_control, maps_simple_notice_without_report_selectors)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Simple alert", .comment = "", .status = "Stopped",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "", .report_format_uuid = "",
    .report_config_uuid = "", .message = "simple message",
    .active = TRUE, .notice = 1,
  };
  char created_uuid[37];

  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";
  assert_that (turbovas_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (received_notice, is_equal_to_string ("1"));
  assert_that (received_report_format, is_null);
  assert_that (received_report_config, is_null);
  assert_that (received_atomic_report_format, is_equal_to_string (""));
  assert_that (received_atomic_report_config, is_equal_to_string (""));
  assert_that (received_from_address, is_null);
  assert_that (received_recipient_credential, is_null);
  assert_that (received_message, is_equal_to_string (request.message));
  assert_that (audit_success_calls, is_equal_to (1));
  assert_that (audit_fail_calls, is_equal_to (0));
}

Ensure (turbovas_control, omits_empty_optional_report_method_data)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Include alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .report_config_uuid = "", .message = "", .active = TRUE, .notice = 0,
  };
  char created_uuid[37];

  create_alert_result = 0;
  audit_fail_calls = 0;
  audit_success_calls = 0;
  mock_operator_name = "operator";
  assert_that (turbovas_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (received_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_report_config, is_null);
  assert_that (received_from_address, is_null);
  assert_that (received_recipient_credential, is_null);
  assert_that (received_message, is_null);
}

Ensure (turbovas_control, rejects_missing_alert_operator_before_authority)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Email alert", .comment = "", .status = "Running",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "", .report_format_uuid = "",
    .report_config_uuid = "", .message = "", .active = TRUE, .notice = 1,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  audit_fail_calls = 0;
  mock_operator_name = NULL;
  assert_that (turbovas_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (99));
  assert_that (create_alert_calls, is_equal_to (0));
  assert_that (audit_fail_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
}

Ensure (turbovas_control, maps_atomic_unavailable_alert_report_format)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Include alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .report_config_uuid = "", .message = "delivery payload",
    .active = TRUE, .notice = 0,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  audit_fail_calls = 0;
  create_alert_result = 90;
  mock_operator_name = "operator";

  assert_that (turbovas_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (90));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (received_atomic_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_atomic_report_config, is_equal_to_string (""));
  assert_that (audit_fail_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (turbovas_control, maps_atomic_unavailable_alert_report_config)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Attach alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .report_config_uuid = "123e4567-e89b-12d3-a456-426614174012",
    .message = "delivery payload", .active = TRUE, .notice = 2,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  audit_fail_calls = 0;
  create_alert_result = 91;
  mock_operator_name = "operator";

  assert_that (turbovas_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (91));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (received_atomic_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_atomic_report_config,
               is_equal_to_string (request.report_config_uuid));
  assert_that (audit_fail_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (turbovas_control, maps_atomic_alert_report_config_mismatch)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Include alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "",
    .report_format_uuid = "123e4567-e89b-12d3-a456-426614174011",
    .report_config_uuid = "123e4567-e89b-12d3-a456-426614174012",
    .message = "delivery payload", .active = TRUE, .notice = 0,
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_alert_calls = 0;
  audit_fail_calls = 0;
  create_alert_result = 92;
  mock_operator_name = "operator";

  assert_that (turbovas_control_create_alert_email (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (92));
  assert_that (create_alert_calls, is_equal_to (1));
  assert_that (received_atomic_report_format,
               is_equal_to_string (request.report_format_uuid));
  assert_that (received_atomic_report_config,
               is_equal_to_string (request.report_config_uuid));
  assert_that (audit_fail_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (turbovas_control, reports_postcommit_alert_uuid_failure_without_failed_audit)
{
  const turbovas_control_alert_email_create_request_t request = {
    .name = "Simple alert", .comment = "", .status = "Done",
    .to_address = "ops@example.com", .from_address = "", .subject = "subject",
    .recipient_credential_uuid = "", .report_format_uuid = "",
    .report_config_uuid = "", .message = "delivery payload",
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

  assert_that (turbovas_control_create_alert_email (
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

Ensure (turbovas_control, maps_every_alert_create_response)
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
    {9, "9 condition_filter_not_found\n"}, {12, "12 invalid_send_host\n"},
    {13, "13 invalid_send_port\n"}, {14, "14 send_format_not_found\n"},
    {15, "15 invalid_scp_host\n"}, {16, "16 invalid_scp_port\n"},
    {17, "17 scp_format_not_found\n"},
    {18, "18 invalid_scp_credential\n"}, {19, "19 invalid_scp_path\n"},
    {20, "20 method_event_mismatch\n"},
    {21, "21 condition_event_mismatch\n"},
    {31, "31 invalid_event_name\n"}, {32, "32 invalid_event_data\n"},
    {40, "40 invalid_smb_credential\n"}, {41, "41 invalid_smb_share\n"},
    {42, "42 invalid_smb_path\n"}, {43, "43 dotted_smb_path\n"},
    {50, "50 invalid_tp_credential\n"}, {51, "51 invalid_tp_host\n"},
    {52, "52 invalid_tp_certificate\n"}, {53, "53 invalid_tp_tls\n"},
    {60, "60 recipient_credential_not_found\n"},
    {61, "61 invalid_recipient_credential\n"},
    {70, "70 vfire_credential_not_found\n"},
    {71, "71 invalid_vfire_credential\n"},
    {80, "80 sourcefire_credential_not_found\n"},
    {81, "81 invalid_sourcefire_credential\n"},
    {90, "90 report_format_not_found\n"},
    {91, "91 report_config_not_found\n"},
    {92, "92 report_config_mismatch\n"}, {99, "99 forbidden\n"},
    {-3, "-3 committed_indeterminate\n"}, {-2, "-2 malformed\n"},
    {-1, "-1 internal\n"},
  };
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];
  size_t index;

  assert_that (turbovas_control_alert_email_create_response (
                 0, "123e4567-e89b-12d3-a456-426614174004", response),
               is_equal_to_string
                 ("0 created 123e4567-e89b-12d3-a456-426614174004\n"));
  assert_that (turbovas_control_alert_email_create_response (
                 0, NULL, response),
               is_equal_to_string ("-1 internal\n"));
  for (index = 0; index < G_N_ELEMENTS (cases); index++)
    {
      assert_that (strlen (cases[index].response),
                   is_less_than (TURBOVAS_CONTROL_MAX_RESPONSE_BYTES));
      assert_that (turbovas_control_alert_email_create_response (
                     cases[index].result, NULL, response),
                   is_equal_to_string (cases[index].response));
    }
}

Ensure (turbovas_control, maps_schedule_create_responses)
{
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (turbovas_control_schedule_create_response (
                 0, "123e4567-e89b-12d3-a456-426614174002", response),
               is_equal_to_string ("0 created 123e4567-e89b-12d3-a456-426614174002\n"));
  assert_that (turbovas_control_schedule_create_response (1, NULL, response),
               is_equal_to_string ("1 exists\n"));
  assert_that (turbovas_control_schedule_create_response (3, NULL, response),
               is_equal_to_string ("3 invalid_ical\n"));
  assert_that (turbovas_control_schedule_create_response (4, NULL, response),
               is_equal_to_string ("4 invalid_timezone\n"));
  assert_that (turbovas_control_schedule_create_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (turbovas_control_schedule_create_response (-1, NULL, response),
               is_equal_to_string ("-1 internal\n"));
}

Ensure (turbovas_control, accepts_username_password_credential_create_request)
{
  const char *request =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 up "
    "Q1NWIG9wZXJhdG9y QnVsayBpbXBvcnQ= cm9iZXJ0 c2VjcmV0IA== \n";
  char operator_uuid[37];
  turbovas_control_credential_create_request_t credential = {0};

  assert_that (turbovas_control_parse_credential_create_request (
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

  turbovas_control_credential_create_request_clear (&credential);
}

Ensure (turbovas_control, accepts_ssh_key_credential_create_request)
{
  const char *request =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 usk "
    "U1NIIG9wZXJhdG9y  cm9iZXJ0  "
    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCg==\n";
  char operator_uuid[37];
  turbovas_control_credential_create_request_t credential = {0};

  assert_that (turbovas_control_parse_credential_create_request (
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

  turbovas_control_credential_create_request_clear (&credential);
}

Ensure (turbovas_control, rejects_malformed_credential_create_requests)
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
  turbovas_control_credential_create_request_t credential = {0};

  assert_that (turbovas_control_parse_credential_create_request (
                 bad_type, strlen (bad_type), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_false);
  assert_that (turbovas_control_parse_credential_create_request (
                 missing_password, strlen (missing_password),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &credential),
               is_false);
  assert_that (turbovas_control_parse_credential_create_request (
                 up_with_key, strlen (up_with_key), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_false);
  assert_that (turbovas_control_parse_credential_create_request (
                 ssh_without_key, strlen (ssh_without_key),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &credential),
               is_false);
}

Ensure (turbovas_control, creates_credential_in_operator_session)
{
  const turbovas_control_credential_create_request_t request = {
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

  assert_that (turbovas_control_create_credential (
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

Ensure (turbovas_control, maps_credential_create_responses)
{
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (turbovas_control_credential_create_response (
                 0, "123e4567-e89b-12d3-a456-426614174003", response),
               is_equal_to_string
                 ("0 created 123e4567-e89b-12d3-a456-426614174003\n"));
  assert_that (turbovas_control_credential_create_response (1, NULL, response),
               is_equal_to_string ("1 exists\n"));
  assert_that (turbovas_control_credential_create_response (2, NULL, response),
               is_equal_to_string ("2 invalid_login\n"));
  assert_that (turbovas_control_credential_create_response (3, NULL, response),
               is_equal_to_string ("3 invalid_key\n"));
  assert_that (turbovas_control_credential_create_response (5, NULL, response),
               is_equal_to_string ("5 login_required\n"));
  assert_that (turbovas_control_credential_create_response (6, NULL, response),
               is_equal_to_string ("6 password_required\n"));
  assert_that (turbovas_control_credential_create_response (7, NULL, response),
               is_equal_to_string ("7 key_required\n"));
  assert_that (turbovas_control_credential_create_response (-2, NULL, response),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (turbovas_control_credential_create_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
}

Ensure (turbovas_control, tracks_partial_request_length_and_clears_secrets)
{
  const char *partial = "credential-create partial-secret cGFzc3dvcmQ=";
  char request[TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1] = {0};
  gchar *sensitive = g_strdup ("secret-copy");
  size_t request_len = 999;
  int sockets[2];
  size_t i;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (write (sockets[0], partial, strlen (partial)),
               is_equal_to ((ssize_t) strlen (partial)));
  close (sockets[0]);
  assert_that (turbovas_control_read_request (sockets[1], request,
                                               &request_len),
               is_false);
  close (sockets[1]);
  assert_that (request_len, is_equal_to (strlen (partial)));
  assert_that (memcmp (request, partial, request_len), is_equal_to (0));

  turbovas_control_secure_clear (request, request_len);
  for (i = 0; i < request_len; i++)
    assert_that (request[i], is_equal_to (0));

  turbovas_control_secure_clear (sensitive, strlen (sensitive));
  for (i = 0; i < strlen ("secret-copy"); i++)
    assert_that (sensitive[i], is_equal_to (0));
  g_free (sensitive);
}

Ensure (turbovas_control, rejects_nonexistent_credential_operator_before_create)
{
  const turbovas_control_credential_create_request_t request = {
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

  assert_that (turbovas_control_create_credential (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (99));
  assert_that (create_credential_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
}

Ensure (turbovas_control, accepts_schedule_modify_presence_and_empty_tokens)
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
  turbovas_control_schedule_modify_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_modify_request (
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

  turbovas_control_schedule_modify_request_clear (&schedule);
  g_free (request);
  g_free (calendar_b64);
}

Ensure (turbovas_control, rejects_malformed_or_unauthenticated_schedule_modify)
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
  turbovas_control_schedule_modify_request_t schedule = {0};

  control_name_b64 = g_base64_encode ((const guchar *) "line\nname", 9);
  control_name_request = g_strdup_printf (
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 +%s - - +QQ==\n",
    control_name_b64);

  assert_that (turbovas_control_parse_schedule_modify_request (
                 extra, strlen (extra), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 bare_base64, strlen (bare_base64), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 noncanonical_base64, strlen (noncanonical_base64),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 wrong_secret, strlen (wrong_secret), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 invalid_uuid, strlen (invalid_uuid), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 all_absent, strlen (all_absent), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 control_name_request, strlen (control_name_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);

  g_free (control_name_request);
  g_free (control_name_b64);
}

Ensure (turbovas_control, rejects_invalid_schedule_modify_field_bytes)
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
    TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES + 1, 'n');
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
  turbovas_control_schedule_modify_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_modify_request (
                 nul_request, strlen (nul_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 invalid_utf8_request, strlen (invalid_utf8_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
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

Ensure (turbovas_control, distinguishes_absent_and_empty_schedule_modify_calendar)
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
  turbovas_control_schedule_modify_request_t absent = {0};
  turbovas_control_schedule_modify_request_t empty = {0};

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  modify_schedule_calls = 0;
  modify_schedule_result = 0;
  mock_operator_name = "operator";

  assert_that (turbovas_control_parse_schedule_modify_request (
                 absent_request, strlen (absent_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &absent),
               is_true);
  assert_that (absent.comment, is_equal_to_string ("metadata"));
  assert_that (absent.icalendar, is_null);
  assert_that (turbovas_control_modify_schedule (operator_uuid, schedule_uuid,
                                                 &absent),
               is_equal_to (0));
  assert_that (received_icalendar, is_null);

  modify_schedule_result = 6;
  assert_that (turbovas_control_parse_schedule_modify_request (
                 empty_request, strlen (empty_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &empty),
               is_true);
  assert_that (empty.comment, is_equal_to_string ("metadata"));
  assert_that (empty.icalendar, is_equal_to_string (""));
  assert_that (turbovas_control_modify_schedule (operator_uuid, schedule_uuid,
                                                 &empty),
               is_equal_to (6));
  assert_that (received_icalendar, is_equal_to_string (""));
  assert_that (reinit_calls, is_equal_to (2));
  assert_that (session_init_calls, is_equal_to (2));
  assert_that (modify_schedule_calls, is_equal_to (2));
  assert_that (cleanup_calls, is_equal_to (2));

  turbovas_control_schedule_modify_request_clear (&empty);
  turbovas_control_schedule_modify_request_clear (&absent);
}

Ensure (turbovas_control, modifies_schedule_in_operator_session)
{
  const turbovas_control_schedule_modify_request_t request = {
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

  assert_that (turbovas_control_modify_schedule (
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

Ensure (turbovas_control, maps_schedule_modify_responses)
{
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (turbovas_control_schedule_modify_response (0, response),
               is_equal_to_string ("0 modified\n"));
  assert_that (turbovas_control_schedule_modify_response (1, response),
               is_equal_to_string ("1 not_found\n"));
  assert_that (turbovas_control_schedule_modify_response (2, response),
               is_equal_to_string ("2 duplicate\n"));
  assert_that (turbovas_control_schedule_modify_response (6, response),
               is_equal_to_string ("6 invalid_ical\n"));
  assert_that (turbovas_control_schedule_modify_response (7, response),
               is_equal_to_string ("7 invalid_timezone\n"));
  assert_that (turbovas_control_schedule_modify_response (99, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (turbovas_control_schedule_modify_response (-2, response),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (turbovas_control_schedule_modify_response (-1, response),
               is_equal_to_string ("-1 internal\n"));
}

int
__wrap_stop_task (const char *task_uuid)
{
  (void) task_uuid;
  stop_task_calls++;
  return 0;
}

void
__wrap_cleanup_manage_process (gboolean full)
{
  (void) full;
  cleanup_calls++;
}

Ensure (turbovas_control, accepts_exact_authenticated_stop_request)
{
  const char *request =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (turbovas_control_parse_request (request, strlen (request),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (task_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
}

Ensure (turbovas_control, rejects_noncanonical_or_extra_requests)
{
  const char *extra =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 extra\n";
  const char *invalid_uuid =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z\n";
  char request[TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1];
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (turbovas_control_parse_request (extra, strlen (extra),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_false);
  assert_that (turbovas_control_parse_request (invalid_uuid,
                                               strlen (invalid_uuid),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_false);
  memset (request, 'x', sizeof (request));
  assert_that (turbovas_control_parse_request (
                 request, sizeof (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, task_uuid),
               is_false);
}

Ensure (turbovas_control, rejects_missing_weak_or_incorrect_secrets)
{
  const char *request =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (turbovas_control_secret_is_valid (NULL, 0), is_false);
  assert_that (turbovas_control_secret_is_valid ("too-short", 9), is_false);
  assert_that (turbovas_control_secret_is_valid (TEST_CONTROL_SECRET,
                                                 strlen (TEST_CONTROL_SECRET)),
               is_true);
  assert_that (turbovas_control_secret_is_valid (
                 "0123456789abcdef0123456789abcde!", 32),
               is_false);
  assert_that (turbovas_control_parse_request (
                 request, strlen (request), NULL, 0,
                 operator_uuid, task_uuid),
               is_false);
  assert_that (turbovas_control_parse_request (
                 request, strlen (request), "too-short", 9,
                 operator_uuid, task_uuid),
               is_false);
  assert_that (turbovas_control_parse_request (
                 request, strlen (request),
                 "fedcba9876543210fedcba9876543210", 32,
                 operator_uuid, task_uuid),
               is_false);
}

Ensure (turbovas_control, maps_only_protocol_responses)
{
  assert_that (turbovas_control_response (0), is_equal_to_string ("0 stopped\n"));
  assert_that (turbovas_control_response (2),
               is_equal_to_string ("2 inactive\n"));
  assert_that (turbovas_control_response (1),
               is_equal_to_string ("1 requested\n"));
  assert_that (turbovas_control_response (3),
               is_equal_to_string ("3 not_found\n"));
  assert_that (turbovas_control_response (99),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (turbovas_control_response (-1),
               is_equal_to_string ("-1 internal\n"));
  assert_that (turbovas_control_response (-2),
               is_equal_to_string ("-2 scanner_status\n"));
  assert_that (turbovas_control_response (-3),
               is_equal_to_string ("-3 scanner_stop\n"));
  assert_that (turbovas_control_response (-4),
               is_equal_to_string ("-4 scanner_delete\n"));
  assert_that (turbovas_control_response (-5),
               is_equal_to_string ("-5 scanner_verify\n"));
}

Ensure (turbovas_control, rejects_nonexistent_operator_before_session_setup)
{
  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  stop_task_calls = 0;
  mock_operator_name = NULL;

  assert_that (turbovas_control_stop_task (
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

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, turbovas_control,
                         accepts_exact_authenticated_stop_request);
  add_test_with_context (suite, turbovas_control,
                         rejects_noncanonical_or_extra_requests);
  add_test_with_context (suite, turbovas_control,
                         rejects_missing_weak_or_incorrect_secrets);
  add_test_with_context (suite, turbovas_control,
                         maps_only_protocol_responses);
  add_test_with_context (suite, turbovas_control,
                         accepts_strict_bounded_trash_empty_request);
  add_test_with_context (suite, turbovas_control,
                         rejects_malformed_trash_empty_requests);
  add_test_with_context (suite, turbovas_control,
                         maps_trash_empty_contract_responses);
  add_test_with_context (suite, turbovas_control,
                         dispatches_trash_count_mismatch);
  add_test_with_context (suite, turbovas_control,
                         audits_successful_trash_empty);
  add_test_with_context (suite, turbovas_control,
                         audits_trash_empty_failures);
  add_test_with_context (suite, turbovas_control,
                         does_not_audit_missing_trash_operator);
  add_test_with_context (suite, turbovas_control,
                         locks_before_count_and_skips_delete_on_mismatch);
  add_test_with_context (suite, turbovas_control,
                         accepts_canonical_schedule_create_request);
  add_test_with_context (suite, turbovas_control,
                         accepts_maximum_schedule_fields);
  add_test_with_context (suite, turbovas_control,
                         rejects_noncanonical_or_oversized_schedule_fields);
  add_test_with_context (suite, turbovas_control,
                         creates_schedule_in_operator_session);
  add_test_with_context (suite, turbovas_control,
                         maps_schedule_create_responses);
  add_test_with_context (suite, turbovas_control,
                         accepts_username_password_credential_create_request);
  add_test_with_context (suite, turbovas_control,
                         accepts_ssh_key_credential_create_request);
  add_test_with_context (suite, turbovas_control,
                         rejects_malformed_credential_create_requests);
  add_test_with_context (suite, turbovas_control,
                         creates_credential_in_operator_session);
  add_test_with_context (suite, turbovas_control,
                         maps_credential_create_responses);
  add_test_with_context (suite, turbovas_control,
                         tracks_partial_request_length_and_clears_secrets);
  add_test_with_context (suite, turbovas_control,
                         rejects_nonexistent_credential_operator_before_create);
  add_test_with_context (suite, turbovas_control,
                         accepts_schedule_modify_presence_and_empty_tokens);
  add_test_with_context (suite, turbovas_control,
                         rejects_malformed_or_unauthenticated_schedule_modify);
  add_test_with_context (suite, turbovas_control,
                         rejects_invalid_schedule_modify_field_bytes);
  add_test_with_context (suite, turbovas_control,
                         distinguishes_absent_and_empty_schedule_modify_calendar);
  add_test_with_context (suite, turbovas_control,
                         modifies_schedule_in_operator_session);
  add_test_with_context (suite, turbovas_control,
                         maps_schedule_modify_responses);
  add_test_with_context (suite, turbovas_control,
                         rejects_nonexistent_operator_before_session_setup);
  add_test_with_context (suite, turbovas_control,
                         parses_canonical_bounded_alert_email_request);
  add_test_with_context (suite, turbovas_control,
                         enforces_alert_email_notice_mode_semantics);
  add_test_with_context (suite, turbovas_control,
                         enforces_alert_email_canonicalization_and_bounds);
  add_test_with_context (suite, turbovas_control,
                         maps_alert_email_arrays_session_and_success_audit);
  add_test_with_context (suite, turbovas_control,
                         maps_selected_attach_message_and_failure_audit);
  add_test_with_context (suite, turbovas_control,
                         maps_simple_notice_without_report_selectors);
  add_test_with_context (suite, turbovas_control,
                         omits_empty_optional_report_method_data);
  add_test_with_context (suite, turbovas_control,
                         rejects_missing_alert_operator_before_authority);
  add_test_with_context (suite, turbovas_control,
                         maps_atomic_unavailable_alert_report_format);
  add_test_with_context (suite, turbovas_control,
                         maps_atomic_unavailable_alert_report_config);
  add_test_with_context (suite, turbovas_control,
                         maps_atomic_alert_report_config_mismatch);
  add_test_with_context (
    suite, turbovas_control,
    reports_postcommit_alert_uuid_failure_without_failed_audit);
  add_test_with_context (suite, turbovas_control,
                         maps_every_alert_create_response);
  add_test_with_context (suite, turbovas_control,
                         returns_malformed_for_truncated_alert_frame);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
