/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "turbovas_control.c"

#include <cgreen/cgreen.h>
#include <string.h>

#define TEST_CONTROL_SECRET "0123456789abcdef0123456789abcdef"

Describe (turbovas_control);
BeforeEach (turbovas_control) {}
AfterEach (turbovas_control) {}

static int cleanup_calls;
static int create_schedule_calls;
static int create_schedule_result;
static int reinit_calls;
static int session_init_calls;
static int stop_task_calls;
static const char *mock_operator_name;
static gchar *received_comment;
static gchar *received_icalendar;
static gchar *received_name;
static gchar *received_timezone;

gchar *
__wrap_user_name (const char *uuid)
{
  (void) uuid;
  return mock_operator_name ? g_strdup (mock_operator_name) : NULL;
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

void
__wrap_manage_session_init (const char *uuid)
{
  (void) uuid;
  session_init_calls++;
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
                         rejects_nonexistent_operator_before_session_setup);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
