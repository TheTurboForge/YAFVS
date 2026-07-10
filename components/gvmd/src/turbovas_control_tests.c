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
static int session_init_calls;
static int stop_task_calls;

gchar *
__wrap_user_name (const char *uuid)
{
  (void) uuid;
  return NULL;
}

void
__wrap_reinit_manage_process ()
{
}

void
__wrap_manage_session_init (const char *uuid)
{
  (void) uuid;
  session_init_calls++;
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
  session_init_calls = 0;
  stop_task_calls = 0;

  assert_that (turbovas_control_stop_task (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001"),
               is_equal_to (99));
  assert_that (cleanup_calls, is_equal_to (1));
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
                         rejects_nonexistent_operator_before_session_setup);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
