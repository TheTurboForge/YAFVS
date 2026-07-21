/* Copyright (C) 2019-2022 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage.c"

#include <cgreen/cgreen.h>

Describe (manage);
BeforeEach (manage)
{
}
AfterEach (manage)
{
}

static task_status_t mock_task_status;
static osp_scan_status_t mock_osp_statuses[3];
static int mock_osp_status_count;
static int mock_osp_status_index;
static int mock_scanner_connect_failure;
static int mock_stop_calls;
static int mock_delete_calls;
static int mock_queue_remove_calls;
static task_status_t mock_report_status;
static report_t mock_unfinished_reports[4];
static int mock_unfinished_report_count;
static int mock_unfinished_report_index;
static int mock_ended_report_count;

int
__wrap_lockfile_lock (lockfile_t *lockfile, const gchar *name)
{
  (void) lockfile;
  (void) name;
  return 0;
}

int
__wrap_lockfile_unlock (lockfile_t *lockfile)
{
  (void) lockfile;
  return 0;
}

int
__wrap_task_unfinished_report (task_t task, report_t *report)
{
  (void) task;
  *report =
    mock_unfinished_report_index < mock_unfinished_report_count
      ? mock_unfinished_reports[mock_unfinished_report_index++]
      : 0;
  return 0;
}

task_status_t
__wrap_task_run_status (task_t task)
{
  (void) task;
  return mock_task_status;
}

scanner_t
__wrap_task_scanner (task_t task)
{
  (void) task;
  return 7;
}

gchar *
__wrap_report_uuid (report_t report)
{
  (void) report;
  return g_strdup ("123e4567-e89b-12d3-a456-426614174001");
}

osp_connection_t *
__wrap_osp_scanner_connect (scanner_t scanner)
{
  (void) scanner;
  return mock_scanner_connect_failure
           ? NULL
           : (osp_connection_t *) 0x1;
}

osp_scan_status_t
__wrap_osp_get_scan_status_ext (osp_connection_t *connection,
                                osp_get_scan_status_opts_t options,
                                char **error)
{
  osp_scan_status_t status;

  (void) connection;
  (void) options;
  status = mock_osp_statuses[
    mock_osp_status_index < mock_osp_status_count
      ? mock_osp_status_index++
      : mock_osp_status_count - 1];
  if (status == OSP_SCAN_STATUS_ERROR && error)
    *error = g_strdup ("Failed to find scan");
  return status;
}

int
__wrap_osp_stop_scan (osp_connection_t *connection, const char *scan_id,
                      char **error)
{
  (void) connection;
  (void) scan_id;
  (void) error;
  mock_stop_calls++;
  return 0;
}

int
__wrap_osp_delete_scan (osp_connection_t *connection, const char *scan_id)
{
  (void) connection;
  (void) scan_id;
  mock_delete_calls++;
  return 0;
}

void
__wrap_osp_connection_close (osp_connection_t *connection)
{
  (void) connection;
}

void
__wrap_set_task_run_status (task_t task, task_status_t status)
{
  (void) task;
  mock_task_status = status;
}

int
__wrap_report_scan_run_status (report_t report, task_status_t *status)
{
  (void) report;
  *status = mock_report_status;
  return 0;
}

void
__wrap_set_report_scan_run_status (report_t report, task_status_t status)
{
  (void) report;
  mock_report_status = status;
}

void
__wrap_set_task_end_time_epoch (task_t task, time_t end_time)
{
  (void) task;
  (void) end_time;
}

void
__wrap_set_scan_end_time_epoch (report_t report, time_t end_time)
{
  (void) report;
  (void) end_time;
  mock_ended_report_count++;
}

void
__wrap_scan_queue_remove (report_t report)
{
  (void) report;
  mock_queue_remove_calls++;
}

static void
reset_stop_mocks (void)
{
  mock_task_status = TASK_STATUS_QUEUED;
  mock_osp_status_count = 0;
  mock_osp_status_index = 0;
  mock_scanner_connect_failure = 0;
  mock_stop_calls = 0;
  mock_delete_calls = 0;
  mock_queue_remove_calls = 0;
  mock_report_status = TASK_STATUS_QUEUED;
  mock_unfinished_reports[0] = 99;
  mock_unfinished_reports[1] = 0;
  mock_unfinished_report_count = 2;
  mock_unfinished_report_index = 0;
  mock_ended_report_count = 0;
}

Ensure (manage, osp_stop_requires_verified_scanner_absence)
{
  reset_stop_mocks ();
  mock_osp_statuses[0] = OSP_SCAN_STATUS_QUEUED;
  mock_osp_statuses[1] = OSP_SCAN_STATUS_ERROR;
  mock_osp_status_count = 2;

  assert_that (stop_osp_task (42), is_equal_to (0));
  assert_that (mock_stop_calls, is_equal_to (0));
  assert_that (mock_delete_calls, is_equal_to (1));
  assert_that (mock_queue_remove_calls, is_equal_to (1));
  assert_that (mock_task_status, is_equal_to (TASK_STATUS_STOPPED));
  assert_that (mock_report_status, is_equal_to (TASK_STATUS_STOPPED));
  assert_that (mock_ended_report_count, is_equal_to (1));
}

Ensure (manage, osp_running_stop_waits_for_terminal_state_before_delete)
{
  reset_stop_mocks ();
  mock_task_status = TASK_STATUS_RUNNING;
  mock_osp_statuses[0] = OSP_SCAN_STATUS_RUNNING;
  mock_osp_statuses[1] = OSP_SCAN_STATUS_STOPPED;
  mock_osp_statuses[2] = OSP_SCAN_STATUS_ERROR;
  mock_osp_status_count = 3;

  assert_that (stop_osp_task (42), is_equal_to (0));
  assert_that (mock_stop_calls, is_equal_to (1));
  assert_that (mock_delete_calls, is_equal_to (1));
  assert_that (mock_task_status, is_equal_to (TASK_STATUS_STOPPED));
}

Ensure (manage, osp_stop_accepts_explicit_scanner_absence)
{
  reset_stop_mocks ();
  mock_osp_statuses[0] = OSP_SCAN_STATUS_ERROR;
  mock_osp_status_count = 1;

  assert_that (stop_osp_task (42), is_equal_to (0));
  assert_that (mock_stop_calls, is_equal_to (0));
  assert_that (mock_delete_calls, is_equal_to (0));
  assert_that (mock_task_status, is_equal_to (TASK_STATUS_STOPPED));
}

Ensure (manage, osp_stop_does_not_claim_stopped_when_scanner_is_unavailable)
{
  reset_stop_mocks ();
  mock_scanner_connect_failure = 1;

  assert_that (stop_osp_task (42), is_equal_to (-2));
  assert_that (mock_queue_remove_calls, is_equal_to (0));
  assert_that (mock_task_status, is_equal_to (TASK_STATUS_QUEUED));
  assert_that (mock_report_status, is_equal_to (TASK_STATUS_QUEUED));
  assert_that (mock_ended_report_count, is_equal_to (0));
}

Ensure (manage, osp_stop_drains_every_unfinished_report)
{
  reset_stop_mocks ();
  mock_osp_statuses[0] = OSP_SCAN_STATUS_ERROR;
  mock_osp_statuses[1] = OSP_SCAN_STATUS_ERROR;
  mock_osp_status_count = 2;
  mock_unfinished_reports[0] = 101;
  mock_unfinished_reports[1] = 102;
  mock_unfinished_reports[2] = 0;
  mock_unfinished_report_count = 3;

  assert_that (stop_osp_task (42), is_equal_to (0));
  assert_that (mock_stop_calls, is_equal_to (0));
  assert_that (mock_delete_calls, is_equal_to (0));
  assert_that (mock_queue_remove_calls, is_equal_to (2));
  assert_that (mock_ended_report_count, is_equal_to (2));
  assert_that (mock_task_status, is_equal_to (TASK_STATUS_STOPPED));
  assert_that (mock_report_status, is_equal_to (TASK_STATUS_STOPPED));
}

Ensure (manage, osp_stop_preserves_terminal_report_status_while_finalizing)
{
  reset_stop_mocks ();
  mock_report_status = TASK_STATUS_INTERRUPTED;
  mock_osp_statuses[0] = OSP_SCAN_STATUS_ERROR;
  mock_osp_status_count = 1;

  assert_that (stop_osp_task (42), is_equal_to (0));
  assert_that (mock_queue_remove_calls, is_equal_to (1));
  assert_that (mock_ended_report_count, is_equal_to (1));
  assert_that (mock_task_status, is_equal_to (TASK_STATUS_STOPPED));
  assert_that (mock_report_status, is_equal_to (TASK_STATUS_INTERRUPTED));
}

/* truncate_certificate */

Ensure (manage, truncate_certificate_given_truncated)
{
  const gchar *given;
  gchar *truncated;

  given = "-----BEGIN CERTIFICATE-----\n"
          "MIIEjTCCAvWgAwIBAgIMWtd9bxgrX+9SgEHXMA0GCSqGSIb3DQEBCwUAMGIxKjAo\n"
          "BgNVBAsTIUNlcnRpZmljYXRlIEF1dGhvcml0eSBmb3IgYy5sb2NhbDESMBAGA1UE\n"
          "ChMJR1ZNIFVzZXJzMRMwEQYDVQQHEwpPc25hYnJ1ZWNrMQswCQYDVQQGEwJERTAe\n"
          "Fw0xODA0MTgxNzE2MzFaFw0yODA0MTcxNzE2MzFaMGIxKjAoBgNVBAsTIUNlcnRp\n"
          "ZmljYXRlIEF1dGhvcml0eSBmb3IgYy5sb2NhbDESMBAGA1UEChMJR1ZNIFVzZXJz\n"
          "MRMwEQYDVQQHEwpPc25hYnJ1ZWNrMQswCQYDVQQGEwJERTCCAaIwDQYJKoZIhvcN\n"
          "AQEBBQADggGPADCCAYoCggGBAN7Xjg8ZUAVg3URxV8DJ7DhArjEzR7m1BKYC3PPu\n"
          "yaAnRZqed4eZo9t6Gk+EvZxjkyN79Sooz9xpYV43naBLzTJlgbTIhkKDi9t9kB9O\n"
          "5kA8b5YxKDHaVmmJ1oxR3k115fLtBcwyjt6juL4FvyP+zJ7v1bLcXSjgUytuAce1\n"
          "C2BTLP8IaLde1bkhxINnD6moEarsZex0THQffPof6nI1gaPiDOXorzWCTegMnT1s\n"
          "26jRvQog8H7Tw+TvGwENW28MwrTy5ZnzwWIND64vmPy3oC5LQhTacd++84CstuZ9\n"
          "nI4mXh++gXRqP7lx9CSpVH+z7/Lo9S3JkWvl756m1ieJtX6bJtAadDdOsofbgasN\n"
          "xhJ42oxjjxdYdH5s0AX2frv+OvnBIWCGN9/6Tws1VCAF1SjIB7GRuyM7FcUoONtx\n"
          "svQiwNal/hOCN6DbCSM/ff76G4VwKOUlpY3GJdveTugum7V7VN9hYBSBcK45diAd\n"
          "b0ZZiRSq9T61/zFayeVQWPiWfwIDAQABo0MwQTAPBgNVHRMBAf8EBTADAQH/MA8G\n"
          "A1UdDwEB/wQFAwMHBgAwHQYDVR0OBBYEFBHD0+uQ+JXQmoUvLIJGldpGgaUdMA0G\n"
          "CSqGSIb3DQEBCwUAA4IBgQCqW2XCz2zMW14oKUu0jq33MKUE0MKG2VUy/JjVyUl9\n"
          "Vg2ZIuDFnX3qpGZJaHDOeFz3xYGcLny0QuKm4I+zYL6/rmDMhcHyuO3N+cOc+x4X\n"
          "4PRz8jydhrOMED16Tg0+o5L3JDplWpmsqUKu+sY378ZNdGPBIE1LIIzOjH296SWe\n"
          "0fztTTHLr56ftmakwC241Etmgf8ow95kxhFxbxB0hUFcIkCvi0S9eZ4ip0v/Yo2z\n"
          "lZ/DYl9GnkdnwlHB/f1/iZzrn7arEKwhqE8L/STJH+K0nJT4IGQZnyUfId7Jb+lO\n"
          "HWIyYyrUHkqIRqfybZrDXPTYGW/NvheOm8OTQmz65ySLWWNVpy2TRoLD3198GSF9\n"
          "fnkIVNvsMB5h5uCzboV+HqkYX72wg1Vfda0/8M/riYbEaxNcKKfuReoPNoCOBC8h\n"
          "NKOM6mBOCkc7MifVDVwCxaVlvGX5fKzHDhfSoNreotdL2mFJfk15Jjk4w3bmgiVT\n"
          "u1UuTizi5guqzOf+57s4o7Q=\n"
          "-----END CERTIFICATE-----\n";

  truncated = truncate_certificate (given);
  assert_that (truncated, is_equal_to_string (given));
  g_free (truncated);
}

Ensure (manage, truncate_certificate_empty_string)
{
  const gchar *given;
  gchar *truncated;

  given = "";

  truncated = truncate_certificate (given);
  assert_that (truncated, is_null);
  g_free (truncated);
}

Ensure (manage, truncate_certificate_invalid_certificate)
{
  const gchar *given;
  gchar *truncated;

  given = "foo bar baz";

  truncated = truncate_certificate (given);
  assert_that (truncated, is_null);
  g_free (truncated);
}

Ensure (manage, truncate_certificate_extra_data)
{
  const gchar *given, *expected;
  gchar *truncated;
  given = "-----BEGIN CERTIFICATE-----\n"
          "MIIEjTCCAvWgAwIBAgIMWtd9bxgrX+9SgEHXMA0GCSqGSIb3DQEBCwUAMGIxKjAo\n"
          "-----END CERTIFICATE-----\n"
          "u1UuTizi5guqzOf+57s4o7Q=\n";
  expected =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEjTCCAvWgAwIBAgIMWtd9bxgrX+9SgEHXMA0GCSqGSIb3DQEBCwUAMGIxKjAo\n"
    "-----END CERTIFICATE-----\n";
  truncated = truncate_certificate (given);
  assert_that (truncated, is_equal_to_string (expected));
  g_free (truncated);
}

/* truncate_text */

Ensure (manage, truncate_text_truncates)
{
  gchar *given;

  given = g_strdup ("1234567890");

  truncate_text (given, 4, 0 /* Not XML. */, NULL /* No suffix. */);
  assert_that (given, is_equal_to_string ("1234"));
  g_free (given);
}

Ensure (manage, severity_data_index_clamps_above_maximum)
{
  assert_that (severity_data_index (SEVERITY_MAX + 0.1),
               is_equal_to (severity_data_index (SEVERITY_MAX)));
  assert_that (severity_data_index (INFINITY),
               is_equal_to (severity_data_index (SEVERITY_MAX)));
}

Ensure (manage, severity_data_index_rejects_nan)
{
  assert_that (severity_data_index (NAN), is_equal_to (0));
}

Ensure (manage, truncate_text_does_not_truncate)
{
  const gchar *original;
  gchar *given;

  original = "1234567890";
  given = g_strdup (original);
  truncate_text (given, 40, 0 /* Not XML. */, NULL /* No suffix. */);
  assert_that (given, is_equal_to_string (original));
  g_free (given);
}

Ensure (manage, truncate_text_handles_null)
{
  truncate_text (NULL, 40, 0 /* Not XML. */, NULL /* No suffix. */);
}

Ensure (manage, truncate_text_appends_suffix)
{
  const gchar *suffix;
  gchar *given;

  suffix = "abc";
  given = g_strdup ("1234567890");

  truncate_text (given, strlen (suffix) + 1, 0 /* Not XML. */, suffix);
  assert_that (given, is_equal_to_string ("1abc"));
  g_free (given);
}

Ensure (manage, truncate_text_skips_suffix)
{
  const gchar *suffix;
  gchar *given;

  suffix = "abc";
  given = g_strdup ("1234567890");

  truncate_text (given,
                 /* Too little space for suffix. */
                 strlen (suffix) - 1,
                 /* Not XML. */
                 0, suffix);
  assert_that (given, is_equal_to_string ("12"));
  g_free (given);
}

Ensure (manage, truncate_text_preserves_xml)
{
  gchar *given;

  given = g_strdup ("12&nbsp;90");

  truncate_text (given, 5, 1 /* Preserve entities. */, NULL /* No suffix. */);
  assert_that (given, is_equal_to_string ("12"));
  g_free (given);
}

/* delete_reports */

// TODO
//
// To test this kind of function we need to isolate the code in the manage.c
// module.  So we need to create stubs/mocks in manage_tests.c that simulate
// init_report_iterator, next_report, delete_report_internal and
// cleanup_iterator.  Then we can use these stubs/mocks to create simple
// tests of delete_reports, like delete_reports_deletes_each_report_once or
// delete_reports_returns_negative_1_on_error.
//
// Should be easier to do after splitting Manager source code up.

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage,
                         osp_stop_requires_verified_scanner_absence);
  add_test_with_context (
    suite, manage,
    osp_running_stop_waits_for_terminal_state_before_delete);
  add_test_with_context (suite, manage,
                         osp_stop_accepts_explicit_scanner_absence);
  add_test_with_context (
    suite, manage,
    osp_stop_does_not_claim_stopped_when_scanner_is_unavailable);
  add_test_with_context (suite, manage,
                         osp_stop_drains_every_unfinished_report);
  add_test_with_context (
    suite, manage,
    osp_stop_preserves_terminal_report_status_while_finalizing);

  add_test_with_context (suite, manage, truncate_certificate_given_truncated);
  add_test_with_context (suite, manage, truncate_certificate_empty_string);
  add_test_with_context (suite, manage,
                         truncate_certificate_invalid_certificate);
  add_test_with_context (suite, manage, truncate_certificate_extra_data);

  add_test_with_context (suite, manage, truncate_text_truncates);
  add_test_with_context (suite, manage, truncate_text_does_not_truncate);
  add_test_with_context (suite, manage, truncate_text_handles_null);
  add_test_with_context (suite, manage, truncate_text_appends_suffix);
  add_test_with_context (suite, manage, truncate_text_skips_suffix);
  add_test_with_context (suite, manage, truncate_text_preserves_xml);
  add_test_with_context (suite, manage,
                         severity_data_index_clamps_above_maximum);
  add_test_with_context (suite, manage, severity_data_index_rejects_nan);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
