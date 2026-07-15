/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "nasl_ssh_output.h"

static void
test_exact_limit_succeeds (void)
{
  GString *output = g_string_new ("abc");

  g_assert_true (
    nasl_ssh_output_append_with_limit (output, NULL, "defgh", 5, 8));
  g_assert_cmpuint (output->len, ==, 8);
  g_assert_cmpstr (output->str, ==, "abcdefgh");

  g_string_free (output, TRUE);
}

static void
test_one_byte_over_fails_without_partial_output (void)
{
  GString *output = g_string_new ("abc");

  g_assert_false (
    nasl_ssh_output_append_with_limit (output, NULL, "defghi", 6, 8));
  g_assert_cmpuint (output->len, ==, 3);
  g_assert_cmpstr (output->str, ==, "abc");

  g_string_free (output, TRUE);
}

static void
test_aggregate_stream_budget (void)
{
  GString *stdout_output = g_string_new ("abc");
  GString *stderr_output = g_string_new ("defg");

  g_assert_true (nasl_ssh_output_append_with_limit (stdout_output,
                                                    stderr_output, "h", 1, 8));
  g_assert_false (nasl_ssh_output_append_with_limit (stdout_output,
                                                     stderr_output, "i", 1, 8));
  g_assert_cmpstr (stdout_output->str, ==, "abch");
  g_assert_cmpstr (stderr_output->str, ==, "defg");

  g_string_free (stdout_output, TRUE);
  g_string_free (stderr_output, TRUE);
}

static void
test_compatibility_concat_cannot_bypass_budget (void)
{
  GString *response = g_string_new ("abcde");
  GString *compatibility = g_string_new ("fghi");

  g_assert_false (nasl_ssh_output_append_with_limit (
    response, NULL, compatibility->str, compatibility->len, 8));
  g_assert_cmpstr (response->str, ==, "abcde");

  g_string_free (response, TRUE);
  g_string_free (compatibility, TRUE);
}

static void
test_incremental_reads_share_budget (void)
{
  GString *output = g_string_new (NULL);

  g_assert_true (
    nasl_ssh_output_append_with_limit (output, NULL, "abcd", 4, 8));
  g_assert_true (
    nasl_ssh_output_append_with_limit (output, NULL, "efgh", 4, 8));
  g_assert_false (nasl_ssh_output_append_with_limit (output, NULL, "i", 1, 8));
  g_assert_cmpstr (output->str, ==, "abcdefgh");

  g_string_free (output, TRUE);
}

static void
test_length_overflow_is_rejected (void)
{
  GString *output = g_string_new ("abc");

  g_assert_false (nasl_ssh_output_append_with_limit (output, NULL, "x",
                                                     G_MAXSIZE, G_MAXSIZE));
  g_assert_cmpstr (output->str, ==, "abc");

  g_string_free (output, TRUE);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/nasl/ssh-output/exact-limit", test_exact_limit_succeeds);
  g_test_add_func ("/nasl/ssh-output/one-byte-over",
                   test_one_byte_over_fails_without_partial_output);
  g_test_add_func ("/nasl/ssh-output/aggregate-streams",
                   test_aggregate_stream_budget);
  g_test_add_func ("/nasl/ssh-output/compatibility-concat",
                   test_compatibility_concat_cannot_bypass_budget);
  g_test_add_func ("/nasl/ssh-output/incremental",
                   test_incremental_reads_share_budget);
  g_test_add_func ("/nasl/ssh-output/length-overflow",
                   test_length_overflow_is_rejected);

  return g_test_run ();
}
