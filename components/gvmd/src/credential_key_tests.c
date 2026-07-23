/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * YAFVS-Derivation: original
 */

#include "credential_key.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#include <cgreen/cgreen.h>
#pragma GCC diagnostic pop
#include <glib/gstdio.h>

Describe (credential_key);
BeforeEach (credential_key) {}
AfterEach (credential_key) {}

Ensure (credential_key, closed_askpass_pipe_does_not_terminate_manager)
{
  int descriptors[2];

  assert_that (pipe (descriptors), is_equal_to (0));
  close (descriptors[0]);
  assert_that (write_passphrase (descriptors[1], "safe-passphrase"),
               is_false);
  close (descriptors[1]);
}

Ensure (credential_key, shell_metacharacters_are_passphrase_data)
{
  gchar *marker =
    g_strdup_printf ("/tmp/yafvs-credential-key-injection-%ld", (long) getpid ());
  gchar *passphrase = g_strdup_printf ("safe$(touch %s)'\";word", marker);
  gchar *private_key = NULL;

  g_unlink (marker);
  assert_that (credential_ssh_key_create (passphrase, &private_key),
               is_equal_to (0));
  assert_that (private_key, is_non_null);
  assert_that (private_key,
               contains_string ("-----BEGIN OPENSSH PRIVATE KEY-----"));
  assert_that (g_file_test (marker, G_FILE_TEST_EXISTS), is_false);

  g_free (private_key);
  g_free (passphrase);
  g_free (marker);
}

int
main (int argc, char **argv)
{
  int result;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (
    suite, credential_key, closed_askpass_pipe_does_not_terminate_manager);
  add_test_with_context (
    suite, credential_key, shell_metacharacters_are_passphrase_data);

  if (argc > 1)
    result = run_single_test (suite, argv[1], create_text_reporter ());
  else
    result = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return result;
}
