/* Copyright (C) 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#include <glib.h>
#include <stdlib.h>
#include <string.h>


#ifndef GVM_SYSCONF_DIR
# define GVM_SYSCONF_DIR "/tmp"
#endif

#include "gvmd_config.h"
#include "manage_runtime_flags.c"
Describe (manage_runtime_flags);

BeforeEach (manage_runtime_flags)
{
  unsetenv ("GVMD_ENABLE_OPENVASD");
  unsetenv ("GVMD_ENABLE_CREDENTIAL_STORES");
  unsetenv ("GVMD_ENABLE_VT_METADATA");
}

AfterEach (manage_runtime_flags)
{
}

static char *
write_test_config (const char *content)
{
  char *path = g_strdup ("runtime_flags_test.conf");
  FILE *f = fopen (path, "w");

  assert_true (f != NULL);
  fputs (content, f);
  fclose (f);

  return path;
}

Ensure (manage_runtime_flags, default_flags_no_config_no_env)
{
  runtime_flags_init ();

#if ENABLE_OPENVASD
  assert_that (feature_compiled_in (FEATURE_ID_OPENVASD_SCANNER),
               is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_OPENVASD_SCANNER), is_equal_to (0));
#else
  assert_that (feature_compiled_in (FEATURE_ID_OPENVASD_SCANNER),
               is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_OPENVASD_SCANNER), is_equal_to (0));
#endif

#if ENABLE_CREDENTIAL_STORES
  assert_that (feature_compiled_in (FEATURE_ID_CREDENTIAL_STORES),
               is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_CREDENTIAL_STORES), is_equal_to (0));
#else
  assert_that (feature_compiled_in (FEATURE_ID_CREDENTIAL_STORES),
               is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_CREDENTIAL_STORES), is_equal_to (0));
#endif

  assert_that (feature_compiled_in (FEATURE_ID_VT_METADATA), is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_VT_METADATA), is_equal_to (0));
  assert_that (feature_compiled_in (FEATURE_ID_SECURITY_INTELLIGENCE_EXPORT), is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_SECURITY_INTELLIGENCE_EXPORT), is_equal_to (0));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_runtime_flags,
                         default_flags_no_config_no_env);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
