/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define sql_ps test_sql_ps
#define sql_ps_sensitive test_sql_ps_sensitive
#include "manage_sql_users.c"
#undef sql_ps
#undef sql_ps_sensitive

#include <cgreen/cgreen.h>
#include <stdarg.h>
#include <string.h>

static GPtrArray *invalidated_usernames;
static gchar *sensitive_statement;
static gchar *sensitive_parameters[3];

void
test_sql_ps (const char *statement, ...)
{
  const sql_param_t *username;
  va_list args;

  assert_that (statement, is_equal_to_string (
                            "DELETE FROM auth_cache WHERE username = $1;"));

  va_start (args, statement);
  username = va_arg (args, const sql_param_t *);
  va_end (args);

  assert_that (username, is_not_null);
  assert_that (username->type, is_equal_to (SQL_PARAM_TYPE_STRING));
  g_ptr_array_add (invalidated_usernames, g_strdup (username->value.str_value));
}

void
test_sql_ps_sensitive (const char *statement, ...)
{
  const sql_param_t *parameter;
  va_list args;

  sensitive_statement = g_strdup (statement);
  va_start (args, statement);
  for (guint index = 0; index < G_N_ELEMENTS (sensitive_parameters); index++)
    {
      parameter = va_arg (args, const sql_param_t *);
      assert_that (parameter, is_not_null);
      assert_that (parameter->type, is_equal_to (SQL_PARAM_TYPE_STRING));
      sensitive_parameters[index] = g_strdup (parameter->value.str_value);
    }
  va_end (args);
}

Describe (manage_sql_users);

BeforeEach (manage_sql_users)
{
  invalidated_usernames = g_ptr_array_new_with_free_func (g_free);
  sensitive_statement = NULL;
  memset (sensitive_parameters, 0, sizeof (sensitive_parameters));
}

AfterEach (manage_sql_users)
{
  g_ptr_array_free (invalidated_usernames, TRUE);
  g_free (sensitive_statement);
  for (guint index = 0; index < G_N_ELEMENTS (sensitive_parameters); index++)
    g_free (sensitive_parameters[index]);
}

Ensure (manage_sql_users, comment_only_change_preserves_auth_cache)
{
  invalidate_auth_cache_for_user_change ("operator", NULL, FALSE);

  assert_that (invalidated_usernames->len, is_equal_to (0));
}

Ensure (manage_sql_users, password_or_method_change_invalidates_current_name)
{
  invalidate_auth_cache_for_user_change ("operator", NULL, TRUE);

  assert_that (invalidated_usernames->len, is_equal_to (1));
  assert_that (g_ptr_array_index (invalidated_usernames, 0),
               is_equal_to_string ("operator"));
}

Ensure (manage_sql_users, unchanged_auth_method_preserves_auth_cache)
{
  assert_that (user_authentication_changed (NULL, "file", "file"), is_false);
  invalidate_auth_cache_for_user_change ("operator", NULL, FALSE);

  assert_that (invalidated_usernames->len, is_equal_to (0));
}

Ensure (manage_sql_users, changed_auth_method_invalidates_current_name)
{
  gboolean changed;

  changed = user_authentication_changed (NULL, "file", "ldap_connect");
  assert_that (changed, is_true);
  invalidate_auth_cache_for_user_change ("operator", NULL, changed);

  assert_that (invalidated_usernames->len, is_equal_to (1));
  assert_that (g_ptr_array_index (invalidated_usernames, 0),
               is_equal_to_string ("operator"));
}

Ensure (manage_sql_users, password_update_and_cache_invalidation_are_atomic)
{
  gchar *rejection_message = NULL;

  assert_that (set_password ("operator", "123e4567-e89b-12d3-a456-426614174001",
                             "correct-horse-battery-staple",
                             &rejection_message),
               is_equal_to (0));

  assert_that (rejection_message, is_null);
  assert_that (sensitive_statement, contains_string ("WITH updated_user AS"));
  assert_that (sensitive_statement, contains_string ("DELETE FROM auth_cache"));
  assert_that (sensitive_parameters[0],
               is_not_equal_to_string ("correct-horse-battery-staple"));
  assert_that (sensitive_parameters[1],
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (sensitive_parameters[2], is_equal_to_string ("operator"));
}

Ensure (manage_sql_users, rename_invalidates_old_and_new_names)
{
  invalidate_auth_cache_for_user_change ("operator", "scanner-admin", FALSE);

  assert_that (invalidated_usernames->len, is_equal_to (2));
  assert_that (g_ptr_array_index (invalidated_usernames, 0),
               is_equal_to_string ("operator"));
  assert_that (g_ptr_array_index (invalidated_usernames, 1),
               is_equal_to_string ("scanner-admin"));
}

Ensure (manage_sql_users, unchanged_name_is_invalidated_only_once)
{
  invalidate_auth_cache_for_user_change ("operator", "operator", FALSE);

  assert_that (invalidated_usernames->len, is_equal_to (1));
  assert_that (g_ptr_array_index (invalidated_usernames, 0),
               is_equal_to_string ("operator"));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();
  add_test_with_context (suite, manage_sql_users,
                         comment_only_change_preserves_auth_cache);
  add_test_with_context (suite, manage_sql_users,
                         password_or_method_change_invalidates_current_name);
  add_test_with_context (suite, manage_sql_users,
                         unchanged_auth_method_preserves_auth_cache);
  add_test_with_context (suite, manage_sql_users,
                         changed_auth_method_invalidates_current_name);
  add_test_with_context (suite, manage_sql_users,
                         rename_invalidates_old_and_new_names);
  add_test_with_context (suite, manage_sql_users,
                         unchanged_name_is_invalidated_only_once);
  add_test_with_context (suite, manage_sql_users,
                         password_update_and_cache_invalidation_are_atomic);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
