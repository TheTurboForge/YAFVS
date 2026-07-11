/* Copyright (C) 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_users.h"
#include "manage_acl.h"
#include "manage_authentication.h"
#include "manage_sql.h"
#include "manage_sql_filters.h"
#include "manage_sql_permissions.h"
#include "manage_sql_permissions_cache.h"
#include "manage_sql_port_lists.h"
#include "manage_sql_report_configs.h"
#include "manage_sql_report_formats.h"
#include "manage_sql_resources.h"
#include "manage_sql_schedules.h"
#include "manage_sql_settings.h"
#include "manage_sql_targets.h"
#include "manage_sql_tls_certificates.h"
#include "sql.h"

#include <gvm/base/pwpolicy.h>
#include <gvm/util/uuidutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @file
 * @brief GVM management layer: Users SQL
 *
 * The Users SQL for the GVM management layer.
 */

/**
 * @brief Return the name of a user.
 *
 * @param[in]  uuid  UUID of user.
 *
 * @return Newly allocated name if available, else NULL.
 */
gchar *
user_name (const char *uuid)
{
  gchar *name, *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  name = sql_string ("SELECT name FROM users WHERE uuid = '%s';",
                     quoted_uuid);
  g_free (quoted_uuid);
  return name;
}

/**
 * @brief Return the UUID of a user.
 *
 * Warning: this is only safe for users that are known to be in the db.
 *
 * @param[in]  user  User.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
user_uuid (user_t user)
{
  return sql_string ("SELECT uuid FROM users WHERE id = %llu;",
                     user);
}

/**
 * @brief Count number of users.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of users in usered set.
 */
int
user_count (const get_data_t *get)
{
  static const char *filter_columns[] = USER_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = USER_ITERATOR_COLUMNS;
  return count ("user", get, columns, NULL, filter_columns,
                  0, 0, 0, TRUE);
}

/**
 * @brief Initialise a user iterator, including observed users.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find user, 2 failed to find user (filt_id),
 *         -1 error.
 */
int
init_user_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = USER_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = USER_ITERATOR_COLUMNS;
  static column_t trash_columns[] = USER_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "user",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Get the method of the user from a user iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Method of the user or NULL if iteration is complete.
 */
DEF_ACCESS (user_iterator_method, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Find a user for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of user.
 * @param[out]  user        User return, 0 if successfully failed to find user.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find user), TRUE on error.
 */
gboolean
find_user_with_permission (const char* uuid, user_t* user,
                           const char *permission)
{
  return find_resource_with_permission ("user", uuid, user, permission, 0);
}

/**
 * @brief Find a user given a name.
 *
 * @param[in]   name  A user name.
 * @param[out]  user  User return, 0 if successfully failed to find user.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find user), TRUE on error.
 */
gboolean
find_user_by_name_with_permission (const char* name, user_t *user,
                                   const char *permission)
{
  return find_resource_by_name_with_permission ("user", name, user, permission);
}

/**
 * @brief Find a user given a name.
 *
 * @param[in]   name  A user name.
 * @param[out]  user  User return, 0 if successfully failed to find user.
 *
 * @return FALSE on success (including if failed to find user), TRUE on error.
 */
gboolean
find_user_by_name (const char* name, user_t *user)
{
  return find_resource_by_name ("user", name, user);
}

/**
 * @brief Check if user exists.
 *
 * @param[in]  name    User name.
 * @param[in]  method  Auth method.
 *
 * @return 1 yes, 0 no.
 */
int
user_exists_method (const gchar *name, auth_method_t method)
{
  gchar *quoted_name, *quoted_method;
  int ret;

  quoted_name = sql_quote (name);
  quoted_method = sql_quote (auth_method_name (method));
  ret = sql_int ("SELECT count (*) FROM users"
                 " WHERE name = '%s' AND method = '%s';",
                 quoted_name,
                 quoted_method);
  g_free (quoted_name);
  g_free (quoted_method);

  return ret;
}

/**
 * @brief Check if user exists.
 *
 * @param[in]  name    User name.
 *
 * @return 1 yes, 0 no.
 */
int
user_exists (const gchar *name)
{
  if (ldap_auth_enabled ()
      && user_exists_method (name, AUTHENTICATION_METHOD_LDAP_CONNECT))
    return 1;
  if (radius_auth_enabled ()
      && user_exists_method (name, AUTHENTICATION_METHOD_RADIUS_CONNECT))
    return 1;
  return user_exists_method (name, AUTHENTICATION_METHOD_FILE);
}

/**
 * @brief Get user uuid.
 *
 * @param[in]  username  User name.
 * @param[in]  method    Authentication method.
 *
 * @return UUID.
 */
static gchar *
user_uuid_method (const gchar *username, auth_method_t method)
{
  gchar *uuid, *quoted_username, *quoted_method;
  quoted_username = sql_quote (username);
  quoted_method = sql_quote (auth_method_name (method));
  uuid = sql_string ("SELECT uuid FROM users"
                     " WHERE name = '%s' AND method = '%s';",
                     quoted_username,
                     quoted_method);
  g_free (quoted_username);
  g_free (quoted_method);
  return uuid;
}

/**
 * @brief Get user uuid, trying all authentication methods.
 *
 * @param[in]  name    User name.
 *
 * @return UUID.
 */
gchar *
user_uuid_any_method (const gchar *name)
{
  if (ldap_auth_enabled ()
      && user_exists_method (name, AUTHENTICATION_METHOD_LDAP_CONNECT))
    return user_uuid_method (name, AUTHENTICATION_METHOD_LDAP_CONNECT);
  if (radius_auth_enabled ()
      && user_exists_method (name, AUTHENTICATION_METHOD_RADIUS_CONNECT))
    return user_uuid_method (name, AUTHENTICATION_METHOD_RADIUS_CONNECT);
  if (user_exists_method (name, AUTHENTICATION_METHOD_FILE))
    return user_uuid_method (name, AUTHENTICATION_METHOD_FILE);
  return NULL;
}

/**
 * @brief Add users to a group or role.
 *
 * Caller must take care of transaction.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Group or role.
 * @param[in]  users     List of users.
 *
 * @return 0 success, 2 failed to find user, 4 user name validation failed,
 *         99 permission denied, -1 error.
 */
int
add_users (const gchar *type, resource_t resource, const char *users)
{
  if (users)
    {
      gchar **split, **point;
      GList *added;

      /* Add each user. */

      added = NULL;
      split = g_strsplit_set (users, " ,", 0);
      point = split;

      while (*point)
        {
          user_t user;
          gchar *name;

          name = *point;

          g_strstrip (name);

          if (strcmp (name, "") == 0)
            {
              point++;
              continue;
            }

          if (g_list_find_custom (added, name, (GCompareFunc) strcmp))
            {
              point++;
              continue;
            }

          added = g_list_prepend (added, name);

          if (user_exists (name) == 0)
            {
              g_list_free (added);
              g_strfreev (split);
              return 2;
            }

          if (find_user_by_name (name, &user))
            {
              g_list_free (added);
              g_strfreev (split);
              return -1;
            }

          if (user == 0)
            {
              gchar *uuid;

              if (validate_username (name))
                {
                  g_list_free (added);
                  g_strfreev (split);
                  return 4;
                }

              uuid = user_uuid_any_method (name);

              if (uuid == NULL)
                {
                  g_list_free (added);
                  g_strfreev (split);
                  return -1;
                }

              if (sql_int ("SELECT count(*) FROM users WHERE uuid = '%s';",
                           uuid)
                  == 0)
                {
                  gchar *quoted_name;
                  quoted_name = sql_quote (name);
                  sql ("INSERT INTO users"
                       " (uuid, name, creation_time, modification_time)"
                       " VALUES"
                       " ('%s', '%s', m_now (), m_now ());",
                       uuid,
                       quoted_name);
                  g_free (quoted_name);

                  user = sql_last_insert_id ();
                }
              else
                {
                  /* find_user_by_name should have found it. */
                  assert (0);
                  g_free (uuid);
                  g_list_free (added);
                  g_strfreev (split);
                  return -1;
                }

              g_free (uuid);
            }

          if (find_user_by_name_with_permission (name, &user, "get_users"))
            {
              g_list_free (added);
              g_strfreev (split);
              return -1;
            }

          if (user == 0)
            {
              g_list_free (added);
              g_strfreev (split);
              return 99;
            }

          sql ("INSERT INTO %s_users (\"%s\", \"user\") VALUES (%llu, %llu);",
               type,
               type,
               resource,
               user);

          point++;
        }

      g_list_free (added);
      g_strfreev (split);
    }

  return 0;
}

/**
 * @brief Adds a new user to the GVM installation.
 *
 * @todo Adding users authenticating with certificates is not yet implemented.
 *
 * @param[in]  name         The name of the new user.
 * @param[in]  password     The password of the new user.
 * @param[in]  comment      Comment for the new user or NULL.
 * @param[in]  allowed_methods  Allowed login methods.
 * @param[out] r_errdesc    If not NULL the address of a variable to receive
 *                          a malloced string with the error description.  Will
 *                          always be set to NULL on success.
 * @param[out] new_user     Created user.
 *
 * @return 0 if the user has been added successfully, 99 permission denied,
 *         -1 on error, -2 if user exists already, -3 if wrong number of methods,
 *         -4 error in method.
 */
int
create_user (const gchar * name, const gchar * password, const gchar *comment,
             const array_t * allowed_methods, gchar **r_errdesc,
             user_t *new_user)
{
  char *errstr, *uuid;
  gchar *quoted_method, *quoted_name, *hash;
  gchar *quoted_comment, *generated;
  int ret;
  user_t user;


  assert (name);
  assert (password);

  if (r_errdesc)
    *r_errdesc = NULL;

  if (allowed_methods && (allowed_methods->len > 2))
    return -3;

  if (allowed_methods && (allowed_methods->len <= 1))
    allowed_methods = NULL;

  if (allowed_methods
      && (auth_method_name_valid (g_ptr_array_index (allowed_methods, 0))
          == 0))
    return -4;

  if (validate_username (name) != 0)
    {
      g_warning ("Invalid characters in user name!");
      if (r_errdesc)
        *r_errdesc = g_strdup ("Invalid characters in user name");
      return -1;
    }

  if (allowed_methods &&
      (!strcmp (g_ptr_array_index (allowed_methods, 0), "ldap_connect")
       || !strcmp (g_ptr_array_index (allowed_methods, 0), "radius_connect")))
    password = generated = gvm_uuid_make ();
  else
    generated = NULL;

  if ((errstr = gvm_validate_password (password, name)))
    {
      g_warning ("new password for '%s' rejected: %s", name, errstr);
      if (r_errdesc)
        *r_errdesc = errstr;
      else
        g_free (errstr);
      g_free (generated);
      return -1;
    }

  sql_begin_immediate ();

  if (acl_user_may ("create_user") == 0)
    {
      sql_rollback ();
      g_free (generated);
      return 99;
    }

  if (resource_with_name_exists_global (name, "user", 0))
    {
      sql_rollback ();
      g_free (generated);
      return -2;
    }

  quoted_name = sql_quote (name);
  hash = manage_authentication_hash (password);
  quoted_comment = sql_quote (comment ? comment : "");
  quoted_method = sql_quote (allowed_methods
                              ? g_ptr_array_index (allowed_methods, 0)
                              : "file");

  ret = sql_error ("INSERT INTO users"
                   " (uuid, owner, name, password, comment, method,"
                   "  creation_time, modification_time)"
                   " VALUES"
                   " (make_uuid (),"
                   "  (SELECT id FROM users WHERE uuid = '%s'),"
                   "  '%s', '%s', '%s', '%s', m_now (), m_now ());",
                   current_credentials.uuid,
                   quoted_name,
                   hash,
                   quoted_comment,
                   quoted_method);
  g_free (generated);
  g_free (hash);
  g_free (quoted_comment);
  g_free (quoted_method);
  g_free (quoted_name);

  if (ret == 3)
    {
      sql_rollback ();
      return -2;
    }
  else if (ret)
    {
      sql_rollback ();
      return -1;
    }

  user = sql_last_insert_id ();
  if (new_user)
    *new_user = user;

  uuid = user_uuid (user);
  if (uuid == NULL)
    {
      g_warning ("%s: Failed to allocate UUID", __func__);
      sql_rollback ();
      return -1;
    }
  g_free (uuid);

  sql_commit ();
  return 0;
}

int
delete_user (const char *user_id_arg, const char *name_arg,
             int forbid_super_admin,
             const char* inheritor_id, const char *inheritor_name)
{
  user_t user, inheritor, locked_user;


  assert (user_id_arg || name_arg);

  if (current_credentials.username && current_credentials.uuid)
    {
      if (user_id_arg && strcmp (user_id_arg, current_credentials.uuid) == 0)
        return 5;
      if (name_arg && strcmp (name_arg, current_credentials.username) == 0)
        return 5;
    }

  sql_begin_immediate ();
  sql ("LOCK TABLE users IN ROW SHARE MODE;");

  if (acl_user_may ("delete_user") == 0)
    {
      sql_rollback ();
      return 99;
    }

  user = 0;
  if (user_id_arg)
    {
      if (find_user_with_permission (user_id_arg, &user, "delete_user"))
        {
          sql_rollback ();
          return -1;
        }
    }
  else if (find_user_by_name_with_permission (name_arg, &user, "delete_user"))
    {
      sql_rollback ();
      return -1;
    }

  if (user == 0)
    {
      sql_rollback ();
      return 2;
    }

  switch (sql_int64 (&locked_user,
                     "SELECT id FROM users WHERE id = %llu FOR UPDATE;",
                     user))
    {
      case 0:
        if (locked_user != user)
          {
            sql_rollback ();
            return -1;
          }
        break;
      case 1:
        sql_rollback ();
        return 2;
      default:
        sql_rollback ();
        return -1;
    }

  if (sql_int ("SELECT count(*) <= 1 FROM users;"))
    {
      sql_rollback ();
      return 9;
    }

  inheritor = 0;
  if (inheritor_id && strcmp (inheritor_id, ""))
    {
      if (strcmp (inheritor_id, "self") == 0)
        sql_int64 (&inheritor, "SELECT id FROM users WHERE uuid = '%s'",
                   current_credentials.uuid);
      else if (find_user_with_permission (inheritor_id, &inheritor,
                                          "get_users"))
        {
          sql_rollback ();
          return -1;
        }
      if (inheritor == 0)
        {
          sql_rollback ();
          return 6;
        }
    }
  else if (inheritor_name && strcmp (inheritor_name, ""))
    {
      if (find_user_by_name_with_permission (inheritor_name, &inheritor,
                                             "get_users"))
        {
          sql_rollback ();
          return -1;
        }
      if (inheritor == 0)
        {
          sql_rollback ();
          return 6;
        }
    }

  if (inheritor == user)
    {
      sql_rollback ();
      return 7;
    }

  if (inheritor)
    sql ("DO $$ DECLARE r record; BEGIN"
         " FOR r IN SELECT table_name FROM information_schema.columns"
         "          WHERE table_schema = 'public' AND column_name = 'owner' LOOP"
         "   EXECUTE format('UPDATE %I SET owner = %s WHERE owner = %s',"
         "                  r.table_name, %llu, %llu);"
         " END LOOP; END $$;",
         inheritor,
         user);
  else
    sql ("DO $$ DECLARE r record; BEGIN"
         " FOR r IN SELECT table_name FROM information_schema.columns"
         "          WHERE table_schema = 'public' AND column_name = 'owner' LOOP"
         "   EXECUTE format('UPDATE %I SET owner = NULL WHERE owner = %s',"
         "                  r.table_name, %llu);"
         " END LOOP; END $$;",
         user);

  sql ("DELETE FROM settings WHERE owner = %llu;", user);
  sql ("DELETE FROM report_counts WHERE \"user\" = %llu;", user);
  sql ("DELETE FROM tag_resources"
       " WHERE resource_type = 'user' AND resource = %llu;",
       user);
  sql ("DELETE FROM tag_resources_trash"
       " WHERE resource_type = 'user' AND resource = %llu;",
       user);
  sql ("DELETE FROM users WHERE id = %llu;", user);

  sql_commit ();
  return 0;
}

int
copy_user (const char* name, const char* comment, const char *user_id,
           user_t* new_user)
{
  user_t user;
  int ret;

  sql_begin_immediate ();

  ret = copy_resource_lock ("user", name, comment, user_id,
                            "password, timezone, method",
                            1, &user, NULL);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  sql ("UPDATE users SET password = NULL WHERE id = %llu;", user);

  if (new_user)
    *new_user = user;

  sql_commit ();
  return 0;
}

int
modify_user (const gchar * user_id, gchar **name, const gchar *new_name,
             const gchar * password, const gchar * comment,
             const array_t * allowed_methods, gchar **r_errdesc)
{
  char *errstr;
  gchar *hash, *quoted_method, *uuid;
  gchar *quoted_new_name, *quoted_comment;
  user_t user;


  if (r_errdesc)
    *r_errdesc = NULL;

  if (allowed_methods && (allowed_methods->len > 2))
    return -3;

  if (allowed_methods && (allowed_methods->len <= 1))
    allowed_methods = NULL;

  if (allowed_methods && (strlen (g_ptr_array_index (allowed_methods, 0)) == 0))
    allowed_methods = NULL;

  if (allowed_methods
      && (auth_method_name_valid (g_ptr_array_index (allowed_methods, 0))
          == 0))
    return -4;

  sql_begin_immediate ();

  if (acl_user_may ("modify_user") == 0)
    {
      sql_rollback ();
      return 99;
    }

  user = 0;
  if (user_id)
    {
      if (find_user_with_permission (user_id, &user, "modify_user"))
        {
          sql_rollback ();
          return -1;
        }
    }
  else if (find_user_by_name_with_permission (*name, &user, "modify_user"))
    {
      sql_rollback ();
      return -1;
    }

  if (user == 0)
    {
      sql_rollback ();
      return 2;
    }

  uuid = sql_string ("SELECT uuid FROM users WHERE id = %llu", user);

  if (password)
    {
      char *user_name;

      user_name = sql_string ("SELECT name FROM users WHERE id = %llu", user);
      errstr = gvm_validate_password (password, user_name);
      if (errstr)
        {
          g_warning ("new password for '%s' rejected: %s", user_name, errstr);
          if (r_errdesc)
            *r_errdesc = errstr;
          else
            g_free (errstr);
          sql_rollback ();
          g_free (user_name);
          g_free (uuid);
          return -1;
        }
      g_free (user_name);
    }

  if (new_name)
    {
      if (validate_username (new_name) != 0)
        {
          sql_rollback ();
          g_free (uuid);
          return 7;
        }

      if (strcmp (uuid, current_credentials.uuid) == 0)
        {
          sql_rollback ();
          g_free (uuid);
          return 99;
        }

      if (resource_with_name_exists_global (new_name, "user", user))
        {
          sql_rollback ();
          g_free (uuid);
          return 8;
        }
      quoted_new_name = sql_quote (new_name);
    }
  else
    quoted_new_name = NULL;

  hash = password ? manage_authentication_hash (password) : NULL;
  quoted_comment = comment ? sql_quote (comment) : NULL;
  quoted_method = sql_quote (allowed_methods
                              ? g_ptr_array_index (allowed_methods, 0)
                              : "");

  sql ("UPDATE users"
       " SET name = %s%s%s,"
       "     comment = %s%s%s,"
       "     method = %s%s%s,"
       "     modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_new_name ? "'" : "",
       quoted_new_name ? quoted_new_name : "name",
       quoted_new_name ? "'" : "",
       quoted_comment ? "'" : "",
       quoted_comment ? quoted_comment : "comment",
       quoted_comment ? "'" : "",
       allowed_methods ? "'" : "",
       allowed_methods ? quoted_method : "method",
       allowed_methods ? "'" : "",
       user);
  g_free (quoted_new_name);
  g_free (quoted_method);
  g_free (quoted_comment);

  if (hash)
    sql ("UPDATE users SET password = '%s' WHERE id = %llu;", hash, user);
  g_free (hash);
  g_free (uuid);

  sql_commit ();
  return 0;
}

int
manage_create_user (GSList *log_config, const db_conn_info_t *database,
                    const gchar *name, const gchar *password,
                    const gchar *role_name)
{
  char *uuid;
  int ret;
  gchar *rejection_msg = NULL;

  (void) role_name;

  g_info ("   Creating user.");

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  uuid = password ? NULL : gvm_uuid_make ();

  current_credentials.uuid = "";

  ret = create_user (name, password ? password : uuid, "",
                     NULL, &rejection_msg, NULL);

  switch (ret)
    {
      case 0:
        if (password)
          printf ("User created.\n");
        else
          printf ("User created with password '%s'.\n", uuid);
        break;
      case -2:
        fprintf (stderr, "User exists already.\n");
        break;
      default:
        if (rejection_msg)
          fprintf (stderr, "Failed to create user: %s\n", rejection_msg);
        else
          fprintf (stderr, "Failed to create user.\n");
        break;
    }

  current_credentials.uuid = NULL;
  g_free (rejection_msg);
  free (uuid);
  manage_option_cleanup ();

  return ret ? -1 : 0;
}

int
manage_delete_user (GSList *log_config, const db_conn_info_t *database,
                    const gchar *name, const gchar *inheritor_name)
{
  int ret;

  g_info ("   Deleting user.");

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  /* Setup a dummy user, so that delete_user will work. */
  current_credentials.uuid = "";

  switch ((ret = delete_user (NULL, name, 0, NULL, inheritor_name)))
    {
      case 0:
        printf ("User deleted.\n");
        break;
      case 2:
        fprintf (stderr, "Failed to find user.\n");
        break;
      case 4:
        fprintf (stderr, "User has active tasks.\n");
        break;
      case 6:
        fprintf (stderr, "Inheritor not found.\n");
        break;
      case 7:
        fprintf (stderr, "Inheritor same as deleted user.\n");
        break;
      case 8:
        fprintf (stderr, "Invalid inheritor.\n");
        break;
      case 9:
        fprintf (stderr,
                 "Resources owned by the user are still in use by others.\n");
        break;
      case 10:
        fprintf (stderr, "User is Feed Import Owner.\n");
        break;
      default:
        fprintf (stderr, "Internal Error.\n");
        break;
    }

  current_credentials.uuid = NULL;

  manage_option_cleanup ();

  return ret;
}

/**
 * @brief List users.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 * @param[in]  role_name   Role name.
 * @param[in]  verbose     Whether to print UUID.
 *
 * @return 0 success, -1 error.
 */
int
manage_get_users (GSList *log_config, const db_conn_info_t *database,
                  const gchar* role_name, int verbose)
{
  iterator_t users;
  int ret;

  g_info ("   Getting users.");

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  (void) role_name;
  init_iterator (&users, "SELECT name, uuid FROM users;");
  while (next (&users))
    if (verbose)
      printf ("%s %s\n", iterator_string (&users, 0), iterator_string (&users, 1));
    else
      printf ("%s\n", iterator_string (&users, 0));

  cleanup_iterator (&users);

  manage_option_cleanup ();

  return 0;
}

/**
 * @brief Set the password of a user.
 *
 * @param[in]  name      Name of user.
 * @param[in]  uuid      User UUID.
 * @param[in]  password  New password.
 * @param[out] r_errdesc Address to receive a malloced string with the error
 *                       description, or NULL.
 *
 * @return 0 success, -1 error.
 */
int
set_password (const gchar *name, const gchar *uuid, const gchar *password,
              gchar **r_errdesc)
{
  gchar *errstr, *hash;

  assert (name && uuid);

  if ((errstr = gvm_validate_password (password, name)))
    {
      g_warning ("new password for '%s' rejected: %s", name, errstr);
      if (r_errdesc)
        *r_errdesc = errstr;
      else
        g_free (errstr);
      return -1;
    }
  hash = manage_authentication_hash (password);
  sql ("UPDATE users SET password = '%s', modification_time = m_now ()"
       " WHERE uuid = '%s';",
       hash,
       uuid);
  g_free (hash);
  return 0;
}

/**
 * @brief Set the password of a user.
 *
 * @param[in]  log_config      Log configuration.
 * @param[in]  database  Location of manage database.
 * @param[in]  name      Name of user.
 * @param[in]  password  New password.
 *
 * @return 0 success, -1 error.
 */
int
manage_set_password (GSList *log_config, const db_conn_info_t *database,
                     const gchar *name, const gchar *password)
{
  user_t user;
  char *uuid;
  int ret;
  gchar *rejection_msg;

  g_info ("   Modifying user password.");

  if (name == NULL)
    {
      fprintf (stderr, "--user required.\n");
      return -1;
    }

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  sql_begin_immediate ();

  if (find_user_by_name (name, &user))
    {
      fprintf (stderr, "Internal error.\n");
      goto fail;
    }

  if (user == 0)
    {
      fprintf (stderr, "Failed to find user.\n");
      goto fail;
    }

  uuid = user_uuid (user);
  if (uuid == NULL)
    {
      fprintf (stderr, "Failed to allocate UUID.\n");
      goto fail;
    }

  rejection_msg = NULL;
  if (set_password (name, uuid, password, &rejection_msg))
    {
      if (rejection_msg)
        {
          fprintf (stderr, "New password rejected: %s\n", rejection_msg);
          g_free (rejection_msg);
        }
      else
        fprintf (stderr, "New password rejected.\n");
      free (uuid);
      goto fail;
    }

  sql_commit ();
  free (uuid);
  manage_option_cleanup ();
  return ret;

 fail:
  sql_rollback ();
  manage_option_cleanup ();
  return -1;
}

/**
 * @brief  Get a GArray of all users as user_t.
 *
 * @return  Newly allocated GArray containing all users.
 */
GArray*
all_users_array ()
{
  iterator_t users_iter;
  GArray *ret;

  ret = g_array_new (TRUE, TRUE, sizeof (resource_t));

  init_iterator (&users_iter, "SELECT id FROM users;");

  while (next (&users_iter))
    {
      user_t user = iterator_int64 (&users_iter, 0);
      g_array_append_val (ret, user);
    }

  cleanup_iterator (&users_iter);

  return ret;
}

/**
 * @brief Set the timezone of the current user.
 *
 * @param[in]  zone  The timezone to set
 *
 * @return 0 success, 1 invalid timezone, 2 no current user
 */
int
current_user_set_timezone (const gchar *zone)
{
  if (manage_timezone_supported (zone) == FALSE)
    return 1;

  if (current_credentials.uuid == 0)
    return 2;

  sql_ps ("UPDATE users SET timezone = $1"
          " WHERE uuid = $2",
          SQL_STR_PARAM (zone),
          SQL_STR_PARAM (current_credentials.uuid),
          NULL);

  return 0;
}
