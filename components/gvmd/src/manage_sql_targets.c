/* Copyright (C) 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_targets.h"
#include "manage_acl.h"
#include "manage_sql_assets.h"
#include "manage_sql_permissions.h"
#include "manage_sql_port_lists.h"
#include "manage_sql_resources.h"
#include "manage_sql_tags.h"
#include "sql.h"

#include <assert.h>
#include <ctype.h>

/**
 * @file
 * @brief GVM management layer: Targets SQL
 *
 * The Targets SQL for the GVM management layer.
 */

/**
 * @brief Return number of hosts described by a hosts string.
 *
 * @param[in]  given_hosts      String describing hosts.
 * @param[in]  exclude_hosts    String describing hosts excluded from given set.
 *
 * @return Number of hosts, or -1 on error.
 */
int
manage_count_hosts (const char *given_hosts, const char *exclude_hosts)
{
  return manage_count_hosts_max (given_hosts,
                                 exclude_hosts,
                                 manage_max_hosts ());
}

/**
 * @brief Find a target for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of target.
 * @param[out]  target      Target return, 0 if successfully failed to find target.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find target), TRUE on error.
 */
gboolean
find_target_with_permission (const char* uuid, target_t* target,
                             const char *permission)
{
  return find_resource_with_permission ("target", uuid, target, permission, 0);
}

/**
 * @brief Return the UUID of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
target_uuid (target_t target)
{
  return sql_string ("SELECT uuid FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the UUID of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
trash_target_uuid (target_t target)
{
  return sql_string ("SELECT uuid FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the name of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
target_name (target_t target)
{
  return sql_string ("SELECT name FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the name of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
trash_target_name (target_t target)
{
  return sql_string ("SELECT name FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the comment of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
target_comment (target_t target)
{
  return sql_string ("SELECT comment FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the comment of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
trash_target_comment (target_t target)
{
  return sql_string ("SELECT comment FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return a target's alive tests.
 *
 * @param[in]  target  Target.
 *
 * @return Alive test bitfield.
 */
alive_test_t
target_alive_tests (target_t target)
{
  return sql_int ("SELECT alive_test FROM targets WHERE id = %llu;",
                  target);
}

/**
 * @brief Return the hosts associated with a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated comma separated list of hosts if available,
 *         else NULL.
 */
char*
target_hosts (target_t target)
{
  return sql_string ("SELECT hosts FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the excluded hosts associated with a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated comma separated list of excluded hosts if available,
 *         else NULL.
 */
char*
target_exclude_hosts (target_t target)
{
  return sql_string ("SELECT exclude_hosts FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the reverse_lookup_only value of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Reverse lookup only value if available, else NULL.
 */
char*
target_reverse_lookup_only (target_t target)
{
  return sql_string ("SELECT reverse_lookup_only FROM targets"
                     " WHERE id = %llu;", target);
}

/**
 * @brief Return the reverse_lookup_unify value of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Reverse lookup unify value if available, else NULL.
 */
char*
target_reverse_lookup_unify (target_t target)
{
  return sql_string ("SELECT reverse_lookup_unify FROM targets"
                     " WHERE id = %llu;", target);
}

/**
 * @brief Get a login port from a target.
 *
 * @param[in]  target         The target.
 * @param[in]  type           The credential type (e.g. "ssh" or "smb").
 *
 * @return  0 on success, -1 on error, 1 credential not found, 99 permission
 *          denied.
 */
static int
target_login_port (target_t target, const char* type)
{
  gchar *quoted_type;
  int port;

  if (target == 0 || type == NULL)
    return 0;

  quoted_type = sql_quote (type);

  if (sql_int ("SELECT NOT EXISTS"
               " (SELECT * FROM targets_login_data"
               "  WHERE target = %llu and type = '%s');",
               target, quoted_type))
    {
      g_free (quoted_type);
      return 0;
    }

  port = sql_int ("SELECT port FROM targets_login_data"
                  " WHERE target = %llu AND type = '%s';",
                  target, quoted_type);

  g_free (quoted_type);

  return port;
}

/**
 * @brief Return the SSH LSC port of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated port if available, else NULL.
 */
char*
target_ssh_port (target_t target)
{
  int port = target_login_port (target, "ssh");
  return port ? g_strdup_printf ("%d", port) : NULL;
}

/**
 * @brief Return the SSH server host-key pins associated with a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated canonical JSON pin data, or NULL.
 */
char *
target_ssh_host_key_pins (target_t target)
{
  if (target == 0)
    return NULL;

  return sql_string ("SELECT host_key_pins FROM targets_login_data"
                     " WHERE target = %llu AND type = 'ssh';",
                     target);
}

/**
 * @brief Get a credential from a target.
 *
 * @param[in]  target         The target.
 * @param[in]  type           The credential type (e.g. "ssh" or "smb").
 *
 * @return  0 on success, -1 on error, 1 credential not found, 99 permission
 *          denied.
 */
credential_t
target_credential (target_t target, const char* type)
{
  gchar *quoted_type;
  credential_t credential;

  if (target == 0 || type == NULL)
    return 0;

  quoted_type = sql_quote (type);

  if (sql_int ("SELECT NOT EXISTS"
               " (SELECT * FROM targets_login_data"
               "  WHERE target = %llu and type = '%s');",
               target, quoted_type))
    {
      g_free (quoted_type);
      return 0;
    }

  sql_int64 (&credential,
             "SELECT credential FROM targets_login_data"
             " WHERE target = %llu AND type = '%s';",
             target, quoted_type);

  g_free (quoted_type);

  return credential;
}

/**
 * @brief Return the SSH credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return SSH credential if any, else 0.
 */
credential_t
target_ssh_credential (target_t target)
{
  return target_credential (target, "ssh");
}

/**
 * @brief Return the SMB credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return SMB credential if any, else 0.
 */
credential_t
target_smb_credential (target_t target)
{
  return target_credential (target, "smb");
}

/**
 * @brief Return the ESXi credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return ESXi credential if any, else 0.
 */
credential_t
target_esxi_credential (target_t target)
{
  return target_credential (target, "esxi");
}

/**
 * @brief Return the ELEVATE credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return ELEVATE credential if any, else 0.
 */
credential_t
target_ssh_elevate_credential (target_t target)
{
  return target_credential (target, "elevate");
}

/**
 * @brief Return the Kerberos 5 credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return Kerberos 5 credential if any, else 0.
 */
credential_t
target_krb5_credential (target_t target)
{
  return target_credential (target, "krb5");
}

/**
 * @brief Count number of targets.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of targets in filtered set.
 */
int
target_count (const get_data_t *get)
{
  static const char *extra_columns[] = TARGET_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = TARGET_ITERATOR_COLUMNS;
  static column_t trash_columns[] = TARGET_ITERATOR_TRASH_COLUMNS;
  return count ("target", get, columns, trash_columns, extra_columns, 0, 0, 0,
                TRUE);
}

/**
 * @brief Initialise a target iterator, including observed targets.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_target_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = TARGET_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = TARGET_ITERATOR_COLUMNS;
  static column_t trash_columns[] = TARGET_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "target",
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
 * @brief Get the hosts of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Hosts of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_hosts, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the SSH LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return SSH LSC credential.
 */
int
target_iterator_ssh_credential (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
  return ret;
}

/**
 * @brief Get the SSH LSC port of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return SSH LSC port of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_ssh_port, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the SMB LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return SMB LSC credential.
 */
int
target_iterator_smb_credential (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
  return ret;
}

/**
 * @brief Get the location of the SSH LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 0 in table, 1 in trash
 */
int
target_iterator_ssh_trash (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
  return ret;
}

/**
 * @brief Get the location of the SMB LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 0 in table, 1 in trash
 */
int
target_iterator_smb_trash (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
  return ret;
}

/**
 * @brief Get the port list uuid of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID of the target port list or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_port_list_uuid, GET_ITERATOR_COLUMN_COUNT + 7);

/**
 * @brief Get the port list name of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the target port list or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_port_list_name, GET_ITERATOR_COLUMN_COUNT + 8);

/**
 * @brief Get the location of the port list from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 0 in table, 1 in trash.
 */
int
target_iterator_port_list_trash (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 9);
  return ret;
}

/**
 * @brief Get the excluded hosts of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Excluded hosts of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_exclude_hosts, GET_ITERATOR_COLUMN_COUNT + 10);

/**
 * @brief Get the reverse lookup only value from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Reverse lookup only of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_reverse_lookup_only,
            GET_ITERATOR_COLUMN_COUNT + 11);

/**
 * @brief Get the reverse lookup unify value from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Reverse lookup unify of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_reverse_lookup_unify,
            GET_ITERATOR_COLUMN_COUNT + 12);

/**
 * @brief Get the alive_tests value from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Alive_tests of the target or -1 if iteration is complete.
 */
int
target_iterator_alive_tests (iterator_t* iterator)
{
  if (iterator->done)
    return -1;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 13);
}

/**
 * @brief Get the ESXi LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return ESXi LSC credential.
 */
int
target_iterator_esxi_credential (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 14);
  return ret;
}

/**
 * @brief Get the ESXi LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return ESXi LSC credential.
 */
int
target_iterator_esxi_trash (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 15);
  return ret;
}

/**
 * @brief Get the SNMP LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return ESXi LSC credential.
 */
int
target_iterator_snmp_credential (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 16);
  return ret;
}

/**
 * @brief Get the SNMP LSC credential location from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return ESXi LSC credential.
 */
int
target_iterator_snmp_trash (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 17);
  return ret;
}

/**
 * @brief Get the ELEVATE LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return ELEVATE LSC credential.
 */
int
target_iterator_ssh_elevate_credential (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 18);
  return ret;
}

/**
 * @brief Get the ELEVATE LSC credential location from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return ELEVATE LSC credential.
 */
int
target_iterator_ssh_elevate_trash (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 19);
  return ret;
}

/**
 * @brief Get the Kerberos 5 LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Kerberos 5 LSC credential.
 */
int
target_iterator_krb5_credential (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 20);
  return ret;
}

/**
 * @brief Get the Kerberos 5 LSC credential location from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Kerberos 5 LSC credential.
 */
int
target_iterator_krb5_trash (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 21);
  return ret;
}

/**
 * @brief Get the allow_simultaneous_ips value from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return allow_simult_ips_same_host or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_allow_simultaneous_ips,
            GET_ITERATOR_COLUMN_COUNT + 22);

/**
 * @brief Initialise a target task iterator.
 *
 * Iterates over all tasks that use the target.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  target     Target.
 */
void
init_target_task_iterator (iterator_t* iterator, target_t target)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (target);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_tasks"));
  available = acl_where_owned ("task", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT name, uuid, %s FROM tasks"
                 " WHERE target = %llu"
                 " AND hidden = 0"
                 " ORDER BY name ASC;",
                 with_clause ? with_clause : "",
                 available,
                 target);

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the name from a target_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the host, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (target_task_iterator_name, 0);

/**
 * @brief Get the uuid from a target_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The uuid of the host, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (target_task_iterator_uuid, 1);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
target_task_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 2);
}

/**
 * @brief Return whether a target is in use by a task.
 *
 * @param[in]  target  Target.
 *
 * @return 1 if in use, else 0.
 */
int
target_in_use (target_t target)
{
  return !!sql_int ("SELECT count(*) FROM tasks"
                    " WHERE target = %llu"
                    " AND target_location = " G_STRINGIFY (LOCATION_TABLE)
                    " AND hidden = 0;",
                    target);
}

/**
 * @brief Return whether a trashcan target is referenced by a task.
 *
 * @param[in]  target  Target.
 *
 * @return 1 if in use, else 0.
 */
int
trash_target_in_use (target_t target)
{
  return !!sql_int ("SELECT count(*) FROM tasks"
                    " WHERE target = %llu"
                    " AND target_location = " G_STRINGIFY (LOCATION_TRASH),
                    target);
}

/**
 * @brief Return the port list associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return Port list
 */
static port_list_t
target_port_list (target_t target)
{
  port_list_t port_list;

  switch (sql_int64 (&port_list,
                     "SELECT port_list FROM targets"
                     " WHERE id = %llu;",
                     target))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        return 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        /** @todo Move return to arg; return -1. */
        return 0;
        break;
    }
  return port_list;
}

/**
 * @brief Return the port range of a target, in GMP port range list format.
 *
 * For "OpenVAS Default", return the explicit port ranges instead of "default".
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated port range if available, else NULL.
 */
char*
target_port_range (target_t target)
{
  GString *range;
  iterator_t ranges;
  range = g_string_new ("");
  init_port_range_iterator (&ranges, target_port_list (target), 0, 1,
                            "type, CAST (start AS INTEGER)");
  if (next (&ranges))
    {
      const char *start, *end;
      int type;

      start = port_range_iterator_start (&ranges);
      end = port_range_iterator_end (&ranges);
      type = port_range_iterator_type_int (&ranges);

      /* Scanner can only handle: T:1-3,5-6,9,U:1-2 */

      if (end && strcmp (end, "0") && strcmp (end, start))
        g_string_append_printf (range, "%s%s-%s",
                                (type == PORT_PROTOCOL_UDP ? "U:" : "T:"),
                                start, end);
      else
        g_string_append_printf (range, "%s%s",
                                (type == PORT_PROTOCOL_UDP ? "U:" : "T:"),
                                start);
      while (next (&ranges))
        {
          int tcp;

          start = port_range_iterator_start (&ranges);
          end = port_range_iterator_end (&ranges);
          tcp = (type == PORT_PROTOCOL_TCP);
          type = port_range_iterator_type_int (&ranges);

          if (end && strcmp (end, "0") && strcmp (end, start))
            g_string_append_printf (range, ",%s%s-%s",
                                    (tcp && type == PORT_PROTOCOL_UDP ? "U:" : ""),
                                    start, end);
          else
            g_string_append_printf (range, ",%s%s",
                                    (tcp && type == PORT_PROTOCOL_UDP ? "U:" : ""),
                                    start);
        }
    }
  cleanup_iterator (&ranges);
  return g_string_free (range, FALSE);
}
