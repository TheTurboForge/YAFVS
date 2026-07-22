/* Copyright (C) 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_overrides.h"
#include "manage_acl.h"
#include "manage_sql_filters.h"
#include "manage_sql_settings.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Count number of overrides.
 *
 * @param[in]  get         GET params.
 * @param[in]  result      Result to limit overrides to, 0 for all.
 * @param[in]  task        If result is > 0, task whose overrides on result to
 *                         include, otherwise task to limit overrides to.  0 for
 *                         all tasks.
 * @param[in]  nvt         NVT to limit overrides to, 0 for all.
 *
 * @return Total number of overrides in filtered set.
 */
int
override_count (const get_data_t *get, nvt_t nvt, result_t result, task_t task)
{
  static const char *filter_columns[] = OVERRIDE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OVERRIDE_ITERATOR_COLUMNS;
  static column_t trash_columns[] = OVERRIDE_ITERATOR_TRASH_COLUMNS;
  gchar *result_clause, *filter, *task_id;
  int ret;

  /* Treat the "task_id" filter keyword as if the task was given in "task". */

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      filter = filter_term (get->filt_id);
      if (filter == NULL)
        return 2;
    }
  else
    filter = NULL;

  task_id = filter_term_value (filter ? filter : get->filter, "task_id");

  g_free (filter);

  if (task_id)
    {
      find_task_with_permission (task_id, &task, "get_tasks");
      g_free (task_id);
    }

  if (result)
    {
      gchar *severity_sql;

      if (setting_dynamic_severity_int ())
        severity_sql = g_strdup_printf ("(SELECT CASE"
                                        " WHEN results.severity"
                                        "      > " G_STRINGIFY (SEVERITY_LOG)
                                        " THEN CAST (nvts.cvss_base AS real)"
                                        " ELSE results.severity END"
                                        " FROM results, nvts"
                                        " WHERE (nvts.oid = results.nvt)"
                                        "   AND (results.id = %llu))",
                                        result);
      else
        severity_sql = g_strdup_printf ("(SELECT results.severity"
                                        " FROM results"
                                        " WHERE results.id = %llu)",
                                        result);

      result_clause = g_strdup_printf (" AND"
                                       " (result = %llu"
                                       "  OR (result = 0 AND nvt ="
                                       "      (SELECT results.nvt FROM results"
                                       "       WHERE results.id = %llu)))"
                                       " AND (hosts is NULL"
                                       "      OR hosts = ''"
                                       "      OR hosts_contains (hosts,"
                                       "      (SELECT results.host FROM results"
                                       "       WHERE results.id = %llu)))"
                                       " AND (port is NULL"
                                       "      OR port = ''"
                                       "      OR port ="
                                       "      (SELECT results.port FROM results"
                                       "       WHERE results.id = %llu))"
                                       " AND (severity_matches_ov (%s,"
                                       "                           severity))"
                                       " AND (task = 0 OR task = %llu)",
                                       result,
                                       result,
                                       result,
                                       result,
                                       severity_sql,
                                       task);

      g_free (severity_sql);
    }
  else if (task)
    {
      result_clause = g_strdup_printf
                       (" AND (overrides.task = %llu OR overrides.task = 0)"
                        " AND nvt IN"
                        " (SELECT DISTINCT nvt FROM results"
                        "  WHERE results.task = %llu)"
                        " AND (overrides.result = 0"
                        "      OR (SELECT task FROM results"
                        "          WHERE results.id = overrides.result)"
                        "         = %llu)",
                        task,
                        task,
                        task);
    }
  else if (nvt)
    {
      result_clause = g_strdup_printf
                       (" AND (overrides.nvt"
                        "      = (SELECT oid FROM nvts WHERE nvts.id = %llu))",
                        nvt);
    }
  else
    result_clause = NULL;

  ret = count ("override",
               get,
               columns,
               trash_columns,
               filter_columns,
               task || nvt,
               NULL,
               result_clause,
               TRUE);

  g_free (result_clause);

  return ret;
}

/**
 * @brief Initialise an override iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 * @param[in]  result      Result to limit overrides to, 0 for all.
 * @param[in]  task        If result is > 0, task whose overrides on result to
 *                         include, otherwise task to limit overrides to.  0 for
 *                         all tasks.
 * @param[in]  nvt         NVT to limit overrides to, 0 for all.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_override_iterator (iterator_t* iterator, const get_data_t *get, nvt_t nvt,
                        result_t result, task_t task)
{
  static const char *filter_columns[] = OVERRIDE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OVERRIDE_ITERATOR_COLUMNS;
  static column_t trash_columns[] = OVERRIDE_ITERATOR_TRASH_COLUMNS;
  gchar *result_clause, *filter, *task_id;
  int ret;

  assert (current_credentials.uuid);
  assert ((nvt && get->id) == 0);
  assert ((task && get->id) == 0);

  assert (result ? nvt == 0 : 1);
  assert (task ? nvt == 0 : 1);

  /* Treat the "task_id" filter keyword as if the task was given in "task". */

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      filter = filter_term (get->filt_id);
      if (filter == NULL)
        return 2;
    }
  else
    filter = NULL;

  task_id = filter_term_value (filter ? filter : get->filter, "task_id");

  g_free (filter);

  if (task_id)
    {
      find_task_with_permission (task_id, &task, "get_tasks");
      g_free (task_id);
    }

  if (result)
    {
      gchar *severity_sql;

      if (setting_dynamic_severity_int ())
        severity_sql = g_strdup_printf ("(SELECT CASE"
                                        " WHEN results.severity"
                                        "      > " G_STRINGIFY (SEVERITY_LOG)
                                        " THEN CAST (nvts.cvss_base AS real)"
                                        " ELSE results.severity END"
                                        " FROM results, nvts"
                                        " WHERE (nvts.oid = results.nvt)"
                                        "   AND (results.id = %llu))",
                                        result);
      else
        severity_sql = g_strdup_printf ("(SELECT results.severity"
                                        " FROM results"
                                        " WHERE results.id = %llu)",
                                        result);

      result_clause = g_strdup_printf (" AND"
                                       " (result = %llu"
                                       "  OR (result = 0 AND nvt ="
                                       "      (SELECT results.nvt FROM results"
                                       "       WHERE results.id = %llu)))"
                                       " AND (hosts is NULL"
                                       "      OR hosts = ''"
                                       "      OR hosts_contains (hosts,"
                                       "      (SELECT results.host FROM results"
                                       "       WHERE results.id = %llu)))"
                                       " AND (port is NULL"
                                       "      OR port = ''"
                                       "      OR port ="
                                       "      (SELECT results.port FROM results"
                                       "       WHERE results.id = %llu))"
                                       " AND (severity_matches_ov (%s,"
                                       "                           severity))"
                                       " AND (task = 0 OR task = %llu)",
                                       result,
                                       result,
                                       result,
                                       result,
                                       severity_sql,
                                       task);

      g_free (severity_sql);
    }
  else if (task)
    {
      result_clause = g_strdup_printf
                       (" AND (overrides.task = %llu OR overrides.task = 0)"
                        " AND nvt IN"
                        " (SELECT DISTINCT nvt FROM results"
                        "  WHERE results.task = %llu)"
                        " AND (overrides.result = 0"
                        "      OR (SELECT task FROM results"
                        "          WHERE results.id = overrides.result)"
                        "         = %llu)",
                        task,
                        task,
                        task);
    }
  else if (nvt)
    {
      result_clause = g_strdup_printf
                       (" AND (overrides.nvt = (SELECT oid FROM nvts"
                       "                        WHERE nvts.id = %llu))",
                        nvt);
    }
  else
    result_clause = NULL;

  ret = init_get_iterator (iterator,
                           "override",
                           get,
                           columns,
                           trash_columns,
                           filter_columns,
                           task || nvt,
                           NULL,
                           result_clause,
                           TRUE);

  g_free (result_clause);

  return ret;
}

/**
 * @brief Initialise an override iterator not limited to result, task or NVT.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_override_iterator_all (iterator_t* iterator, get_data_t *get)
{
  return init_override_iterator (iterator, get, 0, 0, 0);
}

/**
 * @brief Get the NVT OID from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_nvt_oid, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the text from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Text, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_text, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the hosts from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Hosts, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_hosts, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the port from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Port, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_port, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the threat from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Threat.
 */
const char *
override_iterator_threat (iterator_t *iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
  return ret;
}

/**
 * @brief Get the threat from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Threat.
 */
const char *
override_iterator_new_threat (iterator_t *iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
  return ret;
}

/**
 * @brief Get the task from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The task associated with the override, or 0 on error.
 */
task_t
override_iterator_task (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
}

/**
 * @brief Get the result from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The result associated with the override, or 0 on error.
 */
result_t
override_iterator_result (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (result_t) iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
}

/**
 * @brief Get the end time from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time until which override applies.  0 for always.  1 means the
 *         override has been explicitly turned off.
 */
time_t
override_iterator_end_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 8);
  return ret;
}

/**
 * @brief Get the active status from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if active, else 0.
 */
int
override_iterator_active (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 9);
  return ret;
}

/**
 * @brief Get the NVT name from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_nvt_name, GET_ITERATOR_COLUMN_COUNT + 10);

/**
 * @brief Get the NVT type from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT type, or NULL.  Static string.
 */
const char *
override_iterator_nvt_type (iterator_t *iterator)
{
  const char *oid;

  oid = override_iterator_nvt_oid (iterator);
  if (oid == NULL)
    return NULL;

  if (g_str_has_prefix (oid, "CVE-"))
    return "cve";

  return "nvt";
}

/**
 * @brief Get the severity from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity score to which the override applies or NULL if
 *         iteration is complete, Freed by cleanup_iterator.
 */
DEF_ACCESS (override_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 14);

/**
 * @brief Get the new severity from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity score to override to or NULL if
 *         iteration is complete, Freed by cleanup_iterator.
 */
DEF_ACCESS (override_iterator_new_severity, GET_ITERATOR_COLUMN_COUNT + 15);
