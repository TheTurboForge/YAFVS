/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 * YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for Greenbone Management Protocol communication.
 *
 * This provides higher level, GMP-aware, facilities for working with with
 * the Greenbone Vulnerability Manager.
 *
 * There are examples of using this interface in the gvm tests.
 */

#include "gmp.h"

#include "../util/serverutils.h" /* for gvm_server_sendf, gvm_server_sendf_xml */

#include <errno.h>  /* for ERANGE, errno */
#include <stdlib.h> /* for NULL, strtol, atoi */
#include <strings.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm gmp"

#define GMP_FMT_BOOL_ATTRIB(var, attrib) \
  (var.attrib == 0 ? " " #attrib "=\"0\"" : " " #attrib "=\"1\"")

#define GMP_FMT_STRING_ATTRIB(var, attrib)                                \
  (var.attrib ? " " #attrib "= \"" : ""), (var.attrib ? var.attrib : ""), \
    (var.attrib ? "\"" : "")

/* GMP. */

/**
 * @brief Get the task status from a GMP GET_TASKS response.
 *
 * @param[in]  response   GET_TASKS response.
 *
 * @return The entity_text of the status entity if the entity is found, else
 *         NULL.
 */
const char *
gmp_task_status (entity_t response)
{
  entity_t task = entity_child (response, "task");
  if (task)
    {
      entity_t status = entity_child (task, "status");
      if (status)
        return entity_text (status);
    }
  return NULL;
}

/**
 * @brief Read response and convert status of response to a return value.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  entity   Entity containing response when GMP response code
 *                      is 2xx, else NULL.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
static int
gmp_check_response (gnutls_session_t *session, entity_t *entity)
{
  int ret;
  const char *status;

  /* Read the response. */

  *entity = NULL;
  if (read_entity (session, entity))
    return -1;

  /* Check the response. */

  status = entity_attribute (*entity, "status");
  if (status == NULL)
    {
      free_entity (*entity);
      *entity = NULL;
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (*entity);
      *entity = NULL;
      return -1;
    }
  if (status[0] == '2')
    {
      return 0;
    }
  ret = (int) strtol (status, NULL, 10);
  free_entity (*entity);
  *entity = NULL;
  if (errno == ERANGE)
    return -1;
  return ret;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  username  Username.
 * @param[in]  password  Password.
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         -1 on error.
 */
int
gmp_authenticate (gnutls_session_t *session, const char *username,
                  const char *password)
{
  entity_t entity;
  int ret;

  /* Send the auth request. */
  ret = gvm_server_sendf_xml_quiet (session,
                                    "<authenticate><credentials>"
                                    "<username>%s</username>"
                                    "<password>%s</password>"
                                    "</credentials></authenticate>",
                                    username ? username : "",
                                    password ? password : "");
  if (ret)
    return ret;

  /* Read the response. */

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    {
      free_entity (entity);
      return ret;
    }
  else if (ret == -1)
    return ret;
  return 2;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]     session  Pointer to GNUTLS session.
 * @param[in,out] opts     In: Struct containing the options to apply.
 *                         Out: Additional account information if authentication
 *                              was successful.
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, -1 on error.
 */
int
gmp_authenticate_info_ext (gnutls_session_t *session,
                           gmp_authenticate_info_opts_t opts)
{
  entity_t entity;
  const char *status;
  char first;
  int ret;

  *(opts.timezone) = NULL;
  if (opts.user_uuid)
    *opts.user_uuid = NULL;

  /* Send the auth request. */

  ret = gvm_server_sendf_xml_quiet (session,
                                    "<authenticate><credentials>"
                                    "<username>%s</username>"
                                    "<password>%s</password>"
                                    "</credentials></authenticate>",
                                    opts.username, opts.password);
  if (ret)
    return ret;

  /* Read the response. */

  entity = NULL;
  switch (try_read_entity (session, opts.timeout, &entity))
    {
    case 0:
      break;
    case -4:
      return 3;
    default:
      return -1;
    }

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  if (first == '2')
    {
      entity_t timezone_entity, role_entity, pw_warn_entity, user_uuid_entity;
      /* Get the extra info. */
      timezone_entity = entity_child (entity, "timezone");
      if (timezone_entity)
        *opts.timezone = g_strdup (entity_text (timezone_entity));
      role_entity = entity_child (entity, "role");
      if (role_entity)
        *opts.role = g_strdup (entity_text (role_entity));
      pw_warn_entity = entity_child (entity, "password_warning");
      if (pw_warn_entity)
        *(opts.pw_warning) = g_strdup (entity_text (pw_warn_entity));
      else
        *(opts.pw_warning) = NULL;
      user_uuid_entity = entity_child (entity, "user_uuid");
      if (user_uuid_entity && opts.user_uuid)
        *opts.user_uuid = g_strdup (entity_text (user_uuid_entity));

      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 2;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]  connection  Connection
 * @param[in]  opts        Struct containing the options to apply.
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, -1 on error.
 */
int
gmp_authenticate_info_ext_c (gvm_connection_t *connection,
                             gmp_authenticate_info_opts_t opts)
{
  entity_t entity;
  const char *status;
  char first;
  int ret;

  if (opts.role)
    *opts.role = NULL;
  if (opts.timezone)
    *opts.timezone = NULL;
  if (opts.pw_warning)
    *opts.pw_warning = NULL;
  if (opts.jwt)
    *opts.jwt = NULL;
  if (opts.user_uuid)
    *opts.user_uuid = NULL;

  /* Send the auth request. */

  ret = gvm_connection_sendf_xml_quiet (connection,
                                        "<authenticate token=\"%d\">"
                                        "<credentials>"
                                        "<username>%s</username>"
                                        "<password>%s</password>"
                                        "</credentials>"
                                        "</authenticate>",
                                        opts.jwt_requested, opts.username,
                                        opts.password);
  if (ret)
    return ret;

  /* Read the response. */

  entity = NULL;
  switch (try_read_entity_c (connection, opts.timeout, &entity))
    {
    case 0:
      break;
    case -4:
      return 3;
    default:
      return -1;
    }

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  if (first == '2')
    {
      entity_t timezone_entity, role_entity, token_entity, user_uuid_entity;
      /* Get the extra info. */
      timezone_entity = entity_child (entity, "timezone");
      if (timezone_entity && opts.timezone)
        *opts.timezone = g_strdup (entity_text (timezone_entity));
      role_entity = entity_child (entity, "role");
      if (role_entity && opts.role)
        *opts.role = g_strdup (entity_text (role_entity));
      if (opts.pw_warning)
        {
          entity_t pw_warn_entity;
          pw_warn_entity = entity_child (entity, "password_warning");
          if (pw_warn_entity)
            *(opts.pw_warning) = g_strdup (entity_text (pw_warn_entity));
          else
            *(opts.pw_warning) = NULL;
        }
      token_entity = entity_child (entity, "token");
      if (token_entity && opts.jwt_requested == 1 && opts.jwt)
        *opts.jwt = g_strdup (entity_text (token_entity));
      user_uuid_entity = entity_child (entity, "user_uuid");
      if (user_uuid_entity && opts.user_uuid)
        *opts.user_uuid = g_strdup (entity_text (user_uuid_entity));

      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 2;
}

/**
 * @brief Create a task.
 *
 * FIXME: Using the according opts it should be possible to generate
 * any type of create_task request defined by the spec.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out]  id       Pointer for newly allocated ID of new task, or NULL.
 *                       Only set on successful return.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_task_ext (gnutls_session_t *session, gmp_create_task_opts_t opts,
                     gchar **id)
{
  /* Create the GMP request. */

  gchar *prefs, *start, *scanner, *schedule, *slave;
  GString *alerts, *observers;
  int ret;
  if ((opts.config_id == NULL) || (opts.target_id == NULL))
    return -1;

  prefs = NULL;
  start = g_markup_printf_escaped (
    "<create_task>"
    "<config id=\"%s\"/>"
    "<target id=\"%s\"/>"
    "<name>%s</name>"
    "<comment>%s</comment>"
    "<alterable>%d</alterable>",
    opts.config_id, opts.target_id, opts.name ? opts.name : "unnamed",
    opts.comment ? opts.comment : "", opts.alterable ? 1 : 0);

  if (opts.scanner_id)
    scanner = g_strdup_printf ("<scanner id=\"%s\"/>", opts.scanner_id);
  else
    scanner = NULL;

  if (opts.schedule_id)
    schedule = g_strdup_printf ("<schedule id=\"%s\"/>"
                                "<schedule_periods>%d</schedule_periods>",
                                opts.schedule_id, opts.schedule_periods);
  else
    schedule = NULL;

  if (opts.slave_id)
    slave = g_strdup_printf ("<slave id=\"%s\"/>", opts.slave_id);
  else
    slave = NULL;

  if (opts.max_checks || opts.max_hosts || opts.in_assets || opts.source_iface)
    {
      gchar *in_assets, *checks, *hosts, *source_iface;

      in_assets = checks = hosts = source_iface = NULL;

      if (opts.in_assets)
        in_assets = g_markup_printf_escaped ("<preference>"
                                             "<scanner_name>"
                                             "in_assets"
                                             "</scanner_name>"
                                             "<value>"
                                             "%s"
                                             "</value>"
                                             "</preference>",
                                             opts.in_assets);

      if (opts.max_hosts)
        hosts = g_markup_printf_escaped ("<preference>"
                                         "<scanner_name>"
                                         "max_hosts"
                                         "</scanner_name>"
                                         "<value>"
                                         "%s"
                                         "</value>"
                                         "</preference>",
                                         opts.max_hosts);

      if (opts.max_checks)
        checks = g_markup_printf_escaped ("<preference>"
                                          "<scanner_name>"
                                          "max_checks"
                                          "</scanner_name>"
                                          "<value>"
                                          "%s"
                                          "</value>"
                                          "</preference>",
                                          opts.max_checks);

      if (opts.source_iface)
        source_iface = g_markup_printf_escaped ("<preference>"
                                                "<scanner_name>"
                                                "source_iface"
                                                "</scanner_name>"
                                                "<value>"
                                                "%s"
                                                "</value>"
                                                "</preference>",
                                                opts.source_iface);

      prefs =
        g_strdup_printf ("<preferences>%s%s%s%s</preferences>",
                         in_assets ? in_assets : "", checks ? checks : "",
                         hosts ? hosts : "", source_iface ? source_iface : "");
      g_free (in_assets);
      g_free (checks);
      g_free (hosts);
      g_free (source_iface);
    }

  if (opts.alert_ids)
    {
      unsigned int i;
      alerts = g_string_new ("");
      for (i = 0; i < opts.alert_ids->len; i++)
        {
          char *alert = (char *) g_ptr_array_index (opts.alert_ids, i);
          g_string_append_printf (alerts, "<alert id=\"%s\"/>", alert);
        }
    }
  else
    alerts = g_string_new ("");

  if (opts.observers || opts.observer_groups)
    {
      observers = g_string_new ("<observers>");

      if (opts.observers)
        g_string_append (observers, opts.observers);

      if (opts.observer_groups)
        {
          unsigned int i;
          for (i = 0; i < opts.observer_groups->len; i++)
            {
              char *group =
                (char *) g_ptr_array_index (opts.observer_groups, i);
              g_string_append_printf (observers, "<group id=\"%s\"/>", group);
            }
        }
      g_string_append (observers, "</observers>");
    }
  else
    observers = g_string_new ("");

  /* Send the request. */
  ret = gvm_server_sendf (
    session, "%s%s%s%s%s%s%s</create_task>", start, prefs ? prefs : "",
    scanner ? scanner : "", schedule ? schedule : "", slave ? slave : "",
    alerts ? alerts->str : "", observers ? observers->str : "");
  g_free (start);
  g_free (prefs);
  g_free (scanner);
  g_free (schedule);
  g_free (slave);
  g_string_free (alerts, TRUE);
  g_string_free (observers, TRUE);

  if (ret)
    return -1;

  /* Read the response. */

  ret = gmp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create a task given a config and target.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   name        Task name.
 * @param[in]   config      Task config name.
 * @param[in]   target      Task target name.
 * @param[in]   comment     Task comment.
 * @param[out]  id          Pointer for newly allocated ID of new task.  Only
 *                          set on successful return.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_task (gnutls_session_t *session, const char *name,
                 const char *config, const char *target, const char *comment,
                 gchar **id)
{
  int ret;

  ret = gvm_server_sendf_xml (session,
                              "<create_task>"
                              "<config id=\"%s\"/>"
                              "<target id=\"%s\"/>"
                              "<name>%s</name>"
                              "<comment>%s</comment>"
                              "</create_task>",
                              config, target, name, comment);
  if (ret)
    return -1;

  /* Read the response. */

  ret = gmp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Read response status and resource UUID.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[out] uuid     Either NULL or address for freshly allocated UUID of
 *                      created response.
 *
 * @return GMP response code on success, -1 on error.
 */
int
gmp_read_create_response (gnutls_session_t *session, gchar **uuid)
{
  int ret;
  const char *status;
  entity_t entity;

  /* Read the response. */

  entity = NULL;
  if (read_entity (session, &entity))
    return -1;

  /* Parse the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }

  if (uuid)
    {
      const char *id;

      id = entity_attribute (entity, "id");
      if (id == NULL)
        {
          free_entity (entity);
          return -1;
        }
      if (strlen (id) == 0)
        {
          free_entity (entity);
          return -1;
        }
      *uuid = g_strdup (id);
    }

  ret = atoi (status);
  free_entity (entity);
  return ret;
}

/**
 * @brief Delete a task and read the manager response.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  id        ID of task.
 * @param[in]  opts      Struct containing the options to apply.
 *
 * @return 0 on success, GMP response code on failure, -1 on error.
 */
int
gmp_delete_task_ext (gnutls_session_t *session, const char *id,
                     gmp_delete_opts_t opts)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session,
                        "<delete_task task_id=\"%s\" ultimate=\"%d\"/>", id,
                        opts.ultimate)
      == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Get the status of a task.
 *
 * @param[in]  session         Pointer to GNUTLS session.
 * @param[in]  id              ID of task or NULL for all tasks.
 * @param[in]  details         Whether to request task details.
 * @param[in]  include_rcfile  Ignored.  Removed since GMP 6.0.
 * @param[out] status          Status return.  On success contains GET_TASKS
 *                             response.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_get_tasks (gnutls_session_t *session, const char *id, int details,
               int include_rcfile, entity_t *status)
{
  (void) include_rcfile;
  if (id == NULL)
    {
      if (gvm_server_sendf (session, "<get_tasks details=\"%i\"/>", details)
          == -1)
        return -1;
    }
  else
    {
      if (gvm_server_sendf (session,
                            "<get_tasks"
                            " task_id=\"%s\""
                            " details=\"%i\"/>",
                            id, details)
          == -1)
        return -1;
    }

  /* Read the response. */
  return gmp_check_response (session, status);
}

/**
 * @brief Get a task (generic version).
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Task.  On success contains GET_TASKS response.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_get_task_ext (gnutls_session_t *session, gmp_get_task_opts_t opts,
                  entity_t *response)
{
  if ((response == NULL) || (opts.task_id == NULL))
    return -1;

  if (opts.actions)
    {
      if (gvm_server_sendf (session,
                            "<get_tasks"
                            " task_id=\"%s\""
                            " actions=\"%s\""
                            "%s/>",
                            opts.task_id, opts.actions,
                            GMP_FMT_BOOL_ATTRIB (opts, details)))
        return -1;
    }
  else if (gvm_server_sendf (session,
                             "<get_tasks"
                             " task_id=\"%s\""
                             "%s/>",
                             opts.task_id, GMP_FMT_BOOL_ATTRIB (opts, details)))
    return -1;

  return gmp_check_response (session, response);
}

/**
 * @brief Get all tasks (generic version).
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Tasks.  On success contains GET_TASKS response.
 *
 * @return 0 on success, 2 on timeout, -1 or GMP response code on error.
 */
int
gmp_get_tasks_ext (gnutls_session_t *session, gmp_get_tasks_opts_t opts,
                   entity_t *response)
{
  int ret;
  const char *status_code;
  gchar *cmd;

  if (response == NULL)
    return -1;

  cmd = g_markup_printf_escaped ("<get_tasks"
                                 " filter=\"%s\"",
                                 opts.filter);

  if (gvm_server_sendf (session, "%s%s/>", cmd,
                        GMP_FMT_BOOL_ATTRIB (opts, details)))
    {
      g_free (cmd);
      return -1;
    }
  g_free (cmd);

  *response = NULL;
  switch (try_read_entity (session, opts.timeout, response))
    {
    case 0:
      break;
    case -4:
      return 2;
    default:
      return -1;
    }

  /* Check the response. */

  status_code = entity_attribute (*response, "status");
  if (status_code == NULL)
    {
      free_entity (*response);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*response);
      return -1;
    }
  if (status_code[0] == '2')
    return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*response);
  if (errno == ERANGE)
    return -1;
  return ret;
}

/**
 * @brief Modify a file on a task.
 *
 * @param[in]  session      Pointer to GNUTLS session.
 * @param[in]  id           ID of task.
 * @param[in]  name         Name of file.
 * @param[in]  content      New content.  NULL to remove file.
 * @param[in]  content_len  Length of content.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_modify_task_file (gnutls_session_t *session, const char *id,
                      const char *name, const void *content, gsize content_len)
{
  entity_t entity;
  int ret;

  if (name == NULL)
    return -1;

  if (gvm_server_sendf (session, "<modify_task task_id=\"%s\">", id))
    return -1;

  if (content)
    {
      if (gvm_server_sendf (session, "<file name=\"%s\" action=\"update\">",
                            name))
        return -1;

      if (content_len)
        {
          gchar *base64_content =
            g_base64_encode ((guchar *) content, content_len);
          ret = gvm_server_sendf (session, "%s", base64_content);
          g_free (base64_content);
          if (ret)
            return -1;
        }

      if (gvm_server_sendf (session, "</file>"))
        return -1;
    }
  else
    {
      if (gvm_server_sendf (session, "<file name=\"%s\" action=\"remove\" />",
                            name))
        return -1;
    }

  if (gvm_server_sendf (session, "</modify_task>"))
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Delete a task and read the manager response.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, GMP response code on failure, -1 on error.
 */
int
gmp_delete_task (gnutls_session_t *session, const char *id)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session, "<delete_task task_id=\"%s\"/>", id) == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Get a report (generic version).
 *
 * FIXME: Using the according opts it should be possible to generate
 * any type of get_reports request defined by the spec.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Report.  On success contains GET_REPORT response.
 *
 * @return 0 on success, 2 on timeout, -1 or GMP response code on error.
 */
int
gmp_get_report_ext (gnutls_session_t *session, gmp_get_report_opts_t opts,
                    entity_t *response)
{
  int ret;
  const char *status_code;

  if (response == NULL)
    return -1;

  if (gvm_server_sendf (
        session,
        "<get_reports"
        " details=\"1\""
        " report_id=\"%s\""
        " format_id=\"%s\""
        " host_first_result=\"%i\""
        " host_max_results=\"%i\""
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s%s%s%s%s/>",
        opts.report_id, opts.format_id, opts.host_first_result,
        opts.host_max_results, GMP_FMT_STRING_ATTRIB (opts, type),
        GMP_FMT_STRING_ATTRIB (opts, filter),
        GMP_FMT_STRING_ATTRIB (opts, filt_id),
        GMP_FMT_STRING_ATTRIB (opts, host), GMP_FMT_STRING_ATTRIB (opts, pos),
        GMP_FMT_STRING_ATTRIB (opts, timezone),
        GMP_FMT_STRING_ATTRIB (opts, alert_id),
        GMP_FMT_STRING_ATTRIB (opts, host_levels),
        GMP_FMT_STRING_ATTRIB (opts, search_phrase),
        GMP_FMT_STRING_ATTRIB (opts, host_search_phrase),
        GMP_FMT_STRING_ATTRIB (opts, min_cvss_base),
        GMP_FMT_STRING_ATTRIB (opts, min_qod),
        GMP_FMT_BOOL_ATTRIB (opts, notes),
        GMP_FMT_BOOL_ATTRIB (opts, notes_details),
        GMP_FMT_BOOL_ATTRIB (opts, overrides),
        GMP_FMT_BOOL_ATTRIB (opts, override_details),
        GMP_FMT_BOOL_ATTRIB (opts, apply_overrides),
        GMP_FMT_BOOL_ATTRIB (opts, result_hosts_only),
        GMP_FMT_BOOL_ATTRIB (opts, ignore_pagination)))
    return -1;

  *response = NULL;
  switch (try_read_entity (session, opts.timeout, response))
    {
    case 0:
      break;
    case -4:
      return 2;
    default:
      return -1;
    }

  /* Check the response. */

  status_code = entity_attribute (*response, "status");
  if (status_code == NULL)
    {
      free_entity (*response);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*response);
      return -1;
    }
  if (status_code[0] == '2')
    return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*response);
  if (errno == ERANGE)
    return -1;
  return ret;
}

/**
 * @brief Remove a report.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  id        ID of report.
 *
 * @return 0 on success, GMP response code on failure, -1 on error.
 */
int
gmp_delete_report (gnutls_session_t *session, const char *id)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session, "<delete_report report_id=\"%s\"/>", id))
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Delete a config.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   id          UUID of config.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_delete_config_ext (gnutls_session_t *session, const char *id,
                       gmp_delete_opts_t opts)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session,
                        "<delete_config config_id=\"%s\" ultimate=\"%d\"/>", id,
                        opts.ultimate)
      == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Create an LSC Credential.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[in]   name      Name of LSC Credential.
 * @param[in]   login     Login associated with name.
 * @param[in]   password  Required password for the credential.
 * @param[in]   comment   LSC Credential comment.
 * @param[out]  uuid      Either NULL or address for UUID of created credential.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_lsc_credential (gnutls_session_t *session, const char *name,
                           const char *login, const char *password,
                           const char *comment, gchar **uuid)
{
  int ret;

  if (password == NULL)
    return -1;

  if (comment)
    {
      ret = gvm_server_sendf_xml_quiet (session,
                                        "<create_credential>"
                                        "<name>%s</name>"
                                        "<login>%s</login>"
                                        "<password>%s</password>"
                                        "<comment>%s</comment>"
                                        "</create_credential>",
                                        name, login, password, comment);
    }
  else
    {
      ret = gvm_server_sendf_xml_quiet (session,
                                        "<create_credential>"
                                        "<name>%s</name>"
                                        "<login>%s</login>"
                                        "<password>%s</password>"
                                        "</create_credential>",
                                        name, login, password);
    }
  if (ret)
    return -1;

  ret = gmp_read_create_response (session, uuid);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create an LSC Credential with a key.
 *
 * @param[in]   session      Pointer to GNUTLS session.
 * @param[in]   name         Name of LSC Credential.
 * @param[in]   login        Login associated with name.
 * @param[in]   passphrase   Passphrase for private key.
 * @param[in]   private_key  Private key.
 * @param[in]   comment      LSC Credential comment.
 * @param[out]  uuid         Either NULL or address for UUID of created
 *                           credential.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_lsc_credential_key (gnutls_session_t *session, const char *name,
                               const char *login, const char *passphrase,
                               const char *private_key, const char *comment,
                               gchar **uuid)
{
  int ret;

  if (comment)
    ret = gvm_server_sendf_xml (session,
                                "<create_credential>"
                                "<name>%s</name>"
                                "<login>%s</login>"
                                "<key>"
                                "<phrase>%s</phrase>"
                                "<private>%s</private>"
                                "</key>"
                                "<comment>%s</comment>"
                                "</create_credential>",
                                name, login, passphrase ? passphrase : "",
                                private_key, comment);
  else
    ret = gvm_server_sendf_xml (session,
                                "<create_credential>"
                                "<name>%s</name>"
                                "<login>%s</login>"
                                "<key>"
                                "<phrase>%s</phrase>"
                                "<private>%s</private>"
                                "</key>"
                                "</create_credential>",
                                name, login, passphrase ? passphrase : "",
                                private_key);

  if (ret)
    return -1;

  ret = gmp_read_create_response (session, uuid);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create an LSC credential.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] id        Pointer for newly allocated ID of new LSC credential,
 *                       or NULL.  Only set on successful return.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_lsc_credential_ext (gnutls_session_t *session,
                               gmp_create_lsc_credential_opts_t opts,
                               gchar **id)
{
  gchar *comment, *pass, *start, *snmp_elems;
  int ret;

  /* Create the GMP request. */

  if (opts.login == NULL)
    return -1;

  start =
    g_markup_printf_escaped ("<create_credential>"
                             "<name>%s</name>"
                             "<login>%s</login>",
                             opts.name ? opts.name : "unnamed", opts.login);

  if (opts.comment)
    comment = g_markup_printf_escaped ("<comment>"
                                       "%s"
                                       "</comment>",
                                       opts.comment);
  else
    comment = NULL;

  if (opts.private_key)
    pass = g_markup_printf_escaped ("<key>"
                                    "<phrase>%s</phrase>"
                                    "<private>%s</private>"
                                    "</key>",
                                    opts.passphrase ? opts.passphrase : "",
                                    opts.private_key);
  else
    {
      if (opts.passphrase)
        pass = g_markup_printf_escaped ("<password>"
                                        "%s"
                                        "</password>",
                                        opts.passphrase);
      else
        pass = NULL;
    }

  if (opts.community && opts.auth_algorithm && opts.privacy_password
      && opts.privacy_algorithm)
    snmp_elems =
      g_markup_printf_escaped ("<community>"
                               "%s"
                               "</community>"
                               "<auth_algorithm>"
                               "%s"
                               "</auth_algorithm>"
                               "<privacy>"
                               "<password>%s</password>"
                               "<algorithm>%s</algorithm>"
                               "</privacy>",
                               opts.community, opts.auth_algorithm,
                               opts.privacy_password, opts.privacy_algorithm);
  else
    snmp_elems = NULL;

  /* Send the request. */

  ret = gvm_server_sendf (session, "%s%s%s%s</create_credential>", start,
                          comment ? comment : "", pass ? pass : "",
                          snmp_elems ? snmp_elems : "");

  g_free (start);
  g_free (comment);
  g_free (pass);
  if (ret)
    return -1;

  /* Read the response. */

  ret = gmp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Delete a LSC credential.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   id          UUID of LSC credential.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_delete_lsc_credential_ext (gnutls_session_t *session, const char *id,
                               gmp_delete_opts_t opts)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session,
                        "<delete_credential credential_id=\"%s\""
                        " ultimate=\"%d\"/>",
                        id, opts.ultimate)
      == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}
