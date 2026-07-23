/* Copyright (C) 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Generic command handling.
 *
 * Non-SQL generic command handling code for the GVM management layer.
 */

/**
 * @brief Enable extra GNU functions.
 */
#define _GNU_SOURCE

#include <assert.h>
#include "manage_commands.h"
#include "manage_resources.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/**
 * @brief The GMP command list.
 */
command_t gmp_commands[]
 = {{"AUTHENTICATE", "Authenticate with the manager." },
    {"CREATE_ASSET", "Create an asset."},
    {"CREATE_CONFIG", "Import a scan config."},
    {"CREATE_CREDENTIAL", "Create a credential."},
    {"CREATE_TARGET", "Create a target."},
    {"CREATE_TASK", "Create a task."},
    {"DELETE_ASSET", "Delete an asset."},
    {"DELETE_CONFIG", "Delete a config."},
    {"DELETE_REPORT", "Delete a report."},
    {"DELETE_TARGET", "Delete a target."},
    {"DELETE_TASK", "Delete a task."},
    {"GET_AGGREGATES", "Get aggregates of resources."},
    {"GET_ASSETS", "Get all assets."},
    {"GET_CONFIGS", "Get all configs."},
    {"GET_CREDENTIALS", "Get all credentials."},
    {"GET_INFO", "Get raw information for a given item."},
    {"GET_NVTS", "Get one or all available NVTs."},
    {"GET_OVERRIDES", "Get all overrides."},
    {"GET_PORT_LISTS", "Get all port lists."},
    {"GET_PREFERENCES", "Get preferences for all available NVTs."},
    {"GET_REPORTS", "Get all reports."},
    {"GET_SCOPE", "Get one reporting scope."},
    {"GET_SCOPES", "Get reporting scopes."},
    {"GET_SETTINGS", "Get all settings."},
    {"GET_TARGETS", "Get all targets."},
    {"GET_TASKS", "Get all tasks."},
    {"GET_VERSION", "Get the Greenbone Management Protocol version."},
    {"HELP", "Get this help text."},
    {"MODIFY_ASSET", "Modify an existing asset."},
    {"MODIFY_CONFIG", "Update an existing config."},
    {"MODIFY_CREDENTIAL", "Modify an existing credential."},
    {"MODIFY_SETTING", "Modify an existing setting."},
    {"MODIFY_TARGET", "Modify an existing target."},
    {"MODIFY_TASK", "Update an existing task."},
    {"MOVE_TASK", "Assign task to another slave scanner, even while running."},
    {"START_TASK", "Manually start an existing task."},
    {"STOP_TASK", "Stop a running task."},
    {NULL, NULL}};

/* Native control paths can retain gvmd ACL operation keys after their public
 * GMP parser, help, and schema surfaces are removed. */
static const char *native_acl_operations[] = {
  "CREATE_ALERT",
  "DELETE_ALERT",
  "GET_ALERTS",
  "TEST_ALERT",
  "CREATE_USER",
  "CREATE_PORT_LIST",
  "CREATE_REPORT_FORMAT",
  "DELETE_SCHEDULE",
  "GET_SCHEDULES",
  "CREATE_SCHEDULE",
  "CREATE_TAG",
  "DELETE_TAG",
  "DELETE_USER",
  "EMPTY_TRASHCAN",
  "GET_FILTERS",
  "GET_REPORT_FORMATS",
  "GET_TAGS",
  "GET_USERS",
  "MODIFY_SCHEDULE",
  "MODIFY_USER",
  "MODIFY_TAG",
  NULL
};

/**
 * @brief Check whether a command name is valid.
 *
 * @param[in]  name  Command name.
 *
 * @return 1 yes, 0 no.
 */
int
valid_gmp_command (const char* name)
{
  command_t *command;
  const char **operation;
  command = gmp_commands;
  while (command[0].name)
    if (strcasecmp (command[0].name, name) == 0)
      return 1;
    else
      command++;
  operation = native_acl_operations;
  while (*operation)
    if (strcasecmp (*operation, name) == 0)
      return 1;
    else
      operation++;
  return 0;
}

/**
 * @brief Get the type associated with a GMP command.
 *
 * @param[in]  name  Command name.
 *
 * @return Freshly allocated type name if any, else NULL.
 */
gchar *
gmp_command_type (const char* name)
{
  const char *under;
  under = strchr (name, '_');
  if (under && (strlen (under) > 1))
    {
      gchar *command;
      under++;
      command = g_strdup (under);
      if (command[strlen (command) - 1] == 's')
        command[strlen (command) - 1] = '\0';
      if (valid_type (command))
        return command;
      g_free (command);
    }
  return NULL;
}

/**
 * @brief Check whether a GMP command takes a resource.
 *
 * MODIFY_TARGET, for example, takes a target.
 *
 * @param[in]  name  Command name.
 *
 * @return 1 if takes resource, else 0.
 */
int
gmp_command_takes_resource (const char* name)
{
  assert (name);
  return strcasecmp (name, "AUTHENTICATE")
         && strcasestr (name, "CREATE_") != name
         && strcasestr (name, "DESCRIBE_") != name
         && strcasecmp (name, "EMPTY_TRASHCAN")
         && strcasecmp (name, "GET_VERSION")
         && strcasecmp (name, "HELP")
         && strcasestr (name, "SYNC_") != name;
}
