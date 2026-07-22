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
    {"CREATE_FILTER", "Create a filter."},
    {"CREATE_PORT_LIST", "Create a port list."},
    {"CREATE_PORT_RANGE", "Create a port range in a port list."},
    {"CREATE_REPORT", "Create a report."},
    {"CREATE_REPORT_FORMAT", "Create a report format."},
    {"CREATE_SCOPE", "Create a reporting scope."},
    {"CREATE_SCANNER", "Create a scanner."},
    {"CREATE_TAG", "Create a tag."},
    {"CREATE_TARGET", "Create a target."},
    {"CREATE_TASK", "Create a task."},
    {"CREATE_TLS_CERTIFICATE", "Create a TLS certificate."},
    {"CREATE_USER", "Create a new user."},
    {"DELETE_ALERT", "Delete an alert."},
    {"DELETE_ASSET", "Delete an asset."},
    {"DELETE_CONFIG", "Delete a config."},
    {"DELETE_CREDENTIAL", "Delete a credential."},
    {"DELETE_FILTER", "Delete a filter."},
    {"DELETE_PORT_LIST", "Delete a port list."},
    {"DELETE_PORT_RANGE", "Delete a port range."},
    {"DELETE_REPORT", "Delete a report."},
    {"DELETE_REPORT_FORMAT", "Delete a report format."},
    {"DELETE_SCOPE", "Delete a reporting scope."},
    {"DELETE_SCANNER", "Delete a scanner."},
    {"DELETE_SCHEDULE", "Delete a schedule."},
    {"DELETE_TAG", "Delete a tag."},
    {"DELETE_TARGET", "Delete a target."},
    {"DELETE_TASK", "Delete a task."},
    {"DELETE_TLS_CERTIFICATE", "Delete a TLS certificate."},
    {"DELETE_USER", "Delete an existing user."},
    {"DESCRIBE_AUTH", "Get details about the used authentication methods."},
    {"EMPTY_TRASHCAN", "Empty the trashcan."},
    {"GET_AGGREGATES", "Get aggregates of resources."},
    {"GET_ALERTS", "Get all alerts."},
    {"GET_ASSETS", "Get all assets."},
    {"GET_CONFIGS", "Get all configs."},
    {"GET_CREDENTIALS", "Get all credentials."},
    {"GET_FILTERS", "Get all filters."},
    {"GET_INFO", "Get raw information for a given item."},
    {"GET_INTEGRATION_CONFIGS", "Get integration configurations."},
    {"GET_LICENSE", "Get license information." },
    {"GET_NVTS", "Get one or all available NVTs."},
    {"GET_OVERRIDES", "Get all overrides."},
    {"GET_PORT_LISTS", "Get all port lists."},
    {"GET_PREFERENCES", "Get preferences for all available NVTs."},
    {"GET_REPORTS", "Get all reports."},
    {"GET_REPORT_FORMATS", "Get all report formats."},
    {"GET_SCOPE", "Get one reporting scope."},
    {"GET_SCOPES", "Get reporting scopes."},
    {"GET_SCANNERS", "Get all scanners."},
    {"GET_SCHEDULES", "Get all schedules."},
    {"GET_SETTINGS", "Get all settings."},
    {"GET_TAGS", "Get all tags."},
    {"GET_TARGETS", "Get all targets."},
    {"GET_TASKS", "Get all tasks."},
    {"GET_TLS_CERTIFICATES", "Get all TLS certificates."},
    {"GET_USERS", "Get all users."},
    {"GET_VERSION", "Get the Greenbone Management Protocol version."},
    {"GET_VULNS", "Get all vulnerabilities."},
    {"HELP", "Get this help text."},
    {"MODIFY_ASSET", "Modify an existing asset."},
    {"MODIFY_AUTH", "Modify the authentication methods."},
    {"MODIFY_CONFIG", "Update an existing config."},
    {"MODIFY_CREDENTIAL", "Modify an existing credential."},
    {"MODIFY_FILTER", "Modify an existing filter."},
    {"MODIFY_INTEGRATION_CONFIG", "Modify integration configuration."},
    {"MODIFY_LICENSE", "Modify the existing license."},
    {"MODIFY_PORT_LIST", "Modify an existing port list."},
    {"MODIFY_REPORT_FORMAT", "Modify an existing report format."},
    {"MODIFY_SCOPE", "Modify a reporting scope."},
    {"MODIFY_SCANNER", "Modify an existing scanner."},
    {"MODIFY_SETTING", "Modify an existing setting."},
    {"MODIFY_TAG", "Modify an existing tag."},
    {"MODIFY_TARGET", "Modify an existing target."},
    {"MODIFY_TASK", "Update an existing task."},
    {"MODIFY_TLS_CERTIFICATE", "Modify an existing TLS certificate."},
    {"MODIFY_USER", "Modify a user."},
    {"MOVE_TASK", "Assign task to another slave scanner, even while running."},
    {"RESTORE", "Restore a resource."},
    {"START_TASK", "Manually start an existing task."},
    {"STOP_TASK", "Stop a running task."},
    {"SYNC_CONFIG", "Synchronize a config with a scanner."},
    {"TEST_ALERT", "Run an alert."},
    {"VERIFY_REPORT_FORMAT", "Verify a report format."},
    {"VERIFY_SCANNER", "Verify a scanner."},
    {NULL, NULL}};

/* Native control paths can retain gvmd ACL operation keys after their public
 * GMP parser, help, and schema surfaces are removed. */
static const char *native_acl_operations[] = {
  "MODIFY_SCHEDULE",
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
