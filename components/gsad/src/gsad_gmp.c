/* Copyright (C) 2009-2021 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_gmp.c
 * @brief GMP communication module of Greenbone Security Assistant daemon.
 *
 * This file implements an API for GMP.  The functions call the Greenbone
 * Vulnerability Manager via GMP properly.
 */

#include "gsad_gmp.h"

#include "gsad_base.h"               /* for set_language_code */
#include "gsad_connection_watcher.h" /* for gsad_connection_watcher_* */
#include "gsad_credentials.h"
#include "gsad_gmp_arguments.h" /* for gmp_arguments_t */
#include "gsad_gmp_auth.h"      /* for authenticate_gmp */
#include "gsad_gmp_request.h"   /* for gmp_request() */
#include "gsad_http.h"          /* for gsad_http_create_gsad_message */
#include "gsad_http_compression.h" /* for gsad_http_may_compress, gsad_http_may_deflate, gsad_http_may_brotli */
#include "gsad_i18n.h"
#include "gsad_manager.h" /* for gsad_manager_connect_with_username_password */
#include "gsad_params.h"
#include "gsad_params_mhd.h"
#include "gsad_session.h"
#include "gsad_settings.h" /* for gsad_settings_is_jwt_requested */
#include "gsad_user_session.h" /* for gsad_user_session_find and gsad_user_session_add */
#include "gsad_utils.h"
#include "gsad_validator.h" /* for gsad_validator_* */

#include <assert.h>
#include <glib.h>
#include <gvm/base/cvss.h> /* for get_cvss_score_from_base_metrics */
#include <gvm/gmp/gmp.h>
#include <gvm/util/fileutils.h> /* for gvm_export_file_name */
#include <gvm/util/xmlutils.h>  /* for xml_string_append, read_string_c, ... */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad gmp"

/**
 * @brief Manager (gvmd) address.
 */
#define OPENVASMD_ADDRESS "127.0.0.1"

/** @brief Answer for invalid input. */
#define GSAD_MESSAGE_INVALID                                              \
  "<gsad_msg status_text=\"%s\" operation=\"%s\">"                        \
  "At least one entered value contains invalid characters or exceeds"     \
  " a size limit.  You may use the Back button of your browser to adjust" \
  " the entered values.  If in doubt, the online help of the respective " \
  "section"                                                               \
  " will lead you to the appropriate help page."                          \
  "</gsad_msg>"

/** @brief Answer for invalid input. */
#define GSAD_MESSAGE_INVALID_PARAM(op)                                    \
  "<gsad_msg status_text=\"Invalid parameter\" operation=\"" op "\">"     \
  "At least one entered value contains invalid characters or exceeds"     \
  " a size limit.  You may use the Back button of your browser to adjust" \
  " the entered values.  If in doubt, the online help of the respective " \
  "section"                                                               \
  " will lead you to the appropriate help page."                          \
  "</gsad_msg>"

/**
 * @brief HTTP status code for expected failure of gmp requests e.g. if some
 *        parameter was missing or invalid.
 */
#if MHD_VERSION < 0x00097400
#define GSAD_STATUS_INVALID_REQUEST MHD_HTTP_UNPROCESSABLE_ENTITY
#else
#define GSAD_STATUS_INVALID_REQUEST MHD_HTTP_UNPROCESSABLE_CONTENT
#endif

/**
 * @brief Initial filtered results per page on the report summary.
 */
#define RESULTS_PER_PAGE 100

/**
 * @brief filt_id value to use term or built-in default filter.
 */
#define FILT_ID_NONE "0"

/**
 * @brief filt_id value to use the filter in the user setting if possible.
 */
#define FILT_ID_USER_SETTING "-2"

/**
 * @brief Check if variable is NULL
 *
 * @param[in]  name      Param name.
 * @param[in]  op_name   Operation name.
 */
#define CHECK_VARIABLE_INVALID(name, op_name)                                 \
  if (name == NULL)                                                           \
    {                                                                         \
      return message_invalid (connection, credentials, params, response_data, \
                              "Given " G_STRINGIFY (name) " was invalid",     \
                              op_name);                                       \
    }

/**
 * @brief Check if login name is valid on create.
 *
 * @param[in]  name      Param name.
 * @param[in]  op_name   Operation name.
 */
#define CHECK_LOGIN_NAME_INVALID_CREATE(name, op_name)                        \
  if (name == NULL || !credential_username_is_valid (name))                   \
    {                                                                         \
      return message_invalid (connection, credentials, params, response_data, \
                              "Login name must not be empty and may contain"  \
                              " only alphanumeric characters or the"          \
                              " following: - _ \\ . @",                       \
                              op_name);                                       \
    }

/**
 * @brief Check if login name is valid on edit.
 *
 * @param[in]  name      Param name.
 * @param[in]  op_name   Operation name.
 */
#define CHECK_LOGIN_NAME_INVALID_EDIT(name, op_name)                          \
  if (name == NULL || !credential_username_is_valid (name))                   \
    {                                                                         \
      return message_invalid (connection, credentials, params, response_data, \
                              "Login name may only contain alphanumeric"      \
                              " characters or the following: - _ \\ . @",     \
                              op_name);                                       \
    }

#define XML_REPORT_FORMAT_ID "a994b278-1f62-11e1-96ac-406186ea4fc5"
#define ANONXML_REPORT_FORMAT_ID "5057e5cc-b825-11e4-9d0e-28d24461215b"

/* Headers. */

static int
gmp (gvm_connection_t *, gsad_credentials_t *, gchar **, entity_t *,
     gsad_command_response_data_t *, const char *);

static int
gmpf (gvm_connection_t *, gsad_credentials_t *, gchar **, entity_t *,
      gsad_command_response_data_t *, const char *, ...);

static char *
get_alert (gvm_connection_t *, gsad_credentials_t *, params_t *, const char *,
           gsad_command_response_data_t *);

static char *
get_asset (gvm_connection_t *, gsad_credentials_t *, params_t *, const char *,
           gsad_command_response_data_t *);

static char *
get_config_family (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);

static char *
get_credential (gvm_connection_t *, gsad_credentials_t *, params_t *,
                const char *, gsad_command_response_data_t *);

static char *
get_override (gvm_connection_t *, gsad_credentials_t *, params_t *,
              const char *, gsad_command_response_data_t *);

static char *
get_port_list (gvm_connection_t *, gsad_credentials_t *, params_t *,
               const char *, gsad_command_response_data_t *);

static char *
get_tag (gvm_connection_t *, gsad_credentials_t *, params_t *, const char *,
         gsad_command_response_data_t *);

static char *
get_target (gvm_connection_t *, gsad_credentials_t *, params_t *, const char *,
            gsad_command_response_data_t *);

static char *
get_scanner (gvm_connection_t *, gsad_credentials_t *, params_t *, const char *,
             gsad_command_response_data_t *);

static char *
get_schedule (gvm_connection_t *, gsad_credentials_t *, params_t *,
              const char *, gsad_command_response_data_t *);

static char *
get_user (gvm_connection_t *, gsad_credentials_t *, params_t *, const char *,
          gsad_command_response_data_t *);

static int
gmp_success (entity_t entity);

static gchar *
response_from_entity (gvm_connection_t *, gsad_credentials_t *, params_t *,
                      entity_t, const char *, gsad_command_response_data_t *);

static gchar *
action_result (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *, const char *action,
               const char *message, const char *details, const char *id);

/* Helpers. */

/**
 *  @brief Structure to search a key by value
 */
typedef struct
{
  gchar *value;
  GList *keys;
} find_by_value_t;

/**
 * @brief Wrap some XML in an envelope.
 *
 * @param[in]     connection     Connection to manager
 * @param[in]     credentials    Username and password for authentication.
 * @param[in]     params         HTTP request params (UNUSED)
 * @param[in]     xml            XML string.  Freed before exit.
 * @param[in,out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped GMP XML.
 */
static char *
envelope_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
              params_t *params, gchar *xml,
              gsad_command_response_data_t *response_data)
{
  return gsad_http_create_envelope (credentials, xml, response_data);
}

/**
 * @brief Look for a param with name equal to a given string.
 *
 * @param[in]  params  Params.
 * @param[in]  string  String.
 *
 * @return 1 if param with name \arg string exists in \arg params, else 0.
 */
static int
member (params_t *params, const char *string)
{
  params_iterator_t iter;
  param_t *param;
  char *name;

  params_iterator_init (&iter, params);
  while (params_iterator_next (&iter, &name, &param))
    if (strcmp (name, string) == 0)
      return 1;
  return 0;
}

/**
 * @brief Look for param with value 1 and name equal to given string.
 *
 * @param[in]  params  Params.
 * @param[in]  string  String.
 *
 * @return 1 if param with name \arg string exists in \arg params, else 0.
 */
int
member1 (params_t *params, const char *string)
{
  params_iterator_t iter;
  param_t *param;
  char *name;

  params_iterator_init (&iter, params);
  while (params_iterator_next (&iter, &name, &param))
    if (param->value_size && param->value[0] == '1'
        && strcmp (name, string) == 0)
      return 1;
  return 0;
}

/**
 * @brief Set a content type from a format string.
 *
 * For example set the content type to GSAD_CONTENT_TYPE_APP_DEB when given
 * format "deb".
 *
 * @param[out]  content_type  Return location for the newly set content type,
 *                            defaults to GSAD_CONTENT_TYPE_OCTET_STREAM.
 * @param[in]   format        Lowercase format string as in the respective
 *                            GMP commands.
 */
static void
content_type_from_format_string (enum content_type *content_type,
                                 const char *format)
{
  if (!format)
    *content_type = GSAD_CONTENT_TYPE_OCTET_STREAM;

  else if (strcmp (format, "deb") == 0)
    *content_type = GSAD_CONTENT_TYPE_APP_DEB;
  else if (strcmp (format, "exe") == 0)
    *content_type = GSAD_CONTENT_TYPE_APP_EXE;
  else if (strcmp (format, "html") == 0)
    *content_type = GSAD_CONTENT_TYPE_TEXT_HTML;
  else if (strcmp (format, "key") == 0)
    *content_type = GSAD_CONTENT_TYPE_APP_KEY;
  else if (strcmp (format, "nbe") == 0)
    *content_type = GSAD_CONTENT_TYPE_APP_NBE;
  else if (strcmp (format, "pdf") == 0)
    *content_type = GSAD_CONTENT_TYPE_APP_PDF;
  else if (strcmp (format, "rpm") == 0)
    *content_type = GSAD_CONTENT_TYPE_APP_RPM;
  else if (strcmp (format, "xml") == 0)
    *content_type = GSAD_CONTENT_TYPE_APP_XML;
  else
    *content_type = GSAD_CONTENT_TYPE_OCTET_STREAM;
}

/**
 * @brief Check a modify_config response.
 *
 * @param[in]  connection   Connection with manager.
 * @param[in]  credentials  Credentials of user issuing the action.
 * @param[in]  params       HTTP request parameters.
 * @param[in]  next         Next page command on success.
 * @param[in]  fail_next    Next page command on failure.
 * @param[out] success      Whether the command returned a success response.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Error message on failure, NULL on success.
 */
static char *
check_modify_config (gvm_connection_t *connection,
                     gsad_credentials_t *credentials, params_t *params,
                     const char *next, const char *fail_next, int *success,
                     gsad_command_response_data_t *response_data)
{
  entity_t entity;
  gchar *response;
  const char *status_text;

  if (success)
    *success = 0;

  /** @todo This would be much easier with real error codes. */

  /* Read the response. */

  if (read_entity_c (connection, &entity))
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a config. "
        "It is unclear whether the entire config has been saved. "
        "Diagnostics: Failure to read command to manager daemon.",
        response_data);
    }

  /* Check the response. */

  status_text = entity_attribute (entity, "status_text");
  if (status_text == NULL)
    {
      free_entity (entity);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a config. "
        "It is unclear whether the entire config has been saved. "
        "Diagnostics: Failure to parse status_text from response.",
        response_data);
    }
  else if (str_equal (status_text, "MODIFY_CONFIG name must be unique"))
    {
      const char *message = "A config with the given name exists already.";

      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      response = action_result (connection, credentials, params, response_data,
                                "Save Config", message, NULL, NULL);

      free_entity (entity);
      return response;
    }
  else if (success && gmp_success (entity))
    {
      *success = 1;
    }

  response = response_from_entity (connection, credentials, params, entity,
                                   "Save Config", response_data);
  free_entity (entity);

  return response;
}

/**
 * @brief Check whether an GMP command failed.
 *
 * @param[in] entity  Response entity.
 *
 * @return 1 success, 0 fail, -1 error.
 */
static int
gmp_success (entity_t entity)
{
  const char *status;

  if (entity == NULL)
    return 0;

  status = entity_attribute (entity, "status");
  if ((status == NULL) || (strlen (status) == 0))
    return -1;

  return status[0] == '2';
}

/**
 * @brief Set the HTTP status according to GMP response entity.
 *
 * @param[in]  entity         The GMP response entity.
 * @param[in]  response_data  Response data.
 */
void
set_http_status_from_entity (entity_t entity,
                             gsad_command_response_data_t *response_data)
{
  if (entity == NULL)
    gsad_command_response_data_set_status_code (response_data,
                                                MHD_HTTP_INTERNAL_SERVER_ERROR);
  else if (str_equal (entity_attribute (entity, "status_text"),
                      "Permission denied"))
    gsad_command_response_data_set_status_code (response_data,
                                                MHD_HTTP_FORBIDDEN);
  else if (str_equal (entity_attribute (entity, "status"), "404"))
    gsad_command_response_data_set_status_code (response_data,
                                                MHD_HTTP_NOT_FOUND);
  else if (str_equal (entity_attribute (entity, "status"), "503"))
    gsad_command_response_data_set_status_code (response_data,
                                                MHD_HTTP_SERVICE_UNAVAILABLE);
  else
    gsad_command_response_data_set_status_code (response_data,
                                                MHD_HTTP_BAD_REQUEST);
}

/**
 * @brief Run a single GMP command.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  credentials    Username and password for authentication.
 * @param[out] response       Location for response, or NULL.
 * @param[out] entity_return  Response entity.
 * @param[out] response_data  Extra data return for the HTTP response.
 * @param[in]  command        Command.
 *
 * @return 0 success (response set), 1 send error, 2 read error.
 */
static int
gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
     gchar **response, entity_t *entity_return,
     gsad_command_response_data_t *response_data, const char *command)
{
  int ret;
  entity_t entity;

  if (entity_return)
    *entity_return = NULL;

  ret = gvm_connection_sendf (connection, "%s", command);
  if (ret == -1)
    {
      return 1;
    }

  entity = NULL;
  if (read_entity_and_text_c (connection, &entity, response))
    {
      return 2;
    }
  if (entity_return)
    *entity_return = entity;
  else
    free_entity (entity);
  return 0;
}

/**
 * @brief Run a single formatted GMP command.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  credentials    Username and password for authentication.
 * @param[out] response       Location for response, or NULL.
 * @param[out] entity_return  Response entity.
 * @param[out] response_data  Extra data return for the HTTP response.
 * @param[in]  format         Command.
 * @param[in]  ...            Arguments for format string.
 *
 * @return 0 success (response set), 1 send error, 2 read error.
 */
static int
gmpf (gvm_connection_t *connection, gsad_credentials_t *credentials,
      gchar **response, entity_t *entity_return,
      gsad_command_response_data_t *response_data, const char *format, ...)
{
  int ret;
  gchar *command;
  va_list args;

  va_start (args, format);
  command = g_markup_vprintf_escaped (format, args);
  va_end (args);

  ret = gmp (connection, credentials, response, entity_return, response_data,
             command);
  g_free (command);
  return ret;
}

/**
 * @brief Get a setting by UUID for the current user of an GMP connection.
 *
 * @param[in]  connection  Connection.
 * @param[in]  setting_id  UUID of the setting to get.
 * @param[out] value       Value of the setting.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return     -1 internal error, 0 success, 1 send error, 2 read error.
 */
static int
setting_get_value (gvm_connection_t *connection, const char *setting_id,
                   gchar **value, gsad_command_response_data_t *response_data)
{
  int ret;
  entity_t entity;
  const char *status;

  *value = NULL;

  ret = gvm_connection_sendf (connection, "<get_settings setting_id=\"%s\"/>",
                              setting_id);
  if (ret)
    return 1;

  entity = NULL;
  if (read_entity_c (connection, &entity))
    return 2;

  status = entity_attribute (entity, "status");
  if (status == NULL || strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }

  if (status[0] == '2')
    {
      entity_t setting;
      setting = entity_child (entity, "setting");
      if (setting == NULL)
        {
          free_entity (entity);
          return 0;
        }
      setting = entity_child (setting, "value");
      if (setting == NULL)
        {
          free_entity (entity);
          return -1;
        }
      *value = g_strdup (entity_text (setting));
      free_entity (entity);
    }
  else
    {
      if (response_data)
        set_http_status_from_entity (entity, response_data);
      free_entity (entity);
      return -1;
    }

  return 0;
}

/* Generic page handlers. */

/**
 * @brief Generate a enveloped GMP XML containing an action result.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         HTTP request params
 * @param[out] response_data  Extra data return for the HTTP response.
 * @param[in]  action         Name of the action.
 * @param[in]  message        Status message.
 * @param[in]  details        Status details (optional).
 * @param[in]  id             ID of the handled entity (optional).
 *
 * @return Enveloped XML object.
 */
static gchar *
action_result (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data,
               const char *action, const char *message, const char *details,
               const char *id)
{
  GString *xml;

  xml = g_string_new ("");
  xml_string_append (xml,
                     "<action_result>"
                     "<action>%s</action>"
                     "<message>%s</message>",
                     action ? action : "", message ? message : "");

  if (details)
    xml_string_append (xml, "<details>%s</details>", details);

  if (id)
    xml_string_append (xml, "<id>%s</id>", id);

  g_string_append (xml, "</action_result>");

  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Check a param using the direct response method.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  response_data  Response data.
 * @param[in]  message        Message.
 * @param[in]  op_name        Operation name.
 *
 * @return Enveloped XML object.
 */
gchar *
message_invalid (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data,
                 const char *message, const char *op_name)
{
  gchar *ret = action_result (connection, credentials, params, response_data,
                              op_name, message, NULL, NULL);

  gsad_command_response_data_set_status_code (response_data,
                                              GSAD_STATUS_INVALID_REQUEST);

  return ret;
}

/**
 * @brief Set redirect or return a basic action_result page based on entity.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  entity         Entity.
 * @param[in]  action         Name of the action.
 * @param[in]  response_data  Response data.
 *
 * @return Enveloped XML object.
 */
static gchar *
response_from_entity (gvm_connection_t *connection,
                      gsad_credentials_t *credentials, params_t *params,
                      entity_t entity, const char *action,
                      gsad_command_response_data_t *response_data)
{
  gchar *res;
  entity_t status_details_entity;
  int success;
  success = gmp_success (entity);

  if (!success)
    {
      set_http_status_from_entity (entity, response_data);
    }

  status_details_entity = entity_child (entity, "status_details");

  res = action_result (connection, credentials, params, response_data, action,
                       entity_attribute (entity, "status_text"),
                       entity_text (status_details_entity),
                       entity_attribute (entity, "id"));
  return res;
}

/**
 * @brief Get a single entity, envelope the result.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  type           Type of resource.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  arguments      Extra arguments for GMP GET command.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_entity (gvm_connection_t *connection, const char *type,
            gsad_credentials_t *credentials, params_t *params,
            gmp_arguments_t *arguments,
            gsad_command_response_data_t *response_data)
{
  GString *xml;
  gchar *cmd;
  entity_t entity;

  xml = g_string_new ("");

  if (str_equal (type, "info") || str_equal (type, "license"))
    {
      cmd = g_strdup_printf ("get_%s", type);
    }
  else
    {
      cmd = g_strdup_printf ("get_%ss", type);
    }

  g_string_append_printf (xml, "<get_%s>", type);

  if (gmp_request (connection, cmd, arguments))
    {
      g_free (cmd);

      gmp_arguments_free (arguments);

      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a resource list. "
        "The current list of resources is not available. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  gmp_arguments_free (arguments);

  if (read_entity_and_string_c (connection, &entity, &xml))
    {
      g_string_free (xml, TRUE);
      g_free (cmd);

      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting resources list. "
        "The current list of resources is not available. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  if (gmp_success (entity) != 1)
    {
      gchar *message;

      set_http_status_from_entity (entity, response_data);

      message = gsad_http_create_gsad_message (
        credentials, entity_attribute (entity, "status_text"), response_data);

      g_string_free (xml, TRUE);
      g_free (cmd);
      free_entity (entity);
      return message;
    }

  g_string_append_printf (xml, "</get_%s>", type);

  g_free (cmd);
  free_entity (entity);

  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Get one resource, envelope the result.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  type           Type of resource.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  extra_xml      Extra XML to insert inside page element.
 * @param[in]  arguments      Extra arguments for GMP GET command.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_one (gvm_connection_t *connection, const char *type,
         gsad_credentials_t *credentials, params_t *params,
         const char *extra_xml, gmp_arguments_t *arguments,
         gsad_command_response_data_t *response_data)
{
  gchar *id_name;
  const gchar *id;
  const gchar *details;

  id_name = g_strdup_printf ("%s_id", type);
  id = params_value (params, id_name);

  CHECK_VARIABLE_INVALID (id, "Get")

  details = params_value (params, "details");
  if (!details)
    {
      details = "1";
    }

  if (arguments == NULL)
    {
      arguments = gmp_arguments_new ();
    }

  gmp_arguments_add (arguments, id_name, id);

  if (details && !str_equal (details, ""))
    {
      gmp_arguments_add (arguments, "details", details);
    }

  g_free (id_name);

  return get_entity (connection, type, credentials, params, arguments,
                     response_data);
}

/**
 * @brief Get all entities of a particular type, envelope the result.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  type           Entity type.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  arguments      Extra arguments for GMP GET command.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_entities (gvm_connection_t *connection, const char *type,
              gsad_credentials_t *credentials, params_t *params,
              gmp_arguments_t *arguments,
              gsad_command_response_data_t *response_data)
{
  GString *xml;
  gchar *cmd;
  entity_t entity;

  cmd = g_strdup_printf ("get_%s", type);

  if (gmp_request (connection, cmd, arguments))
    {
      g_free (cmd);

      gmp_arguments_free (arguments);

      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a resource list. "
        "The current list of resources is not available. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  gmp_arguments_free (arguments);

  xml = g_string_new ("");
  g_string_append_printf (xml, "<%s>", cmd);

  if (read_entity_and_string_c (connection, &entity, &xml))
    {
      g_free (cmd);
      g_string_free (xml, TRUE);

      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting resources list. "
        "The current list of resources is not available. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  if (gmp_success (entity) != 1)
    {
      gchar *message;

      set_http_status_from_entity (entity, response_data);

      message = gsad_http_create_gsad_message (
        credentials, entity_attribute (entity, "status_text"), response_data);

      g_free (cmd);
      g_string_free (xml, TRUE);
      free_entity (entity);
      return message;
    }

  g_string_append_printf (xml, "</%s>", cmd);

  g_free (cmd);
  free_entity (entity);

  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Get all of a particular type of resource, envelope the result.
 *
 * @param[in]  connection     Connection to manager
 * @param[in]  type           Resource type in plural form.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  arguments      Extra arguments for GMP GET command.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_many (gvm_connection_t *connection, const char *type,
          gsad_credentials_t *credentials, params_t *params,
          gmp_arguments_t *arguments,
          gsad_command_response_data_t *response_data)
{
  const gchar *filter_id, *filter;
  const gchar *details;

  filter_id = params_value (params, "filter_id");
  filter = params_value (params, "filter");
  details = params_value (params, "details");

  if (arguments == NULL)
    {
      arguments = gmp_arguments_new ();
    }

  if (details && !str_equal (details, ""))
    {
      gmp_arguments_add (arguments, "details", details);
    }

  if (!filter_id && !filter)
    {
      filter_id = FILT_ID_USER_SETTING;
    }

  if (filter_id)
    {
      gmp_arguments_add (arguments, "filt_id", filter_id);
    }

  if (filter)
    {
      gmp_arguments_add (arguments, "filter", filter);
    }

  return get_entities (connection, type, credentials, params, arguments,
                       response_data);
}

/**
 * @brief Generates a file name for exporting.
 *
 * @param[in]   fname_format      Format string.
 * @param[in]   credentials       Current credentials.
 * @param[in]   type              Type of resource.
 * @param[in]   uuid              UUID of resource.
 * @param[in]   resource_entity   Resource entity to extract extra data from.
 *
 * @return The file name.
 */
gchar *
format_file_name (gchar *fname_format, gsad_credentials_t *credentials,
                  const char *type, const char *uuid, entity_t resource_entity)
{
  gchar *creation_time, *modification_time, *name, *format_name;
  gchar *ret;

  if (resource_entity)
    {
      entity_t creation_time_entity, modification_time_entity;
      entity_t task_entity, format_entity, format_name_entity, name_entity;

      creation_time_entity = entity_child (resource_entity, "creation_time");

      if (creation_time_entity)
        creation_time = entity_text (creation_time_entity);
      else
        creation_time = NULL;

      modification_time_entity =
        entity_child (resource_entity, "modification_time");

      if (modification_time_entity)
        modification_time = entity_text (modification_time_entity);
      else
        modification_time = NULL;

      if (strcasecmp (type, "report") == 0)
        {
          task_entity = entity_child (resource_entity, "task");
          if (task_entity)
            name_entity = entity_child (task_entity, "name");
          else
            name_entity = NULL;

          format_entity = entity_child (resource_entity, "report_format");
          if (format_entity)
            {
              format_name_entity = entity_child (format_entity, "name");
            }
          else
            format_name_entity = NULL;

          if (format_name_entity && strlen (entity_text (format_name_entity)))
            format_name = entity_text (format_name_entity);
          else
            format_name = NULL;
        }
      else
        {
          name_entity = entity_child (resource_entity, "name");
          format_name = NULL;
        }

      if (name_entity)
        name = entity_text (name_entity);
      else
        name = NULL;
    }
  else
    {
      creation_time = NULL;
      modification_time = NULL;
      name = NULL;
      format_name = NULL;
    }

  gsad_user_t *user = gsad_credentials_get_user (credentials);
  ret = gvm_export_file_name (
    fname_format, user ? gsad_user_get_username (user) : NULL, type, uuid,
    creation_time, modification_time, name, format_name);
  return ret;
}

/**
 * @brief Export a resource.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   type                 Type of resource.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Resource XML on success.  XML error object on error.
 */
char *
export_resource (gvm_connection_t *connection, const char *type,
                 gsad_credentials_t *credentials, params_t *params,
                 gsad_command_response_data_t *response_data)
{
  GString *xml;
  entity_t entity;
  entity_t resource_entity;
  char *content = NULL;
  gchar *id_name;
  gchar *fname_format, *file_name;
  int ret;
  const char *resource_id, *subtype;

  xml = g_string_new ("");

  id_name = g_strdup_printf ("%s_id", type);
  resource_id = params_value (params, id_name);
  g_free (id_name);

  if (resource_id == NULL)
    {
      g_string_append (xml, GSAD_MESSAGE_INVALID_PARAM ("Export Resource"));
      return envelope_gmp (connection, credentials, params,
                           g_string_free (xml, FALSE), response_data);
    }

  subtype = params_value (params, "subtype");

  if (gvm_connection_sendf (connection,
                            "<get_%ss"
                            " %s_id=\"%s\""
                            "%s%s%s"
                            " export=\"1\""
                            " details=\"1\"/>",
                            type, type, resource_id, subtype ? " type=\"" : "",
                            subtype ? subtype : "", subtype ? "\"" : "")
      == -1)
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a resource. "
        "The resource could not be delivered. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  entity = NULL;
  if (read_entity_and_text_c (connection, &entity, &content))
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a resource. "
        "The resource could not be delivered. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  if (!gmp_success (entity))
    set_http_status_from_entity (entity, response_data);

  resource_entity = entity_child (entity, type);

  if (resource_entity == NULL)
    {
      g_free (content);
      free_entity (entity);
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a resource. "
        "The resource could not be delivered. "
        "Diagnostics: Failure to receive resource from manager daemon.",
        response_data);
    }

  ret = setting_get_value (connection, "a6ac88c5-729c-41ba-ac0a-deea4a3441f2",
                           &fname_format, response_data);
  if (ret)
    {
      g_free (content);
      free_entity (entity);
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      switch (ret)
        {
        case 1:
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a setting. "
            "The setting could not be delivered. "
            "Diagnostics: Failure to send command to manager daemon.",
            response_data);
        case 2:
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a setting. "
            "The setting could not be delivered. "
            "Diagnostics: Failure to receive response from manager daemon.",
            response_data);
        default:
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a setting. "
            "The setting could not be delivered. "
            "Diagnostics: Internal error.",
            response_data);
        }
    }

  if (fname_format == NULL)
    {
      g_warning ("%s : File name format setting not found.", __func__);
      fname_format = "%T-%U";
    }

  file_name = format_file_name (fname_format, credentials, type, resource_id,
                                resource_entity);
  if (file_name == NULL)
    file_name = g_strdup_printf ("%s-%s", type, resource_id);

  gsad_command_response_data_set_content_type (response_data,
                                               GSAD_CONTENT_TYPE_APP_XML);
  gsad_command_response_data_set_content_disposition (
    response_data,
    g_strdup_printf ("attachment; filename=\"%s.xml\"", file_name));
  gsad_command_response_data_set_content_length (response_data,
                                                 strlen (content));

  free_entity (entity);
  g_free (file_name);
  g_string_free (xml, TRUE);
  return content;
}

/**
 * @brief Export a list of resources.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   type                 Type of resource.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return XML on success.  XML error object on error.
 */
static char *
export_many (gvm_connection_t *connection, const char *type,
             gsad_credentials_t *credentials, params_t *params,
             gsad_command_response_data_t *response_data)
{
  entity_t entity;
  char *content = NULL;
  const char *filter;
  gchar *filter_escaped;
  gchar *type_many;
  gchar *fname_format, *file_name;
  int ret;

  filter = params_value (params, "filter");

  filter_escaped = g_markup_escape_text (filter, -1);

  if (strcmp (type, "info") == 0)
    {
      if (gvm_connection_sendf (connection,
                                "<get_info"
                                " type=\"%s\""
                                " export=\"1\""
                                " details=\"1\""
                                " filter=\"%s\"/>",
                                params_value (params, "info_type"),
                                filter_escaped ? filter_escaped : "")
          == -1)
        {
          g_free (filter_escaped);
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a list. "
            "The list could not be delivered. "
            "Diagnostics: Failure to send command to manager daemon.",
            response_data);
        }
    }
  else if (strcmp (type, "asset") == 0)
    {
      if (gvm_connection_sendf (connection,
                                "<get_assets"
                                " type=\"%s\""
                                " export=\"1\""
                                " details=\"1\""
                                " filter=\"%s\"/>",
                                params_value (params, "asset_type"),
                                filter_escaped ? filter_escaped : "")
          == -1)
        {
          g_free (filter_escaped);
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a list. "
            "The list could not be delivered. "
            "Diagnostics: Failure to send command to manager daemon.",
            response_data);
        }
    }
  else
    {
      if (gvm_connection_sendf (connection,
                                "<get_%ss"
                                " export=\"1\""
                                " details=\"1\""
                                " filter=\"%s\"/>",
                                type, filter_escaped ? filter_escaped : "")
          == -1)
        {
          g_free (filter_escaped);
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a list. "
            "The list could not be delivered. "
            "Diagnostics: Failure to send command to manager daemon.",
            response_data);
        }
    }
  g_free (filter_escaped);

  entity = NULL;
  if (read_entity_and_text_c (connection, &entity, &content))
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a list. "
        "The list could not be delivered. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  if (!gmp_success (entity))
    set_http_status_from_entity (entity, response_data);

  ret = setting_get_value (connection, "0872a6ed-4f85-48c5-ac3f-a5ef5e006745",
                           &fname_format, response_data);
  if (ret)
    {
      g_free (content);
      free_entity (entity);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      switch (ret)
        {
        case 1:
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a setting. "
            "The setting could not be delivered. "
            "Diagnostics: Failure to send command to manager daemon.",
            response_data);
        case 2:
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a setting. "
            "The setting could not be delivered. "
            "Diagnostics: Failure to receive response from manager daemon.",
            response_data);
        default:
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a setting. "
            "The setting could not be delivered. "
            "Diagnostics: Internal error.",
            response_data);
        }
    }

  if (fname_format == NULL)
    {
      g_warning ("%s : File name format setting not found.", __func__);
      fname_format = "%T-%D";
    }

  if (strcmp (type, "info") == 0)
    type_many = g_strdup (type);
  else
    type_many = g_strdup_printf ("%ss", type);

  file_name =
    format_file_name (fname_format, credentials, type_many, "list", NULL);
  if (file_name == NULL)
    file_name = g_strdup_printf ("%s-%s", type_many, "list");

  g_free (type_many);

  gsad_command_response_data_set_content_type (response_data,
                                               GSAD_CONTENT_TYPE_APP_XML);
  gsad_command_response_data_set_content_disposition (
    response_data,
    g_strdup_printf ("attachment; filename=\"%s.xml\"", file_name));
  gsad_command_response_data_set_content_length (response_data,
                                                 strlen (content));

  free_entity (entity);
  g_free (file_name);
  return content;
}

/**
 * @brief Delete a resource, get all resources, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  type           Type of resource.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  ultimate       0 move to trash, 1 remove entirely.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_resource (gvm_connection_t *connection, const char *type,
                 gsad_credentials_t *credentials, params_t *params,
                 gboolean ultimate, gsad_command_response_data_t *response_data)
{
  gchar *html, *id_name, *resource_id, *extra_attribs;
  entity_t entity;
  gchar *cap_type, *prev_action;

  id_name = g_strdup_printf ("%s_id", type);
  if (params_value (params, id_name))
    resource_id = g_strdup (params_value (params, id_name));
  else
    {
      g_free (id_name);
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while deleting a resource. "
        "The resource was not deleted. "
        "Diagnostics: Required parameter resource_id was NULL.",
        response_data);
    }

  /* This is a hack for assets, because asset_id is the param name used for
   * both the asset being deleted and the asset on the next page. */
  g_free (id_name);

  /* Extra attributes */
  extra_attribs = NULL;

  /* Inheritor of user's resource */
  if (strcmp (type, "user") == 0)
    {
      const char *inheritor_id;
      inheritor_id = params_value (params, "inheritor_id");
      if (inheritor_id)
        extra_attribs = g_strdup_printf ("inheritor_id=\"%s\"", inheritor_id);
      else if (params_given (params, "inheritor_id"))
        return message_invalid (connection, credentials, params, response_data,
                                "Invalid inheritor_id", "Delete User");
    }

  /* Delete the resource and get all resources. */

  if (gvm_connection_sendf (
        connection, "<delete_%s %s_id=\"%s\" ultimate=\"%i\"%s%s/>", type, type,
        resource_id, !!ultimate, extra_attribs ? " " : "",
        extra_attribs ? extra_attribs : "")
      == -1)
    {
      g_free (resource_id);
      g_free (extra_attribs);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while deleting a resource. "
        "The resource is not deleted. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  g_free (resource_id);
  g_free (extra_attribs);

  entity = NULL;
  if (read_entity_c (connection, &entity))
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while deleting a resource. "
        "It is unclear whether the resource has been deleted or not. "
        "Diagnostics: Failure to read response from manager daemon.",
        response_data);
    }

  if (!gmp_success (entity))
    set_http_status_from_entity (entity, response_data);

  cap_type = capitalize (type);
  prev_action = g_strdup_printf ("Delete %s", cap_type);

  html = response_from_entity (connection, credentials, params, entity,
                               prev_action, response_data);

  free_entity (entity);
  g_free (cap_type);
  g_free (prev_action);

  return html;
}

/**
 * @brief Move a resource to the trashcan
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  type           Type of resource.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
move_resource_to_trash (gvm_connection_t *connection, const char *type,
                        gsad_credentials_t *credentials, params_t *params,
                        gsad_command_response_data_t *response_data)
{
  return delete_resource (connection, type, credentials, params, FALSE,
                          response_data);
}

/**
 * @brief Perform action on resource, get next page, envelope result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  type           Type of resource.
 * @param[in]  action         Action to perform.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
resource_action (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, const char *type, const char *action,
                 gsad_command_response_data_t *response_data)
{
  gchar *html, *param_name;
  const char *resource_id;
  gchar *cap_action, *cap_type, *get_cmd, *prev_action;

  int ret;
  entity_t entity;

  assert (type);

  param_name = g_strdup_printf ("%s_id", type);
  resource_id = params_value (params, param_name);

  if (resource_id == NULL)
    {
      gchar *message;
      message = g_strdup_printf (
        "An internal error occurred while performing an action. "
        "The resource remains the same. "
        "Diagnostics: Required parameter %s was NULL.",
        param_name);
      g_free (param_name);
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      html =
        gsad_http_create_gsad_message (credentials, message, response_data);
      g_free (message);
      return html;
    }
  g_free (param_name);

  entity = NULL;
  ret = gmpf (connection, credentials, NULL, &entity, response_data,
              "<%s_%s %s_id=\"%s\"/>", action, type, type, resource_id);
  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while performing an action. "
        "The resource remains the same. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while performing an action. "
        "It is unclear whether the resource has been affected. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while performing an action. "
        "It is unclear whether the resource has been affected. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  if (!gmp_success (entity))
    set_http_status_from_entity (entity, response_data);

  cap_action = capitalize (action);
  cap_type = capitalize (type);
  get_cmd = g_strdup_printf ("get_%ss", type);
  prev_action = g_strdup_printf ("%s %s", cap_action, cap_type);
  html = response_from_entity (connection, credentials, params, entity,
                               prev_action, response_data);

  free_entity (entity);
  g_free (cap_action);
  g_free (cap_type);
  g_free (get_cmd);
  g_free (prev_action);

  return html;
}

/* Page handlers. */

/**
 * @todo Consider doing the input sanatizing in the page handlers.
 *
 * Currently the input sanatizing is done in serve_post, exec_gmp_post and
 * exec_gmp_get in gsad.c.  This means that the information about what
 * input is suitable for a page is separate from the page handler.
 *
 * Doing the input sanatizing in the page handler will probably also help
 * in responding with more detailed messages when an input error occurs.
 */

/**
 * @todo Take care of XML in input.
 *
 * Anything that is printed into the XML directly (usually via
 * g_string_append_printf below) must use something like
 * g_markup_printf_escaped or g_markup_escape_text to ensure that any
 * XML special sequences in the string are escaped.
 */

/**
 * @brief Get a value from a param or fall back to a setting
 *
 * @param[out]  value       Variable to assign the value to.
 * @param[in]   param       The param to try get the value from first.
 * @param[in]   setting_id  The UUID of the setting to try next.
 * @param[in]   cleanup     Code to run on failure.
 */
#define PARAM_OR_SETTING(value, param, setting_id, cleanup)                   \
  if (params_valid (params, param))                                           \
    value = g_strdup (params_value (params, param));                          \
  else                                                                        \
    {                                                                         \
      char *message;                                                          \
      message = setting_get_value_error (connection, credentials, setting_id, \
                                         &value, response_data);              \
      if (message)                                                            \
        {                                                                     \
          cleanup;                                                            \
          return message;                                                     \
        }                                                                     \
    }

/**
 * @brief Create a task, get all tasks, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
create_task_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  entity_t entity;
  int ret;
  GString *command;
  gchar *html;
  const char *name, *comment, *config_id, *target_id, *scanner_type;
  const char *scanner_id, *schedule_id, *schedule_periods;
  const char *max_checks, *max_hosts;
  const char *auto_delete, *auto_delete_data;
  const char *apply_overrides, *min_qod, *usage_type;
  params_t *alerts;

  apply_overrides = params_value (params, "apply_overrides");
  auto_delete = "keep";
  auto_delete_data = params_value (params, "auto_delete_data");
  if (auto_delete_data == NULL || strlen (auto_delete_data) == 0)
    auto_delete_data = "10";
  comment = params_value (params, "comment");
  config_id = params_value (params, "config_id");
  max_checks = params_value (params, "max_checks");
  max_hosts = params_value (params, "max_hosts");
  min_qod = params_value (params, "min_qod");
  name = params_value (params, "name");
  scanner_id = params_value (params, "scanner_id");
  scanner_type = params_value (params, "scanner_type");
  schedule_id = params_value (params, "schedule_id");
  schedule_periods = params_value (params, "schedule_periods");
  target_id = params_value (params, "target_id");
  usage_type = params_value (params, "usage_type");
  CHECK_VARIABLE_INVALID (scanner_type, "Create Task");
  if (!strcmp (scanner_type, "1"))
    {
      max_checks = "";
      max_hosts = "";
    }
  else if (!strcmp (scanner_type, "3"))
    {
      config_id = "";
      max_checks = "";
      max_hosts = "";
    }

  CHECK_VARIABLE_INVALID (name, "Create Task");
  CHECK_VARIABLE_INVALID (comment, "Create Task");
  CHECK_VARIABLE_INVALID (usage_type, "Create Task");
  CHECK_VARIABLE_INVALID (config_id, "Create Task");
  CHECK_VARIABLE_INVALID (target_id, "Create Task");
  CHECK_VARIABLE_INVALID (scanner_id, "Create Task");
  CHECK_VARIABLE_INVALID (schedule_id, "Create Task");

  if (str_equal (target_id, "0"))
    {
      /* Don't allow to create import task via create_task */
      return message_invalid (connection, credentials, params, response_data,
                              "Given target_id was invalid", "Create Task");
    }

  if (params_given (params, "schedule_periods"))
    {
      CHECK_VARIABLE_INVALID (schedule_periods, "Create Task");
    }
  else
    schedule_periods = "0";

  CHECK_VARIABLE_INVALID (apply_overrides, "Create Task");
  CHECK_VARIABLE_INVALID (min_qod, "Create Task");

  CHECK_VARIABLE_INVALID (max_checks, "Create Task");
  CHECK_VARIABLE_INVALID (auto_delete_data, "Create Task");
  CHECK_VARIABLE_INVALID (max_hosts, "Create Task");

  command = g_string_new ("<create_task>");

  if (schedule_id && strcmp (schedule_id, "0"))
    xml_string_append (command, "<schedule id=\"%s\"/>", schedule_id);

  if (params_given (params, "alert_id_optional:"))
    alerts = params_values (params, "alert_id_optional:");
  else
    alerts = params_values (params, "alert_ids:");

  if (alerts)
    {
      params_iterator_t iter;
      char *name;
      param_t *param;

      params_iterator_init (&iter, alerts);
      while (params_iterator_next (&iter, &name, &param))
        if (param->value && strcmp (param->value, "0"))
          xml_string_append (command, "<alert id=\"%s\"/>",
                             param->value ? param->value : "");
    }

  xml_string_append (
    command,
    "<config id=\"%s\"/>"
    "<schedule_periods>%s</schedule_periods>"
    "<target id=\"%s\"/>"
    "<scanner id=\"%s\"/>"
    "<name>%s</name>"
    "<comment>%s</comment>"
    "<preferences>"
    "<preference>"
    "<scanner_name>max_checks</scanner_name>"
    "<value>%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>max_hosts</scanner_name>"
    "<value>%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>in_assets</scanner_name>"
    "<value>%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>"
    "assets_apply_overrides"
    "</scanner_name>"
    "<value>%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>assets_min_qod</scanner_name>"
    "<value>%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>auto_delete</scanner_name>"
    "<value>%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>auto_delete_data</scanner_name>"
    "<value>%s</value>"
    "</preference>"
    "</preferences>"
    "<alterable>1</alterable>"
    "<usage_type>%s</usage_type>"
    "</create_task>",
    config_id, schedule_periods, target_id, scanner_id, name, comment,
    max_checks, max_hosts, "yes",
    strcmp (apply_overrides, "0") ? "yes" : "no", min_qod, auto_delete,
    auto_delete_data, usage_type);

  ret =
    gmp (connection, credentials, NULL, &entity, response_data, command->str);
  g_string_free (command, TRUE);

  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new task. "
        "No new task was created. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new task. "
        "It is unclear whether the task has been created or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new task. "
        "It is unclear whether the task has been created or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  if (gmp_success (entity))
    {
      if (entity_attribute (entity, "id"))
        params_add (params, "task_id", entity_attribute (entity, "id"));
      html = response_from_entity (connection, credentials, params, entity,
                                   "Create Task", response_data);
    }
  else
    {
      html = response_from_entity (connection, credentials, params, entity,
                                   "Create Task", response_data);
    }
  free_entity (entity);
  return html;
}

/**
 * @brief Delete a task, get all tasks, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_task_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  return move_resource_to_trash (connection, "task", credentials, params,
                                 response_data);
}

/**
 * @brief Save task, get next page, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
save_task_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  gchar *html, *format;
  const char *comment, *name, *schedule_id;
  const char *scanner_id, *task_id, *max_checks, *max_hosts;
  const char *config_id, *target_id;
  const char *scanner_type, *schedule_periods, *auto_delete, *auto_delete_data;
  const char *apply_overrides, *min_qod;
  int ret;
  params_t *alerts;
  GString *alert_element;
  entity_t entity;

  apply_overrides = params_value (params, "apply_overrides");
  auto_delete = "keep";
  auto_delete_data = params_value (params, "auto_delete_data");
  if (auto_delete_data == NULL || strlen (auto_delete_data) == 0)
    auto_delete_data = "10";
  comment = params_value (params, "comment");
  config_id = params_value (params, "config_id");
  max_checks = params_value (params, "max_checks");
  max_hosts = params_value (params, "max_hosts");
  min_qod = params_value (params, "min_qod");
  name = params_value (params, "name");
  scanner_id = params_value (params, "scanner_id");
  scanner_type = params_value (params, "scanner_type");
  schedule_id = params_value (params, "schedule_id");
  schedule_periods = params_value (params, "schedule_periods");
  target_id = params_value (params, "target_id");
  task_id = params_value (params, "task_id");
  if (scanner_type != NULL)
    {
      CHECK_VARIABLE_INVALID (scanner_type, "Save Task");
      if (!strcmp (scanner_type, "1"))
        {
          max_checks = "";
          max_hosts = "";
        }
      else if (!strcmp (scanner_type, "3"))
        {
          config_id = "0";
          max_checks = "";
          max_hosts = "";
        }
    }

  CHECK_VARIABLE_INVALID (name, "Save Task");
  CHECK_VARIABLE_INVALID (comment, "Save Task");
  CHECK_VARIABLE_INVALID (target_id, "Save Task");
  CHECK_VARIABLE_INVALID (config_id, "Save Task");
  CHECK_VARIABLE_INVALID (schedule_id, "Save Task");

  if (params_given (params, "schedule_periods"))
    {
      CHECK_VARIABLE_INVALID (schedule_periods, "Save Task");
    }
  else
    schedule_periods = "0";

  CHECK_VARIABLE_INVALID (scanner_id, "Save Task");
  CHECK_VARIABLE_INVALID (task_id, "Save Task");
  CHECK_VARIABLE_INVALID (max_checks, "Save Task");
  CHECK_VARIABLE_INVALID (auto_delete_data, "Save Task");
  CHECK_VARIABLE_INVALID (max_hosts, "Save Task");

  CHECK_VARIABLE_INVALID (apply_overrides, "Save Task");
  CHECK_VARIABLE_INVALID (min_qod, "Save Task");

  alert_element = g_string_new ("");
  if (params_given (params, "alert_id_optional:"))
    alerts = params_values (params, "alert_id_optional:");
  else
    alerts = params_values (params, "alert_ids:");

  if (alerts)
    {
      params_iterator_t iter;
      char *name;
      param_t *param;

      params_iterator_init (&iter, alerts);
      while (params_iterator_next (&iter, &name, &param))
        {
          if (param->value && strcmp (param->value, "0"))
            g_string_append_printf (alert_element, "<alert id=\"%s\"/>",
                                    param->value ? param->value : "");
        }
    }

  // Remove Alerts from Task if none are given.
  if (strcmp (alert_element->str, "") == 0)
    g_string_append_printf (alert_element, "<alert id=\"0\"/>");

  format = g_strdup_printf (
    "<modify_task task_id=\"%%s\">"
    "<name>%%s</name>"
    "<comment>%%s</comment>"
    "%s"
    "<target id=\"%%s\"/>"
    "<config id=\"%%s\"/>"
    "<schedule id=\"%%s\"/>"
    "<schedule_periods>%%s</schedule_periods>"
    "<scanner id=\"%%s\"/>"
    "<preferences>"
    "<preference>"
    "<scanner_name>max_checks</scanner_name>"
    "<value>%%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>max_hosts</scanner_name>"
    "<value>%%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>in_assets</scanner_name>"
    "<value>%%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>assets_apply_overrides</scanner_name>"
    "<value>%%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>assets_min_qod</scanner_name>"
    "<value>%%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>auto_delete</scanner_name>"
    "<value>%%s</value>"
    "</preference>"
    "<preference>"
    "<scanner_name>auto_delete_data</scanner_name>"
    "<value>%%s</value>"
    "</preference>"
    "</preferences>"
    "<alterable>1</alterable>"
    "</modify_task>",
    alert_element->str);
  entity = NULL;
  ret = gmpf (
    connection, credentials, NULL, &entity, response_data, format, task_id,
    name, comment, target_id, config_id, schedule_id, schedule_periods,
    scanner_id, max_checks, max_hosts, "yes",
    strcmp (apply_overrides, "0") ? "yes" : "no", min_qod, auto_delete,
    auto_delete_data);
  g_free (format);

  g_string_free (alert_element, TRUE);

  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a task. "
        "The task was not saved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a task. "
        "It is unclear whether the task has been saved or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a task. "
        "It is unclear whether the task has been saved or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  html = response_from_entity (connection, credentials, params, entity,
                               "Save Task", response_data);
  free_entity (entity);
  return html;
}

#undef CHECK

/**
 * @brief Export a task.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Note XML on success.  Enveloped XML on error.
 */
char *
export_task_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "task", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of tasks.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Tasks XML on success.  Enveloped XML
 *         on error.
 */
char *
export_tasks_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  return export_many (connection, "task", credentials, params, response_data);
}

/**
 * @brief Stop a task, get all tasks, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
stop_task_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  return resource_action (connection, credentials, params, "task", "stop",
                          response_data);
}

/**
 * @brief Start a task, get all tasks, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
start_task_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  return resource_action (connection, credentials, params, "task", "start",
                          response_data);
}

/**
 * @brief Reassign a task to a new GMP slave.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
move_task_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  gchar *command, *html;
  const char *task_id, *slave_id;
  int ret;
  entity_t entity;

  slave_id = params_value (params, "slave_id");
  task_id = params_value (params, "task_id");

  command = g_strdup_printf ("<move_task task_id=\"%s\" slave_id=\"%s\"/>",
                             task_id ? task_id : "", slave_id ? slave_id : "");

  entity = NULL;
  ret = gmp (connection, credentials, NULL, &entity, response_data, command);
  g_free (command);
  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while moving a task. "
        "The task was not moved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while moving a task. "
        "It is unclear whether the task has been moved or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while moving a task. "
        "It is unclear whether the task has been moved or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  html = response_from_entity (connection, credentials, params, entity,
                               "Move Task", response_data);

  free_entity (entity);
  return html;
}

/**
 * @brief Get info, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_info_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
              params_t *params, gsad_command_response_data_t *response_data)
{
  const gchar *info_type;
  const gchar *info_name;
  const gchar *info_id;
  const gchar *details;

  gmp_arguments_t *arguments;

  info_type = params_value (params, "info_type");
  info_name = params_value (params, "info_name");
  info_id = params_value (params, "info_id");
  details = params_value (params, "details");

  CHECK_VARIABLE_INVALID (info_type, "Get SecInfo")

  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "type", info_type);
  if (details)
    {
      gmp_arguments_add (arguments, "details", details);
    }

  if (info_id)
    {
      gmp_arguments_add (arguments, "info_id", info_id);

      return get_entity (connection, "info", credentials, params, arguments,
                         response_data);
    }
  else if (info_name)
    {
      gmp_arguments_add (arguments, "name", info_name);
    }

  return get_many (connection, "info", credentials, params, arguments,
                   response_data);
}

/**
 * @brief Get all tasks, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_tasks_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  const char *schedules_only, *ignore_pagination, *usage_type;
  gmp_arguments_t *arguments;

  schedules_only = params_value (params, "schedules_only");
  ignore_pagination = params_value (params, "ignore_pagination");
  usage_type = params_value (params, "usage_type");
  if (params_given (params, "usage_type"))
    CHECK_VARIABLE_INVALID (usage_type, "Get Tasks");

  arguments = gmp_arguments_new ();

  if (schedules_only)
    {
      gmp_arguments_add (arguments, "schedules_only", schedules_only);
    }

  if (ignore_pagination)
    {
      gmp_arguments_add (arguments, "ignore_pargination", ignore_pagination);
    }

  if (usage_type)
    {
      gmp_arguments_add (arguments, "usage_type", usage_type);
    }

  return get_many (connection, "tasks", credentials, params, arguments,
                   response_data);
}

/**
 * @brief Get a task, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_task_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
              params_t *params, gsad_command_response_data_t *response_data)
{
  return get_one (connection, "task", credentials, params, NULL, NULL,
                  response_data);
}

/**
 * @brief Create a credential, get all credentials, envelope result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
create_credential_gmp (gvm_connection_t *connection,
                       gsad_credentials_t *credentials, params_t *params,
                       gsad_command_response_data_t *response_data)
{
  int ret;
  gchar *html;
  const char *name, *comment, *credential_login, *type, *password, *passphrase;
  const char *private_key, *public_key, *certificate, *community;
  const char *privacy_password, *auth_algorithm, *privacy_algorithm;
  const char *autogenerate;
  const char *kdc, *realm;
  params_t *kdcs_param;
  entity_t entity;

  name = params_value (params, "name");
  comment = params_value (params, "comment");
  credential_login = params_value (params, "credential_login");
  type = params_value (params, "credential_type");
  password = params_value (params, "lsc_password");
  passphrase = params_value (params, "passphrase");
  private_key = params_value (params, "private_key");
  public_key = params_value (params, "public_key");
  certificate = params_value (params, "certificate");
  community = params_value (params, "community");
  privacy_password = params_value (params, "privacy_password");
  auth_algorithm = params_value (params, "auth_algorithm");
  privacy_algorithm = params_value (params, "privacy_algorithm");
  autogenerate = params_value (params, "autogenerate");
  kdc = params_value (params, "kdc");
  realm = params_value (params, "realm");
  kdcs_param = params_values (params, "kdcs:");

  CHECK_VARIABLE_INVALID (name, "Create Credential");
  CHECK_VARIABLE_INVALID (comment, "Create Credential");
  CHECK_VARIABLE_INVALID (type, "Create Credential");
  CHECK_VARIABLE_INVALID (autogenerate, "Create Credential");

  if (str_equal (autogenerate, "1"))
    {
      if (str_equal (type, "cc"))
        {
          // Auto-generate types without username
          ret = gmpf (connection, credentials, NULL, &entity, response_data,
                      "<create_credential>"
                      "<name>%s</name>"
                      "<comment>%s</comment>"
                      "<type>%s</type>"
                      "<allow_insecure>1</allow_insecure>"
                      "</create_credential>",
                      name, comment ? comment : "", type);
        }
      else
        {
          // Auto-generate types with username
          CHECK_VARIABLE_INVALID (credential_login, "Create Credential");

          ret = gmpf (connection, credentials, NULL, &entity, response_data,
                      "<create_credential>"
                      "<name>%s</name>"
                      "<comment>%s</comment>"
                      "<type>%s</type>"
                      "<login>%s</login>"
                      "<allow_insecure>1</allow_insecure>"
                      "</create_credential>",
                      name, comment ? comment : "", type, credential_login);
        }
    }
  else
    {
      if (str_equal (type, "up"))
        {
          CHECK_VARIABLE_INVALID (credential_login, "Create Credential");
          CHECK_VARIABLE_INVALID (password, "Create Credential");

          ret = gmpf (connection, credentials, NULL, &entity, response_data,
                      "<create_credential>"
                      "<name>%s</name>"
                      "<comment>%s</comment>"
                      "<type>%s</type>"
                      "<login>%s</login>"
                      "<password>%s</password>"
                      "<allow_insecure>1</allow_insecure>"
                      "</create_credential>",
                      name, comment ? comment : "", type,
                      credential_login ? credential_login : "",
                      password ? password : "");
        }
      else if (str_equal (type, "krb5"))
        {
          GString *login_password_xml = g_string_new ("");
          CHECK_LOGIN_NAME_INVALID_CREATE (credential_login,
                                           "Create Credential");

          CHECK_VARIABLE_INVALID (password, "Create Credential");

          gchar *login_esc = g_markup_escape_text (
            credential_login ? credential_login : "", -1);
          gchar *password_esc =
            g_markup_escape_text (password ? password : "", -1);

          g_string_append_printf (login_password_xml,
                                  "<login>%s</login>"
                                  "<password>%s</password>",
                                  login_esc, password_esc);
          g_free (login_esc);
          g_free (password_esc);
          // escape provided values
          gchar *name_esc = g_markup_escape_text (name ? name : "", -1);
          gchar *comment_esc =
            g_markup_escape_text (comment ? comment : "", -1);
          gchar *type_esc = g_markup_escape_text (type, -1);
          gchar *realm_esc = g_markup_escape_text (realm ? realm : "", -1);

          GString *kdcs_xml = g_string_new ("");
          if (kdcs_param)
            {
              g_string_append (kdcs_xml, "<kdcs>");
              params_iterator_t iter;
              char *param_name;
              param_t *param;

              params_iterator_init (&iter, kdcs_param);
              while (params_iterator_next (&iter, &param_name, &param))
                {
                  if (param->value && *param->value)
                    {
                      gchar *escaped = g_markup_escape_text (param->value, -1);
                      g_string_append_printf (kdcs_xml, "<kdc>%s</kdc>",
                                              escaped);
                      g_free (escaped);
                    }
                }
              g_string_append (kdcs_xml, "</kdcs>");
            }
          else if (kdc && *kdc)
            {
              gchar *kdc_esc = g_markup_escape_text (kdc, -1);
              g_string_append_printf (kdcs_xml, "<kdc>%s</kdc>", kdc_esc);
              g_free (kdc_esc);
            }

          // build full command XML
          gchar *command = g_strdup_printf (
            "<create_credential>"
            "<name>%s</name>"
            "<comment>%s</comment>"
            "<type>%s</type>"
            "%s" // login and password block
            "%s" // kdcs or kdc block
            "<realm>%s</realm>"
            "<allow_insecure>1</allow_insecure>"
            "</create_credential>",
            name_esc, comment_esc, type_esc,
            login_password_xml->str ? login_password_xml->str : "",
            kdcs_xml->str ? kdcs_xml->str : "", realm_esc);

          ret = gmp (connection, credentials, NULL, &entity, response_data,
                     command);

          // cleanup
          g_free (command);
          g_string_free (kdcs_xml, TRUE);
          g_free (name_esc);
          g_free (comment_esc);
          g_free (type_esc);
          g_string_free (login_password_xml, TRUE);
          g_free (realm_esc);
        }
      else if (str_equal (type, "usk"))
        {
          CHECK_VARIABLE_INVALID (credential_login, "Create Credential");
          CHECK_VARIABLE_INVALID (private_key, "Create Credential");

          if (params_given (params, "passphrase"))
            CHECK_VARIABLE_INVALID (passphrase, "Create Credential");

          ret = gmpf (connection, credentials, NULL, &entity, response_data,
                      "<create_credential>"
                      "<name>%s</name>"
                      "<comment>%s</comment>"
                      "<type>%s</type>"
                      "<login>%s</login>"
                      "<key>"
                      "<private>%s</private>"
                      "<phrase>%s</phrase>"
                      "</key>"
                      "<allow_insecure>1</allow_insecure>"
                      "</create_credential>",
                      name, comment ? comment : "", type, credential_login,
                      private_key, passphrase ? passphrase : "");
        }
      else if (str_equal (type, "cc"))
        {
          CHECK_VARIABLE_INVALID (certificate, "Create Credential");
          CHECK_VARIABLE_INVALID (passphrase, "Create Credential");
          CHECK_VARIABLE_INVALID (private_key, "Create Credential");

          ret = gmpf (
            connection, credentials, NULL, &entity, response_data,
            "<create_credential>"
            "<name>%s</name>"
            "<comment>%s</comment>"
            "<type>%s</type>"
            "<certificate>%s</certificate>"
            "<key>"
            "<private>%s</private>"
            "<phrase>%s</phrase>"
            "</key>"
            "<allow_insecure>1</allow_insecure>"
            "</create_credential>",
            name, comment ? comment : "", type, certificate ? certificate : "",
            private_key ? private_key : "", passphrase ? passphrase : "");
        }
      else if (str_equal (type, "snmp"))
        {
          CHECK_VARIABLE_INVALID (community, "Create Credential");
          CHECK_VARIABLE_INVALID (credential_login, "Create Credential");
          CHECK_VARIABLE_INVALID (password, "Create Credential");
          CHECK_VARIABLE_INVALID (privacy_password, "Create Credential");
          CHECK_VARIABLE_INVALID (auth_algorithm, "Create Credential");
          CHECK_VARIABLE_INVALID (privacy_algorithm, "Create Credential");

          if (privacy_password && strcmp (privacy_password, ""))
            ret = gmpf (connection, credentials, NULL, &entity, response_data,
                        "<create_credential>"
                        "<name>%s</name>"
                        "<comment>%s</comment>"
                        "<type>%s</type>"
                        "<community>%s</community>"
                        "<login>%s</login>"
                        "<password>%s</password>"
                        "<privacy>"
                        "<password>%s</password>"
                        "<algorithm>%s</algorithm>"
                        "</privacy>"
                        "<auth_algorithm>%s</auth_algorithm>"
                        "<allow_insecure>1</allow_insecure>"
                        "</create_credential>",
                        name, comment ? comment : "", type,
                        community ? community : "",
                        credential_login ? credential_login : "",
                        password ? password : "",
                        privacy_password ? privacy_password : "",
                        privacy_algorithm ? privacy_algorithm : "",
                        auth_algorithm ? auth_algorithm : "");
          else
            ret = gmpf (
              connection, credentials, NULL, &entity, response_data,
              "<create_credential>"
              "<name>%s</name>"
              "<comment>%s</comment>"
              "<type>%s</type>"
              "<community>%s</community>"
              "<login>%s</login>"
              "<password>%s</password>"
              "<auth_algorithm>%s</auth_algorithm>"
              "<allow_insecure>1</allow_insecure>"
              "</create_credential>",
              name, comment ? comment : "", type, community ? community : "",
              credential_login ? credential_login : "",
              password ? password : "", auth_algorithm ? auth_algorithm : "");
        }
      else if (str_equal (type, "pgp"))
        {
          CHECK_VARIABLE_INVALID (public_key, "Create Credential");

          ret = gmpf (connection, credentials, NULL, &entity, response_data,
                      "<create_credential>"
                      "<name>%s</name>"
                      "<comment>%s</comment>"
                      "<type>%s</type>"
                      "<key>"
                      "<public>%s</public>"
                      "</key>"
                      "<allow_insecure>1</allow_insecure>"
                      "</create_credential>",
                      name, comment ? comment : "", type, public_key);
        }
      else if (str_equal (type, "smime"))
        {
          CHECK_VARIABLE_INVALID (certificate, "Create Credential");

          ret = gmpf (connection, credentials, NULL, &entity, response_data,
                      "<create_credential>"
                      "<name>%s</name>"
                      "<comment>%s</comment>"
                      "<type>%s</type>"
                      "<certificate>%s</certificate>"
                      "<allow_insecure>1</allow_insecure>"
                      "</create_credential>",
                      name, comment ? comment : "", type, certificate);
        }
      else if (type && (strcmp (type, "pw") == 0))
        {
          CHECK_VARIABLE_INVALID (password, "Create Credential");

          ret =
            gmpf (connection, credentials, NULL, &entity, response_data,
                  "<create_credential>"
                  "<name>%s</name>"
                  "<comment>%s</comment>"
                  "<type>%s</type>"
                  "<password>%s</password>"
                  "<allow_insecure>1</allow_insecure>"
                  "</create_credential>",
                  name, comment ? comment : "", type, password ? password : "");
        }
      else
        {
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while creating a new credential. "
            "The credential could not be created. "
            "Diagnostics: Unrecognized credential type.",
            response_data);
        }
    }

  /* Create the credential. */
  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new credential. "
        "It is unclear whether the credential has been created or not. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new credential. "
        "It is unclear whether the credential has been created or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new credential. "
        "It is unclear whether the credential has been created or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  if (entity_attribute (entity, "id"))
    params_add (params, "credential_id", entity_attribute (entity, "id"));
  html = response_from_entity (connection, credentials, params, entity,
                               "Create Credential", response_data);
  free_entity (entity);
  return html;
}

/**
 * @brief Get one credential, envelope the result.
 *
 * @param[in]   connection         Connection to manager.
 * @param[in]   credentials        Username and password for authentication.
 * @param[in]   params             Request parameters.
 * @param[in]   extra_xml          Extra XML to insert inside page element.
 * @param[out]  response_data      Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_credential (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, const char *extra_xml,
                gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments = gmp_arguments_new ();
  gmp_arguments_add (arguments, "targets", "1");
  gmp_arguments_add (arguments, "scanners", "1");
  return get_one (connection, "credential", credentials, params, extra_xml,
                  arguments, response_data);
}

/**
 * @brief Get one credential, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_credential_gmp (gvm_connection_t *connection,
                    gsad_credentials_t *credentials, params_t *params,
                    gsad_command_response_data_t *response_data)
{
  return get_credential (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Export a Credential in a defined format.
 *
 * @param[in]   connection     Connection to manager.
 * @param[in]   credentials    Username and password for authentication.
 * @param[in]   params         Request parameters.
 * @param[out]  response_data  Extra data return for the HTTP response.
 *
 * @return Binary data
 */
char *
download_credential_gmp (gvm_connection_t *connection,
                         gsad_credentials_t *credentials, params_t *params,
                         gsad_command_response_data_t *response_data)
{
  entity_t entity = NULL, credential_entity = NULL;
  const gchar *credential_id, *format;
  gchar *data = NULL, *content_disposition = NULL, *login = NULL;
  content_type_t content_type = GSAD_CONTENT_TYPE_OCTET_STREAM;

  credential_id = params_value (params, "credential_id");
  format = params_value (params, "package_format");

  CHECK_VARIABLE_INVALID (format, "Download Credential");
  CHECK_VARIABLE_INVALID (credential_id, "Download Credential");

  if (str_equal (credential_id, ""))
    return message_invalid (connection, credentials, params, response_data,
                            "Required credential_id parameter is missing.",
                            "Download Credential");

  if (gvm_connection_sendf (connection,
                            "<get_credentials"
                            " credential_id=\"%s\""
                            " format=\"%s\"/>",
                            credential_id, format)
      == -1)
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a credential. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  if (strcmp (format, "rpm") == 0 || strcmp (format, "deb") == 0
      || strcmp (format, "exe") == 0)
    {
      entity_t package_entity = NULL;

      /* A base64 encoded package. */
      if (read_entity_c (connection, &entity))
        {
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a credential. "
            "The credential is not available. "
            "Diagnostics: Failure to receive response from manager daemon.",
            response_data);
        }

      credential_entity = entity_child (entity, "credential");
      if (credential_entity)
        package_entity = entity_child (credential_entity, "package");
      if (package_entity != NULL)
        {
          gsize len;
          char *package_encoded = entity_text (package_entity);
          if (strlen (package_encoded))
            {
              data = (gchar *) g_base64_decode (package_encoded, &len);
              if (data == NULL)
                {
                  data = g_strdup ("");
                  len = 0;
                }
            }
          else
            {
              data = g_strdup ("");
              len = 0;
            }

          gsad_command_response_data_set_content_length (response_data, len);
        }
      else
        {
          free_entity (entity);
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a credential. "
            "The credential could not be delivered. "
            "Diagnostics: Failure to receive credential from manager daemon.",
            response_data);
        }
    }
  else
    {
      entity_t key_entity = NULL;

      /* A key or certificate. */
      if (read_entity_c (connection, &entity))
        {
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a credential. "
            "The credential could not be delivered. "
            "Diagnostics: Failure to receive credential from manager daemon.",
            response_data);
        }

      credential_entity = entity_child (entity, "credential");
      if (credential_entity)
        {
          if (strcmp (format, "pem") == 0)
            key_entity = entity_child (credential_entity, "certificate");
          else
            key_entity = entity_child (credential_entity, "public_key");
        }
      if (key_entity != NULL)
        {
          data = g_strdup (entity_text (key_entity));
          entity_t login_entity = entity_child (credential_entity, "login");
          if (login_entity)
            login = g_strdup (entity_text (login_entity));
          else
            login = NULL;

          gsad_command_response_data_set_content_length (response_data,
                                                         strlen (data));
        }
      else
        {
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          free_entity (entity);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a credential. "
            "The credential could not be delivered. "
            "Diagnostics: Failure to parse credential from manager daemon.",
            response_data);
        }
    }

  if (credential_entity != NULL)
    {
      entity_t login_entity;
      login_entity = entity_child (credential_entity, "login");
      if (login_entity)
        login = g_strdup (entity_text (login_entity));
      else
        login = NULL;
    }

  content_disposition =
    g_strdup_printf ("attachment; filename=credential-%s.%s",
                     (login && strcmp (login, "")) ? login : credential_id,
                     (strcmp (format, "key") == 0 ? "pub" : format));
  content_type_from_format_string (&content_type, format);

  gsad_command_response_data_set_content_disposition (response_data,
                                                      content_disposition);
  gsad_command_response_data_set_content_type (response_data, content_type);

  free_entity (entity);
  g_free (login);

  return data;
}

/**
 * @brief Export a Credential.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Credential XML on success.  Enveloped XML
 *         on error.
 */
char *
export_credential_gmp (gvm_connection_t *connection,
                       gsad_credentials_t *credentials, params_t *params,
                       gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "credential", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of Credentials.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Credentials XML on success.  Enveloped XML
 *         on error.
 */
char *
export_credentials_gmp (gvm_connection_t *connection,
                        gsad_credentials_t *credentials, params_t *params,
                        gsad_command_response_data_t *response_data)
{
  return export_many (connection, "credential", credentials, params,
                      response_data);
}

/**
 * @brief Get one or all credentials, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return 0 success, 1 failure.
 */
char *
get_credentials_gmp (gvm_connection_t *connection,
                     gsad_credentials_t *credentials, params_t *params,
                     gsad_command_response_data_t *response_data)
{
  return get_many (connection, "credentials", credentials, params, NULL,
                   response_data);
}

/**
 * @brief Delete credential, get all credentials, envelope result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_credential_gmp (gvm_connection_t *connection,
                       gsad_credentials_t *credentials, params_t *params,
                       gsad_command_response_data_t *response_data)
{
  return move_resource_to_trash (connection, "credential", credentials, params,
                                 response_data);
}

/**
 * @brief Save credential, get next page, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials       Username and password for authentication.
 * @param[in]  params            Request parameters.
 * @param[out] response_data     Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
save_credential_gmp (gvm_connection_t *connection,
                     gsad_credentials_t *credentials, params_t *params,
                     gsad_command_response_data_t *response_data)
{
  int ret;
  gchar *html = NULL;
  const char *credential_id, *public_key;
  const char *name, *comment, *credential_login, *password, *passphrase, *type;
  const char *private_key, *certificate, *community, *privacy_password;
  const char *kdc, *realm;
  const char *auth_algorithm, *privacy_algorithm;
  params_t *kdcs_param;
  GString *command;
  entity_t entity = NULL;

  credential_id = params_value (params, "credential_id");
  type = params_value (params, "credential_type");
  name = params_value (params, "name");
  comment = params_value (params, "comment");
  credential_login = params_value (params, "credential_login");
  password = params_value (params, "password");
  passphrase = params_value (params, "passphrase");
  private_key = params_value (params, "private_key");
  certificate = params_value (params, "certificate");
  community = params_value (params, "community");
  privacy_password = params_value (params, "privacy_password");
  auth_algorithm = params_value (params, "auth_algorithm");
  privacy_algorithm = params_value (params, "privacy_algorithm");
  kdc = params_value (params, "kdc");
  realm = params_value (params, "realm");
  public_key = params_value (params, "public_key");
  kdcs_param = params_values (params, "kdcs:");

  CHECK_VARIABLE_INVALID (credential_id, "Save Credential");
  CHECK_VARIABLE_INVALID (name, "Save Credential");
  CHECK_VARIABLE_INVALID (comment, "Save Credential");
  CHECK_VARIABLE_INVALID (type, "Save Credential");

  if (str_equal (credential_id, ""))
    return message_invalid (connection, credentials, params, response_data,
                            "Missing credential_id", "Save Credential");

  if (str_equal (type, "cc"))
    {
      if (params_given (params, "certificate"))
        CHECK_VARIABLE_INVALID (certificate, "Save Credential");

      if (params_given (params, "private_key"))
        CHECK_VARIABLE_INVALID (private_key, "Save Credential");

      if (params_given (params, "passphrase"))
        CHECK_VARIABLE_INVALID (passphrase, "Save Credential");
    }
  else if (str_equal (type, "krb5"))
    {
      if (params_given (params, "credential_login"))
        CHECK_LOGIN_NAME_INVALID_EDIT (credential_login, "Save Credential");
    }
  else if (str_equal (type, "snmp"))
    {
      if (params_given (params, "auth_algorithm"))
        CHECK_VARIABLE_INVALID (auth_algorithm, "Save Credential");

      if (params_given (params, "privacy_algorithm"))
        CHECK_VARIABLE_INVALID (privacy_algorithm, "Save Credential");

      if (params_given (params, "privacy_password"))
        CHECK_VARIABLE_INVALID (privacy_password, "Save Credential");

      if (params_given (params, "community"))
        CHECK_VARIABLE_INVALID (community, "Save Credential");
    }
  else if (str_equal (type, "up") || str_equal (type, "pw"))
    {
      if (params_given (params, "password"))
        CHECK_VARIABLE_INVALID (password, "Save Credential");
    }
  else if (str_equal (type, "smime"))
    {
      if (params_given (params, "certificate"))
        CHECK_VARIABLE_INVALID (certificate, "Save Credential");
    }
  else if (str_equal (type, "smime") || str_equal (type, "pgp"))
    {
      if (params_given (params, "public_key"))
        CHECK_VARIABLE_INVALID (public_key, "Save Credential");
    }
  else if (str_equal (type, "usk"))
    {
      if (params_given (params, "private_key"))
        CHECK_VARIABLE_INVALID (private_key, "Save Credential");

      if (params_given (params, "passphrase"))
        CHECK_VARIABLE_INVALID (passphrase, "Save Credential");
    }

  if (!str_equal (type, "krb5") && params_given (params, "credential_login"))
    CHECK_VARIABLE_INVALID (credential_login, "Save Credential");

  /* Prepare command */
  command = g_string_new ("");

  xml_string_append (command,
                     "<modify_credential credential_id=\"%s\">"
                     "<name>%s</name>"
                     "<comment>%s</comment>"
                     "<allow_insecure>1</allow_insecure>",
                     credential_id, name, comment);

  if (str_equal (type, "snmp"))
    {
      if (auth_algorithm)
        xml_string_append (command, "<auth_algorithm>%s</auth_algorithm>",
                           auth_algorithm);

      if (community)
        xml_string_append (command, "<community>%s</community>", community);

      if (privacy_algorithm || privacy_password)
        {
          xml_string_append (command, "<privacy>");
          if (privacy_algorithm)
            {
              xml_string_append (command, "<algorithm>%s</algorithm>",
                                 privacy_algorithm);
            }
          if (privacy_password)
            {
              xml_string_append (command, "<password>%s</password>",
                                 privacy_password);
            }

          xml_string_append (command, "</privacy>");
        }
    }
  else if (str_equal (type, "krb5"))
    {
      if (kdcs_param)
        {
          xml_string_append (command, "<kdcs>");
          params_iterator_t iter;
          char *param_name;
          param_t *param;

          params_iterator_init (&iter, kdcs_param);
          while (params_iterator_next (&iter, &param_name, &param))
            {
              if (param->value && *param->value)
                xml_string_append (command, "<kdc>%s</kdc>", param->value);
            }
          xml_string_append (command, "</kdcs>");
        }
      else
        {
          if (kdc)
            {
              xml_string_append (command, "<kdc>%s</kdc>", kdc);
            }
        }
      if (realm)
        {
          xml_string_append (command, "<realm>%s</realm>", realm);
        }
    }
  else if (str_equal (type, "cc"))
    {
      if (certificate)
        {
          xml_string_append (command, "<certificate>%s</certificate>",
                             certificate);
        }

      if (private_key || passphrase)
        {
          xml_string_append (command, "<key>");
          if (passphrase)
            xml_string_append (command, "<phrase>%s</phrase>", passphrase);
          if (private_key)
            xml_string_append (command, "<private>%s</private>", private_key);
          xml_string_append (command, "</key>");
        }
    }
  else if (str_equal (type, "usk"))
    {
      if (private_key || passphrase)
        {
          xml_string_append (command, "<key>");
          if (passphrase)
            xml_string_append (command, "<phrase>%s</phrase>", passphrase);
          if (private_key)
            xml_string_append (command, "<private>%s</private>", private_key);
          xml_string_append (command, "</key>");
        }
    }
  else if (str_equal (type, "up") || str_equal (type, "pw"))
    {
      if (password)
        xml_string_append (command, "<password>%s</password>", password);
    }
  else if (str_equal (type, "smime"))
    {
      if (certificate)
        {
          xml_string_append (command, "<certificate>%s</certificate>",
                             certificate);
        }
    }
  else if (str_equal (type, "pgp"))
    {
      if (public_key)
        {
          xml_string_append (command, "<key>");
          xml_string_append (command, "<public>%s</public>", public_key);
          xml_string_append (command, "</key>");
        }
    }

  if (credential_login)
    xml_string_append (command, "<login>%s</login>", credential_login);

  xml_string_append (command, "</modify_credential>");

  /* Modify the credential. */
  ret =
    gmp (connection, credentials, NULL, &entity, response_data, command->str);
  g_string_free (command, TRUE);

  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a Credential. "
        "The Credential was not saved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a Credential. "
        "It is unclear whether the Credential has been saved or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a Credential. "
        "It is unclear whether the Credential has been saved or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  html = response_from_entity (connection, credentials, params, entity,
                               "Save Credential", response_data);
  free_entity (entity);
  return html;
}

/**
 * @brief Get an aggregate of resources.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return The aggregate.
 */
char *
get_aggregate_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  params_t *data_columns, *text_columns;
  params_t *sort_fields, *sort_stats, *sort_orders;
  params_iterator_t data_columns_iterator, text_columns_iterator;
  params_iterator_t sort_fields_iterator, sort_stats_iterator;
  params_iterator_t sort_orders_iterator;
  char *param_name;
  param_t *param;

  const char *data_column, *group_column, *subgroup_column, *type;
  const char *filter, *filter_id;
  const char *first_group, *max_groups;
  const char *mode;
  const char *usage_type;
  gchar *filter_escaped, *command_escaped, *response;
  entity_t entity;
  GString *xml, *command;
  int ret;

  data_columns = params_values (params, "data_columns:");
  data_column = params_value (params, "data_column");
  text_columns = params_values (params, "text_columns:");
  group_column = params_value (params, "group_column");
  subgroup_column = params_value (params, "subgroup_column");
  type = params_value (params, "aggregate_type");
  filter = params_value (params, "filter");
  filter_id = params_value (params, "filter_id");
  sort_fields = params_values (params, "sort_fields:");
  sort_stats = params_values (params, "sort_stats:");
  sort_orders = params_values (params, "sort_orders:");
  first_group = params_value (params, "first_group");
  max_groups = params_value (params, "max_groups");
  mode = params_value (params, "aggregate_mode");
  usage_type = params_value (params, "usage_type");

  if (filter && !str_equal (filter, ""))
    filter_escaped = g_markup_escape_text (filter, -1);
  else
    {
      if (filter_id == NULL || str_equal (filter_id, "")
          || str_equal (filter_id, FILT_ID_NONE))
        filter_escaped = g_strdup ("rows=-2");
      else
        filter_escaped = NULL;
    }

  xml = g_string_new ("<get_aggregate>");

  command = g_string_new ("<get_aggregates");
  g_string_append_printf (command, " type=\"%s\"", type);
  if (data_column)
    g_string_append_printf (command, " data_column=\"%s\"", data_column);

  if (group_column)
    g_string_append_printf (command, " group_column=\"%s\"", group_column);

  if (subgroup_column)
    g_string_append_printf (command, " subgroup_column=\"%s\"",
                            subgroup_column);
  if (filter_escaped && strcmp (filter_escaped, ""))
    g_string_append_printf (command, " filter=\"%s\"", filter_escaped);

  if (filter_id && !str_equal (filter_id, ""))
    g_string_append_printf (command, " filt_id=\"%s\"", filter_id);

  if (first_group && strcmp (first_group, ""))
    g_string_append_printf (command, " first_group=\"%s\"", first_group);

  if (max_groups && strcmp (max_groups, ""))
    g_string_append_printf (command, " max_groups=\"%s\"", max_groups);

  if (mode && strcmp (mode, ""))
    g_string_append_printf (command, " mode=\"%s\"", mode);

  if (usage_type && strcmp (usage_type, ""))
    g_string_append_printf (command, " usage_type=\"%s\"", usage_type);

  g_string_append (command, ">");

  if (sort_fields && sort_stats && sort_orders)
    {
      param_t *field_param, *stat_param, *order_param;
      gchar *field_i, *stat_i, *order_i;

      params_iterator_init (&sort_fields_iterator, sort_fields);
      params_iterator_init (&sort_stats_iterator, sort_stats);
      params_iterator_init (&sort_orders_iterator, sort_orders);

      while (
        params_iterator_next (&sort_fields_iterator, &field_i, &field_param)
        && params_iterator_next (&sort_stats_iterator, &stat_i, &stat_param)
        && params_iterator_next (&sort_orders_iterator, &order_i, &order_param))
        {
          if (field_param->valid && stat_param->valid && order_param->valid)
            {
              xml_string_append (command,
                                 "<sort field=\"%s\""
                                 "      stat=\"%s\""
                                 "      order=\"%s\"/>",
                                 field_param->value ? field_param->value : "",
                                 stat_param->value ? stat_param->value : "",
                                 order_param->value ? order_param->value : "");
            }
        }
    }

  if (data_columns)
    {
      params_iterator_init (&data_columns_iterator, data_columns);
      while (params_iterator_next (&data_columns_iterator, &param_name, &param))
        {
          if (param->valid)
            {
              xml_string_append (command, "<data_column>%s</data_column>",
                                 param->value);
            }
        }
    }

  if (text_columns)
    {
      params_iterator_init (&text_columns_iterator, text_columns);
      while (params_iterator_next (&text_columns_iterator, &param_name, &param))
        {
          if (param->valid)
            {
              xml_string_append (command, "<text_column>%s</text_column>",
                                 param->value);
            }
        }
    }

  g_string_append (command, "</get_aggregates>");

  g_free (filter_escaped);

  command_escaped = g_markup_escape_text (command->str, -1);
  g_string_append (xml, command_escaped);
  g_free (command_escaped);

  response = NULL;
  ret = gmp (connection, credentials, &response, &entity, response_data,
             command->str);
  g_string_free (command, TRUE);

  if (ret)
    {
      free_entity (entity);
      g_string_free (xml, TRUE);
    }

  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting aggregates. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting aggregates. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting aggregates. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  if (gmp_success (entity) == 0)
    set_http_status_from_entity (entity, response_data);

  g_string_append (xml, response);

  g_string_append (xml, "</get_aggregate>");

  free_entity (entity);
  g_free (response);
  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Delete an alert, get all alerts, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_alert_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  return move_resource_to_trash (connection, "alert", credentials, params,
                                 response_data);
}

/**
 * @brief Get one alert, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[in]  extra_xml    Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_alert (gvm_connection_t *connection, gsad_credentials_t *credentials,
           params_t *params, const char *extra_xml,
           gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments;
  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "tasks", "1");

  return get_one (connection, "alert", credentials, params, NULL, arguments,
                  response_data);
}

/**
 * @brief Get one alert, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials   Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_alert_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  return get_alert (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Get all alerts, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_alerts_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  return get_many (connection, "alerts", credentials, params, NULL,
                   response_data);
}

/**
 * @brief Test an alert, get all alerts envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
test_alert_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  gchar *html;
  const char *alert_id;
  entity_t entity;

  alert_id = params_value (params, "alert_id");

  if (alert_id == NULL)
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  GSAD_STATUS_INVALID_REQUEST);
      return gsad_http_create_gsad_message (
        credentials,
        "Missing parameter alert_id."
        "Diagnostics: Required parameter was NULL.",
        response_data);
    }

  /* Test the alert. */

  if (gvm_connection_sendf (connection, "<test_alert alert_id=\"%s\"/>",
                            alert_id)
      == -1)
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while testing an alert. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  entity = NULL;
  if (read_entity_c (connection, &entity))
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while testing an alert. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  html = response_from_entity (connection, credentials, params, entity,
                               "Test Alert", response_data);

  free_entity (entity);
  return html;
}

/**
 * @brief Export an alert.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Alert XML on success.  Enveloped XML on error.
 */
char *
export_alert_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "alert", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of alerts.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Alerts XML on success.  Enveloped XML
 *         on error.
 */
char *
export_alerts_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return export_many (connection, "alert", credentials, params, response_data);
}

/**
 * @brief Create a target, get all targets, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
create_target_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  int ret;
  gchar *html, *command;
  const char *name, *hosts, *exclude_hosts, *comment;
  const char *target_ssh_credential, *port, *target_smb_credential;
  const char *target_ssh_elevate_credential;
  const char *target_krb5_credential;
  const char *target_esxi_credential, *target_snmp_credential, *target_source;
  const char *target_exclude_source;
  const char *port_list_id, *reverse_lookup_only, *reverse_lookup_unify;
  const char *alive_tests = NULL;
  GHashTable *alive_tests_table;
  const char *hosts_filter, *file, *exclude_file;
  const char *allow_simultaneous_ips;
  gchar *ssh_credentials_element, *smb_credentials_element;
  gchar *krb5_credentials_element;
  gchar *esxi_credentials_element, *snmp_credentials_element;
  gchar *ssh_elevate_credentials_element;
  gchar *asset_hosts_element;
  gchar *comment_element = NULL;
  entity_t entity;
  GString *xml;

  name = params_value (params, "name");
  hosts = params_value (params, "hosts");
  exclude_hosts = params_value (params, "exclude_hosts");
  reverse_lookup_only = params_value (params, "reverse_lookup_only");
  reverse_lookup_unify = params_value (params, "reverse_lookup_unify");
  target_source = params_value (params, "target_source");
  target_exclude_source = params_value (params, "target_exclude_source");
  comment = params_value (params, "comment");
  port_list_id = params_value (params, "port_list_id");
  target_ssh_credential = params_value (params, "ssh_credential_id");
  target_ssh_elevate_credential =
    params_value (params, "ssh_elevate_credential_id");
  port = params_value (params, "port");
  target_smb_credential = params_value (params, "smb_credential_id");
  target_esxi_credential = params_value (params, "esxi_credential_id");
  target_krb5_credential = params_value (params, "krb5_credential_id");
  target_snmp_credential = params_value (params, "snmp_credential_id");
  hosts_filter = params_value (params, "hosts_filter");
  file = params_value (params, "file");
  exclude_file = params_value (params, "exclude_file");
  allow_simultaneous_ips = params_value (params, "allow_simultaneous_ips");
  alive_tests_table = params_values (params, "alive_tests:");

  CHECK_VARIABLE_INVALID (name, "Create Target");
  CHECK_VARIABLE_INVALID (target_source, "Create Target")
  if (strcmp (target_source, "manual") == 0)
    CHECK_VARIABLE_INVALID (hosts, "Create Target");
  if (strcmp (target_source, "file") == 0)
    CHECK_VARIABLE_INVALID (file, "Create Target")
  /* require hosts_filter if target_source is "asset_hosts" */
  if (strcmp (target_source, "asset_hosts") == 0)
    CHECK_VARIABLE_INVALID (hosts_filter, "Create Target");

  if (params_given (params, "alive_tests"))
    {
      alive_tests = params_value (params, "alive_tests");
      CHECK_VARIABLE_INVALID (alive_tests, "Create Target");
    }

  if (params_given (params, "target_exclude_source"))
    {
      CHECK_VARIABLE_INVALID (target_exclude_source, "Create Target")
      if (strcmp (target_exclude_source, "manual") == 0
          /* In case browser doesn't send empty field. */
          && params_given (params, "exclude_hosts"))
        CHECK_VARIABLE_INVALID (exclude_hosts, "Create Target");
      if (strcmp (target_exclude_source, "file") == 0)
        CHECK_VARIABLE_INVALID (exclude_file, "Create Target");
    }

  CHECK_VARIABLE_INVALID (comment, "Create Target");
  CHECK_VARIABLE_INVALID (port_list_id, "Create Target");
  CHECK_VARIABLE_INVALID (target_ssh_credential, "Create Target");
  if (strcmp (target_ssh_credential, "--"))
    CHECK_VARIABLE_INVALID (port, "Create Target");
  if (params_given (params, "ssh_elevate_credential_id"))
    CHECK_VARIABLE_INVALID (target_ssh_elevate_credential, "Create Target");
  CHECK_VARIABLE_INVALID (target_smb_credential, "Create Target");
  CHECK_VARIABLE_INVALID (target_esxi_credential, "Create Target");
  if (params_given (params, "krb5_credential_id"))
    CHECK_VARIABLE_INVALID (target_krb5_credential, "Create Target");
  CHECK_VARIABLE_INVALID (target_snmp_credential, "Create Target");
  CHECK_VARIABLE_INVALID (allow_simultaneous_ips, "Create Target");

  if (comment != NULL)
    comment_element =
      g_markup_printf_escaped ("<comment>%s</comment>", comment);
  else
    comment_element = g_strdup ("");

  if (strcmp (target_ssh_credential, "0") == 0)
    {
      ssh_credentials_element = g_strdup ("");
      ssh_elevate_credentials_element = g_strdup ("");
    }
  else
    {
      ssh_credentials_element = g_strdup_printf ("<ssh_credential id=\"%s\">"
                                                 "<port>%s</port>"
                                                 "</ssh_credential>",
                                                 target_ssh_credential, port);
      if (target_ssh_elevate_credential)
        ssh_elevate_credentials_element = g_strdup_printf (
          "<ssh_elevate_credential id=\"%s\"/>", target_ssh_elevate_credential);
      else
        ssh_elevate_credentials_element = NULL;
    }

  if (strcmp (target_smb_credential, "0") == 0)
    smb_credentials_element = g_strdup ("");
  else
    smb_credentials_element =
      g_strdup_printf ("<smb_credential id=\"%s\"/>", target_smb_credential);

  if (strcmp (target_esxi_credential, "0") == 0)
    esxi_credentials_element = g_strdup ("");
  else
    esxi_credentials_element =
      g_strdup_printf ("<esxi_credential id=\"%s\"/>", target_esxi_credential);

  if (target_krb5_credential)
    {
      if (strcmp (target_krb5_credential, "0") == 0)
        krb5_credentials_element = g_strdup ("");
      else
        krb5_credentials_element = g_strdup_printf (
          "<krb5_credential id=\"%s\"/>", target_krb5_credential);
    }
  else
    krb5_credentials_element = NULL;

  if (strcmp (target_snmp_credential, "0") == 0)
    snmp_credentials_element = g_strdup ("");
  else
    snmp_credentials_element =
      g_strdup_printf ("<snmp_credential id=\"%s\"/>", target_snmp_credential);

  if (strcmp (target_source, "asset_hosts") == 0)
    asset_hosts_element = g_markup_printf_escaped ("<asset_hosts"
                                                   " filter=\"%s\"/>",
                                                   hosts_filter);
  else
    asset_hosts_element = g_strdup ("");

  /* Create the target. */

  xml = g_string_new ("");

  xml_string_append (
    xml,
    "<name>%s</name>"
    "<hosts>%s</hosts>"
    "<exclude_hosts>%s</exclude_hosts>"
    "<reverse_lookup_only>%s</reverse_lookup_only>"
    "<reverse_lookup_unify>%s</reverse_lookup_unify>"
    "<port_list id=\"%s\"/>"
    "<allow_simultaneous_ips>%s</allow_simultaneous_ips>",
    name, strcmp (target_source, "file") == 0 ? file : hosts,
    target_exclude_source ? (strcmp (target_exclude_source, "file") == 0
                               ? exclude_file
                               : (exclude_hosts ? exclude_hosts : ""))
                          : "",
    reverse_lookup_only ? reverse_lookup_only : "0",
    reverse_lookup_unify ? reverse_lookup_unify : "0", port_list_id,
    allow_simultaneous_ips ? allow_simultaneous_ips : "1");

  if (alive_tests_table)
    {
      params_iterator_t iter;
      char *name;
      param_t *param;

      params_iterator_init (&iter, alive_tests_table);
      g_string_append (xml, "<alive_tests>");
      while (params_iterator_next (&iter, &name, &param))
        if (param->value)
          g_string_append_printf (xml, "<alive_test>%s</alive_test>",
                                  param->value);
      g_string_append (xml, "</alive_tests>");
    }
  else if (alive_tests)
    {
      g_string_append_printf (xml, "<alive_tests>%s</alive_tests>",
                              alive_tests);
    }

  command = g_strdup_printf (
    "<create_target>"
    "%s%s%s%s%s%s%s%s%s"
    "</create_target>",
    xml->str, comment_element, ssh_credentials_element,
    ssh_elevate_credentials_element ? ssh_elevate_credentials_element : "",
    smb_credentials_element, esxi_credentials_element, snmp_credentials_element,
    krb5_credentials_element ?: "", asset_hosts_element);

  g_string_free (xml, TRUE);
  g_free (comment_element);
  g_free (ssh_credentials_element);
  g_free (ssh_elevate_credentials_element);
  g_free (smb_credentials_element);
  g_free (snmp_credentials_element);
  g_free (esxi_credentials_element);
  g_free (krb5_credentials_element);
  g_free (asset_hosts_element);

  ret = gmp (connection, credentials, NULL, &entity, response_data, command);
  g_free (command);
  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new target. "
        "No new target was created. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new target. "
        "It is unclear whether the target has been created or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new target. "
        "It is unclear whether the target has been created or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  if (entity_attribute (entity, "id"))
    params_add (params, "target_id", entity_attribute (entity, "id"));
  html = response_from_entity (connection, credentials, params, entity,
                               "Create Target", response_data);
  free_entity (entity);
  return html;
}

/**
 * @brief Delete a target, get all targets, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_target_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return move_resource_to_trash (connection, "target", credentials, params,
                                 response_data);
}



/**
 * @brief Export a tag.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Target XML on success.  Enveloped XML
 *         on error.
 */
/**
 * @brief Get one tag, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[in]  extra_xml    Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_tag (gvm_connection_t *connection, gsad_credentials_t *credentials,
         params_t *params, const char *extra_xml,
         gsad_command_response_data_t *response_data)
{
  return get_one (connection, "tag", credentials, params, extra_xml, NULL,
                  response_data);
}

/**
 * @brief Get one tag, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_tag_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
             params_t *params, gsad_command_response_data_t *response_data)
{
  return get_tag (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Get all tags, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_tags_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
              params_t *params, gsad_command_response_data_t *response_data)
{
  return get_many (connection, "tags", credentials, params, NULL,
                   response_data);
}


/**
 * @brief Get one target, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[in]  extra_xml    Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_target (gvm_connection_t *connection, gsad_credentials_t *credentials,
            params_t *params, const char *extra_xml,
            gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments;
  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "tasks", "1");

  return get_one (connection, "target", credentials, params, extra_xml,
                  arguments, response_data);
}

/**
 * @brief Get one target, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_target_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  return get_target (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Get all targets, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_targets_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  return get_many (connection, "targets", credentials, params, NULL,
                   response_data);
}

/**
 * @brief Modify a target, get all targets, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
save_target_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  gchar *html;
  const char *name, *comment, *target_id;
  const char *hosts = NULL, *exclude_hosts = NULL;
  const char *hosts_file = NULL, *exclude_hosts_file = NULL;
  const char *target_ssh_credential = NULL, *port = NULL;
  const char *target_ssh_elevate_credential = NULL;
  const char *target_esxi_credential = NULL, *target_snmp_credential = NULL;
  const char *target_krb5_credential = NULL, *target_smb_credential = NULL;
  const char *target_source = NULL, *target_exclude_source = NULL;
  const char *reverse_lookup_unify = NULL, *reverse_lookup_only = NULL;
  const char *allow_simultaneous_ips = NULL;
  const char *port_list_id = NULL;
  const char *alive_tests = NULL;
  GHashTable *alive_tests_table = NULL;
  GString *command;

  name = params_value (params, "name");
  comment = params_value (params, "comment");
  target_id = params_value (params, "target_id");
  alive_tests_table = params_values (params, "alive_tests:");

  CHECK_VARIABLE_INVALID (name, "Save Target");
  CHECK_VARIABLE_INVALID (target_id, "Save Target");

  if (params_given (params, "comment"))
    {
      comment = params_value (params, "comment");
      CHECK_VARIABLE_INVALID (comment, "Save Target");
    }
  if (params_given (params, "alive_tests"))
    {
      alive_tests = params_value (params, "alive_tests");
      CHECK_VARIABLE_INVALID (alive_tests, "Save Target");
    }
  if (params_given (params, "target_source"))
    {
      target_source = params_value (params, "target_source");
      CHECK_VARIABLE_INVALID (target_source, "Save Target");
    }
  if (params_given (params, "target_exclude_source"))
    {
      target_exclude_source = params_value (params, "target_exclude_source");
      CHECK_VARIABLE_INVALID (target_exclude_source, "Save Target");
    }
  if (params_given (params, "port_list_id"))
    {
      port_list_id = params_value (params, "port_list_id");
      CHECK_VARIABLE_INVALID (port_list_id, "Save Target");
    }
  if (params_given (params, "reverse_lookup_only"))
    {
      reverse_lookup_only = params_value (params, "reverse_lookup_only");
      CHECK_VARIABLE_INVALID (reverse_lookup_only, "Save Target");
    }
  if (params_given (params, "reverse_lookup_unify"))
    {
      reverse_lookup_unify = params_value (params, "reverse_lookup_unify");
      CHECK_VARIABLE_INVALID (reverse_lookup_unify, "Save Target");
    }
  if (params_given (params, "ssh_credential_id"))
    {
      target_ssh_credential = params_value (params, "ssh_credential_id");
      CHECK_VARIABLE_INVALID (target_ssh_credential, "Save Target");
    }
  if (params_given (params, "smb_credential_id"))
    {
      target_smb_credential = params_value (params, "smb_credential_id");
      CHECK_VARIABLE_INVALID (target_smb_credential, "Save Target");
    }
  if (params_given (params, "esxi_credential_id"))
    {
      target_esxi_credential = params_value (params, "esxi_credential_id");
      CHECK_VARIABLE_INVALID (target_esxi_credential, "Save Target");
    }
  if (params_given (params, "krb5_credential_id"))
    {
      target_krb5_credential = params_value (params, "krb5_credential_id");
      CHECK_VARIABLE_INVALID (target_krb5_credential, "Save Target");
    }
  if (params_given (params, "snmp_credential_id"))
    {
      target_snmp_credential = params_value (params, "snmp_credential_id");
      CHECK_VARIABLE_INVALID (target_snmp_credential, "Save Target");
    }
  if (params_given (params, "allow_simultaneous_ips"))
    {
      allow_simultaneous_ips = params_value (params, "allow_simultaneous_ips");
      CHECK_VARIABLE_INVALID (allow_simultaneous_ips, "Save Target");
    }
  if (params_given (params, "ssh_elevate_credential_id"))
    {
      target_ssh_elevate_credential =
        params_value (params, "ssh_elevate_credential_id");
      CHECK_VARIABLE_INVALID (target_ssh_elevate_credential, "Save Target");
    }
  if (params_given (params, "port"))
    {
      port = params_value (params, "port");
      CHECK_VARIABLE_INVALID (port, "Save Target");
    }

  if (target_source && str_equal (target_source, "manual"))
    {
      hosts = params_value (params, "hosts");
      CHECK_VARIABLE_INVALID (hosts, "Save Target")
    }
  else if (target_source && str_equal (target_source, "file"))
    {
      hosts_file = params_value (params, "file");
      CHECK_VARIABLE_INVALID (hosts_file, "Save Target")
    }

  if (target_exclude_source && str_equal (target_exclude_source, "manual"))
    {
      exclude_hosts = params_value (params, "exclude_hosts");
      CHECK_VARIABLE_INVALID (exclude_hosts, "Save Target")
    }
  else if (target_exclude_source && str_equal (target_exclude_source, "file"))
    {
      exclude_hosts_file = params_value (params, "exclude_file");
      CHECK_VARIABLE_INVALID (exclude_hosts_file, "Save Target")
    }

  command = g_string_new ("");
  xml_string_append (command,
                     "<modify_target target_id=\"%s\">"
                     "<name>%s</name>",
                     target_id, name);
  if (comment)
    xml_string_append (command, "<comment>%s</comment>", comment);

  if (hosts)
    xml_string_append (command, "<hosts>%s</hosts>", hosts);
  else if (hosts_file)
    xml_string_append (command, "<hosts>%s</hosts>", hosts_file);

  if (exclude_hosts)
    xml_string_append (command, "<exclude_hosts>%s</exclude_hosts>",
                       exclude_hosts);
  else if (exclude_hosts_file)
    xml_string_append (command, "<exclude_hosts>%s</exclude_hosts>",
                       exclude_hosts_file);

  if (reverse_lookup_only)
    xml_string_append (command, "<reverse_lookup_only>%s</reverse_lookup_only>",
                       reverse_lookup_only);

  if (reverse_lookup_unify)
    xml_string_append (command,
                       "<reverse_lookup_unify>%s</reverse_lookup_unify>",
                       reverse_lookup_unify);

  if (port_list_id)
    xml_string_append (command, "<port_list id=\"%s\"/>", port_list_id);

  if (allow_simultaneous_ips)
    xml_string_append (command,
                       "<allow_simultaneous_ips>%s</allow_simultaneous_ips>",
                       allow_simultaneous_ips);

  if (target_ssh_credential && !str_equal (target_ssh_credential, "--"))
    {
      xml_string_append (command,
                         "<ssh_credential id=\"%s\">"
                         "<port>%s</port>"
                         "</ssh_credential>",
                         target_ssh_credential, port ? port : "");
      if (target_ssh_elevate_credential)
        xml_string_append (command, "<ssh_elevate_credential id=\"%s\"/>",
                           target_ssh_elevate_credential);
    }

  if (target_smb_credential && !str_equal (target_smb_credential, "--"))
    xml_string_append (command, "<smb_credential id=\"%s\"/>",
                       target_smb_credential);

  if (target_esxi_credential && !str_equal (target_esxi_credential, "--"))
    xml_string_append (command, "<esxi_credential id=\"%s\"/>",
                       target_esxi_credential);

  if (target_krb5_credential && !str_equal (target_krb5_credential, "--"))
    xml_string_append (command, "<krb5_credential id=\"%s\"/>",
                       target_krb5_credential);

  if (target_snmp_credential && !str_equal (target_snmp_credential, "--"))
    xml_string_append (command, "<snmp_credential id=\"%s\"/>",
                       target_snmp_credential);

  if (alive_tests_table)
    {
      params_iterator_t iter;
      char *name;
      param_t *param;

      params_iterator_init (&iter, alive_tests_table);
      xml_string_append (command, "<alive_tests>");
      while (params_iterator_next (&iter, &name, &param))
        if (param->value)
          xml_string_append (command, "<alive_test>%s</alive_test>",
                             param->value);
      xml_string_append (command, "</alive_tests>");
    }
  else if (alive_tests)
    {
      xml_string_append (command, "<alive_test>%s</alive_test>", alive_tests);
    }

  xml_string_append (command, "</modify_target>");

  /* Modify the target. */
  int ret;
  entity_t entity;

  ret = gvm_connection_sendf (connection, "%s", command->str);
  g_string_free (command, TRUE);

  if (ret == -1)
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while modifying target. "
        "No target was modified. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  entity = NULL;
  if (read_entity_c (connection, &entity))
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while modifying a target. "
        "It is unclear whether the target has been modified or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  html = response_from_entity (connection, credentials, params, entity,
                               "Save Target", response_data);

  free_entity (entity);
  return html;
}

/**
 * @brief Export a target.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Target XML on success.  Enveloped XML
 *         on error.
 */
char *
export_target_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "target", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of targets.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Targets XML on success.  Enveloped XML
 *         on error.
 */
char *
export_targets_gmp (gvm_connection_t *connection,
                    gsad_credentials_t *credentials, params_t *params,
                    gsad_command_response_data_t *response_data)
{
  return export_many (connection, "target", credentials, params, response_data);
}

/**
 * @brief Get all scan configs, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_configs_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  const char *usage_type;
  gmp_arguments_t *arguments = NULL;

  usage_type = params_value (params, "usage_type");
  if (params_given (params, "usage_type"))
    CHECK_VARIABLE_INVALID (usage_type, "Get Configs")

  if (usage_type)
    {
      arguments = gmp_arguments_new ();
      gmp_arguments_add (arguments, "usage_type", usage_type);
    }

  return get_many (connection, "configs", credentials, params, arguments,
                   response_data);
}

/**
 * @brief Get a config, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_config_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments;

  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "families", "1");
  gmp_arguments_add (arguments, "tasks", "1");
  gmp_arguments_add (arguments, "preferences", "1");

  return get_one (connection, "config", credentials, params, NULL, arguments,
                  response_data);
}

/**
 * @brief Save details of an NVT for a config and return the next page.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Following page.
 */
char *
save_config_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  int gmp_ret;
  char *ret;
  params_t *preferences, *selects, *trends;
  const char *config_id, *name, *comment, *scanner_id;
  int success;

  config_id = params_value (params, "config_id");
  name = params_value (params, "name");
  comment = params_value (params, "comment");
  scanner_id = params_value (params, "scanner_id");

  CHECK_VARIABLE_INVALID (config_id, "Save Config");
  CHECK_VARIABLE_INVALID (name, "Save Config");
  CHECK_VARIABLE_INVALID (comment, "Save Config");

  /* Save name and comment. */

  if (scanner_id)
    gmp_ret = gvm_connection_sendf_xml (connection,
                                        "<modify_config config_id=\"%s\">"
                                        "<name>%s</name>"
                                        "<comment>%s</comment>"
                                        "<scanner>%s</scanner>"
                                        "</modify_config>",
                                        params_value (params, "config_id"),
                                        name, comment, scanner_id);
  else
    gmp_ret = gvm_connection_sendf_xml (connection,
                                        "<modify_config config_id=\"%s\">"
                                        "<name>%s</name>"
                                        "<comment>%s</comment>"
                                        "</modify_config>",
                                        params_value (params, "config_id"),
                                        name, comment);

  if (gmp_ret == -1)
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a config. "
        "It is unclear whether the entire config has been saved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  ret = check_modify_config (connection, credentials, params, "get_config",
                             "edit_config", &success, response_data);
  if (success == 0)
    {
      return ret;
    }

  /* Save preferences. */

  preferences = params_values (params, "preference:");
  if (preferences)
    {
      params_iterator_t iter;
      char *param_name;
      param_t *param;

      params_iterator_init (&iter, preferences);
      while (params_iterator_next (&iter, &param_name, &param))
        {
          gchar *value;

          value = param->value_size ? g_base64_encode ((guchar *) param->value,
                                                       param->value_size)
                                    : g_strdup ("");

          if (gvm_connection_sendf (connection,
                                    "<modify_config config_id=\"%s\">"
                                    "<preference>"
                                    "<name>%s</name>"
                                    "<value>%s</value>"
                                    "</preference>"
                                    "</modify_config>",
                                    params_value (params, "config_id"),
                                    param_name, value)
              == -1)
            {
              g_free (value);
              gsad_command_response_data_set_status_code (
                response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
              return gsad_http_create_gsad_message (
                credentials,
                "An internal error occurred while saving a config. "
                "It is unclear whether the entire config has been saved. "
                "Diagnostics: Failure to send command to manager daemon.",
                response_data);
            }
          g_free (value);
          g_free (ret);

          ret =
            check_modify_config (connection, credentials, params, "get_config",
                                 "edit_config", &success, response_data);
          if (success == 0)
            {
              return ret;
            }
        }
    }

  /* Update the config. */

  trends = params_values (params, "trend:");
  selects = params_values (params, "select:");

  if (trends || selects || params_value (params, "trend"))
    {
      if (gvm_connection_sendf (
            connection,
            "<modify_config config_id=\"%s\">"
            "<family_selection>"
            "<growing>%i</growing>",
            params_value (params, "config_id"),
            trends && params_value (params, "trend")
              && strcmp (params_value (params, "trend"), "0"))
          == -1)
        {
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while saving a config. "
            "It is unclear whether the entire config has been saved. "
            "Diagnostics: Failure to send command to manager daemon.",
            response_data);
        }

      if (selects)
        {
          gchar *family;
          params_iterator_t iter;
          param_t *param;

          params_iterator_init (&iter, selects);
          while (params_iterator_next (&iter, &family, &param))
            if (gvm_connection_sendf (connection,
                                      "<family>"
                                      "<name>%s</name>"
                                      "<all>1</all>"
                                      "<growing>%i</growing>"
                                      "</family>",
                                      family,
                                      trends && member1 (trends, family))
                == -1)
              {
                gsad_command_response_data_set_status_code (
                  response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
                return gsad_http_create_gsad_message (
                  credentials,
                  "An internal error occurred while saving a config. "
                  "It is unclear whether the entire config has been saved. "
                  "Diagnostics: Failure to send command to manager daemon.",
                  response_data);
              }
        }

      if (trends)
        {
          gchar *family;
          params_iterator_t iter;
          param_t *param;

          params_iterator_init (&iter, trends);
          while (params_iterator_next (&iter, &family, &param))
            {
              if (param->value_size == 0)
                continue;
              if (param->value[0] == '0')
                continue;
              if (selects && member (selects, family))
                continue;
              if (gvm_connection_sendf (connection,
                                        "<family>"
                                        "<name>%s</name>"
                                        "<all>0</all>"
                                        "<growing>1</growing>"
                                        "</family>",
                                        family)
                  == -1)
                {
                  gsad_command_response_data_set_status_code (
                    response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
                  return gsad_http_create_gsad_message (
                    credentials,
                    "An internal error occurred while saving a config. "
                    "It is unclear whether the entire config has been saved. "
                    "Diagnostics: Failure to send command to manager daemon.",
                    response_data);
                }
            }
        }

      if (gvm_connection_sendf (connection, "</family_selection>"
                                            "</modify_config>")
          == -1)
        {
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while saving a config. "
            "It is unclear whether the entire config has been saved. "
            "Diagnostics: Failure to send command to manager daemon.",
            response_data);
        }

      g_free (ret);
      ret = check_modify_config (connection, credentials, params, "get_config",
                                 "edit_config", NULL, response_data);
    }
  return ret;
}

/**
 * @brief Get details of a family for a config, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_config_family (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  GString *xml;
  const char *config_id, *family, *sort_field, *sort_order;
  entity_t entity;

  config_id = params_value (params, "config_id");
  family = params_value (params, "family");

  CHECK_VARIABLE_INVALID (config_id, "Get Scan Config Family")
  CHECK_VARIABLE_INVALID (family, "Get Scan Config Family")

  xml = g_string_new ("<get_config_family_response>");

  /* Get the details for all NVT's in the config in the family. */

  sort_field = params_value (params, "sort_field");
  sort_order = params_value (params, "sort_order");

  if (gvm_connection_sendf (
        connection,
        "<get_nvts"
        " config_id=\"%s\" details=\"1\""
        " family=\"%s\" timeout=\"1\" preference_count=\"1\""
        " skip_cert_refs=\"1\" skip_tags=\"1\" lean=\"1\""
        " sort_field=\"%s\" sort_order=\"%s\"/>",
        config_id, family, sort_field ? sort_field : "name",
        sort_order ? sort_order : "ascending")
      == -1)
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting list of configs. "
        "The current list of configs is not available. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  if (read_entity_and_string_c (connection, &entity, &xml))
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting list of configs. "
        "The current list of configs is not available. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }
  g_string_append (xml, "</get_config_family_response>");

  if (gmp_success (entity) != 1)
    {
      set_http_status_from_entity (entity, response_data);
    }
  free_entity (entity);

  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Get details of a family for a config, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_config_family_gmp (gvm_connection_t *connection,
                       gsad_credentials_t *credentials, params_t *params,
                       gsad_command_response_data_t *response_data)
{
  return get_config_family (connection, credentials, params, response_data);
}

/**
 * @brief Get details of a family for editing a config, envelope result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
edit_config_family_gmp (gvm_connection_t *connection,
                        gsad_credentials_t *credentials, params_t *params,
                        gsad_command_response_data_t *response_data)
{
  return get_config_family (connection, credentials, params, response_data);
}

/**
 * @brief Get all details of a family for editing a config, envelope result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
edit_config_family_all_gmp (gvm_connection_t *connection,
                            gsad_credentials_t *credentials, params_t *params,
                            gsad_command_response_data_t *response_data)
{
  GString *xml;
  const char *config_id, *family, *sort_field, *sort_order;
  entity_t entity;

  config_id = params_value (params, "config_id");
  family = params_value (params, "family");

  CHECK_VARIABLE_INVALID (config_id, "Get Scan Config Family")
  CHECK_VARIABLE_INVALID (family, "Get Scan Config Family")

  xml = g_string_new ("<get_config_family_response>");

  /* Get the details for all NVT's in the family. */

  sort_field = params_value (params, "sort_field");
  sort_order = params_value (params, "sort_order");

  if (gvm_connection_sendf (connection,
                            "<get_nvts"
                            " details=\"1\""
                            " timeout=\"1\""
                            " family=\"%s\""
                            " preferences_config_id=\"%s\""
                            " preference_count=\"1\""
                            " skip_cert_refs=\"1\""
                            " skip_tags=\"1\""
                            " lean=\"1\""
                            " sort_field=\"%s\""
                            " sort_order=\"%s\"/>",
                            family, config_id, sort_field ? sort_field : "name",
                            sort_order ? sort_order : "ascending")
      == -1)
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting list of configs. "
        "The current list of configs is not available. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  if (read_entity_and_string_c (connection, &entity, &xml))
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting list of configs. "
        "The current list of configs is not available. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }
  g_string_append (xml, "</get_config_family_response>");

  if (gmp_success (entity) != 1)
    {
      set_http_status_from_entity (entity, response_data);
    }

  free_entity (entity);

  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Get details of an NVT for a config, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
save_config_family_gmp (gvm_connection_t *connection,
                        gsad_credentials_t *credentials, params_t *params,
                        gsad_command_response_data_t *response_data)
{
  char *ret;
  const char *config_id, *family;
  params_t *nvts;

  config_id = params_value (params, "config_id");
  family = params_value (params, "family");

  CHECK_VARIABLE_INVALID (config_id, "Save Config Family")
  CHECK_VARIABLE_INVALID (family, "Save Config Family")

  /* Set the NVT selection. */

  if (gvm_connection_sendf (connection,
                            "<modify_config config_id=\"%s\">"
                            "<nvt_selection>"
                            "<family>%s</family>",
                            config_id, family)
      == -1)
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a config. "
        "It is unclear whether the entire config has been saved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  nvts = params_values (params, "nvt:");
  if (nvts)
    {
      params_iterator_t iter;
      char *name;
      param_t *param;

      params_iterator_init (&iter, nvts);
      while (params_iterator_next (&iter, &name, &param))
        if (gvm_connection_sendf (connection, "<nvt oid=\"%s\"/>", name) == -1)
          {
            gsad_command_response_data_set_status_code (
              response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
            return gsad_http_create_gsad_message (
              credentials,
              "An internal error occurred while saving a config. "
              "It is unclear whether the entire config has been saved. "
              "Diagnostics: Failure to send command to manager daemon.",
              response_data);
          }
    }

  if (gvm_connection_sendf (connection, "</nvt_selection>"
                                        "</modify_config>")
      == -1)
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a config. "
        "It is unclear whether the entire config has been saved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  ret =
    check_modify_config (connection, credentials, params, "get_config_family",
                         "edit_config_family", NULL, response_data);

  return ret;
}

/**
 * @brief Delete config, get all configs, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_config_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return move_resource_to_trash (connection, "config", credentials, params,
                                 response_data);
}

/**
 * @brief Export an override.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Override XML on success.  Enveloped XML on error.
 */
char *
export_override_gmp (gvm_connection_t *connection,
                     gsad_credentials_t *credentials, params_t *params,
                     gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "override", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of overrides.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Overrides XML on success.  Enveloped XML
 *         on error.
 */
char *
export_overrides_gmp (gvm_connection_t *connection,
                      gsad_credentials_t *credentials, params_t *params,
                      gsad_command_response_data_t *response_data)
{
  return export_many (connection, "override", credentials, params,
                      response_data);
}

/**
 * @brief Export a file preference.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Config XML on success.  Enveloped XML on error.
 */
char *
export_preference_file_gmp (gvm_connection_t *connection,
                            gsad_credentials_t *credentials, params_t *params,
                            gsad_command_response_data_t *response_data)
{
  GString *xml;
  entity_t entity, preference_entity, value_entity;
  const char *config_id, *oid, *preference_name;

  config_id = params_value (params, "config_id");
  oid = params_value (params, "oid");
  preference_name = params_value (params, "preference_name");

  xml = g_string_new ("<get_preferences_response>");

  CHECK_VARIABLE_INVALID (config_id, "Export Preference File")
  CHECK_VARIABLE_INVALID (oid, "Export Preference File")
  CHECK_VARIABLE_INVALID (preference_name, "Export Preference File")

  if (gvm_connection_sendf (connection,
                            "<get_preferences"
                            " config_id=\"%s\""
                            " nvt_oid=\"%s\""
                            " preference=\"%s\"/>",
                            config_id, oid, preference_name)
      == -1)
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a preference file. "
        "The file could not be delivered. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  entity = NULL;
  if (read_entity_c (connection, &entity))
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a preference file. "
        "The file could not be delivered. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  preference_entity = entity_child (entity, "preference");
  if (preference_entity != NULL
      && (value_entity = entity_child (preference_entity, "value")))
    {
      char *content = strdup (entity_text (value_entity));
      gsad_command_response_data_set_content_type (
        response_data, GSAD_CONTENT_TYPE_OCTET_STREAM);
      gsad_command_response_data_set_content_disposition (
        response_data,
        g_strdup_printf ("attachment; filename=\"pref_file.bin\""));
      gsad_command_response_data_set_content_length (response_data,
                                                     strlen (content));
      free_entity (entity);
      g_string_free (xml, TRUE);
      return content;
    }
  else
    {
      free_entity (entity);
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a preference file. "
        "The file could not be delivered. "
        "Diagnostics: Failure to receive file from manager daemon.",
        response_data);
    }

  g_string_append (xml, "</get_preferences_response>");
  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Delete report, get task status, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_report_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return delete_resource (connection, "report", credentials, params, TRUE,
                          response_data);
}

static gmp_arguments_t *
scope_get_arguments (params_t *params, const char *scope_id)
{
  gmp_arguments_t *arguments;
  const gchar *details, *filter;

  arguments = gmp_arguments_new ();
  details = params_value (params, "details");
  filter = params_value (params, "filter");
  if (details && !str_equal (details, ""))
    gmp_arguments_add (arguments, "details", details);
  if (filter && !str_equal (filter, ""))
    gmp_arguments_add (arguments, "filter", filter);
  if (scope_id && !str_equal (scope_id, ""))
    gmp_arguments_add (arguments, "scope_id", scope_id);
  return arguments;
}

char *
get_scope_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  const char *scope_id;

  scope_id = params_value (params, "scope_id");
  CHECK_VARIABLE_INVALID (scope_id, "Get Scope");

  return get_entities (connection, "scope", credentials, params,
                       scope_get_arguments (params, scope_id),
                       response_data);
}

char *
get_scopes_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  return get_entities (connection, "scopes", credentials, params,
                       scope_get_arguments (params,
                                            params_value (params, "scope_id")),
                       response_data);
}

/**
 * @brief Get a report and return the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[in]  extra_xml    Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Report.
 */
char *
get_report (gvm_connection_t *connection, gsad_credentials_t *credentials,
            params_t *params, const char *extra_xml,
            gsad_command_response_data_t *response_data)
{
  GString *xml;
  entity_t entity;
  entity_t report_entity;
  const char *report_id;
  const char *format_id;
  const char *filter;
  const char *filter_id;
  gboolean lean, ignore_pagination, details;
  int ret;
  gchar *fname_format;
  const gchar *extension, *requested_content_type;

  details = params_value_bool (params, "details");
  ignore_pagination = params_value_bool (params, "ignore_pagination");
  lean = params_value_bool (params, "lean");

  report_id = params_value (params, "report_id");

  CHECK_VARIABLE_INVALID (report_id, "Get Report");

  format_id = params_value (params, "report_format_id");

  filter = params_value (params, "filter");
  filter_id = params_value (params, "filter_id");

  details = params_value_bool (params, "details");

  if (filter == NULL || filter_id)
    filter = "";

  ret = gvm_connection_sendf_xml (
    connection,
    "<get_reports"
    " details=\"%d\""
    " ignore_pagination=\"%d\""
    " lean=\"%d\""
    " filter=\"%s\""
    " filt_id=\"%s\""
    " report_id=\"%s\""
    " format_id=\"%s\"/>",
    details, ignore_pagination, lean, filter,
    filter_id ? filter_id : FILT_ID_NONE, report_id,
    format_id ? format_id : "");

  if (ret == -1)
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting a report. "
        "The report could not be delivered. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  if (format_id)
    {
      if ((str_equal (format_id, XML_REPORT_FORMAT_ID))
          || str_equal (format_id, ANONXML_REPORT_FORMAT_ID))
        {
          /* Manager sends XML report as plain XML. */

          if (read_entity_c (connection, &entity))
            {
              gsad_command_response_data_set_status_code (
                response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
              return gsad_http_create_gsad_message (
                credentials,
                "An internal error occurred while getting a report. "
                "The report could not be delivered. "
                "Diagnostics: Failure to receive response from manager daemon.",
                response_data);
            }
          entity_t report = entity_child (entity, "report");
          if (report == NULL)
            {
              free_entity (entity);
              gsad_command_response_data_set_status_code (
                response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
              return gsad_http_create_gsad_message (
                credentials,
                "An internal error occurred while getting a report. "
                "The report could not be delivered. "
                "Diagnostics: Response from manager daemon did not contain a "
                "report.",
                response_data);
            }
          extension = entity_attribute (report, "extension");
          requested_content_type = entity_attribute (report, "content_type");
          if (extension && requested_content_type)
            {
              gchar *file_name;
              ret = setting_get_value (connection,
                                       "e1a2ae0b-736e-4484-b029-330c9e15b900",
                                       &fname_format, response_data);
              if (ret)
                {
                  switch (ret)
                    {
                    case 1:
                      gsad_command_response_data_set_status_code (
                        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
                      return gsad_http_create_gsad_message (
                        credentials,
                        "An internal error occurred while getting a setting. "
                        "The setting could not be delivered. "
                        "Diagnostics: Failure to send command to manager "
                        "daemon.",
                        response_data);
                    case 2:
                      gsad_command_response_data_set_status_code (
                        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
                      return gsad_http_create_gsad_message (
                        credentials,
                        "An internal error occurred while getting a setting. "
                        "The setting could not be delivered. "
                        "Diagnostics: Failure to receive response from manager "
                        "daemon.",
                        response_data);
                    default:
                      gsad_command_response_data_set_status_code (
                        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
                      return gsad_http_create_gsad_message (
                        credentials,
                        "An internal error occurred while getting a setting. "
                        "The setting could not be delivered. "
                        "Diagnostics: Internal error.",
                        response_data);
                    }
                }

              if (fname_format == NULL)
                {
                  g_warning ("%s : File name format setting not found.",
                             __func__);
                  fname_format = "%T-%U";
                }

              file_name = format_file_name (fname_format, credentials, "report",
                                            report_id, report);
              if (file_name == NULL)
                file_name = g_strdup_printf ("%s-%s", "report", report_id);

              gsad_command_response_data_set_content_type_string (
                response_data, g_strdup (requested_content_type));
              gsad_command_response_data_set_content_disposition (
                response_data,
                g_strdup_printf ("attachment; filename=\"%s.%s\"", file_name,
                                 extension));

              g_free (file_name);
            }
          xml = g_string_new ("");
          print_entity_to_string (report, xml);
          free_entity (entity);
          return g_string_free (xml, FALSE);
        }
      else
        {
          /* "nbe", "pdf", "dvi", "html", "html-pdf"... */

          entity = NULL;
          if (read_entity_c (connection, &entity))
            {
              gsad_command_response_data_set_status_code (
                response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
              return gsad_http_create_gsad_message (
                credentials,
                "An internal error occurred while getting a report. "
                "The report could not be delivered. "
                "Diagnostics: Failure to receive response from manager daemon.",
                response_data);
            }

          report_entity = entity_child (entity, "report");
          if (report_entity != NULL)
            {
              char *report_encoded;
              gsize report_len;
              gchar *report_decoded;
              extension = entity_attribute (report_entity, "extension");
              requested_content_type =
                entity_attribute (report_entity, "content_type");
              report_encoded = entity_text (report_entity);
              report_decoded =
                (gchar *) g_base64_decode (report_encoded, &report_len);
              /* g_base64_decode can return NULL (Glib 2.12.4-2), at least
               * when *report_len is zero. */
              if (report_decoded == NULL)
                {
                  report_decoded = g_strdup ("");
                  report_len = 0;
                }
              if (extension && requested_content_type)
                {
                  gchar *file_name;
                  const char *id;
                  if (report_id)
                    id = report_id;
                  else
                    id = "ERROR";

                  ret = setting_get_value (
                    connection, "e1a2ae0b-736e-4484-b029-330c9e15b900",
                    &fname_format, response_data);
                  if (ret)
                    {
                      switch (ret)
                        {
                        case 1:
                          gsad_command_response_data_set_status_code (
                            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
                          return gsad_http_create_gsad_message (
                            credentials,
                            "An internal error occurred while getting a "
                            "setting. "
                            "The setting could not be delivered. "
                            "Diagnostics: Failure to send command to manager "
                            "daemon.",
                            response_data);
                        case 2:
                          gsad_command_response_data_set_status_code (
                            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
                          return gsad_http_create_gsad_message (
                            credentials,
                            "An internal error occurred while getting a "
                            "setting. "
                            "The setting could not be delivered. "
                            "Diagnostics: Failure to receive response from "
                            "manager daemon.",
                            response_data);
                        default:
                          gsad_command_response_data_set_status_code (
                            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
                          return gsad_http_create_gsad_message (
                            credentials,
                            "An internal error occurred while getting a "
                            "setting. "
                            "The setting could not be delivered. "
                            "Diagnostics: Internal error.",
                            response_data);
                        }
                    }

                  if (fname_format == NULL)
                    {
                      g_warning ("%s : File name format setting not found.",
                                 __func__);
                      fname_format = "%T-%U";
                    }

                  file_name = format_file_name (fname_format, credentials,
                                                "report", id, report_entity);
                  if (file_name == NULL)
                    file_name = g_strdup_printf ("%s-%s", "report", id);

                  gsad_command_response_data_set_content_type_string (
                    response_data, g_strdup (requested_content_type));
                  gsad_command_response_data_set_content_disposition (
                    response_data,
                    g_strdup_printf ("attachment; filename=\"%s.%s\"",
                                     file_name, extension));

                  g_free (file_name);
                }

              free_entity (entity);

              gsad_command_response_data_set_content_length (response_data,
                                                             report_len);
              return report_decoded;
            }
          else
            {
              free_entity (entity);
              gsad_command_response_data_set_status_code (
                response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
              return gsad_http_create_gsad_message (
                credentials,
                "An internal error occurred while getting a report. "
                "The report could not be delivered. "
                "Diagnostics: Failure to receive report from manager daemon.",
                response_data);
            }
        }
    }
  else
    {
      /* Format is NULL, send enveloped XML. */

      xml = g_string_new ("<get_report>");

      if (extra_xml)
        g_string_append (xml, extra_xml);

      if (read_string_c (connection, &xml))
        {
          gsad_command_response_data_set_status_code (
            response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
          return gsad_http_create_gsad_message (
            credentials,
            "An internal error occurred while getting a report. "
            "The report could not be delivered. "
            "Diagnostics: Failure to receive response from manager daemon.",
            response_data);
        }

      g_string_append (xml, "</get_report>");

      return envelope_gmp (connection, credentials, params,
                           g_string_free (xml, FALSE), response_data);
    }
}

/**
 * @brief Get a report and envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Report.
 */
char *
get_report_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  return get_report (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Get all reports, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_reports_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  const gchar *filter, *filter_id, *details, *usage_type;
  gmp_arguments_t *arguments;

  filter = params_value (params, "filter");
  filter_id = params_value (params, "filter_id");
  details = params_value (params, "details");
  usage_type = params_value (params, "usage_type");

  arguments = gmp_arguments_new ();

  if (!filter && !filter_id)
    {
      filter_id = FILT_ID_USER_SETTING;
    }

  if (filter)
    {
      gmp_arguments_add (arguments, "report_filter", filter);
    }

  if (!filter_id && !filter)
    {
      filter_id = FILT_ID_USER_SETTING;
    }

  if (filter_id)
    {
      gmp_arguments_add (arguments, "report_filt_id", filter_id);
    }

  if (details && !str_equal (details, ""))
    {
      gmp_arguments_add (arguments, "details", details);
    }
  if (usage_type)
    {
      gmp_arguments_add (arguments, "usage_type", usage_type);
    }

  params_remove (params, "filter");
  params_remove (params, "filter_id");

  return get_entities (connection, "reports", credentials, params, arguments,
                       response_data);
}

/**
 * @brief Get an SSL Certificate.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return SSL Certificate.
 */
char *
download_ssl_cert (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  const char *ssl_cert;
  gchar *cert;
  char *unescaped;

  ssl_cert = params_value (params, "ssl_cert");
  if (ssl_cert == NULL)
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      return gsad_http_create_gsad_message (credentials,
                                            "An internal error occurred."
                                            " Diagnostics: ssl_cert was NULL.",
                                            response_data);
    }
  /* The Base64 comes URI escaped as it may contain special characters. */
  unescaped = g_uri_unescape_string (ssl_cert, NULL);

  cert = g_strdup_printf ("-----BEGIN CERTIFICATE-----\n"
                          "%s\n-----END CERTIFICATE-----\n",
                          unescaped);

  gsad_command_response_data_set_content_length (response_data, strlen (cert));

  g_free (unescaped);
  return cert;
}

/**
 * @brief Get a Scanner's CA Certificate.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return CA Certificate.
 */
char *
download_ca_pub (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  const char *ca_pub;
  char *unescaped;

  ca_pub = params_value (params, "ca_pub");
  if (ca_pub == NULL)
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      return gsad_http_create_gsad_message (credentials,
                                            "An internal error occurred."
                                            " Diagnostics: ca_pub was NULL.",
                                            response_data);
    }
  /* The Base64 comes URI escaped as it may contain special characters. */
  unescaped = g_uri_unescape_string (ca_pub, NULL);
  gsad_command_response_data_set_content_length (response_data,
                                                 strlen (unescaped));
  return unescaped;
}

/**
 * @brief Get a Scanner's Certificate.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Certificate.
 */
char *
download_key_pub (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  const char *key_pub;
  char *unescaped;

  key_pub = params_value (params, "key_pub");
  if (key_pub == NULL)
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      return gsad_http_create_gsad_message (credentials,
                                            "An internal error occurred."
                                            " Diagnostics: key_pub was NULL.",
                                            response_data);
    }

  /* The Base64 comes URI escaped as it may contain special characters. */
  unescaped = g_uri_unescape_string (key_pub, NULL);
  gsad_command_response_data_set_content_length (response_data,
                                                 strlen (unescaped));
  return unescaped;
}

/**
 * @brief Export a result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Result XML on success.  Enveloped XML
 *         on error.
 */
char *
export_result_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "result", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of results.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Results XML on success.  Enveloped XML
 *         on error.
 */
char *
export_results_gmp (gvm_connection_t *connection,
                    gsad_credentials_t *credentials, params_t *params,
                    gsad_command_response_data_t *response_data)
{
  return export_many (connection, "result", credentials, params, response_data);
}

/**
 * @brief Get a port from request params
 *
 * @param[in]  params  Request parameters.
 *
 * @return The port
 */
const char *
get_port_from_params (params_t *params)
{
  const char *port;

  port = params_value (params, "port");

  if (port == NULL)
    return "";

  if (strcmp (port, "--") == 0)
    port = params_value (params, "port_manual");

  if (port == NULL)
    port = "";

  return port;
}

/**
 * @brief Get hosts from request params
 *
 * @param[in]  params  Request parameters.
 *
 * @return The hosts
 */
const char *
get_hosts_from_params (params_t *params)
{
  const char *hosts;

  if (params_valid (params, "hosts"))
    {
      hosts = params_value (params, "hosts");
      if (str_equal (hosts, "--"))
        {
          if (params_valid (params, "hosts_manual"))
            hosts = params_value (params, "hosts_manual");
          else
            hosts = NULL;
        }
    }
  else
    hosts = NULL;

  return hosts;
}

/**
 * @brief Get task_id from request params
 *
 * @param[in]  params  Request parameters.
 *
 * @return The task_id
 */
const char *
get_task_id_from_params (params_t *params)
{
  const char *task_id;

  task_id = params_value (params, "task_id");

  if (task_id && (strcmp (task_id, "0") == 0))
    task_id = params_value (params, "task_uuid");

  return task_id;
}

/**
 * @brief Get severity from request params
 *
 * @param[in]  params  Request parameters.
 *
 * @return The severity
 */
const char *
get_severity_from_params (params_t *params)
{
  const char *severity;

  if (params_valid (params, "severity"))
    severity = params_value (params, "severity");
  else if (params_given (params, "severity")
           && strcmp (params_original_value (params, "severity"), ""))
    severity = NULL;
  else
    severity = "";

  return severity;
}

/**
 * @brief Get result_id from request params
 *
 * @param[in]  params  Request parameters.
 *
 * @return The result_id
 */
const char *
get_result_id_from_params (params_t *params)
{
  const char *result_id;

  result_id = params_value (params, "result_id");

  if (result_id && (strcmp (result_id, "0") == 0))
    {
      result_id = params_value (params, "result_uuid");
    }

  return result_id;
}

/**
 * @brief Get all overrides, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_overrides_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return get_many (connection, "overrides", credentials, params, NULL,
                   response_data);
}

/**
 * @brief Get a override, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[in]  extra_xml    Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_override (gvm_connection_t *connection, gsad_credentials_t *credentials,
              params_t *params, const char *extra_xml,
              gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments;
  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "result", "1");

  return get_one (connection, "override", credentials, params, extra_xml,
                  arguments, response_data);
}

/**
 * @brief Get an override, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_override_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  return get_override (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Create an override, get report, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
/* Scanners. */

/**
 * @brief Get all scanners, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_scanners_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  return get_many (connection, "scanners", credentials, params, NULL,
                   response_data);
}

/**
 * @brief Get one scanner, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[in]  extra_xml    Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_scanner (gvm_connection_t *connection, gsad_credentials_t *credentials,
             params_t *params, const char *extra_xml,
             gsad_command_response_data_t *response_data)
{
  return get_one (connection, "scanner", credentials, params, extra_xml, NULL,
                  response_data);
}

/**
 * @brief Get one scanner, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_scanner_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  return get_scanner (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Export a scanner.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Scanner XML on success.  Enveloped XML on error.
 */
char *
export_scanner_gmp (gvm_connection_t *connection,
                    gsad_credentials_t *credentials, params_t *params,
                    gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "scanner", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of scanners.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Scanners XML on success. Enveloped XML on error.
 */
char *
export_scanners_gmp (gvm_connection_t *connection,
                     gsad_credentials_t *credentials, params_t *params,
                     gsad_command_response_data_t *response_data)
{
  return export_many (connection, "scanner", credentials, params,
                      response_data);
}

/**
 * @brief Verify scanner, get scanners, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
verify_scanner_gmp (gvm_connection_t *connection,
                    gsad_credentials_t *credentials, params_t *params,
                    gsad_command_response_data_t *response_data)
{
  gchar *html;
  const char *scanner_id;
  int ret;
  entity_t entity;

  scanner_id = params_value (params, "scanner_id");
  CHECK_VARIABLE_INVALID (scanner_id, "Verify Scanner");

  ret = gmpf (connection, credentials, NULL, &entity, response_data,
              "<verify_scanner scanner_id=\"%s\"/>", scanner_id);

  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while verifying a scanner. "
        "The scanner was not verified. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while verifying a scanner. "
        "It is unclear whether the scanner was verified or not. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while verifying a scanner. "
        "It is unclear whether the scanner was verified or not. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  html = response_from_entity (connection, credentials, params, entity,
                               "Verify Scanner", response_data);
  free_entity (entity);
  return html;
}

/* Schedules. */

/**
 * @brief Get one schedule, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[in]  extra_xml    Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_schedule (gvm_connection_t *connection, gsad_credentials_t *credentials,
              params_t *params, const char *extra_xml,
              gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments;
  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "tasks", "1");

  return get_one (connection, "schedule", credentials, params, extra_xml,
                  arguments, response_data);
}

/**
 * @brief Get one schedule, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_schedule_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  return get_schedule (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Get all schedules, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_schedules_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return get_many (connection, "schedules", credentials, params, NULL,
                   response_data);
}

/**
 * @brief Delete a schedule, get all schedules, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_schedule_gmp (gvm_connection_t *connection,
                     gsad_credentials_t *credentials, params_t *params,
                     gsad_command_response_data_t *response_data)
{
  return move_resource_to_trash (connection, "schedule", credentials, params,
                                 response_data);
}

/**
 * @brief Get resource names, envelope the result.
 *
 * @param[in]  connection   Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_resource_names_gmp (gvm_connection_t *connection,
                        gsad_credentials_t *credentials, params_t *params,
                        gsad_command_response_data_t *response_data)
{
  const gchar *type;
  gmp_arguments_t *arguments;

  type = params_value (params, "resource_type");

  CHECK_VARIABLE_INVALID (type, "Get Resource Names");

  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "type", type);

  return get_many (connection, "resource_names", credentials, params, arguments,
                   response_data);
}


/* Port lists. */

/**
 * @brief Get one port_list, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  extra_xml      Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
get_port_list (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, const char *extra_xml,
               gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments;
  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "targets", "1");
  gmp_arguments_add (arguments, "details", "1");

  return get_one (connection, "port_list", credentials, params, extra_xml,
                  arguments, response_data);
}

/**
 * @brief Get one port_list, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_port_list_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return get_port_list (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Get all port_lists, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_port_lists_gmp (gvm_connection_t *connection,
                    gsad_credentials_t *credentials, params_t *params,
                    gsad_command_response_data_t *response_data)
{
  return get_many (connection, "port_lists", credentials, params, NULL,
                   response_data);
}

/**
 * @brief Modify a port list, get all port list, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
/* Feeds. */

/**
 * @brief Synchronize with a feed and envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication
 * @param[in]  params         Request parameters.
 * @param[in]  sync_cmd       Name of the GMP command used to sync the feed.
 * @param[in]  action         Action shown in gsad status messages.
 * @param[in]  feed_name      Name of the feed shown in error messages.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
static char *
sync_feed (gvm_connection_t *connection, gsad_credentials_t *credentials,
           params_t *params, const char *sync_cmd, const char *action,
           const char *feed_name, gsad_command_response_data_t *response_data)
{
  entity_t entity;
  gchar *html, *msg;

  if (gvm_connection_sendf (connection, "<%s/>", sync_cmd) == -1)
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);

      msg = g_strdup_printf (
        "An internal error occurred while synchronizing with %s. "
        "Feed synchronization is currently not available. "
        "Diagnostics: Failure to send command to manager daemon.",
        feed_name);
      html = gsad_http_create_gsad_message (credentials, msg, response_data);
      g_free (msg);
      return html;
    }

  if (read_entity_c (connection, &entity))
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);

      msg = g_strdup_printf (
        "An internal error occurred while synchronizing with %s. "
        "Feed synchronization is currently not available. "
        "Diagnostics: Failure to receive response from manager daemon.",
        feed_name);
      html = gsad_http_create_gsad_message (credentials, msg, response_data);
      g_free (msg);
      return html;
    }

  html = response_from_entity (connection, credentials, params, entity, action,
                               response_data);

  return html;
}

/**
 * @brief Synchronize with an NVT feed and envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
sync_feed_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  return sync_feed (connection, credentials, params, "sync_feed",
                    "Synchronize Feed", "the NVT feed", response_data);
}

/**
 * @brief Synchronize with a SCAP feed and envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
sync_scap_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  return sync_feed (connection, credentials, params, "sync_scap",
                    "Synchronize Feed", "the SCAP feed", response_data);
}

/**
 * @brief Synchronize with a CERT feed and envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
sync_cert_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  return sync_feed (connection, credentials, params, "sync_cert",
                    "Synchronize CERT Feed", "the CERT feed", response_data);
}

/* Schedules. */

/**
 * @brief Export a schedule.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Schedule XML on success.  Enveloped XML on error.
 */
char *
export_schedule_gmp (gvm_connection_t *connection,
                     gsad_credentials_t *credentials, params_t *params,
                     gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "schedule", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of schedules.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Schedules XML on success. Enveloped XML on error.
 */
char *
export_schedules_gmp (gvm_connection_t *connection,
                      gsad_credentials_t *credentials, params_t *params,
                      gsad_command_response_data_t *response_data)
{
  return export_many (connection, "schedule", credentials, params,
                      response_data);
}

/* Users. */

/**
 * @brief Delete a user, get all users, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_user_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  return move_resource_to_trash (connection, "user", credentials, params,
                                 response_data);
}

/**
 * @brief Get one user, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[in]  extra_xml      Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_user (gvm_connection_t *connection, gsad_credentials_t *credentials,
          params_t *params, const char *extra_xml,
          gsad_command_response_data_t *response_data)
{
  return get_one (connection, "user", credentials, params, extra_xml, NULL,
                  response_data);
}

/**
 * @brief Get one user, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_user_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
              params_t *params, gsad_command_response_data_t *response_data)
{
  return get_user (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Get all users, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_users_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  return get_many (connection, "users", credentials, params, NULL,
                   response_data);
}

/**
 * @brief Create a user, get all users, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
create_user_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  const char *name, *password, *auth_method, *comment;
  int ret;
  GString *string;
  gchar *buf, *html;
  entity_t entity;

  name = params_value (params, "login");
  password = params_value (params, "password");
  auth_method = params_value (params, "auth_method");
  comment = params_value (params, "comment");

  CHECK_VARIABLE_INVALID (name, "Create User");

  if (auth_method && strcmp (auth_method, "1") == 0)
    {
      CHECK_VARIABLE_INVALID (password, "Create User");
    }

  if (params_given (params, "comment"))
    {
      CHECK_VARIABLE_INVALID (comment, "Create User");
    }

  string = g_string_new ("<create_user>");
  buf = g_markup_printf_escaped ("<name>%s</name>"
                                 "<password>%s</password>",
                                 name, password ? password : "");
  g_string_append (string, buf);
  g_free (buf);

  if (auth_method && !strcmp (auth_method, "1"))
    g_string_append (string,
                     "<sources><source>ldap_connect</source></sources>");
  else if (auth_method && !strcmp (auth_method, "2"))
    g_string_append (string,
                     "<sources><source>radius_connect</source></sources>");

  if (comment)
    xml_string_append (string, "<comment>%s</comment>", comment);

  g_string_append (string, "</create_user>");
  buf = g_string_free (string, FALSE);

  entity = NULL;
  ret = gmp (connection, credentials, NULL, &entity, response_data, buf);
  g_free (buf);
  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new user. "
        "No new user was created. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new user. "
        "It is unclear whether the user has been created or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new user. "
        "It is unclear whether the user has been created or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  if (entity_attribute (entity, "id"))
    params_add (params, "user_id", entity_attribute (entity, "id"));
  html = response_from_entity (connection, credentials, params, entity,
                               "Create User", response_data);
  free_entity (entity);
  return html;
}

/**
 * @brief Modify a user, get all users, envelope the result.
 *
 * @param[in]  connection       Connection to manager.
 * @param[in]  credentials      Username and password for authentication.
 * @param[in]  params           Request parameters.
 * @param[out] response_data    Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
save_user_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  int ret;
  gchar *html, *buf;
  const char *user_id, *login, *old_login, *modify_password, *password;
  const char *comment;
  entity_t entity;
  GString *command;
  gsad_user_t *current_user;

  login = params_value (params, "login");
  old_login = params_value (params, "old_login");
  modify_password = params_value (params, "modify_password");
  password = params_value (params, "password");
  user_id = params_value (params, "user_id");
  comment = params_value (params, "comment");

  CHECK_VARIABLE_INVALID (user_id, "Save User");
  CHECK_VARIABLE_INVALID (modify_password, "Save User");
  CHECK_VARIABLE_INVALID (login, "Save User");
  CHECK_VARIABLE_INVALID (old_login, "Save User");

  if (modify_password && str_equal (modify_password, "1"))
    CHECK_VARIABLE_INVALID (password, "Save User");

  if (params_given (params, "comment"))
    CHECK_VARIABLE_INVALID (comment, "Save User");

  command = g_string_new ("");
  buf = g_markup_printf_escaped ("<modify_user user_id=\"%s\">"
                                 "<password modify=\"%s\">"
                                 "%s</password>",
                                 user_id, modify_password,
                                 password ? password : "");
  g_string_append (command, buf);
  g_free (buf);

  current_user = gsad_credentials_get_user (credentials);

  if (login
      && current_user
      && strcmp (login, gsad_user_get_username (current_user)))
    {
      buf = g_markup_printf_escaped ("<new_name>%s</new_name>", login);
      g_string_append (command, buf);
      g_free (buf);
    }

  if (modify_password && !strcmp (modify_password, "2"))
    g_string_append (command,
                     "<sources><source>ldap_connect</source></sources>");
  else if (modify_password && !strcmp (modify_password, "3"))
    g_string_append (command,
                     "<sources><source>radius_connect</source></sources>");
  else
    g_string_append (command, "<sources><source>file</source></sources>");

  if (comment)
    xml_string_append (command, "<comment>%s</comment>", comment);

  g_string_append (command, "</modify_user>");

  entity = NULL;
  ret =
    gmp (connection, credentials, NULL, &entity, response_data, command->str);
  g_string_free (command, TRUE);

  switch (ret)
    {
    case 0:
      if (gmp_success (entity) == 1)
        {
          if (!str_equal (modify_password, "0")
              || !str_equal (old_login, login))
            {
              if (current_user)
                gsad_session_remove_other_sessions (
                  gsad_user_get_token (current_user), old_login);
            }

          if (current_user
              && str_equal (old_login, gsad_user_get_username (current_user)))
            {
              gsad_user_set_username (current_user, login);

              if (str_equal (modify_password, "1"))
                gsad_user_set_password (current_user, password);
            }
        }
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a user. "
        "The user was not saved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a user. "
        "It is unclear whether the user has been saved or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a user. "
        "It is unclear whether the user has been saved or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  if (gmp_success (entity)
      && (str_equal (modify_password, "2") || !str_equal (modify_password, "3"))
      && current_user
      && str_equal (old_login, gsad_user_get_username (current_user)))
    {
      free_entity (entity);

      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_UNAUTHORIZED);
      return gsad_http_create_gsad_message (
        credentials, "Authentication method changed. Please login with ",
        response_data);
    }
  else
    html = response_from_entity (connection, credentials, params, entity,
                                 "Save User", response_data);
  free_entity (entity);
  return html;
}

/**
 * @brief Export a user.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Note XML on success.  Enveloped XML on error.
 */
char *
export_user_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "user", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of users.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Users XML on success.  Enveloped XML
 *         on error.
 */
char *
export_users_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  return export_many (connection, "user", credentials, params, response_data);
}

/**
 * @brief Get all user defined settings
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Credentials of user issuing the action.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_settings_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  GString *xml;
  gchar *command;
  const gchar *filter;

  xml = g_string_new ("<get_settings>");

  /* Get the settings. */

  filter = params_value (params, "filter");
  if (filter)
    {
      command = g_markup_printf_escaped ("<get_settings"
                                         " filter=\"%s\""
                                         " sort_field=\"name\""
                                         " sort_order=\"ascending\"/>",
                                         filter);
    }
  else
    {
      command = g_strdup ("<get_settings"
                          " sort_field=\"name\""
                          " sort_order=\"ascending\"/>");
    }

  if (gvm_connection_sendf (connection, command))
    {
      g_free (command);

      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting the settings. "
        "The current list of settings is not available. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  if (read_string_c (connection, &xml))
    {
      g_free (command);
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting the settings. "
        "The current list of settings is not available. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  g_free (command);
  g_string_append (xml, "</get_settings>");
  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Save user setting
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return An action response.
 */
char *
save_setting_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  const gchar *setting_value = params_value (params, "setting_value");
  const gchar *setting_name = NULL;
  const gchar *setting_id = NULL;

  CHECK_VARIABLE_INVALID (setting_value, "Save Setting");

  if (params_given (params, "setting_name"))
    {
      setting_name = params_value (params, "setting_name");
      CHECK_VARIABLE_INVALID (setting_name, "Save Settings")
    }
  else
    {
      setting_id = params_value (params, "setting_id");
      CHECK_VARIABLE_INVALID (setting_id, "Save Setting");
    }

  gchar *value_64 =
    g_base64_encode ((guchar *) setting_value, strlen (setting_value));
  gchar *html;
  entity_t entity = NULL;
  int ret;
  GString *xml = g_string_new ("");

  if (setting_name)
    {
      xml_string_append (xml,
                         "<modify_setting>"
                         "<name>%s</name>"
                         "<value>%s</value>",
                         setting_name, value_64);
    }
  else
    {
      xml_string_append (xml,
                         "<modify_setting setting_id=\"%s\">"
                         "<value>%s</value>",
                         setting_id, value_64);
    }

  xml_string_append (xml, "</modify_setting>");

  gsad_command_response_data_set_content_type (response_data,
                                               GSAD_CONTENT_TYPE_APP_XML);

  ret = gmp (connection, credentials, NULL, &entity, response_data, xml->str);

  g_free (value_64);
  g_string_free (xml, TRUE);

  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving settings. "
        "It is unclear whether all the settings were saved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:

      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving settings. "
        "It is unclear whether all the settings were saved. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:

      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving settings. "
        "It is unclear whether all the settings were saved. "
        "Diagnostics: Internal Error.",
        response_data);
    }
  html = response_from_entity (connection, credentials, params, entity,
                               "Save Setting", response_data);
  free_entity (entity);
  return html;
}

char *
get_setting_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  const gchar *setting_id = params_value (params, "setting_id");
  CHECK_VARIABLE_INVALID (setting_id, "Get Setting");
  GString *xml = g_string_new ("<get_settings>");

  if (gvm_connection_sendf_xml (connection,
                                "<get_settings"
                                " setting_id=\"%s\"/>",
                                setting_id))
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting the "
        "dashboard settings"
        "Diagnostics: Failure to send command to manager "
        "daemon.",
        response_data);
    }

  if (read_string_c (connection, &xml))
    {
      g_string_free (xml, TRUE);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting the "
        "dashboard settings"
        "Diagnostics: Failure to receive response from "
        "manager daemon.",
        response_data);
    }

  g_string_append (xml, "</get_settings>");
  return envelope_gmp (connection, credentials, params,
                       g_string_free (xml, FALSE), response_data);
}

/**
 * @brief Delete multiple resources, get next page, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
bulk_delete_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  const char *type;
  params_t *selected_ids;
  gchar *extra_attribs;
  int count, fail;

  type = params_value (params, "resource_type");
  if (type == NULL)
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while deleting resources. "
        "The resources were not deleted. "
        "Diagnostics: Required parameter 'resource_type' was NULL.",
        response_data);
    }

  /* Extra attributes */
  extra_attribs = NULL;

  /* Inheritor of user's resource */
  if (strcmp (type, "user") == 0)
    {
      const char *inheritor_id;
      inheritor_id = params_value (params, "inheritor_id");
      if (inheritor_id)
        extra_attribs = g_strdup_printf ("inheritor_id=\"%s\"", inheritor_id);
    }

  count = fail = 0;
  selected_ids = params_values (params, "bulk_selected:");
  if (selected_ids)
    {
      params_iterator_t iter;
      param_t *param;
      gchar *param_name;

      params_iterator_init (&iter, selected_ids);
      while (params_iterator_next (&iter, &param_name, &param))
        {
          gchar *command;
          entity_t entity;

          /* Delete the resource. */

          command = g_strdup_printf ("<delete_%s %s_id=\"%s\""
                                     "           ultimate=\"0\" %s/>",
                                     type, type, param_name,
                                     extra_attribs ? extra_attribs : "");
          if (gvm_connection_sendf_xml (connection, command) == -1)
            {
              g_free (command);
              g_free (extra_attribs);
              gsad_command_response_data_set_status_code (
                response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
              return gsad_http_create_gsad_message (
                credentials,
                "An internal error occurred while deleting resources. "
                "The resources were not deleted. "
                "Diagnostics: Failure to send command to manager daemon.",
                response_data);
            }
          g_free (command);

          entity = NULL;
          if (read_entity_c (connection, &entity))
            {
              g_free (extra_attribs);
              gsad_command_response_data_set_status_code (
                response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
              return gsad_http_create_gsad_message (
                credentials,
                "An internal error occurred while deleting resources. "
                "It is unclear whether the resources have been deleted or not. "
                "Diagnostics: Failure to read response from manager daemon.",
                response_data);
            }

          if (*(entity_attribute (entity, "status")) != '2')
            fail = 1;
          else
            count++;

          free_entity (entity);
        }
    }
  g_free (extra_attribs);

  /* Cleanup, and return transformed XML. */

  if (fail)
    {
      gchar *html, *msg;

      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);

      msg = g_strdup_printf (
        "An error occurred while deleting one or more resources. "
        "However, %i of the resources %s successfully deleted. "
        "Diagnostics: At least one DELETE command failed.",
        count, count > 1 ? "were" : "was");

      html = gsad_http_create_gsad_message (credentials, msg, response_data);
      g_free (msg);
      return html;
    }

  return action_result (connection, credentials, params, response_data,
                        "Bulk Delete", "OK", "", /* Status details. */
                        NULL);                   /* ID. */
}

/**
 * @brief Export multiple resources
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
bulk_export_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  const gchar *type, *filter, *bulk_select;
  gchar *param_name;
  GString *bulk_string;
  params_t *selected_ids;
  params_iterator_t iter;
  param_t *param;

  type = params_value (params, "resource_type");
  filter = params_value (params, "filter");
  bulk_select = params_value (params, "bulk_select");

  CHECK_VARIABLE_INVALID (type, "Bulk Export")
  CHECK_VARIABLE_INVALID (bulk_select, "Bulk Export")

  if (g_ascii_strcasecmp (type, "filter") == 0
      || g_ascii_strcasecmp (type, "port_list") == 0
      || g_ascii_strcasecmp (type, "report_format") == 0
      || g_ascii_strcasecmp (type, "tag") == 0
      || g_ascii_strcasecmp (type, "vuln") == 0)
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      return gsad_http_create_gsad_message (
        credentials,
        "Filter, port-list, report-format, tag, and vulnerability XML bulk "
        "export are no longer supported. Use the native JSON metadata export "
        "endpoints instead.",
        response_data);
    }

  if (bulk_select && str_equal (bulk_select, "1"))
    {
      bulk_string = g_string_new ("first=1 rows=-1 uuid=");

      selected_ids = params_values (params, "bulk_selected:");
      if (selected_ids)
        {
          params_iterator_init (&iter, selected_ids);
          while (params_iterator_next (&iter, &param_name, &param))
            {
              xml_string_append (bulk_string, " uuid=%s", param_name);
            }
        }
    }
  else
    {
      bulk_string = g_string_new (filter ?: "");
    }

  params_add (params, "filter", g_string_free (bulk_string, FALSE));

  return export_many (connection, type, credentials, params, response_data);
}

/* Assets. */

/**
 * @brief Create a host, serve next page.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
create_host_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                 params_t *params, gsad_command_response_data_t *response_data)
{
  int ret;
  gchar *html;
  const char *name, *comment;
  entity_t entity;
  GString *xml;

  name = params_value (params, "name");
  CHECK_VARIABLE_INVALID (name, "Create Host");

  comment = params_value (params, "comment");
  CHECK_VARIABLE_INVALID (comment, "Create Host");

  /* Create the host. */

  xml = g_string_new ("");

  xml_string_append (xml,
                     "<create_asset>"
                     "<asset>"
                     "<type>host</type>"
                     "<name>%s</name>"
                     "<comment>%s</comment>"
                     "</asset>"
                     "</create_asset>",
                     name, comment);

  ret = gmp (connection, credentials, NULL, &entity, response_data, xml->str);
  g_string_free (xml, TRUE);
  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new host. "
        "No new host was created. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new host. "
        "It is unclear whether the host has been created or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a new host. "
        "It is unclear whether the host has been created or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  if (entity_attribute (entity, "id"))
    params_add (params, "asset_id", entity_attribute (entity, "id"));
  html = response_from_entity (connection, credentials, params, entity,
                               "Create Host", response_data);
  free_entity (entity);
  return html;
}

/**
 * @brief Request an asset.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Credentials for the manager connection.
 * @param[in]  params       Request parameters.
 * @param[in]  extra_xml    Extra XML to insert inside page element.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return XML enveloped asset response or error message.
 */
char *
get_asset (gvm_connection_t *connection, gsad_credentials_t *credentials,
           params_t *params, const char *extra_xml,
           gsad_command_response_data_t *response_data)
{
  const gchar *asset_type;
  gmp_arguments_t *arguments;

  asset_type = params_value (params, "asset_type");

  CHECK_VARIABLE_INVALID (asset_type, "Get Asset")

  if (params_value (params, "asset_name") && params_value (params, "asset_id"))
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while getting an asset. "
        "Diagnostics: Both ID and Name set.",
        response_data);
    }

  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "type", asset_type);

  if (params_value (params, "asset_name"))
    {
      gmp_arguments_add (arguments, "name",
                         params_value (params, "asset_name"));
    }

  return get_one (connection, "asset", credentials, params, NULL, arguments,
                  response_data);
}

/**
 * @brief Get asset, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_asset_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
               params_t *params, gsad_command_response_data_t *response_data)
{
  return get_asset (connection, credentials, params, NULL, response_data);
}

/**
 * @brief Request assets.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Credentials for the manager connection.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return XML enveloped assets response or error message.
 */
char *
get_assets_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments;
  const char *asset_type;

  asset_type = params_value (params, "asset_type");

  CHECK_VARIABLE_INVALID (asset_type, "Get Assets");

  arguments = gmp_arguments_new ();

  gmp_arguments_add (arguments, "type", asset_type);

  if (params_value (params, "ignore_pagination"))
    {
      gmp_arguments_add (arguments, "ignore_pagination",
                         params_value (params, "ignore_pagination"));
    }

  return get_many (connection, "assets", credentials, params, arguments,
                   response_data);
}

/**
 * @brief Create an asset, get report, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
create_asset_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  char *ret;
  const char *report_id, *filter;
  entity_t entity;

  report_id = params_value (params, "report_id");
  filter = params_value (params, "filter");

  CHECK_VARIABLE_INVALID (report_id, "Create Asset");
  CHECK_VARIABLE_INVALID (filter, "Create Asset");

  entity = NULL;
  switch (gmpf (connection, credentials, NULL, &entity, response_data,
                "<create_asset>"
                "<report id=\"%s\">"
                "<filter><term>%s</term></filter>"
                "</report>"
                "</create_asset>",
                report_id, filter))
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating an asset. "
        "No new asset was created. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating an asset. "
        "It is unclear whether the asset has been created or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating an asset. "
        "It is unclear whether the asset has been created or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  ret = response_from_entity (connection, credentials, params, entity,
                              "Create Asset", response_data);
  free_entity (entity);
  return ret;
}

/**
 * @brief Delete an asset, go to the next page.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_asset_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  gchar *html, *resource_id;
  const char *next_id;
  entity_t entity;

  if (params_value (params, "asset_id"))
    resource_id = g_strdup (params_value (params, "asset_id"));
  else if (params_value (params, "report_id"))
    resource_id = g_strdup (params_value (params, "report_id"));
  else
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while deleting an asset. "
        "The asset was not deleted. "
        "Diagnostics: Required parameter was NULL.",
        response_data);
    }

  /* This is a hack, needed because asset_id is the param name used for
   * both the asset being deleted and the asset on the next page. */
  next_id = params_value (params, "next_id");
  if (next_id && params_value (params, "asset_id"))
    {
      param_t *param;
      param = params_get (params, "asset_id");
      g_free (param->value);
      param->value = g_strdup (next_id);
      param->value_size = strlen (param->value);
    }

  /* Delete the resource and get all resources. */

  if (gvm_connection_sendf (
        connection, "<delete_asset %s_id=\"%s\"/>",
        params_value (params, "asset_id") ? "asset" : "report", resource_id)
      == -1)
    {
      g_free (resource_id);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while deleting an asset. "
        "The asset is not deleted. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }

  g_free (resource_id);

  entity = NULL;
  if (read_entity_c (connection, &entity))
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while deleting an asset. "
        "It is unclear whether the asset has been deleted or not. "
        "Diagnostics: Failure to read response from manager daemon.",
        response_data);
    }

  /* Cleanup, and return transformed XML. */

  html = response_from_entity (connection, credentials, params, entity,
                               "Delete Asset", response_data);
  free_entity (entity);
  return html;
}

/**
 * @brief Export an asset.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Asset XML on success.  Enveloped XML on error.
 */
char *
export_asset_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                  params_t *params, gsad_command_response_data_t *response_data)
{
  return export_resource (connection, "asset", credentials, params,
                          response_data);
}

/**
 * @brief Export a list of assets.
 *
 * @param[in]   connection           Connection to manager.
 * @param[in]   credentials          Username and password for authentication.
 * @param[in]   params               Request parameters.
 * @param[out]  response_data        Extra data return for the HTTP response.
 *
 * @return Assets XML on success.  Enveloped XML
 *         on error.
 */
char *
export_assets_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  return export_many (connection, "asset", credentials, params, response_data);
}

/**
 * @brief Modify an asset, get all assets, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials  Username and password for authentication.
 * @param[in]  params       Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
save_asset_gmp (gvm_connection_t *connection, gsad_credentials_t *credentials,
                params_t *params, gsad_command_response_data_t *response_data)
{
  int ret;
  gchar *html;
  const char *asset_id, *comment;
  entity_t entity;

  asset_id = params_value (params, "asset_id");
  comment = params_value (params, "comment");

  CHECK_VARIABLE_INVALID (asset_id, "Save Asset");
  CHECK_VARIABLE_INVALID (comment, "Save Asset");

  /* Modify the asset. */

  entity = NULL;
  ret = gmpf (connection, credentials, NULL, &entity, response_data,
              "<modify_asset asset_id=\"%s\">"
              "<comment>%s</comment>"
              "</modify_asset>",
              asset_id, comment);

  switch (ret)
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving an asset. "
        "The asset was not saved. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving an asset. "
        "It is unclear whether the asset has been saved or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving an asset. "
        "It is unclear whether the asset has been saved or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  html = response_from_entity (connection, credentials, params, entity,
                               "Save Asset", response_data);
  free_entity (entity);
  return html;
}

/**
 * @brief Get all TLS certificates, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_tls_certificates_gmp (gvm_connection_t *connection,
                          gsad_credentials_t *credentials, params_t *params,
                          gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments = gmp_arguments_new ();
  const char *include_certificate_data;

  if (params_given (params, "include_certificate_data"))
    {
      include_certificate_data =
        params_value (params, "include_certificate_data");
      CHECK_VARIABLE_INVALID (include_certificate_data, "Get TLS Certificate");
      gmp_arguments_add (arguments, "include_certificate_data",
                         include_certificate_data);
    }

  return get_many (connection, "tls_certificates", credentials, params,
                   arguments, response_data);
}

/**
 * @brief Get single TLS certificates, envelope the result.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
get_tls_certificate_gmp (gvm_connection_t *connection,
                         gsad_credentials_t *credentials, params_t *params,
                         gsad_command_response_data_t *response_data)
{
  gmp_arguments_t *arguments = gmp_arguments_new ();
  const char *include_certificate_data;

  if (params_given (params, "include_certificate_data"))
    {
      include_certificate_data =
        params_value (params, "include_certificate_data");
      CHECK_VARIABLE_INVALID (include_certificate_data, "Get TLS Certificate");
      gmp_arguments_add (arguments, "include_certificate_data",
                         include_certificate_data);
    }

  return get_one (connection, "tls_certificate", credentials, params, NULL,
                  arguments, response_data);
}

/**
 * @brief Create a TLS certificate.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
create_tls_certificate_gmp (gvm_connection_t *connection,
                            gsad_credentials_t *credentials, params_t *params,
                            gsad_command_response_data_t *response_data)
{
  entity_t entity = NULL;
  const gchar *name, *comment, *trust, *certificate_bin;
  size_t certificate_size;
  gchar *certificate_b64;
  gchar *ret;

  name = params_value (params, "name");
  comment = params_value (params, "comment");
  trust = params_value (params, "trust");
  certificate_bin = params_value (params, "certificate_bin");
  certificate_size = params_value_size (params, "certificate_bin");

  certificate_b64 =
    (certificate_size > 0)
      ? g_base64_encode ((guchar *) certificate_bin, certificate_size)
      : g_strdup ("");

  CHECK_VARIABLE_INVALID (name, "Create TLS Certificate");
  CHECK_VARIABLE_INVALID (comment, "Create TLS Certificate");
  CHECK_VARIABLE_INVALID (trust, "Create TLS Certificate");

  switch (gmpf (connection, credentials, NULL, &entity, response_data,
                "<create_tls_certificate>"
                "<name>%s</name>"
                "<comment>%s</comment>"
                "<trust>%s</trust>"
                "<certificate>%s</certificate>"
                "</create_tls_certificate>",
                name, comment, trust, certificate_b64))
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a TLS certificate. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a TLS certificate. "
        "It is unclear whether the TLS certificate has been created or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while creating a TLS certificate. "
        "It is unclear whether the TLS certificate has been created or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  ret = response_from_entity (connection, credentials, params, entity,
                              "Create TLS Certificate", response_data);

  free_entity (entity);
  g_free (certificate_b64);
  return ret;
}

/**
 * @brief Modify a TLS certificate.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
save_tls_certificate_gmp (gvm_connection_t *connection,
                          gsad_credentials_t *credentials, params_t *params,
                          gsad_command_response_data_t *response_data)
{
  entity_t entity = NULL;
  const gchar *tls_certificate_id, *name, *comment, *trust, *certificate_bin;
  size_t certificate_size;
  gchar *certificate_b64;
  gchar *ret;

  tls_certificate_id = params_value (params, "tls_certificate_id");
  name = params_value (params, "name");
  comment = params_value (params, "comment");
  trust = params_value (params, "trust");
  certificate_bin = params_value (params, "certificate_bin");
  certificate_size = params_value_size (params, "certificate_bin");

  certificate_b64 =
    (certificate_size > 0)
      ? g_base64_encode ((guchar *) certificate_bin, certificate_size)
      : g_strdup ("");

  CHECK_VARIABLE_INVALID (tls_certificate_id, "Save TLS Certificate");
  CHECK_VARIABLE_INVALID (name, "Save TLS Certificate");
  CHECK_VARIABLE_INVALID (comment, "Save TLS Certificate");
  CHECK_VARIABLE_INVALID (trust, "Save TLS Certificate");

  switch (gmpf (connection, credentials, NULL, &entity, response_data,
                "<modify_tls_certificate tls_certificate_id=\"%s\">"
                "<name>%s</name>"
                "<comment>%s</comment>"
                "<trust>%s</trust>"
                "<certificate>%s</certificate>"
                "</modify_tls_certificate>",
                tls_certificate_id, name, comment, trust, certificate_b64))
    {
    case 0:
      break;
    case 1:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a TLS certificate. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    case 2:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a TLS certificate. "
        "It is unclear whether the TLS certificate has been saved or not. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    default:
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while saving a TLS certificate. "
        "It is unclear whether the TLS certificate has been saved or not. "
        "Diagnostics: Internal Error.",
        response_data);
    }

  ret = response_from_entity (connection, credentials, params, entity,
                              "Save TLS Certificate", response_data);

  free_entity (entity);
  g_free (certificate_b64);
  return ret;
}

/**
 * @brief Delete a TLS certificate.
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return Enveloped XML object.
 */
char *
delete_tls_certificate_gmp (gvm_connection_t *connection,
                            gsad_credentials_t *credentials, params_t *params,
                            gsad_command_response_data_t *response_data)
{
  return move_resource_to_trash (connection, "tls_certificate", credentials,
                                 params, response_data);
}

/**
 * @brief Change user password
 *
 * @param[in]  connection     Connection to manager.
 * @param[in]  credentials    Username and password for authentication.
 * @param[in]  params         Request parameters.
 * @param[out] response_data  Extra data return for the HTTP response.
 *
 * @return An action response.
 */
char *
change_password_gmp (gvm_connection_t *connection,
                     gsad_credentials_t *credentials, params_t *params,
                     gsad_command_response_data_t *response_data)
{
  const char *old_passwd, *passwd;
  gchar *passwd_64 = NULL;
  gchar *html = NULL;
  entity_t entity = NULL;
  gsad_user_t *user = gsad_credentials_get_user (credentials);

  old_passwd = params_value (params, "old_password");
  passwd = params_value (params, "password");

  CHECK_VARIABLE_INVALID (passwd, "Change Password")
  CHECK_VARIABLE_INVALID (old_passwd, "Change Password")

  passwd_64 = g_base64_encode ((guchar *) passwd, strlen (passwd));

  if (gvm_connection_sendf (connection,
                            "<modify_setting>"
                            "<name>Password</name>"
                            "<value>%s</value>"
                            "</modify_setting>",
                            passwd_64 ? passwd_64 : "")
      == -1)
    {
      g_free (passwd_64);
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while changing the password. "
        "Diagnostics: Failure to send command to manager daemon.",
        response_data);
    }
  g_free (passwd_64);

  if (read_entity_c (connection, &entity))
    {
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      return gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred while changing the password. "
        "Diagnostics: Failure to receive response from manager daemon.",
        response_data);
    }

  if (gmp_success (entity) == 1 && user)
    {
      gsad_user_set_password (user, passwd);
      gsad_session_remove_other_sessions (gsad_user_get_token (user),
                                          gsad_user_get_username (user));
      gsad_session_replace_user_if_exists (user);
    }

  gsad_command_response_data_set_content_type (response_data,
                                               GSAD_CONTENT_TYPE_APP_XML);
  html = response_from_entity (connection, credentials, params, entity,
                               "Change Password", response_data);
  return html;
}

char *
renew_session_gmp (gvm_connection_t *connection,
                   gsad_credentials_t *credentials, params_t *params,
                   gsad_command_response_data_t *response_data)
{
  gchar *html;
  gchar *message;
  gsad_user_t *user = gsad_credentials_get_user (credentials);

  if (user)
    {
      gsad_user_session_renew_timeout (user);

      message = g_strdup_printf ("%ld", gsad_user_session_get_timeout (user));
    }
  else
    {
      // FIXME this is currently a placeholder for JWT based session timeout
      time_t current_time = time (NULL);
      gsad_settings_t *gsad_global_settings =
        gsad_settings_get_global_settings ();
      time_t session_timeout =
        current_time
        + gsad_settings_get_session_timeout (gsad_global_settings) * 60;
      message = g_strdup_printf ("%ld", session_timeout);
    }

  html = action_result (connection, credentials, params, response_data,
                        "renew_session", message, NULL, NULL);
  g_free (message);
  return html;
}

/**
 * @brief Check authentication credentials.
 *
 * @param[in]  username      Username.
 * @param[in]  password      Password.
 * @param[out] timezone      Timezone.
 * @param[out] capabilities  Capabilities of manager.
 * @param[out] language      User Interface Language, or NULL.
 * @param[out] pw_warning    Password warning message, NULL if password is OK.
 * @param[out] jwt           JWT value, NULL if not requested.
 * @param[out] user_uuid     Authenticated user UUID, or NULL.
 *
 * @return 0 if valid, 1 manager down, 2 failed, 3 timeout, -1 error.
 */
static int
authenticate_gmp_with_user_uuid (const gchar *username, const gchar *password,
                                 gchar **timezone, gchar **capabilities,
                                 gchar **language, gchar **jwt,
                                 gchar **user_uuid)
{
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  gvm_connection_t connection;
  gmp_authenticate_info_opts_t auth_opts;

  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = username;
  auth_opts.password = password;
  auth_opts.timezone = timezone;
  auth_opts.jwt_requested =
    gsad_settings_is_jwt_requested (gsad_global_settings);
  auth_opts.jwt = jwt;
  auth_opts.user_uuid = user_uuid;

  int auth = gsad_manager_connect_with_auth_opts (&connection, auth_opts);
  if (auth == 0)
    {
      entity_t entity;
      const char *status;
      char first;
      gchar *response;
      int ret;

      /* Get language setting. */

      ret = setting_get_value (
        &connection, "6765549a-934e-11e3-b358-406186ea4fc5", language, NULL);

      switch (ret)
        {
        case 0:
          break;
        case 1:
        case 2:
          gvm_connection_close (&connection);
          return 1;
        default:
          gvm_connection_close (&connection);
          return -1;
        }

      /* Request help. */

      ret = gvm_connection_sendf (&connection,
                                  "<help format=\"XML\" type=\"brief\"/>");
      if (ret)
        {
          gvm_connection_close (&connection);
          return 1;
        }

      /* Read the response. */

      entity = NULL;
      if (read_entity_and_text_c (&connection, &entity, &response))
        {
          gvm_connection_close (&connection);
          return 1;
        }

      /* Check the response. */

      status = entity_attribute (entity, "status");
      if (status == NULL || strlen (status) == 0)
        {
          g_free (response);
          free_entity (entity);
          return -1;
        }

      first = status[0];
      free_entity (entity);

      if (first == '2')
        {
          *capabilities = response;
        }
      else
        {
          gvm_connection_close (&connection);
          g_free (response);
          return -1;
        }

      gvm_connection_close (&connection);
      return 0;
    }
  else
    {
      gvm_connection_close (&connection);

      switch (auth)
        {
        case 1: /* manager closed connection */
        case 2: /* auth failed */
        case 3: /* timeout */
        case 4: /* failed to connect */
          return auth;
        default:
          return -1;
        }
    }
}

int
authenticate_gmp (const gchar *username, const gchar *password,
                  gchar **timezone, gchar **capabilities, gchar **language,
                  gchar **jwt)
{
  return authenticate_gmp_with_user_uuid (
    username, password, timezone, capabilities, language, jwt, NULL);
}

/**
 * @brief Log out.
 *
 * @param[in]  username      Username.
 * @param[in]  password      Password.
 *
 * @return 0 success, else error.
 */
int
logout_gmp (const gchar *username, const gchar *password)
{
  gvm_connection_t connection;
  entity_t entity;
  const char *status;

  int ret = gsad_manager_connect_with_username_password (&connection, username,
                                                         password);
  if (ret)
    {
      gvm_connection_close (&connection);

      switch (ret)
        {
        case 1: /* manager closed connection */
        case 2: /* auth failed */
        case 3: /* timeout */
          return ret;
        default:
          return -1;
        }
    }

  ret = gvm_connection_sendf_xml (&connection, "<logout/>");
  if (ret)
    {
      gvm_connection_close (&connection);
      return -1;
    }

  entity = NULL;
  if (read_entity_c (&connection, &entity))
    {
      gvm_connection_close (&connection);
      return 1;
    }

  gvm_connection_close (&connection);

  status = entity_attribute (entity, "status");
  if ((status == NULL) || (strlen (status) == 0))
    {
      free_entity (entity);
      return -1;
    }
  else if (status[0] == '2')
    {
      free_entity (entity);
      return 2;
    }

  free_entity (entity);
  return 0;
}

/**
 * @brief Login and create a session
 *
 * @param[in]   con             HTTP Connection
 * @param[in]   params          Request parameters
 * @param[out]  response_data   Extra data return for the HTTP response
 * @param[in]   client_address  Client address
 *
 * @return MHD_YES on success. MHD_NO on errors.
 */
int
login (gsad_http_connection_t *con, params_t *params,
       gsad_command_response_data_t *response_data, const char *client_address)
{
  int ret, status;
  gsad_authentication_reason_t auth_reason;
  gsad_credentials_t *credentials;
  gchar *timezone;
  gchar *capabilities;
  gchar *language;
  gchar *jwt = NULL;
  gchar *user_uuid = NULL;

  const char *password = params_value (params, "password");
  const char *login = params_value (params, "login");

  if ((password == NULL)
      && (params_original_value (params, "password") == NULL))
    password = "";
  if (login && password)
    {
      ret = authenticate_gmp_with_user_uuid (
        login, password, &timezone, &capabilities, &language, &jwt, &user_uuid);
      if (ret)
        {
          switch (ret)
            {
            case 1: /* could not connect to manager */
            case 3: /* timeout */
              status = MHD_HTTP_SERVICE_UNAVAILABLE;
              auth_reason = GMP_SERVICE_DOWN;
              break;
            case 2: /* authentication failure */
              status = MHD_HTTP_UNAUTHORIZED;
              auth_reason = LOGIN_FAILED;
              break;
            default: /* unspecified error */
              status = MHD_HTTP_INTERNAL_SERVER_ERROR;
              auth_reason = LOGIN_ERROR;
              break;
            }

          g_warning ("Authentication failure for '%s' from %s. "
                     "Status was %d.",
                     login ?: "", client_address, ret);
          g_free (user_uuid);
          return gsad_http_send_reauthentication (con, status, auth_reason);
        }
      else
        {
          gsad_user_t *user =
            gsad_user_new_with_data (login, password, timezone, capabilities,
                                     language, client_address);

          if (!gsad_user_set_uuid (user, user_uuid))
            {
              g_warning ("Authentication failure for '%s' from %s. "
                         "Manager returned no valid user identity.",
                         login ?: "", client_address);
              gsad_user_free (user);
              g_free (timezone);
              g_free (capabilities);
              g_free (language);
              g_free (jwt);
              g_free (user_uuid);
              return gsad_http_send_reauthentication (
                con, MHD_HTTP_INTERNAL_SERVER_ERROR, LOGIN_ERROR);
            }

          int add_user = gsad_user_session_add (user);
          if (add_user)
            {
              status = MHD_HTTP_FORBIDDEN;
              auth_reason = TOO_MANY_USER_SESSIONS;

              g_warning ("Authentication failure for '%s' from %s."
                         " Too many sessions for user.",
                         login ?: "", client_address);

              gsad_user_free (user);
              g_free (timezone);
              g_free (capabilities);
              g_free (language);
              g_free (jwt);
              g_free (user_uuid);

              return gsad_http_send_reauthentication (con, status, auth_reason);
            }

          g_message ("Authentication success for '%s' from %s", login ?: "",
                     client_address);

          credentials = gsad_credentials_new ();
          gsad_credentials_set_user (credentials, user);
          gsad_credentials_set_jwt (credentials, jwt);

          // xml must not be NULL: gsad_http_create_envelope() expects a valid
          // string and passing NULL would trigger a GLib critical
          gchar *data = gsad_http_create_envelope (credentials, g_strdup (""),
                                                   response_data);

          ret = gsad_http_create_response (con, data, response_data,
                                           gsad_user_get_cookie (user));

          gsad_user_free (user);

          gsad_credentials_free (credentials);

          g_free (timezone);
          g_free (capabilities);
          g_free (language);
          g_free (jwt);
          g_free (user_uuid);

          return ret;
        }
    }
  else
    {
      g_warning ("Authentication failure for '%s' from %s", login ?: "",
                 client_address);
      return gsad_http_send_reauthentication (con, MHD_HTTP_UNAUTHORIZED,
                                              LOGIN_FAILED);
    }
}

#undef ELSE

/**
 * @brief Add else branch for an GMP operation.
 */
#define ELSE(name)                                  \
  else if (!strcmp (cmd, G_STRINGIFY (name))) res = \
    name##_gmp (&connection, credentials, params, response_data);

/**
 * @brief Handle a complete GET request.
 *
 * After some input checking, depending on the cmd parameter of the connection,
 * issue an gmp command (via *_gmp functions).
 *
 * @param[in]   con                  HTTP Connection
 * @param[in]   con_info             Connection info.
 * @param[in]   credentials          User credentials.
 *
 * @return MHD_YES on success, MHD_NO on error.
 */
gsad_http_result_t
exec_gmp_get (gsad_http_connection_t *con, gsad_connection_info_t *con_info,
              gsad_credentials_t *credentials)
{
  const gchar *cmd = NULL;
  const int CMD_MAX_SIZE = 22;
  params_t *params = gsad_connection_info_get_params (con_info);
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  gvm_connection_t connection;
  gchar *res = NULL, *comp = NULL;
  gsize res_len = 0;
  gsad_http_response_t *response;
  gsad_command_response_data_t *response_data =
    gsad_command_response_data_new ();
  gsad_connection_watcher_t *watcher = NULL;
  validator_t validator = gsad_get_validator ();
  gchar *encoding;

  cmd = params_value (params, "cmd");

  if (gvm_validate (validator, "cmd", cmd))
    cmd = NULL;

  if ((cmd != NULL) && (strlen (cmd) <= CMD_MAX_SIZE))
    {
      g_debug ("Handling GMP command '%s' for HTTP GET", cmd);
    }
  else
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred inside GSA daemon. "
        "Diagnostics: No valid command for gmp.",
        response_data);
      return gsad_http_create_response (con, res, response_data, NULL);
    }

  /* Connect to manager */
  switch (gsad_manager_connect_with_credentials (&connection, credentials))
    {
    case 0:
      break;
    case 1: /* manager closed connection */
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred. "
        "Diagnostics: Could not connect to manager daemon. "
        "Manager closed the connection.",
        response_data);
      break;
    case 2: /* auth failed */
      gsad_command_response_data_free (response_data);
      return gsad_http_send_reauthentication (con, MHD_HTTP_UNAUTHORIZED,
                                              LOGIN_FAILED);
    case 3: /* timeout */
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred. "
        "Diagnostics: Could not connect to manager daemon. "
        "Connection timeout.",
        response_data);
      break;
    case 4: /* can't connect to manager */
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_SERVICE_UNAVAILABLE);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred. "
        "Diagnostics: Could not connect to manager daemon. "
        "Could not open a connection.",
        response_data);
      break;
    default: /* unknown error */
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred. "
        "Diagnostics: Could not connect to manager daemon. "
        "Unknown error.",
        response_data);
    }

  if (res)
    {
      return gsad_http_create_response (con, res, response_data, NULL);
    }

  /* Set page display settings */

  if (gsad_settings_get_client_watch_interval (gsad_global_settings))
    {
      const union MHD_ConnectionInfo *mhd_con_info;
      mhd_con_info =
        MHD_get_connection_info (con, MHD_CONNECTION_INFO_CONNECTION_FD);

      watcher = gsad_connection_watcher_new (gsad_global_settings, &connection,
                                             mhd_con_info->connect_fd);
      gsad_connection_watcher_start (watcher);
    }

  if (0)
    {
    }
  ELSE (edit_config_family)
  ELSE (edit_config_family_all)
  ELSE (export_alert)
  ELSE (export_alerts)
  ELSE (export_asset)
  ELSE (export_assets)
  ELSE (download_credential)
  ELSE (export_credential)
  ELSE (export_credentials)
  ELSE (export_override)
  ELSE (export_overrides)
  ELSE (export_preference_file)
  ELSE (export_result)
  ELSE (export_results)
  ELSE (export_scanner)
  ELSE (export_scanners)
  ELSE (export_schedule)
  ELSE (export_schedules)
  ELSE (export_target)
  ELSE (export_targets)
  ELSE (export_task)
  ELSE (export_tasks)
  ELSE (export_user)
  ELSE (export_users)
  ELSE (get_asset)
  ELSE (get_assets)
  ELSE (get_aggregate)
  ELSE (get_alert)
  ELSE (get_alerts)
  ELSE (get_config)
  ELSE (get_configs)
  ELSE (get_config_family)
  ELSE (get_credential)
  ELSE (get_credentials)
  ELSE (get_info)
  ELSE (get_override)
  ELSE (get_overrides)
  ELSE (get_port_list)
  ELSE (get_port_lists)
  ELSE (get_report)
  ELSE (get_reports)
  ELSE (get_resource_names)
  ELSE (get_scanner)
  ELSE (get_scanners)
  ELSE (get_schedule)
  ELSE (get_schedules)
  ELSE (get_scope)
  ELSE (get_scopes)
  ELSE (get_setting)
  ELSE (get_settings)
  ELSE (get_tag)
  ELSE (get_tags)
  ELSE (get_target)
  ELSE (get_targets)
  ELSE (get_task)
  ELSE (get_tasks)
  ELSE (get_tls_certificate)
  ELSE (get_tls_certificates)
  ELSE (get_user)
  ELSE (get_users)
  else if (!strcmp (cmd, "download_ssl_cert"))
  {
    gsad_command_response_data_set_content_type (response_data,
                                                 GSAD_CONTENT_TYPE_APP_KEY);
    gsad_command_response_data_set_content_disposition (
      response_data, g_strdup_printf ("attachment; filename=ssl-cert-%s.pem",
                                      params_value (params, "name")));

    res = download_ssl_cert (&connection, credentials, params, response_data);
  }

  else if (!strcmp (cmd, "download_ca_pub"))
  {
    gsad_command_response_data_set_content_type (response_data,
                                                 GSAD_CONTENT_TYPE_APP_KEY);
    gsad_command_response_data_set_content_disposition (
      response_data,
      g_strdup_printf ("attachment; filename=scanner-ca-pub-%s.pem",
                       params_value (params, "scanner_id")));
    res = download_ca_pub (&connection, credentials, params, response_data);
  }

  else if (!strcmp (cmd, "download_key_pub"))
  {
    gsad_command_response_data_set_content_type (response_data,
                                                 GSAD_CONTENT_TYPE_APP_KEY);
    gsad_command_response_data_set_content_disposition (
      response_data,
      g_strdup_printf ("attachment; filename=scanner-key-pub-%s.pem",
                       params_value (params, "scanner_id")));
    res = download_key_pub (&connection, credentials, params, response_data);
  }

  else
  {
    gsad_command_response_data_set_status_code (response_data,
                                                MHD_HTTP_BAD_REQUEST);
    res = gsad_http_create_gsad_message (
      credentials,
      "An internal error occurred inside GSA daemon. "
      "Diagnostics: Unknown command.",
      response_data);
  }

  res_len = gsad_command_response_data_get_content_length (response_data);

  if (res_len == 0)
    res_len = strlen (res);

  encoding = NULL;

  if (gsad_http_may_brotli (con))
    {
      gsize comp_len;

      if (gsad_http_compress_response_brotli (res_len, res, &comp_len, &comp))
        {
          free (res);
          res_len = comp_len;
          res = comp;
          encoding = "br";
        }
    }
  if ((encoding == NULL) && gsad_http_may_deflate (con))
    {
      gsize comp_len;

      if (gsad_http_compress_response_deflate (res_len, res, &comp_len, &comp))
        {
          free (res);
          res_len = comp_len;
          res = comp;
          encoding = "deflate";
        }
    }

  response = MHD_create_response_from_buffer (res_len, (void *) res,
                                              MHD_RESPMEM_MUST_FREE);

  if (encoding)
    MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_ENCODING,
                             encoding);

  if (watcher)
    {
      gsad_connection_watcher_stop (watcher);
      gsad_connection_watcher_free (watcher);
    }
  else
    {
      gvm_connection_close (&connection);
    }

  gsad_user_t *user = gsad_credentials_get_user (credentials);

  return gsad_http_send_response (con, response, response_data,
                                  user ? gsad_user_get_cookie (user) : NULL);
}

/**
 * @brief Handle a complete POST request.
 *
 * Ensures there is a command, then depending on the command validates
 * parameters and calls the appropriate GMP function (like
 * create_task_gmp).
 *
 * @param[in]   con             HTTP connection
 * @param[in]   con_info        Connection info.
 * @param[in]   credentials     Client credentials.
 *
 * @return MHD_YES on success, MHD_NO on error.
 */
gsad_http_result_t
exec_gmp_post (gsad_http_connection_t *con, gsad_connection_info_t *con_info,
               gsad_credentials_t *credentials)
{
  gchar *res = NULL;
  const gchar *cmd;
  gvm_connection_t connection;
  gsad_command_response_data_t *response_data =
    gsad_command_response_data_new ();
  gsad_user_t *user = gsad_credentials_get_user (credentials);
  validator_t validator = gsad_get_validator ();
  params_t *params = gsad_connection_info_get_params (con_info);

  cmd = params_value (params, "cmd");

  if (gvm_validate (validator, "cmd", cmd))
    cmd = NULL;

  if (!cmd)
    {
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_BAD_REQUEST);

      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred inside GSA daemon. "
        "Diagnostics: Invalid command.",
        response_data);
      return gsad_http_create_response (con, res, response_data, NULL);
    }

  g_debug ("Handling GMP command '%s' for HTTP POST", cmd);

  /* Connect to manager */
  switch (gsad_manager_connect_with_credentials (&connection, credentials))
    {
    case 0:
      break;
    case 1: /* manager closed connection */
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred. "
        "Diagnostics: Could not connect to manager daemon. "
        "Manager closed the connection.",
        response_data);
      break;
    case 2: /* auth failed */
      gsad_command_response_data_free (response_data);
      return gsad_http_send_reauthentication (con, MHD_HTTP_UNAUTHORIZED,
                                              LOGIN_FAILED);
    case 3: /* timeout */
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred. "
        "Diagnostics: Could not connect to manager daemon. "
        "Connection timeout.",
        response_data);
      break;
    case 4: /* can't connect to manager */
      gsad_command_response_data_set_status_code (response_data,
                                                  MHD_HTTP_SERVICE_UNAVAILABLE);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred. "
        "Diagnostics: Could not connect to manager daemon. "
        "Could not open a connection.",
        response_data);
      break;
    default: /* unknown error */
      gsad_command_response_data_set_status_code (
        response_data, MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_http_create_gsad_message (
        credentials,
        "An internal error occurred. "
        "Diagnostics: Could not connect to manager daemon. "
        "Unknown error.",
        response_data);
    }

  if (res)
    {
      return gsad_http_create_response (con, res, response_data, NULL);
    }

  /* always renew session for http post */
  if (user)
    {
      gsad_user_session_renew_timeout (user);
    }

  /* Handle the usual commands. */
  if (0)
    {
    }
  ELSE (bulk_delete)
  ELSE (bulk_export)
  ELSE (change_password)
  ELSE (create_asset)
  ELSE (create_credential)
  ELSE (create_host)
  ELSE (create_task)
  ELSE (create_target)
  ELSE (create_tls_certificate)
  ELSE (create_user)
  ELSE (delete_asset)
  ELSE (delete_alert)
  ELSE (delete_config)
  ELSE (delete_credential)
  ELSE (delete_report)
  ELSE (delete_schedule)
  ELSE (delete_target)
  ELSE (delete_task)
  ELSE (delete_tls_certificate)
  ELSE (delete_user)
  ELSE (move_task)
  ELSE (renew_session)
  ELSE (save_asset)
  ELSE (save_setting)
  ELSE (save_config)
  ELSE (save_config_family)
  ELSE (save_credential)
  ELSE (save_target)
  ELSE (save_task)
  ELSE (save_tls_certificate)
  ELSE (save_user)
  ELSE (start_task)
  ELSE (stop_task)
  ELSE (sync_feed)
  ELSE (sync_scap)
  ELSE (sync_cert)
  ELSE (test_alert)
  ELSE (verify_scanner)
  else
  {
    gsad_command_response_data_set_status_code (response_data,
                                                MHD_HTTP_BAD_REQUEST);
    res = gsad_http_create_gsad_message (
      credentials,
      "An internal error occurred inside GSA daemon. "
      "Diagnostics: Unknown command.",
      response_data);
  }

  gvm_connection_close (&connection);
  return gsad_http_create_response (con, res, response_data,
                                    user ? gsad_user_get_cookie (user) : NULL);
}
