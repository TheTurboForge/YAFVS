/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Private TurboVAS control listener.
 */

#include "turbovas_control.h"

#include "gmp_base.h"
#include "manage.h"
#include "manage_alerts.h"
#include "manage_configs.h"
#include "manage_filters.h"
#include "manage_filter_utils.h"
#include "manage_schedules.h"
#include "manage_settings.h"
#include "manage_sql.h"
#include "manage_sql_alerts.h"
#include "manage_sql_users.h"
#include "manage_tags.h"
#include "manage_users.h"

#include <gvm/base/pwpolicy.h>
#include <errno.h>
#include <glib.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "md   control"

#define TURBOVAS_CONTROL_SECRET_ENV "TURBOVAS_GVMD_CONTROL_SECRET"
#define TURBOVAS_CONTROL_SECRET_MIN_BYTES 32
#define TURBOVAS_CONTROL_SECRET_MAX_BYTES 128
#define TURBOVAS_CONTROL_STOP_MAX_REQUEST_BYTES 256
#define TURBOVAS_CONTROL_MAX_REQUEST_BYTES 65536
#define TURBOVAS_CONTROL_MAX_RESPONSE_BYTES 64
#define TURBOVAS_CONTROL_TIMEOUT_SECONDS 5
#define TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND "trash-empty "
#define TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND) - 1)
#define TURBOVAS_CONTROL_TRASH_EMPTY_SNAPSHOT_DIGEST_LENGTH 64
#define TURBOVAS_CONTROL_SCHEDULE_CREATE_COMMAND "schedule-create "
#define TURBOVAS_CONTROL_SCHEDULE_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_SCHEDULE_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND "schedule-modify "
#define TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND) - 1)
#define TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES 4096
#define TURBOVAS_CONTROL_SCHEDULE_COMMENT_MAX_BYTES 4096
#define TURBOVAS_CONTROL_SCHEDULE_TIMEZONE_MAX_BYTES 256
#define TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES 32768
#define TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND "credential-create "
#define TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_CREDENTIAL_NAME_MAX_BYTES 4096
#define TURBOVAS_CONTROL_CREDENTIAL_COMMENT_MAX_BYTES 4096
#define TURBOVAS_CONTROL_CREDENTIAL_LOGIN_MAX_BYTES 4096
#define TURBOVAS_CONTROL_CREDENTIAL_SECRET_MAX_BYTES 4096
#define TURBOVAS_CONTROL_CREDENTIAL_PRIVATE_KEY_MAX_BYTES 32768
#define TURBOVAS_CONTROL_CREDENTIAL_TYPE_UP "up"
#define TURBOVAS_CONTROL_CREDENTIAL_TYPE_USK "usk"
#define TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND "alert-email-create "
#define TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND \
  "alert-start-task-create "
#define TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_ALERT_TEST_COMMAND "alert-test "
#define TURBOVAS_CONTROL_ALERT_TEST_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_ALERT_TEST_COMMAND) - 1)
#define TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND \
  "alert-deliver-report "
#define TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND) - 1)
#define TURBOVAS_CONTROL_ALERT_DELIVERY_FILTER_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_STATUS_MAX_BYTES 32
#define TURBOVAS_CONTROL_ALERT_ADDRESS_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_SUBJECT_MAX_BYTES 80
#define TURBOVAS_CONTROL_ALERT_MESSAGE_MAX_BYTES 2000
#define TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES 36
#define TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND "alert-smb-create "
#define TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND "alert-scp-create "
#define TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND "alert-syslog-create "
#define TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND "alert-snmp-create "
#define TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_ALERT_SMB_PATH_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_SMB_PROTOCOL_MAX_BYTES 4
#define TURBOVAS_CONTROL_ALERT_SCP_PORT_MAX_BYTES 5
#define TURBOVAS_CONTROL_ALERT_SCP_HOST_MAX_BYTES 253
#define TURBOVAS_CONTROL_ALERT_SCP_TEXT_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_SNMP_AGENT_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_SNMP_COMMUNITY_MAX_BYTES 4096
#define TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND \
  "scan-config-nvt-diagnostic "
#define TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND) - 1)
#define TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_MAX_REQUEST_BYTES 512
#define TURBOVAS_CONTROL_NVT_OID_MAX_BYTES 128
#define TURBOVAS_CONTROL_TAG_CREATE_COMMAND "tag-create "
#define TURBOVAS_CONTROL_TAG_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_TAG_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_TAG_MODIFY_COMMAND "tag-modify "
#define TURBOVAS_CONTROL_TAG_MODIFY_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_TAG_MODIFY_COMMAND) - 1)
#define TURBOVAS_CONTROL_TAG_RESOURCE_TYPE_MAX_BYTES 128
#define TURBOVAS_CONTROL_TAG_TEXT_MAX_BYTES 4096
#define TURBOVAS_CONTROL_TAG_RESOURCE_ID_MAX_BYTES 4096
#define TURBOVAS_CONTROL_TAG_RESOURCE_IDS_MAX_BYTES 32768
#define TURBOVAS_CONTROL_TAG_RESOURCE_IDS_MAX 200
#define TURBOVAS_CONTROL_TAG_FILTER_MAX_BYTES 16384
#define TURBOVAS_CONTROL_TASK_CLONE_COMMAND "task-clone "
#define TURBOVAS_CONTROL_TASK_CLONE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_TASK_CLONE_COMMAND) - 1)
#define TURBOVAS_CONTROL_USER_PASSWORD_CHANGE_COMMAND \
  "user-password-change "
#define TURBOVAS_CONTROL_USER_PASSWORD_CHANGE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_USER_PASSWORD_CHANGE_COMMAND) - 1)
#define TURBOVAS_CONTROL_USER_PASSWORD_MAX_BYTES 4096
#define TURBOVAS_CONTROL_USER_CREATE_COMMAND "user-create "
#define TURBOVAS_CONTROL_USER_CREATE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_USER_CREATE_COMMAND) - 1)
#define TURBOVAS_CONTROL_USER_MODIFY_COMMAND "user-modify "
#define TURBOVAS_CONTROL_USER_MODIFY_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_USER_MODIFY_COMMAND) - 1)
#define TURBOVAS_CONTROL_USER_DELETE_COMMAND "user-delete "
#define TURBOVAS_CONTROL_USER_DELETE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_USER_DELETE_COMMAND) - 1)
#define TURBOVAS_CONTROL_USER_CLONE_COMMAND "user-clone "
#define TURBOVAS_CONTROL_USER_CLONE_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_USER_CLONE_COMMAND) - 1)
#define TURBOVAS_CONTROL_USER_NAME_MAX_BYTES 256
#define TURBOVAS_CONTROL_USER_COMMENT_MAX_BYTES 4096
#define TURBOVAS_CONTROL_USER_METHOD_MAX_BYTES 16
#define TURBOVAS_CONTROL_USER_SETTING_MODIFY_COMMAND \
  "user-setting-modify "
#define TURBOVAS_CONTROL_USER_SETTING_MODIFY_COMMAND_LENGTH \
  (sizeof (TURBOVAS_CONTROL_USER_SETTING_MODIFY_COMMAND) - 1)
#define TURBOVAS_CONTROL_USER_SETTING_VALUE_MAX_BYTES 32768

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *timezone;
  gchar *icalendar;
} turbovas_control_schedule_create_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *timezone;
  gchar *icalendar;
} turbovas_control_schedule_modify_request_t;

typedef struct
{
  gchar *credential_type;
  gchar *name;
  gchar *comment;
  gchar *login;
  gchar *secret;
  gchar *private_key;
} turbovas_control_credential_create_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *status;
  gchar *to_address;
  gchar *from_address;
  gchar *subject;
  gchar *recipient_credential_uuid;
  gchar *report_format_uuid;
  gchar *message;
  gboolean active;
  unsigned int notice;
} turbovas_control_alert_email_create_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *status;
  char task_uuid[37];
  gboolean active;
} turbovas_control_alert_start_task_create_request_t;

typedef struct
{
  char alert_uuid[37];
  char report_uuid[37];
  char filter_uuid[37];
  gchar *filter;
} turbovas_control_alert_deliver_report_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *status;
  gchar *credential_uuid;
  gchar *share_path;
  gchar *file_path;
  gchar *report_format_uuid;
  gchar *max_protocol;
  gboolean active;
} turbovas_control_alert_smb_create_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *status;
  gchar *credential_uuid;
  gchar *host;
  gchar *port;
  gchar *known_hosts;
  gchar *path;
  gchar *report_format_uuid;
  gboolean active;
} turbovas_control_alert_scp_create_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *status;
  gboolean active;
} turbovas_control_alert_syslog_create_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *status;
  gchar *agent;
  gchar *community;
  gchar *message;
  gboolean active;
} turbovas_control_alert_snmp_create_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *value;
  gchar *resource_type;
  array_t *resource_ids;
  gchar *resource_filter;
  gboolean active;
} turbovas_control_tag_create_request_t;

typedef struct
{
  gchar *name;
  gchar *comment;
  gchar *value;
  gchar *resource_type;
  array_t *resource_ids;
  gchar *resource_filter;
  gchar *resources_action;
  gchar *active;
} turbovas_control_tag_modify_request_t;

typedef struct
{
  gchar *old_password;
  gchar *new_password;
} turbovas_control_user_password_change_request_t;

typedef struct
{
  char method[TURBOVAS_CONTROL_USER_METHOD_MAX_BYTES];
  gchar *name;
  gchar *comment;
  gchar *password;
} turbovas_control_user_create_request_t;

typedef struct
{
  char target_uuid[37];
  char method[TURBOVAS_CONTROL_USER_METHOD_MAX_BYTES];
  gchar *name;
  gchar *comment;
  gchar *password;
} turbovas_control_user_modify_request_t;

typedef struct
{
  char target_uuid[37];
  char inheritor_uuid[37];
} turbovas_control_user_delete_request_t;

typedef struct
{
  gboolean timezone;
  char setting_uuid[37];
  gchar *value;
} turbovas_control_user_setting_modify_request_t;

static gboolean
turbovas_control_decode_base64_field (const char *, size_t, size_t, gboolean,
                                      gchar **);

static gboolean
turbovas_control_next_field (const char **, const char *, const char **,
                             size_t *);

static gboolean
turbovas_control_parse_authenticated_prefix (
  const char *, size_t, const char *, size_t, const char *, size_t, char[37],
  const char **, const char **);

static gboolean
turbovas_control_text_has_allowed_controls (const gchar *, gsize, gboolean);

static void
turbovas_control_secure_free (gchar *);

static void
turbovas_control_secure_clear (void *, size_t);

static gboolean
turbovas_control_alert_status_is_valid (const char *);

static gboolean
turbovas_control_optional_uuid_is_valid (const char *);

static gboolean
turbovas_control_secret_matches (const char *, size_t, const char *, size_t);

static gboolean
turbovas_control_uuid_is_valid (const char *);

static void
turbovas_control_array_add_data (array_t *, const char *, const char *);

static void
turbovas_control_secure_array_free (array_t *);

static gboolean
turbovas_control_user_method_from_field (const char *, size_t,
                                          char[TURBOVAS_CONTROL_USER_METHOD_MAX_BYTES]);

static gboolean
turbovas_control_user_method_is_valid (const char *);

static gboolean
turbovas_control_decode_user_password_field (const char *, size_t, gchar **);

static gboolean
turbovas_control_decode_user_comment_field (const char *, size_t, gchar **);

static gboolean
turbovas_control_secret_is_valid (const char *secret, size_t secret_len)
{
  size_t i;

  if (secret == NULL || secret_len < TURBOVAS_CONTROL_SECRET_MIN_BYTES
      || secret_len > TURBOVAS_CONTROL_SECRET_MAX_BYTES)
    return FALSE;

  for (i = 0; i < secret_len; i++)
    if (!g_ascii_isalnum (secret[i]) && secret[i] != '-'
        && secret[i] != '_')
      return FALSE;

  return TRUE;
}

static void
turbovas_control_user_setting_modify_request_clear (
  turbovas_control_user_setting_modify_request_t *request)
{
  turbovas_control_secure_clear (request->setting_uuid,
                                 sizeof (request->setting_uuid));
  turbovas_control_secure_free (request->value);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_user_password_change_request_clear (
  turbovas_control_user_password_change_request_t *request)
{
  turbovas_control_secure_free (request->old_password);
  turbovas_control_secure_free (request->new_password);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_user_create_request_clear (
  turbovas_control_user_create_request_t *request)
{
  g_free (request->name);
  g_free (request->comment);
  turbovas_control_secure_free (request->password);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_user_modify_request_clear (
  turbovas_control_user_modify_request_t *request)
{
  turbovas_control_secure_clear (request->target_uuid,
                                 sizeof (request->target_uuid));
  g_free (request->name);
  g_free (request->comment);
  turbovas_control_secure_free (request->password);
  memset (request, 0, sizeof (*request));
}

static gboolean
turbovas_control_user_method_from_field (
  const char *field, size_t field_len,
  char method[TURBOVAS_CONTROL_USER_METHOD_MAX_BYTES])
{
  size_t index;

  if (field_len == 0 || field_len >= TURBOVAS_CONTROL_USER_METHOD_MAX_BYTES)
    return FALSE;
  for (index = 0; index < field_len; index++)
    if (!g_ascii_islower (field[index]) && field[index] != '_')
      return FALSE;

  memcpy (method, field, field_len);
  method[field_len] = '\0';
  return TRUE;
}

static gboolean
turbovas_control_user_method_is_valid (const char *method)
{
  return strcmp (method, "file") == 0
         || strcmp (method, "ldap_connect") == 0
         || strcmp (method, "radius_connect") == 0;
}

static gboolean
turbovas_control_decode_user_comment_field (const char *field,
                                             size_t field_len,
                                             gchar **comment)
{
  if (field_len == 1 && field[0] == '-')
    {
      *comment = g_strdup ("");
      return TRUE;
    }

  return turbovas_control_decode_base64_field (
           field, field_len, TURBOVAS_CONTROL_USER_COMMENT_MAX_BYTES, FALSE,
           comment)
         && turbovas_control_text_has_allowed_controls (
              *comment, strlen (*comment), FALSE);
}

static gboolean
turbovas_control_decode_user_password_field (const char *field,
                                              size_t field_len,
                                              gchar **password)
{
  if (field_len == 1 && field[0] == '-')
    {
      *password = NULL;
      return TRUE;
    }

  return turbovas_control_decode_base64_field (
           field, field_len, TURBOVAS_CONTROL_USER_PASSWORD_MAX_BYTES, FALSE,
           password)
         && turbovas_control_text_has_allowed_controls (
              *password, strlen (*password), FALSE);
}

static gboolean
turbovas_control_parse_user_create_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_user_create_request_t *user_request)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;

  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_USER_CREATE_COMMAND,
        TURBOVAS_CONTROL_USER_CREATE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end))
    return FALSE;

  if (!turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_user_method_from_field (field, field_len,
                                                    user_request->method)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_decode_base64_field (
           field, field_len, TURBOVAS_CONTROL_USER_NAME_MAX_BYTES, TRUE,
           &user_request->name)
      || !turbovas_control_text_has_allowed_controls (
           user_request->name, strlen (user_request->name), FALSE)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_decode_user_comment_field (
           field, field_len, &user_request->comment)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || cursor != end
      || !turbovas_control_decode_user_password_field (
           field, field_len, &user_request->password))
    {
      turbovas_control_user_create_request_clear (user_request);
      return FALSE;
    }

  return TRUE;
}

static gboolean
turbovas_control_parse_user_modify_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_user_modify_request_t *user_request)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;

  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_USER_MODIFY_COMMAND,
        TURBOVAS_CONTROL_USER_MODIFY_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || field_len != 36)
    return FALSE;

  memcpy (user_request->target_uuid, field, field_len);
  user_request->target_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (user_request->target_uuid)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_user_method_from_field (field, field_len,
                                                    user_request->method)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_decode_base64_field (
           field, field_len, TURBOVAS_CONTROL_USER_NAME_MAX_BYTES, TRUE,
           &user_request->name)
      || !turbovas_control_text_has_allowed_controls (
           user_request->name, strlen (user_request->name), FALSE)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_decode_user_comment_field (
           field, field_len, &user_request->comment)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || cursor != end
      || !turbovas_control_decode_user_password_field (
           field, field_len, &user_request->password))
    {
      turbovas_control_user_modify_request_clear (user_request);
      return FALSE;
    }

  return TRUE;
}

static gboolean
turbovas_control_parse_user_delete_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_user_delete_request_t *user_request)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;

  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_USER_DELETE_COMMAND,
        TURBOVAS_CONTROL_USER_DELETE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || field_len != 36)
    return FALSE;

  memcpy (user_request->target_uuid, field, field_len);
  user_request->target_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (user_request->target_uuid)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || cursor != end)
    {
      turbovas_control_secure_clear (user_request, sizeof (*user_request));
      return FALSE;
    }

  if (field_len == 1 && field[0] == '-')
    return TRUE;
  if (field_len != 36)
    {
      turbovas_control_secure_clear (user_request, sizeof (*user_request));
      return FALSE;
    }
  memcpy (user_request->inheritor_uuid, field, field_len);
  user_request->inheritor_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (user_request->inheritor_uuid))
    {
      turbovas_control_secure_clear (user_request, sizeof (*user_request));
      return FALSE;
    }

  return TRUE;
}

static gboolean
turbovas_control_parse_user_clone_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37], char source_uuid[37])
{
  const char *cursor;
  const char *end;

  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_USER_CLONE_COMMAND,
        TURBOVAS_CONTROL_USER_CLONE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end)
      || (size_t) (end - cursor) != 36)
    return FALSE;

  memcpy (source_uuid, cursor, 36);
  source_uuid[36] = '\0';
  return turbovas_control_uuid_is_valid (source_uuid);
}

static gboolean
turbovas_control_parse_user_password_change_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_user_password_change_request_t *password_request)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;

  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_USER_PASSWORD_CHANGE_COMMAND,
        TURBOVAS_CONTROL_USER_PASSWORD_CHANGE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end))
    return FALSE;

  if (!turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_decode_base64_field (
           field, field_len, TURBOVAS_CONTROL_USER_PASSWORD_MAX_BYTES, TRUE,
           &password_request->old_password)
      || !turbovas_control_text_has_allowed_controls (
           password_request->old_password,
           strlen (password_request->old_password), FALSE)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || cursor != end
      || !turbovas_control_decode_base64_field (
           field, field_len, TURBOVAS_CONTROL_USER_PASSWORD_MAX_BYTES, TRUE,
           &password_request->new_password)
      || !turbovas_control_text_has_allowed_controls (
           password_request->new_password,
           strlen (password_request->new_password), FALSE))
    {
      turbovas_control_user_password_change_request_clear (password_request);
      return FALSE;
    }

  return TRUE;
}

static const char *
turbovas_control_user_create_response (
  int result, const char *uuid,
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  if (result == 0 && uuid && turbovas_control_uuid_is_valid (uuid))
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 created %s\n", uuid);
      return response;
    }

  switch (result)
    {
      case 1: return "1 exists\n";
      case 2: return "2 invalid_name\n";
      case 3: return "3 password_rejected\n";
      case 4: return "4 invalid_method\n";
      case 99: return "99 forbidden\n";
      case -3: return "-3 committed_indeterminate\n";
      case -2: return "-2 malformed\n";
      default: return "-1 internal\n";
    }
}

static const char *
turbovas_control_user_modify_response (int result)
{
  switch (result)
    {
      case 0: return "0 modified\n";
      case 1: return "1 not_found\n";
      case 2: return "2 invalid_name\n";
      case 3: return "3 exists\n";
      case 4: return "4 password_rejected\n";
      case 5: return "5 password_required\n";
      case 6: return "6 self_mutation\n";
      case 7: return "7 invalid_method\n";
      case 99: return "99 forbidden\n";
      case -3: return "-3 committed_indeterminate\n";
      case -2: return "-2 malformed\n";
      default: return "-1 internal\n";
    }
}

static const char *
turbovas_control_user_delete_response (int result)
{
  switch (result)
    {
      case 0: return "0 deleted\n";
      case 1: return "1 not_found\n";
      case 2: return "2 current_user\n";
      case 3: return "3 inheritor_not_found\n";
      case 4: return "4 same_inheritor\n";
      case 5: return "5 last_user\n";
      case 99: return "99 forbidden\n";
      case -2: return "-2 malformed\n";
      default: return "-1 internal\n";
    }
}

static const char *
turbovas_control_user_clone_response (
  int result, const char *uuid,
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  if (result == 0 && uuid && turbovas_control_uuid_is_valid (uuid))
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 created %s\n", uuid);
      return response;
    }

  switch (result)
    {
      case 1: return "1 duplicate\n";
      case 2: return "2 not_found\n";
      case 99: return "99 forbidden\n";
      case -3: return "-3 committed_indeterminate\n";
      case -2: return "-2 malformed\n";
      default: return "-1 internal\n";
    }
}

static gboolean
turbovas_control_parse_user_setting_modify_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_user_setting_modify_request_t *setting_request)
{
  const char *cursor;
  const char *end;
  const char *kind;
  const char *identifier;
  const char *identifier_end;
  const char *value;
  size_t kind_len;
  size_t identifier_len;
  size_t value_len;
  gboolean timezone;

  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_USER_SETTING_MODIFY_COMMAND,
        TURBOVAS_CONTROL_USER_SETTING_MODIFY_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end)
      || !turbovas_control_next_field (&cursor, end, &kind, &kind_len)
      || cursor > end)
    return FALSE;

  identifier = cursor;
  identifier_end = memchr (identifier, ' ', (size_t) (end - identifier));
  if (identifier_end == NULL)
    return FALSE;
  identifier_len = (size_t) (identifier_end - identifier);
  value = identifier_end + 1;
  value_len = (size_t) (end - value);
  if (memchr (value, ' ', value_len) != NULL)
    return FALSE;

  timezone = kind_len == strlen ("timezone")
             && memcmp (kind, "timezone", kind_len) == 0;
  if (timezone)
    {
      if (identifier_len != 1 || identifier[0] != '-')
        return FALSE;
    }
  else
    {
      if (kind_len != strlen ("id") || memcmp (kind, "id", kind_len) != 0
          || identifier_len != 36)
        return FALSE;
      memcpy (setting_request->setting_uuid, identifier, identifier_len);
      setting_request->setting_uuid[identifier_len] = '\0';
      if (!turbovas_control_uuid_is_valid (setting_request->setting_uuid))
        {
          turbovas_control_user_setting_modify_request_clear (setting_request);
          return FALSE;
        }
    }

  if (!turbovas_control_decode_base64_field (
        value, value_len, TURBOVAS_CONTROL_USER_SETTING_VALUE_MAX_BYTES, FALSE,
        &setting_request->value))
    {
      turbovas_control_user_setting_modify_request_clear (setting_request);
      return FALSE;
    }

  setting_request->timezone = timezone;
  return TRUE;
}

static gboolean
turbovas_control_text_has_allowed_controls (const gchar *text, gsize text_len,
                                             gboolean icalendar)
{
  const gchar *cursor = text;
  const gchar *end = text + text_len;

  while (cursor < end)
    {
      gunichar character = g_utf8_get_char_validated (cursor, end - cursor);

      if (character == (gunichar) -1 || character == (gunichar) -2)
        return FALSE;
      if (g_unichar_iscntrl (character)
          && (!icalendar || (character != '\r' && character != '\n'
                              && character != '\t')))
        return FALSE;
      cursor = g_utf8_next_char (cursor);
    }

  return TRUE;
}

static const char *
turbovas_control_user_setting_modify_response (int result)
{
  switch (result)
    {
      case MODIFY_SETTING_RESULT_OK:
        return "0 modified\n";
      case MODIFY_SETTING_RESULT_NOT_FOUND:
        return "1 not_found\n";
      case MODIFY_SETTING_RESULT_SYNTAX_ERROR:
        return "2 invalid_value\n";
      case MODIFY_SETTING_RESULT_FEATURE_DISABLED:
        return "3 feature_disabled\n";
      case MODIFY_SETTING_RESULT_PERMISSION_DENIED:
        return "99 forbidden\n";
      case -2:
        return "-2 malformed\n";
      default:
        return "-1 internal\n";
    }
}

static const char *
turbovas_control_user_password_change_response (int result)
{
  switch (result)
    {
      case 0:
        return "0 changed\n";
      case 1:
        return "1 old_password_invalid\n";
      case 2:
        return "2 unsupported_auth_method\n";
      case 3:
        return "3 new_password_rejected\n";
      case 99:
        return "99 forbidden\n";
      case -2:
        return "-2 malformed\n";
      default:
        return "-1 internal\n";
    }
}

static gboolean
turbovas_control_decode_schedule_modify_field (const char *value,
                                                size_t value_len,
                                                size_t max_decoded_len,
                                                gboolean icalendar,
                                                gchar **decoded_out)
{
  if (value_len == 1 && value[0] == '-')
    {
      *decoded_out = NULL;
      return TRUE;
    }
  if (value_len == 0 || value[0] != '+'
      || !turbovas_control_decode_base64_field (
           value + 1, value_len - 1, max_decoded_len, FALSE, decoded_out))
    return FALSE;

  if (!turbovas_control_text_has_allowed_controls (*decoded_out,
                                                   strlen (*decoded_out),
                                                   icalendar))
    {
      g_free (*decoded_out);
      *decoded_out = NULL;
      return FALSE;
    }

  return TRUE;
}

static gboolean
turbovas_control_parse_authenticated_prefix (
  const char *request, size_t request_len, const char *command,
  size_t command_len, const char *expected_secret, size_t expected_secret_len,
  char operator_uuid[37], const char **cursor_out, const char **end_out)
{
  const char *end;
  const char *operator_start;
  const char *secret;
  const char *secret_end;
  size_t secret_len;

  if (request == NULL || request_len >= TURBOVAS_CONTROL_MAX_REQUEST_BYTES
      || request_len < command_len + TURBOVAS_CONTROL_SECRET_MIN_BYTES + 1
                           + 37
      || memcmp (request, command, command_len)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                             expected_secret_len))
    return FALSE;

  end = request + request_len - 1;
  secret = request + command_len;
  secret_end = memchr (secret, ' ', (size_t) (end - secret));
  if (secret_end == NULL)
    return FALSE;
  secret_len = (size_t) (secret_end - secret);
  if (!turbovas_control_secret_is_valid (secret, secret_len)
      || !turbovas_control_secret_matches (secret, secret_len,
                                            expected_secret,
                                            expected_secret_len))
    return FALSE;

  operator_start = secret_end + 1;
  if ((size_t) (end - operator_start) < 37 || operator_start[36] != ' ')
    return FALSE;
  memcpy (operator_uuid, operator_start, 36);
  operator_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (operator_uuid))
    return FALSE;

  *cursor_out = operator_start + 37;
  *end_out = end;
  return TRUE;
}

static gboolean
turbovas_control_decode_tag_text_field (const char *value, size_t value_len,
                                         size_t max_decoded_len,
                                         gboolean required,
                                         gchar **decoded_out)
{
  return turbovas_control_decode_base64_field (
           value, value_len, max_decoded_len, required, decoded_out)
         && turbovas_control_text_has_allowed_controls (
              *decoded_out, strlen (*decoded_out), FALSE);
}

static gboolean
turbovas_control_tag_resource_ids_from_field (const char *value,
                                               size_t value_len,
                                               array_t **resource_ids_out)
{
  array_t *resource_ids;
  gchar *decoded = NULL;
  gchar **parts = NULL;
  guint count = 0;
  gboolean valid = FALSE;

  if (!turbovas_control_decode_base64_field (
        value, value_len, TURBOVAS_CONTROL_TAG_RESOURCE_IDS_MAX_BYTES, FALSE,
        &decoded))
    return FALSE;

  resource_ids = make_array ();
  if (decoded[0] == '\0')
    {
      array_terminate (resource_ids);
      *resource_ids_out = resource_ids;
      g_free (decoded);
      return TRUE;
    }

  parts = g_strsplit (decoded, "\n", -1);
  for (guint index = 0; parts[index]; index++)
    {
      size_t length = strlen (parts[index]);
      if (length == 0 || length > TURBOVAS_CONTROL_TAG_RESOURCE_ID_MAX_BYTES
          || ++count > TURBOVAS_CONTROL_TAG_RESOURCE_IDS_MAX
          || !g_utf8_validate (parts[index], -1, NULL)
          || !turbovas_control_text_has_allowed_controls (
               parts[index], length, FALSE))
        goto cleanup;
      array_add (resource_ids, g_strdup (parts[index]));
    }
  array_terminate (resource_ids);
  *resource_ids_out = resource_ids;
  resource_ids = NULL;
  valid = TRUE;

cleanup:
  array_free (resource_ids);
  g_strfreev (parts);
  g_free (decoded);
  return valid;
}

static void
turbovas_control_tag_create_request_clear (
  turbovas_control_tag_create_request_t *request)
{
  g_free (request->name);
  g_free (request->comment);
  g_free (request->value);
  g_free (request->resource_type);
  array_free (request->resource_ids);
  g_free (request->resource_filter);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_alert_scp_create_request_clear (
  turbovas_control_alert_scp_create_request_t *request)
{
  turbovas_control_secure_free (request->name);
  turbovas_control_secure_free (request->comment);
  turbovas_control_secure_free (request->status);
  turbovas_control_secure_free (request->credential_uuid);
  turbovas_control_secure_free (request->host);
  turbovas_control_secure_free (request->port);
  turbovas_control_secure_free (request->known_hosts);
  turbovas_control_secure_free (request->path);
  turbovas_control_secure_free (request->report_format_uuid);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_alert_syslog_create_request_clear (
  turbovas_control_alert_syslog_create_request_t *request)
{
  g_free (request->name);
  g_free (request->comment);
  g_free (request->status);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_alert_snmp_create_request_clear (
  turbovas_control_alert_snmp_create_request_t *request)
{
  turbovas_control_secure_free (request->name);
  turbovas_control_secure_free (request->comment);
  turbovas_control_secure_free (request->status);
  turbovas_control_secure_free (request->agent);
  turbovas_control_secure_free (request->community);
  turbovas_control_secure_free (request->message);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_tag_modify_request_clear (
  turbovas_control_tag_modify_request_t *request)
{
  g_free (request->name);
  g_free (request->comment);
  g_free (request->value);
  g_free (request->resource_type);
  array_free (request->resource_ids);
  g_free (request->resource_filter);
  g_free (request->resources_action);
  g_free (request->active);
  memset (request, 0, sizeof (*request));
}

static gboolean
turbovas_control_secret_matches (const char *candidate,
                                  size_t candidate_len,
                                  const char *expected,
                                  size_t expected_len)
{
  volatile unsigned char difference;
  size_t i;

  if (candidate_len > TURBOVAS_CONTROL_SECRET_MAX_BYTES
      || expected_len > TURBOVAS_CONTROL_SECRET_MAX_BYTES)
    return FALSE;

  difference = (unsigned char) (candidate_len ^ expected_len);
  for (i = 0; i < TURBOVAS_CONTROL_SECRET_MAX_BYTES; i++)
    {
      unsigned char candidate_byte =
        i < candidate_len ? (unsigned char) candidate[i] : 0;
      unsigned char expected_byte =
        i < expected_len ? (unsigned char) expected[i] : 0;

      difference |= candidate_byte ^ expected_byte;
    }

  return difference == 0;
}

static gboolean
turbovas_control_configured_secret (const char **secret, size_t *secret_len)
{
  const char *configured = g_getenv (TURBOVAS_CONTROL_SECRET_ENV);
  size_t configured_len;

  if (configured == NULL)
    return FALSE;

  configured_len = strnlen (configured,
                            TURBOVAS_CONTROL_SECRET_MAX_BYTES + 1);
  if (!turbovas_control_secret_is_valid (configured, configured_len))
    return FALSE;

  *secret = configured;
  *secret_len = configured_len;
  return TRUE;
}

static gboolean
turbovas_control_uuid_is_valid (const char *uuid)
{
  size_t i;

  if (strlen (uuid) != 36)
    return FALSE;

  for (i = 0; i < 36; i++)
    {
      if (i == 8 || i == 13 || i == 18 || i == 23)
        {
          if (uuid[i] != '-')
            return FALSE;
        }
      else if (!g_ascii_isxdigit (uuid[i]))
        return FALSE;
    }

  return TRUE;
}

static gboolean
turbovas_control_nvt_oid_is_valid (const char *oid, size_t oid_len)
{
  size_t index;
  gboolean previous_was_dot = TRUE;

  if (oid == NULL || oid_len == 0
      || oid_len > TURBOVAS_CONTROL_NVT_OID_MAX_BYTES)
    return FALSE;

  for (index = 0; index < oid_len; index++)
    {
      if (oid[index] == '.')
        {
          if (previous_was_dot)
            return FALSE;
          previous_was_dot = TRUE;
        }
      else if (g_ascii_isdigit (oid[index]))
        previous_was_dot = FALSE;
      else
        return FALSE;
    }

  return !previous_was_dot;
}

static gboolean
turbovas_control_parse_scan_config_nvt_diagnostic_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37], char config_uuid[37],
  char nvt_oid[TURBOVAS_CONTROL_NVT_OID_MAX_BYTES + 1])
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;

  if (request == NULL
      || request_len
           > TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_MAX_REQUEST_BYTES
      || request_len
           < TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND_LENGTH
               + TURBOVAS_CONTROL_SECRET_MIN_BYTES + 1 + 36 + 1 + 36 + 1
               + 1 + 1
      || memcmp (request, TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND,
                 TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND_LENGTH)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                            expected_secret_len))
    return FALSE;

  cursor =
    request + TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND_LENGTH;
  end = request + request_len - 1;
  if (!turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_secret_is_valid (field, field_len)
      || !turbovas_control_secret_matches (
           field, field_len, expected_secret, expected_secret_len))
    return FALSE;
  if (!turbovas_control_next_field (&cursor, end, &field, &field_len)
      || field_len != 36)
    return FALSE;
  memcpy (operator_uuid, field, field_len);
  operator_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (operator_uuid))
    return FALSE;
  if (!turbovas_control_next_field (&cursor, end, &field, &field_len)
      || field_len != 36)
    return FALSE;
  memcpy (config_uuid, field, field_len);
  config_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (config_uuid))
    return FALSE;
  if (!turbovas_control_next_field (&cursor, end, &field, &field_len)
      || cursor != end || !turbovas_control_nvt_oid_is_valid (field, field_len))
    return FALSE;
  memcpy (nvt_oid, field, field_len);
  nvt_oid[field_len] = '\0';

  return TRUE;
}

static gboolean
turbovas_control_parse_request (const char *request, size_t request_len,
                                const char *expected_secret,
                                size_t expected_secret_len,
                                char operator_uuid[37], char task_uuid[37])
{
  const char *secret;
  const char *secret_end;
  const char *operator_start;
  const char *task_start;
  size_t secret_len;

  if (request_len > TURBOVAS_CONTROL_STOP_MAX_REQUEST_BYTES
      || request_len < 80 + TURBOVAS_CONTROL_SECRET_MIN_BYTES
      || memcmp (request, "stop ", 5)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                            expected_secret_len))
    return FALSE;

  secret = request + 5;
  secret_end = memchr (secret, ' ', request_len - 6);
  if (secret_end == NULL)
    return FALSE;
  secret_len = (size_t) (secret_end - secret);
  if (!turbovas_control_secret_is_valid (secret, secret_len)
      || !turbovas_control_secret_matches (secret, secret_len,
                                           expected_secret,
                                           expected_secret_len))
    return FALSE;

  operator_start = secret_end + 1;
  if ((size_t) ((request + request_len) - operator_start) != 74
      || operator_start[36] != ' ')
    return FALSE;
  task_start = operator_start + 37;

  memcpy (operator_uuid, operator_start, 36);
  operator_uuid[36] = '\0';
  memcpy (task_uuid, task_start, 36);
  task_uuid[36] = '\0';

  return turbovas_control_uuid_is_valid (operator_uuid)
         && turbovas_control_uuid_is_valid (task_uuid);
}

static gboolean
turbovas_control_parse_nonnegative_int64 (const char *value, size_t value_len,
                                          gint64 *parsed)
{
  guint64 total = 0;
  size_t index;

  if (value == NULL || value_len == 0 || parsed == NULL)
    return FALSE;

  for (index = 0; index < value_len; index++)
    {
      guint64 digit;

      if (!g_ascii_isdigit (value[index]))
        return FALSE;
      digit = (guint64) (value[index] - '0');
      if (total > ((guint64) G_MAXINT64 - digit) / 10)
        return FALSE;
      total = total * 10 + digit;
    }

  *parsed = (gint64) total;
  return TRUE;
}

static gboolean
turbovas_control_snapshot_digest_is_valid (const char *value, size_t value_len)
{
  size_t index;

  if (value == NULL
      || value_len != TURBOVAS_CONTROL_TRASH_EMPTY_SNAPSHOT_DIGEST_LENGTH)
    return FALSE;
  for (index = 0; index < value_len; index++)
    if (!g_ascii_isdigit (value[index])
        && (value[index] < 'a' || value[index] > 'f'))
      return FALSE;
  return TRUE;
}

static gboolean
turbovas_control_parse_trash_empty_request
  (const char *request, size_t request_len, const char *expected_secret,
   size_t expected_secret_len, char operator_uuid[37], gint64 *expected_total,
   char expected_snapshot_digest[65])
{
  const char *end;
  const char *operator_start;
  const char *secret;
  const char *secret_end;
  const char *total_end;
  const char *total_start;
  size_t secret_len;

  if (request == NULL || expected_total == NULL
      || expected_snapshot_digest == NULL
      || request_len > TURBOVAS_CONTROL_STOP_MAX_REQUEST_BYTES
      || request_len
           < TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND_LENGTH
               + TURBOVAS_CONTROL_SECRET_MIN_BYTES + 1 + 36 + 1 + 1 + 1
               + TURBOVAS_CONTROL_TRASH_EMPTY_SNAPSHOT_DIGEST_LENGTH + 1
      || memcmp (request, TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND,
                 TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND_LENGTH)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                            expected_secret_len))
    return FALSE;

  end = request + request_len - 1;
  secret = request + TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND_LENGTH;
  secret_end = memchr (secret, ' ', (size_t) (end - secret));
  if (secret_end == NULL)
    return FALSE;
  secret_len = (size_t) (secret_end - secret);
  if (!turbovas_control_secret_is_valid (secret, secret_len)
      || !turbovas_control_secret_matches (secret, secret_len,
                                           expected_secret,
                                           expected_secret_len))
    return FALSE;

  operator_start = secret_end + 1;
  if (operator_start + 37 >= end || operator_start[36] != ' ')
    return FALSE;
  memcpy (operator_uuid, operator_start, 36);
  operator_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (operator_uuid))
    return FALSE;

  total_start = operator_start + 37;
  total_end = memchr (total_start, ' ', (size_t) (end - total_start));
  if (total_end == NULL
      || !turbovas_control_parse_nonnegative_int64 (
        total_start, (size_t) (total_end - total_start), expected_total)
      || !turbovas_control_snapshot_digest_is_valid (
        total_end + 1, (size_t) (end - (total_end + 1))))
    return FALSE;
  memcpy (expected_snapshot_digest, total_end + 1,
          TURBOVAS_CONTROL_TRASH_EMPTY_SNAPSHOT_DIGEST_LENGTH);
  expected_snapshot_digest[
    TURBOVAS_CONTROL_TRASH_EMPTY_SNAPSHOT_DIGEST_LENGTH] = '\0';
  return TRUE;
}

static void
turbovas_control_schedule_create_request_clear
  (turbovas_control_schedule_create_request_t *request)
{
  g_free (request->name);
  g_free (request->comment);
  g_free (request->timezone);
  g_free (request->icalendar);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_alert_smb_create_request_clear (
  turbovas_control_alert_smb_create_request_t *request)
{
  turbovas_control_secure_free (request->name);
  turbovas_control_secure_free (request->comment);
  turbovas_control_secure_free (request->status);
  turbovas_control_secure_free (request->credential_uuid);
  turbovas_control_secure_free (request->share_path);
  turbovas_control_secure_free (request->file_path);
  turbovas_control_secure_free (request->report_format_uuid);
  turbovas_control_secure_free (request->max_protocol);
  memset (request, 0, sizeof (*request));
}

static const char *
turbovas_control_trash_empty_response
  (int result, gint64 actual,
   char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  if (result == 0)
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 emptied %" G_GINT64_FORMAT "\n", actual);
      return response;
    }
  if (result == 1)
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "1 expected-snapshot-mismatch %" G_GINT64_FORMAT "\n",
                  actual);
      return response;
    }

  switch (result)
    {
      case 2:
        status = "2 forbidden\n";
        break;
      case 3:
        status = "3 operator-not-found\n";
        break;
      default:
        status = "-1 error\n";
        break;
    }

  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static const char *
turbovas_control_tag_create_response (
  int result, const char *created_uuid,
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  if (result == 0 && created_uuid
      && turbovas_control_uuid_is_valid (created_uuid))
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 created %s\n", created_uuid);
      return response;
    }

  switch (result)
    {
      case 1:
        status = "1 resource_not_found\n";
        break;
      case 2:
        status = "2 no_resources\n";
        break;
      case 3:
        status = "3 too_many_resources\n";
        break;
      case 99:
        status = "99 forbidden\n";
        break;
      case -2:
        status = "-2 malformed\n";
        break;
      case -3:
        status = "-3 committed_indeterminate\n";
        break;
      default:
        status = "-1 internal\n";
        break;
    }
  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static const char *
turbovas_control_tag_modify_response (
  int result, char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  switch (result)
    {
      case 0:
        status = "0 modified\n";
        break;
      case 1:
        status = "1 tag_not_found\n";
        break;
      case 3:
        status = "3 invalid_action\n";
        break;
      case 4:
        status = "4 resource_not_found\n";
        break;
      case 5:
        status = "5 no_resources\n";
        break;
      case 6:
        status = "6 too_many_resources\n";
        break;
      case 99:
        status = "99 forbidden\n";
        break;
      case -2:
        status = "-2 malformed\n";
        break;
      default:
        status = "-1 internal\n";
        break;
    }
  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static void
turbovas_control_log_trash_empty_audit (const char *operator_uuid,
                                         gint64 expected_total,
                                         gint64 actual_total, int result)
{
  const char *message;
  const char *outcome;

  if (result == 0)
    {
      log_event ("trashcan", "Trashcan", NULL, "emptied");
      message = "Trashcan emptied";
      outcome = "emptied";
    }
  else if (result == 1)
    {
      message = "Trashcan empty request rejected";
      outcome = "expected-snapshot-mismatch";
    }
  else if (result != 3)
    {
      log_event_fail ("trashcan", "Trashcan", NULL, "emptied");
      message = "Trashcan empty request failed";
      outcome = result == 2 ? "forbidden" : "error";
    }
  else
    return;

  g_log_structured (G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "MESSAGE", "%s",
                    message, "TURBOVAS_AUDIT_ACTION", "%s", "trash-empty",
                    "TURBOVAS_OPERATOR_UUID", "%s", operator_uuid,
                    "TURBOVAS_OUTCOME", "%s", outcome,
                    "TURBOVAS_EXPECTED_TOTAL", "%" G_GINT64_FORMAT,
                    expected_total, "TURBOVAS_ACTUAL_TOTAL", "%" G_GINT64_FORMAT,
                    actual_total, NULL);
}

static void
turbovas_control_alert_email_create_request_clear
  (turbovas_control_alert_email_create_request_t *request)
{
  g_free (request->name);
  g_free (request->comment);
  g_free (request->status);
  turbovas_control_secure_free (request->to_address);
  turbovas_control_secure_free (request->from_address);
  turbovas_control_secure_free (request->subject);
  turbovas_control_secure_free (request->recipient_credential_uuid);
  turbovas_control_secure_free (request->report_format_uuid);
  turbovas_control_secure_free (request->message);
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_alert_start_task_create_request_clear (
  turbovas_control_alert_start_task_create_request_t *request)
{
  g_free (request->name);
  g_free (request->comment);
  g_free (request->status);
  turbovas_control_secure_clear (request->task_uuid,
                                 sizeof (request->task_uuid));
  memset (request, 0, sizeof (*request));
}

static void
turbovas_control_secure_clear (void *value, size_t length)
{
  volatile unsigned char *cursor = value;

  if (value == NULL)
    return;

  while (length--)
    *cursor++ = 0;
}

static void
turbovas_control_secure_free (gchar *value)
{
  if (value == NULL)
    return;

  turbovas_control_secure_clear (value, strlen (value));
  g_free (value);
}

static void
turbovas_control_credential_create_request_clear
  (turbovas_control_credential_create_request_t *request)
{
  g_free (request->credential_type);
  g_free (request->name);
  g_free (request->comment);
  g_free (request->login);
  turbovas_control_secure_free (request->secret);
  turbovas_control_secure_free (request->private_key);
  memset (request, 0, sizeof (*request));
}

static gboolean
turbovas_control_decode_base64_field (const char *value, size_t value_len,
                                      size_t max_decoded_len,
                                      gboolean required, gchar **decoded_out)
{
  gchar *canonical;
  gchar *encoded;
  guchar *decoded;
  gsize decoded_len;
  size_t encoded_len;
  gboolean valid;

  encoded_len = value_len;
  if (encoded_len == 0)
    {
      if (required)
        return FALSE;
      *decoded_out = g_strdup ("");
      return TRUE;
    }
  if (encoded_len % 4)
    return FALSE;

  encoded = g_strndup (value, encoded_len);
  decoded = g_base64_decode (encoded, &decoded_len);
  canonical = decoded ? g_base64_encode (decoded, decoded_len) : NULL;
  valid = canonical != NULL && strlen (canonical) == encoded_len
          && memcmp (canonical, encoded, encoded_len) == 0
          && decoded_len <= max_decoded_len
          && (!required || decoded_len > 0)
          && memchr (decoded, '\0', decoded_len) == NULL
          && g_utf8_validate ((const gchar *) decoded, decoded_len, NULL);
  if (valid)
    *decoded_out = g_strndup ((const gchar *) decoded, decoded_len);

  if (canonical)
    turbovas_control_secure_clear (canonical, strlen (canonical));
  turbovas_control_secure_clear (decoded, decoded_len);
  turbovas_control_secure_clear (encoded, encoded_len);
  g_free (canonical);
  g_free (decoded);
  g_free (encoded);
  return valid;
}

static gboolean
turbovas_control_smb_max_protocol_is_valid (const char *max_protocol)
{
  return max_protocol[0] == '\0' || strcmp (max_protocol, "NT1") == 0
         || strcmp (max_protocol, "SMB2") == 0
         || strcmp (max_protocol, "SMB3") == 0;
}

static gboolean
turbovas_control_parse_alert_smb_create_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_alert_smb_create_request_t *alert)
{
  const char *cursor;
  const char *end;
  const char *field;
  const char *operator_start;
  const char *secret;
  const char *secret_end;
  size_t field_len;
  size_t secret_len;
  gboolean valid;

  memset (alert, 0, sizeof (*alert));
  if (request == NULL || request_len >= TURBOVAS_CONTROL_MAX_REQUEST_BYTES
      || request_len < TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND_LENGTH
                         + TURBOVAS_CONTROL_SECRET_MIN_BYTES + 1 + 37 + 1
      || memcmp (request, TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND,
                 TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND_LENGTH)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                            expected_secret_len))
    return FALSE;

  end = request + request_len - 1;
  secret = request + TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND_LENGTH;
  secret_end = memchr (secret, ' ', (size_t) (end - secret));
  if (secret_end == NULL)
    return FALSE;
  secret_len = (size_t) (secret_end - secret);
  if (!turbovas_control_secret_is_valid (secret, secret_len)
      || !turbovas_control_secret_matches (secret, secret_len, expected_secret,
                                           expected_secret_len))
    return FALSE;

  operator_start = secret_end + 1;
  if ((size_t) (end - operator_start) < 37 || operator_start[36] != ' ')
    return FALSE;
  memcpy (operator_uuid, operator_start, 36);
  operator_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (operator_uuid))
    return FALSE;

  cursor = operator_start + 37;
  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 1 && (field[0] == '0' || field[0] == '1');
  if (!valid)
    return FALSE;
  alert->active = field[0] == '1';

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES, TRUE,
            &alert->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES, FALSE,
            &alert->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_STATUS_MAX_BYTES, TRUE,
            &alert->status)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES, TRUE,
            &alert->credential_uuid)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SMB_PATH_MAX_BYTES, TRUE,
            &alert->share_path)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SMB_PATH_MAX_BYTES, TRUE,
            &alert->file_path)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES, TRUE,
            &alert->report_format_uuid)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SMB_PROTOCOL_MAX_BYTES,
            FALSE, &alert->max_protocol)
          && cursor == end;
  if (valid)
    valid =
      turbovas_control_alert_status_is_valid (alert->status)
      && turbovas_control_uuid_is_valid (alert->credential_uuid)
      && turbovas_control_uuid_is_valid (alert->report_format_uuid)
      && turbovas_control_smb_max_protocol_is_valid (alert->max_protocol)
      && turbovas_control_text_has_allowed_controls (
        alert->name, strlen (alert->name), FALSE)
      && turbovas_control_text_has_allowed_controls (
        alert->comment, strlen (alert->comment), FALSE)
      && turbovas_control_text_has_allowed_controls (
        alert->share_path, strlen (alert->share_path), FALSE)
      && turbovas_control_text_has_allowed_controls (
        alert->file_path, strlen (alert->file_path), FALSE);
  if (!valid)
    turbovas_control_alert_smb_create_request_clear (alert);

  return valid;
}

static gboolean
turbovas_control_parse_alert_start_task_create_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_alert_start_task_create_request_t *alert)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;
  gboolean valid;

  memset (alert, 0, sizeof (*alert));
  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND,
        TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND_LENGTH,
        expected_secret, expected_secret_len, operator_uuid, &cursor, &end))
    return FALSE;

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 1 && (field[0] == '0' || field[0] == '1');
  if (!valid)
    return FALSE;
  alert->active = field[0] == '1';

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES, TRUE,
            &alert->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES, FALSE,
            &alert->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_STATUS_MAX_BYTES, TRUE,
            &alert->status)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 36 && cursor == end;
  if (valid)
    {
      memcpy (alert->task_uuid, field, 36);
      alert->task_uuid[36] = '\0';
      valid = turbovas_control_alert_status_is_valid (alert->status)
              && turbovas_control_uuid_is_valid (alert->task_uuid)
              && turbovas_control_text_has_allowed_controls (
                alert->name, strlen (alert->name), FALSE)
              && turbovas_control_text_has_allowed_controls (
                alert->comment, strlen (alert->comment), FALSE);
    }
  if (!valid)
    turbovas_control_alert_start_task_create_request_clear (alert);

  return valid;
}

static gboolean
turbovas_control_parse_alert_test_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37], char alert_uuid[37])
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;

  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_ALERT_TEST_COMMAND,
        TURBOVAS_CONTROL_ALERT_TEST_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || field_len != 36 || cursor != end)
    return FALSE;

  memcpy (alert_uuid, field, 36);
  alert_uuid[36] = '\0';
  return turbovas_control_uuid_is_valid (alert_uuid);
}

static void
turbovas_control_alert_deliver_report_request_clear (
  turbovas_control_alert_deliver_report_request_t *request)
{
  turbovas_control_secure_free (request->filter);
  turbovas_control_secure_clear (request, sizeof (*request));
}

static gboolean
turbovas_control_parse_alert_deliver_report_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_alert_deliver_report_request_t *delivery)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;
  gboolean valid;

  memset (delivery, 0, sizeof (*delivery));
  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND,
        TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end)
      || !turbovas_control_next_field (&cursor, end, &field, &field_len)
      || field_len != 36)
    return FALSE;
  memcpy (delivery->alert_uuid, field, 36);
  delivery->alert_uuid[36] = '\0';

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 36;
  if (valid)
    {
      memcpy (delivery->report_uuid, field, 36);
      delivery->report_uuid[36] = '\0';
    }
  valid = valid
          && turbovas_control_next_field (&cursor, end, &field, &field_len);
  if (valid && field_len == 1 && field[0] == '-')
    delivery->filter = g_strdup ("");
  else if (valid)
    valid = turbovas_control_decode_base64_field (
      field, field_len, TURBOVAS_CONTROL_ALERT_DELIVERY_FILTER_MAX_BYTES,
      TRUE, &delivery->filter);

  valid = valid
          && turbovas_control_next_field (&cursor, end, &field, &field_len);
  if (valid && field_len == 1 && field[0] == '-')
    delivery->filter_uuid[0] = '\0';
  else if (valid && field_len == 36)
    {
      memcpy (delivery->filter_uuid, field, 36);
      delivery->filter_uuid[36] = '\0';
    }
  else
    valid = FALSE;

  valid = valid && cursor == end
          && turbovas_control_uuid_is_valid (delivery->alert_uuid)
          && turbovas_control_uuid_is_valid (delivery->report_uuid)
          && (delivery->filter_uuid[0] == '\0'
              || turbovas_control_uuid_is_valid (delivery->filter_uuid))
          && (delivery->filter[0] == '\0'
              || delivery->filter_uuid[0] == '\0')
          && turbovas_control_text_has_allowed_controls (
            delivery->filter, strlen (delivery->filter), FALSE);
  if (!valid)
    turbovas_control_alert_deliver_report_request_clear (delivery);
  return valid;
}

static gboolean
turbovas_control_alert_status_is_valid (const char *status)
{
  static const char *allowed[] = {
    "Delete Requested",
    "Ultimate Delete Requested",
    "Ultimate Delete Waiting",
    "Delete Waiting",
    "Done",
    "New",
    "Requested",
    "Running",
    "Queued",
    "Stop Requested",
    "Stop Waiting",
    "Stopped",
    "Processing",
    "Interrupted",
    NULL,
  };
  size_t index;

  for (index = 0; allowed[index]; index++)
    if (strcmp (status, allowed[index]) == 0)
      return TRUE;

  return FALSE;
}

static const char *
turbovas_control_alert_deliver_report_response (int result)
{
  switch (result)
    {
      case 0: return "0 delivered\n";
      case 1: return "1 alert_not_found\n";
      case 2: return "2 report_not_found\n";
      case 3: return "3 filter_not_found\n";
      case 99: return "99 forbidden\n";
      case -2: return "-2 report_format_not_found\n";
      case -3: return "-3 delivery_failed\n";
      default: return "-1 internal\n";
    }
}

static gboolean
turbovas_control_alert_scp_port_is_valid (const char *port)
{
  unsigned long value;
  char *end = NULL;

  if (port == NULL || port[0] == '\0')
    return FALSE;
  if (strspn (port, "0123456789") != strlen (port))
    return FALSE;
  errno = 0;
  value = strtoul (port, &end, 10);
  return errno == 0 && end != port && *end == '\0' && value > 0
         && value <= 65535;
}

static gboolean
turbovas_control_parse_alert_scp_create_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_alert_scp_create_request_t *alert)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;
  gboolean valid;

  memset (alert, 0, sizeof (*alert));
  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND,
        TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end))
    return FALSE;

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 1 && (field[0] == '0' || field[0] == '1');
  if (!valid)
    return FALSE;
  alert->active = field[0] == '1';

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES, TRUE,
            &alert->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES, FALSE,
            &alert->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_STATUS_MAX_BYTES, TRUE,
            &alert->status)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES, TRUE,
            &alert->credential_uuid)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SCP_HOST_MAX_BYTES, TRUE,
            &alert->host)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SCP_PORT_MAX_BYTES, TRUE,
            &alert->port)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SCP_TEXT_MAX_BYTES, TRUE,
            &alert->known_hosts)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SCP_TEXT_MAX_BYTES, TRUE,
            &alert->path)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES, TRUE,
            &alert->report_format_uuid)
          && cursor == end
          && turbovas_control_alert_status_is_valid (alert->status)
          && turbovas_control_uuid_is_valid (alert->credential_uuid)
          && turbovas_control_uuid_is_valid (alert->report_format_uuid)
          && turbovas_control_alert_scp_port_is_valid (alert->port)
          && turbovas_control_text_has_allowed_controls (
            alert->name, strlen (alert->name), FALSE)
          && turbovas_control_text_has_allowed_controls (
            alert->comment, strlen (alert->comment), FALSE)
          && turbovas_control_text_has_allowed_controls (
            alert->host, strlen (alert->host), FALSE)
          && turbovas_control_text_has_allowed_controls (
            alert->known_hosts, strlen (alert->known_hosts), TRUE)
          && turbovas_control_text_has_allowed_controls (
            alert->path, strlen (alert->path), FALSE);
  if (!valid)
    turbovas_control_alert_scp_create_request_clear (alert);

  return valid;
}

static gboolean
turbovas_control_parse_alert_syslog_create_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_alert_syslog_create_request_t *alert)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;
  gboolean valid;

  memset (alert, 0, sizeof (*alert));
  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND,
        TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end))
    return FALSE;

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 1 && (field[0] == '0' || field[0] == '1');
  if (!valid)
    return FALSE;
  alert->active = field[0] == '1';

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES, TRUE,
            &alert->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES, FALSE,
            &alert->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_STATUS_MAX_BYTES, TRUE,
            &alert->status)
          && cursor == end
          && turbovas_control_alert_status_is_valid (alert->status)
          && turbovas_control_text_has_allowed_controls (
            alert->name, strlen (alert->name), FALSE)
          && turbovas_control_text_has_allowed_controls (
            alert->comment, strlen (alert->comment), FALSE);
  if (!valid)
    turbovas_control_alert_syslog_create_request_clear (alert);

  return valid;
}

static gboolean
turbovas_control_parse_alert_snmp_create_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_alert_snmp_create_request_t *alert)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;
  gboolean valid;

  memset (alert, 0, sizeof (*alert));
  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND,
        TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end))
    return FALSE;

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 1 && (field[0] == '0' || field[0] == '1');
  if (!valid)
    return FALSE;
  alert->active = field[0] == '1';

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES, TRUE,
            &alert->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES, FALSE,
            &alert->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_STATUS_MAX_BYTES, TRUE,
            &alert->status)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SNMP_AGENT_MAX_BYTES,
            TRUE, &alert->agent)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_SNMP_COMMUNITY_MAX_BYTES,
            TRUE, &alert->community)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field (
            field, field_len, TURBOVAS_CONTROL_ALERT_MESSAGE_MAX_BYTES, TRUE,
            &alert->message)
          && cursor == end
          && turbovas_control_alert_status_is_valid (alert->status)
          && turbovas_control_text_has_allowed_controls (
            alert->name, strlen (alert->name), FALSE)
          && turbovas_control_text_has_allowed_controls (
            alert->comment, strlen (alert->comment), FALSE)
          && turbovas_control_text_has_allowed_controls (
            alert->agent, strlen (alert->agent), FALSE)
          && turbovas_control_text_has_allowed_controls (
            alert->community, strlen (alert->community), FALSE)
          && turbovas_control_text_has_allowed_controls (
            alert->message, strlen (alert->message), TRUE);
  if (!valid)
    turbovas_control_alert_snmp_create_request_clear (alert);

  return valid;
}

static gboolean
turbovas_control_optional_uuid_is_valid (const char *uuid)
{
  return uuid[0] == '\0' || turbovas_control_uuid_is_valid (uuid);
}

static gboolean
turbovas_control_parse_alert_email_create_request
  (const char *request, size_t request_len, const char *expected_secret,
   size_t expected_secret_len, char operator_uuid[37],
   turbovas_control_alert_email_create_request_t *alert)
{
  const char *cursor;
  const char *end;
  const char *field;
  const char *operator_start;
  const char *secret;
  const char *secret_end;
  size_t field_len;
  size_t secret_len;
  gboolean valid;

  memset (alert, 0, sizeof (*alert));
  if (request == NULL
      || request_len >= TURBOVAS_CONTROL_MAX_REQUEST_BYTES
      || request_len < TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH
                       + TURBOVAS_CONTROL_SECRET_MIN_BYTES + 1 + 37 + 1
      || memcmp (request, TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND,
                 TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                            expected_secret_len))
    return FALSE;

  end = request + request_len - 1;
  secret = request + TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH;
  secret_end = memchr (secret, ' ', (size_t) (end - secret));
  if (secret_end == NULL)
    return FALSE;
  secret_len = (size_t) (secret_end - secret);
  if (!turbovas_control_secret_is_valid (secret, secret_len)
      || !turbovas_control_secret_matches (secret, secret_len,
                                           expected_secret,
                                           expected_secret_len))
    return FALSE;

  operator_start = secret_end + 1;
  if ((size_t) (end - operator_start) < 37 || operator_start[36] != ' ')
    return FALSE;
  memcpy (operator_uuid, operator_start, 36);
  operator_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (operator_uuid))
    return FALSE;

  cursor = operator_start + 37;
  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 1 && (field[0] == '0' || field[0] == '1');
  if (!valid)
    return FALSE;
  alert->active = field[0] == '1';

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES, TRUE,
                &alert->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES,
                FALSE, &alert->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_STATUS_MAX_BYTES, TRUE,
                &alert->status)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_ADDRESS_MAX_BYTES,
                TRUE, &alert->to_address)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_ADDRESS_MAX_BYTES,
                FALSE, &alert->from_address)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_SUBJECT_MAX_BYTES,
                TRUE, &alert->subject)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 1 && field[0] >= '0' && field[0] <= '2';
  if (!valid)
    {
      turbovas_control_alert_email_create_request_clear (alert);
      return FALSE;
    }
  alert->notice = (unsigned int) (field[0] - '0');

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES, FALSE,
                &alert->recipient_credential_uuid)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES, FALSE,
                &alert->report_format_uuid)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_MESSAGE_MAX_BYTES,
                FALSE, &alert->message)
          && cursor == end
          && turbovas_control_alert_status_is_valid (alert->status)
          && turbovas_control_optional_uuid_is_valid
               (alert->recipient_credential_uuid)
          && turbovas_control_optional_uuid_is_valid (alert->report_format_uuid)
          && ((alert->notice == 1
               && alert->report_format_uuid[0] == '\0')
              || (alert->notice != 1
                  && alert->report_format_uuid[0] != '\0'));
  if (!valid)
    turbovas_control_alert_email_create_request_clear (alert);

  return valid;
}

static void
turbovas_control_schedule_modify_request_clear
  (turbovas_control_schedule_modify_request_t *request)
{
  g_free (request->name);
  g_free (request->comment);
  g_free (request->timezone);
  g_free (request->icalendar);
  memset (request, 0, sizeof (*request));
}

static gboolean
turbovas_control_parse_schedule_modify_request
  (const char *request, size_t request_len, const char *expected_secret,
   size_t expected_secret_len, char operator_uuid[37], char schedule_uuid[37],
   turbovas_control_schedule_modify_request_t *schedule)
{
  const char *cursor;
  const char *end;
  const char *field;
  const char *operator_start;
  const char *schedule_start;
  const char *secret;
  const char *secret_end;
  size_t field_len;
  size_t secret_len;
  gboolean valid;

  memset (schedule, 0, sizeof (*schedule));
  if (request == NULL
      || request_len > TURBOVAS_CONTROL_MAX_REQUEST_BYTES
      || request_len < TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND_LENGTH
                       + TURBOVAS_CONTROL_SECRET_MIN_BYTES + 1 + 37 + 37
      || memcmp (request, TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND,
                 TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND_LENGTH)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                            expected_secret_len))
    return FALSE;

  end = request + request_len - 1;
  secret = request + TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND_LENGTH;
  secret_end = memchr (secret, ' ', (size_t) (end - secret));
  if (secret_end == NULL)
    return FALSE;
  secret_len = (size_t) (secret_end - secret);
  if (!turbovas_control_secret_is_valid (secret, secret_len)
      || !turbovas_control_secret_matches (secret, secret_len,
                                           expected_secret,
                                           expected_secret_len))
    return FALSE;

  operator_start = secret_end + 1;
  if (operator_start + 37 > end || operator_start[36] != ' ')
    return FALSE;
  memcpy (operator_uuid, operator_start, 36);
  operator_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (operator_uuid))
    return FALSE;

  schedule_start = operator_start + 37;
  if (schedule_start + 37 > end || schedule_start[36] != ' ')
    return FALSE;
  memcpy (schedule_uuid, schedule_start, 36);
  schedule_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (schedule_uuid))
    return FALSE;

  cursor = schedule_start + 37;
  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_schedule_modify_field
               (field, field_len, TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES,
                FALSE, &schedule->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_schedule_modify_field
               (field, field_len, TURBOVAS_CONTROL_SCHEDULE_COMMENT_MAX_BYTES,
                FALSE, &schedule->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_schedule_modify_field
               (field, field_len,
                TURBOVAS_CONTROL_SCHEDULE_TIMEZONE_MAX_BYTES, FALSE,
                &schedule->timezone)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_schedule_modify_field
               (field, field_len,
                TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES, TRUE,
                &schedule->icalendar)
          && cursor == end
          && (schedule->name || schedule->comment || schedule->timezone
              || schedule->icalendar);
  if (!valid)
    turbovas_control_schedule_modify_request_clear (schedule);

  return valid;
}

static gboolean
turbovas_control_next_field (const char **cursor, const char *end,
                             const char **field, size_t *field_len)
{
  const char *separator;

  if (*cursor > end)
    return FALSE;

  separator = memchr (*cursor, ' ', (size_t) (end - *cursor));
  if (separator)
    {
      *field = *cursor;
      *field_len = (size_t) (separator - *cursor);
      *cursor = separator + 1;
    }
  else
    {
      *field = *cursor;
      *field_len = (size_t) (end - *cursor);
      *cursor = end;
    }

  return TRUE;
}

static gboolean
turbovas_control_parse_task_clone_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37], char task_uuid[37])
{
  const char *cursor;
  const char *end;

  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_TASK_CLONE_COMMAND,
        TURBOVAS_CONTROL_TASK_CLONE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end)
      || (size_t) (end - cursor) != 36)
    return FALSE;

  memcpy (task_uuid, cursor, 36);
  task_uuid[36] = '\0';
  return turbovas_control_uuid_is_valid (task_uuid);
}

static gboolean
turbovas_control_parse_tag_create_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37],
  turbovas_control_tag_create_request_t *tag)
{
  const char *cursor;
  const char *end;
  const char *field;
  size_t field_len;
  gboolean valid;

  memset (tag, 0, sizeof (*tag));
  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_TAG_CREATE_COMMAND,
        TURBOVAS_CONTROL_TAG_CREATE_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end))
    return FALSE;

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && field_len == 1 && (field[0] == '0' || field[0] == '1');
  if (!valid)
    return FALSE;
  tag->active = field[0] == '1';

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_text_field (
               field, field_len, TURBOVAS_CONTROL_TAG_RESOURCE_TYPE_MAX_BYTES,
               TRUE, &tag->resource_type)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_text_field (
               field, field_len, TURBOVAS_CONTROL_TAG_TEXT_MAX_BYTES, TRUE,
               &tag->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_text_field (
               field, field_len, TURBOVAS_CONTROL_TAG_TEXT_MAX_BYTES, FALSE,
               &tag->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_text_field (
               field, field_len, TURBOVAS_CONTROL_TAG_TEXT_MAX_BYTES, FALSE,
               &tag->value)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_tag_resource_ids_from_field (
               field, field_len, &tag->resource_ids)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_text_field (
               field, field_len, TURBOVAS_CONTROL_TAG_FILTER_MAX_BYTES, FALSE,
               &tag->resource_filter)
          && cursor == end
          && strcasecmp (tag->resource_type, "tag") != 0
          && (valid_db_resource_type (tag->resource_type)
              || valid_subtype (tag->resource_type))
          && !(g_ptr_array_index (tag->resource_ids, 0) != NULL
               && tag->resource_filter[0] != '\0');
  if (!valid)
    turbovas_control_tag_create_request_clear (tag);
  return valid;
}

static gboolean
turbovas_control_decode_tag_modify_field (const char *field,
                                           size_t field_len,
                                           size_t max_decoded_len,
                                           gchar **decoded_out)
{
  return turbovas_control_decode_schedule_modify_field (
    field, field_len, max_decoded_len, FALSE, decoded_out);
}

static gboolean
turbovas_control_parse_tag_modify_request (
  const char *request, size_t request_len, const char *expected_secret,
  size_t expected_secret_len, char operator_uuid[37], char tag_uuid[37],
  turbovas_control_tag_modify_request_t *tag)
{
  const char *cursor;
  const char *end;
  const char *field;
  const char *tag_start;
  size_t field_len;
  gboolean action_present;
  gboolean filter_present;
  gboolean ids_present;
  gboolean valid;

  memset (tag, 0, sizeof (*tag));
  if (!turbovas_control_parse_authenticated_prefix (
        request, request_len, TURBOVAS_CONTROL_TAG_MODIFY_COMMAND,
        TURBOVAS_CONTROL_TAG_MODIFY_COMMAND_LENGTH, expected_secret,
        expected_secret_len, operator_uuid, &cursor, &end))
    return FALSE;

  tag_start = cursor;
  if ((size_t) (end - tag_start) < 37 || tag_start[36] != ' ')
    return FALSE;
  memcpy (tag_uuid, tag_start, 36);
  tag_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (tag_uuid))
    return FALSE;
  cursor = tag_start + 37;

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_modify_field (
               field, field_len, TURBOVAS_CONTROL_TAG_TEXT_MAX_BYTES,
               &tag->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_modify_field (
               field, field_len, TURBOVAS_CONTROL_TAG_TEXT_MAX_BYTES,
               &tag->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_modify_field (
               field, field_len, TURBOVAS_CONTROL_TAG_TEXT_MAX_BYTES,
               &tag->value)
          && turbovas_control_next_field (&cursor, end, &field, &field_len);
  if (!valid)
    goto invalid;
  if (field_len == 1 && field[0] == '-')
    tag->active = NULL;
  else if (field_len == 1 && (field[0] == '0' || field[0] == '1'))
    tag->active = g_strndup (field, 1);
  else
    goto invalid;

  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_tag_modify_field (
               field, field_len, TURBOVAS_CONTROL_TAG_RESOURCE_TYPE_MAX_BYTES,
               &tag->resource_type)
          && turbovas_control_next_field (&cursor, end, &field, &field_len);
  if (!valid)
    goto invalid;
  if (field_len == 1 && field[0] == '-')
    tag->resources_action = NULL;
  else if ((field_len == 3 && memcmp (field, "add", 3) == 0)
           || (field_len == 3 && memcmp (field, "set", 3) == 0)
           || (field_len == 6 && memcmp (field, "remove", 6) == 0))
    tag->resources_action = g_strndup (field, field_len);
  else
    goto invalid;

  if (!turbovas_control_next_field (&cursor, end, &field, &field_len))
    goto invalid;
  if (!(field_len == 1 && field[0] == '-'))
    {
      if (field_len == 0 || field[0] != '+'
          || !turbovas_control_tag_resource_ids_from_field (
               field + 1, field_len - 1, &tag->resource_ids))
        goto invalid;
    }

  if (!turbovas_control_next_field (&cursor, end, &field, &field_len)
      || !turbovas_control_decode_tag_modify_field (
           field, field_len, TURBOVAS_CONTROL_TAG_FILTER_MAX_BYTES,
           &tag->resource_filter)
      || cursor != end)
    goto invalid;

  action_present = tag->resources_action != NULL;
  ids_present = tag->resource_ids
                && g_ptr_array_index (tag->resource_ids, 0) != NULL;
  filter_present = tag->resource_filter && tag->resource_filter[0] != '\0';
  valid = !(ids_present && filter_present)
          && (!tag->name || tag->name[0] != '\0')
          && (!tag->resource_type
              || (strcasecmp (tag->resource_type, "tag") != 0
                  && (valid_db_resource_type (tag->resource_type)
                      || valid_subtype (tag->resource_type))))
          && (!tag->resource_type
              || (action_present
                  && strcmp (tag->resources_action, "set") == 0))
          && ((action_present
               && (strcmp (tag->resources_action, "set") == 0 || ids_present
                   || filter_present))
              || (!action_present && !tag->resource_ids
                  && !tag->resource_filter && !tag->resource_type))
          && (tag->name || tag->comment || tag->value || tag->active
              || action_present);
  if (valid && action_present
      && strcmp (tag->resources_action, "set") == 0
      && tag->resource_ids == NULL && !filter_present)
    {
      tag->resource_ids = make_array ();
      array_terminate (tag->resource_ids);
    }
  if (valid)
    return TRUE;

invalid:
  turbovas_control_tag_modify_request_clear (tag);
  return FALSE;
}

static gboolean
turbovas_control_parse_schedule_create_request
  (const char *request, size_t request_len, const char *expected_secret,
   size_t expected_secret_len, char operator_uuid[37],
   turbovas_control_schedule_create_request_t *schedule)
{
  const char *cursor;
  const char *end;
  const char *field;
  const char *operator_start;
  const char *secret;
  const char *secret_end;
  size_t field_len;
  size_t secret_len;
  gboolean valid;

  memset (schedule, 0, sizeof (*schedule));
  if (request == NULL
      || request_len > TURBOVAS_CONTROL_MAX_REQUEST_BYTES
      || request_len < TURBOVAS_CONTROL_SCHEDULE_CREATE_COMMAND_LENGTH
                       + TURBOVAS_CONTROL_SECRET_MIN_BYTES + 1 + 37
      || memcmp (request, TURBOVAS_CONTROL_SCHEDULE_CREATE_COMMAND,
                 TURBOVAS_CONTROL_SCHEDULE_CREATE_COMMAND_LENGTH)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                            expected_secret_len))
    return FALSE;

  end = request + request_len - 1;
  secret = request + TURBOVAS_CONTROL_SCHEDULE_CREATE_COMMAND_LENGTH;
  secret_end = memchr (secret, ' ', (size_t) (end - secret));
  if (secret_end == NULL)
    return FALSE;
  secret_len = (size_t) (secret_end - secret);
  if (!turbovas_control_secret_is_valid (secret, secret_len)
      || !turbovas_control_secret_matches (secret, secret_len,
                                           expected_secret,
                                           expected_secret_len))
    return FALSE;

  operator_start = secret_end + 1;
  if (operator_start + 37 > end || operator_start[36] != ' ')
    return FALSE;
  memcpy (operator_uuid, operator_start, 36);
  operator_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (operator_uuid))
    return FALSE;

  cursor = operator_start + 37;
  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES,
                TRUE, &schedule->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_SCHEDULE_COMMENT_MAX_BYTES,
                FALSE, &schedule->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len,
                TURBOVAS_CONTROL_SCHEDULE_TIMEZONE_MAX_BYTES, FALSE,
                &schedule->timezone)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len,
                TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES, TRUE,
                &schedule->icalendar)
          && cursor == end;
  if (!valid)
    turbovas_control_schedule_create_request_clear (schedule);

  return valid;
}

static gboolean
turbovas_control_parse_credential_create_request
  (const char *request, size_t request_len, const char *expected_secret,
   size_t expected_secret_len, char operator_uuid[37],
   turbovas_control_credential_create_request_t *credential)
{
  const char *cursor;
  const char *end;
  const char *field;
  const char *operator_start;
  const char *secret;
  const char *secret_end;
  size_t field_len;
  size_t secret_len;
  gboolean is_up;
  gboolean valid;

  memset (credential, 0, sizeof (*credential));
  if (request == NULL
      || request_len > TURBOVAS_CONTROL_MAX_REQUEST_BYTES
      || request_len < TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND_LENGTH
                       + TURBOVAS_CONTROL_SECRET_MIN_BYTES + 1 + 37 + 1
      || memcmp (request, TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND,
                 TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND_LENGTH)
      || request[request_len - 1] != '\n'
      || !turbovas_control_secret_is_valid (expected_secret,
                                            expected_secret_len))
    return FALSE;

  end = request + request_len - 1;
  secret = request + TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND_LENGTH;
  secret_end = memchr (secret, ' ', (size_t) (end - secret));
  if (secret_end == NULL)
    return FALSE;
  secret_len = (size_t) (secret_end - secret);
  if (!turbovas_control_secret_is_valid (secret, secret_len)
      || !turbovas_control_secret_matches (secret, secret_len,
                                           expected_secret,
                                           expected_secret_len))
    return FALSE;

  operator_start = secret_end + 1;
  if (operator_start + 37 > end || operator_start[36] != ' ')
    return FALSE;
  memcpy (operator_uuid, operator_start, 36);
  operator_uuid[36] = '\0';
  if (!turbovas_control_uuid_is_valid (operator_uuid))
    return FALSE;

  cursor = operator_start + 37;
  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && ((field_len == strlen (TURBOVAS_CONTROL_CREDENTIAL_TYPE_UP)
               && memcmp (field, TURBOVAS_CONTROL_CREDENTIAL_TYPE_UP,
                          field_len) == 0)
              || (field_len == strlen (TURBOVAS_CONTROL_CREDENTIAL_TYPE_USK)
                  && memcmp (field, TURBOVAS_CONTROL_CREDENTIAL_TYPE_USK,
                             field_len) == 0));
  if (!valid)
    return FALSE;

  credential->credential_type = g_strndup (field, field_len);
  is_up = strcmp (credential->credential_type,
                  TURBOVAS_CONTROL_CREDENTIAL_TYPE_UP) == 0;
  valid = turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_CREDENTIAL_NAME_MAX_BYTES,
                TRUE, &credential->name)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len,
                TURBOVAS_CONTROL_CREDENTIAL_COMMENT_MAX_BYTES, FALSE,
                &credential->comment)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_CREDENTIAL_LOGIN_MAX_BYTES,
                TRUE, &credential->login)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len,
                TURBOVAS_CONTROL_CREDENTIAL_SECRET_MAX_BYTES, is_up,
                &credential->secret)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len,
                TURBOVAS_CONTROL_CREDENTIAL_PRIVATE_KEY_MAX_BYTES, !is_up,
                &credential->private_key)
          && cursor == end
          && (is_up ? credential->private_key[0] == '\0'
                    : credential->private_key[0] != '\0')
          && turbovas_control_text_has_allowed_controls
               (credential->name, strlen (credential->name), FALSE)
          && turbovas_control_text_has_allowed_controls
               (credential->comment, strlen (credential->comment), FALSE)
          && turbovas_control_text_has_allowed_controls
               (credential->login, strlen (credential->login), FALSE)
          && turbovas_control_text_has_allowed_controls
               (credential->private_key, strlen (credential->private_key),
                TRUE);
  if (!valid)
    turbovas_control_credential_create_request_clear (credential);

  return valid;
}

static const char *
turbovas_control_response (int result)
{
  switch (result)
    {
      case 0:
        return "0 stopped\n";
      case 1:
        return "1 requested\n";
      case 2:
        return "2 inactive\n";
      case 3:
        return "3 not_found\n";
      case 99:
        return "99 forbidden\n";
      case -2:
        return "-2 scanner_status\n";
      case -3:
        return "-3 scanner_stop\n";
      case -4:
        return "-4 scanner_delete\n";
      case -5:
        return "-5 scanner_verify\n";
      default:
        return "-1 internal\n";
    }
}

static const char *
turbovas_control_schedule_create_response
  (int result, const char *uuid,
   char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  if (result == 0 && uuid && turbovas_control_uuid_is_valid (uuid))
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 created %s\n", uuid);
      return response;
    }

  switch (result)
    {
      case 1:
        status = "1 exists\n";
        break;
      case 3:
        status = "3 invalid_ical\n";
        break;
      case 4:
        status = "4 invalid_timezone\n";
        break;
      case 99:
        status = "99 forbidden\n";
        break;
      default:
        status = "-1 internal\n";
        break;
    }

  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static const char *
turbovas_control_alert_create_response (
  int result, const char *uuid,
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  if (result == 0 && uuid && turbovas_control_uuid_is_valid (uuid))
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 created %s\n", uuid);
      return response;
    }

  switch (result)
    {
      case 0: status = "-1 internal\n"; break;
      case 1: status = "1 exists\n"; break;
      case 2: status = "2 invalid_email\n"; break;
      case 3: status = "3 filter_not_found\n"; break;
      case 4: status = "4 invalid_filter_type\n"; break;
      case 5: status = "5 invalid_condition_name\n"; break;
      case 6: status = "6 invalid_condition_data\n"; break;
      case 7: status = "7 subject_too_long\n"; break;
      case 8: status = "8 message_too_long\n"; break;
      case 9: status = "9 condition_filter_not_found\n"; break;
      case 15: status = "15 invalid_scp_host\n"; break;
      case 16: status = "16 invalid_scp_port\n"; break;
      case 17: status = "17 scp_format_not_found\n"; break;
      case 18: status = "18 invalid_scp_credential\n"; break;
      case 19: status = "19 invalid_scp_path\n"; break;
      case 20: status = "20 method_event_mismatch\n"; break;
      case 21: status = "21 condition_event_mismatch\n"; break;
      case 31: status = "31 invalid_event_name\n"; break;
      case 32: status = "32 invalid_event_data\n"; break;
      case 40: status = "40 invalid_smb_credential\n"; break;
      case 41: status = "41 invalid_smb_share\n"; break;
      case 42: status = "42 invalid_smb_path\n"; break;
      case 43: status = "43 dotted_smb_path\n"; break;
      case 60: status = "60 recipient_credential_not_found\n"; break;
      case 61: status = "61 invalid_recipient_credential\n"; break;
      case 90: status = "90 report_format_not_found\n"; break;
      case 99: status = "99 forbidden\n"; break;
      case -3: status = "-3 committed_indeterminate\n"; break;
      case -2: status = "-2 malformed\n"; break;
      case -1: status = "-1 internal\n"; break;
      default: status = "-1 internal\n"; break;
    }

  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static const char *
turbovas_control_alert_start_task_create_response (
  int result, const char *uuid,
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  if (result == 0 && uuid && turbovas_control_uuid_is_valid (uuid))
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 created %s\n", uuid);
      return response;
    }

  switch (result)
    {
    case 1:
      status = "1 exists\n";
      break;
    case 3:
      status = "3 task_not_found\n";
      break;
    case 99:
      status = "99 forbidden\n";
      break;
    case -3:
      status = "-3 committed_indeterminate\n";
      break;
    case -2:
      status = "-2 malformed\n";
      break;
    default:
      status = "-1 internal\n";
      break;
    }

  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static const char *
turbovas_control_alert_test_response (int result)
{
  switch (result)
    {
      case 0: return "0 tested\n";
      case 1: return "1 not_found\n";
      case 99: return "99 forbidden\n";
      case -2: return "-2 report_format_not_found\n";
      case -3: return "-3 filter_not_found\n";
      case -4: return "-4 credential_not_found\n";
      case -5: return "-5 delivery_failed\n";
      default: return "-1 internal\n";
    }
}

static const char *
turbovas_control_credential_create_response
  (int result, const char *uuid,
   char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  if (result == 0 && uuid && turbovas_control_uuid_is_valid (uuid))
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 created %s\n", uuid);
      return response;
    }

  switch (result)
    {
      case 1:
        status = "1 exists\n";
        break;
      case 2:
        status = "2 invalid_login\n";
        break;
      case 3:
        status = "3 invalid_key\n";
        break;
      case 5:
        status = "5 login_required\n";
        break;
      case 6:
        status = "6 password_required\n";
        break;
      case 7:
        status = "7 key_required\n";
        break;
      case 99:
        status = "99 forbidden\n";
        break;
      case -2:
        status = "-2 malformed\n";
        break;
      default:
        status = "-1 internal\n";
        break;
    }

  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static const char *
turbovas_control_schedule_modify_response
  (int result, char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  switch (result)
    {
      case 0:
        status = "0 modified\n";
        break;
      case 1:
        status = "1 not_found\n";
        break;
      case 2:
        status = "2 duplicate\n";
        break;
      case 6:
        status = "6 invalid_ical\n";
        break;
      case 7:
        status = "7 invalid_timezone\n";
        break;
      case 99:
        status = "99 forbidden\n";
        break;
      case 3:
      case 4:
      case -2:
        status = "-2 malformed\n";
        break;
      default:
        status = "-1 internal\n";
        break;
    }

  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static const char *
turbovas_control_scan_config_nvt_diagnostic_response (int result)
{
  switch (result)
    {
      case 0: return "0 configured\n";
      case 1: return "1 in_use\n";
      case 2: return "2 whole_only\n";
      case 3: return "3 config_not_found\n";
      case 4: return "4 nvt_not_found\n";
      case 5: return "5 prerequisite_not_found\n";
      case 6: return "6 shared_selector\n";
      case 99: return "99 forbidden\n";
      case -3: return "-3 committed_indeterminate\n";
      case -2: return "-2 malformed\n";
      default: return "-1 internal\n";
    }
}

static const char *
turbovas_control_task_clone_response (
  int result, const char *uuid,
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES])
{
  const char *status;

  if (result == 0 && uuid && turbovas_control_uuid_is_valid (uuid))
    {
      g_snprintf (response, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES,
                  "0 created %s\n", uuid);
      return response;
    }

  switch (result)
    {
    case 1:
      status = "1 duplicate\n";
      break;
    case 2:
      status = "2 not_found\n";
      break;
    case 99:
      status = "99 forbidden\n";
      break;
    case -3:
      status = "-3 committed_indeterminate\n";
      break;
    case -2:
      status = "-2 malformed\n";
      break;
    default:
      status = "-1 internal\n";
      break;
    }

  g_strlcpy (response, status, TURBOVAS_CONTROL_MAX_RESPONSE_BYTES);
  return response;
}

static gboolean
turbovas_control_write_all (int socket, const char *response)
{
  size_t length = strlen (response);
  size_t written = 0;

  while (written < length)
    {
      ssize_t ret = write (socket, response + written, length - written);

      if (ret > 0)
        {
          written += ret;
          continue;
        }
      if (ret < 0 && errno == EINTR)
        continue;
      return FALSE;
    }

  return TRUE;
}

static gboolean
turbovas_control_read_request
  (int socket, char request[TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1],
                               size_t *request_len)
{
  size_t length = 0;
  *request_len = 0;

  while (length < TURBOVAS_CONTROL_MAX_REQUEST_BYTES)
    {
      ssize_t ret = read (socket, request + length,
                          TURBOVAS_CONTROL_MAX_REQUEST_BYTES - length);
      char *newline;

      if (ret > 0)
        {
          length += ret;
          *request_len = length;
          newline = memchr (request, '\n', length);
          if (newline)
            {
              *request_len = length;
              return newline == request + length - 1;
            }
          continue;
        }
      if (ret < 0 && errno == EINTR)
        continue;
      return FALSE;
    }

  return FALSE;
}

static void
turbovas_control_set_timeouts (int socket)
{
  struct timeval timeout = { TURBOVAS_CONTROL_TIMEOUT_SECONDS, 0 };

  if (setsockopt (socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                  sizeof (timeout)) == -1)
    g_warning ("%s: failed to set read timeout: %s", __func__,
               strerror (errno));
  if (setsockopt (socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                  sizeof (timeout)) == -1)
    g_warning ("%s: failed to set write timeout: %s", __func__,
               strerror (errno));
}

static gboolean
turbovas_control_start_operator_session (const char *operator_uuid)
{
  gchar *operator_uuid_copy;
  gchar *operator_name;

  reinit_manage_process ();

  operator_uuid_copy = g_strdup (operator_uuid);
  operator_name = user_name (operator_uuid_copy);
  if (operator_name == NULL)
    {
      g_free (operator_uuid_copy);
      cleanup_manage_process (FALSE);
      return FALSE;
    }
  current_credentials.uuid = operator_uuid_copy;
  current_credentials.username = operator_name;
  manage_session_init (current_credentials.uuid);

  return TRUE;
}

static void
turbovas_control_finish_operator_session (void)
{
  g_free (current_credentials.username);
  g_free (current_credentials.uuid);
  current_credentials.username = NULL;
  current_credentials.uuid = NULL;
  cleanup_manage_process (FALSE);
}

static int
turbovas_control_stop_task (const char *operator_uuid, const char *task_uuid)
{
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = stop_task (task_uuid);

  turbovas_control_finish_operator_session ();

  return result;
}

static int
turbovas_control_modify_user_setting (
  const char *operator_uuid,
  const turbovas_control_user_setting_modify_request_t *request)
{
  gchar *error_description = NULL;
  gchar *value_64;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return MODIFY_SETTING_RESULT_PERMISSION_DENIED;

  value_64 = g_base64_encode ((const guchar *) request->value,
                              strlen (request->value));
  result = modify_setting (request->timezone ? NULL : request->setting_uuid,
                           request->timezone ? "Timezone" : NULL, value_64,
                           &error_description);
  turbovas_control_secure_free (value_64);
  turbovas_control_secure_free (error_description);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_change_user_password (
  const char *operator_uuid,
  const turbovas_control_user_password_change_request_t *request)
{
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = current_user_change_password (request->old_password,
                                         request->new_password);
  if (result == 0)
    log_event ("user", "User", operator_uuid, "password changed");
  else
    log_event_fail ("user", "User", operator_uuid, "password changed");

  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_user (
  const char *operator_uuid,
  const turbovas_control_user_create_request_t *request,
  char created_uuid[37])
{
  array_t *allowed_methods;
  gchar *password_error;
  gchar *uuid;
  user_t user = 0;
  int native_result;
  int result;

  created_uuid[0] = '\0';
  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  if (!turbovas_control_user_method_is_valid (request->method))
    result = 4;
  else if (validate_username (request->name) != 0)
    result = 2;
  else if (strcmp (request->method, "file") == 0
           && (request->password == NULL || request->password[0] == '\0'))
    result = 3;
  else if (strcmp (request->method, "file") == 0
           && (password_error = gvm_validate_password (request->password,
                                                        request->name)) != NULL)
    {
      turbovas_control_secure_free (password_error);
      result = 3;
    }
  else
    {
      allowed_methods = make_array ();
      array_add (allowed_methods, g_strdup (request->method));
      array_terminate (allowed_methods);
      native_result = create_user (request->name,
                                   request->password ? request->password : "",
                                   request->comment, allowed_methods, NULL,
                                   &user);
      array_free (allowed_methods);
      switch (native_result)
        {
          case 0:
            uuid = user_uuid (user);
            if (uuid && turbovas_control_uuid_is_valid (uuid))
              {
                g_strlcpy (created_uuid, uuid, 37);
                result = 0;
              }
            else
              result = -3;
            g_free (uuid);
            break;
          case -2: result = 1; break;
          case -4: result = 4; break;
          case 99: result = 99; break;
          default: result = -1; break;
        }
    }

  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_modify_user (
  const char *operator_uuid,
  const turbovas_control_user_modify_request_t *request)
{
  array_t *allowed_methods;
  gchar *current_name;
  gchar *password_error;
  const gchar *new_name;
  int native_result;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  if (!turbovas_control_user_method_is_valid (request->method))
    result = 7;
  else
    {
      current_name = user_name (request->target_uuid);
      if (current_name == NULL)
        result = 1;
      else
        {
          if (validate_username (request->name) != 0)
            result = 2;
          else if (strcmp (operator_uuid, request->target_uuid) == 0
                   && strcmp (current_name, request->name) != 0)
            result = 6;
          else if (request->password
                   && (password_error = gvm_validate_password (
                         request->password, current_name)) != NULL)
            {
              turbovas_control_secure_free (password_error);
              result = 4;
            }
          else
            {
              allowed_methods = make_array ();
              array_add (allowed_methods, g_strdup (request->method));
              array_terminate (allowed_methods);
              new_name = strcmp (current_name, request->name) == 0
                           ? NULL : request->name;
              native_result = modify_user (request->target_uuid, &current_name,
                                           new_name, request->password,
                                           request->comment, allowed_methods,
                                           NULL);
              array_free (allowed_methods);
              switch (native_result)
                {
                  case 0: result = 0; break;
                  case 2: result = 1; break;
                  case 7: result = 2; break;
                  case 8: result = 3; break;
                  case MODIFY_USER_PASSWORD_REQUIRED: result = 5; break;
                  case -4: result = 7; break;
                  case 99: result = 99; break;
                  default: result = -1; break;
                }
            }
        }
      g_free (current_name);
    }

  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_delete_user (
  const char *operator_uuid,
  const turbovas_control_user_delete_request_t *request)
{
  int native_result;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  native_result = delete_user (
    request->target_uuid, NULL, 1,
    request->inheritor_uuid[0] ? request->inheritor_uuid : NULL, NULL);
  switch (native_result)
    {
      case 0: result = 0; break;
      case 2: result = 1; break;
      case 5: result = 2; break;
      case 6: result = 3; break;
      case 7: result = 4; break;
      case 9: result = 5; break;
      case 99: result = 99; break;
      default: result = -1; break;
    }

  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_clone_user (const char *operator_uuid,
                             const char *source_user_uuid,
                             char created_uuid[37])
{
  user_t new_user = 0;
  char *uuid = NULL;
  gboolean committed = FALSE;
  int result;

  created_uuid[0] = '\0';
  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = copy_user (NULL, NULL, source_user_uuid, &new_user);
  if (result == 0)
    {
      committed = TRUE;
      uuid = user_uuid (new_user);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        {
          g_warning ("%s: user clone committed but UUID lookup failed",
                     __func__);
          log_event ("user", "User", NULL, "created");
          result = -3;
        }
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
          log_event ("user", "User", created_uuid, "created");
        }
    }

  if (result != 0 && !committed)
    log_event_fail ("user", "User", source_user_uuid, "created");

  free (uuid);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_clone_task (const char *operator_uuid,
                             const char *source_task_uuid,
                             char created_uuid[37])
{
  task_t new_task = 0;
  char *uuid = NULL;
  gboolean committed = FALSE;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = copy_task (NULL, NULL, source_task_uuid, -1, &new_task);
  if (result == 0)
    {
      committed = TRUE;
      task_uuid (new_task, &uuid);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        {
          g_warning ("%s: task clone committed but UUID lookup failed",
                     __func__);
          log_event ("task", "Task", NULL, "created");
          result = -3;
        }
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
          log_event ("task", "Task", created_uuid, "created");
        }
    }

  if (result != 0 && !committed)
    log_event_fail ("task", "Task", source_task_uuid, "created");

  free (uuid);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_alert_smb (
  const char *operator_uuid,
  const turbovas_control_alert_smb_create_request_t *request,
  char created_uuid[37])
{
  array_t *condition_data = NULL;
  array_t *event_data = NULL;
  array_t *method_data = NULL;
  alert_t alert = 0;
  char active[2] = {request->active ? '1' : '0', '\0'};
  char *uuid = NULL;
  gboolean committed = FALSE;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  condition_data = make_array ();
  event_data = make_array ();
  method_data = make_array ();
  turbovas_control_array_add_data (event_data, "status", request->status);
  turbovas_control_array_add_data (method_data, "smb_credential",
                                   request->credential_uuid);
  turbovas_control_array_add_data (method_data, "smb_share_path",
                                   request->share_path);
  turbovas_control_array_add_data (method_data, "smb_file_path",
                                   request->file_path);
  turbovas_control_array_add_data (method_data, "smb_report_format",
                                   request->report_format_uuid);
  if (request->max_protocol[0])
    turbovas_control_array_add_data (method_data, "smb_max_protocol",
                                     request->max_protocol);
  array_terminate (condition_data);
  array_terminate (event_data);
  array_terminate (method_data);

  result = create_alert_smb_with_report_refs (
    request->name, request->comment, active, event_data, condition_data,
    method_data, request->credential_uuid, request->report_format_uuid, &alert);
  if (result == 0)
    {
      committed = TRUE;
      uuid = alert_uuid (alert);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        {
          g_warning ("%s: alert creation committed but UUID lookup failed",
                     __func__);
          log_event ("alert", "Alert", NULL, "created");
          result = -3;
        }
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
          log_event ("alert", "Alert", created_uuid, "created");
        }
    }

  if (result != 0 && !committed)
    log_event_fail ("alert", "Alert", NULL, "created");

  free (uuid);
  turbovas_control_secure_array_free (condition_data);
  turbovas_control_secure_array_free (event_data);
  turbovas_control_secure_array_free (method_data);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_alert_scp (
  const char *operator_uuid,
  const turbovas_control_alert_scp_create_request_t *request,
  char created_uuid[37])
{
  array_t *condition_data = NULL;
  array_t *event_data = NULL;
  array_t *method_data = NULL;
  alert_t alert = 0;
  char active[2] = {request->active ? '1' : '0', '\0'};
  char *uuid = NULL;
  gboolean committed = FALSE;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  condition_data = make_array ();
  event_data = make_array ();
  method_data = make_array ();
  turbovas_control_array_add_data (event_data, "status", request->status);
  turbovas_control_array_add_data (method_data, "scp_credential",
                                   request->credential_uuid);
  turbovas_control_array_add_data (method_data, "scp_host", request->host);
  turbovas_control_array_add_data (method_data, "scp_port", request->port);
  turbovas_control_array_add_data (method_data, "scp_known_hosts",
                                   request->known_hosts);
  turbovas_control_array_add_data (method_data, "scp_path", request->path);
  turbovas_control_array_add_data (method_data, "scp_report_format",
                                   request->report_format_uuid);
  array_terminate (condition_data);
  array_terminate (event_data);
  array_terminate (method_data);

  result = create_alert_scp_with_report_refs (
    request->name, request->comment, active, event_data, condition_data,
    method_data, request->credential_uuid, request->report_format_uuid, &alert);
  if (result == 0)
    {
      committed = TRUE;
      uuid = alert_uuid (alert);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        {
          g_warning ("%s: alert creation committed but UUID lookup failed",
                     __func__);
          log_event ("alert", "Alert", NULL, "created");
          result = -3;
        }
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
          log_event ("alert", "Alert", created_uuid, "created");
        }
    }

  if (result != 0 && !committed)
    log_event_fail ("alert", "Alert", NULL, "created");

  free (uuid);
  turbovas_control_secure_array_free (condition_data);
  turbovas_control_secure_array_free (event_data);
  turbovas_control_secure_array_free (method_data);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_alert_fixed (
  const char *operator_uuid, const char *name, const char *comment,
  gboolean active, const char *status, alert_method_t method,
  const char *const method_names[], const char *const method_values[],
  size_t method_value_count, char created_uuid[37])
{
  array_t *condition_data = NULL;
  array_t *event_data = NULL;
  array_t *method_data = NULL;
  alert_t alert = 0;
  char active_value[2] = { active ? '1' : '0', '\0' };
  char *uuid = NULL;
  gboolean committed = FALSE;
  size_t index;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  condition_data = make_array ();
  event_data = make_array ();
  method_data = make_array ();
  turbovas_control_array_add_data (event_data, "status", status);
  for (index = 0; index < method_value_count; index++)
    turbovas_control_array_add_data (method_data, method_names[index],
                                     method_values[index]);
  array_terminate (condition_data);
  array_terminate (event_data);
  array_terminate (method_data);

  result = create_alert_task_status_changed (
    name, comment, active_value, event_data, condition_data, method,
    method_data, &alert);
  if (result == 0)
    {
      committed = TRUE;
      uuid = alert_uuid (alert);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        {
          g_warning ("%s: alert creation committed but UUID lookup failed",
                     __func__);
          log_event ("alert", "Alert", NULL, "created");
          result = -3;
        }
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
          log_event ("alert", "Alert", created_uuid, "created");
        }
    }

  if (result != 0 && !committed)
    log_event_fail ("alert", "Alert", NULL, "created");

  free (uuid);
  turbovas_control_secure_array_free (condition_data);
  turbovas_control_secure_array_free (event_data);
  turbovas_control_secure_array_free (method_data);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_alert_start_task (
  const char *operator_uuid,
  const turbovas_control_alert_start_task_create_request_t *request,
  char created_uuid[37])
{
  array_t *condition_data = NULL;
  array_t *event_data = NULL;
  alert_t alert = 0;
  char active[2] = {request->active ? '1' : '0', '\0'};
  char *uuid = NULL;
  gboolean committed = FALSE;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  condition_data = make_array ();
  event_data = make_array ();
  turbovas_control_array_add_data (event_data, "status", request->status);
  array_terminate (condition_data);
  array_terminate (event_data);

  result = create_alert_start_task_with_task_ref (
    request->name, request->comment, active, event_data, condition_data,
    request->task_uuid, &alert);
  if (result == 0)
    {
      committed = TRUE;
      uuid = alert_uuid (alert);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        {
          g_warning ("%s: alert creation committed but UUID lookup failed",
                     __func__);
          log_event ("alert", "Alert", NULL, "created");
          result = -3;
        }
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
          log_event ("alert", "Alert", created_uuid, "created");
        }
    }

  if (result != 0 && !committed)
    log_event_fail ("alert", "Alert", NULL, "created");

  free (uuid);
  turbovas_control_secure_array_free (condition_data);
  turbovas_control_secure_array_free (event_data);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_test_alert (const char *operator_uuid, const char *alert_uuid)
{
  gchar *script_message = NULL;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = manage_test_alert (alert_uuid, &script_message);
  if (result == 0)
    log_event ("alert", "Alert", alert_uuid, "tested");
  else
    log_event_fail ("alert", "Alert", alert_uuid, "tested");

  turbovas_control_secure_free (script_message);
  turbovas_control_finish_operator_session ();
  return result;
}

static gboolean
turbovas_control_filter_has_rows (const char *filter)
{
  return g_str_has_prefix (filter, "rows=") || strstr (filter, " rows=") != NULL;
}

static int
turbovas_control_deliver_alert_report (
  const char *operator_uuid,
  const turbovas_control_alert_deliver_report_request_t *request)
{
  static const char *default_filter =
    "first=1 rows=-1 result_hosts_only=0 apply_overrides=1 overrides=1 "
    "sort-reverse=severity";
  alert_t alert = 0;
  filter_t filter = 0;
  get_data_t get = {0};
  report_t report = 0;
  int result = -1;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  if (find_alert_with_permission (request->alert_uuid, &alert, "get_alerts"))
    goto cleanup;
  if (alert == 0)
    {
      result = 1;
      goto cleanup;
    }
  if (find_report_with_permission (request->report_uuid, &report,
                                   "get_reports"))
    goto cleanup;
  if (report == 0)
    {
      result = 2;
      goto cleanup;
    }

  get.details = 1;
  get.ignore_pagination = 0;
  if (request->filter_uuid[0])
    {
      if (find_filter_with_permission (request->filter_uuid, &filter,
                                       "get_filters"))
        goto cleanup;
      if (filter == 0)
        {
          result = 3;
          goto cleanup;
        }
      get.filt_id = g_strdup (request->filter_uuid);
      get.filter = filter_term (request->filter_uuid);
      if (get.filter == NULL)
        goto cleanup;
    }
  else
    get.filter =
      g_strdup (request->filter[0] ? request->filter : default_filter);

  if (!turbovas_control_filter_has_rows (get.filter))
    {
      gchar *with_rows = g_strdup_printf (
        "%s rows=%d", get.filter,
        alert_method (alert) == ALERT_METHOD_EMAIL ? 1000 : -1);
      g_free (get.filter);
      get.filter = with_rows;
    }

  result = manage_send_report (
    report, -1, &get, 0, 0, 1, 0, 0, NULL, NULL, NULL,
    request->alert_uuid, NULL);
  if (result == -4)
    result = 3;
  else if (result == -3)
    result = -3;
  else if (result == -2)
    result = -2;
  else if (result != 0 && result != 1)
    result = -1;

cleanup:
  if (result == 0)
    log_event ("alert", "Alert", request->alert_uuid, "delivered");
  else
    log_event_fail ("alert", "Alert", request->alert_uuid, "delivered");
  get_data_reset (&get);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_alert_syslog (
  const char *operator_uuid,
  const turbovas_control_alert_syslog_create_request_t *request,
  char created_uuid[37])
{
  static const char *method_names[] = { "submethod" };
  static const char *method_values[] = { "syslog" };

  return turbovas_control_create_alert_fixed (
    operator_uuid, request->name, request->comment, request->active,
    request->status, ALERT_METHOD_SYSLOG, method_names, method_values,
    G_N_ELEMENTS (method_names), created_uuid);
}

static int
turbovas_control_create_alert_snmp (
  const char *operator_uuid,
  const turbovas_control_alert_snmp_create_request_t *request,
  char created_uuid[37])
{
  static const char *method_names[] = {
    "snmp_agent",
    "snmp_community",
    "snmp_message",
  };
  const char *method_values[] = {
    request->agent,
    request->community,
    request->message,
  };

  return turbovas_control_create_alert_fixed (
    operator_uuid, request->name, request->comment, request->active,
    request->status, ALERT_METHOD_SNMP, method_names, method_values,
    G_N_ELEMENTS (method_names), created_uuid);
}

static int
turbovas_control_empty_trash (const char *operator_uuid, gint64 expected_total,
                              const char *expected_snapshot_digest,
                              gint64 *actual_total)
{
  long long int actual = 0;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 3;

  result = manage_empty_trashcan_confirmed ((long long int) expected_total,
                                            expected_snapshot_digest, &actual);
  *actual_total = (gint64) actual;
  turbovas_control_log_trash_empty_audit (operator_uuid, expected_total,
                                           *actual_total, result);
  turbovas_control_finish_operator_session ();
  return result;
}

static void
turbovas_control_array_add_data (array_t *array, const char *name,
                                 const char *value)
{
  size_t name_len = strlen (name);
  size_t value_len = strlen (value);
  gchar *item = g_malloc (name_len + value_len + 2);

  memcpy (item, name, name_len + 1);
  memcpy (item + name_len + 1, value, value_len + 1);
  array_add (array, item);
}

static void
turbovas_control_secure_array_free (array_t *array)
{
  guint index;

  if (array == NULL)
    return;

  for (index = 0; index < array->len; index++)
    {
      gchar *item = g_ptr_array_index (array, index);
      size_t name_len;
      size_t value_len;

      if (item == NULL)
        continue;
      name_len = strlen (item);
      value_len = strlen (item + name_len + 1);
      turbovas_control_secure_clear (item, name_len + value_len + 2);
    }
  array_free (array);
}

static int
turbovas_control_create_alert_email
  (const char *operator_uuid,
   const turbovas_control_alert_email_create_request_t *request,
   char created_uuid[37])
{
  array_t *condition_data = NULL;
  array_t *event_data = NULL;
  array_t *method_data = NULL;
  alert_t alert = 0;
  char active[2] = { request->active ? '1' : '0', '\0' };
  char notice[2] = { (char) ('0' + request->notice), '\0' };
  char *uuid = NULL;
  gboolean committed = FALSE;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  condition_data = make_array ();
  event_data = make_array ();
  method_data = make_array ();
  turbovas_control_array_add_data (event_data, "status", request->status);
  turbovas_control_array_add_data (method_data, "to_address",
                                   request->to_address);
  if (request->from_address[0])
    turbovas_control_array_add_data (method_data, "from_address",
                                     request->from_address);
  turbovas_control_array_add_data (method_data, "subject", request->subject);
  turbovas_control_array_add_data (method_data, "notice", notice);
  if (request->recipient_credential_uuid[0])
    turbovas_control_array_add_data (method_data, "recipient_credential",
                                     request->recipient_credential_uuid);
  if (request->notice == 0)
    {
      turbovas_control_array_add_data (method_data, "notice_report_format",
                                       request->report_format_uuid);
    }
  else if (request->notice == 2)
    {
      turbovas_control_array_add_data (method_data, "notice_attach_format",
                                       request->report_format_uuid);
    }
  if (request->message[0])
    turbovas_control_array_add_data (method_data, "message", request->message);
  array_terminate (condition_data);
  array_terminate (event_data);
  array_terminate (method_data);

  result = create_alert_email_with_report_refs
             (request->name, request->comment, active, event_data,
              condition_data, method_data, request->recipient_credential_uuid,
              request->report_format_uuid, &alert);
  if (result == 0)
    {
      committed = TRUE;
      uuid = alert_uuid (alert);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        {
          g_warning ("%s: alert creation committed but UUID lookup failed",
                     __func__);
          log_event ("alert", "Alert", NULL, "created");
          result = -3;
        }
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
          log_event ("alert", "Alert", created_uuid, "created");
        }
    }

  if (result != 0 && !committed)
    log_event_fail ("alert", "Alert", NULL, "created");

  free (uuid);
  turbovas_control_secure_array_free (condition_data);
  turbovas_control_secure_array_free (event_data);
  turbovas_control_secure_array_free (method_data);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_schedule
  (const char *operator_uuid,
   const turbovas_control_schedule_create_request_t *request,
   char created_uuid[37])
{
  gchar *ical_error = NULL;
  char *uuid = NULL;
  schedule_t schedule = 0;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = create_schedule (request->name, request->comment,
                            request->icalendar, request->timezone, &schedule,
                            &ical_error);
  if (result == 0)
    {
      uuid = schedule_uuid (schedule);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        result = -1;
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
        }
    }

  free (uuid);
  g_free (ical_error);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_credential
  (const char *operator_uuid,
   const turbovas_control_credential_create_request_t *request,
   char created_uuid[37])
{
  char *uuid = NULL;
  const char *key_private;
  credential_t credential = 0;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  key_private = strcmp (request->credential_type,
                        TURBOVAS_CONTROL_CREDENTIAL_TYPE_USK) == 0
                  ? request->private_key : NULL;
  result = create_credential (request->name, request->comment,
                              request->login, request->secret, key_private,
                              NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                              NULL,
                              request->credential_type, "0", &credential);
  if (result == 0)
    {
      uuid = credential_uuid (credential);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        result = -1;
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
        }
    }

  free (uuid);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_modify_schedule
  (const char *operator_uuid, const char *schedule_uuid,
   const turbovas_control_schedule_modify_request_t *request)
{
  gchar *ical_error = NULL;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = modify_schedule (schedule_uuid, request->name, request->comment,
                            request->icalendar, request->timezone,
                            &ical_error);

  g_free (ical_error);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_create_tag (
  const char *operator_uuid,
  const turbovas_control_tag_create_request_t *request,
  char created_uuid[37])
{
  gchar *error_extra = NULL;
  char *uuid = NULL;
  tag_t tag = 0;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = create_tag (
    request->name, request->comment, request->value, request->resource_type,
    request->resource_ids, request->resource_filter,
    request->active ? "1" : "0", &tag, &error_extra);
  if (result == 0)
    {
      uuid = tag_uuid (tag);
      if (uuid == NULL || !turbovas_control_uuid_is_valid (uuid))
        {
          g_warning ("%s: tag creation committed but UUID lookup failed",
                     __func__);
          log_event ("tag", "Tag", NULL, "created");
          result = -3;
        }
      else
        {
          memcpy (created_uuid, uuid, 36);
          created_uuid[36] = '\0';
          log_event ("tag", "Tag", created_uuid, "created");
        }
    }
  else
    log_event_fail ("tag", "Tag", NULL, "created");

  free (uuid);
  g_free (error_extra);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_modify_tag (
  const char *operator_uuid, const char *tag_uuid,
  const turbovas_control_tag_modify_request_t *request)
{
  gchar *error_extra = NULL;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = modify_tag (
    tag_uuid, request->name, request->comment, request->value,
    request->resource_type, request->resource_ids, request->resource_filter,
    request->resources_action, request->active, &error_extra);
  if (result == 0)
    log_event ("tag", "Tag", tag_uuid, "modified");
  else
    log_event_fail ("tag", "Tag", tag_uuid, "modified");

  g_free (error_extra);
  turbovas_control_finish_operator_session ();
  return result;
}

static int
turbovas_control_configure_diagnostic_nvt (const char *operator_uuid,
                                           const char *config_uuid,
                                           const char *nvt_oid)
{
  gboolean changed = FALSE;
  gboolean committed = FALSE;
  int result;

  if (!turbovas_control_start_operator_session (operator_uuid))
    return 99;

  result = manage_configure_diagnostic_nvt (config_uuid, nvt_oid, &changed,
                                            &committed);
  if (result == 0 || committed)
    log_event ("config", "Scan Config", config_uuid, "modified");
  else
    log_event_fail ("config", "Scan Config", config_uuid, "modified");

  turbovas_control_finish_operator_session ();
  return result;
}

static void
turbovas_control_serve_client (int client_socket)
{
  char request[TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1];
  char operator_uuid[37];
  char expected_snapshot_digest[65];
  char alert_uuid[37];
  char created_uuid[37];
  char config_uuid[37];
  char schedule_uuid[37];
  char tag_uuid[37];
  char task_uuid[37];
  char source_user_uuid[37];
  char nvt_oid[TURBOVAS_CONTROL_NVT_OID_MAX_BYTES + 1];
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];
  const char *expected_secret;
  const char *result_response;
  gint64 actual_total = 0;
  gint64 expected_total = 0;
  size_t expected_secret_len;
  size_t request_len = 0;
  int result = -1;
  turbovas_control_schedule_create_request_t schedule_request = {0};
  turbovas_control_schedule_modify_request_t schedule_modify_request = {0};
  turbovas_control_credential_create_request_t credential_request = {0};
  turbovas_control_alert_email_create_request_t alert_request = {0};
  turbovas_control_alert_deliver_report_request_t alert_delivery_request = {0};
  turbovas_control_alert_smb_create_request_t smb_alert_request = {0};
  turbovas_control_alert_start_task_create_request_t start_task_alert_request =
    {0};
  turbovas_control_alert_scp_create_request_t scp_alert_request = {0};
  turbovas_control_alert_syslog_create_request_t syslog_alert_request = {0};
  turbovas_control_alert_snmp_create_request_t snmp_alert_request = {0};
  turbovas_control_tag_create_request_t tag_create_request = {0};
  turbovas_control_tag_modify_request_t tag_modify_request = {0};
  turbovas_control_user_password_change_request_t password_change_request = {0};
  turbovas_control_user_create_request_t user_create_request = {0};
  turbovas_control_user_modify_request_t user_modify_request = {0};
  turbovas_control_user_delete_request_t user_delete_request = {0};
  turbovas_control_user_setting_modify_request_t setting_modify_request = {0};
  memset (request, 0, sizeof (request));

  turbovas_control_set_timeouts (client_socket);
  if (turbovas_control_configured_secret (&expected_secret,
                                          &expected_secret_len)
      && turbovas_control_read_request (client_socket, request, &request_len))
    {
      if (turbovas_control_parse_user_create_request (
            request, request_len, expected_secret, expected_secret_len,
            operator_uuid, &user_create_request))
        {
          result = turbovas_control_create_user (operator_uuid,
                                                 &user_create_request,
                                                 created_uuid);
          result_response = turbovas_control_user_create_response (
            result, created_uuid, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_USER_CREATE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_USER_CREATE_COMMAND,
                          TURBOVAS_CONTROL_USER_CREATE_COMMAND_LENGTH) == 0)
        result_response = turbovas_control_user_create_response (-2, NULL,
                                                                 response);
      else if (turbovas_control_parse_user_modify_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &user_modify_request))
        {
          result = turbovas_control_modify_user (operator_uuid,
                                                 &user_modify_request);
          result_response = turbovas_control_user_modify_response (result);
        }
      else if (request_len >= TURBOVAS_CONTROL_USER_MODIFY_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_USER_MODIFY_COMMAND,
                          TURBOVAS_CONTROL_USER_MODIFY_COMMAND_LENGTH) == 0)
        result_response = turbovas_control_user_modify_response (-2);
      else if (turbovas_control_parse_user_delete_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &user_delete_request))
        {
          result = turbovas_control_delete_user (operator_uuid,
                                                 &user_delete_request);
          result_response = turbovas_control_user_delete_response (result);
        }
      else if (request_len >= TURBOVAS_CONTROL_USER_DELETE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_USER_DELETE_COMMAND,
                          TURBOVAS_CONTROL_USER_DELETE_COMMAND_LENGTH) == 0)
        result_response = turbovas_control_user_delete_response (-2);
      else if (turbovas_control_parse_user_clone_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, source_user_uuid))
        {
          result = turbovas_control_clone_user (operator_uuid,
                                                source_user_uuid,
                                                created_uuid);
          result_response = turbovas_control_user_clone_response (
            result, created_uuid, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_USER_CLONE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_USER_CLONE_COMMAND,
                          TURBOVAS_CONTROL_USER_CLONE_COMMAND_LENGTH) == 0)
        result_response = turbovas_control_user_clone_response (-2, NULL,
                                                                 response);
      else if (turbovas_control_parse_user_password_change_request (
            request, request_len, expected_secret, expected_secret_len,
            operator_uuid, &password_change_request))
        {
          result = turbovas_control_change_user_password (
            operator_uuid, &password_change_request);
          result_response =
            turbovas_control_user_password_change_response (result);
        }
      else if (
        request_len >= TURBOVAS_CONTROL_USER_PASSWORD_CHANGE_COMMAND_LENGTH
        && memcmp (request, TURBOVAS_CONTROL_USER_PASSWORD_CHANGE_COMMAND,
                   TURBOVAS_CONTROL_USER_PASSWORD_CHANGE_COMMAND_LENGTH) == 0)
        result_response = turbovas_control_user_password_change_response (-2);
      else if (turbovas_control_parse_user_setting_modify_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &setting_modify_request))
        {
          result = turbovas_control_modify_user_setting (
            operator_uuid, &setting_modify_request);
          result_response =
            turbovas_control_user_setting_modify_response (result);
        }
      else if (
        request_len >= TURBOVAS_CONTROL_USER_SETTING_MODIFY_COMMAND_LENGTH
        && memcmp (request, TURBOVAS_CONTROL_USER_SETTING_MODIFY_COMMAND,
                   TURBOVAS_CONTROL_USER_SETTING_MODIFY_COMMAND_LENGTH) == 0)
        result_response = turbovas_control_user_setting_modify_response (-2);
      else if (turbovas_control_parse_scan_config_nvt_diagnostic_request (
            request, request_len, expected_secret, expected_secret_len,
            operator_uuid, config_uuid, nvt_oid))
        {
          result = turbovas_control_configure_diagnostic_nvt (
            operator_uuid, config_uuid, nvt_oid);
          result_response =
            turbovas_control_scan_config_nvt_diagnostic_response (result);
        }
      else if (
        request_len
          >= TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND_LENGTH
        && memcmp (
             request, TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND,
             TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND_LENGTH)
             == 0)
        result_response =
          turbovas_control_scan_config_nvt_diagnostic_response (-2);
      else if (turbovas_control_parse_trash_empty_request
            (request, request_len, expected_secret, expected_secret_len,
             operator_uuid, &expected_total, expected_snapshot_digest))
        {
          result = turbovas_control_empty_trash (operator_uuid,
                                                  expected_total,
                                                  expected_snapshot_digest,
                                                  &actual_total);
          result_response = turbovas_control_trash_empty_response
                              (result, actual_total, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND,
                          TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND_LENGTH) == 0)
        result_response = turbovas_control_trash_empty_response (-1, 0,
                                                                  response);
      else if (turbovas_control_parse_tag_create_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &tag_create_request))
        {
          result = turbovas_control_create_tag (
            operator_uuid, &tag_create_request, created_uuid);
          result_response = turbovas_control_tag_create_response (
            result, created_uuid, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_TAG_CREATE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_TAG_CREATE_COMMAND,
                          TURBOVAS_CONTROL_TAG_CREATE_COMMAND_LENGTH) == 0)
        result_response =
          turbovas_control_tag_create_response (-2, NULL, response);
      else if (turbovas_control_parse_tag_modify_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, tag_uuid, &tag_modify_request))
        {
          result = turbovas_control_modify_tag (
            operator_uuid, tag_uuid, &tag_modify_request);
          result_response =
            turbovas_control_tag_modify_response (result, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_TAG_MODIFY_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_TAG_MODIFY_COMMAND,
                          TURBOVAS_CONTROL_TAG_MODIFY_COMMAND_LENGTH) == 0)
        result_response = turbovas_control_tag_modify_response (-2, response);
      else if (turbovas_control_parse_task_clone_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, task_uuid))
        {
          result = turbovas_control_clone_task (operator_uuid, task_uuid,
                                                created_uuid);
          result_response = turbovas_control_task_clone_response (
            result, created_uuid, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_TASK_CLONE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_TASK_CLONE_COMMAND,
                          TURBOVAS_CONTROL_TASK_CLONE_COMMAND_LENGTH)
                    == 0)
        result_response =
          turbovas_control_task_clone_response (-2, NULL, response);
      else if (turbovas_control_parse_request (request, request_len,
                                          expected_secret,
                                          expected_secret_len,
                                          operator_uuid, task_uuid))
        {
          result = turbovas_control_stop_task (operator_uuid, task_uuid);
          result_response = turbovas_control_response (result);
        }
      else if (turbovas_control_parse_schedule_create_request
                 (request, request_len, expected_secret, expected_secret_len,
                  operator_uuid, &schedule_request))
        {
          result = turbovas_control_create_schedule (operator_uuid,
                                                      &schedule_request,
                                                      created_uuid);
          result_response = turbovas_control_schedule_create_response
                              (result, created_uuid, response);
        }
      else if (turbovas_control_parse_credential_create_request
                 (request, request_len, expected_secret, expected_secret_len,
                  operator_uuid, &credential_request))
        {
          result = turbovas_control_create_credential (operator_uuid,
                                                        &credential_request,
                                                        created_uuid);
          result_response = turbovas_control_credential_create_response
                              (result, created_uuid, response);
        }
      else if (turbovas_control_parse_schedule_modify_request
                 (request, request_len, expected_secret, expected_secret_len,
                  operator_uuid, schedule_uuid, &schedule_modify_request))
        {
          result = turbovas_control_modify_schedule (operator_uuid,
                                                      schedule_uuid,
                                                      &schedule_modify_request);
          result_response = turbovas_control_schedule_modify_response
                              (result, response);
        }
      else if (turbovas_control_parse_alert_email_create_request
                 (request, request_len, expected_secret, expected_secret_len,
                  operator_uuid, &alert_request))
        {
          result = turbovas_control_create_alert_email (operator_uuid,
                                                        &alert_request,
                                                        created_uuid);
          result_response = turbovas_control_alert_create_response (
            result, created_uuid, response);
        }
      else if (request_len
                 >= TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH
               && memcmp (request,
                          TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND,
                          TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH)
                    == 0)
        result_response =
          turbovas_control_alert_create_response (-2, NULL, response);
      else if (turbovas_control_parse_alert_start_task_create_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &start_task_alert_request))
        {
          result = turbovas_control_create_alert_start_task (
            operator_uuid, &start_task_alert_request, created_uuid);
          result_response = turbovas_control_alert_start_task_create_response (
            result, created_uuid, response);
        }
      else if (request_len
                 >= TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND_LENGTH
               && memcmp (
                    request, TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND,
                    TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND_LENGTH)
                    == 0)
        result_response = turbovas_control_alert_start_task_create_response (
          -2, NULL, response);
      else if (turbovas_control_parse_alert_deliver_report_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &alert_delivery_request))
        {
          result = turbovas_control_deliver_alert_report (
            operator_uuid, &alert_delivery_request);
          result_response =
            turbovas_control_alert_deliver_report_response (result);
        }
      else if (
        request_len >= TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND_LENGTH
        && memcmp (request, TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND,
                   TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND_LENGTH)
             == 0)
        result_response = "-2 malformed\n";
      else if (turbovas_control_parse_alert_test_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, alert_uuid))
        {
          result = turbovas_control_test_alert (operator_uuid, alert_uuid);
          result_response = turbovas_control_alert_test_response (result);
        }
      else if (request_len >= TURBOVAS_CONTROL_ALERT_TEST_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_ALERT_TEST_COMMAND,
                          TURBOVAS_CONTROL_ALERT_TEST_COMMAND_LENGTH) == 0)
        result_response = "-2 malformed\n";
      else if (turbovas_control_parse_alert_syslog_create_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &syslog_alert_request))
        {
          result = turbovas_control_create_alert_syslog (
            operator_uuid, &syslog_alert_request, created_uuid);
          result_response = turbovas_control_alert_create_response (
            result, created_uuid, response);
        }
      else if (request_len
                 >= TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND,
                          TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND_LENGTH)
                    == 0)
        result_response =
          turbovas_control_alert_create_response (-2, NULL, response);
      else if (turbovas_control_parse_alert_snmp_create_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &snmp_alert_request))
        {
          result = turbovas_control_create_alert_snmp (
            operator_uuid, &snmp_alert_request, created_uuid);
          result_response = turbovas_control_alert_create_response (
            result, created_uuid, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND,
                          TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND_LENGTH)
                    == 0)
        result_response =
          turbovas_control_alert_create_response (-2, NULL, response);
      else if (turbovas_control_parse_alert_scp_create_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &scp_alert_request))
        {
          result = turbovas_control_create_alert_scp (
            operator_uuid, &scp_alert_request, created_uuid);
          result_response = turbovas_control_alert_create_response (
            result, created_uuid, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND,
                          TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND_LENGTH)
                    == 0)
        result_response =
          turbovas_control_alert_create_response (-2, NULL, response);
      else if (turbovas_control_parse_alert_smb_create_request (
                 request, request_len, expected_secret, expected_secret_len,
                 operator_uuid, &smb_alert_request))
        {
          result = turbovas_control_create_alert_smb (
            operator_uuid, &smb_alert_request, created_uuid);
          result_response = turbovas_control_alert_create_response (
            result, created_uuid, response);
        }
      else if (request_len >= TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND,
                          TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND_LENGTH)
                    == 0)
        result_response =
          turbovas_control_alert_create_response (-2, NULL, response);
      else if (request_len >= TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND,
                          TURBOVAS_CONTROL_SCHEDULE_MODIFY_COMMAND_LENGTH)
                    == 0)
        result_response = turbovas_control_schedule_modify_response (-2,
                                                                      response);
      else if (request_len >= TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND_LENGTH
               && memcmp (request, TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND,
                          TURBOVAS_CONTROL_CREDENTIAL_CREATE_COMMAND_LENGTH)
                    == 0)
        result_response = turbovas_control_credential_create_response (-2,
                                                                        NULL,
                                                                        response);
      else
        result_response = turbovas_control_response (result);
    }
  else if (
    request_len >= TURBOVAS_CONTROL_USER_CREATE_COMMAND_LENGTH
    && memcmp (request, TURBOVAS_CONTROL_USER_CREATE_COMMAND,
               TURBOVAS_CONTROL_USER_CREATE_COMMAND_LENGTH) == 0)
    result_response = turbovas_control_user_create_response (-2, NULL,
                                                              response);
  else if (request_len >= TURBOVAS_CONTROL_USER_MODIFY_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_USER_MODIFY_COMMAND,
                      TURBOVAS_CONTROL_USER_MODIFY_COMMAND_LENGTH) == 0)
    result_response = turbovas_control_user_modify_response (-2);
  else if (request_len >= TURBOVAS_CONTROL_USER_DELETE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_USER_DELETE_COMMAND,
                      TURBOVAS_CONTROL_USER_DELETE_COMMAND_LENGTH) == 0)
    result_response = turbovas_control_user_delete_response (-2);
  else if (request_len >= TURBOVAS_CONTROL_USER_CLONE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_USER_CLONE_COMMAND,
                      TURBOVAS_CONTROL_USER_CLONE_COMMAND_LENGTH) == 0)
    result_response = turbovas_control_user_clone_response (-2, NULL,
                                                             response);
  else if (
    request_len >= TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND_LENGTH
    && memcmp (request, TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND,
               TURBOVAS_CONTROL_SCAN_CONFIG_NVT_DIAGNOSTIC_COMMAND_LENGTH)
         == 0)
    result_response =
      turbovas_control_scan_config_nvt_diagnostic_response (-2);
  else if (request_len >= TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND,
                      TURBOVAS_CONTROL_TRASH_EMPTY_COMMAND_LENGTH) == 0)
    result_response = turbovas_control_trash_empty_response (-1, 0, response);
  else if (request_len >= TURBOVAS_CONTROL_TAG_CREATE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_TAG_CREATE_COMMAND,
                      TURBOVAS_CONTROL_TAG_CREATE_COMMAND_LENGTH) == 0)
    result_response =
      turbovas_control_tag_create_response (-2, NULL, response);
  else if (request_len >= TURBOVAS_CONTROL_TAG_MODIFY_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_TAG_MODIFY_COMMAND,
                      TURBOVAS_CONTROL_TAG_MODIFY_COMMAND_LENGTH) == 0)
    result_response = turbovas_control_tag_modify_response (-2, response);
  else if (request_len >= TURBOVAS_CONTROL_TASK_CLONE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_TASK_CLONE_COMMAND,
                      TURBOVAS_CONTROL_TASK_CLONE_COMMAND_LENGTH)
                == 0)
    result_response = turbovas_control_task_clone_response (-2, NULL, response);
  else if (request_len >= TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND,
                      TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH)
                == 0)
    result_response =
      turbovas_control_alert_create_response (-2, NULL, response);
  else if (request_len
             >= TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND,
                      TURBOVAS_CONTROL_ALERT_START_TASK_CREATE_COMMAND_LENGTH)
                == 0)
    result_response =
      turbovas_control_alert_start_task_create_response (-2, NULL, response);
  else if (
    request_len >= TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND_LENGTH
    && memcmp (request, TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND,
               TURBOVAS_CONTROL_ALERT_DELIVER_REPORT_COMMAND_LENGTH)
         == 0)
    result_response = "-2 malformed\n";
  else if (request_len >= TURBOVAS_CONTROL_ALERT_TEST_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_ALERT_TEST_COMMAND,
                      TURBOVAS_CONTROL_ALERT_TEST_COMMAND_LENGTH) == 0)
    result_response = "-2 malformed\n";
  else if (request_len >= TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND,
                      TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND_LENGTH)
                == 0)
    result_response =
      turbovas_control_alert_create_response (-2, NULL, response);
  else if (request_len >= TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND,
                      TURBOVAS_CONTROL_ALERT_SYSLOG_CREATE_COMMAND_LENGTH)
                == 0)
    result_response =
      turbovas_control_alert_create_response (-2, NULL, response);
  else if (request_len >= TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND,
                      TURBOVAS_CONTROL_ALERT_SNMP_CREATE_COMMAND_LENGTH)
                == 0)
    result_response =
      turbovas_control_alert_create_response (-2, NULL, response);
  else if (request_len >= TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND,
                      TURBOVAS_CONTROL_ALERT_SMB_CREATE_COMMAND_LENGTH)
                == 0)
    result_response =
      turbovas_control_alert_create_response (-2, NULL, response);
  else
    result_response = turbovas_control_response (result);

  (void) turbovas_control_write_all (client_socket,
                                      result_response);
  turbovas_control_schedule_create_request_clear (&schedule_request);
  turbovas_control_schedule_modify_request_clear (&schedule_modify_request);
  turbovas_control_credential_create_request_clear (&credential_request);
  turbovas_control_alert_email_create_request_clear (&alert_request);
  turbovas_control_alert_deliver_report_request_clear (
    &alert_delivery_request);
  turbovas_control_alert_smb_create_request_clear (&smb_alert_request);
  turbovas_control_alert_start_task_create_request_clear (
    &start_task_alert_request);
  turbovas_control_alert_scp_create_request_clear (&scp_alert_request);
  turbovas_control_secure_clear (alert_uuid, sizeof (alert_uuid));
  turbovas_control_alert_syslog_create_request_clear (&syslog_alert_request);
  turbovas_control_alert_snmp_create_request_clear (&snmp_alert_request);
  turbovas_control_tag_create_request_clear (&tag_create_request);
  turbovas_control_tag_modify_request_clear (&tag_modify_request);
  turbovas_control_user_password_change_request_clear (
    &password_change_request);
  turbovas_control_user_create_request_clear (&user_create_request);
  turbovas_control_user_modify_request_clear (&user_modify_request);
  turbovas_control_secure_clear (&user_delete_request,
                                 sizeof (user_delete_request));
  turbovas_control_user_setting_modify_request_clear (&setting_modify_request);
  if (request_len <= TURBOVAS_CONTROL_MAX_REQUEST_BYTES)
    {
      turbovas_control_secure_clear (request, request_len);
    }
}

void
turbovas_control_accept_and_fork (int server_socket, int manager_socket,
                                  int manager_socket_2,
                                  sigset_t *sigmask_normal)
{
  int client_socket;
  pid_t pid;

  while ((client_socket = accept (server_socket, NULL, NULL)) == -1)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      g_warning ("%s: failed to accept control connection: %s", __func__,
                 strerror (errno));
      return;
    }

  pid = fork ();
  if (pid == -1)
    {
      g_warning ("%s: failed to fork control handler: %s", __func__,
                 strerror (errno));
      close (client_socket);
      return;
    }
  if (pid != 0)
    {
      close (client_socket);
      return;
    }

  if (sigmask_normal)
    pthread_sigmask (SIG_SETMASK, sigmask_normal, NULL);
  close (server_socket);
  if (manager_socket > -1 && manager_socket != server_socket)
    close (manager_socket);
  if (manager_socket_2 > -1 && manager_socket_2 != server_socket
      && manager_socket_2 != manager_socket)
    close (manager_socket_2);
  turbovas_control_serve_client (client_socket);
  close (client_socket);
  _exit (EXIT_SUCCESS);
}
