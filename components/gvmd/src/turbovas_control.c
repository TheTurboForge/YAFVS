/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Private TurboVAS control listener.
 */

#include "turbovas_control.h"

#include <errno.h>
#include <glib.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "manage.h"
#include "manage_alerts.h"
#include "manage_schedules.h"
#include "manage_users.h"
#include "gmp_base.h"

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "md   control"

#define TURBOVAS_CONTROL_SECRET_ENV "TURBOVAS_GVMD_CONTROL_SECRET"
#define TURBOVAS_CONTROL_SECRET_MIN_BYTES 32
#define TURBOVAS_CONTROL_SECRET_MAX_BYTES 128
#define TURBOVAS_CONTROL_STOP_MAX_REQUEST_BYTES 256
#define TURBOVAS_CONTROL_MAX_REQUEST_BYTES 65536
#define TURBOVAS_CONTROL_MAX_RESPONSE_BYTES 64
#define TURBOVAS_CONTROL_TIMEOUT_SECONDS 5
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
#define TURBOVAS_CONTROL_ALERT_NAME_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_COMMENT_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_STATUS_MAX_BYTES 32
#define TURBOVAS_CONTROL_ALERT_ADDRESS_MAX_BYTES 4096
#define TURBOVAS_CONTROL_ALERT_SUBJECT_MAX_BYTES 80
#define TURBOVAS_CONTROL_ALERT_MESSAGE_MAX_BYTES 2000
#define TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES 36

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
  gchar *report_config_uuid;
  gchar *message;
  gboolean active;
  unsigned int notice;
} turbovas_control_alert_email_create_request_t;

static gboolean
turbovas_control_decode_base64_field (const char *, size_t, size_t, gboolean,
                                      gchar **);

static gboolean
turbovas_control_next_field (const char **, const char *, const char **,
                             size_t *);

static void
turbovas_control_secure_free (gchar *);

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
  turbovas_control_secure_free (request->report_config_uuid);
  turbovas_control_secure_free (request->message);
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
               (field, field_len, TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES, FALSE,
                &alert->report_config_uuid)
          && turbovas_control_next_field (&cursor, end, &field, &field_len)
          && turbovas_control_decode_base64_field
               (field, field_len, TURBOVAS_CONTROL_ALERT_MESSAGE_MAX_BYTES,
                FALSE, &alert->message)
          && cursor == end
          && turbovas_control_alert_status_is_valid (alert->status)
          && turbovas_control_optional_uuid_is_valid
               (alert->recipient_credential_uuid)
          && turbovas_control_optional_uuid_is_valid (alert->report_format_uuid)
          && turbovas_control_optional_uuid_is_valid (alert->report_config_uuid)
          && ((alert->notice == 1
               && alert->report_format_uuid[0] == '\0'
               && alert->report_config_uuid[0] == '\0')
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
turbovas_control_alert_email_create_response
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
      case 12: status = "12 invalid_send_host\n"; break;
      case 13: status = "13 invalid_send_port\n"; break;
      case 14: status = "14 send_format_not_found\n"; break;
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
      case 50: status = "50 invalid_tp_credential\n"; break;
      case 51: status = "51 invalid_tp_host\n"; break;
      case 52: status = "52 invalid_tp_certificate\n"; break;
      case 53: status = "53 invalid_tp_tls\n"; break;
      case 60: status = "60 recipient_credential_not_found\n"; break;
      case 61: status = "61 invalid_recipient_credential\n"; break;
      case 70: status = "70 vfire_credential_not_found\n"; break;
      case 71: status = "71 invalid_vfire_credential\n"; break;
      case 80: status = "80 sourcefire_credential_not_found\n"; break;
      case 81: status = "81 invalid_sourcefire_credential\n"; break;
      case 90: status = "90 report_format_not_found\n"; break;
      case 91: status = "91 report_config_not_found\n"; break;
      case 92: status = "92 report_config_mismatch\n"; break;
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
      if (request->report_config_uuid[0])
        turbovas_control_array_add_data (method_data, "notice_report_config",
                                         request->report_config_uuid);
    }
  else if (request->notice == 2)
    {
      turbovas_control_array_add_data (method_data, "notice_attach_format",
                                       request->report_format_uuid);
      if (request->report_config_uuid[0])
        turbovas_control_array_add_data (method_data, "notice_attach_config",
                                         request->report_config_uuid);
    }
  if (request->message[0])
    turbovas_control_array_add_data (method_data, "message", request->message);
  array_terminate (condition_data);
  array_terminate (event_data);
  array_terminate (method_data);

  result = create_alert_email_with_report_refs
             (request->name, request->comment, active, event_data,
              condition_data, method_data, request->recipient_credential_uuid,
              request->report_format_uuid, request->report_config_uuid,
              &alert);
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
                              NULL, NULL, NULL, NULL, NULL,
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

static void
turbovas_control_serve_client (int client_socket)
{
  char request[TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1];
  char operator_uuid[37];
  char created_uuid[37];
  char schedule_uuid[37];
  char task_uuid[37];
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];
  const char *expected_secret;
  const char *result_response;
  size_t expected_secret_len;
  size_t request_len = 0;
  int result = -1;
  turbovas_control_schedule_create_request_t schedule_request = {0};
  turbovas_control_schedule_modify_request_t schedule_modify_request = {0};
  turbovas_control_credential_create_request_t credential_request = {0};
  turbovas_control_alert_email_create_request_t alert_request = {0};
  memset (request, 0, sizeof (request));

  turbovas_control_set_timeouts (client_socket);
  if (turbovas_control_configured_secret (&expected_secret,
                                          &expected_secret_len)
      && turbovas_control_read_request (client_socket, request, &request_len))
    {
      if (turbovas_control_parse_request (request, request_len,
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
          result_response = turbovas_control_alert_email_create_response
                              (result, created_uuid, response);
        }
      else if (request_len
                 >= TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH
               && memcmp (request,
                          TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND,
                          TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH)
                    == 0)
        result_response = turbovas_control_alert_email_create_response
                            (-2, NULL, response);
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
  else if (request_len >= TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH
           && memcmp (request, TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND,
                      TURBOVAS_CONTROL_ALERT_EMAIL_CREATE_COMMAND_LENGTH)
                == 0)
    result_response = turbovas_control_alert_email_create_response (-2, NULL,
                                                                    response);
  else
    result_response = turbovas_control_response (result);

  (void) turbovas_control_write_all (client_socket,
                                      result_response);
  turbovas_control_schedule_create_request_clear (&schedule_request);
  turbovas_control_schedule_modify_request_clear (&schedule_modify_request);
  turbovas_control_credential_create_request_clear (&credential_request);
  turbovas_control_alert_email_create_request_clear (&alert_request);
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
