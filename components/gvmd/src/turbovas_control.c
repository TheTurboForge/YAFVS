/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Private TurboVAS task-stop control listener.
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
#include "manage_users.h"

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "md   control"

#define TURBOVAS_CONTROL_SECRET_ENV "TURBOVAS_GVMD_CONTROL_SECRET"
#define TURBOVAS_CONTROL_SECRET_MIN_BYTES 32
#define TURBOVAS_CONTROL_SECRET_MAX_BYTES 128
#define TURBOVAS_CONTROL_MAX_REQUEST_BYTES 256
#define TURBOVAS_CONTROL_TIMEOUT_SECONDS 5

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

  if (request_len > TURBOVAS_CONTROL_MAX_REQUEST_BYTES
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
turbovas_control_read_request (int socket, char request[257],
                               size_t *request_len)
{
  size_t length = 0;

  while (length < TURBOVAS_CONTROL_MAX_REQUEST_BYTES)
    {
      ssize_t ret = read (socket, request + length,
                          TURBOVAS_CONTROL_MAX_REQUEST_BYTES - length);
      char *newline;

      if (ret > 0)
        {
          length += ret;
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

static int
turbovas_control_stop_task (const char *operator_uuid, const char *task_uuid)
{
  gchar *operator_uuid_copy;
  gchar *operator_name;
  int result;

  reinit_manage_process ();

  operator_uuid_copy = g_strdup (operator_uuid);
  operator_name = user_name (operator_uuid_copy);
  if (operator_name == NULL)
    {
      g_free (operator_uuid_copy);
      cleanup_manage_process (FALSE);
      return 99;
    }
  current_credentials.uuid = operator_uuid_copy;
  current_credentials.username = operator_name;
  manage_session_init (current_credentials.uuid);

  result = stop_task (task_uuid);

  g_free (current_credentials.username);
  g_free (current_credentials.uuid);
  current_credentials.username = NULL;
  current_credentials.uuid = NULL;
  cleanup_manage_process (FALSE);

  return result;
}

static void
turbovas_control_serve_client (int client_socket)
{
  char request[TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1];
  char operator_uuid[37];
  char task_uuid[37];
  const char *expected_secret;
  size_t expected_secret_len;
  size_t request_len;
  int result = -1;

  turbovas_control_set_timeouts (client_socket);
  if (turbovas_control_configured_secret (&expected_secret,
                                          &expected_secret_len)
      && turbovas_control_read_request (client_socket, request, &request_len)
      && turbovas_control_parse_request (request, request_len,
                                         expected_secret,
                                         expected_secret_len,
                                         operator_uuid, task_uuid))
    result = turbovas_control_stop_task (operator_uuid, task_uuid);

  (void) turbovas_control_write_all (client_socket,
                                      turbovas_control_response (result));
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
