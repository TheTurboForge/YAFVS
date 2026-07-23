/* Copyright (C) 2009-2022 Greenbone AG
 * YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SSH key generation for credentials.
 */

#include "credential_key.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gvm/util/fileutils.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Prepare an isolated session for SSH_ASKPASS.
 *
 * This callback runs between fork and exec, so it uses only async-signal-safe
 * operations.
 *
 * @param[in] user_data  Unused.
 */
static void
ssh_key_child_setup (gpointer user_data)
{
  (void) user_data;
  if (setsid () == -1)
    _exit (127);
}

/**
 * @brief Write a complete buffer to a descriptor.
 *
 * @param[in] fd      Descriptor.
 * @param[in] buffer  Buffer.
 * @param[in] length  Buffer length.
 *
 * @return TRUE on success, FALSE on failure.
 */
static gboolean
write_all (int fd, const char *buffer, size_t length)
{
  while (length)
    {
      ssize_t written = write (fd, buffer, length);

      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0)
        return FALSE;
      buffer += written;
      length -= (size_t) written;
    }
  return TRUE;
}

/**
 * @brief Supply the passphrase twice for ssh-keygen's confirmation prompts.
 *
 * @param[in] fd          ssh-keygen standard input.
 * @param[in] passphrase  Passphrase.
 *
 * @return TRUE on success, FALSE on failure.
 */
static gboolean
write_passphrase (int fd, const char *passphrase)
{
  sigset_t mask;
  sigset_t old_mask;
  sigset_t pending;
  struct timespec no_wait = {0, 0};
  gboolean already_pending = FALSE;
  gboolean written;
  int mask_error;
  size_t length = strlen (passphrase);

  sigemptyset (&mask);
  sigaddset (&mask, SIGPIPE);
  mask_error = pthread_sigmask (SIG_BLOCK, &mask, &old_mask);
  if (mask_error)
    {
      errno = mask_error;
      return FALSE;
    }
  if (sigpending (&pending) == 0)
    already_pending = sigismember (&pending, SIGPIPE) == 1;

  written = write_all (fd, passphrase, length) && write_all (fd, "\n", 1)
            && write_all (fd, passphrase, length) && write_all (fd, "\n", 1);

  if (!written && errno == EPIPE && !already_pending)
    while (sigtimedwait (&mask, NULL, &no_wait) == -1 && errno == EINTR)
      continue;

  mask_error = pthread_sigmask (SIG_SETMASK, &old_mask, NULL);
  if (mask_error)
    {
      errno = mask_error;
      return FALSE;
    }
  return written;
}

/**
 * @brief Create an SSH key for local security checks.
 *
 * Forks and creates a key for local checks with ssh-keygen. The passphrase is
 * supplied to SSH_ASKPASS over standard input, rather than a command line,
 * environment value, or persistent file. A directory will be created if it
 * does not exist.
 *
 * @param[in]  comment     Comment to use.
 * @param[in]  passphrase  Passphrase for key, must be longer than 4 characters.
 * @param[in]  privpath    Filename of the key file.
 *
 * @return 0 if successful, -1 otherwise.
 */
static int
create_ssh_key (const char *comment, const char *passphrase,
                const char *privpath)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status = 0;
  GPid child_pid = 0;
  gint child_input = -1;
  gchar *dir;
  gchar *askpass_path = NULL;
  gchar **environment = NULL;
  gboolean passphrase_written = FALSE;
  gchar *argv[] = {
    (gchar *) "ssh-keygen", (gchar *) "-q", (gchar *) "-t",
    (gchar *) "rsa",        (gchar *) "-f", (gchar *) privpath,
    (gchar *) "-C",         (gchar *) comment, NULL,
  };

  if (!comment || comment[0] == '\0')
    {
      g_warning ("%s: comment must be set", __func__);
      return -1;
    }
  if (!passphrase || strlen (passphrase) < 5)
    {
      g_warning ("%s: password must be longer than 4 characters", __func__);
      return -1;
    }
  if (strchr (passphrase, '\n') || strchr (passphrase, '\r'))
    {
      g_warning ("%s: password must not contain line breaks", __func__);
      return -1;
    }

  dir = g_path_get_dirname (privpath);
  if (g_mkdir_with_parents (dir, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to access %s", __func__, dir);
      g_free (dir);
      return -1;
    }

  askpass_path = g_build_filename (dir, ".yafvs-ssh-askpass", NULL);
  if (!g_file_set_contents (
        askpass_path,
        "#!/bin/sh\n"
        "IFS= read -r value || exit 1\n"
        "printf '%s\\n' \"$value\"\n",
        -1, &err)
      || g_chmod (askpass_path, 0700))
    {
      g_warning ("%s: failed to create SSH askpass helper: %s", __func__,
                 err ? err->message : g_strerror (errno));
      g_clear_error (&err);
      goto cleanup;
    }

  environment = g_get_environ ();
  environment =
    g_environ_setenv (environment, "SSH_ASKPASS", askpass_path, TRUE);
  environment =
    g_environ_setenv (environment, "SSH_ASKPASS_REQUIRE", "force", TRUE);
  environment = g_environ_setenv (environment, "DISPLAY", ":0", TRUE);
  g_debug ("command: ssh-keygen -q -t rsa -f %s -C \"%s\"", privpath,
           comment);

  if (!g_spawn_async_with_pipes (
        NULL, argv, environment,
        G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD, ssh_key_child_setup,
        NULL, &child_pid, &child_input, NULL, NULL, &err))
    {
      g_warning ("%s: failed to start ssh-keygen: %s", __func__,
                 err ? err->message : "unknown error");
      g_clear_error (&err);
      goto cleanup;
    }

  passphrase_written = write_passphrase (child_input, passphrase);
  if (!passphrase_written)
    g_warning ("%s: failed to supply ssh-keygen passphrase", __func__);
  close (child_input);
  child_input = -1;

  while (waitpid (child_pid, &exit_status, 0) == -1)
    {
      if (errno != EINTR)
        {
          g_warning ("%s: failed to wait for ssh-keygen: %s", __func__,
                     g_strerror (errno));
          goto cleanup;
        }
    }
  g_spawn_close_pid (child_pid);
  child_pid = 0;

  if (!passphrase_written || !WIFEXITED (exit_status)
      || WEXITSTATUS (exit_status))
    {
      g_warning ("%s: ssh-keygen failed", __func__);
      goto cleanup;
    }

  g_strfreev (environment);
  environment = NULL;
  g_unlink (askpass_path);
  g_free (askpass_path);
  g_free (dir);
  g_free (astdout);
  g_free (astderr);
  return 0;

cleanup:
  if (child_input >= 0)
    close (child_input);
  if (child_pid)
    {
      while (waitpid (child_pid, NULL, 0) == -1 && errno == EINTR)
        continue;
      g_spawn_close_pid (child_pid);
    }
  g_strfreev (environment);
  if (askpass_path)
    g_unlink (askpass_path);
  g_free (askpass_path);
  g_free (dir);
  g_free (astdout);
  g_free (astderr);
  return -1;
}

/**
 * @brief Create local security check keys.
 *
 * @param[in]   password     Password.
 * @param[out]  private_key  Private key.
 *
 * @return 0 success, -1 error.
 */
int
credential_ssh_key_create (const gchar *password, gchar **private_key)
{
  GError *error;
  gsize length;
  char key_dir[] = "/tmp/openvas_key_XXXXXX";
  gchar *key_path = NULL;
  int ret = -1;

  if (mkdtemp (key_dir) == NULL)
    return -1;

  key_path = g_build_filename (key_dir, "key", NULL);
  if (create_ssh_key ("Key generated by GVM", password, key_path))
    goto free_exit;

  error = NULL;
  g_file_get_contents (key_path, private_key, &length, &error);
  if (error)
    {
      g_error_free (error);
      goto free_exit;
    }
  ret = 0;

free_exit:
  g_free (key_path);
  gvm_file_remove_recurse (key_dir);
  return ret;
}
