/* Copyright (C) 2020-2022 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Alerts.
 *
 * General functions for managing alerts.
 */

#include "manage_alerts.h"
#include "debug_utils.h"
#include "manage_filters.h"
#include "manage_report_formats.h"
#include "manage_settings.h"
#include "manage_sql.h"
#include "manage_sql_alerts.h"
#include "manage_acl.h"
#include "manage_sql_report_formats.h"
#include "manage_sql_resources.h"
#include "manage_users.h"
#include "yafvs_control.h"

#include <bsd/unistd.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gvm/gmp/gmp.h>
#include <gvm/util/fileutils.h>
#include <gvm/util/gpgmeutils.h>
#include <gvm/util/uuidutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

static void
alert_secure_clear (void *value, size_t length)
{
  volatile unsigned char *cursor = value;

  if (value == NULL)
    return;
  while (length--)
    *cursor++ = 0;
}

static void
alert_secure_gfree (gchar *value)
{
  if (value == NULL)
    return;
  alert_secure_clear (value, strlen (value));
  g_free (value);
}

static void
alert_secure_free (char *value)
{
  if (value == NULL)
    return;
  alert_secure_clear (value, strlen (value));
  free (value);
}

static void
alert_secure_gfree_bytes (gpointer value, gsize length)
{
  alert_secure_clear (value, length);
  g_free (value);
}

static int
close_alert_fd (int *fd)
{
  int ret = 0;
  if (fd && *fd >= 0)
    {
      ret = close (*fd);
      *fd = -1;
    }
  return ret;
}

static int
write_all (int fd, const char *content, size_t size)
{
  size_t written = 0;
  while (written < size)
    {
      ssize_t ret = write (fd, content + written, size - written);
      if (ret < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (ret == 0)
        return -1;
      written += ret;
    }
  return 0;
}

static int
open_private_write (const char *path)
{
  return open (path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
}



/* Variables. */

/**
 * @brief Default max number of bytes of reports attached to email alerts.
 */
#define MAX_EMAIL_ATTACHMENT_SIZE 1048576

/**
 * @brief Maximum number of bytes of reports attached to email alerts.
 *
 * A value less or equal to 0 allows any size.
 */
static int max_email_attachment_size = MAX_EMAIL_ATTACHMENT_SIZE;

/**
 * @brief Get the max number of bytes of reports attached to email alerts.
 *
 * @return The size in bytes.
 */
int
get_max_email_attachment_size ()
{
  return max_email_attachment_size;
}

/**
 * @brief Set the max email attachment size.
 *
 * @param size The new size in bytes.
 */
void
set_max_email_attachment_size (int size)
{
  max_email_attachment_size = size;
}

/**
 * @brief Default max number of bytes of reports included in email alerts.
 */
#define MAX_EMAIL_INCLUDE_SIZE 20000

/**
 * @brief Maximum number of bytes of reports included in email alerts.
 *
 * A value less or equal to 0 allows any size.
 */
static int max_email_include_size = MAX_EMAIL_INCLUDE_SIZE;

/**
 * @brief Get the max number of bytes of reports included in email alerts.
 *
 * @return The size in bytes.
 */
int
get_max_email_include_size ()
{
  return max_email_include_size;
}

/**
 * @brief Set the max email include size.
 *
 * @param size The new size in bytes.
 */
void
set_max_email_include_size (int size)
{
  max_email_include_size = size;
}

/**
 * @brief Default max number of bytes of user-defined message in email alerts.
 */
#define MAX_EMAIL_MESSAGE_SIZE 2000

/**
 * @brief Maximum number of bytes of user-defined message text in email alerts.
 *
 * A value less or equal to 0 allows any size.
 */
static int max_email_message_size = MAX_EMAIL_MESSAGE_SIZE;

/**
 * @brief Get the max email message size.
 *
 * @return The size in bytes.
 */
int
get_max_email_message_size ()
{
  return max_email_message_size;
}

/**
 * @brief Set the max email message size.
 *
 * @param size The new size in bytes.
 */
void
set_max_email_message_size (int size)
{
  max_email_message_size = size;
}



/* Alert conditions. */

/**
 * @brief Get the name of an alert condition.
 *
 * @param[in]  condition  Condition.
 *
 * @return The name of the condition (for example, "Always").
 */
const char*
alert_condition_name (alert_condition_t condition)
{
  switch (condition)
    {
      case ALERT_CONDITION_ALWAYS:
        return "Always";
      case ALERT_CONDITION_FILTER_COUNT_AT_LEAST:
        return "Filter count at least";
      case ALERT_CONDITION_FILTER_COUNT_CHANGED:
        return "Filter count changed";
      case ALERT_CONDITION_SEVERITY_AT_LEAST:
        return "Severity at least";
      case ALERT_CONDITION_SEVERITY_CHANGED:
        return "Severity changed";
      default:
        return "Internal Error";
    }
}

/**
 * @brief Get a description of an alert condition.
 *
 * @param[in]  condition  Condition.
 * @param[in]  alert  Alert.
 *
 * @return Freshly allocated description of condition.
 */
gchar*
alert_condition_description (alert_condition_t condition,
                             alert_t alert)
{
  switch (condition)
    {
      case ALERT_CONDITION_ALWAYS:
        return g_strdup ("Always");
      case ALERT_CONDITION_FILTER_COUNT_AT_LEAST:
        {
          char *count;
          gchar *ret;

          count = alert_data (alert, "condition", "count");
          ret = g_strdup_printf ("Filter count at least %s",
                                 count ? count : "0");
          free (count);
          return ret;
        }
      case ALERT_CONDITION_FILTER_COUNT_CHANGED:
        return g_strdup ("Filter count changed");
      case ALERT_CONDITION_SEVERITY_AT_LEAST:
        {
          char *level = alert_data (alert, "condition", "severity");
          gchar *ret = g_strdup_printf ("Task severity is at least '%s'",
                                        level);
          free (level);
          return ret;
        }
      case ALERT_CONDITION_SEVERITY_CHANGED:
        {
          char *direction;
          direction = alert_data (alert, "condition", "direction");
          gchar *ret = g_strdup_printf ("Task severity %s", direction);
          free (direction);
          return ret;
        }
      default:
        return g_strdup ("Internal Error");
    }
}

/**
 * @brief Get an alert condition from a name.
 *
 * @param[in]  name  Condition name.
 *
 * @return The condition.
 */
alert_condition_t
alert_condition_from_name (const char* name)
{
  if (strcasecmp (name, "Always") == 0)
    return ALERT_CONDITION_ALWAYS;
  if (strcasecmp (name, "Filter count at least") == 0)
    return ALERT_CONDITION_FILTER_COUNT_AT_LEAST;
  if (strcasecmp (name, "Filter count changed") == 0)
    return ALERT_CONDITION_FILTER_COUNT_CHANGED;
  if (strcasecmp (name, "Severity at least") == 0)
    return ALERT_CONDITION_SEVERITY_AT_LEAST;
  if (strcasecmp (name, "Severity changed") == 0)
    return ALERT_CONDITION_SEVERITY_CHANGED;
  return ALERT_CONDITION_ERROR;
}



/* Alert methods. */

/**
 * @brief Get the name of an alert method.
 *
 * @param[in]  method  Method.
 *
 * @return The name of the method (for example, "Email" or "SNMP").
 */
const char*
alert_method_name (alert_method_t method)
{
  switch (method)
    {
      case ALERT_METHOD_EMAIL:       return "Email";
      case ALERT_METHOD_SCP:         return "SCP";
      case ALERT_METHOD_SMB:         return "SMB";
      case ALERT_METHOD_SNMP:        return "SNMP";
      case ALERT_METHOD_START_TASK:  return "Start Task";
      case ALERT_METHOD_SYSLOG:      return "Syslog";
      default:                       return "Internal Error";
    }
}

/**
 * @brief Get an alert method from a name.
 *
 * @param[in]  name  Method name.
 *
 * @return The method.
 */
alert_method_t
alert_method_from_name (const char* name)
{
  if (strcasecmp (name, "Email") == 0)
    return ALERT_METHOD_EMAIL;
  if (strcasecmp (name, "SCP") == 0)
    return ALERT_METHOD_SCP;
  if (strcasecmp (name, "SMB") == 0)
    return ALERT_METHOD_SMB;
  if (strcasecmp (name, "SNMP") == 0)
    return ALERT_METHOD_SNMP;
  if (strcasecmp (name, "Start Task") == 0)
    return ALERT_METHOD_START_TASK;
  if (strcasecmp (name, "Syslog") == 0)
    return ALERT_METHOD_SYSLOG;
  return ALERT_METHOD_ERROR;
}

/**
 * @brief Test an alert.
 *
 * @param[in]  alert_id    Alert UUID.
 * @param[out] script_message  Custom message from the alert script.
 *
 * @return 0 success, 1 failed to find alert, 2 failed to find task,
 *         99 permission denied, -1 error, -2 failed to find report format
 *         for alert, -3 failed to find filter for alert, -4 failed to find
 *         credential for alert, -5 alert script failed.
 */
int
manage_test_alert (const char *alert_id, gchar **script_message)
{
  int ret;
  alert_t alert;
  task_t task;
  report_t report;
  result_t result;
  char *task_id, *report_id;
  time_t now;
  char now_string[26];
  gchar *clean;

  if (acl_user_may ("test_alert") == 0)
    return 99;

  if (find_alert_with_permission (alert_id, &alert, "test_alert"))
    return -1;
  if (alert == 0)
    return 1;

  if (alert_event (alert) == EVENT_NEW_SECINFO
      || alert_event (alert) == EVENT_UPDATED_SECINFO)
    {
      char *alert_event_data;
      gchar *type;

      alert_event_data = alert_data (alert, "event", "secinfo_type");
      type = g_strdup_printf ("%s_example", alert_event_data ?: "NVT");
      free (alert_event_data);

      if (alert_event (alert) == EVENT_NEW_SECINFO)
        ret = manage_alert (alert_id, "0", EVENT_NEW_SECINFO, (void*) type,
                            script_message);
      else
        ret = manage_alert (alert_id, "0", EVENT_UPDATED_SECINFO, (void*) type,
                            script_message);

      g_free (type);

      return ret;
    }

  task = make_task (g_strdup ("Temporary Task for Alert"),
                    g_strdup (""),
                    0,  /* Exclude from assets. */
                    0); /* Skip event and log. */

  report_id = gvm_uuid_make ();
  if (report_id == NULL)
    return -1;
  task_uuid (task, &task_id);
  report = make_report (task, report_id, TASK_STATUS_DONE);

  result = make_result (task, "127.0.0.1", "localhost", "23/tcp",
                        "1.3.6.1.4.1.25623.1.0.10330", "Alarm",
                        "A telnet server seems to be running on this port.",
                        NULL);
  if (result)
    report_add_result (report, result);


  result = make_result (
              task, "127.0.0.1", "localhost", "general/tcp",
              "1.3.6.1.4.1.25623.1.0.103823", "Alarm",
              "IP,Host,Port,SSL/TLS-Version,Ciphers,Application-CPE\n"
              "127.0.0.1,localhost,443,TLSv1.1;TLSv1.2",
              NULL);
  if (result)
    report_add_result (report, result);

  now = time (NULL);
  if (strlen (ctime_r (&now, now_string)) == 0)
    {
      ret = -1;
      goto exit;
    }
  clean = g_strdup (now_string);
  if (clean[strlen (clean) - 1] == '\n')
    clean[strlen (clean) - 1] = '\0';
  set_task_start_time_ctime (task, g_strdup (clean));
  set_scan_start_time_ctime (report, g_strdup (clean));
  set_scan_host_start_time_ctime (report, "127.0.0.1", clean);

  insert_report_host_detail (report,
                             "127.0.0.1",
                             "nvt",
                             "1.3.6.1.4.1.25623.1.0.108577",
                             "",
                             "App",
                             "cpe:/a:openbsd:openssh:8.9p1",
                             "0123456789ABCDEF0123456789ABCDEF");

  insert_report_host_detail (report,
                             "127.0.0.1",
                             "nvt",
                             "1.3.6.1.4.1.25623.1.0.10330",
                             "Host Details",
                             "best_os_cpe",
                             "cpe:/o:canonical:ubuntu_linux:22.04",
                             "123456789ABCDEF0123456789ABCDEF0");

  set_scan_host_end_time_ctime (report, "127.0.0.1", clean);
  set_scan_end_time_ctime (report, clean);
  g_free (clean);
  ret = manage_alert (alert_id,
                      task_id,
                      EVENT_TASK_RUN_STATUS_CHANGED,
                      (void*) TASK_STATUS_DONE,
                      script_message);
 exit:
  /* No one should be running this task, so we don't worry about the lock.  We
   * could guarantee that no one runs the task, but this is a very rare case. */
  delete_task (task, 1);
  free (task_id);
  free (report_id);
  return ret;
}

/**
 * @brief Check if any SecInfo alerts are due.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, -1 error,
 *         -2 database is too old, -3 database needs to be initialised
 *         from server, -5 database is too new.
 */
int
manage_check_alerts (GSList *log_config, const db_conn_info_t *database)
{
  int ret;

  g_info ("   Checking alerts.");

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  /* Setup a dummy user, so that create_user will work. */
  current_credentials.uuid = "";

  check_alerts ();

  current_credentials.uuid = NULL;

  manage_option_cleanup ();

  return ret;
}



/* Triggering an Alert. */

/**
 * @brief Write the content of a plain text email to a stream.
 *
 * @param[in]  content_file  Stream to write the email content to.
 * @param[in]  to_address    Address to send to.
 * @param[in]  from_address  Address to send to.
 * @param[in]  subject       Subject of email.
 * @param[in]  body          Body of email.
 * @param[in]  attachment    Attachment in line broken base64, or NULL.
 * @param[in]  attachment_type  Attachment MIME type, or NULL.
 * @param[in]  attachment_name  Base file name of the attachment, or NULL.
 * @param[in]  attachment_extension  Attachment file extension, or NULL.
 *
 * @return 0 success, -1 error.
 */
static int
email_write_content (FILE *content_file,
                     const char *to_address, const char *from_address,
                     const char *subject, const char *body,
                     const gchar *attachment, const char *attachment_type,
                     const char *attachment_name,
                     const char *attachment_extension)
{
  if (fprintf (content_file,
               "To: %s\n"
               "From: %s\n"
               "Subject: %s\n"
               "%s%s%s"
               "\n"
               "%s"
               "%s\n",
               to_address,
               from_address ? from_address
                            : "automated@openvas.org",
               subject,
               (attachment
                 ? "MIME-Version: 1.0\n"
                   "Content-Type: multipart/mixed;"
                   " boundary=\""
                 : "Content-Type: text/plain; charset=utf-8\n"
                   "Content-Transfer-Encoding: 8bit\n"),
               /* @todo Future callers may give email containing this string. */
               (attachment ? "=-=-=-=-=" : ""),
               (attachment ? "\"\n" : ""),
               (attachment ? "--=-=-=-=-=\n"
                             "Content-Type: text/plain; charset=utf-8\n"
                             "Content-Transfer-Encoding: 8bit\n"
                             "Content-Disposition: inline\n"
                             "\n"
                           : ""),
               body)
      < 0)
    {
      g_warning ("%s: output error", __func__);
      return -1;
    }

  if (attachment)
    {
      int len;

      if (fprintf (content_file,
                   "--=-=-=-=-=\n"
                   "Content-Type: %s\n"
                   "Content-Disposition: attachment;"
                   " filename=\"%s.%s\"\n"
                   "Content-Transfer-Encoding: base64\n"
                   "Content-Description: Report\n\n",
                   attachment_type,
                   attachment_name,
                   attachment_extension)
          < 0)
        {
          g_warning ("%s: output error", __func__);
          return -1;
        }

      len = strlen (attachment);
      while (len)
        if (len > 72)
          {
            if (fprintf (content_file,
                         "%.*s\n",
                         72,
                         attachment)
                < 0)
              {
                g_warning ("%s: output error", __func__);
                return -1;
              }
            attachment += 72;
            len -= 72;
          }
        else
          {
            if (fprintf (content_file,
                         "%s\n",
                         attachment)
                < 0)
              {
                g_warning ("%s: output error", __func__);
                return -1;
              }
            break;
          }

      if (fprintf (content_file,
                   "--=-=-=-=-=--\n")
          < 0)
        {
          g_warning ("%s: output error", __func__);
          return -1;
        }
    }

  while (fflush (content_file))
    if (errno == EINTR)
      continue;
    else
      {
        g_warning ("%s", strerror (errno));
        return -1;
      }

  return 0;
}

/**
 * @brief  Create a PGP encrypted email from a plain text one.
 *
 * @param[in]  plain_file     Stream to read the plain text email from.
 * @param[in]  encrypted_file Stream to write the encrypted email to.
 * @param[in]  public_key     Recipient public key to use for encryption.
 * @param[in]  to_address     Email address to send to.
 * @param[in]  from_address   Email address to use as sender.
 * @param[in]  subject        Subject of email.
 *
 * @return 0 success, -1 error.
 */
static int
email_encrypt_gpg (FILE *plain_file, FILE *encrypted_file,
                   const char *public_key,
                   const char *to_address, const char *from_address,
                   const char *subject)
{
  // Headers and metadata parts
  if (fprintf (encrypted_file,
               "To: %s\n"
               "From: %s\n"
               "Subject: %s\n"
               "MIME-Version: 1.0\n"
               "Content-Type: multipart/encrypted;\n"
               " protocol=\"application/pgp-encrypted\";\n"
               " boundary=\"=-=-=-=-=\"\n"
               "\n"
               "--=-=-=-=-=\n"
               "Content-Type: application/pgp-encrypted\n"
               "Content-Description: PGP/MIME version identification\n"
               "\n"
               "Version: 1\n"
               "\n"
               "--=-=-=-=-=\n"
               "Content-Type: application/octet-stream\n"
               "Content-Description: OpenPGP encrypted message\n"
               "Content-Disposition: inline; filename=\"encrypted.asc\"\n"
               "\n",
               to_address,
               from_address ? from_address
                            : "automated@openvas.org",
               subject) < 0)
    {
      g_warning ("%s: output error at headers", __func__);
      return -1;
    }

  // Encrypted message
  if (gvm_pgp_pubkey_encrypt_stream (plain_file, encrypted_file, to_address,
                                     public_key, -1))
    {
      return -1;
    }

  // End of message
  if (fprintf (encrypted_file,
               "\n"
               "--=-=-=-=-=--\n") < 0)
    {
      g_warning ("%s: output error at end of message", __func__);
      return -1;
    }

  while (fflush (encrypted_file))
    if (errno == EINTR)
      continue;
    else
      {
        g_warning ("%s", strerror (errno));
        return -1;
      }

  return 0;
}

/**
 * @brief  Create an S/MIME encrypted email from a plain text one.
 *
 * @param[in]  plain_file     Stream to read the plain text email from.
 * @param[in]  encrypted_file Stream to write the encrypted email to.
 * @param[in]  certificate    Recipient certificate chain for encryption.
 * @param[in]  to_address     Email address to send to.
 * @param[in]  from_address   Email address to use as sender.
 * @param[in]  subject        Subject of email.
 *
 * @return 0 success, -1 error.
 */
static int
email_encrypt_smime (FILE *plain_file, FILE *encrypted_file,
                     const char *certificate,
                     const char *to_address, const char *from_address,
                     const char *subject)
{
  // Headers and metadata parts
  if (fprintf (encrypted_file,
               "To: %s\n"
               "From: %s\n"
               "Subject: %s\n"
               "Content-Type: application/x-pkcs7-mime;"
               " smime-type=enveloped-data; name=\"smime.p7m\"\n"
               "Content-Disposition: attachment; filename=\"smime.p7m\"\n"
               "Content-Transfer-Encoding: base64\n"
               "\n",
               to_address,
               from_address ? from_address
                            : "automated@openvas.org",
               subject) < 0)
    {
      g_warning ("%s: output error at headers", __func__);
      return -1;
    }

  // Encrypted message
  if (gvm_smime_encrypt_stream (plain_file, encrypted_file, to_address,
                                certificate, -1))
    {
      g_warning ("%s: encryption failed", __func__);
      return -1;
    }

  // End of message
  if (fprintf (encrypted_file,
               "\n") < 0)
    {
      g_warning ("%s: output error at end of message", __func__);
      return -1;
    }

  while (fflush (encrypted_file))
    if (errno == EINTR)
      continue;
    else
      {
        g_warning ("%s", strerror (errno));
        return -1;
      }

  return 0;
}

/**
 * @brief Send an email.
 *
 * @param[in]  to_address    Address to send to.
 * @param[in]  from_address  Address to send to.
 * @param[in]  subject       Subject of email.
 * @param[in]  body          Body of email.
 * @param[in]  attachment    Attachment in line broken base64, or NULL.
 * @param[in]  attachment_type  Attachment MIME type, or NULL.
 * @param[in]  attachment_name  Base file name of the attachment, or NULL.
 * @param[in]  attachment_extension  Attachment file extension, or NULL.
 * @param[in]  recipient_credential  Optional credential to use for encryption.
 *
 * @return 0 success, -1 error.
 */
static int
email (const char *to_address, const char *from_address, const char *subject,
       const char *body, const gchar *attachment, const char *attachment_type,
       const char *attachment_name, const char *attachment_extension,
       credential_t recipient_credential)
{
  int ret, content_fd, args_fd;
  gchar *command;
  GError *error = NULL;
  char content_file_name[] = "/tmp/gvmd-content-XXXXXX";
  char args_file_name[] = "/tmp/gvmd-args-XXXXXX";
  gchar *sendmail_args;
  FILE *content_file;

  content_fd = mkstemp (content_file_name);
  if (content_fd == -1)
    {
      g_warning ("%s: mkstemp: %s", __func__, strerror (errno));
      return -1;
    }

  g_debug ("   EMAIL to %s from %s subject: %s, body: %s",
          to_address, from_address, subject, body);

  content_file = fdopen (content_fd, "w");
  if (content_file == NULL)
    {
      g_warning ("%s: Could not open content file: %s",
                 __func__, strerror (errno));
      close (content_fd);
      return -1;
    }

  if (recipient_credential)
    {
      iterator_t iterator;
      init_credential_iterator_one (&iterator, recipient_credential);

      if (next (&iterator))
        {
          const char *type = credential_iterator_type (&iterator);
          const char *public_key = credential_iterator_public_key (&iterator);
          const char *certificate
            = credential_iterator_certificate (&iterator);
          char plain_file_name[] = "/tmp/gvmd-plain-XXXXXX";
          int plain_fd;
          FILE *plain_file;

          // Create plain text message
          plain_fd = mkstemp (plain_file_name);
          if (plain_fd == -1)
            {
              g_warning ("%s: mkstemp for plain text file: %s",
                         __func__, strerror (errno));
              fclose (content_file);
              unlink (content_file_name);
              cleanup_iterator (&iterator);
              return -1;
            }

          plain_file = fdopen (plain_fd, "w+");
          if (plain_file == NULL)
            {
              g_warning ("%s: Could not open plain text file: %s",
                         __func__, strerror (errno));
              fclose (content_file);
              unlink (content_file_name);
              close (plain_fd);
              unlink (plain_file_name);
              cleanup_iterator (&iterator);
              return -1;
            }

          if (email_write_content (plain_file,
                                   to_address, from_address,
                                   subject, body, attachment,
                                   attachment_type, attachment_name,
                                   attachment_extension))
            {
              fclose (content_file);
              unlink (content_file_name);
              fclose (plain_file);
              unlink (plain_file_name);
              cleanup_iterator (&iterator);
              return -1;
            }

          rewind (plain_file);

          // Create encrypted email
          if (strcmp (type, "pgp") == 0)
            {
              ret = email_encrypt_gpg (plain_file, content_file,
                                       public_key,
                                       to_address, from_address, subject);

              fclose (plain_file);
              unlink (plain_file_name);

              if (ret)
                {
                  g_warning ("%s: PGP encryption failed", __func__);
                  fclose (content_file);
                  unlink (content_file_name);
                  cleanup_iterator (&iterator);
                  return -1;
                }
            }
          else if (strcmp (type, "smime") == 0)
            {
              ret = email_encrypt_smime (plain_file, content_file,
                                         certificate,
                                         to_address, from_address, subject);

              fclose (plain_file);
              unlink (plain_file_name);

              if (ret)
                {
                  g_warning ("%s: S/MIME encryption failed", __func__);
                  fclose (content_file);
                  unlink (content_file_name);
                  cleanup_iterator (&iterator);
                  return -1;
                }
            }
          else
            {
              g_warning ("%s: Invalid recipient credential type",
                        __func__);
              fclose (content_file);
              unlink (content_file_name);
              fclose (plain_file);
              unlink (plain_file_name);
              cleanup_iterator (&iterator);
              return -1;
            }
        }

      cleanup_iterator (&iterator);
    }
  else
    {
      if (email_write_content (content_file,
                               to_address, from_address,
                               subject, body, attachment, attachment_type,
                               attachment_name, attachment_extension))
        {
          fclose (content_file);
          return -1;
        }
    }

  args_fd = mkstemp (args_file_name);
  if (args_fd == -1)
    {
      g_warning ("%s: mkstemp: %s", __func__, strerror (errno));
      fclose (content_file);
      return -1;
    }

  sendmail_args = g_strdup_printf ("%s %s",
                                   from_address,
                                   to_address);
  g_file_set_contents (args_file_name,
                       sendmail_args,
                       strlen (sendmail_args),
                       &error);
  g_free (sendmail_args);

  if (error)
    {
      g_warning ("%s", error->message);
      g_error_free (error);
      fclose (content_file);
      close (args_fd);
      return -1;
    }

  command = g_strdup_printf ("read FROM TO < %s;"
                             " /usr/sbin/sendmail -f \"$FROM\" \"$TO\" < %s"
                             " > /dev/null 2>&1",
                             args_file_name,
                             content_file_name);

  g_debug ("Executing sendmail alert command with redacted arguments");

  ret = system (command);
  if ((ret == -1) || WEXITSTATUS (ret))
    {
      g_warning ("%s: system failed with ret %i, %i",
                 __func__,
                 ret,
                 WEXITSTATUS (ret));
      g_free (command);
      fclose (content_file);
      close (args_fd);
      unlink (content_file_name);
      unlink (args_file_name);
      return -1;
    }
  g_free (command);
  fclose (content_file);
  close (args_fd);
  unlink (content_file_name);
  unlink (args_file_name);
  return 0;
}

/**
 * @brief Initialize common files and variables for an alert script.
 *
 * The temporary file / dir parameters will be modified by mkdtemp / mkstemp
 *  to contain the actual path.
 * The extra data is meant for data that should not be logged like passwords.
 *
 * @param[in]     report_filename Filename for the report or NULL for default.
 * @param[in]     report          Report that should be sent.
 * @param[in]     report_size     Size of the report.
 * @param[in]     extra_content   Optional extra data, e.g. credentials
 * @param[in]     extra_size      Optional extra data length
 * @param[in,out] report_dir      Template for temporary report directory
 * @param[out]    report_path Pointer to store path to report file at
 * @param[out]    error_path  Pointer to temporary file path for error messages
 * @param[out]    extra_path  Pointer to temporary extra data file path
 *
 * @return 0 success, -1 error.
 */
static int
alert_script_init (const char *report_filename, const char* report,
                   size_t report_size,
                   const char *extra_content, size_t extra_size,
                   char *report_dir,
                   gchar **report_path, gchar **error_path, gchar **extra_path,
                   int *report_fd, int *error_fd, int *extra_fd)
{
  *report_fd = -1;
  *error_fd = -1;
  *extra_fd = -1;

  /* Create temp directory */

  if (mkdtemp (report_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed", __func__);
      return -1;
    }

  /* Create report file */

  *report_path = g_strdup_printf ("%s/%s",
                                  report_dir,
                                  report_filename ? report_filename
                                                  : "report");

  *report_fd = open_private_write (*report_path);
  if (*report_fd == -1 || write_all (*report_fd, report, report_size))
    {
      g_warning ("%s: could not write report: %s", __func__, strerror (errno));
      close_alert_fd (report_fd);
      g_free (*report_path);
      gvm_file_remove_recurse (report_dir);
      return -1;
    }

  /* Create error file */

  *error_path = g_strdup_printf ("%s/error_XXXXXX", report_dir);

  *error_fd = mkstemp (*error_path);
  if (*error_fd == -1)
    {
      g_warning ("%s: mkstemp for error output failed", __func__);
      gvm_file_remove_recurse (report_dir);
      close_alert_fd (report_fd);
      g_free (*report_path);
      g_free (*error_path);
      return -1;
    }

  /* Create extra data file */

  if (extra_content)
    {
      *extra_path = g_strdup_printf ("%s/extra_XXXXXX", report_dir);
      *extra_fd = mkstemp (*extra_path);
      if (*extra_fd == -1)
        {
          g_warning ("%s: mkstemp for extra data failed", __func__);
          gvm_file_remove_recurse (report_dir);
          close_alert_fd (report_fd);
          close_alert_fd (error_fd);
          g_free (*report_path);
          g_free (*error_path);
          g_free (*extra_path);
          return -1;
        }

      if (write_all (*extra_fd, extra_content, extra_size))
        {
          g_warning ("%s: could not write extra data: %s", __func__,
                     strerror (errno));
          gvm_file_remove_recurse (report_dir);
          close_alert_fd (report_fd);
          close_alert_fd (error_fd);
          close_alert_fd (extra_fd);
          g_free (*report_path);
          g_free (*error_path);
          g_free (*extra_path);
          return -1;
        }
    }
  else
    *extra_path = NULL;

  return 0;
}

/**
 * @brief Execute the alert script.
 *
 * @param[in]  alert_id      UUID of the alert.
 * @param[in]  command_args  Args for the "alert" script.
 * @param[in]  report_path   Path to temporary file containing the report
 * @param[in]  report_dir    Temporary directory for the report
 * @param[in]  error_path    Path to the script error message file
 * @param[in]  extra_path    Path to the extra data file
 * @param[in]  report_fd     Open descriptor for report_path.
 * @param[in]  error_fd      Open descriptor for error_path.
 * @param[in]  extra_fd      Open descriptor for extra_path, or -1.
 * @param[out] message       Custom error message generated by the script
 *
 * @return 0 success, -1 error, -5 alert script failed.
 */
static int
alert_script_exec (const char *alert_id, const char *command_args,
                   const char *report_path, const char *report_dir,
                   const char *error_path, const char *extra_path,
                   int report_fd, int error_fd, int extra_fd,
                   gchar **message)
{
  gchar *script, *script_dir;

  /* Setup script file name. */
  script_dir = g_build_filename (GVMD_DATA_DIR,
                                 "global_alert_methods",
                                 alert_id,
                                 NULL);

  script = g_build_filename (script_dir, "alert", NULL);

  if (!gvm_file_is_readable (script))
    {
      g_warning ("%s: Failed to find alert script: %s",
           __func__,
           script);
      close_alert_fd (&report_fd);
      close_alert_fd (&error_fd);
      close_alert_fd (&extra_fd);
      g_free (script);
      g_free (script_dir);
      return -1;
    }

  /* Run the script */
  {
    gchar *command;
    char *previous_dir;
    int ret;

    /* Change into the script directory. */

    previous_dir = getcwd (NULL, 0);
    if (previous_dir == NULL)
      {
        g_warning ("%s: Failed to getcwd: %s",
                   __func__,
                   strerror (errno));
        g_free (previous_dir);
        close_alert_fd (&report_fd);
        close_alert_fd (&error_fd);
        close_alert_fd (&extra_fd);
        g_free (script);
        g_free (script_dir);
        return -1;
      }

    if (chdir (script_dir))
      {
        g_warning ("%s: Failed to chdir: %s",
                   __func__,
                   strerror (errno));
        g_free (previous_dir);
        close_alert_fd (&report_fd);
        close_alert_fd (&error_fd);
        close_alert_fd (&extra_fd);
        g_free (script);
        g_free (script_dir);
        return -1;
      }
    g_free (script_dir);

    /* Call the script. */

    if (extra_path)
      command = g_strdup_printf ("%s %s %s %s"
                                 " > /dev/null 2> %s",
                                 script,
                                 command_args,
                                 extra_path,
                                 report_path,
                                 error_path);
    else
      command = g_strdup_printf ("%s %s %s"
                                 " > /dev/null 2> %s",
                                 script,
                                 command_args,
                                 report_path,
                                 error_path);
    g_free (script);

    g_debug ("Executing alert script command with redacted arguments");

    if (geteuid () == 0)
      {
        pid_t pid;
        struct passwd *nobody;

        /* Run the command with lower privileges in a fork. */

        nobody = getpwnam ("nobody");
        if ((nobody == NULL)
            || chown (report_dir, nobody->pw_uid, nobody->pw_gid)
            || fchown (report_fd, nobody->pw_uid, nobody->pw_gid)
            || fchown (error_fd, nobody->pw_uid, nobody->pw_gid)
            || (extra_fd >= 0 && fchown (extra_fd, nobody->pw_uid,
                                         nobody->pw_gid)))
          {
            g_warning ("%s: Failed to set permissions for user nobody: %s",
                       __func__,
                       strerror (errno));
            close_alert_fd (&report_fd);
            close_alert_fd (&error_fd);
            close_alert_fd (&extra_fd);
            g_free (previous_dir);
            alert_secure_gfree (command);
            return -1;
          }

        close_alert_fd (&report_fd);
        close_alert_fd (&error_fd);
        close_alert_fd (&extra_fd);

        pid = fork ();
        switch (pid)
          {
            case 0:
              {
                /* Child.  Drop privileges, run command, exit. */
                init_sentry ();
                cleanup_manage_process (FALSE);

                setproctitle ("Running alert script");

                if (setgroups (0,NULL))
                  {
                    g_warning ("%s (child): setgroups: %s",
                               __func__, strerror (errno));
                    gvm_close_sentry ();
                    exit (EXIT_FAILURE);
                  }
                if (setgid (nobody->pw_gid))
                  {
                    g_warning ("%s (child): setgid: %s",
                               __func__,
                               strerror (errno));
                    gvm_close_sentry ();
                    exit (EXIT_FAILURE);
                  }
                if (setuid (nobody->pw_uid))
                  {
                    g_warning ("%s (child): setuid: %s",
                               __func__,
                               strerror (errno));
                    gvm_close_sentry ();
                    exit (EXIT_FAILURE);
                  }

                ret = system (command);
                /*
                 * Check shell command exit status, assuming 0 means success.
                 */
                if (ret == -1)
                  {
                    g_warning ("%s (child):"
                               " system failed with ret %i, %i",
                               __func__,
                               ret,
                               WEXITSTATUS (ret));
                    gvm_close_sentry ();
                    exit (EXIT_FAILURE);
                  }
                else if (ret != 0)
                  {
                    GError *error;

                    if (g_file_get_contents (error_path, message,
                                             NULL, &error) == FALSE)
                      {
                        g_warning ("%s: failed to test error message: %s",
                                    __func__, error->message);
                        g_error_free (error);
                        if (message)
                          g_free (*message);
                        gvm_close_sentry ();
                        exit (EXIT_FAILURE);
                      }

                    if (message == NULL)
                      exit (EXIT_FAILURE);
                    else if (*message == NULL || strcmp (*message, "") == 0)
                      {
                        g_free (*message);
                        *message
                          = g_strdup_printf ("Exited with code %d.",
                                              WEXITSTATUS (ret));

                        if (g_file_set_contents (error_path, *message,
                                                 strlen (*message),
                                                 &error) == FALSE)
                          {
                            g_warning ("%s: failed to write error message:"
                                        " %s",
                                        __func__, error->message);
                            g_error_free (error);
                            g_free (*message);
                            gvm_close_sentry ();
                            exit (EXIT_FAILURE);
                          }
                      }

                    g_free (*message);
                    gvm_close_sentry ();
                    exit (2);
                  }

                exit (EXIT_SUCCESS);
              }

            case -1:
              /* Parent when error. */

              g_warning ("%s: Failed to fork: %s",
                         __func__,
                         strerror (errno));
              if (chdir (previous_dir))
                g_warning ("%s: and chdir failed",
                           __func__);
              g_free (previous_dir);
              alert_secure_gfree (command);
              return -1;
              break;

            default:
              {
                int status;

                /* Parent on success.  Wait for child, and check result. */

                while (waitpid (pid, &status, 0) < 0)
                  {
                    if (errno == ECHILD)
                      {
                        g_warning ("%s: Failed to get child exit status",
                                   __func__);
                        if (chdir (previous_dir))
                          g_warning ("%s: and chdir failed",
                                     __func__);
                        g_free (previous_dir);
                        alert_secure_gfree (command);
                        return -1;
                      }
                    if (errno == EINTR)
                      continue;
                    g_warning ("%s: wait: %s",
                               __func__,
                               strerror (errno));
                    if (chdir (previous_dir))
                      g_warning ("%s: and chdir failed",
                                 __func__);
                    g_free (previous_dir);
                    alert_secure_gfree (command);
                    return -1;
                  }
                if (WIFEXITED (status))
                  switch (WEXITSTATUS (status))
                    {
                    case EXIT_SUCCESS:
                      break;
                    case 2: // script failed
                      if (message)
                        {
                          GError *error = NULL;
                          if (g_file_get_contents (error_path, message,
                                                   NULL, &error) == FALSE)
                            {
                              g_warning ("%s: failed to get error message: %s",
                                         __func__, error->message);
                              g_error_free (error);
                            }

                          if (strcmp (*message, "") == 0)
                            {
                              g_free (*message);
                              *message = NULL;
                            }
                        }
                      if (chdir (previous_dir))
                        g_warning ("%s: chdir failed",
                                   __func__);
                      g_free (previous_dir);
                      alert_secure_gfree (command);
                      return -5;
                    case EXIT_FAILURE:
                    default:
                      g_warning ("%s: alert script child failed", __func__);
                      if (chdir (previous_dir))
                        g_warning ("%s: and chdir failed",
                                   __func__);
                      g_free (previous_dir);
                      alert_secure_gfree (command);
                      return -1;
                    }
                else
                  {
                    g_warning ("%s: alert script child failed", __func__);
                    if (chdir (previous_dir))
                      g_warning ("%s: and chdir failed",
                                 __func__);
                    g_free (previous_dir);
                    alert_secure_gfree (command);
                    return -1;
                  }

                /* Child succeeded, continue to process result. */

                break;
              }
          }
      }
    else
      {
        /* Just run the command as the current user. */

        close_alert_fd (&report_fd);
        close_alert_fd (&error_fd);
        close_alert_fd (&extra_fd);

        ret = system (command);
        /* Ignore the shell command exit status, because we've not
         * specified what it must be in the past. */
        if (ret == -1)
          {
            g_warning ("%s: system failed with ret %i, %i",
                       __func__,
                       ret,
                       WEXITSTATUS (ret));
            if (chdir (previous_dir))
              g_warning ("%s: and chdir failed",
                         __func__);
            g_free (previous_dir);
            alert_secure_gfree (command);
            return -1;
          }
        else if (ret)
          {
            if (message)
              {
                GError *error = NULL;
                if (g_file_get_contents (error_path, message, NULL, &error)
                      == FALSE)
                  {
                    g_warning ("%s: failed to get error message: %s",
                               __func__, error->message);
                    g_error_free (error);
                  }

                if (strcmp (*message, "") == 0)
                  {
                    g_free (*message);
                    *message = NULL;
                  }

                if (*message == NULL)
                  {
                    *message
                      = g_strdup_printf ("Exited with code %d.",
                                         WEXITSTATUS (ret));
                  }
              }
            g_free (previous_dir);
            alert_secure_gfree (command);
            return -5;
          }
      }

    alert_secure_gfree (command);

    /* Change back to the previous directory. */

    if (chdir (previous_dir))
      {
        g_warning ("%s: Failed to chdir back: %s",
                   __func__,
                   strerror (errno));
        g_free (previous_dir);
        return -1;
      }
    g_free (previous_dir);
  }
  return 0;
}

/**
 * @brief Write data to a file for use by an alert script.
 *
 * @param[in]  directory      Base directory to create the file in
 * @param[in]  filename       Filename without directory
 * @param[in]  content        The file content
 * @param[in]  content_size   Size of the file content
 * @param[in]  description    Short file description for error messages
 * @param[out] file_path      Return location of combined file path
 *
 * @return 0 success, -1 error
 */
static int
alert_write_data_file (const char *directory, const char *filename,
                       const char *content, gsize content_size,
                       const char *description, gchar **file_path)
{
  gchar *path;
  GError *error;

  if (file_path)
    *file_path = NULL;

  /* Setup extra data file */
  path = g_build_filename (directory, filename, NULL);
  error = NULL;
  if (g_file_set_contents (path, content, content_size, &error) == FALSE)
    {
      g_warning ("%s: Failed to write %s to file: %s",
                 __func__,
                 description ? description : "extra data",
                 error->message);
      g_free (path);
      return -1;
    }

  if (chmod (path, S_IRUSR | S_IWUSR))
    {
      g_warning ("%s: Failed to set owner-only permissions for %s: %s",
                 __func__,
                 description ? description : "extra data",
                 strerror (errno));
      g_unlink (path);
      g_free (path);
      return -1;
    }

  if (geteuid () == 0)
    {
      struct passwd *nobody;

      /* Set the owner for the extra data file like the other
       * files handled by alert_script_exec, to be able to
       * run the command with lower privileges in a fork. */

      nobody = getpwnam ("nobody");
      if ((nobody == NULL)
          || chown (path, nobody->pw_uid, nobody->pw_gid))
        {
          g_warning ("%s: Failed to set permissions for user nobody: %s",
                      __func__,
                      strerror (errno));
          g_free (path);
          return -1;
        }
    }

  if (file_path)
    *file_path = path;

  return 0;
}

/**
 * @brief Clean up common files and variables for running alert script.
 *
 * @param[in]  report_dir   The temporary directory.
 * @param[in]  report_path  The temporary report file path to free.
 * @param[in]  error_path   The temporary error file path to free.
 * @param[in]  extra_path   The temporary extra data file path to free.
 *
 * @return 0 success, -1 error.
 */
static int
alert_script_cleanup (const char *report_dir,
                      gchar *report_path, gchar *error_path, gchar *extra_path)
{
  gvm_file_remove_recurse (report_dir);
  g_free (report_path);
  g_free (error_path);
  g_free (extra_path);
  return 0;
}

/**
 * @brief Run an alert's "alert" script with one file of extra data.
 *
 * @param[in]  alert_id         ID of alert.
 * @param[in]  command_args     Args for the "alert" script.
 * @param[in]  report_filename  Optional report file name, default: "report"
 * @param[in]  report           Report that should be sent.
 * @param[in]  report_size      Size of the report.
 * @param[in]  extra_content    Optional extra data like passwords
 * @param[in]  extra_size       Size of the report.
 * @param[out] message          Custom error message of the script.
 *
 * @return 0 success, -1 error, -5 alert script failed.
 */
static int
run_alert_script (const char *alert_id, const char *command_args,
                  const char *report_filename, const char *report,
                  size_t report_size,
                  const char *extra_content, size_t extra_size,
                  gchar **message)
{
  char report_dir[] = "/tmp/gvmd_alert_XXXXXX";
  gchar *report_path, *error_path, *extra_path;
  int report_fd, error_fd, extra_fd;
  int ret;

  if (message)
    *message = NULL;

  if (report == NULL)
    return -1;

  /* Setup files. */
  ret = alert_script_init (report_filename, report, report_size,
                           extra_content, extra_size,
                           report_dir,
                           &report_path, &error_path, &extra_path,
                           &report_fd, &error_fd, &extra_fd);
  if (ret)
    return ret;

  /* Run the script */
  ret = alert_script_exec (alert_id, command_args, report_path, report_dir,
                           error_path, extra_path, report_fd, error_fd,
                           extra_fd, message);
  if (ret)
    {
      alert_script_cleanup (report_dir, report_path, error_path, extra_path);
      return ret;
    }

  /* Remove the directory. */
  ret = alert_script_cleanup (report_dir, report_path, error_path, extra_path);

  return ret;
}

/**
 * @brief Send an SNMP TRAP to a host.
 *
 * @param[in]  community  Community.
 * @param[in]  agent      Agent.
 * @param[in]  message    Message.
 * @param[out] script_message  Custom error message of the script.
 *
 * @return 0 success, -1 error, -5 alert script failed.
 */
static int
snmp_to_host (const char *community, const char *agent, const char *message,
              gchar **script_message)
{
  gchar *clean_community, *clean_agent, *clean_message, *command_args;
  int ret;

  if (community == NULL || agent == NULL || message == NULL)
    {
      g_warning ("%s: parameter was NULL", __func__);
      return -1;
    }

  clean_community = g_shell_quote (community);
  clean_agent = g_shell_quote (agent);
  clean_message = g_shell_quote (message);
  command_args = g_strdup_printf ("%s %s %s", clean_community, clean_agent,
                                  clean_message);
  alert_secure_gfree (clean_community);
  alert_secure_gfree (clean_agent);
  alert_secure_gfree (clean_message);

  ret = run_alert_script ("9d435134-15d3-11e6-bf5c-28d24461215b", command_args,
                          "report", "", 0, NULL, 0, script_message);

  alert_secure_gfree (command_args);
  return ret;
}

/**
 * @brief Send a report to a host via TCP.
 *
 * @param[in]  username     Username.
 * @param[in]  password     Password or passphrase of private key.
 * @param[in]  private_key  Private key or NULL for password-only auth.
 * @param[in]  host         Address of host.
 * @param[in]  port         SSH Port of host.
 * @param[in]  path         Destination filename with path.
 * @param[in]  known_hosts  Content for known_hosts file.
 * @param[in]  report       Report that should be sent.
 * @param[in]  report_size  Size of the report.
 * @param[out] script_message  Custom error message of the alert script.
 *
 * @return 0 success, -1 error, -5 alert script failed.
 */
static int
scp_to_host (const char *username, const char *password,
             const char *private_key,
             const char *host, int port,
             const char *path, const char *known_hosts,
             const char *report, int report_size, gchar **script_message)
{
  const char *alert_id = "2db07698-ec49-11e5-bcff-28d24461215b";
  char report_dir[] = "/tmp/gvmd_alert_XXXXXX";
  gchar *report_path, *error_path, *password_path, *private_key_path;
  gchar *known_hosts_path;
  gchar *clean_username, *clean_host, *clean_path, *clean_private_key_path;
  gchar *clean_known_hosts_path, *command_args;
  int report_fd, error_fd, password_fd;
  int ret;

  if (password == NULL || username == NULL || host == NULL || path == NULL
      || known_hosts == NULL || known_hosts[0] == '\0'
      || port <= 0 || port > 65535)
    return -1;

  /* Setup files, including password but not private key */
  ret = alert_script_init ("report", report, report_size,
                           password, strlen (password),
                           report_dir,
                           &report_path, &error_path, &password_path,
                           &report_fd, &error_fd, &password_fd);
  if (ret)
    return -1;

  if (private_key && private_key[0] != '\0')
    {
      /* Setup private key here because alert_script_init and alert_script_exec
       *  only handle one extra file. */
      if (alert_write_data_file (report_dir, "private_key",
                                 private_key, strlen (private_key),
                                 "private key", &private_key_path))
        {
          close_alert_fd (&report_fd);
          close_alert_fd (&error_fd);
          close_alert_fd (&password_fd);
          alert_script_cleanup (report_dir, report_path, error_path,
                                password_path);
          g_free (private_key_path);
          return -1;
        }
    }
  else
    private_key_path = g_strdup ("");

  if (alert_write_data_file (report_dir, "known_hosts",
                             known_hosts, strlen (known_hosts),
                             "known hosts", &known_hosts_path))
    {
      close_alert_fd (&report_fd);
      close_alert_fd (&error_fd);
      close_alert_fd (&password_fd);
      alert_script_cleanup (report_dir, report_path, error_path,
                            password_path);
      g_free (private_key_path);
      return -1;
    }

  /* Create arguments */
  clean_username = g_shell_quote (username);
  clean_host = g_shell_quote (host);
  clean_path = g_shell_quote (path);
  clean_known_hosts_path = g_shell_quote (known_hosts_path);
  clean_private_key_path = g_shell_quote (private_key_path);
  command_args = g_strdup_printf ("%s %s %d %s %s %s",
                                  clean_username,
                                  clean_host,
                                  port,
                                  clean_path,
                                  clean_known_hosts_path,
                                  clean_private_key_path);
  alert_secure_gfree (clean_username);
  alert_secure_gfree (clean_host);
  alert_secure_gfree (clean_path);
  alert_secure_gfree (clean_known_hosts_path);
  alert_secure_gfree (clean_private_key_path);

  /* Run script */
  ret = alert_script_exec (alert_id, command_args, report_path, report_dir,
                           error_path, password_path, report_fd, error_fd,
                           password_fd, script_message);
  alert_secure_gfree (command_args);
  if (ret)
    {
      alert_script_cleanup (report_dir, report_path, error_path,
                            password_path);
      g_free (private_key_path);
      g_free (known_hosts_path);
      return ret;
    }

  /* Remove the directory and free path strings. */
  ret = alert_script_cleanup (report_dir, report_path, error_path,
                              password_path);
  g_free (private_key_path);
  g_free (known_hosts_path);
  return ret;
}

/**
 * @brief Send a report to a host via SMB.
 *
 * @param[in]  password       Password.
 * @param[in]  username       Username.
 * @param[in]  share_path     Name/address of host and name of the share.
 * @param[in]  file_path      Destination filename with path inside the share.
 * @param[in]  max_protocol   Max protocol.
 * @param[in]  report         Report that should be sent.
 * @param[in]  report_size    Size of the report.
 * @param[out] script_message Custom error message of the alert script.
 *
 * @return 0 success, -1 error, -5 alert script failed.
 */
static int
smb_send_to_host (const char *password, const char *username,
                  const char *share_path, const char *file_path,
                  const char *max_protocol,
                  const char *report, gsize report_size,
                  gchar **script_message)
{
  gchar *clean_share_path, *clean_file_path, *clean_max_protocol;
  gchar *authfile_content;
  gchar *command_args;
  int ret;

  g_debug ("Sending report through SMB alert delivery");

  if (password == NULL || username == NULL
      || share_path == NULL || file_path == NULL)
    return -1;
  if (strpbrk (username, "\r\n") || strpbrk (password, "\r\n")
      || strpbrk (share_path, "\"';|&`$\r\n")
      || strpbrk (file_path, "\"';|&`$\r\n"))
    return -1;

  clean_share_path = g_shell_quote (share_path);
  clean_file_path = g_shell_quote (file_path);
  clean_max_protocol = g_shell_quote (max_protocol ? max_protocol : "");
  authfile_content = g_strdup_printf ("username = %s\n"
                                      "password = %s\n",
                                      username, password);
  command_args = g_strdup_printf ("%s %s %s",
                                  clean_share_path,
                                  clean_file_path,
                                  clean_max_protocol);
  g_free (clean_share_path);
  g_free (clean_file_path);
  g_free (clean_max_protocol);

  ret = run_alert_script ("c427a688-b653-40ab-a9d0-d6ba842a9d63", command_args,
                          "report", report, report_size,
                          authfile_content, strlen (authfile_content),
                          script_message);

  alert_secure_gfree (authfile_content);
  alert_secure_gfree (command_args);
  return ret;
}

/**
 * @brief Format string for simple notice alert email.
 */
#define SIMPLE_NOTICE_FORMAT                                                  \
 "%s.\n"                                                                      \
 "\n"                                                                         \
 "After the event %s,\n"                                                      \
 "the following condition was met: %s\n"                                      \
 "\n"                                                                         \
 "This email escalation is not configured to provide more details.\n"         \
 "Full details are stored on the scan engine.\n"                              \
 "\n"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This email was sent to you as a configured security scan escalation.\n"     \
 "Please contact your local system administrator if you think you\n"          \
 "should not have received it.\n"

/**
 * @brief Format string for simple notice alert email.
 */
#define SECINFO_SIMPLE_NOTICE_FORMAT                                          \
 "%s.\n"                                                                      \
 "\n"                                                                         \
 "After the event %s,\n"                                                      \
 "the following condition was met: %s\n"                                      \
 "\n"                                                                         \
 "This email escalation is not configured to provide more details.\n"         \
 "Full details are stored on the scan engine.\n"                              \
 "\n"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This email was sent to you as a configured security scan escalation.\n"     \
 "Please contact your local system administrator if you think you\n"          \
 "should not have received it.\n"

/**
 * @brief Print an alert subject.
 *
 * @param[in]  subject     Format string for subject.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  alert       Alert.
 * @param[in]  task        Task.
 * @param[in]  total       Total number of resources (for SecInfo alerts).
 *
 * @return Freshly allocated subject.
 */
static gchar *
alert_subject_print (const gchar *subject, event_t event,
                     const void *event_data,
                     alert_t alert, task_t task, int total)
{
  int formatting;
  const gchar *point, *end;
  GString *new_subject;

  assert (subject);

  new_subject = g_string_new ("");
  for (formatting = 0, point = subject, end = (subject + strlen (subject));
       point < end;
       point++)
    if (formatting)
      {
        switch (*point)
          {
            case '$':
              g_string_append_c (new_subject, '$');
              break;
            case 'd':
              /* Date that the check was last performed. */
              if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
                {
                  char time_string[100];
                  time_t date;
                  struct tm tm;

                  if (event_data && (strcasecmp (event_data, "nvt") == 0))
                    date = nvts_check_time ();
                  else if (secinfo_type_is_scap (event_data))
                    date = scap_check_time ();
                  else
                    date = cert_check_time ();

                  if (localtime_r (&date, &tm) == NULL)
                    {
                      g_warning ("%s: localtime failed, aborting",
                                 __func__);
                      abort ();
                    }
                  if (strftime (time_string, 98, "%F", &tm) == 0)
                    break;
                  g_string_append (new_subject, time_string);
                }
              break;
            case 'e':
              {
                gchar *event_desc;
                event_desc = event_description (event, event_data,
                                                NULL);
                g_string_append (new_subject, event_desc);
                g_free (event_desc);
                break;
              }
            case 'n':
              {
                if (task)
                  {
                    char *name = task_name (task);
                    g_string_append (new_subject, name);
                    free (name);
                  }
                break;
              }
            case 'N':
              {
                /* Alert Name */
                char *name = alert_name (alert);
                g_string_append (new_subject, name);
                free (name);
                break;
              }
            case 'q':
              if (event == EVENT_NEW_SECINFO)
                g_string_append (new_subject, "New");
              else if (event == EVENT_UPDATED_SECINFO)
                g_string_append (new_subject, "Updated");
              break;
            case 's':
              /* Type. */
              if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
                g_string_append (new_subject,
                                 secinfo_type_name (event_data));
              break;
            case 'S':
              /* Type, plural. */
              if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
                g_string_append (new_subject,
                                 secinfo_type_name_plural (event_data));
              break;
            case 'T':
              g_string_append_printf (new_subject, "%i", total);
              break;
            case 'u':
              {
                /* Current user or owner of the Alert */
                if (current_credentials.username
                    && strcmp (current_credentials.username, ""))
                  {
                    g_string_append (new_subject, current_credentials.username);
                  }
                else
                  {
                    char *owner = alert_owner_uuid (alert);
                    gchar *name = user_name (owner);
                    g_string_append (new_subject, name);
                    free (owner);
                    g_free (name);
                  }
                break;
              }
            case 'U':
              {
                /* Alert UUID */
                char *uuid = alert_uuid (alert);
                g_string_append (new_subject, uuid);
                free (uuid);
                break;
              }
            default:
              g_string_append_c (new_subject, '$');
              g_string_append_c (new_subject, *point);
              break;
          }
        formatting = 0;
      }
    else if (*point == '$')
      formatting = 1;
    else
      g_string_append_c (new_subject, *point);

  return g_string_free (new_subject, FALSE);
}

/**
 * @brief Print an alert message.
 *
 * @param[in]  message      Format string for message.
 * @param[in]  event        Event.
 * @param[in]  event_data   Event data.
 * @param[in]  task         Task.
 * @param[in]  alert        Alert.
 * @param[in]  condition    Alert condition.
 * @param[in]  format_name  Report format name.
 * @param[in]  filter       Filter.
 * @param[in]  term         Filter term.
 * @param[in]  zone         Timezone.
 * @param[in]  host_summary    Host summary.
 * @param[in]  content         The report, for inlining.
 * @param[in]  content_length  Length of content.
 * @param[in]  truncated       Whether the report was truncated.
 * @param[in]  total        Total number of resources (for SecInfo alerts).
 * @param[in]  max_length   Max allowed length of content.
 *
 * @return Freshly allocated message.
 */
static gchar *
alert_message_print (const gchar *message, event_t event,
                     const void *event_data, task_t task,
                     alert_t alert, alert_condition_t condition,
                     gchar *format_name, filter_t filter,
                     const gchar *term, const gchar *zone,
                     const gchar *host_summary, const gchar *content,
                     gsize content_length, int truncated, int total,
                     int max_length)
{
  int formatting;
  const gchar *point, *end;
  GString *new_message;

  assert (message);

  new_message = g_string_new ("");
  for (formatting = 0, point = message, end = (message + strlen (message));
       point < end;
       point++)
    if (formatting)
      {
        switch (*point)
          {
            case '$':
              g_string_append_c (new_message, '$');
              break;
            case 'c':
              {
                gchar *condition_desc;
                condition_desc = alert_condition_description
                                  (condition, alert);
                g_string_append (new_message, condition_desc);
                g_free (condition_desc);
                break;
              }
            case 'd':
              /* Date that the check was last performed. */
              if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
                {
                  char time_string[100];
                  time_t date;
                  struct tm tm;

                  if (event_data && (strcasecmp (event_data, "nvt") == 0))
                    date = nvts_check_time ();
                  else if (secinfo_type_is_scap (event_data))
                    date = scap_check_time ();
                  else
                    date = cert_check_time ();

                  if (localtime_r (&date, &tm) == NULL)
                    {
                      g_warning ("%s: localtime failed, aborting",
                                 __func__);
                      abort ();
                    }
                  if (strftime (time_string, 98, "%F", &tm) == 0)
                    break;
                  g_string_append (new_message, time_string);
                }
              break;
            case 'e':
              {
                gchar *event_desc;
                event_desc = event_description (event, event_data,
                                                NULL);
                g_string_append (new_message, event_desc);
                g_free (event_desc);
                break;
              }
            case 'H':
              {
                /* Host summary. */

                g_string_append (new_message,
                                 host_summary ? host_summary : "N/A");
                break;
              }
            case 'i':
              {
                if (content)
                  {
                    int max;

                    max = get_max_email_include_size ();
                    g_string_append_printf (new_message,
                                            "%.*s",
                                            /* Cast for 64 bit. */
                                            (int) MIN (content_length, max),
                                            content);
                    if (content_length > max)
                      g_string_append_printf (new_message,
                                              "\n... (report truncated after"
                                              " %i characters)\n",
                                              max);
                  }

                break;
              }
            case 'n':
              if (task)
                {
                  char *name = task_name (task);
                  g_string_append (new_message, name);
                  free (name);
                }
              break;
            case 'N':
              {
                /* Alert Name */
                char *name = alert_name (alert);
                g_string_append (new_message, name);
                free (name);
                break;
              }
            case 'r':
              {
                /* Report format name. */

                g_string_append (new_message,
                                 format_name ? format_name : "N/A");
                break;
              }
            case 'F':
              {
                /* Name of filter. */

                if (filter)
                  {
                    char *name = filter_name (filter);
                    g_string_append (new_message, name);
                    free (name);
                  }
                else
                  g_string_append (new_message, "N/A");
                break;
              }
            case 'f':
              {
                /* Filter term. */

                g_string_append (new_message, term ? term : "N/A");
                break;
              }
            case 'q':
              {
                if (event == EVENT_NEW_SECINFO)
                  g_string_append (new_message, "New");
                else if (event == EVENT_UPDATED_SECINFO)
                  g_string_append (new_message, "Updated");
                break;
              }
            case 's':
              /* Type. */
              if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
                g_string_append (new_message,
                                 secinfo_type_name (event_data));
              break;
            case 'S':
              /* Type, plural. */
              if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
                g_string_append (new_message,
                                 secinfo_type_name_plural (event_data));
              break;
            case 't':
              {
                if (truncated)
                  g_string_append_printf (new_message,
                                          "Note: This report exceeds the"
                                          " maximum length of %i characters"
                                          " and thus\n"
                                          "was truncated.\n",
                                          max_length);
                break;
              }
            case 'T':
              {
                g_string_append_printf (new_message, "%i", total);
                break;
              }
            case 'u':
              {
                /* Current user or owner of the Alert */
                if (current_credentials.username
                    && strcmp (current_credentials.username, ""))
                  {
                    g_string_append (new_message, current_credentials.username);
                  }
                else
                  {
                    char *owner = alert_owner_uuid (alert);
                    gchar *name = user_name (owner);
                    g_string_append (new_message, name);
                    free (owner);
                    g_free (name);
                  }
                break;
              }
            case 'U':
              {
                /* Alert UUID */
                char *uuid = alert_uuid (alert);
                g_string_append (new_message, uuid);
                free (uuid);
                break;
              }
            case 'z':
              {
                /* Timezone. */

                g_string_append (new_message, zone ? zone : "N/A");
                break;
              }

            case 'R':
            default:
              g_string_append_c (new_message, '$');
              g_string_append_c (new_message, *point);
              break;
          }
        formatting = 0;
      }
    else if (*point == '$')
      formatting = 1;
    else
      g_string_append_c (new_message, *point);

  return g_string_free (new_message, FALSE);
}

/**
 * @brief Print an SCP alert file path.
 *
 * @param[in]  message      Format string for message.
 * @param[in]  task         Task.
 *
 * @return Freshly allocated message.
 */
static gchar *
scp_alert_path_print (const gchar *message, task_t task)
{
  int formatting;
  const gchar *point, *end;
  GString *new_message;

  assert (message);

  new_message = g_string_new ("");
  for (formatting = 0, point = message, end = (message + strlen (message));
       point < end;
       point++)
    if (formatting)
      {
        switch (*point)
          {
            case '$':
              g_string_append_c (new_message, '$');
              break;
            case 'D':
            case 'T':
              {
                char time_string[9];
                time_t current_time;
                struct tm tm;
                const gchar *format_str;

                if (*point == 'T')
                  format_str = "%H%M%S";
                else
                  format_str = "%Y%m%d";

                memset(&time_string, 0, 9);
                current_time = time (NULL);

                if (localtime_r (&current_time, &tm) == NULL)
                  {
                    g_warning ("%s: localtime failed, aborting",
                                __func__);
                    abort ();
                  }
                if (strftime (time_string, 9, format_str, &tm))
                  g_string_append (new_message, time_string);
                break;
              }
            case 'n':
              if (task)
                {
                  char *name = task_name (task);
                  g_string_append (new_message, name);
                  free (name);
                }
              break;
          }
        formatting = 0;
      }
    else if (*point == '$')
      formatting = 1;
    else
      g_string_append_c (new_message, *point);

  return g_string_free (new_message, FALSE);
}

/**
 * @brief Build and send email for SecInfo alert.
 *
 * @param[in]  alert       Alert.
 * @param[in]  task        Task.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  method      Method from alert.
 * @param[in]  condition   Condition from alert, which was met by event.
 * @param[in]  to_address    To address.
 * @param[in]  from_address  From address.
 *
 * @return 0 success, -1 error, -2 failed to find report format, -3 failed to
 *         find filter.
 */
static int
email_secinfo (alert_t alert, task_t task, event_t event,
               const void* event_data, alert_method_t method,
               alert_condition_t condition, const gchar *to_address,
               const gchar *from_address)
{
  gchar *alert_subject, *message, *subject, *example, *list, *type, *base64;
  gchar *term, *body;
  char *notice, *recipient_credential_id, *condition_filter_id;
  filter_t condition_filter;
  credential_t recipient_credential;
  int ret, count;

  list = new_secinfo_list (event, event_data, alert, &count);

  type = g_strdup (event_data);
  if (type && (example = strstr (type, "_example")))
    example[0] = '\0';

  /* Setup subject. */

  subject = g_strdup_printf
             ("[GVM] %s %s arrived",
              event == EVENT_NEW_SECINFO ? "New" : "Updated",
              secinfo_type_name_plural (type ? type : "nvt"));
  alert_subject = alert_data (alert, "method", "subject");
  if (alert_subject && strlen (alert_subject))
    {
      g_free (subject);
      subject = alert_subject_print (alert_subject, event,
                                     type, alert, task, count);
    }
  g_free (alert_subject);

  /* Setup body. */

  notice = alert_data (alert, "method", "notice");

  message = alert_data (alert, "method", "message");
  if (message == NULL || strlen (message) == 0)
    {
      g_free (message);
      if (notice && strcmp (notice, "0") == 0)
        /* Message with inlined report. */
        message = g_strdup (SECINFO_ALERT_MESSAGE_INCLUDE);
      else if (notice && strcmp (notice, "2") == 0)
        /* Message with attached report. */
        message = g_strdup (SECINFO_ALERT_MESSAGE_ATTACH);
      else
        /* Simple notice message. */
        message = NULL;
    }

  base64 = NULL;
  if (list && notice && strcmp (notice, "2") == 0)
    {
      /* Add list as text attachment. */
      if (get_max_email_attachment_size () <= 0
          || strlen (list) <= get_max_email_attachment_size ())
        base64 = g_base64_encode ((guchar*) list,
                                  strlen (list));
    }

  condition_filter = 0;
  term = NULL;
  condition_filter_id = alert_data (alert, "condition", "filter_id");
  if (condition_filter_id)
    {
      find_resource_no_acl ("filter", condition_filter_id, &condition_filter);
      term = filter_term (condition_filter_id);
    }
  free (condition_filter_id);

  if (message && strlen (message))
    body = alert_message_print (message, event, type,
                                task, alert, condition,
                                NULL, condition_filter, term, NULL, NULL,
                                list,
                                list ? strlen (list) : 0,
                                0, count, 0);
  else
    {
      gchar *event_desc, *condition_desc;
      event_desc = event_description (event, event_data, NULL);
      condition_desc = alert_condition_description
                        (condition, alert);
      body = g_strdup_printf (SECINFO_SIMPLE_NOTICE_FORMAT,
                              event_desc,
                              event_desc,
                              condition_desc);
      free (event_desc);
      free (condition_desc);
    }

  g_free (term);
  g_free (message);
  g_free (list);

  /* Get credential */
  recipient_credential_id = alert_data (alert, "method",
                                        "recipient_credential");
  recipient_credential = 0;
  if (recipient_credential_id)
    {
      find_credential_with_permission (recipient_credential_id,
                                       &recipient_credential, NULL);
    }

  /* Send email. */

  ret = email (to_address, from_address, subject,
               body, base64,
               base64 ? "text/plain" : NULL,
               base64 ? "secinfo-alert" : NULL,
               base64 ? "txt" : NULL,
               recipient_credential);
  g_free (body);
  g_free (type);
  g_free (subject);
  free (recipient_credential_id);
  return ret;
}

/**
 * @brief  Generates report results get data for an alert.
 *
 * @param[in]  alert              The alert to try to get the filter data from.
 * @param[in]  base_get_data      The get data for fallback and other data.
 * @param[out] alert_filter_get   Pointer to the newly allocated get_data.
 * @param[out] filter_return      Pointer to the filter.
 *
 * @return  0 success, -1 error, -3 filter not found.
 */
static int
generate_alert_filter_get (alert_t alert, const get_data_t *base_get_data,
                           get_data_t **alert_filter_get,
                           filter_t *filter_return)
{
  char *ignore_pagination;
  char *filt_id;
  filter_t filter;

  if (alert_filter_get == NULL)
    return -1;

  filt_id = alert_filter_id (alert);
  filter = 0;
  if (filt_id)
    {
      if (find_filter_with_permission (filt_id, &filter,
                                       "get_filters"))
        {
          free (filt_id);
          return -1;
        }
      if (filter == 0)
        {
          free (filt_id);
          return -3;
        }
    }

  if (filter_return)
    *filter_return = filter;

  (*alert_filter_get) = g_malloc0 (sizeof (get_data_t));
  (*alert_filter_get)->details = base_get_data->details;
  (*alert_filter_get)->ignore_pagination = base_get_data->ignore_pagination;
  (*alert_filter_get)->ignore_max_rows_per_page
    = base_get_data->ignore_max_rows_per_page;

  if (filter)
    {
      (*alert_filter_get)->filt_id = g_strdup (filt_id);
      (*alert_filter_get)->filter = filter_term (filt_id);
    }
  else
    {
      (*alert_filter_get)->filt_id = NULL;
      (*alert_filter_get)->filter = g_strdup (base_get_data->filter);
    }

  /* Adjust filter for report composer.
   *
   * As a first step towards a full composer we store a field on the alert
   * for controlling visibility of overrides.
   *
   * We simply use these fields to adjust the filter.  In the future we'll
   * remove the filter terms and extend the way we get the report. */

  gchar *include_overrides;

  ignore_pagination = alert_data (alert, "method",
                                  "composer_ignore_pagination");
  if (ignore_pagination)
    {
      (*alert_filter_get)->ignore_pagination = atoi (ignore_pagination);
      g_free (ignore_pagination);
    }

  include_overrides = alert_data (alert, "method",
                                  "composer_include_overrides");
  if (include_overrides)
    {
      gchar *new_filter;

      new_filter = g_strdup_printf ("overrides=%i %s",
                                    atoi (include_overrides),
                                    (*alert_filter_get)->filter);
      g_free ((*alert_filter_get)->filter);
      (*alert_filter_get)->filter = new_filter;
      (*alert_filter_get)->filt_id = NULL;
      g_free (include_overrides);
    }

  return 0;
}

/**
 * @brief Generate report content for alert
 *
 * @param[in]  alert  The alert the report is generated for.
 * @param[in]  report Report or NULL to get last report of task.
 * @param[in]  task   Task the report belongs to.
 * @param[in]  get    GET data for the report.
 * @param[in]  report_format_data_name  Name of alert data with report format,
 *                                      or NULL if not configurable.
 * @param[in]  report_format_lookup     Name of report format to lookup if
 *                                      lookup by name, or NULL if not required.
 *                                      Used if report_format_data_name is
 *                                      NULL or fails.
 * @param[in]  fallback_format_id       UUID of fallback report format.  Used
 *                                      if both report_format_data_name and
 *                                      report_format_lookup are NULL or fail.
 * @param[in]  overrides_details Whether to include override details in report.
 * @param[out] content              Report content location.
 * @param[out] content_length       Length of report content.
 * @param[out] extension            File extension of report format.
 * @param[out] content_type         Content type of report format.
 * @param[out] term                 Filter term.
 * @param[out] report_zone          Actual timezone used in report.
 * @param[out] host_summary         Summary of results per host.
 * @param[out] used_report_format   Report format used.
 * @param[out] filter_return        Filter used.
 *
 * @return 0 success, -1 error, -2 failed to find report format, -3 failed to
 *         find filter.
 */
static int
report_content_for_alert (alert_t alert, report_t report, task_t task,
                          const get_data_t *get,
                          const char *report_format_data_name,
                          const char *report_format_lookup,
                          const char *fallback_format_id,
                          int overrides_details,
                          gchar **content, gsize *content_length,
                          gchar **extension, gchar **content_type,
                          gchar **term, gchar **report_zone,
                          gchar **host_summary,
                          report_format_t *used_report_format,
                          filter_t *filter_return)
{
  int ret;
  report_format_t report_format;
  get_data_t *alert_filter_get;
  gchar *report_content;
  filter_t filter;

  assert (content);

  // Get filter

  ret = generate_alert_filter_get (alert, get, &alert_filter_get, &filter);
  if (ret)
    return ret;

  // Get last report from task if no report is given

  if ((report == 0)
      && (task_last_report_any_status (task, &report)
          || (report == 0)))
    {
      if (alert_filter_get)
        {
          get_data_reset (alert_filter_get);
          g_free (alert_filter_get);
        }
      return -1;
    }

  // Get report format or use fallback.

  report_format = 0;

  if (report_format_data_name)
    {
      gchar *format_uuid;

      format_uuid = alert_data (alert,
                                "method",
                                report_format_data_name);

      if (format_uuid && strlen (format_uuid))
        {
          if (find_report_format_with_permission (format_uuid,
                                                  &report_format,
                                                  "get_report_formats")
              || (report_format == 0))
            {
              g_warning ("%s: Could not find report format '%s' for %s",
                         __func__, format_uuid,
                         alert_method_name (alert_method (alert)));
              g_free (format_uuid);
              if (alert_filter_get)
                {
                  get_data_reset (alert_filter_get);
                  g_free (alert_filter_get);
                }
              return -2;
            }
        }
      g_free (format_uuid);
    }

  if (report_format_lookup && (report_format == 0))
    {
      if (lookup_report_format (report_format_lookup, &report_format)
          || (report_format == 0))
        {
          g_warning ("%s: Could not find report format '%s' for %s",
                     __func__, report_format_lookup,
                     alert_method_name (alert_method (alert)));
          if (alert_filter_get)
            {
              get_data_reset (alert_filter_get);
              g_free (alert_filter_get);
            }
          return -2;
        }
    }

  if (report_format == 0)
    {
      if (fallback_format_id == NULL)
        {
          g_warning ("%s: No fallback report format for %s",
                     __func__,
                     alert_method_name (alert_method (alert)));
          if (alert_filter_get)
            {
              get_data_reset (alert_filter_get);
              g_free (alert_filter_get);
            }
          return -1;
        }

      if (find_report_format_with_permission
            (fallback_format_id,
             &report_format,
             "get_report_formats")
          || (report_format == 0))
        {
          g_warning ("%s: Could not find fallback RFP '%s' for %s",
                      __func__, fallback_format_id,
                     alert_method_name (alert_method (alert)));
          if (alert_filter_get)
            {
              get_data_reset (alert_filter_get);
              g_free (alert_filter_get);
            }
          return -2;
        }
    }

  // Generate report content

  report_content = manage_report (report,
                                  alert_filter_get ? alert_filter_get : get,
                                  report_format,
                                  overrides_details,
                                  content_length,
                                  extension,
                                  content_type,
                                  term,
                                  report_zone,
                                  host_summary);

  if (alert_filter_get)
    {
      get_data_reset (alert_filter_get);
      g_free (alert_filter_get);
    }

  if (report_content == NULL)
    return -1;

  *content = report_content;
  *used_report_format = report_format;

  return 0;
}

/**
 * @brief  Generates a filename or path for a report.
 *
 * If no custom_format is given, the setting "Report Export File Name"
 *  is used instead.
 *
 * @param[in]  report         The report to generate the filename for.
 * @param[in]  report_format  The report format to use.
 * @param[in]  custom_format  A custom format string to use for the filename.
 * @param[in]  add_extension  Whether to add the filename extension or not.
 *
 * @return  Newly allocated filename.
 */
static gchar *
generate_report_filename (report_t report, report_format_t report_format,
                          const char *custom_format, gboolean add_extension)
{
  task_t task;
  char *fname_format, *report_id, *creation_time, *modification_time;
  char *report_task_name, *rf_name;
  gchar *filename_base, *filename;

  if (custom_format && strcmp (custom_format, ""))
    fname_format = g_strdup (custom_format);
  else
    setting_value (SETTING_UUID_FILE_REPORT, &fname_format);

  report_id = report_uuid (report);

  creation_time = report_creation_time (report);

  modification_time = report_modification_time (report);

  report_task (report, &task);
  report_task_name = task_name (task);

  rf_name = report_format ? report_format_name (report_format)
                          : g_strdup ("unknown");

  filename_base
    = gvm_export_file_name (fname_format,
                            current_credentials.username,
                            "report", report_id,
                            creation_time, modification_time,
                            report_task_name, rf_name);

  if (add_extension && report_format)
    {
      gchar *extension;
      extension = report_format_extension (report_format);
      filename = g_strdup_printf ("%s.%s", filename_base, extension);
      free (extension);
    }
  else
    filename = g_strdup (filename_base);

  free (fname_format);
  free (report_id);
  free (creation_time);
  free (modification_time);
  free (report_task_name);
  free (rf_name);
  g_free (filename_base);

  return filename;
}

/**
 * @brief Trigger an event.
 *
 * @param[in]  alert       Alert.
 * @param[in]  task        Task.
 * @param[in]  report      Report.  0 for most recent report.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  method      Method from alert.
 * @param[in]  condition   Condition from alert, which was met by event.
 * @param[in]  get         GET data for report.
 * @param[in]  overrides_details  If overrides, Whether to include details.
 * @param[out] script_message  Custom error message from the script.
 *
 * @return 0 success, -1 error, -2 failed to find report format, -3 failed to
 *         find filter, -4 failed to find credential, -5 alert script failed.
 */
/**
 * @brief Trigger an event.
 *
 * @param[in]  alert   Alert.
 * @param[in]  task        Task.
 * @param[in]  report      Report.  0 for most recent report.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  method      Method from alert.
 * @param[in]  condition   Condition from alert, which was met by event.
 * @param[in]  get         GET data for report.
 * @param[in]  overrides_details  If overrides, Whether to include details.
 * @param[out] script_message  Custom error message from the script.
 *
 * @return 0 success, -1 error, -2 failed to find report format, -3 failed to
 *         find filter, -4 failed to find credential, -5 alert script failed.
 */
int
trigger (alert_t alert, task_t task, report_t report, event_t event,
         const void* event_data, alert_method_t method,
         alert_condition_t condition,
         const get_data_t *get, int overrides_details, gchar **script_message)
{
  if (script_message)
    *script_message = NULL;

  {
    char *name_alert;
    gchar *event_desc, *alert_desc;

    name_alert = alert_name (alert);
    event_desc = event_description (event, event_data, NULL);
    alert_desc = alert_condition_description (condition, alert);
    g_log ("event alert", G_LOG_LEVEL_MESSAGE,
           "The alert %s was triggered "
           "(Event: %s, Condition: %s)",
           name_alert,
           event_desc,
           alert_desc);
    free (name_alert);
    free (event_desc);
    free (alert_desc);
  }

  switch (method)
    {
      case ALERT_METHOD_EMAIL:
        {
          char *to_address;
          char *format_name;
          format_name = NULL;

          to_address = alert_data (alert, "method", "to_address");

          if (to_address)
            {
              int ret;
              gchar *body, *subject;
              char *name, *notice, *from_address;
              gchar *base64, *type, *extension;

              base64 = NULL;
              type = NULL;
              extension = NULL;

              from_address = alert_data (alert,
                                         "method",
                                         "from_address");

              if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
                {
                  ret = email_secinfo (alert, task, event, event_data, method,
                                       condition, to_address, from_address);
                  free (to_address);
                  free (from_address);
                  return ret;
                }

              notice = alert_data (alert, "method", "notice");
              name = task_name (task);

              if (notice && strcmp (notice, "0") == 0)
                {
                  gchar *event_desc, *condition_desc, *report_content;
                  gchar *alert_subject, *message;
                  gchar *term, *report_zone, *host_summary;
                  report_format_t report_format = 0;
                  gsize content_length;
                  filter_t filter;

                  /* Message with inlined report. */

                  term = NULL;
                  report_zone = NULL;
                  host_summary = NULL;
                  /* report_content_for_alert always sets this, but init it
                   * anyway, to make it easier for the compiler to see. */
                  filter = 0;
                  ret = report_content_for_alert
                          (alert, report, task, get,
                           "notice_report_format",
                           NULL,
                           /* TXT fallback */
                           "a3810a62-1f62-11e1-9219-406186ea4fc5",
                           overrides_details,
                           &report_content, &content_length, &extension,
                           NULL, &term, &report_zone, &host_summary,
                           &report_format, &filter);
                  if (ret || report_content == NULL)
                    {
                      free (notice);
                      free (name);
                      free (to_address);
                      free (from_address);
                      g_free (term);
                      g_free (report_zone);
                      g_free (host_summary);
                      return -1;
                    }
                  format_name = report_format_name (report_format);
                  condition_desc = alert_condition_description (condition,
                                                                alert);
                  event_desc = event_description (event, event_data, NULL);
                  subject = g_strdup_printf ("[GVM] Task '%s': %s",
                                             name ? name : "Internal Error",
                                             event_desc);
                  g_free (event_desc);

                  alert_subject = alert_data (alert, "method", "subject");
                  if (alert_subject && strlen (alert_subject))
                    {
                      g_free (subject);
                      subject = alert_subject_print (alert_subject, event,
                                                     event_data,
                                                     alert, task, 0);
                    }
                  g_free (alert_subject);

                  message = alert_data (alert, "method", "message");
                  if (message == NULL || strlen (message) == 0)
                    {
                      g_free (message);
                      message = g_strdup (ALERT_MESSAGE_INCLUDE);
                    }
                  body = alert_message_print (message, event, event_data,
                                              task, alert, condition,
                                              format_name, filter,
                                              term, report_zone,
                                              host_summary, report_content,
                                              content_length,
                                              content_length
                                              > get_max_email_include_size (),
                                              0,
                                              get_max_email_include_size ());
                  g_free (message);
                  g_free (report_content);
                  g_free (condition_desc);
                  g_free (term);
                  g_free (report_zone);
                  g_free (host_summary);
                }
              else if (notice && strcmp (notice, "2") == 0)
                {
                  gchar *event_desc, *condition_desc, *report_content;
                  report_format_t report_format = 0;
                  gsize content_length;
                  gchar *alert_subject, *message;
                  gchar *term, *report_zone, *host_summary;
                  filter_t filter;

                  /* Message with attached report. */

                  term = NULL;
                  report_zone = NULL;
                  host_summary = NULL;
                  /* report_content_for_alert always sets this, but init it
                   * anyway, to make it easier for the compiler to see. */
                  filter = 0;
                  ret = report_content_for_alert
                          (alert, report, task, get,
                           "notice_attach_format",
                           NULL,
                           /* TXT fallback */
                           "a3810a62-1f62-11e1-9219-406186ea4fc5",
                           overrides_details,
                           &report_content, &content_length, &extension,
                           &type, &term, &report_zone, &host_summary,
                           &report_format, &filter);
                  if (ret || report_content == NULL)
                    {
                      free (notice);
                      free (name);
                      free (to_address);
                      free (from_address);
                      g_free (term);
                      g_free (report_zone);
                      g_free (host_summary);
                      return -1;
                    }
                  format_name = report_format_name (report_format);
                  condition_desc = alert_condition_description (condition,
                                                                    alert);
                  event_desc = event_description (event, event_data, NULL);
                  subject = g_strdup_printf ("[GVM] Task '%s': %s",
                                             name ? name : "Internal Error",
                                             event_desc);
                  g_free (event_desc);

                  alert_subject = alert_data (alert, "method", "subject");
                  if (alert_subject && strlen (alert_subject))
                    {
                      g_free (subject);
                      subject = alert_subject_print (alert_subject, event,
                                                     event_data,
                                                     alert, task, 0);
                    }
                  g_free (alert_subject);
                  if (get_max_email_attachment_size () <= 0
                      || content_length <= get_max_email_attachment_size ())
                    base64 = g_base64_encode ((guchar*) report_content,
                                              content_length);
                  g_free (report_content);
                  message = alert_data (alert, "method", "message");
                  if (message == NULL || strlen (message) == 0)
                    {
                      g_free (message);
                      message = g_strdup (ALERT_MESSAGE_ATTACH);
                    }
                  body = alert_message_print (message, event, event_data,
                                              task, alert, condition,
                                              format_name, filter,
                                              term, report_zone,
                                              host_summary, NULL, 0,
                                              base64 == NULL,
                                              0,
                                              get_max_email_attachment_size ());
                  g_free (message);
                  g_free (condition_desc);
                  g_free (term);
                  g_free (report_zone);
                  g_free (host_summary);
                }
              else
                {
                  gchar *event_desc, *generic_desc, *condition_desc;
                  gchar *alert_subject, *message;

                  /* Simple notice message. */

                  format_name = NULL;
                  event_desc = event_description (event, event_data, name);
                  generic_desc = event_description (event, event_data, NULL);
                  condition_desc = alert_condition_description (condition,
                                                                    alert);

                  subject = g_strdup_printf ("[GVM] Task '%s':"
                                             " An event occurred",
                                             name);

                  alert_subject = alert_data (alert, "method", "subject");
                  if (alert_subject && strlen (alert_subject))
                    {
                      g_free (subject);
                      subject = alert_subject_print (alert_subject, event,
                                                     event_data,
                                                     alert, task, 0);
                    }
                  g_free (alert_subject);

                  message = alert_data (alert, "method", "message");
                  if (message && strlen (message))
                    body = alert_message_print (message, event, event_data,
                                                task, alert, condition,
                                                NULL, 0, NULL, NULL, NULL,
                                                NULL, 0, 0, 0, 0);
                  else
                    body = g_strdup_printf (SIMPLE_NOTICE_FORMAT,
                                            event_desc,
                                            generic_desc,
                                            condition_desc);
                  g_free (message);
                  g_free (event_desc);
                  g_free (generic_desc);
                  g_free (condition_desc);
                }
              free (notice);

              gchar *fname_format, *file_name;
              gchar *report_id, *creation_time, *modification_time;
              char *recipient_credential_id;
              credential_t recipient_credential;

              setting_value (SETTING_UUID_FILE_REPORT, &fname_format);

              report_id = report_uuid (report);

              creation_time = report_start_time (report);

              modification_time = report_end_time (report);

              file_name
                = gvm_export_file_name (fname_format,
                                        current_credentials.username,
                                        "report", report_id,
                                        creation_time, modification_time,
                                        name, format_name);

              /* Get credential */
              recipient_credential_id = alert_data (alert, "method",
                                                    "recipient_credential");
              recipient_credential = 0;
              if (recipient_credential_id)
                {
                  find_credential_with_permission (recipient_credential_id,
                                                  &recipient_credential, NULL);
                }

              ret = email (to_address, from_address, subject, body, base64,
                           type, file_name ? file_name : "openvas-report",
                           extension, recipient_credential);

              free (extension);
              free (type);
              free (name);
              free (format_name);
              g_free (base64);
              free (to_address);
              free (from_address);
              g_free (subject);
              g_free (body);
              g_free (fname_format);
              g_free (file_name);
              g_free (report_id);
              g_free (creation_time);
              g_free (modification_time);
              free (recipient_credential_id);
              return ret;
            }
          return -1;
        }
      case ALERT_METHOD_SCP:
        {
          credential_t credential;
          char *credential_id;
          char *private_key, *password, *username, *host, *path, *known_hosts;
          char *port_str;
          int port;
          gchar *report_content = NULL, *alert_path;
          gsize content_length = 0;
          report_format_t report_format;
          int ret;

          if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
            {
              gchar *message;

              credential_id = alert_data (alert, "method", "scp_credential");
              if (find_credential_with_permission (credential_id,
                                                   &credential,
                                                   "get_credentials"))
                {
                  alert_secure_free (credential_id);
                  return -1;
                }
              else if (credential == 0)
                {
                  alert_secure_free (credential_id);
                  return -4;
                }
              else
                {
                  message = new_secinfo_message (event, event_data, alert);

                  username = credential_value (credential, "username");
                  password = credential_encrypted_value (credential,
                                                         "password");
                  private_key = credential_encrypted_value (credential,
                                                            "private_key");

                  host = alert_data (alert, "method", "scp_host");
                  port_str = alert_data (alert, "method", "scp_port");
                  if (port_str)
                    port = atoi (port_str);
                  else
                    port = 22;
                  path = alert_data (alert, "method", "scp_path");
                  known_hosts = alert_data (alert, "method", "scp_known_hosts");

                  alert_path = scp_alert_path_print (path, task);
                  alert_secure_free (path);

                  ret = scp_to_host (username, password, private_key,
                                     host, port, alert_path, known_hosts,
                                     message, strlen (message),
                                     script_message);

                  alert_secure_gfree (message);
                  alert_secure_free (credential_id);
                  alert_secure_free (private_key);
                  alert_secure_free (password);
                  alert_secure_free (username);
                  alert_secure_free (host);
                  alert_secure_free (port_str);
                  alert_secure_gfree (alert_path);
                  alert_secure_free (known_hosts);

                  return ret;
                }
            }

          ret = report_content_for_alert
                  (alert, 0, task, get,
                   "scp_report_format",
                   NULL,
                   /* XML fallback. */
                   REPORT_FORMAT_UUID_XML,
                   overrides_details,
                   &report_content, &content_length, NULL,
                   NULL, NULL, NULL, NULL,
                   &report_format, NULL);
          if (ret || report_content == NULL)
            {
              g_warning ("%s: Empty Report", __func__);
              alert_secure_gfree_bytes (report_content, content_length);
              return -1;
            }

          credential_id = alert_data (alert, "method", "scp_credential");
          if (find_credential_with_permission (credential_id, &credential,
                                               "get_credentials"))
            {
              alert_secure_free (credential_id);
              alert_secure_gfree_bytes (report_content, content_length);
              return -1;
            }
          else if (credential == 0)
            {
              alert_secure_free (credential_id);
              alert_secure_gfree_bytes (report_content, content_length);
              return -4;
            }
          else
            {
              username = credential_value (credential, "username");
              password = credential_encrypted_value (credential, "password");
              private_key = credential_encrypted_value (credential,
                                                        "private_key");


              host = alert_data (alert, "method", "scp_host");
              port_str = alert_data (alert, "method", "scp_port");
              if (port_str)
                port = atoi (port_str);
              else
                port = 22;
              path = alert_data (alert, "method", "scp_path");
              known_hosts = alert_data (alert, "method", "scp_known_hosts");

              alert_path = scp_alert_path_print (path, task);
              alert_secure_free (path);

              ret = scp_to_host (username, password, private_key,
                                 host, port, alert_path, known_hosts,
                                 report_content, content_length,
                                 script_message);

              alert_secure_free (credential_id);
              alert_secure_free (private_key);
              alert_secure_free (password);
              alert_secure_free (username);
              alert_secure_free (host);
              alert_secure_free (port_str);
              alert_secure_gfree (alert_path);
              alert_secure_free (known_hosts);
            }
          alert_secure_gfree_bytes (report_content, content_length);

          return ret;
        }
      case ALERT_METHOD_SMB:
        {
          char *credential_id, *username, *password;
          char *share_path, *file_path_format, *max_protocol;
          gboolean file_path_is_dir;
          report_format_t report_format;
          gchar *file_path, *report_content, *extension;
          gsize content_length;
          credential_t credential;
          int ret;

          if (report == 0)
            switch (task_last_report_any_status (task, &report))
              {
                case 0:
                  if (report)
                    break;
                case 1:        /* Too few rows in result of query. */
                case -1:
                  return -1;
                  break;
                default:       /* Programming error. */
                  assert (0);
                  return -1;
              }

          if (task == 0 && report)
            {
              ret = report_task (report, &task);
              if (ret)
                return ret;
            }

          credential_id = alert_data (alert, "method", "smb_credential");
          share_path = alert_data (alert, "method", "smb_share_path");
          max_protocol = alert_data (alert, "method", "smb_max_protocol");

          file_path_format = alert_smb_file_path (alert, task);

          file_path_is_dir = (g_str_has_suffix (file_path_format, "\\")
                              || g_str_has_suffix (file_path_format, "/"));

          report_content = NULL;
          content_length = 0;
          extension = NULL;
          report_format = 0;

          g_debug ("Preparing SMB alert delivery destination");

          ret = report_content_for_alert
                  (alert, report, task, get,
                   "smb_report_format",
                   NULL,
                   REPORT_FORMAT_UUID_XML, /* XML fallback */
                   overrides_details,
                   &report_content, &content_length, &extension,
                   NULL, NULL, NULL, NULL, &report_format, NULL);
          if (ret || report_content == NULL)
            {
              alert_secure_free (credential_id);
              alert_secure_free (share_path);
              alert_secure_free (file_path_format);
              alert_secure_free (max_protocol);
              alert_secure_gfree_bytes (report_content, content_length);
              g_free (extension);
              return ret ? ret : -1;
            }

          if (file_path_is_dir)
            {
              char *dirname, *filename;

              dirname = generate_report_filename (report, report_format,
                                                  file_path_format, FALSE);
              filename = generate_report_filename (report, report_format,
                                                   NULL, TRUE);

              file_path = g_strdup_printf ("%s\\%s", dirname, filename);

              free (dirname);
              free (filename);
            }
          else
            {
              file_path = generate_report_filename (report, report_format,
                                                    file_path_format, TRUE);
            }
          alert_secure_free (file_path_format);

          credential = 0;
          ret = find_credential_with_permission (credential_id, &credential,
                                                 "get_credentials");
          if (ret || credential == 0)
            {
              if (ret == 0)
                {
                  g_warning ("%s: Could not find SMB alert credential",
                             __func__);
                }
              alert_secure_free (credential_id);
              alert_secure_free (share_path);
              alert_secure_free (file_path);
              alert_secure_free (max_protocol);
              alert_secure_gfree_bytes (report_content, content_length);
              g_free (extension);
              return ret ? -1 : -4;
            }

          username = credential_value (credential, "username");
          password = credential_encrypted_value (credential, "password");

          ret = smb_send_to_host (password, username, share_path, file_path,
                                  max_protocol, report_content, content_length,
                                  script_message);

          alert_secure_gfree (username);
          alert_secure_gfree (password);
          alert_secure_free (credential_id);
          alert_secure_free (share_path);
          alert_secure_free (file_path);
          alert_secure_free (max_protocol);
          alert_secure_gfree_bytes (report_content, content_length);
          g_free (extension);
          return ret;
        }
      case ALERT_METHOD_SNMP:
        {
          char *community, *agent, *snmp_message;
          int ret;
          gchar *message;

          community = alert_data (alert, "method", "snmp_community");
          agent = alert_data (alert, "method", "snmp_agent");
          snmp_message = alert_data (alert, "method", "snmp_message");

          if (snmp_message)
            {
              if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
                {
                  int count;
                  gchar *list, *example, *type;

                  type = g_strdup (event_data);

                  if (type && (example = strstr (type, "_example")))
                    example[0] = '\0';

                  list = new_secinfo_list (event, event_data, alert, &count);
                  g_free (list);

                  message = alert_subject_print (snmp_message, event, type,
                                                 alert, task, count);

                  g_free (type);
                }
              else
                message = alert_subject_print (snmp_message, event, event_data,
                                               alert, task, 0);
            }
          else
            {
              gchar *event_desc;
              event_desc = event_description (event, event_data, NULL);
              message = g_strdup_printf ("%s", event_desc);
              g_free (event_desc);
            }

          ret = snmp_to_host (community, agent, message, script_message);

          alert_secure_free (agent);
          alert_secure_free (community);
          alert_secure_free (snmp_message);
          alert_secure_gfree (message);
          return ret;
        }
      case ALERT_METHOD_SYSLOG:
        {
          char *submethod;
          gchar *message, *event_desc, *level;

          event_desc = event_description (event, event_data, NULL);
          message = g_strdup_printf ("%s: %s", event_name (event), event_desc);
          g_free (event_desc);

          submethod = alert_data (alert, "method", "submethod");
          level = g_strdup_printf ("event %s", submethod);
          g_free (submethod);

          g_debug ("  syslog level: %s", level);
          g_debug ("syslog message: %s", message);

          g_log (level, G_LOG_LEVEL_MESSAGE, "%s", message);

          g_free (level);
          g_free (message);

          return 0;
        }
      case ALERT_METHOD_START_TASK:
        {
          gvm_connection_t connection;
          char *task_id, *owner_id;

          /* Run the callback to fork a child connected to the Manager. */

          if (manage_fork_connection == NULL)
            {
              g_warning ("%s: no connection fork available", __func__);
              return -1;
            }

          task_id = alert_data (alert, "method", "start_task_task");
          if (task_id == NULL || strcmp (task_id, "") == 0)
            {
              g_warning ("%s: start_task_task missing or empty", __func__);
              return -1;
            }


          owner_id = alert_owner_uuid (alert);
          if (owner_id == NULL)
            {
              g_warning ("%s: could not find alert owner",
                         __func__);
              free (owner_id);
              return -1;
            }

          switch (manage_fork_connection (&connection, owner_id))
            {
              case 0:
                /* Child.  Break, stop task, exit. */
                break;

              case -1:
                /* Parent on error. */
                g_free (task_id);
                g_warning ("%s: fork failed", __func__);
                return -1;
                break;

              default:
                /* Parent.  Continue with whatever lead to this escalation. */
                g_free (task_id);
                free (owner_id);
                return 0;
                break;
            }

          /* Do not reuse the forked manager connection in the alert child. */
          gvm_connection_free (&connection);
          if (yafvs_control_start_alert_task (owner_id, task_id))
            {
              g_free (task_id);
              free (owner_id);
              gvm_close_sentry ();
              exit (EXIT_FAILURE);
            }

          g_free (task_id);
          free (owner_id);
          gvm_close_sentry ();
          exit (EXIT_SUCCESS);
        }
      case ALERT_METHOD_ERROR:
      default:
        break;
    }
  return -1;
}
