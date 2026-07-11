/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "turbovas_control.c"

#include <cgreen/cgreen.h>
#include <string.h>

#define TEST_CONTROL_SECRET "0123456789abcdef0123456789abcdef"

Describe (turbovas_control);
BeforeEach (turbovas_control) {}
AfterEach (turbovas_control) {}

static int cleanup_calls;
static int create_schedule_calls;
static int create_credential_calls;
static int create_credential_result;
static int create_schedule_result;
static int modify_schedule_calls;
static int modify_schedule_result;
static int reinit_calls;
static int session_init_calls;
static int stop_task_calls;
static const char *mock_operator_name;
static gchar *received_credential_type;
static gchar *received_comment;
static gchar *received_icalendar;
static gchar *received_key_private;
static gchar *received_login;
static gchar *received_name;
static gchar *received_secret;
static gchar *received_schedule_uuid;
static gchar *received_timezone;

gchar *
__wrap_user_name (const char *uuid)
{
  (void) uuid;
  return mock_operator_name ? g_strdup (mock_operator_name) : NULL;
}

void
__wrap_reinit_manage_process ()
{
  reinit_calls++;
}

int
__wrap_create_schedule (const char *name, const char *comment,
                        const char *icalendar, const char *timezone,
                        schedule_t *schedule, gchar **error_out)
{
  create_schedule_calls++;
  g_free (received_name);
  g_free (received_comment);
  g_free (received_timezone);
  g_free (received_icalendar);
  received_name = g_strdup (name);
  received_comment = g_strdup (comment);
  received_timezone = g_strdup (timezone);
  received_icalendar = g_strdup (icalendar);
  *schedule = 7;
  *error_out = NULL;
  return create_schedule_result;
}

char *
__wrap_schedule_uuid (schedule_t schedule)
{
  return schedule == 7
         ? g_strdup ("123e4567-e89b-12d3-a456-426614174002") : NULL;
}

int
__wrap_modify_schedule (const char *schedule_uuid, const char *name,
                        const char *comment, const char *icalendar,
                        const char *timezone, gchar **error_out)
{
  modify_schedule_calls++;
  g_free (received_schedule_uuid);
  g_free (received_name);
  g_free (received_comment);
  g_free (received_timezone);
  g_free (received_icalendar);
  received_schedule_uuid = g_strdup (schedule_uuid);
  received_name = g_strdup (name);
  received_comment = g_strdup (comment);
  received_timezone = g_strdup (timezone);
  received_icalendar = g_strdup (icalendar);
  *error_out = NULL;
  return modify_schedule_result;
}

int
__wrap_create_credential
  (const char *name, const char *comment, const char *login,
   const char *given_password, const char *key_private, const char *key_public,
   const char *certificate, const char *community, const char *auth_algorithm,
   const char *privacy_password, const char *privacy_algorithm,
   const char *kdc, array_t *kdcs, const char *realm,
   const char *credential_store_id, const char *vault_id,
   const char *host_identifier, const char *privacy_host_identifier,
   const char *given_type, const char *allow_insecure,
   credential_t *credential)
{
  (void) key_public;
  (void) certificate;
  (void) community;
  (void) auth_algorithm;
  (void) privacy_password;
  (void) privacy_algorithm;
  (void) kdc;
  (void) kdcs;
  (void) realm;
  (void) credential_store_id;
  (void) vault_id;
  (void) host_identifier;
  (void) privacy_host_identifier;
  (void) allow_insecure;
  create_credential_calls++;
  g_free (received_name);
  g_free (received_comment);
  g_free (received_login);
  g_free (received_secret);
  g_free (received_key_private);
  g_free (received_credential_type);
  received_name = g_strdup (name);
  received_comment = g_strdup (comment);
  received_login = g_strdup (login);
  received_secret = g_strdup (given_password);
  received_key_private = g_strdup (key_private);
  received_credential_type = g_strdup (given_type);
  *credential = 8;
  return create_credential_result;
}

char *
__wrap_credential_uuid (credential_t credential)
{
  return credential == 8
         ? g_strdup ("123e4567-e89b-12d3-a456-426614174003") : NULL;
}

void
__wrap_manage_session_init (const char *uuid)
{
  (void) uuid;
  session_init_calls++;
}

Ensure (turbovas_control, accepts_canonical_schedule_create_request)
{
  const char *calendar = "BEGIN:VCALENDAR\nEND:VCALENDAR\n";
  const char *timezone = "Europe/Berlin";
  gchar *calendar_b64 = g_base64_encode ((const guchar *) calendar,
                                         strlen (calendar));
  gchar *timezone_b64 = g_base64_encode ((const guchar *) timezone,
                                         strlen (timezone));
  gchar *request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "TmlnaHRseQ==  %s %s\n", timezone_b64, calendar_b64);
  char operator_uuid[37];
  turbovas_control_schedule_create_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (schedule.name, is_equal_to_string ("Nightly"));
  assert_that (schedule.comment, is_equal_to_string (""));
  assert_that (schedule.timezone, is_equal_to_string (timezone));
  assert_that (schedule.icalendar, is_equal_to_string (calendar));

  turbovas_control_schedule_create_request_clear (&schedule);
  g_free (request);
  g_free (timezone_b64);
  g_free (calendar_b64);
}

Ensure (turbovas_control, accepts_maximum_schedule_fields)
{
  gchar *name = g_strnfill (TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES, 'n');
  gchar *icalendar = g_strnfill (
    TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES, 'i');
  gchar *name_b64 = g_base64_encode ((const guchar *) name, strlen (name));
  gchar *icalendar_b64 = g_base64_encode ((const guchar *) icalendar,
                                           strlen (icalendar));
  gchar *request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "%s   %s\n", name_b64, icalendar_b64);
  char operator_uuid[37];
  turbovas_control_schedule_create_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_true);
  assert_that (strlen (schedule.name),
               is_equal_to (TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES));
  assert_that (strlen (schedule.icalendar),
               is_equal_to (TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES));

  turbovas_control_schedule_create_request_clear (&schedule);
  g_free (request);
  g_free (icalendar_b64);
  g_free (name_b64);
  g_free (icalendar);
  g_free (name);
}

Ensure (turbovas_control, rejects_noncanonical_or_oversized_schedule_fields)
{
  gchar *oversized_name = g_strnfill (
    TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES + 1, 'a');
  gchar *oversized_icalendar = g_strnfill (
    TURBOVAS_CONTROL_SCHEDULE_ICALENDAR_MAX_BYTES + 1, 'i');
  gchar *oversized_name_b64 = g_base64_encode ((const guchar *) oversized_name,
                                                strlen (oversized_name));
  gchar *oversized_icalendar_b64 = g_base64_encode (
    (const guchar *) oversized_icalendar, strlen (oversized_icalendar));
  gchar *invalid_request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "Nightly   QkVHSU46VkNBTEVOREFSCg==\n");
  gchar *oversized_request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "%s   QkVHSU46VkNBTEVOREFSCg==\n", oversized_name_b64);
  gchar *oversized_icalendar_request = g_strdup_printf (
    "schedule-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "TmlnaHRseQ==   %s\n", oversized_icalendar_b64);
  gchar *overlong_request = g_strnfill (
    TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1, 'x');
  char operator_uuid[37];
  turbovas_control_schedule_create_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_create_request (
                 invalid_request, strlen (invalid_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_create_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_create_request (
                 oversized_icalendar_request,
                 strlen (oversized_icalendar_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_create_request (
                 overlong_request, TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1,
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &schedule),
               is_false);

  g_free (overlong_request);
  g_free (oversized_icalendar_request);
  g_free (oversized_request);
  g_free (invalid_request);
  g_free (oversized_icalendar_b64);
  g_free (oversized_name_b64);
  g_free (oversized_icalendar);
  g_free (oversized_name);
}

Ensure (turbovas_control, creates_schedule_in_operator_session)
{
  const turbovas_control_schedule_create_request_t request = {
    .name = "Nightly",
    .comment = "",
    .timezone = "Europe/Berlin",
    .icalendar = "BEGIN:VCALENDAR\nEND:VCALENDAR\n",
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_schedule_calls = 0;
  create_schedule_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  mock_operator_name = "operator";

  assert_that (turbovas_control_create_schedule (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174002"));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (create_schedule_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (received_name, is_equal_to_string (request.name));
  assert_that (received_comment, is_equal_to_string (request.comment));
  assert_that (received_timezone, is_equal_to_string (request.timezone));
  assert_that (received_icalendar, is_equal_to_string (request.icalendar));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (turbovas_control, maps_schedule_create_responses)
{
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (turbovas_control_schedule_create_response (
                 0, "123e4567-e89b-12d3-a456-426614174002", response),
               is_equal_to_string ("0 created 123e4567-e89b-12d3-a456-426614174002\n"));
  assert_that (turbovas_control_schedule_create_response (1, NULL, response),
               is_equal_to_string ("1 exists\n"));
  assert_that (turbovas_control_schedule_create_response (3, NULL, response),
               is_equal_to_string ("3 invalid_ical\n"));
  assert_that (turbovas_control_schedule_create_response (4, NULL, response),
               is_equal_to_string ("4 invalid_timezone\n"));
  assert_that (turbovas_control_schedule_create_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (turbovas_control_schedule_create_response (-1, NULL, response),
               is_equal_to_string ("-1 internal\n"));
}

Ensure (turbovas_control, accepts_username_password_credential_create_request)
{
  const char *request =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 up "
    "Q1NWIG9wZXJhdG9y QnVsayBpbXBvcnQ= cm9iZXJ0 c2VjcmV0IA== \n";
  char operator_uuid[37];
  turbovas_control_credential_create_request_t credential = {0};

  assert_that (turbovas_control_parse_credential_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (credential.credential_type, is_equal_to_string ("up"));
  assert_that (credential.name, is_equal_to_string ("CSV operator"));
  assert_that (credential.comment, is_equal_to_string ("Bulk import"));
  assert_that (credential.login, is_equal_to_string ("robert"));
  assert_that (credential.secret, is_equal_to_string ("secret "));
  assert_that (credential.private_key, is_equal_to_string (""));

  turbovas_control_credential_create_request_clear (&credential);
}

Ensure (turbovas_control, accepts_ssh_key_credential_create_request)
{
  const char *request =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 usk "
    "U1NIIG9wZXJhdG9y  cm9iZXJ0  "
    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCg==\n";
  char operator_uuid[37];
  turbovas_control_credential_create_request_t credential = {0};

  assert_that (turbovas_control_parse_credential_create_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_true);
  assert_that (credential.credential_type, is_equal_to_string ("usk"));
  assert_that (credential.name, is_equal_to_string ("SSH operator"));
  assert_that (credential.comment, is_equal_to_string (""));
  assert_that (credential.login, is_equal_to_string ("robert"));
  assert_that (credential.secret, is_equal_to_string (""));
  assert_that (credential.private_key,
               is_equal_to_string ("-----BEGIN PRIVATE KEY-----\n"));

  turbovas_control_credential_create_request_clear (&credential);
}

Ensure (turbovas_control, rejects_malformed_credential_create_requests)
{
  const char *bad_type =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 snmp "
    "TmFtZQ==  cm9iZXJ0 c2VjcmV0IA== \n";
  const char *missing_password =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 up "
    "TmFtZQ==  cm9iZXJ0  \n";
  const char *up_with_key =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 up "
    "TmFtZQ==  cm9iZXJ0 c2VjcmV0IA== a2V5\n";
  const char *ssh_without_key =
    "credential-create " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 usk "
    "TmFtZQ==  cm9iZXJ0  \n";
  char operator_uuid[37];
  turbovas_control_credential_create_request_t credential = {0};

  assert_that (turbovas_control_parse_credential_create_request (
                 bad_type, strlen (bad_type), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_false);
  assert_that (turbovas_control_parse_credential_create_request (
                 missing_password, strlen (missing_password),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &credential),
               is_false);
  assert_that (turbovas_control_parse_credential_create_request (
                 up_with_key, strlen (up_with_key), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, &credential),
               is_false);
  assert_that (turbovas_control_parse_credential_create_request (
                 ssh_without_key, strlen (ssh_without_key),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, &credential),
               is_false);
}

Ensure (turbovas_control, creates_credential_in_operator_session)
{
  const turbovas_control_credential_create_request_t request = {
    .credential_type = "usk",
    .name = "SSH operator",
    .comment = "Bulk import",
    .login = "robert",
    .secret = "passphrase",
    .private_key = "-----BEGIN PRIVATE KEY-----\n",
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_credential_calls = 0;
  create_credential_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  mock_operator_name = "operator";

  assert_that (turbovas_control_create_credential (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (0));
  assert_that (created_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174003"));
  assert_that (create_credential_calls, is_equal_to (1));
  assert_that (received_credential_type, is_equal_to_string ("usk"));
  assert_that (received_name, is_equal_to_string (request.name));
  assert_that (received_comment, is_equal_to_string (request.comment));
  assert_that (received_login, is_equal_to_string (request.login));
  assert_that (received_secret, is_equal_to_string (request.secret));
  assert_that (received_key_private,
               is_equal_to_string (request.private_key));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (turbovas_control, maps_credential_create_responses)
{
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (turbovas_control_credential_create_response (
                 0, "123e4567-e89b-12d3-a456-426614174003", response),
               is_equal_to_string
                 ("0 created 123e4567-e89b-12d3-a456-426614174003\n"));
  assert_that (turbovas_control_credential_create_response (1, NULL, response),
               is_equal_to_string ("1 exists\n"));
  assert_that (turbovas_control_credential_create_response (2, NULL, response),
               is_equal_to_string ("2 invalid_login\n"));
  assert_that (turbovas_control_credential_create_response (3, NULL, response),
               is_equal_to_string ("3 invalid_key\n"));
  assert_that (turbovas_control_credential_create_response (5, NULL, response),
               is_equal_to_string ("5 login_required\n"));
  assert_that (turbovas_control_credential_create_response (6, NULL, response),
               is_equal_to_string ("6 password_required\n"));
  assert_that (turbovas_control_credential_create_response (7, NULL, response),
               is_equal_to_string ("7 key_required\n"));
  assert_that (turbovas_control_credential_create_response (-2, NULL, response),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (turbovas_control_credential_create_response (99, NULL, response),
               is_equal_to_string ("99 forbidden\n"));
}

Ensure (turbovas_control, tracks_partial_request_length_and_clears_secrets)
{
  const char *partial = "credential-create partial-secret cGFzc3dvcmQ=";
  char request[TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1] = {0};
  gchar *sensitive = g_strdup ("secret-copy");
  size_t request_len = 999;
  int sockets[2];
  size_t i;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (write (sockets[0], partial, strlen (partial)),
               is_equal_to ((ssize_t) strlen (partial)));
  close (sockets[0]);
  assert_that (turbovas_control_read_request (sockets[1], request,
                                               &request_len),
               is_false);
  close (sockets[1]);
  assert_that (request_len, is_equal_to (strlen (partial)));
  assert_that (memcmp (request, partial, request_len), is_equal_to (0));

  turbovas_control_secure_clear (request, request_len);
  for (i = 0; i < request_len; i++)
    assert_that (request[i], is_equal_to (0));

  turbovas_control_secure_clear (sensitive, strlen (sensitive));
  for (i = 0; i < strlen ("secret-copy"); i++)
    assert_that (sensitive[i], is_equal_to (0));
  g_free (sensitive);
}

Ensure (turbovas_control, rejects_nonexistent_credential_operator_before_create)
{
  const turbovas_control_credential_create_request_t request = {
    .credential_type = "up",
    .name = "Operator",
    .comment = "",
    .login = "operator",
    .secret = "password",
    .private_key = "",
  };
  char created_uuid[37];

  cleanup_calls = 0;
  create_credential_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  mock_operator_name = NULL;

  assert_that (turbovas_control_create_credential (
                 "123e4567-e89b-12d3-a456-426614174000", &request,
                 created_uuid),
               is_equal_to (99));
  assert_that (create_credential_calls, is_equal_to (0));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
}

Ensure (turbovas_control, accepts_schedule_modify_presence_and_empty_tokens)
{
  const char *calendar = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
  gchar *calendar_b64 = g_base64_encode ((const guchar *) calendar,
                                         strlen (calendar));
  gchar *request = g_strdup_printf (
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "+TmV3IG5hbWU= + - +%s\n", calendar_b64);
  char operator_uuid[37];
  char schedule_uuid[37];
  turbovas_control_schedule_modify_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_modify_request (
                 request, strlen (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (schedule_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (schedule.name, is_equal_to_string ("New name"));
  assert_that (schedule.comment, is_equal_to_string (""));
  assert_that (schedule.timezone, is_null);
  assert_that (schedule.icalendar, is_equal_to_string (calendar));

  turbovas_control_schedule_modify_request_clear (&schedule);
  g_free (request);
  g_free (calendar_b64);
}

Ensure (turbovas_control, rejects_malformed_or_unauthenticated_schedule_modify)
{
  const char *extra =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "- - - +QQ== extra\n";
  const char *bare_base64 =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "TmlnaHRseQ== - - +QQ==\n";
  const char *noncanonical_base64 =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "+TQ= - - +QQ==\n";
  const char *wrong_secret =
    "schedule-modify fedcba9876543210fedcba9876543210 "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "- - - +QQ==\n";
  const char *invalid_uuid =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z "
    "- - - +QQ==\n";
  const char *all_absent =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 "
    "- - - -\n";
  gchar *control_name_b64;
  gchar *control_name_request;
  char operator_uuid[37];
  char schedule_uuid[37];
  turbovas_control_schedule_modify_request_t schedule = {0};

  control_name_b64 = g_base64_encode ((const guchar *) "line\nname", 9);
  control_name_request = g_strdup_printf (
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 +%s - - +QQ==\n",
    control_name_b64);

  assert_that (turbovas_control_parse_schedule_modify_request (
                 extra, strlen (extra), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 bare_base64, strlen (bare_base64), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 noncanonical_base64, strlen (noncanonical_base64),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 wrong_secret, strlen (wrong_secret), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 invalid_uuid, strlen (invalid_uuid), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 all_absent, strlen (all_absent), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 control_name_request, strlen (control_name_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);

  g_free (control_name_request);
  g_free (control_name_b64);
}

Ensure (turbovas_control, rejects_invalid_schedule_modify_field_bytes)
{
  const char *prefix =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 ";
  const gchar invalid_utf8[] = {(gchar) 0xc3};
  gchar *nul_b64 = g_base64_encode ((const guchar *) "\0", 1);
  gchar *invalid_utf8_b64 = g_base64_encode ((const guchar *) invalid_utf8,
                                              sizeof (invalid_utf8));
  gchar *oversized_name = g_strnfill (
    TURBOVAS_CONTROL_SCHEDULE_NAME_MAX_BYTES + 1, 'n');
  gchar *oversized_name_b64 = g_base64_encode (
    (const guchar *) oversized_name, strlen (oversized_name));
  gchar *nul_request = g_strdup_printf ("%s+%s - - +QQ==\n", prefix,
                                        nul_b64);
  gchar *invalid_utf8_request = g_strdup_printf ("%s+%s - - +QQ==\n",
                                                 prefix, invalid_utf8_b64);
  gchar *oversized_request = g_strdup_printf ("%s+%s - - +QQ==\n", prefix,
                                               oversized_name_b64);
  gchar *calendar_control_request = g_strdup_printf ("%s- - - +AQ==\n",
                                                      prefix);
  char operator_uuid[37];
  char schedule_uuid[37];
  turbovas_control_schedule_modify_request_t schedule = {0};

  assert_that (turbovas_control_parse_schedule_modify_request (
                 nul_request, strlen (nul_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 invalid_utf8_request, strlen (invalid_utf8_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 oversized_request, strlen (oversized_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);
  assert_that (turbovas_control_parse_schedule_modify_request (
                 calendar_control_request, strlen (calendar_control_request),
                 TEST_CONTROL_SECRET, strlen (TEST_CONTROL_SECRET),
                 operator_uuid, schedule_uuid, &schedule),
               is_false);

  g_free (calendar_control_request);
  g_free (oversized_request);
  g_free (invalid_utf8_request);
  g_free (nul_request);
  g_free (oversized_name_b64);
  g_free (oversized_name);
  g_free (invalid_utf8_b64);
  g_free (nul_b64);
}

Ensure (turbovas_control, distinguishes_absent_and_empty_schedule_modify_calendar)
{
  const char *absent_request =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 - +bWV0YWRhdGE= - -\n";
  const char *empty_request =
    "schedule-modify " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 - +bWV0YWRhdGE= - +\n";
  char operator_uuid[37];
  char schedule_uuid[37];
  turbovas_control_schedule_modify_request_t absent = {0};
  turbovas_control_schedule_modify_request_t empty = {0};

  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  modify_schedule_calls = 0;
  modify_schedule_result = 0;
  mock_operator_name = "operator";

  assert_that (turbovas_control_parse_schedule_modify_request (
                 absent_request, strlen (absent_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &absent),
               is_true);
  assert_that (absent.comment, is_equal_to_string ("metadata"));
  assert_that (absent.icalendar, is_null);
  assert_that (turbovas_control_modify_schedule (operator_uuid, schedule_uuid,
                                                 &absent),
               is_equal_to (0));
  assert_that (received_icalendar, is_null);

  modify_schedule_result = 6;
  assert_that (turbovas_control_parse_schedule_modify_request (
                 empty_request, strlen (empty_request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, schedule_uuid,
                 &empty),
               is_true);
  assert_that (empty.comment, is_equal_to_string ("metadata"));
  assert_that (empty.icalendar, is_equal_to_string (""));
  assert_that (turbovas_control_modify_schedule (operator_uuid, schedule_uuid,
                                                 &empty),
               is_equal_to (6));
  assert_that (received_icalendar, is_equal_to_string (""));
  assert_that (reinit_calls, is_equal_to (2));
  assert_that (session_init_calls, is_equal_to (2));
  assert_that (modify_schedule_calls, is_equal_to (2));
  assert_that (cleanup_calls, is_equal_to (2));

  turbovas_control_schedule_modify_request_clear (&empty);
  turbovas_control_schedule_modify_request_clear (&absent);
}

Ensure (turbovas_control, modifies_schedule_in_operator_session)
{
  const turbovas_control_schedule_modify_request_t request = {
    .name = NULL,
    .comment = "",
    .timezone = "Europe/Berlin",
    .icalendar = "BEGIN:VCALENDAR\nEND:VCALENDAR\n",
  };

  cleanup_calls = 0;
  modify_schedule_calls = 0;
  modify_schedule_result = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  mock_operator_name = "operator";

  assert_that (turbovas_control_modify_schedule (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001", &request),
               is_equal_to (0));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (1));
  assert_that (modify_schedule_calls, is_equal_to (1));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (received_schedule_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
  assert_that (received_name, is_null);
  assert_that (received_comment, is_equal_to_string (request.comment));
  assert_that (received_timezone, is_equal_to_string (request.timezone));
  assert_that (received_icalendar, is_equal_to_string (request.icalendar));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

Ensure (turbovas_control, maps_schedule_modify_responses)
{
  char response[TURBOVAS_CONTROL_MAX_RESPONSE_BYTES];

  assert_that (turbovas_control_schedule_modify_response (0, response),
               is_equal_to_string ("0 modified\n"));
  assert_that (turbovas_control_schedule_modify_response (1, response),
               is_equal_to_string ("1 not_found\n"));
  assert_that (turbovas_control_schedule_modify_response (2, response),
               is_equal_to_string ("2 duplicate\n"));
  assert_that (turbovas_control_schedule_modify_response (6, response),
               is_equal_to_string ("6 invalid_ical\n"));
  assert_that (turbovas_control_schedule_modify_response (7, response),
               is_equal_to_string ("7 invalid_timezone\n"));
  assert_that (turbovas_control_schedule_modify_response (99, response),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (turbovas_control_schedule_modify_response (-2, response),
               is_equal_to_string ("-2 malformed\n"));
  assert_that (turbovas_control_schedule_modify_response (-1, response),
               is_equal_to_string ("-1 internal\n"));
}

int
__wrap_stop_task (const char *task_uuid)
{
  (void) task_uuid;
  stop_task_calls++;
  return 0;
}

void
__wrap_cleanup_manage_process (gboolean full)
{
  (void) full;
  cleanup_calls++;
}

Ensure (turbovas_control, accepts_exact_authenticated_stop_request)
{
  const char *request =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (turbovas_control_parse_request (request, strlen (request),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_true);
  assert_that (operator_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174000"));
  assert_that (task_uuid,
               is_equal_to_string ("123e4567-e89b-12d3-a456-426614174001"));
}

Ensure (turbovas_control, rejects_noncanonical_or_extra_requests)
{
  const char *extra =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001 extra\n";
  const char *invalid_uuid =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-42661417400z\n";
  char request[TURBOVAS_CONTROL_MAX_REQUEST_BYTES + 1];
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (turbovas_control_parse_request (extra, strlen (extra),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_false);
  assert_that (turbovas_control_parse_request (invalid_uuid,
                                               strlen (invalid_uuid),
                                               TEST_CONTROL_SECRET,
                                               strlen (TEST_CONTROL_SECRET),
                                               operator_uuid, task_uuid),
               is_false);
  memset (request, 'x', sizeof (request));
  assert_that (turbovas_control_parse_request (
                 request, sizeof (request), TEST_CONTROL_SECRET,
                 strlen (TEST_CONTROL_SECRET), operator_uuid, task_uuid),
               is_false);
}

Ensure (turbovas_control, rejects_missing_weak_or_incorrect_secrets)
{
  const char *request =
    "stop " TEST_CONTROL_SECRET " "
    "123e4567-e89b-12d3-a456-426614174000 "
    "123e4567-e89b-12d3-a456-426614174001\n";
  char operator_uuid[37];
  char task_uuid[37];

  assert_that (turbovas_control_secret_is_valid (NULL, 0), is_false);
  assert_that (turbovas_control_secret_is_valid ("too-short", 9), is_false);
  assert_that (turbovas_control_secret_is_valid (TEST_CONTROL_SECRET,
                                                 strlen (TEST_CONTROL_SECRET)),
               is_true);
  assert_that (turbovas_control_secret_is_valid (
                 "0123456789abcdef0123456789abcde!", 32),
               is_false);
  assert_that (turbovas_control_parse_request (
                 request, strlen (request), NULL, 0,
                 operator_uuid, task_uuid),
               is_false);
  assert_that (turbovas_control_parse_request (
                 request, strlen (request), "too-short", 9,
                 operator_uuid, task_uuid),
               is_false);
  assert_that (turbovas_control_parse_request (
                 request, strlen (request),
                 "fedcba9876543210fedcba9876543210", 32,
                 operator_uuid, task_uuid),
               is_false);
}

Ensure (turbovas_control, maps_only_protocol_responses)
{
  assert_that (turbovas_control_response (0), is_equal_to_string ("0 stopped\n"));
  assert_that (turbovas_control_response (2),
               is_equal_to_string ("2 inactive\n"));
  assert_that (turbovas_control_response (1),
               is_equal_to_string ("1 requested\n"));
  assert_that (turbovas_control_response (3),
               is_equal_to_string ("3 not_found\n"));
  assert_that (turbovas_control_response (99),
               is_equal_to_string ("99 forbidden\n"));
  assert_that (turbovas_control_response (-1),
               is_equal_to_string ("-1 internal\n"));
  assert_that (turbovas_control_response (-2),
               is_equal_to_string ("-2 scanner_status\n"));
  assert_that (turbovas_control_response (-3),
               is_equal_to_string ("-3 scanner_stop\n"));
  assert_that (turbovas_control_response (-4),
               is_equal_to_string ("-4 scanner_delete\n"));
  assert_that (turbovas_control_response (-5),
               is_equal_to_string ("-5 scanner_verify\n"));
}

Ensure (turbovas_control, rejects_nonexistent_operator_before_session_setup)
{
  cleanup_calls = 0;
  reinit_calls = 0;
  session_init_calls = 0;
  stop_task_calls = 0;
  mock_operator_name = NULL;

  assert_that (turbovas_control_stop_task (
                 "123e4567-e89b-12d3-a456-426614174000",
                 "123e4567-e89b-12d3-a456-426614174001"),
               is_equal_to (99));
  assert_that (cleanup_calls, is_equal_to (1));
  assert_that (reinit_calls, is_equal_to (1));
  assert_that (session_init_calls, is_equal_to (0));
  assert_that (stop_task_calls, is_equal_to (0));
  assert_that (current_credentials.uuid, is_null);
  assert_that (current_credentials.username, is_null);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, turbovas_control,
                         accepts_exact_authenticated_stop_request);
  add_test_with_context (suite, turbovas_control,
                         rejects_noncanonical_or_extra_requests);
  add_test_with_context (suite, turbovas_control,
                         rejects_missing_weak_or_incorrect_secrets);
  add_test_with_context (suite, turbovas_control,
                         maps_only_protocol_responses);
  add_test_with_context (suite, turbovas_control,
                         accepts_canonical_schedule_create_request);
  add_test_with_context (suite, turbovas_control,
                         accepts_maximum_schedule_fields);
  add_test_with_context (suite, turbovas_control,
                         rejects_noncanonical_or_oversized_schedule_fields);
  add_test_with_context (suite, turbovas_control,
                         creates_schedule_in_operator_session);
  add_test_with_context (suite, turbovas_control,
                         maps_schedule_create_responses);
  add_test_with_context (suite, turbovas_control,
                         accepts_username_password_credential_create_request);
  add_test_with_context (suite, turbovas_control,
                         accepts_ssh_key_credential_create_request);
  add_test_with_context (suite, turbovas_control,
                         rejects_malformed_credential_create_requests);
  add_test_with_context (suite, turbovas_control,
                         creates_credential_in_operator_session);
  add_test_with_context (suite, turbovas_control,
                         maps_credential_create_responses);
  add_test_with_context (suite, turbovas_control,
                         tracks_partial_request_length_and_clears_secrets);
  add_test_with_context (suite, turbovas_control,
                         rejects_nonexistent_credential_operator_before_create);
  add_test_with_context (suite, turbovas_control,
                         accepts_schedule_modify_presence_and_empty_tokens);
  add_test_with_context (suite, turbovas_control,
                         rejects_malformed_or_unauthenticated_schedule_modify);
  add_test_with_context (suite, turbovas_control,
                         rejects_invalid_schedule_modify_field_bytes);
  add_test_with_context (suite, turbovas_control,
                         distinguishes_absent_and_empty_schedule_modify_calendar);
  add_test_with_context (suite, turbovas_control,
                         modifies_schedule_in_operator_session);
  add_test_with_context (suite, turbovas_control,
                         maps_schedule_modify_responses);
  add_test_with_context (suite, turbovas_control,
                         rejects_nonexistent_operator_before_session_setup);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
