/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "nasl_ssh_host_key_policy.h"

#include <string.h>

static gchar *
encode_policy (const char *json)
{
  return g_base64_encode ((const guchar *) json, strlen (json));
}

static void
test_disabled_without_credential_policy (void)
{
  const guchar digest[32] = {0};

  g_assert_cmpint (nasl_ssh_host_key_policy_verify (
                     NULL, NULL, "192.0.2.1", digest, sizeof (digest)),
                   ==, NASL_SSH_HOST_KEY_POLICY_DISABLED);
}

static void
test_match_mismatch_and_missing_host (void)
{
  const guchar digest[32] = {0};
  const guchar other_digest[32] = {1};
  gchar *policy = encode_policy (
    "[{\"host\":\"192.0.2.1\","
    "\"fingerprint\":\"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]");

  g_assert_cmpint (nasl_ssh_host_key_policy_verify (
                     "1", policy, "192.0.2.1", digest, sizeof (digest)),
                   ==, NASL_SSH_HOST_KEY_POLICY_MATCH);
  g_assert_cmpint (nasl_ssh_host_key_policy_verify (
                     "1", policy, "192.0.2.1", other_digest,
                     sizeof (other_digest)),
                   ==, NASL_SSH_HOST_KEY_POLICY_MISMATCH);
  g_assert_cmpint (nasl_ssh_host_key_policy_verify (
                     "1", policy, "192.0.2.2", digest, sizeof (digest)),
                   ==, NASL_SSH_HOST_KEY_POLICY_MISSING);
  g_free (policy);
}

static void
test_invalid_and_duplicate_policies (void)
{
  const guchar digest[32] = {0};
  gchar *duplicates = encode_policy (
    "[{\"host\":\"192.0.2.1\","
    "\"fingerprint\":\"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"},"
    "{\"host\":\"192.0.2.1\","
    "\"fingerprint\":\"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]");

  g_assert_cmpint (nasl_ssh_host_key_policy_verify (
                     "1", "not-base64", "192.0.2.1", digest,
                     sizeof (digest)),
                   ==, NASL_SSH_HOST_KEY_POLICY_INVALID);
  g_assert_cmpint (nasl_ssh_host_key_policy_verify (
                     "1", duplicates, "192.0.2.1", digest, sizeof (digest)),
                   ==, NASL_SSH_HOST_KEY_POLICY_INVALID);
  g_free (duplicates);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/nasl/ssh-host-key-policy/disabled",
                   test_disabled_without_credential_policy);
  g_test_add_func ("/nasl/ssh-host-key-policy/verification",
                   test_match_mismatch_and_missing_host);
  g_test_add_func ("/nasl/ssh-host-key-policy/invalid",
                   test_invalid_and_duplicate_policies);
  return g_test_run ();
}
