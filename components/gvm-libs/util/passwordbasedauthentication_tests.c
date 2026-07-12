/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 */

#include "authutils.h"
#include "passwordbasedauthentication.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <string.h>

#define VALID_DIGEST                                                   \
  "m9FKMIu5Cnk2IjQ8apVSyRX8ZoTJCSrW3BVYyCuRBo/cs9.bCCttAMYZykJO6nxT3." \
  "yB/QbsEwz.35MTvePM6/"
#define VALID_HASH "$6$0000000000000000$" VALID_DIGEST
#define PUNCTUATION_HASH                                                \
  "$6$rounds=20000$A-_@z$"                                              \
  "D9GC5BmxmGTohkxCCmoCO47rEclGmoghPPdlQ8vIFUpbl/nby5No6rPgogIB7BikyFO" \
  "OvfXQI3f9A5EhKTaO8/"
#define NO_ROUNDS_HASH                                                  \
  "$6$no-rounds-_@$"                                                    \
  "bdx7ctr3wfSmvF3J18QgjfpufC0HJaaYU4jWJQEzPQt6SGscdww2ADQ9abn8e/m1rJE" \
  "bot20x68BQIbzGr2QZ/"
#define PEPPER_STORED_HASH                                              \
  "$6$rounds=1000$abcdefghijkl0000$"                                    \
  "kOskEdkrT4oDzIIK3d9hK4ewrPTx5CvtLUYzQ6up5iXq9RdmUbxr1Yj5G76UiplOJBE" \
  "8uGTX60VQ5.f0Vt5VS/"

struct pepper_case
{
  const char *pepper;
  unsigned int length;
};

static const struct pepper_case pepper_cases[] = {
  {NULL, 0}, {"A", 1}, {"Az09", 4}, {"./-_", 4}, {"A-_@", 4}, {"?~#\"", 4},
};

static const char *malformed_hashes[] = {
  "$",
  "$6",
  "$6$0000000000000000" VALID_DIGEST,
  "$6$0000000000000000$$" VALID_DIGEST,
  "$5$0000000000000000$" VALID_DIGEST,
  "$06$0000000000000000$" VALID_DIGEST,
  "$6x$0000000000000000$" VALID_DIGEST,
  "$6$rounds=$0000000000000000$" VALID_DIGEST,
  "$6$rounds=abc$0000000000000000$" VALID_DIGEST,
  "$6$rounds=+1000$0000000000000000$" VALID_DIGEST,
  "$6$rounds=-1000$0000000000000000$" VALID_DIGEST,
  "$6$rounds=01000$0000000000000000$" VALID_DIGEST,
  "$6$rounds=999$0000000000000000$" VALID_DIGEST,
  "$6$rounds=1000001$0000000000000000$" VALID_DIGEST,
  "$6$rounds=999999999$0000000000000000$" VALID_DIGEST,
  "$6$rounds=999999999999999999999999$0000000000000000$" VALID_DIGEST,
  "$6$rounds=1000x$0000000000000000$" VALID_DIGEST,
  "$6$$" VALID_DIGEST,
  "$6$00000000000000000$" VALID_DIGEST,
  "$6$000000000000000!$" VALID_DIGEST,
  "$6$0000000000000000$",
  "$6$0000000000000000$"
  "!9FKMIu5Cnk2IjQ8apVSyRX8ZoTJCSrW3BVYyCuRBo/cs9.bCCttAMYZykJO6nxT3."
  "yB/QbsEwz.35MTvePM6/",
  "$6$0000000000000000$" VALID_DIGEST "A",
  "$6$0000000000000000$" VALID_DIGEST "$extra",
};

Describe (PBA);
BeforeEach (PBA)
{
}
AfterEach (PBA)
{
}

Ensure (PBA, returns_false_on_not_phc_compliant_setting)
{
  assert_false (pba_is_phc_compliant ("password"));
}
Ensure (PBA, returns_true_on_phc_compliant_setting)
{
  assert_true (pba_is_phc_compliant ("$"));
  assert_true (pba_is_phc_compliant ("$password"));
}

Ensure (PBA, parses_only_supported_sha512_crypt_hashes)
{
  struct sha512_crypt_parts parts;
  const char *valid_hashes[] = {
    VALID_HASH,
    PUNCTUATION_HASH,
    NO_ROUNDS_HASH,
    "$6$rounds=1000$a$" VALID_DIGEST,
    "$6$rounds=1000000$abcdefghijklmnop$" VALID_DIGEST,
  };
  size_t i;

  for (i = 0; i < sizeof (valid_hashes) / sizeof (valid_hashes[0]); i++)
    assert_true (parse_sha512_crypt (valid_hashes[i], 1, &parts));

  for (i = 0; i < sizeof (malformed_hashes) / sizeof (malformed_hashes[0]); i++)
    assert_false (parse_sha512_crypt (malformed_hashes[i], 1, &parts));
}

Ensure (PBA, separates_salt_and_digest_grammars)
{
  const char accepted_punctuation[] = {'-', '_', '@', '?', '~', '#', '"'};
  const char rejected_salt[] = {'\0', '\t', '\n', ' ',  '!', '$',
                                '*',  ':',  ';',  '\\', 0x7f};
  size_t i;

  for (i = 0;
       i < sizeof (accepted_punctuation) / sizeof (accepted_punctuation[0]);
       i++)
    {
      assert_true (is_sha512_salt_char (accepted_punctuation[i]));
      assert_false (is_crypt_base64_digest_char (accepted_punctuation[i]));
    }
  for (i = 0; i < sizeof (rejected_salt) / sizeof (rejected_salt[0]); i++)
    assert_false (is_sha512_salt_char (rejected_salt[i]));

  assert_true (is_sha512_salt_char ('.'));
  assert_true (is_crypt_base64_digest_char ('.'));
}

Ensure (PBA, enforces_round_generation_and_verification_policy)
{
  struct sha512_crypt_parts parts;
  const char *minimum = "$6$rounds=1000$salt$" VALID_DIGEST;
  const char *maximum = "$6$rounds=1000000$salt$" VALID_DIGEST;
  const char *too_low = "$6$rounds=999$salt$" VALID_DIGEST;
  const char *too_high = "$6$rounds=1000001$salt$" VALID_DIGEST;
  const char *leading_zero = "$6$rounds=01000$salt$" VALID_DIGEST;
  struct PBASettings *setting;

  assert_true (parse_sha512_crypt (minimum, 1, &parts));
  assert_equal (parts.rounds, 1000);
  assert_true (parse_sha512_crypt (maximum, 1, &parts));
  assert_equal (parts.rounds, PBA_MAX_ROUNDS);
  assert_false (parse_sha512_crypt (too_low, 1, &parts));
  assert_false (parse_sha512_crypt (too_high, 1, &parts));
  assert_false (parse_sha512_crypt (leading_zero, 1, &parts));

  assert_equal (pba_init (NULL, 0, 999, NULL), NULL);
  setting = pba_init (NULL, 0, 1000, NULL);
  assert_not_equal (setting, NULL);
  pba_finalize (setting);
  setting = pba_init (NULL, 0, PBA_MAX_ROUNDS, NULL);
  assert_not_equal (setting, NULL);
  pba_finalize (setting);
  assert_equal (pba_init (NULL, 0, PBA_MAX_ROUNDS + 1, NULL), NULL);
}

Ensure (PBA, returns_NULL_on_unsupport_settings)
{
  struct PBASettings setting = {"0000", 20000, "$6$"};
  assert_false (pba_hash (NULL, "*password"));
  assert_false (pba_hash (&setting, NULL));
  setting.prefix = "$1$";
  assert_false (pba_hash (&setting, "*password"));
}
Ensure (PBA, verifies_valid_and_wrong_password_for_all_pepper_lengths)
{
  size_t i;

  for (i = 0; i < sizeof (pepper_cases) / sizeof (pepper_cases[0]); i++)
    {
      struct PBASettings *setting =
        pba_init (pepper_cases[i].pepper, pepper_cases[i].length, 1000, NULL);
      char *hash;

      assert_not_equal (setting, NULL);
      hash = pba_hash (setting, "*password");
      assert_not_equal (hash, NULL);
      assert_equal (pba_verify_hash (setting, hash, "*password"), VALID);
      assert_equal (pba_verify_hash (setting, hash, "wrong-password"), INVALID);
      free (hash);
      pba_finalize (setting);
    }
}

Ensure (PBA, round_trips_every_supported_single_byte_pepper)
{
  unsigned int byte;

  for (byte = 0x21; byte <= 0x7e; byte++)
    if (is_sha512_salt_char ((char) byte))
      {
        char pepper = (char) byte;
        struct PBASettings *setting = pba_init (&pepper, 1, 1000, NULL);
        char *hash;

        assert_not_equal (setting, NULL);
        hash = pba_hash (setting, "pepper-round-trip");
        assert_not_equal (hash, NULL);
        assert_equal (pba_verify_hash (setting, hash, "pepper-round-trip"),
                      VALID);
        free (hash);
        pba_finalize (setting);
      }
}

Ensure (PBA, verifies_known_punctuation_and_pepper_compatibility_hashes)
{
  struct PBASettings *plain = pba_init (NULL, 0, 1000, NULL);
  struct PBASettings *peppered = pba_init ("A-_@", 4, 1000, NULL);

  assert_not_equal (plain, NULL);
  assert_not_equal (peppered, NULL);
  assert_equal (pba_verify_hash (plain, PUNCTUATION_HASH, "compat-password"),
                VALID);
  assert_equal (pba_verify_hash (plain, NO_ROUNDS_HASH, "no-round-password"),
                VALID);
  assert_equal (pba_verify_hash (plain, PUNCTUATION_HASH, "wrong-password"),
                INVALID);
  assert_equal (pba_verify_hash (peppered, PEPPER_STORED_HASH, "pepper-answer"),
                VALID);
  assert_equal (
    pba_verify_hash (peppered, PEPPER_STORED_HASH, "wrong-password"), INVALID);

  pba_finalize (peppered);
  pba_finalize (plain);
}

Ensure (PBA, rejects_malformed_hashes_for_all_pepper_lengths)
{
  char short_digest[sizeof (VALID_HASH)];
  char oversize_hash[SHA512_CRYPT_MAX_LENGTH + 2];
  size_t i, j;

  memcpy (short_digest, VALID_HASH, sizeof (VALID_HASH));
  short_digest[strlen (short_digest) - 1] = '\0';
  memset (oversize_hash, 'A', sizeof (oversize_hash));
  memcpy (oversize_hash, "$6$", 3);
  oversize_hash[sizeof (oversize_hash) - 1] = '\0';

  for (i = 0; i < sizeof (pepper_cases) / sizeof (pepper_cases[0]); i++)
    {
      struct PBASettings *setting =
        pba_init (pepper_cases[i].pepper, pepper_cases[i].length, 1000, NULL);

      assert_not_equal (setting, NULL);
      for (j = 0; j < sizeof (malformed_hashes) / sizeof (malformed_hashes[0]);
           j++)
        assert_equal (
          pba_verify_hash (setting, malformed_hashes[j], "invalid-password"),
          INVALID);
      assert_equal (pba_verify_hash (setting, short_digest, "invalid-password"),
                    INVALID);
      assert_equal (
        pba_verify_hash (setting, oversize_hash, "invalid-password"), INVALID);
      pba_finalize (setting);
    }
}

Ensure (PBA, verify_hash_returns_invalid_on_np_hash_np_password)
{
  struct PBASettings setting = {"4242", 1000, "$6$"};
  char *hash;
  hash = pba_hash (&setting, "*password");
  assert_not_equal (hash, NULL);
  assert_equal (pba_verify_hash (&setting, NULL, "*password"), INVALID);
  assert_equal (pba_verify_hash (&setting, hash, NULL), INVALID);
  free (hash);
}

Ensure (PBA, distinguishes_null_and_empty_modern_passwords)
{
  struct PBASettings *setting = pba_init (NULL, 0, 1000, NULL);
  char *empty_hash;

  assert_not_equal (setting, NULL);
  empty_hash = pba_hash (setting, "");
  assert_not_equal (empty_hash, NULL);
  assert_equal (pba_verify_hash (setting, empty_hash, ""), VALID);
  assert_equal (pba_verify_hash (setting, empty_hash, NULL), INVALID);
  free (empty_hash);
  pba_finalize (setting);
}

Ensure (PBA, enforces_libxcrypt_password_length_boundary)
{
  struct PBASettings *setting = pba_init (NULL, 0, 1000, NULL);
  char password_511[512], password_512[513];
  char *hash;

  memset (password_511, 'A', sizeof (password_511) - 1);
  password_511[sizeof (password_511) - 1] = '\0';
  memset (password_512, 'A', sizeof (password_512) - 1);
  password_512[sizeof (password_512) - 1] = '\0';

  assert_not_equal (setting, NULL);
  hash = pba_hash (setting, password_511);
  assert_not_equal (hash, NULL);
  assert_equal (pba_verify_hash (setting, hash, password_511), VALID);
  assert_equal (pba_verify_hash (setting, hash, password_512), INVALID);
  assert_equal (pba_hash (setting, password_512), NULL);
  free (hash);
  pba_finalize (setting);
}

Ensure (PBA, unknown_users_follow_a_valid_dummy_hash_path)
{
  struct crypt_data data = {0};
  struct sha512_crypt_parts generated_parts, parts;
  struct PBASettings *default_setting;
  char *known_dummy;
  char *generated_hash;
  size_t i;

  assert_true (parse_sha512_crypt (INVALID_HASH, 1, &parts));
  assert_true (parts.rounds_explicit);
  assert_equal (parts.rounds, COUNT_DEFAULT);
  known_dummy = crypt_r ("dummy-password", INVALID_HASH, &data);
  assert_not_equal (known_dummy, NULL);
  assert_string_equal (known_dummy, INVALID_HASH);

  default_setting = pba_init (NULL, 0, 0, NULL);
  assert_not_equal (default_setting, NULL);
  generated_hash = pba_hash (default_setting, "dummy-round-check");
  assert_not_equal (generated_hash, NULL);
  assert_true (parse_sha512_crypt (generated_hash, 1, &generated_parts));
  assert_equal (generated_parts.rounds, parts.rounds);
  free (generated_hash);
  pba_finalize (default_setting);

  for (i = 0; i < sizeof (pepper_cases) / sizeof (pepper_cases[0]); i++)
    {
      struct PBASettings *setting =
        pba_init (pepper_cases[i].pepper, pepper_cases[i].length, 0, NULL);
      assert_not_equal (setting, NULL);
      assert_equal (pba_verify_hash (setting, NULL, "invalid-password"),
                    INVALID);
      pba_finalize (setting);
    }
}

Ensure (PBA, defaults)
{
  int i;
  struct PBASettings *settings = pba_init (NULL, 0, 0, NULL);
  assert_equal (settings->count, 20000);
  for (i = 0; i < MAX_PEPPER_SIZE; i++)
    assert_equal_with_message (settings->pepper[i], 0,
                               "init_without_pepper_should_not_have_pepper");
  assert_string_equal (settings->prefix, "$6$");
  pba_finalize (settings);
}
Ensure (PBA, initialization)
{
  int i;
  struct PBASettings *settings = pba_init ("4-_", 3, 1000, "$6$");
  assert_equal (settings->count, 1000);
  for (i = 0; i < MAX_PEPPER_SIZE - 1; i++)
    assert_equal_with_message (settings->pepper[i], "4-_"[i],
                               "init_with_pepper_should_be_set");
  assert_equal_with_message (settings->pepper[MAX_PEPPER_SIZE - 1], '\0',
                             "last_pepper_should_be_unset_by_pepper_3");
  assert_string_equal (settings->prefix, "$6$");
  pba_finalize (settings);
  settings = pba_init ("444", MAX_PEPPER_SIZE + 1, 1000, "$6$");
  assert_equal_with_message (settings, NULL,
                             "should_fail_due_to_too_much_pepper");
  settings = pba_init ("4444", MAX_PEPPER_SIZE, 1000, "$WALDFEE$");
  assert_equal_with_message (settings, NULL,
                             "should_fail_due_to_unknown_prefix");
}

Ensure (PBA, rejects_unsupported_pepper_bytes)
{
  const unsigned char rejected[] = {0x00, 0x09, 0x0a, 0x0d, 0x20, 0x21, 0x24,
                                    0x2a, 0x3a, 0x3b, 0x5c, 0x7f, 0x80, 0xff};
  size_t i;

  for (i = 0; i < sizeof (rejected) / sizeof (rejected[0]); i++)
    assert_equal (pba_init ((const char *) &rejected[i], 1, 1000, NULL), NULL);
}

Ensure (PBA, handle_md5_hash)
{
  struct PBASettings *settings = pba_init (NULL, 0, 0, NULL);
  char *hash;
  assert_equal (gvm_auth_init (), 0);
  hash = get_password_hashes ("admin");
  assert_equal (pba_verify_hash (settings, hash, "admin"), UPDATE_RECOMMENDED);
  assert_equal (pba_verify_hash (settings, hash, "wrong-password"), INVALID);
  pba_finalize (settings);
  g_free (hash);
}

Ensure (PBA, distinguishes_null_and_empty_legacy_passwords)
{
  struct PBASettings *settings = pba_init (NULL, 0, 1000, NULL);
  char *hash;

  assert_equal (gvm_auth_init (), 0);
  hash = get_password_hashes ("");
  assert_not_equal (hash, NULL);
  assert_equal (pba_verify_hash (settings, hash, ""), UPDATE_RECOMMENDED);
  assert_equal (pba_verify_hash (settings, hash, NULL), INVALID);
  pba_finalize (settings);
  g_free (hash);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, PBA,
                         returns_false_on_not_phc_compliant_setting);
  add_test_with_context (suite, PBA, returns_true_on_phc_compliant_setting);
  add_test_with_context (suite, PBA, parses_only_supported_sha512_crypt_hashes);
  add_test_with_context (suite, PBA, separates_salt_and_digest_grammars);
  add_test_with_context (suite, PBA,
                         enforces_round_generation_and_verification_policy);
  add_test_with_context (suite, PBA, returns_NULL_on_unsupport_settings);
  add_test_with_context (
    suite, PBA, verifies_valid_and_wrong_password_for_all_pepper_lengths);
  add_test_with_context (suite, PBA,
                         round_trips_every_supported_single_byte_pepper);
  add_test_with_context (
    suite, PBA, verifies_known_punctuation_and_pepper_compatibility_hashes);
  add_test_with_context (suite, PBA,
                         rejects_malformed_hashes_for_all_pepper_lengths);
  add_test_with_context (suite, PBA,
                         verify_hash_returns_invalid_on_np_hash_np_password);
  add_test_with_context (suite, PBA,
                         distinguishes_null_and_empty_modern_passwords);
  add_test_with_context (suite, PBA,
                         enforces_libxcrypt_password_length_boundary);
  add_test_with_context (suite, PBA,
                         unknown_users_follow_a_valid_dummy_hash_path);
  add_test_with_context (suite, PBA, handle_md5_hash);
  add_test_with_context (suite, PBA,
                         distinguishes_null_and_empty_legacy_passwords);
  add_test_with_context (suite, PBA, defaults);
  add_test_with_context (suite, PBA, initialization);
  add_test_with_context (suite, PBA, rejects_unsupported_pepper_bytes);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
