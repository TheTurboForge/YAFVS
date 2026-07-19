/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 */

#include "passwordbasedauthentication.h"
// internal usage to have access to gvm_auth initialized to verify if
// initialization is needed
#include "authutils.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// UFC_crypt defines crypt_r when only when __USE_GNU is set
// this shouldn't affect other implementations
#define __USE_GNU
#include <crypt.h>
// INVALID_HASH is used on verify when the given hash is a NULL pointer, so an
// unknown user still follows a valid SHA-512 crypt verification path.
#define INVALID_HASH                                                   \
  "$6$rounds=20000$0000000000000000$"                                  \
  "aXUKPpjT3S5Gf.ERRGmKouM2gJaivVrpYQlMGM9W1nwHUSZyJV1/qPQtKEo0DltLAc" \
  "ey62mY/XeNMqR6fKloA/"
#define SHA512_CRYPT_DIGEST_LENGTH 86
#define SHA512_CRYPT_MAX_LENGTH 123
#define SHA512_CRYPT_SPEC_MAX_ROUNDS 999999999UL
#define SHA512_CRYPT_MIN_ROUNDS 1000UL
#define SHA512_CRYPT_DEFAULT_ROUNDS 5000UL
// Keep attacker-controlled verification cost within 50 times YAFVS's
// 20,000-round generation default while retaining a generous upgrade range.
#define PBA_MAX_ROUNDS 1000000UL
#ifndef CRYPT_GENSALT_OUTPUT_SIZE
#define CRYPT_GENSALT_OUTPUT_SIZE 192
#endif

#ifndef CRYPT_OUTPUT_SIZE
#define CRYPT_OUTPUT_SIZE 384
#endif

/**
 * @brief Check if a prefix is supported.
 *
 * @param[in]  id  Prefix.
 *
 * @return 1 if supported, else 0.
 */
static int
is_prefix_supported (const char *id)
{
  return id != NULL && strcmp (PREFIX_DEFAULT, id) == 0;
}

struct sha512_crypt_parts
{
  size_t salt_offset;
  size_t salt_length;
  unsigned long rounds;
  int rounds_explicit;
};

static int
is_crypt_base64_digest_char (char value)
{
  return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z')
         || (value >= 'a' && value <= 'z') || value == '.' || value == '/';
}

/**
 * @brief Check the libxcrypt SHA-512 salt grammar used by this host.
 *
 * crypt(5) requires printable non-whitespace hash characters and excludes
 * ':', ';', '*', '!', and '\\'. SHA-512 crypt additionally uses '$' as its
 * field delimiter. Host probes confirm all remaining ASCII punctuation,
 * including '-', '_', and '@', round-trips unchanged.
 */
static int
is_sha512_salt_char (char value)
{
  unsigned char byte = (unsigned char) value;

  return byte >= 0x21 && byte <= 0x7e && strchr ("$:;*!\\", (int) byte) == NULL;
}

static int
is_round_count_supported (unsigned long count)
{
  return count >= SHA512_CRYPT_MIN_ROUNDS && count <= PBA_MAX_ROUNDS;
}

/**
 * @brief Parse a supported SHA-512 crypt setting or complete hash.
 *
 * @param[in]  value          Setting or hash to parse.
 * @param[in]  require_hash   Whether an 86-character digest is required.
 * @param[out] parts          Validated salt location.
 *
 * @return 1 when valid, else 0.
 */
static int
parse_sha512_crypt (const char *value, int require_hash,
                    struct sha512_crypt_parts *parts)
{
  size_t length, position;
  unsigned long rounds = 0;

  if (value == NULL || parts == NULL)
    return 0;

  length = strnlen (value, SHA512_CRYPT_MAX_LENGTH + 1);
  if (length == 0 || length > SHA512_CRYPT_MAX_LENGTH
      || strncmp (value, PREFIX_DEFAULT, strlen (PREFIX_DEFAULT)) != 0)
    return 0;

  position = strlen (PREFIX_DEFAULT);
  parts->rounds = SHA512_CRYPT_DEFAULT_ROUNDS;
  parts->rounds_explicit = 0;
  if (strncmp (value + position, "rounds=", strlen ("rounds=")) == 0)
    {
      position += strlen ("rounds=");
      if (position >= length || value[position] < '1' || value[position] > '9')
        return 0;
      while (position < length && value[position] >= '0'
             && value[position] <= '9')
        {
          unsigned long digit = (unsigned long) (value[position] - '0');
          if (rounds > (SHA512_CRYPT_SPEC_MAX_ROUNDS - digit) / 10)
            return 0;
          rounds = rounds * 10 + digit;
          position++;
        }
      if (!is_round_count_supported (rounds) || position >= length
          || value[position] != '$')
        return 0;
      parts->rounds = rounds;
      parts->rounds_explicit = 1;
      position++;
    }

  parts->salt_offset = position;
  while (position < length && is_sha512_salt_char (value[position]))
    position++;
  parts->salt_length = position - parts->salt_offset;
  if (parts->salt_length == 0 || parts->salt_length > 16)
    return 0;

  if (!require_hash)
    return position == length;

  if (position >= length || value[position] != '$')
    return 0;
  position++;
  if (length - position != SHA512_CRYPT_DIGEST_LENGTH)
    return 0;
  while (position < length)
    if (!is_crypt_base64_digest_char (value[position++]))
      return 0;

  return 1;
}

static int
apply_pepper (char *value, const struct sha512_crypt_parts *parts,
              const struct PBASettings *setting)
{
  int i;

  for (i = 0; i < MAX_PEPPER_SIZE; i++)
    if (setting->pepper[i] != 0)
      {
        if (!is_sha512_salt_char (setting->pepper[i]))
          return 0;
        if (parts->salt_length < MAX_PEPPER_SIZE)
          return 0;
        value[parts->salt_offset + parts->salt_length - MAX_PEPPER_SIZE + i] =
          setting->pepper[i];
      }
  return 1;
}

static int
constant_time_equal (const char *left, const char *right, size_t length)
{
  size_t i;
  volatile unsigned char difference = 0;

  for (i = 0; i < length; i++)
    difference |= (unsigned char) left[i] ^ (unsigned char) right[i];
  return difference == 0;
}

// we assume something else than libxcrypt > 3.1; like UFC-crypt
// libxcrypt sets a macro of crypt_gensalt_r to crypt_gensalt_rn
// therefore we could use that mechanism to figure out if we are on
// debian buster or newer.
#ifndef EXTERNAL_CRYPT_GENSALT_R

// used printables within salt
const char ascii64[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/**
 * @brief Try to get random bytes.
 *
 * @param[in]  buf     Destination for bytes.
 * @param[in]  buflen  Number of bytes to get.
 *
 * @return 0 on success, else error.
 */
static int
get_random (char *buf, size_t buflen)
{
  FILE *fp;
  int result = 0;

  if (buf == NULL)
    return -1;
  fp = fopen ("/dev/urandom", "r");
  if (fp == NULL)
    {
      result = -1;
      goto exit;
    }
  size_t nread = fread (buf, 1, buflen, fp);
  fclose (fp);
  if (nread < buflen)
    {
      result = -2;
    }

exit:
  return result;
}

/**
 * @brief Generate string suitable for use as setting when hashing a passphrase.
 *
 * If prefix is a NULL pointer, the current best default is used; if rbytes
 * is a NULL pointer, random data will be retrieved from the operating system
 * if possible.
 *
 * @param[in]  prefix  Controls which hash function will be used.
 * @param[in]  count   Controls the computional cost of the hash.
 * @param[in]  rbytes  Should point to nrbytes bytes of random data.
 * @param[in]  nrbytes  Number of bytes in rbytes.
 * @param[out] output   The generated setting string is written here.
 * @param[in]  output_size  Length of output. Must be at least
 *                          CRYPT_GENSALT_OUTPUT_SIZE.
 *
 * @return On success \p output, else NULL.
 */
char *
crypt_gensalt_r (const char *prefix, unsigned long count, const char *rbytes,
                 int nrbytes, char *output, int output_size);
char *
crypt_gensalt_r (const char *prefix, unsigned long count, const char *rbytes,
                 int nrbytes, char *output, int output_size)
{
  char *internal_rbytes = NULL;
  unsigned int written = 0, used = 0;
  unsigned long value = 0;
  if (output == NULL)
    goto exit;
  if ((rbytes != NULL && nrbytes < 3) || output_size < 16
      || (prefix != NULL && !is_prefix_supported (prefix)))
    {
      output[0] = '*';
      goto exit;
    }
  if (rbytes == NULL)
    {
      internal_rbytes = malloc (16);
      if (internal_rbytes == NULL)
        {
          output[0] = '*';
          goto exit;
        }
      if (get_random (internal_rbytes, 16) != 0)
        {
          output[0] = '*';
          goto exit;
        }
      nrbytes = 16;
      rbytes = internal_rbytes;
    }
  written = snprintf (output, output_size, "%srounds=%lu$",
                      prefix == NULL ? PREFIX_DEFAULT : prefix, count);
  while (written + 5 < (unsigned int) output_size
         && used + 3 < (unsigned int) nrbytes && (used * 4 / 3) < 16)
    {
      value = ((unsigned long) rbytes[used + 0] << 0)
              | ((unsigned long) rbytes[used + 1] << 8)
              | ((unsigned long) rbytes[used + 2] << 16);
      output[written] = ascii64[value & 0x3f];
      output[written + 1] = ascii64[(value >> 6) & 0x3f];
      output[written + 2] = ascii64[(value >> 12) & 0x3f];
      output[written + 3] = ascii64[(value >> 18) & 0x3f];
      written += 4;
      used += 3;
    }
  output[written] = '\0';
exit:
  if (internal_rbytes != NULL)
    free (internal_rbytes);
  return output == NULL || output[0] == '*' ? 0 : output;
}

#endif

/**
 * @brief Init PBA.
 *
 * @param[in] pepper  A static hidden addition to the randomly generated salt.
 * @param[in] pepper_size  The size of pepper; it must not be larger than
 *                         MAX_PEPPER_SIZE.
 * @param[in] count        Number of rounds used to calculate the hash. 0 to
 *                         use COUNT_DEFAULT.
 * @param[in] prefix       The algorithm used, if NULL then the most secure
 *                         available algorithm will be used.
 *
 * @return Settings, or NULL on error. Free with pba_finalize.
 */
struct PBASettings *
pba_init (const char *pepper, unsigned int pepper_size, unsigned int count,
          char *prefix)
{
  unsigned int i = 0;
  struct PBASettings *result = NULL;
  if (pepper_size > MAX_PEPPER_SIZE)
    goto exit;
  if (prefix != NULL && !is_prefix_supported (prefix))
    goto exit;
  if (count != 0 && !is_round_count_supported (count))
    goto exit;
  if (pepper != NULL)
    for (i = 0; i < pepper_size; i++)
      if (!is_sha512_salt_char (pepper[i]))
        goto exit;
  result = malloc (sizeof (struct PBASettings));
  if (result == NULL)
    goto exit;
  for (i = 0; i < MAX_PEPPER_SIZE; i++)
    result->pepper[i] = pepper != NULL && i < pepper_size ? pepper[i] : 0;
  result->count = count == 0 ? COUNT_DEFAULT : count;
  result->prefix = prefix == NULL ? PREFIX_DEFAULT : prefix;
exit:
  return result;
}

/**
 * @brief Cleanup PBA settings.
 *
 * @param[in]  settings  PBA settings.
 */
void
pba_finalize (struct PBASettings *settings)
{
  free (settings);
}

/**
 * @brief Check if a PBA settings is PHC compliant.
 *
 * @param[in]  setting  Setting.
 *
 * @return 1 if compliant, else 0.
 */
static int
pba_is_phc_compliant (const char *setting)
{
  return setting == NULL || setting[0] == '$';
}

/**
 * @brief Create a password hash.
 *
 * @param[in]  setting   PBA settings.
 * @param[in]  password  Password.
 *
 * @return Hash. Must be freed with free().
 */
char *
pba_hash (struct PBASettings *setting, const char *password)
{
  char *result = NULL, *settings = NULL, *rslt;
  size_t result_length;
  int i;
  struct crypt_data *data = NULL;
  struct sha512_crypt_parts parts;

  if (!setting || !password)
    goto exit;
  if (!is_prefix_supported (setting->prefix))
    goto exit;
  if (!is_round_count_supported (setting->count))
    goto exit;
  settings = malloc (CRYPT_GENSALT_OUTPUT_SIZE);
  if (settings == NULL)
    goto exit;
  if (crypt_gensalt_r (setting->prefix, setting->count, NULL, 0, settings,
                       CRYPT_GENSALT_OUTPUT_SIZE)
      == NULL)
    goto exit;
  if (!parse_sha512_crypt (settings, 0, &parts)
      || !apply_pepper (settings, &parts, setting))
    goto exit;

  data = calloc (1, sizeof (struct crypt_data));
  if (data == NULL)
    goto exit;
  rslt = crypt_r (password, settings, data);
  if (rslt == NULL)
    goto exit;
  if (!parse_sha512_crypt (rslt, 1, &parts))
    goto exit;
  result_length = strlen (rslt);
  result = malloc (result_length + 1);
  if (result == NULL)
    goto exit;
  memcpy (result, rslt, result_length + 1);
  // Remove the pepper from the persisted salt at its validated positions.
  for (i = 0; i < MAX_PEPPER_SIZE; i++)
    if (setting->pepper[i] != 0)
      result[parts.salt_offset + parts.salt_length - MAX_PEPPER_SIZE + i] = '0';
exit:
  if (data != NULL)
    free (data);
  if (settings != NULL)
    free (settings);
  return result;
}

/**
 * @brief Verify a password hash.
 *
 * @param[in]  setting   PBA settings.
 * @param[in]  hash      Hash.
 * @param[in]  password  Password.
 *
 * @return Validity. VALID, UPDATE_RECOMMENDED, ...
 */
enum pba_rc
pba_verify_hash (const struct PBASettings *setting, const char *hash,
                 const char *password)
{
  char *cmp, *tmp = NULL;
  const char *candidate;
  struct crypt_data *data = NULL;
  struct sha512_crypt_parts cmp_parts, parts;
  size_t cmp_size, hash_size;
  int matches;
  int i = 0;
  enum pba_rc result = ERR;

  if (!setting)
    goto exit;
  if (!is_prefix_supported (setting->prefix))
    goto exit;
  if (pba_is_phc_compliant (hash) != 0)
    {
      candidate = hash ? hash : INVALID_HASH;
      if (!parse_sha512_crypt (candidate, 1, &parts))
        {
          result = INVALID;
          goto exit;
        }
      hash_size = strlen (candidate);

      data = calloc (1, sizeof (struct crypt_data));
      if (data == NULL)
        goto exit;
      tmp = malloc (hash_size + 1);
      if (tmp == NULL)
        goto exit;
      memcpy (tmp, candidate, hash_size + 1);
      if (!apply_pepper (tmp, &parts, setting))
        {
          result = INVALID;
          goto exit;
        }
      // some crypt_r implementations cannot handle if password is a
      // NULL pointer and run into SEGMENTATION faults.
      // Therefore we set it to ""
      cmp = crypt_r (password ? password : "", tmp, data);
      if (cmp == NULL)
        {
          result = INVALID;
          goto exit;
        }
      cmp_size = strnlen (cmp, SHA512_CRYPT_MAX_LENGTH + 1);
      if (cmp_size != hash_size || !parse_sha512_crypt (cmp, 1, &cmp_parts))
        {
          result = INVALID;
          goto exit;
        }
      matches = constant_time_equal (tmp, cmp, hash_size);
      if (hash != NULL && password != NULL && matches)
        result = VALID;
      else
        result = INVALID;
    }
  else
    {
      // assume authutils hash handling
      // initialize gvm_auth utils if not already initialized
      if (initialized == FALSE && gvm_auth_init () != 0)
        {
          goto exit;
        }
      // verify result of gvm_authenticate_classic
      i = gvm_authenticate_classic (NULL, password ? password : "", hash);
      if (i == 0 && password != NULL)
        result = UPDATE_RECOMMENDED;
      else if (i == 0 || i == 1)
        result = INVALID;
    }
exit:
  if (data != NULL)
    free (data);
  if (tmp != NULL)
    free (tmp);
  return result;
}
