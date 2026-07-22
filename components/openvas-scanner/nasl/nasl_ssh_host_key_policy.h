/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef NASL_SSH_HOST_KEY_POLICY_H
#define NASL_SSH_HOST_KEY_POLICY_H

#include <glib.h>

typedef enum
{
  NASL_SSH_HOST_KEY_POLICY_DISABLED,
  NASL_SSH_HOST_KEY_POLICY_MATCH,
  NASL_SSH_HOST_KEY_POLICY_MISSING,
  NASL_SSH_HOST_KEY_POLICY_MISMATCH,
  NASL_SSH_HOST_KEY_POLICY_INVALID
} nasl_ssh_host_key_policy_result_t;

nasl_ssh_host_key_policy_result_t
nasl_ssh_host_key_policy_verify (const char *require_value,
                                 const char *pins_b64, const char *host,
                                 const guchar *sha256_digest,
                                 gsize digest_length);

#endif
