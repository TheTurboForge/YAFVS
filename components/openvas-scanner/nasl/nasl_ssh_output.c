/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "nasl_ssh_output.h"

gboolean
nasl_ssh_output_append_with_limit (GString *destination, const GString *other,
                                   const char *data, gsize length, gsize limit)
{
  gsize retained;

  if (destination == NULL || (data == NULL && length != 0)
      || length > G_MAXSSIZE)
    return FALSE;

  retained = destination->len;
  if (retained > limit)
    return FALSE;

  if (other && other != destination)
    {
      if (other->len > limit - retained)
        return FALSE;
      retained += other->len;
    }

  if (length > limit - retained)
    return FALSE;

  g_string_append_len (destination, data, length);
  return TRUE;
}

gboolean
nasl_ssh_output_append (GString *destination, const GString *other,
                        const char *data, gsize length)
{
  return nasl_ssh_output_append_with_limit (destination, other, data, length,
                                            SSH_OUTPUT_MAX_SIZE);
}
