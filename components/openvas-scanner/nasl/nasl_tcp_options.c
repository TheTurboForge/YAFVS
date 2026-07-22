/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_tcp_options.h"

#include <netinet/tcp.h>
#include <string.h>

static bool
option_fits (size_t offset, size_t options_len, uint8_t actual_len,
             uint8_t minimum_len)
{
  return actual_len >= minimum_len && actual_len <= options_len - offset;
}

bool
nasl_parse_tcp_options (const uint8_t *options, size_t options_len,
                        struct tcp_options *parsed)
{
  size_t offset = 0;

  if (options == NULL || parsed == NULL)
    return false;

  while (offset < options_len && options[offset] != TCPOPT_EOL)
    {
      uint8_t kind = options[offset];
      uint8_t len;

      if (kind == TCPOPT_NOP)
        {
          offset++;
          continue;
        }

      if (options_len - offset < 2)
        return false;

      len = options[offset + 1];
      switch (kind)
        {
        case TCPOPT_MAXSEG:
          if (!option_fits (offset, options_len, len, 4))
            return false;
          parsed->mss.kind = kind;
          parsed->mss.len = len;
          memcpy (&parsed->mss.mss, options + offset + 2,
                  sizeof (parsed->mss.mss));
          break;
        case TCPOPT_WINDOW:
          if (!option_fits (offset, options_len, len, 3))
            return false;
          parsed->wscale.kind = kind;
          parsed->wscale.len = len;
          parsed->wscale.wscale = options[offset + 2];
          break;
        case TCPOPT_SACK_PERMITTED:
          if (!option_fits (offset, options_len, len, 2))
            return false;
          parsed->sack_perm.kind = kind;
          parsed->sack_perm.len = len;
          break;
        case TCPOPT_TIMESTAMP:
          if (!option_fits (offset, options_len, len, 10))
            return false;
          parsed->tstamp.kind = kind;
          parsed->tstamp.len = len;
          memcpy (&parsed->tstamp.tstamp, options + offset + 2,
                  sizeof (parsed->tstamp.tstamp));
          memcpy (&parsed->tstamp.e_tstamp, options + offset + 6,
                  sizeof (parsed->tstamp.e_tstamp));
          break;
        case TCPOPT_SACK:
          if (!option_fits (offset, options_len, len, 2))
            return false;
          break;
        default:
          /* Preserve best-effort parsing for safely bounded unknown options. */
          return true;
        }

      offset += len;
    }

  return true;
}
