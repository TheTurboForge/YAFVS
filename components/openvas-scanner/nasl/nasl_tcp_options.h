/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_TCP_OPTIONS_H
#define NASL_TCP_OPTIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct tcp_opt_mss
{
  uint8_t kind;
  uint8_t len;
  uint16_t mss;
};

struct tcp_opt_wscale
{
  uint8_t kind;
  uint8_t len;
  uint8_t wscale;
};

struct tcp_opt_sack_perm
{
  uint8_t kind;
  uint8_t len;
};

struct tcp_opt_tstamp
{
  uint8_t kind;
  uint8_t len;
  uint32_t tstamp;
  uint32_t e_tstamp;
};

struct tcp_options
{
  struct tcp_opt_mss mss;
  struct tcp_opt_wscale wscale;
  struct tcp_opt_sack_perm sack_perm;
  struct tcp_opt_tstamp tstamp;
};

bool
nasl_parse_tcp_options (const uint8_t *options, size_t options_len,
                        struct tcp_options *parsed);

#endif
