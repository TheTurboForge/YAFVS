/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef OPENVAS_NASL_TELNET_COPY_H
#define OPENVAS_NASL_TELNET_COPY_H

#include <stddef.h>
#include <string.h>

static inline void
nasl_telnet_copy_response (unsigned char *destination,
                           const unsigned char *source, size_t length)
{
  if (length > 0)
    memcpy (destination, source, length);
  destination[length] = '\0';
}

#endif /* OPENVAS_NASL_TELNET_COPY_H */
