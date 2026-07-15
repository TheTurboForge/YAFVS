/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPENVAS_RESULT_MESSAGE_H
#define OPENVAS_RESULT_MESSAGE_H

char *
openvas_result_message_new (const char *result_type, const char *host_ip,
                            const char *host_name, const char *port,
                            const char *oid, const char *value,
                            const char *uri);

#endif
