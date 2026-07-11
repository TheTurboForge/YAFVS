/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Private TurboVAS control listener.
 */

#ifndef _GVMD_TURBOVAS_CONTROL_H
#define _GVMD_TURBOVAS_CONTROL_H

#include <signal.h>

/*
 * Private one-line protocol:
 *
 * schedule-create <secret> <operator_uuid> <name_b64> <comment_b64>
 *                 <timezone_b64> <icalendar_b64>\n
 *
 * trash-empty <secret> <operator_uuid> <expected_total>\n
 *
 * alert-email-create <secret> <operator_uuid> <active:0|1> <name_b64>
 *                    <comment_b64> <status_b64> <to_b64> <from_b64>
 *                    <subject_b64> <notice:0|1|2>
 *                    <recipient_credential_uuid_b64>
 *                    <report_format_uuid_b64> <report_config_uuid_b64>
 *                    <message_b64>\n
 *
 * Standard base64 fields contain no spaces. Empty optional fields are encoded
 * as empty tokens between their delimiter spaces.
 */

void
turbovas_control_accept_and_fork (int, int, int, sigset_t *);

#endif /* not _GVMD_TURBOVAS_CONTROL_H */
