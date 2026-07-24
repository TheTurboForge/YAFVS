/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Private YAFVS control listener.
 */

#ifndef _GVMD_YAFVS_CONTROL_H
#define _GVMD_YAFVS_CONTROL_H

#include <glib.h>
#include <signal.h>

/*
 * Private one-line protocol:
 *
 * schedule-create <secret> <operator_uuid> <name_b64> <comment_b64>
 *                 <timezone_b64> <icalendar_b64>\n
 *
 * trash-empty <secret> <operator_uuid> <expected_total> <snapshot_sha256>\n
 *
 * alert-email-create <secret> <operator_uuid> <active:0|1> <name_b64>
 *                    <comment_b64> <status_b64> <to_b64> <from_b64>
 *                    <subject_b64> <notice:0|1|2>
 *                    <recipient_credential_uuid_b64>
 *                    <report_format_uuid_b64> <message_b64>\n
 *
 * alert-start-task-create <secret> <operator_uuid> <active:0|1> <name_b64>
 *                         <comment_b64> <status_b64> <task_uuid>\n
 *
 * start <secret> <operator_uuid> <task_uuid>\n
 * stop <secret> <operator_uuid> <task_uuid>\n
 *
 * alert-test <secret> <operator_uuid> <alert_uuid>\n
 *
 * alert-deliver-report <secret> <operator_uuid> <alert_uuid> <report_uuid>
 *                      <filter_b64_or_-> <filter_uuid_or_->\n
 *
 * alert-smb-create <secret> <operator_uuid> <active:0|1> <name_b64>
 *                  <comment_b64> <status_b64> <smb_credential_uuid_b64>
 *                  <share_path_b64> <file_path_b64>
 *                  <report_format_uuid_b64> <max_protocol_b64>\n
 *
 * alert-syslog-create <secret> <operator_uuid> <active:0|1> <name_b64>
 *                     <comment_b64> <status_b64>\n
 *
 * alert-snmp-create <secret> <operator_uuid> <active:0|1> <name_b64>
 *                   <comment_b64> <status_b64> <agent_b64> <community_b64>
 *                   <message_b64>\n
 *
 * scan-config-nvt-diagnostic <secret> <operator_uuid> <config_uuid>
 *                            <nvt_oid>\n
 *
 * Standard base64 fields contain no spaces. Empty optional fields are encoded
 * as empty tokens between their delimiter spaces.
 */

void
yafvs_control_accept_and_fork (int, int, int, sigset_t *);

enum
{
  YAFVS_CONTROL_START_TASK_OK = 0,
  YAFVS_CONTROL_START_TASK_FORBIDDEN = 99
};

typedef enum
{
  YAFVS_CONTROL_STOP_TASK_STOPPED = 0,
  YAFVS_CONTROL_STOP_TASK_REQUESTED = 1,
  YAFVS_CONTROL_STOP_TASK_INACTIVE = 2,
  YAFVS_CONTROL_STOP_TASK_NOT_FOUND = 3,
  YAFVS_CONTROL_STOP_TASK_FORBIDDEN = 99,
  YAFVS_CONTROL_STOP_TASK_INTERNAL = -1,
  YAFVS_CONTROL_STOP_TASK_SCANNER_STATUS = -2,
  YAFVS_CONTROL_STOP_TASK_SCANNER_STOP = -3,
  YAFVS_CONTROL_STOP_TASK_SCANNER_DELETE = -4,
  YAFVS_CONTROL_STOP_TASK_SCANNER_VERIFY = -5,
  YAFVS_CONTROL_STOP_TASK_MALFORMED = -100,
  YAFVS_CONTROL_STOP_TASK_CONFIGURATION = -101,
  YAFVS_CONTROL_STOP_TASK_UNAVAILABLE = -102,
  YAFVS_CONTROL_STOP_TASK_INDETERMINATE = -103
} yafvs_control_stop_task_result_t;

/* Configure the private task-control client only after the listener is bound. */
gboolean
yafvs_control_configure_task_client (const char *);

/* Task-control clients never retry a sent frame. */
int
yafvs_control_start_task_client (const char *, const char *);

yafvs_control_stop_task_result_t
yafvs_control_stop_task_client (const char *, const char *);

#endif /* not _GVMD_YAFVS_CONTROL_H */
