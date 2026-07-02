// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const CREATE_ALERTS_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/create-alerts-from-csv.gmp.py");

#[test]
fn inherited_create_alerts_from_csv_resolves_existing_alerts_credentials_and_formats() {
    for required in [
        "gmp.get_alerts(filter_string=\"rows=-1, name=\" + alert_name)",
        "gmp.get_credentials(filter_string=\"rows=-1, name=\" + credential_name)",
        "gmp.get_report_formats(\n        details=True, filter_string=\"rows=-1, name=\" + report_format_name",
        "content = csv.reader(csvFile, delimiter=\",\")",
        "alert_name = row[0]",
        "str_alert_type = row[1]",
        "report_format = report_format_id(gmp, row[7])",
        "event_data = row[8]",
        "comment = f\"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}\"",
        "alert_type = getattr(gmp.types.AlertMethod, str_alert_type)",
        "if alert_id(gmp, alert_name):",
        "error_and_exit(f\"Failed to read alert_file: {str(e)} (exit)\")",
        "error_and_exit(\"alerts file is empty (exit)\")",
    ] {
        assert!(
            CREATE_ALERTS_CSV.contains(required),
            "create-alerts-from-csv missing {required}"
        );
    }
}

#[test]
fn inherited_create_alerts_from_csv_email_branch_shapes_delivery_payload() {
    for required in [
        "if str_alert_type == \"EMAIL\":",
        "sender_email = strRow2",
        "recipient_email = strRow3",
        "subject = strRow4",
        "message = strRow5",
        "notice_type = strRow6",
        "gmp.create_alert(",
        "event=gmp.types.AlertEvent.TASK_RUN_STATUS_CHANGED",
        "event_data={\"status\": event_data}",
        "condition=gmp.types.AlertCondition.ALWAYS",
        "method=alert_type",
        "\"message\": message",
        "\"notice\": notice_type",
        "\"from_address\": sender_email",
        "\"subject\": subject",
        "\"notice_report_format\": report_format",
        "\"notice_attach_format\": report_format",
        "\"to_address\": recipient_email",
    ] {
        assert!(
            CREATE_ALERTS_CSV.contains(required),
            "create-alerts-from-csv EMAIL branch missing {required}"
        );
    }
}

#[test]
fn inherited_create_alerts_from_csv_smb_branch_shapes_delivery_payload() {
    for required in [
        "smb_credential = credential_id(gmp, strRow2)",
        "smb_share_path = strRow3",
        "smb_report_name = strRow4",
        "smb_folder = strRow5",
        "smb_file_path = smb_folder + \"/\" + smb_report_name",
        "gmp.create_alert(",
        "event=gmp.types.AlertEvent.TASK_RUN_STATUS_CHANGED",
        "event_data={\"status\": event_data}",
        "condition=gmp.types.AlertCondition.ALWAYS",
        "method=alert_type",
        "\"smb_credential\": smb_credential",
        "\"smb_share_path\": smb_share_path",
        "\"smb_report_format\": report_format",
        "\"smb_file_path\": smb_file_path",
    ] {
        assert!(
            CREATE_ALERTS_CSV.contains(required),
            "create-alerts-from-csv SMB branch missing {required}"
        );
    }
}
