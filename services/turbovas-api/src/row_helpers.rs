// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Row;

pub(crate) fn optional_row_string(row: &Row, name: &str) -> Option<String> {
    row.try_get::<_, Option<String>>(name).ok().flatten()
}

pub(crate) fn optional_row_strings(row: &Row, name: &str) -> Vec<String> {
    row.try_get::<_, Vec<String>>(name).unwrap_or_default()
}

pub(crate) fn csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn boolean_int(value: i32) -> bool {
    value != 0
}

pub(crate) fn task_has_active_current_report(status: &str) -> bool {
    matches!(
        status,
        "Requested" | "Queued" | "Running" | "Processing" | "Stop Requested"
    )
}

pub(crate) fn alive_test_labels(value: i64) -> Vec<String> {
    let label = match value {
        0 => "Scan Config Default",
        1 => "ICMP Ping",
        2 => "TCP-ACK Service Ping",
        3 => "TCP-SYN Service Ping",
        4 => "ARP Ping",
        5 => "Consider Alive",
        _ => "Unknown",
    };
    vec![label.to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_values_trims_and_drops_empty_entries() {
        assert_eq!(
            csv_values(" 192.0.2.1, ,example.test,, 198.51.100.2 "),
            vec!["192.0.2.1", "example.test", "198.51.100.2"]
        );
        assert!(csv_values(" , , ").is_empty());
    }

    #[test]
    fn boolean_int_matches_nonzero_database_flags() {
        assert!(!boolean_int(0));
        assert!(boolean_int(1));
        assert!(boolean_int(-1));
    }

    #[test]
    fn task_active_current_report_statuses_are_explicit() {
        for status in [
            "Requested",
            "Queued",
            "Running",
            "Processing",
            "Stop Requested",
        ] {
            assert!(task_has_active_current_report(status), "{status}");
        }
        for status in ["Done", "Stopped", "Interrupted", "New"] {
            assert!(!task_has_active_current_report(status), "{status}");
        }
    }

    #[test]
    fn alive_test_labels_match_public_target_contract() {
        assert_eq!(alive_test_labels(0), vec!["Scan Config Default"]);
        assert_eq!(alive_test_labels(1), vec!["ICMP Ping"]);
        assert_eq!(alive_test_labels(2), vec!["TCP-ACK Service Ping"]);
        assert_eq!(alive_test_labels(3), vec!["TCP-SYN Service Ping"]);
        assert_eq!(alive_test_labels(4), vec!["ARP Ping"]);
        assert_eq!(alive_test_labels(5), vec!["Consider Alive"]);
        assert_eq!(alive_test_labels(99), vec!["Unknown"]);
    }
}
