// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::errors::ApiError;

/// Database representation inherited from gvmd task_status_t.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub(crate) enum TaskStatus {
    DeleteRequested = 0,
    Done = 1,
    New = 2,
    Requested = 3,
    Running = 4,
    StopRequested = 10,
    StopWaiting = 11,
    Stopped = 12,
    Interrupted = 13,
    DeleteUltimateRequested = 14,
    DeleteWaiting = 16,
    DeleteUltimateWaiting = 17,
    Queued = 18,
    Processing = 19,
}

impl TaskStatus {
    pub(crate) const ALL: [(&'static str, Self); 14] = [
        ("TASK_STATUS_DELETE_REQUESTED", Self::DeleteRequested),
        ("TASK_STATUS_DONE", Self::Done),
        ("TASK_STATUS_NEW", Self::New),
        ("TASK_STATUS_REQUESTED", Self::Requested),
        ("TASK_STATUS_RUNNING", Self::Running),
        ("TASK_STATUS_STOP_REQUESTED", Self::StopRequested),
        ("TASK_STATUS_STOP_WAITING", Self::StopWaiting),
        ("TASK_STATUS_STOPPED", Self::Stopped),
        ("TASK_STATUS_INTERRUPTED", Self::Interrupted),
        (
            "TASK_STATUS_DELETE_ULTIMATE_REQUESTED",
            Self::DeleteUltimateRequested,
        ),
        ("TASK_STATUS_DELETE_WAITING", Self::DeleteWaiting),
        (
            "TASK_STATUS_DELETE_ULTIMATE_WAITING",
            Self::DeleteUltimateWaiting,
        ),
        ("TASK_STATUS_QUEUED", Self::Queued),
        ("TASK_STATUS_PROCESSING", Self::Processing),
    ];

    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    pub(crate) const fn is_startable(self) -> bool {
        matches!(
            self,
            Self::Done | Self::New | Self::Stopped | Self::Interrupted,
        )
    }

    pub(crate) const fn blocks_native_trash(self) -> bool {
        matches!(
            self,
            Self::DeleteRequested
                | Self::Requested
                | Self::Running
                | Self::StopRequested
                | Self::StopWaiting
                | Self::DeleteUltimateRequested
                | Self::DeleteWaiting
                | Self::DeleteUltimateWaiting
                | Self::Queued
                | Self::Processing
        )
    }

    pub(crate) fn from_database(value: Option<i32>) -> Result<Self, ApiError> {
        let value = value.unwrap_or(Self::Done.as_i32());
        Self::try_from(value).map_err(|unknown| {
            tracing::warn!(
                task_status = unknown,
                "database contains an unknown task status"
            );
            ApiError::Database
        })
    }
}

impl TryFrom<i32> for TaskStatus {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::ALL
            .iter()
            .find_map(|(_, status)| (status.as_i32() == value).then_some(*status))
            .ok_or(value)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::TaskStatus;

    const GVMD_MANAGE_H: &str = include_str!("../../../components/gvmd/src/manage.h");
    const GVMD_MANAGE_SQL_C: &str = include_str!("../../../components/gvmd/src/manage_sql.c");

    #[test]
    fn task_status_values_match_the_complete_imported_manager_enum() {
        let enum_tail = GVMD_MANAGE_H
            .split_once("TASK_STATUS_DELETE_REQUESTED")
            .expect("imported task status enum must exist")
            .1
            .split_once("} task_status_t;")
            .expect("imported task status enum must end")
            .0;
        let mut imported = vec![("TASK_STATUS_DELETE_REQUESTED".to_string(), 0)];
        imported.extend(enum_tail.lines().filter_map(|line| {
            let (symbol, value) = line.trim().split_once('=')?;
            let symbol = symbol.trim();
            if !symbol.starts_with("TASK_STATUS_") {
                return None;
            }
            Some((
                symbol.to_string(),
                value.trim().trim_end_matches(',').parse::<i32>().unwrap(),
            ))
        }));
        let expected = TaskStatus::ALL
            .iter()
            .map(|(symbol, status)| ((*symbol).to_string(), status.as_i32()))
            .collect::<Vec<_>>();
        assert_eq!(imported, expected);
    }

    #[test]
    fn native_trash_blocking_matches_imported_task_in_use_contract() {
        let body = GVMD_MANAGE_SQL_C
            .split_once("task_in_use (task_t task)")
            .expect("imported task_in_use must exist")
            .1
            .split_once("trash_task_in_use (task_t task)")
            .expect("imported trash_task_in_use must follow task_in_use")
            .0;
        let imported = body
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .filter(|word| word.starts_with("TASK_STATUS_"))
            .collect::<BTreeSet<_>>();
        let expected = TaskStatus::ALL
            .iter()
            .filter_map(|(symbol, status)| status.blocks_native_trash().then_some(*symbol))
            .collect::<BTreeSet<_>>();
        assert_eq!(imported, expected);
    }

    #[test]
    fn unknown_task_statuses_fail_closed() {
        assert_eq!(TaskStatus::try_from(99), Err(99));
        assert!(TaskStatus::from_database(Some(99)).is_err());
    }
}
