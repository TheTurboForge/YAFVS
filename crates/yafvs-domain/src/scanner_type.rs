// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ScannerType {
    None = 0,
    Openvas = 2,
    Cve = 3,
    OspSensor = 5,
    Openvasd = 6,
    OpenvasdSensor = 8,
}

impl ScannerType {
    pub const fn database_value(self) -> i32 {
        self as i32
    }

    pub const fn is_operator_configurable(self) -> bool {
        matches!(
            self,
            Self::Openvas | Self::OspSensor | Self::Openvasd | Self::OpenvasdSensor
        )
    }

    pub const fn is_scan_task_capable(self) -> bool {
        self.is_operator_configurable()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidScannerType(pub i64);

impl fmt::Display for InvalidScannerType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown scanner type {}", self.0)
    }
}

impl Error for InvalidScannerType {}

impl TryFrom<i64> for ScannerType {
    type Error = InvalidScannerType;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            2 => Ok(Self::Openvas),
            3 => Ok(Self::Cve),
            5 => Ok(Self::OspSensor),
            6 => Ok(Self::Openvasd),
            8 => Ok(Self::OpenvasdSensor),
            _ => Err(InvalidScannerType(value)),
        }
    }
}

impl TryFrom<i32> for ScannerType {
    type Error = InvalidScannerType;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::try_from(i64::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANAGE_H: &str = include_str!("../../../components/gvmd/src/manage.h");

    fn inherited_scanner_type_value(name: &str) -> i32 {
        let prefix = format!("{name} = ");
        MANAGE_H
            .lines()
            .map(str::trim)
            .find_map(|line| {
                line.strip_prefix(&prefix)
                    .map(|value| value.trim_end_matches(',').parse::<i32>().unwrap())
            })
            .unwrap_or_else(|| panic!("missing inherited scanner type {name}"))
    }

    #[test]
    fn scanner_type_values_match_the_imported_manager_contract() {
        for (name, scanner_type) in [
            ("SCANNER_TYPE_NONE", ScannerType::None),
            ("SCANNER_TYPE_OPENVAS", ScannerType::Openvas),
            ("SCANNER_TYPE_CVE", ScannerType::Cve),
            ("SCANNER_TYPE_OSP_SENSOR", ScannerType::OspSensor),
            ("SCANNER_TYPE_OPENVASD", ScannerType::Openvasd),
            ("SCANNER_TYPE_OPENVASD_SENSOR", ScannerType::OpenvasdSensor),
        ] {
            assert_eq!(
                inherited_scanner_type_value(name),
                scanner_type.database_value(),
                "{name} drifted from the shared Rust contract"
            );
        }
    }

    #[test]
    fn only_retained_scan_scanner_types_are_operator_configurable() {
        for scanner_type in [
            ScannerType::Openvas,
            ScannerType::OspSensor,
            ScannerType::Openvasd,
            ScannerType::OpenvasdSensor,
        ] {
            assert!(scanner_type.is_operator_configurable());
            assert!(scanner_type.is_scan_task_capable());
        }
        for scanner_type in [ScannerType::None, ScannerType::Cve] {
            assert!(!scanner_type.is_operator_configurable());
            assert!(!scanner_type.is_scan_task_capable());
        }
        for removed in [1, 4, 7, 9, 10, 11] {
            assert!(ScannerType::try_from(removed).is_err());
        }
    }
}
