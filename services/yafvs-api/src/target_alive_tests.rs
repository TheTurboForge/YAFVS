// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::errors::ApiError;

pub(crate) fn validate_alive_tests(value: Option<Vec<String>>) -> Result<Option<i32>, ApiError> {
    let Some(values) = value else {
        return Ok(None);
    };
    if values.is_empty() {
        return Ok(Some(0));
    }
    let mut bitfield = 0;
    let mut saw_default = false;
    let mut saw_consider_alive = false;
    for value in values {
        match value.as_str() {
            "Scan Config Default" => saw_default = true,
            "Consider Alive" => saw_consider_alive = true,
            "TCP-ACK Service Ping" => bitfield |= 1,
            "ICMP Ping" => bitfield |= 2,
            "ARP Ping" => bitfield |= 4,
            "TCP-SYN Service Ping" => bitfield |= 16,
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "unsupported alive_tests value: {value}"
                )));
            }
        }
    }
    if saw_default && (saw_consider_alive || bitfield != 0) {
        return Err(ApiError::BadRequest(
            "Scan Config Default cannot be combined with other alive_tests values".to_string(),
        ));
    }
    if saw_consider_alive && bitfield != 0 {
        return Err(ApiError::BadRequest(
            "Consider Alive cannot be combined with probe alive_tests values".to_string(),
        ));
    }
    if saw_default {
        Ok(Some(0))
    } else if saw_consider_alive {
        Ok(Some(8))
    } else {
        Ok(Some(bitfield))
    }
}
