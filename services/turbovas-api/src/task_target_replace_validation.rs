// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::{errors::ApiError, target_host_validation::validate_target_host_lists};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskTargetReplaceRequest {
    pub(crate) hosts: Vec<String>,
    #[serde(default)]
    pub(crate) exclude_hosts: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTaskTargetReplace {
    pub(crate) hosts: String,
    pub(crate) exclude_hosts: String,
}

pub(crate) fn validate_task_target_replace_request(
    request: TaskTargetReplaceRequest,
) -> Result<ValidatedTaskTargetReplace, ApiError> {
    let (hosts, exclude_hosts) =
        validate_target_host_lists(Some(request.hosts), request.exclude_hosts)?;
    Ok(ValidatedTaskTargetReplace {
        hosts: hosts.ok_or_else(|| ApiError::BadRequest("hosts is required".to_string()))?,
        exclude_hosts: exclude_hosts.unwrap_or_default(),
    })
}
