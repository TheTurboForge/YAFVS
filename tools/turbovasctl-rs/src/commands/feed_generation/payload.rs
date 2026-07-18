// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pure builders for feed activation journal payloads.

use serde_json::{Value, json};

use super::{
    journal,
    transition::{CompletedJournalRequest, GenerationId, TransitionRequest},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PayloadError(&'static str);
impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for PayloadError {}

/// Deployment identity captured before a feed transition.
///
/// Values are cloned only after validation, so their fields are not dropped.
#[derive(Clone, Copy, Debug)]
pub(super) struct DeploymentIdentity<'a> {
    pub(super) restore_gsad_hosts: Option<&'a Value>,
    pub(super) app_image_ids: &'a Value,
    pub(super) app_runtime_artifacts: &'a Value,
    pub(super) app_compose_contract: &'a Value,
}

/// Builds the journal written immediately before a transition.
pub(super) fn transitioning(
    request: &TransitionRequest,
    identity: DeploymentIdentity<'_>,
    started_at: &str,
) -> Result<Value, PayloadError> {
    let payload = json!({
        "schema_version": 1, "status": "transitioning", "action": request.action.as_str(),
        "target_generation_id": request.target.as_str(),
        "previous_generation_id": generation_id(request.previous.as_ref()),
        "rollback_generation_id": generation_id(request.restored_rollback.as_ref()),
        "restore_gsad_hosts": identity.restore_gsad_hosts.cloned(),
        "app_image_ids": identity.app_image_ids,
        "app_runtime_artifacts": identity.app_runtime_artifacts,
        "app_compose_contract": identity.app_compose_contract,
        "current_generation_id": Value::Null, "started_at": started_at,
    });
    journal::validate(&payload).map_err(|_| PayloadError("feed transition journal is invalid"))?;
    Ok(payload)
}

/// Builds the journal written after a target commit or compensation.
pub(super) fn completed(
    request: &CompletedJournalRequest,
    identity: DeploymentIdentity<'_>,
) -> Result<Value, PayloadError> {
    let payload = json!({
        "schema_version": 1, "status": "active",
        "current_generation_id": request.active.as_str(),
        "target_generation_id": Value::Null, "previous_generation_id": Value::Null,
        "rollback_generation_id": generation_id(request.rollback_generation.as_ref()),
        "restore_gsad_hosts": identity.restore_gsad_hosts.cloned(),
        "app_image_ids": identity.app_image_ids,
        "app_runtime_artifacts": identity.app_runtime_artifacts,
        "app_compose_contract": identity.app_compose_contract,
        "completed_at": &request.completed_at,
    });
    journal::validate(&payload).map_err(|_| PayloadError("completed feed journal is invalid"))?;
    Ok(payload)
}

fn generation_id(value: Option<&GenerationId>) -> Value {
    value.map_or(Value::Null, |id| Value::String(id.as_str().to_owned()))
}
