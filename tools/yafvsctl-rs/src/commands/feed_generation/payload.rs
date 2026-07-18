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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::feed_generation::transition::{CompletionKind, TransitionAction};
    use serde_json::json;
    const TIME: &str = "2026-07-18T12:00:00+00:00";
    const APP_SERVICES: [&str; 5] = ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"];
    const ARTIFACT_ROOTS: [&str; 9] = [
        "build/prefix",
        "build/venvs/ospd-openvas",
        "build/venvs/notus-scanner",
        "build/openvas-scanner/nasl",
        "build/openvas-scanner/misc",
        "components/ospd-openvas/ospd",
        "components/ospd-openvas/ospd_openvas",
        "components/notus-scanner/notus/scanner",
        "build/openvas-scanner/src/openvas",
    ];
    fn id(byte: char) -> GenerationId {
        GenerationId::parse(&byte.to_string().repeat(64)).unwrap()
    }
    fn identity<'a>(
        hosts: Option<&'a Value>,
        images: &'a Value,
        artifacts: &'a Value,
        compose: &'a Value,
    ) -> DeploymentIdentity<'a> {
        DeploymentIdentity {
            restore_gsad_hosts: hosts,
            app_image_ids: images,
            app_runtime_artifacts: artifacts,
            app_compose_contract: compose,
        }
    }
    fn values() -> (Value, Value, Value) {
        (
            json!({"gvmd":format!("sha256:{}", "a".repeat(64)), "ospd-openvas":format!("sha256:{}", "b".repeat(64)), "notus-scanner":format!("sha256:{}", "c".repeat(64)), "gsad":format!("sha256:{}", "d".repeat(64)), "yafvs-api":format!("sha256:{}", "e".repeat(64))}),
            json!({"schema_version":1, "algorithm":"sha256", "digest":"f".repeat(64), "entry_count":1, "byte_count":0, "roots":ARTIFACT_ROOTS}),
            json!({"schema_version":1, "algorithm":"sha256", "digest":"1".repeat(64), "services":APP_SERVICES}),
        )
    }
    fn request(
        action: TransitionAction,
        previous: Option<GenerationId>,
        prior: Option<GenerationId>,
    ) -> TransitionRequest {
        TransitionRequest {
            action,
            target: id('a'),
            previous,
            success_rollback: Some(id('b')),
            restored_rollback: prior,
            resume_existing: false,
            recovery_only: false,
        }
    }
    #[test]
    fn activation_has_exact_transitioning_shape() {
        let (images, artifacts, compose) = values();
        let hosts = json!(["127.0.0.1", "::1"]);
        let payload = transitioning(
            &request(TransitionAction::Activate, Some(id('b')), Some(id('c'))),
            identity(Some(&hosts), &images, &artifacts, &compose),
            TIME,
        )
        .unwrap();
        assert_eq!(payload["schema_version"], 1);
        assert_eq!(payload["status"], "transitioning");
        assert_eq!(payload["action"], "activate");
        assert_eq!(payload["target_generation_id"], id('a').as_str());
        assert_eq!(payload["previous_generation_id"], id('b').as_str());
        assert_eq!(payload["rollback_generation_id"], id('c').as_str());
        assert_eq!(payload["restore_gsad_hosts"], hosts);
        assert_eq!(payload["current_generation_id"], Value::Null);
        assert_eq!(payload["started_at"], TIME);
        assert_eq!(payload.as_object().unwrap().len(), 12);
    }
    #[test]
    fn rollback_retains_prior_rollback_identity() {
        let (images, artifacts, compose) = values();
        let payload = transitioning(
            &request(TransitionAction::Rollback, Some(id('b')), Some(id('c'))),
            identity(None, &images, &artifacts, &compose),
            TIME,
        )
        .unwrap();
        assert_eq!(payload["action"], "rollback");
        assert_eq!(payload["previous_generation_id"], id('b').as_str());
        assert_eq!(payload["rollback_generation_id"], id('c').as_str());
        assert_eq!(payload["restore_gsad_hosts"], Value::Null);
    }
    #[test]
    fn first_activation_uses_null_for_absent_identifiers() {
        let (images, artifacts, compose) = values();
        let transition = transitioning(
            &request(TransitionAction::Activate, None, None),
            identity(None, &images, &artifacts, &compose),
            TIME,
        )
        .unwrap();
        let done = CompletedJournalRequest {
            kind: CompletionKind::Target,
            active: id('a'),
            rollback_generation: None,
            completed_at: TIME.to_owned(),
        };
        let completed =
            super::completed(&done, identity(None, &images, &artifacts, &compose)).unwrap();
        assert_eq!(transition["previous_generation_id"], Value::Null);
        assert_eq!(transition["rollback_generation_id"], Value::Null);
        assert_eq!(completed["target_generation_id"], Value::Null);
        assert_eq!(completed["previous_generation_id"], Value::Null);
        assert_eq!(completed["rollback_generation_id"], Value::Null);
    }
    #[test]
    fn compensation_completion_uses_restored_identity() {
        let (images, artifacts, compose) = values();
        let done = CompletedJournalRequest {
            kind: CompletionKind::Compensation,
            active: id('b'),
            rollback_generation: Some(id('c')),
            completed_at: TIME.to_owned(),
        };
        let payload =
            super::completed(&done, identity(None, &images, &artifacts, &compose)).unwrap();
        assert_eq!(payload["status"], "active");
        assert_eq!(payload["current_generation_id"], id('b').as_str());
        assert_eq!(payload["rollback_generation_id"], id('c').as_str());
        assert_eq!(payload["completed_at"], TIME);
        assert_eq!(payload.as_object().unwrap().len(), 11);
    }
    #[test]
    fn valid_identity_values_are_preserved_exactly() {
        let (images, artifacts, compose) = values();
        let hosts = json!(["192.0.2.10"]);
        let done = CompletedJournalRequest {
            kind: CompletionKind::Target,
            active: id('a'),
            rollback_generation: Some(id('b')),
            completed_at: TIME.to_owned(),
        };
        let payload =
            super::completed(&done, identity(Some(&hosts), &images, &artifacts, &compose)).unwrap();
        assert_eq!(payload["restore_gsad_hosts"], hosts);
        assert_eq!(payload["app_image_ids"], images);
        assert_eq!(payload["app_runtime_artifacts"], artifacts);
        assert_eq!(payload["app_compose_contract"], compose);
        assert_eq!(
            payload.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec![
                "app_compose_contract",
                "app_image_ids",
                "app_runtime_artifacts",
                "completed_at",
                "current_generation_id",
                "previous_generation_id",
                "restore_gsad_hosts",
                "rollback_generation_id",
                "schema_version",
                "status",
                "target_generation_id"
            ]
        );
    }

    #[test]
    fn builders_reject_identity_drift_through_the_authoritative_validator() {
        let (mut images, artifacts, compose) = values();
        images["gvmd"] = Value::String("sha256:invalid".into());
        let error = transitioning(
            &request(TransitionAction::Activate, Some(id('b')), Some(id('c'))),
            identity(None, &images, &artifacts, &compose),
            TIME,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "feed transition journal is invalid");
    }
}
