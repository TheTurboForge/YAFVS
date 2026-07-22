// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use serde::{Deserialize, Serialize};
use tokio_postgres::{Row, Transaction};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::{ApiError, mutation_committed_response_unavailable},
    path_ids::{parse_uuid, validate_nvt_oid, validate_scan_config_family},
    scan_config_write_db::{
        ScanConfigPreferenceDefinition, ensure_scan_config_family_nvt_change_oids_exist,
        ensure_unique_scan_config_name, execute_scan_config_write_sql,
        load_scan_config_known_family_names, load_scan_config_preference_definition,
        map_scan_config_write_db_error, query_scan_config_write_record,
        require_scan_config_write_operator, resolve_scan_config_write_operator_owner,
    },
    scan_config_write_transactions::execute_scan_config_preference_mutations_transaction,
    scan_config_write_validation::{
        MAX_SCAN_CONFIG_PREFERENCE_VALUE_BYTES, MAX_SCAN_CONFIG_TEXT_BYTES,
        ScanConfigPreferenceAction, ScanConfigPreferenceScope, SensitiveScanConfigPreferenceValue,
        ValidatedScanConfigPreferenceMutation, ValidatedScanConfigPreferenceNvtIdentity,
    },
    scan_configs::load_scan_config_asset_detail,
};

pub(crate) const MAX_SCAN_CONFIG_BACKUP_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_SCAN_CONFIG_BACKUP_FAMILIES: usize = 512;
const MAX_SCAN_CONFIG_BACKUP_SELECTOR_ROWS: usize = 16 * 1024;
const MAX_SCAN_CONFIG_BACKUP_PREFERENCES: usize = 4096;
const BACKUP_SCHEMA: &str = "yafvs.scan-config-backup";
const LEGACY_BACKUP_SCHEMA: &str = "turbovas.scan-config-backup";
const BACKUP_VERSION: i32 = 1;

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigBackupDocument {
    #[serde(rename = "schema")]
    schema_name: String,
    version: i32,
    usage_type: String,
    name: String,
    comment: String,
    families_growing: bool,
    family_inventory: Vec<String>,
    selectors: Vec<ScanConfigBackupSelector>,
    preferences: Vec<ScanConfigBackupPreference>,
    omitted_secret_preference_count: usize,
    omitted_secret_preferences: Vec<ScanConfigBackupPreferenceIdentity>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ScanConfigBackupSelector {
    #[serde(rename = "type")]
    selector_type: i32,
    exclude: bool,
    family_or_nvt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    family: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ScanConfigBackupPreferenceScope {
    Scanner,
    Nvt,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ScanConfigBackupPreference {
    #[serde(flatten)]
    identity: ScanConfigBackupPreferenceIdentity,
    value: ScanConfigBackupPreferenceValue,
}

struct ScanConfigBackupPreferenceValue(SensitiveScanConfigPreferenceValue);

impl ScanConfigBackupPreferenceValue {
    fn from_string(value: String) -> Self {
        Self(SensitiveScanConfigPreferenceValue::from_string(value))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn into_sensitive(self) -> SensitiveScanConfigPreferenceValue {
        self.0
    }
}

impl Clone for ScanConfigBackupPreferenceValue {
    fn clone(&self) -> Self {
        // Only SQL-redacted, non-secret backup output takes this path.
        Self::from_string(self.as_str().to_string())
    }
}

impl Serialize for ScanConfigBackupPreferenceValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ScanConfigBackupPreferenceValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from_string)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ScanConfigBackupPreferenceIdentity {
    scope: ScanConfigBackupPreferenceScope,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nvt: Option<ScanConfigBackupNvtPreferenceIdentity>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ScanConfigBackupNvtPreferenceIdentity {
    oid: String,
    id: i32,
    #[serde(rename = "type")]
    preference_type: String,
}

struct ValidatedScanConfigBackup {
    name: String,
    comment: String,
    families_growing: bool,
    family_inventory: Vec<String>,
    selectors: Vec<ScanConfigBackupSelector>,
    preferences: Vec<ValidatedBackupPreference>,
    omitted_secret_preferences: Vec<ScanConfigBackupPreferenceIdentity>,
}

struct ValidatedBackupPreference {
    identity: ScanConfigBackupPreferenceIdentity,
    value: SensitiveScanConfigPreferenceValue,
}

pub(crate) async fn backup_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<(HeaderMap, Json<ScanConfigBackupDocument>), ApiError> {
    let scan_config_id = parse_uuid(&scan_config_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let metadata = client
        .query_opt(scan_config_backup_metadata_sql(), &[&scan_config_id])
        .await
        .map_err(|error| map_scan_config_write_db_error(error, "load scan-config backup metadata"))?
        .ok_or(ApiError::NotFound)?;
    let selector_name: String = metadata.get("nvt_selector");
    let selector_rows = client
        .query(scan_config_backup_selectors_sql(), &[&selector_name])
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "load scan-config backup selectors")
        })?;
    let preference_rows = client
        .query(scan_config_backup_preferences_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "load scan-config backup preferences")
        })?;
    let family_inventory = client
        .query(scan_config_backup_family_inventory_sql(), &[])
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "load scan-config backup family inventory")
        })?
        .into_iter()
        .map(|row| row.get(0))
        .collect();

    let mut preferences = Vec::new();
    let mut omitted_secret_preferences = Vec::new();
    for row in &preference_rows {
        let (identity, value, secret) = scan_config_backup_preference_from_row(row);
        if secret {
            omitted_secret_preferences.push(identity);
        } else {
            preferences.push(ScanConfigBackupPreference {
                identity,
                value: ScanConfigBackupPreferenceValue::from_string(value),
            });
        }
    }
    let document = ScanConfigBackupDocument {
        schema_name: BACKUP_SCHEMA.to_string(),
        version: BACKUP_VERSION,
        usage_type: "scan".to_string(),
        name: metadata.get("name"),
        comment: metadata.get("comment"),
        families_growing: metadata.get::<_, i32>("families_growing") != 0,
        family_inventory,
        selectors: selector_rows
            .iter()
            .map(scan_config_backup_selector_from_row)
            .collect(),
        omitted_secret_preference_count: omitted_secret_preferences.len(),
        preferences,
        omitted_secret_preferences,
    };
    validate_scan_config_backup_document(document.clone())?;

    let mut headers = HeaderMap::new();
    let filename = format!("scan-config-{scan_config_id}.backup.json");
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|_| ApiError::Database)?;
    headers.insert(header::CONTENT_DISPOSITION, content_disposition);
    Ok((headers, Json(document)))
}

pub(crate) async fn import_scan_config(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<ScanConfigBackupDocument>, axum::extract::rejection::JsonRejection>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<crate::scan_config_payloads::ScanConfigAssetDetail>,
    ),
    ApiError,
> {
    let operator = require_scan_config_write_operator(operator)?;
    let document = payload.map(|Json(document)| document).map_err(|_| {
        ApiError::BadRequest(
            "request body must be application/json matching ScanConfigBackupDocument".to_string(),
        )
    })?;
    let document = validate_scan_config_backup_document(document)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin import scan-config transaction")
    })?;
    let owner_id = resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE configs, configs_trash, config_preferences, nvt_preferences, nvt_selectors, nvts IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "lock scan-config tables for import"))?;
    ensure_unique_scan_config_name(&tx, &document.name, 0).await?;
    ensure_scan_config_backup_feed_is_current(&tx, &document).await?;
    let preferences = validate_scan_config_backup_preferences_against_feed(&tx, &document).await?;
    let record = query_scan_config_write_record(
        &tx,
        scan_config_backup_insert_metadata_sql(),
        &[
            &owner_id,
            &document.name,
            &document.comment,
            &i32::from(document.families_growing),
        ],
        "insert scan-config backup metadata",
    )
    .await?;
    execute_scan_config_backup_selector_transaction(&tx, record.internal_id, &document).await?;
    execute_scan_config_preference_mutations_transaction(&tx, record.internal_id, &preferences)
        .await?;
    execute_scan_config_write_sql(
        &tx,
        scan_config_backup_recalculate_caches_sql(),
        &[&record.internal_id],
        "recalculate imported scan-config caches",
    )
    .await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit import scan-config transaction")
    })?;

    Ok((
        StatusCode::CREATED,
        scan_config_backup_location_headers(&record.uuid).map_err(|error| {
            mutation_committed_response_unavailable(error, "import scan-config response header")
        })?,
        Json(
            load_scan_config_asset_detail(&client, &record.uuid)
                .await
                .map_err(|error| {
                    mutation_committed_response_unavailable(
                        error,
                        "import scan-config response reload",
                    )
                })?,
        ),
    ))
}

fn validate_scan_config_backup_document(
    document: ScanConfigBackupDocument,
) -> Result<ValidatedScanConfigBackup, ApiError> {
    if document.schema_name != BACKUP_SCHEMA && document.schema_name != LEGACY_BACKUP_SCHEMA {
        return Err(ApiError::BadRequest(
            "unsupported scan-config backup schema".to_string(),
        ));
    }
    if document.version != BACKUP_VERSION {
        return Err(ApiError::BadRequest(
            "unsupported scan-config backup version".to_string(),
        ));
    }
    if document.usage_type != "scan" {
        return Err(ApiError::BadRequest(
            "scan-config backup usage_type must be scan".to_string(),
        ));
    }
    let name = normalize_backup_text(document.name, "name", false)?;
    let comment = normalize_backup_text(document.comment, "comment", true)?;
    if document.family_inventory.len() > MAX_SCAN_CONFIG_BACKUP_FAMILIES {
        return Err(ApiError::BadRequest(
            "scan-config backup has too many families".to_string(),
        ));
    }
    if document.selectors.len() > MAX_SCAN_CONFIG_BACKUP_SELECTOR_ROWS {
        return Err(ApiError::BadRequest(
            "scan-config backup has too many selector rows".to_string(),
        ));
    }
    if document.preferences.len() > MAX_SCAN_CONFIG_BACKUP_PREFERENCES
        || document.omitted_secret_preferences.len() > MAX_SCAN_CONFIG_BACKUP_PREFERENCES
    {
        return Err(ApiError::BadRequest(
            "scan-config backup has too many preference overrides".to_string(),
        ));
    }
    if document.omitted_secret_preference_count != document.omitted_secret_preferences.len() {
        return Err(ApiError::BadRequest(
            "omitted_secret_preference_count does not match omitted_secret_preferences".to_string(),
        ));
    }

    let mut families = HashSet::with_capacity(document.family_inventory.len());
    for family in &document.family_inventory {
        validate_scan_config_family(family)?;
        if !families.insert(family.as_str()) {
            return Err(ApiError::BadRequest(
                "family_inventory must not contain duplicates".to_string(),
            ));
        }
    }
    let mut selector_keys = HashSet::with_capacity(document.selectors.len());
    let mut family_defaults = HashMap::new();
    for selector in &document.selectors {
        match selector.selector_type {
            1 => {
                validate_scan_config_family(&selector.family_or_nvt)?;
                if selector.family.is_some() || selector.exclude != document.families_growing {
                    return Err(ApiError::BadRequest(
                        "family selector rows are not canonical".to_string(),
                    ));
                }
                if !selector_keys.insert((1, selector.family_or_nvt.as_str())) {
                    return Err(ApiError::BadRequest(
                        "scan-config backup contains duplicate selector rows".to_string(),
                    ));
                }
                family_defaults.insert(selector.family_or_nvt.as_str(), !document.families_growing);
            }
            2 => {
                let Some(family) = selector.family.as_deref() else {
                    return Err(ApiError::BadRequest(
                        "NVT selector rows require a family".to_string(),
                    ));
                };
                validate_scan_config_family(family)?;
                validate_nvt_oid(&selector.family_or_nvt)?;
                if !selector_keys.insert((2, selector.family_or_nvt.as_str())) {
                    return Err(ApiError::BadRequest(
                        "scan-config backup contains duplicate selector rows".to_string(),
                    ));
                }
            }
            _ => {
                return Err(ApiError::BadRequest(
                    "scan-config backup selector rows must have type 1 or 2".to_string(),
                ));
            }
        }
    }
    for selector in &document.selectors {
        if selector.selector_type == 2 {
            let family = selector.family.as_deref().expect("validated above");
            let default_selected = family_defaults
                .get(family)
                .copied()
                .unwrap_or(document.families_growing);
            if selector.exclude != default_selected {
                return Err(ApiError::BadRequest(
                    "NVT selector rows are not canonical".to_string(),
                ));
            }
        }
    }

    let mut identities = HashSet::new();
    let mut preferences = Vec::with_capacity(document.preferences.len());
    for preference in document.preferences {
        validate_scan_config_backup_preference_identity(&preference.identity)?;
        validate_backup_preference_value(preference.value.as_str())?;
        if !identities.insert(scan_config_backup_preference_identity_key(
            &preference.identity,
        )) {
            return Err(ApiError::BadRequest(
                "scan-config backup contains duplicate preference identities".to_string(),
            ));
        }
        preferences.push(ValidatedBackupPreference {
            identity: preference.identity,
            value: preference.value.into_sensitive(),
        });
    }
    for identity in &document.omitted_secret_preferences {
        validate_scan_config_backup_preference_identity(identity)?;
        if !identities.insert(scan_config_backup_preference_identity_key(identity)) {
            return Err(ApiError::BadRequest(
                "scan-config backup contains duplicate preference identities".to_string(),
            ));
        }
    }

    Ok(ValidatedScanConfigBackup {
        name,
        comment,
        families_growing: document.families_growing,
        family_inventory: document.family_inventory,
        selectors: document.selectors,
        preferences,
        omitted_secret_preferences: document.omitted_secret_preferences,
    })
}

fn validate_scan_config_backup_preference_identity(
    identity: &ScanConfigBackupPreferenceIdentity,
) -> Result<(), ApiError> {
    validate_backup_preference_text(&identity.name, "preference name", 4096, false)?;
    match (identity.scope, identity.nvt.as_ref()) {
        (ScanConfigBackupPreferenceScope::Scanner, None) => Ok(()),
        (ScanConfigBackupPreferenceScope::Nvt, Some(nvt)) => {
            validate_nvt_oid(&nvt.oid)?;
            if nvt.id < 0 {
                return Err(ApiError::BadRequest(
                    "NVT preference id must not be negative".to_string(),
                ));
            }
            validate_backup_preference_text(&nvt.preference_type, "NVT preference type", 128, false)
        }
        _ => Err(ApiError::BadRequest(
            "scan-config backup preference scope and identity disagree".to_string(),
        )),
    }
}

fn validate_backup_preference_value(value: &str) -> Result<(), ApiError> {
    validate_backup_preference_text(
        value,
        "preference value",
        MAX_SCAN_CONFIG_PREFERENCE_VALUE_BYTES,
        true,
    )
}

fn validate_backup_preference_text(
    value: &str,
    field: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), ApiError> {
    if (!allow_empty && value.is_empty()) || value.len() > max_bytes || value.contains('\0') {
        return Err(ApiError::BadRequest(format!(
            "{field} must {}contain no NUL bytes and be at most {max_bytes} bytes",
            if allow_empty { "" } else { "not be empty, " }
        )));
    }
    Ok(())
}

fn normalize_backup_text(
    value: String,
    field: &str,
    allow_empty: bool,
) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if (!allow_empty && value.is_empty())
        || value.len() > MAX_SCAN_CONFIG_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "{field} must {}be printable text up to {MAX_SCAN_CONFIG_TEXT_BYTES} bytes",
            if allow_empty { "" } else { "not be empty and " }
        )));
    }
    Ok(value)
}

fn scan_config_backup_preference_identity_key(
    identity: &ScanConfigBackupPreferenceIdentity,
) -> (u8, String, Option<String>, Option<i32>, Option<String>) {
    match identity.scope {
        ScanConfigBackupPreferenceScope::Scanner => (0, identity.name.clone(), None, None, None),
        ScanConfigBackupPreferenceScope::Nvt => {
            let nvt = identity.nvt.as_ref().expect("validated NVT identity");
            (
                1,
                identity.name.clone(),
                Some(nvt.oid.clone()),
                Some(nvt.id),
                Some(nvt.preference_type.clone()),
            )
        }
    }
}

async fn ensure_scan_config_backup_feed_is_current(
    tx: &Transaction<'_>,
    document: &ValidatedScanConfigBackup,
) -> Result<(), ApiError> {
    let known_families = load_scan_config_known_family_names(tx).await?;
    if document.family_inventory != known_families {
        return Err(ApiError::Conflict(
            "scan-config backup feed family inventory is stale".to_string(),
        ));
    }
    let known = known_families
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut nvt_oids_by_family = HashMap::<&str, Vec<String>>::new();
    for selector in &document.selectors {
        match selector.selector_type {
            1 if !known.contains(selector.family_or_nvt.as_str()) => {
                return Err(ApiError::NotFound);
            }
            2 => {
                let family = selector
                    .family
                    .as_deref()
                    .expect("validated NVT selector family");
                if !known.contains(family) {
                    return Err(ApiError::NotFound);
                }
                nvt_oids_by_family
                    .entry(family)
                    .or_default()
                    .push(selector.family_or_nvt.clone());
            }
            _ => {}
        }
    }
    for (family, oids) in nvt_oids_by_family {
        ensure_scan_config_family_nvt_change_oids_exist(tx, family, &oids).await?;
    }
    Ok(())
}

async fn validate_scan_config_backup_preferences_against_feed(
    tx: &Transaction<'_>,
    document: &ValidatedScanConfigBackup,
) -> Result<Vec<ValidatedScanConfigPreferenceMutation>, ApiError> {
    let mut mutations = Vec::with_capacity(document.preferences.len());
    for preference in &document.preferences {
        let mutation = scan_config_backup_mutation(&preference.identity, Some(&preference.value));
        let definition = load_scan_config_preference_definition(tx, &mutation).await?;
        ensure_scan_config_backup_preference_is_not_secret(&definition)?;
        mutations.push(mutation);
    }
    for identity in &document.omitted_secret_preferences {
        let mutation = scan_config_backup_mutation(identity, None);
        let definition = load_scan_config_preference_definition(tx, &mutation).await?;
        ensure_scan_config_backup_preference_is_secret(&definition)?;
    }
    Ok(mutations)
}

fn scan_config_backup_mutation(
    identity: &ScanConfigBackupPreferenceIdentity,
    value: Option<&SensitiveScanConfigPreferenceValue>,
) -> ValidatedScanConfigPreferenceMutation {
    let nvt = identity
        .nvt
        .as_ref()
        .map(|nvt| ValidatedScanConfigPreferenceNvtIdentity {
            oid: nvt.oid.clone(),
            id: nvt.id,
            preference_type: nvt.preference_type.clone(),
        });
    ValidatedScanConfigPreferenceMutation {
        scope: match identity.scope {
            ScanConfigBackupPreferenceScope::Scanner => ScanConfigPreferenceScope::Scanner,
            ScanConfigBackupPreferenceScope::Nvt => ScanConfigPreferenceScope::Nvt,
        },
        name: identity.name.clone(),
        action: ScanConfigPreferenceAction::Set,
        value: value.map(|value| {
            SensitiveScanConfigPreferenceValue::from_string(value.as_str().to_string())
        }),
        nvt,
    }
}

fn ensure_scan_config_backup_preference_is_secret(
    definition: &ScanConfigPreferenceDefinition,
) -> Result<(), ApiError> {
    if is_secret_scan_config_preference(&definition.preference_type) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "omitted secret preference identity is not password or file".to_string(),
        ))
    }
}

fn ensure_scan_config_backup_preference_is_not_secret(
    definition: &ScanConfigPreferenceDefinition,
) -> Result<(), ApiError> {
    if is_secret_scan_config_preference(&definition.preference_type) {
        Err(ApiError::BadRequest(
            "password and file preference values must be omitted from scan-config backups"
                .to_string(),
        ))
    } else {
        Ok(())
    }
}

fn is_secret_scan_config_preference(preference_type: &str) -> bool {
    matches!(
        preference_type.to_ascii_lowercase().as_str(),
        "password" | "file"
    )
}

async fn execute_scan_config_backup_selector_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
    document: &ValidatedScanConfigBackup,
) -> Result<(), ApiError> {
    let selector_row = tx
        .query_one(
            scan_config_backup_selector_name_sql(),
            &[&scan_config_internal_id],
        )
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "load imported scan-config selector")
        })?;
    let selector_name: String = selector_row.get(0);
    if document.families_growing {
        execute_scan_config_write_sql(
            tx,
            scan_config_backup_insert_selector_sql(),
            &[
                &selector_name,
                &0_i32,
                &0_i32,
                &"0",
                &Option::<String>::None,
            ],
            "insert imported scan-config global selector",
        )
        .await?;
    }
    for selector in &document.selectors {
        let family = selector.family.as_deref();
        execute_scan_config_write_sql(
            tx,
            scan_config_backup_insert_selector_sql(),
            &[
                &selector_name,
                &i32::from(selector.exclude),
                &selector.selector_type,
                &selector.family_or_nvt,
                &family,
            ],
            "insert imported scan-config selector",
        )
        .await?;
    }
    Ok(())
}

fn scan_config_backup_selector_from_row(row: &Row) -> ScanConfigBackupSelector {
    ScanConfigBackupSelector {
        selector_type: row.get("selector_type"),
        exclude: row.get::<_, i32>("exclude") != 0,
        family_or_nvt: row.get("family_or_nvt"),
        family: row.get("family"),
    }
}

fn scan_config_backup_preference_from_row(
    row: &Row,
) -> (ScanConfigBackupPreferenceIdentity, String, bool) {
    let scope = row.get::<_, String>("scope");
    let identity = match scope.as_str() {
        "scanner" => ScanConfigBackupPreferenceIdentity {
            scope: ScanConfigBackupPreferenceScope::Scanner,
            name: row.get("name"),
            nvt: None,
        },
        "nvt" => ScanConfigBackupPreferenceIdentity {
            scope: ScanConfigBackupPreferenceScope::Nvt,
            name: row.get("name"),
            nvt: Some(ScanConfigBackupNvtPreferenceIdentity {
                oid: row.get("nvt_oid"),
                id: row.get("preference_id"),
                preference_type: row.get("preference_type"),
            }),
        },
        _ => unreachable!("backup SQL returns only scanner and NVT preference scopes"),
    };
    let preference_type: String = row.get("preference_type");
    let value: String = row.get("value");
    let value = if preference_type.eq_ignore_ascii_case("radio") {
        value.split(';').next().unwrap_or_default().to_string()
    } else {
        value
    };
    (
        identity,
        value,
        is_secret_scan_config_preference(&preference_type),
    )
}

fn scan_config_backup_location_headers(scan_config_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("/api/v1/scan-configs/{scan_config_id}"))
        .map_err(|_| ApiError::Database)?;
    headers.insert(header::LOCATION, value);
    Ok(headers)
}

fn scan_config_backup_metadata_sql() -> &'static str {
    "SELECT name, coalesce(comment, '') AS comment, coalesce(families_growing, 0)::integer AS families_growing, coalesce(nvt_selector, '') AS nvt_selector FROM configs WHERE uuid = $1 AND coalesce(usage_type, 'scan') = 'scan';"
}

fn scan_config_backup_family_inventory_sql() -> &'static str {
    "SELECT DISTINCT family FROM nvts WHERE family IS NOT NULL AND family != '' AND family != 'Credentials' ORDER BY family;"
}

fn scan_config_backup_selectors_sql() -> &'static str {
    "SELECT type::integer AS selector_type, exclude::integer AS exclude, family_or_nvt, CASE WHEN type = 1 THEN NULL ELSE family END AS family FROM nvt_selectors WHERE name = $1 AND type IN (1, 2) ORDER BY type, family_or_nvt, family;"
}

fn scan_config_backup_preferences_sql() -> &'static str {
    r#"SELECT CASE WHEN cp.type = 'SERVER_PREFS' THEN 'scanner' ELSE 'nvt' END AS scope,
               cp.name,
               CASE
                 WHEN lower(coalesce(nullif(cp.pref_type, ''), np.pref_type, '')) IN ('password', 'file')
                 THEN ''
                 ELSE coalesce(cp.value, '')
               END AS value,
               coalesce(cp.pref_nvt, '') AS nvt_oid,
               coalesce(cp.pref_id, 0)::integer AS preference_id,
               coalesce(nullif(cp.pref_type, ''), np.pref_type, '') AS preference_type
          FROM configs c
          JOIN config_preferences cp ON cp.config = c.id
          JOIN nvt_preferences np
            ON (cp.type = 'SERVER_PREFS' AND np.pref_nvt IS NULL AND np.name = cp.name)
            OR (cp.type = 'PLUGINS_PREFS'
                AND np.pref_nvt = cp.pref_nvt
                AND coalesce(np.pref_id, 0) = coalesce(cp.pref_id, 0)
                AND coalesce(np.pref_type, '') = coalesce(cp.pref_type, '')
                AND coalesce(np.pref_name, '') = cp.name)
         WHERE c.uuid = $1
           AND coalesce(c.usage_type, 'scan') = 'scan'
           AND cp.type IN ('SERVER_PREFS', 'PLUGINS_PREFS')
         ORDER BY scope, cp.name, nvt_oid, preference_id, preference_type;"#
}

fn scan_config_backup_insert_metadata_sql() -> &'static str {
    "INSERT INTO configs (uuid, owner, name, nvt_selector, comment, family_count, nvt_count, families_growing, nvts_growing, predefined, creation_time, modification_time, usage_type) VALUES (make_uuid(), $1, $2, make_uuid(), $3, 0, 0, $4, 0, 0, m_now(), m_now(), 'scan') RETURNING id::integer, uuid::text;"
}

fn scan_config_backup_selector_name_sql() -> &'static str {
    "SELECT nvt_selector FROM configs WHERE id = $1;"
}

fn scan_config_backup_insert_selector_sql() -> &'static str {
    "INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family) VALUES ($1, $2, $3, $4, $5);"
}

fn scan_config_backup_recalculate_caches_sql() -> &'static str {
    crate::scan_config_write_sql::scan_config_recalculate_family_nvt_caches_sql()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup_document() -> serde_json::Value {
        serde_json::json!({
            "schema": BACKUP_SCHEMA,
            "version": BACKUP_VERSION,
            "usage_type": "scan",
            "name": "Portable scan config",
            "comment": "No source identity is included.",
            "families_growing": true,
            "family_inventory": ["General"],
            "selectors": [
                {
                    "type": 2,
                    "exclude": true,
                    "family_or_nvt": "1.3.6.1.4.1.25623.1.0.100001",
                    "family": "General"
                }
            ],
            "preferences": [
                {"scope": "scanner", "name": "safe_checks", "value": "yes"}
            ],
            "omitted_secret_preference_count": 1,
            "omitted_secret_preferences": [
                {
                    "scope": "nvt",
                    "name": "credential",
                    "nvt": {
                        "oid": "1.3.6.1.4.1.25623.1.0.100001",
                        "id": 1,
                        "type": "password"
                    }
                }
            ]
        })
    }

    #[test]
    fn backup_document_is_strict_and_excludes_secret_values() {
        let document = serde_json::from_value::<ScanConfigBackupDocument>(backup_document())
            .expect("valid strict backup document");
        let document = validate_scan_config_backup_document(document)
            .expect("valid canonical backup document");
        assert_eq!(document.preferences.len(), 1);
        assert_eq!(document.omitted_secret_preferences.len(), 1);

        let mut unknown = backup_document();
        unknown["source_uuid"] = serde_json::json!("12345678-1234-1234-1234-123456789abc");
        assert!(serde_json::from_value::<ScanConfigBackupDocument>(unknown).is_err());

        let serialized = serde_json::to_string(
            &serde_json::from_value::<ScanConfigBackupDocument>(backup_document())
                .expect("backup document"),
        )
        .expect("serialize backup document");
        assert_eq!(serialized.matches("\"value\"").count(), 1);
        let serialized_value: serde_json::Value =
            serde_json::from_str(&serialized).expect("serialized backup JSON");
        assert_eq!(serialized_value["schema"], BACKUP_SCHEMA);
        assert!(
            serialized_value["omitted_secret_preferences"][0]
                .get("value")
                .is_none()
        );
        for forbidden in [
            "source_uuid",
            "owner",
            "predefined",
            "created_at",
            "tasks",
            "tags",
        ] {
            assert!(!serialized.contains(forbidden), "backup leaked {forbidden}");
        }
    }

    #[test]
    fn backup_document_accepts_current_and_legacy_v1_schemas_only() {
        for schema in [BACKUP_SCHEMA, LEGACY_BACKUP_SCHEMA] {
            let mut value = backup_document();
            value["schema"] = serde_json::json!(schema);
            let document = serde_json::from_value::<ScanConfigBackupDocument>(value)
                .expect("strict JSON shape");
            assert!(validate_scan_config_backup_document(document).is_ok());
        }

        for schema in [
            "turbovas.scan-config-backups",
            "yafvs.scan-config-backup-v1",
            "other",
        ] {
            let mut value = backup_document();
            value["schema"] = serde_json::json!(schema);
            let document = serde_json::from_value::<ScanConfigBackupDocument>(value)
                .expect("strict JSON shape");
            assert!(validate_scan_config_backup_document(document).is_err());
        }
    }

    #[test]
    fn backup_document_rejects_stale_shape_and_noncanonical_selectors() {
        for (field, value) in [
            ("schema", serde_json::json!("other")),
            ("version", serde_json::json!(2)),
            ("usage_type", serde_json::json!("audit")),
        ] {
            let mut invalid = backup_document();
            invalid[field] = value;
            let parsed = serde_json::from_value::<ScanConfigBackupDocument>(invalid)
                .expect("strict JSON shape");
            assert!(validate_scan_config_backup_document(parsed).is_err());
        }

        let mut invalid = backup_document();
        invalid["selectors"][0]["exclude"] = serde_json::json!(false);
        let parsed =
            serde_json::from_value::<ScanConfigBackupDocument>(invalid).expect("strict JSON shape");
        assert!(validate_scan_config_backup_document(parsed).is_err());

        let mut invalid = backup_document();
        invalid["omitted_secret_preference_count"] = serde_json::json!(0);
        let parsed =
            serde_json::from_value::<ScanConfigBackupDocument>(invalid).expect("strict JSON shape");
        assert!(validate_scan_config_backup_document(parsed).is_err());
    }

    #[test]
    fn canonical_selector_rows_match_growing_and_static_family_defaults() {
        let cases = [
            // A growing config defaults every family to selected, so its NVT exceptions exclude.
            (true, None, true),
            // In a growing config, a type-1 exclude makes this family static; its NVT exceptions include.
            (true, Some(true), false),
            // A static config defaults every family to unselected, so its NVT exceptions include.
            (false, None, false),
            // In a static config, a type-1 include makes this family growing; NVT exceptions exclude.
            (false, Some(false), true),
        ];
        for (families_growing, family_exclude, nvt_exclude) in cases {
            let mut value = backup_document();
            value["families_growing"] = serde_json::json!(families_growing);
            value["selectors"] = serde_json::json!([{
                "type": 2,
                "exclude": nvt_exclude,
                "family_or_nvt": "1.3.6.1.4.1.25623.1.0.100001",
                "family": "General"
            }]);
            if let Some(family_exclude) = family_exclude {
                value["selectors"] = serde_json::json!([
                    {
                        "type": 1,
                        "exclude": family_exclude,
                        "family_or_nvt": "General"
                    },
                    {
                        "type": 2,
                        "exclude": nvt_exclude,
                        "family_or_nvt": "1.3.6.1.4.1.25623.1.0.100001",
                        "family": "General"
                    }
                ]);
            }
            let document = serde_json::from_value::<ScanConfigBackupDocument>(value)
                .expect("canonical selector JSON");
            assert!(validate_scan_config_backup_document(document).is_ok());
        }
    }

    #[test]
    fn backup_sql_and_import_route_keep_the_portable_contract_bounded() {
        let selector_sql = scan_config_backup_selectors_sql();
        assert!(selector_sql.contains("CASE WHEN type = 1 THEN NULL ELSE family END"));

        let sql = scan_config_backup_preferences_sql();
        assert!(sql.contains("JOIN config_preferences"));
        assert!(sql.contains("JOIN nvt_preferences"));
        assert!(!sql.contains("default_value"));
        assert!(sql.contains("nullif(cp.pref_type, '')"));
        assert!(sql.contains("THEN ''"));
        assert!(sql.contains("cp.type IN ('SERVER_PREFS', 'PLUGINS_PREFS')"));

        let routes = include_str!("direct_api_routes.rs");
        assert!(routes.contains("/api/v1/scan-configs/import"));
        assert!(routes.contains("MAX_SCAN_CONFIG_BACKUP_BODY_BYTES"));
        let request_shapes = include_str!("request_shapes.rs");
        assert!(request_shapes.contains("direct_api_write_body_limit"));
        assert!(request_shapes.contains("/api/v1/scan-configs/import"));
    }
}
