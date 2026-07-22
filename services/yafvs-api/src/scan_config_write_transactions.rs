// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    scan_config_write_db::{
        ScanConfigPreferenceDefinition, ScanConfigWriteRecord, execute_scan_config_write_sql,
        load_scan_config_preference_definition, query_scan_config_write_record,
    },
    scan_config_write_sql::*,
    scan_config_write_validation::{
        ScanConfigPreferenceAction, ScanConfigPreferenceScope, SensitiveScanConfigPreferenceValue,
        ValidatedScanConfigClone, ValidatedScanConfigCreate, ValidatedScanConfigFamilyNvtsPatch,
        ValidatedScanConfigFamilySelection, ValidatedScanConfigPatch,
        ValidatedScanConfigPreferenceMutation,
    },
};

pub(crate) async fn execute_scan_config_create_from_base_transaction(
    tx: &Transaction<'_>,
    source_scan_config_internal_id: i32,
    owner_id: i32,
    request: &ValidatedScanConfigCreate,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_create_from_base_metadata_sql(),
        &[
            &source_scan_config_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "create scan-config metadata from base",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_preferences_sql(),
        &[&source_scan_config_internal_id, &record.internal_id],
        "create scan-config preferences from base",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_selectors_sql(),
        &[&source_scan_config_internal_id, &record.internal_id],
        "create scan-config selectors from base",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_tags_sql(),
        &[
            &source_scan_config_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "create scan-config tag links from base",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scan_config_preference_mutations_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
    mutations: &[ValidatedScanConfigPreferenceMutation],
) -> Result<(), ApiError> {
    for mutation in mutations {
        let definition = load_scan_config_preference_definition(tx, mutation).await?;
        let storage_type = match mutation.scope {
            ScanConfigPreferenceScope::Scanner => "SERVER_PREFS",
            ScanConfigPreferenceScope::Nvt => "PLUGINS_PREFS",
        };
        execute_scan_config_write_sql(
            tx,
            scan_config_delete_preference_override_sql(),
            &[
                &scan_config_internal_id,
                &storage_type,
                &definition.canonical_name,
            ],
            "delete scan-config preference override",
        )
        .await?;

        if mutation.action == ScanConfigPreferenceAction::Set {
            let value = canonical_scan_config_preference_value(mutation, &definition)?;
            let value_text = value.as_str();
            let nvt_oid = (mutation.scope == ScanConfigPreferenceScope::Nvt)
                .then_some(definition.nvt_oid.as_str());
            let preference_id = nvt_oid.map(|_| definition.preference_id);
            let preference_type = nvt_oid.map(|_| definition.preference_type.as_str());
            let preference_name = nvt_oid.map(|_| definition.preference_name.as_str());
            execute_scan_config_write_sql(
                tx,
                scan_config_insert_preference_override_sql(),
                &[
                    &scan_config_internal_id,
                    &storage_type,
                    &definition.canonical_name,
                    &value_text,
                    &nvt_oid,
                    &preference_id,
                    &preference_type,
                    &preference_name,
                ],
                "insert scan-config preference override",
            )
            .await?;
        }
    }
    Ok(())
}

pub(crate) fn canonical_scan_config_preference_value(
    mutation: &ValidatedScanConfigPreferenceMutation,
    definition: &ScanConfigPreferenceDefinition,
) -> Result<SensitiveScanConfigPreferenceValue, ApiError> {
    let value = mutation.value.as_ref().ok_or_else(|| {
        ApiError::BadRequest("set preference mutations must include value".to_string())
    })?;
    let value = value.as_str();
    if !definition.preference_type.eq_ignore_ascii_case("radio") {
        return Ok(SensitiveScanConfigPreferenceValue::from_string(
            value.to_string(),
        ));
    }

    let options = definition
        .default_value
        .split(';')
        .filter(|option| !option.is_empty())
        .collect::<Vec<_>>();
    if !options.contains(&value) {
        return Err(ApiError::BadRequest(
            "radio preference value is not one of the current feed options".to_string(),
        ));
    }
    Ok(SensitiveScanConfigPreferenceValue::from_string(
        std::iter::once(value)
            .chain(options.into_iter().filter(|option| *option != value))
            .collect::<Vec<_>>()
            .join(";"),
    ))
}

pub(crate) async fn execute_scan_config_family_selection_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
    nvt_selector: &str,
    request: &ValidatedScanConfigFamilySelection,
) -> Result<(), ApiError> {
    let family_names = request
        .families
        .iter()
        .map(|family| family.name.clone())
        .collect::<Vec<_>>();
    let family_growing = request
        .families
        .iter()
        .map(|family| family.growing)
        .collect::<Vec<_>>();
    let family_selected = request
        .families
        .iter()
        .map(|family| family.selected)
        .collect::<Vec<_>>();
    let families_growing = i32::from(request.families_growing);

    execute_scan_config_write_sql(
        tx,
        scan_config_replace_family_selection_sql(),
        &[
            &scan_config_internal_id,
            &nvt_selector,
            &families_growing,
            &family_names,
            &family_growing,
            &family_selected,
        ],
        "replace scan-config family selection",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_recalculate_family_nvt_caches_sql(),
        &[&scan_config_internal_id],
        "recalculate scan-config family selection caches",
    )
    .await
}

pub(crate) async fn execute_scan_config_family_nvts_patch_transaction(
    tx: &Transaction<'_>,
    nvt_selector: &str,
    family: &str,
    default_selected: bool,
    request: &ValidatedScanConfigFamilyNvtsPatch,
    scan_config_internal_id: i32,
) -> Result<(), ApiError> {
    let requested_oids = request
        .changes
        .iter()
        .map(|change| change.oid.clone())
        .collect::<Vec<_>>();
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_family_nvt_selector_rows_sql(),
        &[&nvt_selector, &family, &requested_oids],
        "delete scan-config family NVT selector rows",
    )
    .await?;

    let override_oids = request
        .changes
        .iter()
        .filter_map(|change| {
            scan_config_family_nvt_selector_exclude(default_selected, change.selected)
                .map(|_| change.oid.clone())
        })
        .collect::<Vec<_>>();
    if !override_oids.is_empty() {
        let exclude = i32::from(default_selected);
        execute_scan_config_write_sql(
            tx,
            scan_config_insert_family_nvt_selector_rows_sql(),
            &[&nvt_selector, &family, &exclude, &override_oids],
            "insert normalized scan-config family NVT selector rows",
        )
        .await?;
    }

    execute_scan_config_write_sql(
        tx,
        scan_config_recalculate_family_nvt_caches_sql(),
        &[&scan_config_internal_id],
        "recalculate scan-config family NVT selection caches",
    )
    .await
}

pub(crate) fn scan_config_family_nvt_selector_exclude(
    default_selected: bool,
    selected: bool,
) -> Option<i32> {
    (selected != default_selected).then_some(i32::from(default_selected))
}

pub(crate) async fn execute_scan_config_clone_transaction(
    tx: &Transaction<'_>,
    source_scan_config_internal_id: i32,
    owner_id: i32,
    request: &ValidatedScanConfigClone,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_clone_metadata_sql(),
        &[
            &source_scan_config_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone scan-config metadata",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_preferences_sql(),
        &[&source_scan_config_internal_id, &record.internal_id],
        "clone scan-config preferences",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_selectors_sql(),
        &[&source_scan_config_internal_id, &record.internal_id],
        "clone scan-config selectors",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_tags_sql(),
        &[
            &source_scan_config_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "clone scan-config tags",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scan_config_metadata_patch_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
    request: &ValidatedScanConfigPatch,
) -> Result<ScanConfigWriteRecord, ApiError> {
    query_scan_config_write_record(
        tx,
        scan_config_update_metadata_sql(),
        &[&scan_config_internal_id, &request.name, &request.comment],
        "update scan-config metadata",
    )
    .await
}

pub(crate) async fn execute_scan_config_trash_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_trash_insert_sql(),
        &[&scan_config_internal_id],
        "move scan-config metadata to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_preferences_trash_insert_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move scan-config preferences to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_task_relink_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "relink tasks to trashed scan config",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_tag_locations_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move live scan-config tag links to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move trashed tag links to scan-config trash id",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_preferences_sql(),
        &[&scan_config_internal_id],
        "delete live scan-config preferences after trash move",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_metadata_sql(),
        &[&scan_config_internal_id],
        "delete live scan config after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scan_config_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_scan_config_internal_id: i32,
) -> Result<(), ApiError> {
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_delete_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash tag links",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_trash_delete_sql(),
        &[&trash_scan_config_internal_id],
        "delete trashed tag links to scan-config trash id",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_selector_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash NVT selector for hard delete",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_preferences_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash preferences for hard delete",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_metadata_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash metadata for hard delete",
    )
    .await?;
    Ok(())
}

pub(crate) async fn execute_scan_config_restore_transaction(
    tx: &Transaction<'_>,
    trash_scan_config_internal_id: i32,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_restore_metadata_sql(),
        &[&trash_scan_config_internal_id],
        "restore scan-config metadata from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_preferences_restore_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore scan-config preferences from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_task_relink_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "relink trash tasks to restored scan config",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_tag_locations_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore live scan-config tag links from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_locations_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore trashed tag links to scan-config live id",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_preferences_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash preferences after restore",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_metadata_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash metadata after restore",
    )
    .await?;
    Ok(record)
}
