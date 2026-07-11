// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::{Row, Transaction};

use crate::{
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    report_config_write_sql::*,
    report_config_write_validation::{ReportConfigFormatParam, ReportConfigFormatState},
};

use super::map_report_config_write_db_error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
    pub(crate) report_format_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigTrashState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) owner_id: i32,
}

pub(crate) fn require_report_config_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("report config write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_report_config_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        report_config_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "resolve report config write operator")
        })?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!(
                "direct API report config write operator does not resolve to a database user"
            );
            ApiError::Forbidden
        })
}

pub(crate) async fn ensure_unique_live_report_config_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: Option<i32>,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            report_config_unique_live_name_sql(),
            &[&name, &except_internal_id],
        )
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check report config name uniqueness")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "report config with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_live_report_config_name_for_owner(
    tx: &Transaction<'_>,
    name: &str,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            report_config_unique_live_owner_name_sql(),
            &[&name, &owner_id],
        )
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check report config restore name conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "report config with the same owner and name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_report_config_uuid_not_live(
    tx: &Transaction<'_>,
    report_config_id: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(report_config_live_uuid_conflict_sql(), &[&report_config_id])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check report config restore UUID conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "live report config with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn load_report_config_format_state(
    tx: &Transaction<'_>,
    report_format_id: &str,
) -> Result<ReportConfigFormatState, ApiError> {
    let report_format = tx
        .query_opt(report_config_format_state_sql(), &[&report_format_id])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "load report format for report config create")
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = report_format.get(0);
    let param_rows = tx
        .query(report_config_format_params_sql(), &[&internal_id])
        .await
        .map_err(|error| map_report_config_write_db_error(error, "load report format params"))?;
    if param_rows.is_empty() {
        return Err(ApiError::Conflict(
            "report format is not configurable".to_string(),
        ));
    }

    let param_ids = param_rows
        .iter()
        .map(|row| row.get::<_, i32>("internal_id"))
        .collect::<Vec<_>>();
    let option_rows = tx
        .query(report_config_format_param_options_sql(), &[&param_ids])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "load report format param options")
        })?;
    let mut options_by_param = BTreeMap::<i32, BTreeSet<String>>::new();
    for row in option_rows {
        options_by_param
            .entry(row.get("report_format_param"))
            .or_default()
            .insert(row.get("value"));
    }

    let params = param_rows
        .into_iter()
        .map(|row| {
            let param = report_config_format_param_from_row(&row, &options_by_param);
            (row.get("name"), param)
        })
        .collect();
    Ok(ReportConfigFormatState { params })
}

pub(crate) async fn load_report_config_trash_state(
    tx: &Transaction<'_>,
    report_config_id: &str,
) -> Result<ReportConfigTrashState, ApiError> {
    let report_config_id = parse_uuid(report_config_id)?.to_string();
    tx.query_opt(report_config_trash_state_sql(), &[&report_config_id])
        .await
        .map_err(|error| map_report_config_write_db_error(error, "load report config trash state"))?
        .map(|row| ReportConfigTrashState {
            internal_id: row.get(0),
            uuid: row.get(1),
            name: row.get(2),
            owner_id: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn load_report_config_write_state(
    tx: &Transaction<'_>,
    report_config_id: &str,
) -> Result<ReportConfigWriteState, ApiError> {
    let report_config_id = parse_uuid(report_config_id)?.to_string();
    tx.query_opt(report_config_write_state_sql(), &[&report_config_id])
        .await
        .map_err(|error| map_report_config_write_db_error(error, "load report config write state"))?
        .map(|row| ReportConfigWriteState {
            internal_id: row.get(0),
            owner_id: row.get(2),
            report_format_id: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_report_config_owner_matches_operator(
    report_config_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if report_config_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!(
            report_config_owner_id,
            operator_owner_id,
            "direct API report config write owner mismatch"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn ensure_report_config_not_in_use_by_alerts(
    tx: &Transaction<'_>,
    _report_config_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(report_config_in_use_by_alerts_sql(), &[])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check report config alert usage")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "report config is still referenced by an alert".to_string(),
        ))
    }
}

pub(crate) async fn ensure_trash_report_config_not_in_use_by_alerts(
    tx: &Transaction<'_>,
    _report_config_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(report_config_trash_in_use_by_alerts_sql(), &[])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check trash report config alert usage")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "trash report config is still referenced by an alert".to_string(),
        ))
    }
}

fn report_config_format_param_from_row(
    row: &Row,
    options_by_param: &BTreeMap<i32, BTreeSet<String>>,
) -> ReportConfigFormatParam {
    let internal_id = row.get("internal_id");
    ReportConfigFormatParam {
        param_type: row.get("param_type"),
        min: row.get::<_, Option<i64>>("type_min").unwrap_or(0),
        max: row.get::<_, Option<i64>>("type_max").unwrap_or(0),
        options: options_by_param
            .get(&internal_id)
            .cloned()
            .unwrap_or_default(),
    }
}
