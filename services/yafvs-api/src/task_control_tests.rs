// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    errors::ApiError,
    task_control::{
        TaskStartState, ensure_task_is_not_already_queued, ensure_task_is_startable,
        insert_task_start_report, insert_task_start_scan_queue, load_task_start_state,
        mark_task_start_requested,
    },
    task_control_sql::*,
    task_status::TaskStatus,
    task_write_db::ensure_task_is_human_owned,
};
use std::{error::Error, io};
use tokio_postgres::{GenericClient, NoTls};
use uuid::Uuid;
use yafvs_domain::ScannerType;

fn startable_task(run_status: TaskStatus) -> TaskStartState {
    TaskStartState {
        internal_id: 41,
        owner_id: Some(7),
        run_status,
        target_id: Some(19),
        target_has_hosts: true,
        config_id: Some(21),
        scanner_id: Some(23),
        scanner_type: Some(ScannerType::Openvas.database_value()),
    }
}

fn characterization_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

async fn task_admission_observation(
    client: &impl GenericClient,
    task_id: &str,
) -> Result<(i32, i64, i64), Box<dyn Error>> {
    let row = client
        .query_one(
            "SELECT tasks.run_status::integer,
                    (SELECT count(*)::bigint FROM reports WHERE task = tasks.id),
                    (SELECT count(*)::bigint
                       FROM scan_queue
                       JOIN reports ON reports.id = scan_queue.report
                      WHERE reports.task = tasks.id)
               FROM tasks
              WHERE tasks.uuid = $1;",
            &[&task_id],
        )
        .await
        .map_err(|_| characterization_error("could not observe task admission state"))?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

#[tokio::test]
#[ignore = "requires YAFVS_TASK_CONTROL_DATABASE_URL and YAFVS_TASK_CONTROL_TASK_UUID"]
async fn native_task_start_admission_rolls_back_live_database_fixture() -> Result<(), Box<dyn Error>>
{
    // This opt-in proof keeps the production handoff invisible to gvmd by
    // validating it inside one transaction that is always rolled back.
    let database_url = std::env::var("YAFVS_TASK_CONTROL_DATABASE_URL")
        .map_err(|_| characterization_error("YAFVS_TASK_CONTROL_DATABASE_URL is required"))?;
    let task_uuid = std::env::var("YAFVS_TASK_CONTROL_TASK_UUID")
        .map_err(|_| characterization_error("YAFVS_TASK_CONTROL_TASK_UUID is required"))?
        .parse::<Uuid>()
        .map_err(|_| characterization_error("YAFVS_TASK_CONTROL_TASK_UUID must be a UUID"))?;
    let config = database_url
        .parse::<tokio_postgres::Config>()
        .map_err(|_| characterization_error("YAFVS_TASK_CONTROL_DATABASE_URL is malformed"))?;
    let task_id = task_uuid.to_string();
    let (mut client, connection) = config
        .connect(NoTls)
        .await
        .map_err(|_| characterization_error("could not connect to PostgreSQL"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let before = task_admission_observation(&client, &task_id).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| characterization_error("could not begin task admission transaction"))?;
    let admission_result = async {
        let task = load_task_start_state(&tx, &task_id)
            .await
            .map_err(|_| characterization_error("task fixture could not be loaded and locked"))?;
        ensure_task_is_startable(&task)
            .map_err(|_| characterization_error("task fixture is not startable"))?;
        ensure_task_is_not_already_queued(&tx, task.internal_id)
            .await
            .map_err(|_| characterization_error("task fixture is already queued"))?;
        let task_owner_id = ensure_task_is_human_owned(task.owner_id)
            .map_err(|_| characterization_error("task fixture is not human-owned"))?;
        let (report_internal_id, _) = insert_task_start_report(&tx, &task, task_owner_id)
            .await
            .map_err(|_| characterization_error("could not insert requested report"))?;
        insert_task_start_scan_queue(&tx, report_internal_id)
            .await
            .map_err(|_| characterization_error("could not insert scan queue handoff"))?;
        mark_task_start_requested(&tx, task.internal_id)
            .await
            .map_err(|_| characterization_error("could not mark task requested"))?;

        let during = task_admission_observation(&tx, &task_id).await?;
        if during != (TaskStatus::Requested.as_i32(), before.1 + 1, before.2 + 1) {
            return Err(characterization_error(
                "task admission did not create exactly one requested report and queue entry",
            ));
        }
        let report_status: i32 = tx
            .query_one(
                "SELECT scan_run_status::integer FROM reports WHERE id = $1;",
                &[&report_internal_id],
            )
            .await
            .map_err(|_| characterization_error("could not observe requested report status"))?
            .get(0);
        if report_status != TaskStatus::Requested.as_i32() {
            return Err(characterization_error(
                "new report does not have the requested status",
            ));
        }
        let queue_for_report: i64 = tx
            .query_one(
                "SELECT count(*)::bigint FROM scan_queue WHERE report = $1;",
                &[&report_internal_id],
            )
            .await
            .map_err(|_| characterization_error("could not observe new scan queue handoff"))?
            .get(0);
        if queue_for_report != 1 {
            return Err(characterization_error(
                "requested report does not have exactly one scan queue handoff",
            ));
        }
        let repeated_task = load_task_start_state(&tx, &task_id)
            .await
            .map_err(|_| characterization_error("could not reload requested task"))?;
        if !matches!(
            ensure_task_is_startable(&repeated_task),
            Err(ApiError::Conflict(_))
        ) {
            return Err(characterization_error(
                "repeated task admission was not rejected by requested status",
            ));
        }
        if !matches!(
            ensure_task_is_not_already_queued(&tx, task.internal_id).await,
            Err(ApiError::Conflict(_))
        ) {
            return Err(characterization_error(
                "duplicate task admission was not rejected",
            ));
        }
        let after_duplicate = task_admission_observation(&tx, &task_id).await?;
        if after_duplicate != during {
            return Err(characterization_error(
                "duplicate task admission changed report or queue state",
            ));
        }
        Ok(())
    }
    .await;
    tx.rollback()
        .await
        .map_err(|_| characterization_error("could not roll back task admission transaction"))?;
    admission_result?;

    let after = task_admission_observation(&client, &task_id).await?;
    if after != before {
        return Err(characterization_error(
            "rollback did not restore the original task admission state",
        ));
    }
    Ok(())
}

#[test]
fn task_stop_browser_proxy_forwards_authenticated_operator_context() {
    let source = include_str!("browser_proxy_metadata_patch.rs");
    let handler = source
        .split_once("pub(crate) async fn browser_proxy_stop_task")
        .expect("browser task stop proxy must exist")
        .1;
    assert!(
        handler.contains("browser_proxy_operator_from_headers(&state, &auth, &headers).await?")
    );
    assert!(handler.contains("stop_task(Path(task_id), Some(Extension(operator))).await"));
}

#[test]
fn task_start_state_validation_accepts_inactive_supported_scan_tasks() {
    for status in [
        TaskStatus::Done,
        TaskStatus::New,
        TaskStatus::Stopped,
        TaskStatus::Interrupted,
    ] {
        assert!(
            ensure_task_is_startable(&startable_task(status)).is_ok(),
            "status {status:?} should be startable"
        );
    }
}

#[test]
fn task_start_state_validation_rejects_missing_or_unsupported_resources() {
    let mut task = startable_task(TaskStatus::Done);
    task.target_id = None;
    assert!(matches!(
        ensure_task_is_startable(&task),
        Err(ApiError::BadRequest(message)) if message.contains("target")
    ));

    let mut task = startable_task(TaskStatus::Done);
    task.target_has_hosts = false;
    assert!(matches!(
        ensure_task_is_startable(&task),
        Err(ApiError::BadRequest(message)) if message.contains("host")
    ));

    let mut task = startable_task(TaskStatus::Done);
    task.config_id = None;
    assert!(matches!(
        ensure_task_is_startable(&task),
        Err(ApiError::BadRequest(message)) if message.contains("scan config")
    ));

    let mut task = startable_task(TaskStatus::Done);
    task.scanner_id = None;
    assert!(matches!(
        ensure_task_is_startable(&task),
        Err(ApiError::BadRequest(message)) if message.contains("scanner")
    ));

    for scanner_type in [
        ScannerType::None.database_value(),
        1,
        ScannerType::Cve.database_value(),
        4,
        7,
        9,
    ] {
        let mut task = startable_task(TaskStatus::Done);
        task.scanner_type = Some(scanner_type);
        assert!(matches!(
            ensure_task_is_startable(&task),
            Err(ApiError::BadRequest(message)) if message.contains("scanner type")
        ));
    }
    for scanner_type in [
        ScannerType::Openvas,
        ScannerType::OspSensor,
        ScannerType::Openvasd,
        ScannerType::OpenvasdSensor,
    ] {
        let mut task = startable_task(TaskStatus::Done);
        task.scanner_type = Some(scanner_type.database_value());
        assert!(ensure_task_is_startable(&task).is_ok());
    }
}

#[test]
fn task_start_state_validation_rejects_active_deleting_and_processing_statuses() {
    for status in [
        TaskStatus::DeleteRequested,
        TaskStatus::Requested,
        TaskStatus::Running,
        TaskStatus::StopRequested,
        TaskStatus::StopWaiting,
        TaskStatus::DeleteUltimateRequested,
        TaskStatus::DeleteWaiting,
        TaskStatus::DeleteUltimateWaiting,
        TaskStatus::Queued,
        TaskStatus::Processing,
    ] {
        assert!(
            matches!(
                ensure_task_is_startable(&startable_task(status)),
                Err(ApiError::Conflict(_))
            ),
            "status {status:?} must stay unavailable for native task start"
        );
    }
}

#[test]
fn task_start_sql_preserves_the_gvmd_scan_queue_handoff_contract() {
    let state = task_start_state_sql();
    assert!(state.contains("FROM tasks"));
    assert!(state.contains("LEFT JOIN scanners"));
    assert!(state.contains("LEFT JOIN targets"));
    assert!(state.contains("LEFT JOIN configs"));
    assert!(state.contains("nullif(btrim(coalesce(targets.hosts, '')), '')"));
    assert!(state.contains("coalesce(tasks.target_location, 0) = 0"));
    assert!(state.contains("coalesce(tasks.config_location, 0) = 0"));
    assert!(state.contains("coalesce(tasks.scanner_location, 0) = 0"));
    assert!(state.contains("FOR UPDATE OF tasks"));
    assert!(state.contains("coalesce(tasks.hidden, 0) = 0"));
    assert!(state.contains("coalesce(tasks.usage_type, 'scan') = 'scan'"));

    let existing_queue = task_start_scan_queue_exists_sql();
    assert!(existing_queue.contains("FROM scan_queue"));
    assert!(existing_queue.contains("JOIN reports"));
    assert!(existing_queue.contains("reports.task = $1"));

    let report = task_start_insert_report_sql();
    assert!(report.contains("INSERT INTO reports"));
    assert!(report.contains("make_uuid()"));
    assert!(report.contains("m_now(), m_now(), '', $3, 0, 0"));
    assert!(report.contains("RETURNING id::integer, uuid::text"));

    let queue = task_start_insert_scan_queue_sql();
    assert!(queue.contains("INSERT INTO scan_queue"));
    assert!(queue.contains("clock_timestamp()"));
    assert!(queue.contains("handler_pid, start_from"));
    assert!(queue.contains("0,"));

    let update = task_start_mark_requested_sql();
    assert!(update.contains("UPDATE tasks"));
    assert!(update.contains("SET run_status = $2"));
}

#[test]
fn task_start_handler_locks_validates_and_queues_in_one_transaction() {
    let source = include_str!("task_control.rs");
    let handler = source
        .split_once("pub(crate) async fn start_task")
        .expect("task start handler must exist")
        .1;
    for required in [
        "require_task_write_operator(operator)?",
        "parse_uuid(&task_id)?",
        "transaction()",
        "resolve_task_write_operator_owner(&tx, &operator).await?",
        "load_task_start_state(&tx, &task_id).await?",
        "ensure_task_is_human_owned(task.owner_id)?",
        "ensure_task_is_startable(&task)?",
        "ensure_task_is_not_already_queued(&tx, task.internal_id).await?",
        "insert_task_start_report(&tx, &task, task_owner_id).await?",
        "insert_task_start_scan_queue(&tx, report_internal_id).await?",
        "mark_task_start_requested(&tx, task.internal_id).await?",
        "tx.commit()",
        "StatusCode::ACCEPTED",
        "status: \"requested\"",
    ] {
        assert!(
            handler.contains(required),
            "task start handler missing {required}"
        );
    }
    assert!(
        handler.find("load_task_start_state").unwrap()
            < handler.find("ensure_task_is_not_already_queued").unwrap()
    );
    assert!(
        handler.find("ensure_task_is_not_already_queued").unwrap()
            < handler.find("insert_task_start_report").unwrap()
    );
    assert!(
        handler.find("insert_task_start_report").unwrap()
            < handler.find("insert_task_start_scan_queue").unwrap()
    );
    assert!(
        handler.find("insert_task_start_scan_queue").unwrap()
            < handler.find("mark_task_start_requested").unwrap()
    );
}

#[test]
fn task_target_replace_browser_proxy_forwards_authenticated_operator_and_request() {
    let source = include_str!("browser_proxy_metadata_patch.rs");
    let handler = source
        .split_once("pub(crate) async fn browser_proxy_replace_task_target")
        .expect("browser task target replacement proxy must exist")
        .1;
    assert!(
        handler.contains("browser_proxy_operator_from_headers(&state, &auth, &headers).await?")
    );
    assert!(handler.contains(
        "replace_task_target(
        State(state),
        Path(task_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await"
    ));
}

#[test]
fn task_start_browser_proxy_forwards_authenticated_operator_context() {
    let source = include_str!("browser_proxy_metadata_patch.rs");
    let handler = source
        .split_once("pub(crate) async fn browser_proxy_start_task")
        .expect("browser task start proxy must exist")
        .1;
    assert!(
        handler.contains("browser_proxy_operator_from_headers(&state, &auth, &headers).await?")
    );
    assert!(
        handler
            .contains("start_task(State(state), Path(task_id), Some(Extension(operator))).await")
    );
}
