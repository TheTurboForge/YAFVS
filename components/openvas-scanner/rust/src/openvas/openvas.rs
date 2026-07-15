// SPDX-FileCopyrightText: 2024 Greenbone AG
// TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::resources::check::Checker;
use super::{
    cmd,
    error::OpenvasError,
    openvas_redis::{KbAccess, RedisHelper},
    pref_handler::PreferenceHandler,
    result_collector::ResultHelper,
};
use greenbone_scanner_framework::models::{self, HostInfo, Phase, Scan, Status};

use crate::storage::redis::{NameSpaceSelector, RedisCtx};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    fmt::Display,
    process::Child,
    str::FromStr,
    sync::{Arc, Mutex},
    time::SystemTime,
};

#[derive(Debug)]
pub struct Scanner {
    running: Mutex<HashMap<String, RunningScan>>,
    sudo: bool,
    redis_socket: String,
    resource_checker: Option<Checker>,
    default_scanner_preferences: Vec<models::ScanPreferenceInformation>,
}

#[derive(Debug)]
struct RunningScan {
    process: Child,
    db_id: u32,
    owner_token: String,
}
use crate::scanner::{
    Error as ScanError, ScanDeleter, ScanResultFetcher, ScanResultKind, ScanResults, ScanStarter,
    ScanStopper,
};

impl From<OpenvasError> for ScanError {
    fn from(value: OpenvasError) -> Self {
        ScanError::Unexpected(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenvasPhase {
    /// The information in the kb is just stored for openvas
    New,
    /// Openvas is ready and running
    Ready,
    /// Openvas scan has finished
    Finished,
    /// Openvas task has been stopped
    Stopped,
}

impl Display for OpenvasPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "requested"),
            Self::Ready => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Finished => write!(f, "failed"),
        }
    }
}

impl FromStr for OpenvasPhase {
    type Err = ();

    fn from_str(status: &str) -> Result<OpenvasPhase, ()> {
        match status {
            "new" => Ok(OpenvasPhase::New),
            "ready" => Ok(OpenvasPhase::Ready),
            "stopped" => Ok(OpenvasPhase::Stopped),
            "finished" => Ok(OpenvasPhase::Finished),
            _ => Err(()),
        }
    }
}

impl From<OpenvasPhase> for Phase {
    fn from(p: OpenvasPhase) -> Phase {
        match p {
            OpenvasPhase::New => Phase::Requested,
            OpenvasPhase::Ready => Phase::Running,
            OpenvasPhase::Finished => Phase::Succeeded,
            OpenvasPhase::Stopped => Phase::Stopped,
        }
    }
}

impl Scanner {
    pub fn new(
        memory: Option<u64>,
        cpu: Option<f32>,
        sudo: bool,
        url: String,
        default_scanner_preferences: Vec<models::ScanPreferenceInformation>,
    ) -> Self {
        Self {
            running: Default::default(),
            sudo,
            redis_socket: url,
            resource_checker: Some(Checker::new(memory, cpu)),
            default_scanner_preferences,
        }
    }

    /// Removes a scan from init and add it to the list of running scans
    fn add_running(
        &self,
        id: String,
        db_id: u32,
        owner_token: String,
    ) -> Result<bool, OpenvasError> {
        let openvas = cmd::start(&id, self.sudo, None).map_err(OpenvasError::CmdError)?;
        self.running.lock().unwrap().insert(
            id,
            RunningScan {
                process: openvas,
                db_id,
                owner_token,
            },
        );
        Ok(true)
    }

    /// Remove a scan from the list of running scans and returns the process to able to tidy up
    fn remove_running(&self, id: &str) -> Option<RunningScan> {
        self.running.lock().unwrap().remove(id)
    }

    fn create_redis_connector(
        &self,
        owned_namespace: Option<(u32, String)>,
    ) -> Result<RedisHelper<RedisCtx>, ScanError> {
        let namespace = match owned_namespace {
            Some((db_id, owner_token)) => [NameSpaceSelector::Owned(db_id, owner_token)],
            None => [NameSpaceSelector::Free],
        };

        tracing::trace!(url = &self.redis_socket, "connecting to redis");
        let kbctx = Arc::new(Mutex::new(
            match RedisCtx::open(&self.redis_socket, &namespace) {
                Ok(x) => x,
                Err(e) => return Err(ScanError::Connection(format!("{e}"))),
            },
        ));
        let nvtcache = Arc::new(Mutex::new(
            match RedisCtx::open(&self.redis_socket, &[NameSpaceSelector::Key("nvticache")]) {
                Ok(x) => x,
                Err(e) => return Err(ScanError::Connection(format!("nvticache: {e}"))),
            },
        ));
        Ok(RedisHelper::<RedisCtx>::new(nvtcache, kbctx))
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            running: Default::default(),
            sudo: cmd::check_sudo(),
            redis_socket: cmd::get_redis_socket(),
            resource_checker: None,
            default_scanner_preferences: Vec::new(),
        }
    }
}
#[async_trait]
impl ScanStarter for Scanner {
    async fn start_scan(&self, scan: Scan) -> Result<(), ScanError> {
        // Prepare the connections to redis for communication with openvas.
        let mut redis_help = self.create_redis_connector(None)?;

        // Prepare preferences and store them in redis
        let mut pref_handler = PreferenceHandler::new(
            scan.clone(),
            &mut redis_help,
            self.default_scanner_preferences.clone(),
        );
        match pref_handler.prepare_preferences_for_openvas().await {
            Ok(_) => (),
            Err(e) => {
                return Err(ScanError::Unexpected(e.to_string()));
            }
        }

        let db_id = redis_help
            .kb_id()
            .map_err(|error| ScanError::Unexpected(error.to_string()))?;
        let owner_token = redis_help
            .kb_owner_token()
            .map_err(|error| ScanError::Unexpected(error.to_string()))?;
        self.add_running(scan.scan_id, db_id, owner_token)?;

        return Ok(());
    }

    async fn can_start_scan(&self) -> bool {
        self.resource_checker
            .as_ref()
            .map(|v| v.in_boundaries())
            .unwrap_or(true)
    }
}

/// Stops a scan
#[async_trait]
impl ScanStopper for Scanner {
    /// Stops a scan
    async fn stop_scan<I>(&self, id: I) -> Result<(), ScanError>
    where
        I: AsRef<str> + Send + 'static,
    {
        let scan_id = id.as_ref();

        let running_scan = match self.remove_running(scan_id) {
            Some(scan) => scan,
            None => return Err(OpenvasError::ScanNotFound(scan_id.to_string()).into()),
        };
        let mut scan = running_scan.process;

        cmd::stop(scan_id, self.sudo)
            .map_err(OpenvasError::CmdError)?
            .wait()
            .map_err(OpenvasError::CmdError)?;

        scan.wait().map_err(OpenvasError::CmdError)?;

        // Release the task kb
        let mut redis_help =
            self.create_redis_connector(Some((running_scan.db_id, running_scan.owner_token)))?;
        redis_help
            .release()
            .map_err(|e| ScanError::Unexpected(e.to_string()))?;

        Ok(())
    }
}

/// Deletes a scan
#[async_trait]
impl ScanDeleter for Scanner {
    async fn delete_scan<I>(&self, id: I) -> Result<(), ScanError>
    where
        I: AsRef<str> + Send + 'static,
    {
        let scan_id = id.as_ref();

        let owned_namespace = {
            let running = self
                .running
                .lock()
                .map_err(|e| ScanError::Unexpected(e.to_string()))?;
            match running.get(scan_id) {
                Some(scan) => (scan.db_id, scan.owner_token.clone()),
                None => return Err(OpenvasError::ScanNotFound(scan_id.to_string()).into()),
            }
        };

        let mut redis_help = self.create_redis_connector(Some(owned_namespace))?;
        let mut ov_results = ResultHelper::init(&mut redis_help);
        let status = ov_results
            .collect_scan_status(scan_id.to_string())
            .await
            .map_err(|e| ScanError::Unexpected(e.to_string()))?;
        let scan_status = OpenvasPhase::from_str(&status)
            .map_err(|_| ScanError::Unexpected(format!("Invalid Phase status {}", status)))?
            .into();

        match scan_status {
            Phase::Running => {
                return Err(ScanError::Unexpected(format!(
                    "Not allowed to delete a running scan {scan_id}"
                )));
            }
            _ => match self.remove_running(scan_id) {
                Some(_) => {
                    redis_help
                        .release()
                        .map_err(|e| ScanError::Unexpected(e.to_string()))?;
                    tracing::debug!("Scan {scan_id} delete successfully");
                    Ok(())
                }
                None => return Err(OpenvasError::ScanNotFound(scan_id.to_string()).into()),
            },
        }
    }
}

#[async_trait]
impl ScanResultFetcher for Scanner {
    /// Fetches the results of a scan and combines the results with response
    async fn fetch_results<I>(&self, id: I) -> Result<ScanResults, ScanError>
    where
        I: AsRef<str> + Send + 'static,
    {
        let scan_id = id.as_ref();

        let owned_namespace = {
            let running = self
                .running
                .lock()
                .map_err(|e| ScanError::Unexpected(e.to_string()))?;
            match running.get(scan_id) {
                Some(scan) => (scan.db_id, scan.owner_token.clone()),
                None => return Err(OpenvasError::ScanNotFound(scan_id.to_string()).into()),
            }
        };

        let mut redis_help = self.create_redis_connector(Some(owned_namespace))?;
        let mut ov_results = ResultHelper::init(&mut redis_help);

        //TODO: error handling
        let mut all_results = ov_results
            .collect_results()
            .await
            .map_err(|e| ScanError::Unexpected(e.to_string()))?;
        all_results.extend(
            ov_results
                .collect_host_status()
                .await
                .map_err(|e| ScanError::Unexpected(e.to_string()))?,
        );
        all_results.scan_status = ov_results
            .collect_scan_status(scan_id.to_string())
            .await
            .map_err(|e| ScanError::Unexpected(e.to_string()))?;
        let hosts_info = HostInfo {
            all: all_results.count_total as u64,
            excluded: all_results.count_excluded as u64,
            dead: all_results.count_dead as u64,
            alive: all_results.count_alive as u64,
            queued: 0,
            finished: all_results.count_alive as u64,
            scanning: Some(all_results.host_status.clone()),
            ..Default::default()
        };

        let status: Phase = OpenvasPhase::from_str(&all_results.scan_status)
            .map_err(|_| {
                ScanError::Unexpected(format!("Invalid Phase status {}", all_results.scan_status))
            })?
            .into();
        let start_time = match status {
            Phase::Running => Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Valid timestamp for start scan")
                    .as_secs(),
            ),
            _ => None,
        };
        let end_time = match status {
            Phase::Failed | Phase::Stopped | Phase::Succeeded => Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Valid timestamp for start scan")
                    .as_secs(),
            ),
            _ => None,
        };

        let st = Status {
            start_time,
            end_time,
            status: status.clone(),
            host_info: Some(hosts_info),
        };

        let mut scan_res = ScanResults {
            id: scan_id.to_string(),
            status: st,
            results: all_results
                .results
                .iter()
                .map(|r| models::Result::from(r).clone())
                .collect(),
        };
        // If the scan finished, release. Openvas "finished" status is translated into
        // Succeeded. It is necessary to read the exit code to know if it failed.
        if status == Phase::Succeeded {
            let mut scan = match self.remove_running(scan_id) {
                Some(scan) => scan.process,
                None => return Err(OpenvasError::ScanNotFound(scan_id.to_string()).into()),
            };

            // Read openvas scanner exit code and if failed, reset the status to Failed.
            let exit_status = scan.wait().map_err(OpenvasError::CmdError)?;
            if let Some(code) = exit_status.code()
                && code != 0
            {
                scan_res.status.status = Phase::Failed;
                scan_res.status.start_time = scan_res.status.end_time;
                scan_res.status.host_info = None;
            }

            redis_help
                .release()
                .map_err(|e| ScanError::Unexpected(e.to_string()))?;
        }

        return Ok(scan_res);
    }

    fn scan_result_status_kind(&self) -> ScanResultKind {
        ScanResultKind::StatusAddition
    }
}
