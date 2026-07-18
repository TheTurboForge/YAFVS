// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    env,
    fs::File,
    io::{self, ErrorKind, Read},
    os::fd::AsRawFd,
    path::{Path as FsPath, PathBuf},
};

use axum::Json;
use serde::Serialize;

use crate::errors::ApiError;

const FEED_METADATA_ROOT_ENV: &str = "YAFVS_FEED_METADATA_DIR";
const FEED_LOCK_ROOT_ENV: &str = "YAFVS_FEED_LOCK_DIR";
const DEFAULT_FEED_METADATA_ROOT: &str = "/runtime/feeds";
const DEFAULT_FEED_LOCK_ROOT: &str = "/runtime/run";
const MAX_FEED_METADATA_BYTES: u64 = 256 * 1024;
const MAX_FEED_LOCK_BYTES: u64 = 4096;

#[derive(Clone, Copy)]
enum FeedMetadataFormat {
    PluginInfo,
    FeedXml,
}

#[derive(Clone, Copy)]
struct FeedDefinition {
    feed_type: &'static str,
    metadata_rel: &'static str,
    lock_rel: &'static str,
    format: FeedMetadataFormat,
}

const FEED_DEFINITIONS: [FeedDefinition; 4] = [
    FeedDefinition {
        feed_type: "NVT",
        metadata_rel: "openvas/plugins/plugin_feed_info.inc",
        lock_rel: "ospd/feed-update.lock",
        format: FeedMetadataFormat::PluginInfo,
    },
    FeedDefinition {
        feed_type: "SCAP",
        metadata_rel: "gvm/scap-data/feed.xml",
        lock_rel: "feed-update.lock",
        format: FeedMetadataFormat::FeedXml,
    },
    FeedDefinition {
        feed_type: "CERT",
        metadata_rel: "gvm/cert-data/feed.xml",
        lock_rel: "feed-update.lock",
        format: FeedMetadataFormat::FeedXml,
    },
    FeedDefinition {
        feed_type: "GVMD_DATA",
        metadata_rel: "gvm/data-objects/gvmd/22.04/feed.xml",
        lock_rel: "feed-update.lock",
        format: FeedMetadataFormat::FeedXml,
    },
];

#[derive(Debug, Serialize)]
pub(crate) struct FeedsResponse {
    items: Vec<FeedItem>,
}

#[derive(Debug, Serialize)]
struct FeedCurrentlySyncing {
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
struct FeedItem {
    name: String,
    version: String,
    #[serde(rename = "type")]
    feed_type: String,
    status: String,
    sync_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    currently_syncing: Option<FeedCurrentlySyncing>,
    metadata_source: &'static str,
    status_source: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
enum FeedSyncState {
    UpToDate,
    Syncing { timestamp: Option<String> },
    Unknown,
}

pub(crate) async fn feeds() -> Result<Json<FeedsResponse>, ApiError> {
    Ok(Json(feed_inventory()?))
}

fn feed_inventory() -> Result<FeedsResponse, ApiError> {
    let metadata_root = feed_metadata_root();
    let lock_root = feed_lock_root();
    let mut items = Vec::with_capacity(FEED_DEFINITIONS.len());
    for definition in FEED_DEFINITIONS {
        let metadata_path = metadata_root.join(definition.metadata_rel);
        let metadata = read_text_file_bounded(&metadata_path, MAX_FEED_METADATA_BYTES).map_err(|error| {
            tracing::warn!(%error, path = %metadata_path.display(), "feed metadata read failed");
            ApiError::Config
        })?;
        let (name, version) = match definition.format {
            FeedMetadataFormat::PluginInfo => parse_plugin_feed_info(&metadata)?,
            FeedMetadataFormat::FeedXml => parse_feed_xml(&metadata, definition.feed_type)?,
        };
        let lock_path = lock_root.join(definition.lock_rel);
        let sync_state = feed_sync_state(&lock_path);
        items.push(feed_item(definition.feed_type, name, version, sync_state));
    }
    Ok(FeedsResponse { items })
}

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn feed_metadata_root() -> PathBuf {
    env_string(FEED_METADATA_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FEED_METADATA_ROOT))
}

fn feed_lock_root() -> PathBuf {
    env_string(FEED_LOCK_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FEED_LOCK_ROOT))
}

fn feed_item(
    feed_type: &str,
    name: String,
    version: String,
    sync_state: FeedSyncState,
) -> FeedItem {
    match sync_state {
        FeedSyncState::UpToDate => FeedItem {
            name,
            version,
            feed_type: feed_type.to_string(),
            status: "Up-to-date...".to_string(),
            sync_status: "up_to_date".to_string(),
            currently_syncing: None,
            metadata_source: "runtime_feed_copy",
            status_source: "runtime_feed_lock",
        },
        FeedSyncState::Syncing { timestamp } => FeedItem {
            name,
            version,
            feed_type: feed_type.to_string(),
            status: "Update in progress...".to_string(),
            sync_status: "syncing".to_string(),
            currently_syncing: Some(FeedCurrentlySyncing { timestamp }),
            metadata_source: "runtime_feed_copy",
            status_source: "runtime_feed_lock",
        },
        FeedSyncState::Unknown => FeedItem {
            name,
            version,
            feed_type: feed_type.to_string(),
            status: "Unknown".to_string(),
            sync_status: "unknown".to_string(),
            currently_syncing: None,
            metadata_source: "runtime_feed_copy",
            status_source: "unavailable",
        },
    }
}

fn parse_plugin_feed_info(text: &str) -> Result<(String, String), ApiError> {
    let name = parse_quoted_assignment(text, "PLUGIN_FEED").ok_or(ApiError::Config)?;
    let version = parse_quoted_assignment(text, "PLUGIN_SET").ok_or(ApiError::Config)?;
    Ok((name, version))
}

fn parse_quoted_assignment(text: &str, key: &str) -> Option<String> {
    for raw_line in text.lines() {
        let line = raw_line.trim();
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let value = value.strip_prefix('"')?;
        let end = value.find('"')?;
        return Some(value[..end].to_string());
    }
    None
}

fn parse_feed_xml(text: &str, expected_type: &str) -> Result<(String, String), ApiError> {
    let feed_type = extract_xml_text(text, "type").ok_or(ApiError::Config)?;
    if feed_type != expected_type {
        tracing::warn!(expected_type, parsed_type = %feed_type, "feed metadata type mismatch");
        return Err(ApiError::Config);
    }
    let name = extract_xml_text(text, "name").ok_or(ApiError::Config)?;
    let version = extract_xml_text(text, "version").ok_or(ApiError::Config)?;
    Ok((name, version))
}

fn extract_xml_text(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let after_open = text.split_once(&open)?.1;
    let raw = after_open.split_once(&close)?.0;
    Some(decode_basic_xml_entities(raw.trim()))
}

fn decode_basic_xml_entities(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub(crate) fn read_text_file_bounded(path: &FsPath, max_bytes: u64) -> Result<String, io::Error> {
    let file = File::open(path)?;
    let mut limited = file.take(max_bytes + 1);
    let mut buffer = String::new();
    limited.read_to_string(&mut buffer)?;
    if buffer.len() as u64 > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "runtime feed metadata file exceeds size limit",
        ));
    }
    Ok(buffer)
}

fn feed_sync_state(lock_path: &FsPath) -> FeedSyncState {
    let file = match File::open(lock_path) {
        Ok(file) => file,
        Err(error) => {
            tracing::debug!(%error, path = %lock_path.display(), "feed lock file is unavailable");
            return FeedSyncState::Unknown;
        }
    };
    match try_shared_flock(&file) {
        Ok(true) => {
            unlock_flock(&file, lock_path);
            FeedSyncState::UpToDate
        }
        Ok(false) => FeedSyncState::Syncing {
            timestamp: read_feed_lock_timestamp(lock_path),
        },
        Err(error) => {
            tracing::warn!(%error, path = %lock_path.display(), "feed lock status read failed");
            FeedSyncState::Unknown
        }
    }
}

fn read_feed_lock_timestamp(lock_path: &FsPath) -> Option<String> {
    let text = read_text_file_bounded(lock_path, MAX_FEED_LOCK_BYTES).ok()?;
    let timestamp = text.lines().next().unwrap_or_default().trim();
    (!timestamp.is_empty()).then(|| timestamp.to_string())
}

fn try_shared_flock(file: &File) -> Result<bool, io::Error> {
    // SAFETY: flock only receives a valid file descriptor borrowed from File;
    // no pointer aliasing or ownership transfer is involved.
    // nosemgrep: turbovas.native-api.unsafe-rust
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == ErrorKind::WouldBlock
        || matches!(error.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK)
    {
        Ok(false)
    } else {
        Err(error)
    }
}

fn unlock_flock(file: &File, lock_path: &FsPath) {
    // SAFETY: flock only receives a valid file descriptor borrowed from File;
    // no pointer aliasing or ownership transfer is involved.
    // nosemgrep: turbovas.native-api.unsafe-rust
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if result != 0 {
        let error = io::Error::last_os_error();
        tracing::warn!(%error, path = %lock_path.display(), "feed lock unlock failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_plugin_info_parser_reads_only_name_and_version() {
        let text = r#"
PLUGIN_SET = "202605221736";
PLUGIN_FEED = "Greenbone Community Feed";
FEED_COMMIT = "not part of the public contract";
"#;
        let (name, version) = parse_plugin_feed_info(text).unwrap();
        assert_eq!(name, "Greenbone Community Feed");
        assert_eq!(version, "202605221736");
    }

    #[test]
    fn feed_xml_parser_requires_expected_type_and_decodes_basic_entities() {
        let text = r#"<feed><type>SCAP</type><name>Greenbone &amp; SCAP</name><version>202605220623</version></feed>"#;
        let (name, version) = parse_feed_xml(text, "SCAP").unwrap();
        assert_eq!(name, "Greenbone & SCAP");
        assert_eq!(version, "202605220623");
        assert!(parse_feed_xml(text, "CERT").is_err());
    }

    #[test]
    fn feed_definitions_are_fixed_allowlisted_runtime_files() {
        assert_eq!(FEED_DEFINITIONS.len(), 4);
        for definition in FEED_DEFINITIONS {
            assert!(!definition.metadata_rel.starts_with('/'));
            assert!(!definition.metadata_rel.contains(".."));
            assert!(!definition.lock_rel.starts_with('/'));
            assert!(!definition.lock_rel.contains(".."));
        }
    }
}
