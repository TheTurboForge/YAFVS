// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{path::PathBuf, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DBLocation {
    #[default]
    InMemory,
    File(PathBuf),
}

impl DBLocation {
    pub fn sqlite_address(&self, name: &str) -> String {
        match &self {
            Self::InMemory => "sqlite::memory:".to_owned(),
            Self::File(path_buf) => {
                format!(
                    "sqlite:{}",
                    path_buf.join(format!("{name}.sql")).to_string_lossy()
                )
            }
        }
    }

    fn default_file_location(name: &str) -> Self {
        let cache_dir = if let Some(xdg_cache) = std::env::var_os("XDG_CACHE_HOME") {
            PathBuf::from(&xdg_cache)
        } else {
            PathBuf::from(".")
        };

        let cache_dir = cache_dir.join(name);
        Self::File(cache_dir)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(default)]
pub struct SqliteConfiguration {
    #[serde(
        deserialize_with = "DBLocation::config_deserialize",
        serialize_with = "DBLocation::config_serialize"
    )]
    pub location: DBLocation,
    #[serde(
        deserialize_with = "scannerlib::utils::duration::deserialize",
        serialize_with = "scannerlib::utils::duration::serialize"
    )]
    pub busy_timeout: Duration,
    pub max_connections: u32,
    pub credential_key: Option<String>,
}

impl Default for SqliteConfiguration {
    fn default() -> Self {
        Self {
            location: Default::default(),
            busy_timeout: Duration::from_secs(10),
            max_connections: 1,
            credential_key: None,
        }
    }
}

impl SqliteConfiguration {
    pub async fn create_pool(&self, name: &str) -> Result<sqlx::Pool<sqlx::Sqlite>, sqlx::Error> {
        use sqlx::{
            Sqlite,
            pool::PoolOptions,
            sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous},
        };

        if let DBLocation::File(path) = &self.location
            && !path.exists()
        {
            std::fs::create_dir_all(path)
                .unwrap_or_else(|error| panic!("Failed to create dir at {path:?}: {error}"));
        }

        let options = SqliteConnectOptions::from_str(&self.location.sqlite_address(name))?
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(self.busy_timeout)
            .synchronous(SqliteSynchronous::Off)
            .create_if_missing(true);
        PoolOptions::<Sqlite>::new()
            .max_lifetime(None)
            .idle_timeout(None)
            .max_connections(self.max_connections)
            .connect_with(options)
            .await
    }

    pub fn default_file_location(name: &str) -> Self {
        Self {
            location: DBLocation::default_file_location(name),
            ..Default::default()
        }
    }
}

impl From<&str> for DBLocation {
    fn from(value: &str) -> Self {
        match value {
            "in-memory" => Self::InMemory,
            file => Self::File(file.into()),
        }
    }
}

impl DBLocation {
    // toml is not able to handle File(PathBuf) and it looks cleaner in toml when we flatten
    fn config_deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from(s.as_str()))
    }

    // toml is not able to handle File(PathBuf) and it looks cleaner in toml when we flatten
    fn config_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::InMemory => serializer.serialize_str("in-memory"),
            Self::File(path) => serializer.serialize_str(path.to_str().unwrap_or("")),
        }
    }
}
