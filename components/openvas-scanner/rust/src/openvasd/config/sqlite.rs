// SPDX-FileCopyrightText: 2026 TurboVAS contributors
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
