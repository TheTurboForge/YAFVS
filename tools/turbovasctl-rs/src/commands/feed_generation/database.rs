// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Strict PostgreSQL storage for the feed-generation import attestation.

use super::super::compose::{compose_command, runtime_environment};
use crate::process::CommandRunner;
use serde::Deserialize;
use serde::de::{Error as _, MapAccess, Visitor};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::path::Path;
use std::time::Duration;

const META_NAME: &str = "turbovas_feed_generation_attestation";
const FEED_RELEASE: &str = "22.04";
const IMPORT_CONTRACT: &str = "gvmd-nvt+gvmd-data-all+scap/v1";
const MAX_BYTES: usize = 4096;
const OVERSIZED: &str = "__OVERSIZED__";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DatabaseAttestation {
    generation_id: String,
    completed_at: String,
}

impl DatabaseAttestation {
    pub(super) fn new(generation_id: &str, completed_at: &str) -> Result<Self, String> {
        validate_generation_id(generation_id)?;
        validate_completed_at(completed_at)?;
        Ok(Self {
            generation_id: generation_id.to_owned(),
            completed_at: completed_at.to_owned(),
        })
    }

    pub(super) fn generation_id(&self) -> &str {
        &self.generation_id
    }

    pub(super) fn as_value(&self) -> Value {
        json!({
            "schema_version": 1,
            "generation_id": self.generation_id,
            "feed_release": FEED_RELEASE,
            "manifest_schema_version": 1,
            "import_contract": IMPORT_CONTRACT,
            "completed_at": self.completed_at,
        })
    }

    fn canonical_json(&self) -> Result<String, String> {
        let mut values = BTreeMap::new();
        values.insert("completed_at", Value::String(self.completed_at.clone()));
        values.insert("feed_release", Value::String(FEED_RELEASE.to_owned()));
        values.insert("generation_id", Value::String(self.generation_id.clone()));
        values.insert("import_contract", Value::String(IMPORT_CONTRACT.to_owned()));
        values.insert("manifest_schema_version", Value::from(1));
        values.insert("schema_version", Value::from(1));
        serde_json::to_string(&values)
            .map_err(|_| "feed generation database attestation serialization failed".to_owned())
    }
}

/// The narrow database primitive used by activation and rollback adapters.
pub(super) struct DatabaseAttestationAdapter<'a> {
    repo_root: &'a Path,
    runner: &'a dyn CommandRunner,
}

impl<'a> DatabaseAttestationAdapter<'a> {
    pub(super) fn new(repo_root: &'a Path, runner: &'a dyn CommandRunner) -> Self {
        Self { repo_root, runner }
    }

    pub(super) fn read(&self) -> Result<Option<DatabaseAttestation>, String> {
        let raw_hex = self.query_single_value(&read_query())?;
        let Some(raw_hex) = raw_hex else {
            return Ok(None);
        };
        if raw_hex == OVERSIZED {
            return Err("feed generation database attestation is oversized".into());
        }
        let raw = decode_hex(&raw_hex)?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| "feed generation database attestation encoding is invalid".to_owned())?;
        parse_attestation_json(text).map(Some)
    }

    pub(super) fn write(
        &self,
        generation_id: &str,
        completed_at: &str,
    ) -> Result<DatabaseAttestation, String> {
        let candidate = DatabaseAttestation::new(generation_id, completed_at)?;
        let encoded = candidate.canonical_json()?;
        if encoded.len() > MAX_BYTES {
            return Err("feed generation database attestation is oversized".into());
        }
        self.execute(&write_query(&encoded))?;
        let observed = self
            .read()?
            .ok_or_else(|| "feed generation database attestation readback mismatch".to_owned())?;
        if observed != candidate {
            return Err("feed generation database attestation readback mismatch".into());
        }
        Ok(candidate)
    }

    /// Runs a bounded PostgreSQL scalar query through the same credential-safe
    /// Compose boundary used for attestation reads and writes.
    pub(super) fn query_single_value(&self, sql: &str) -> Result<Option<String>, String> {
        psql_single_value(&self.execute(sql)?)
    }

    fn execute(&self, sql: &str) -> Result<String, String> {
        let environment = runtime_environment(self.repo_root);
        let user = environment
            .get(&OsString::from("POSTGRES_USER"))
            .and_then(|value| value.to_str())
            .ok_or_else(|| "PostgreSQL runtime user is invalid".to_owned())?;
        let password = environment
            .get(&OsString::from("POSTGRES_PASSWORD"))
            .and_then(|value| value.to_str())
            .ok_or_else(|| "PostgreSQL runtime password is invalid".to_owned())?;
        let database = environment
            .get(&OsString::from("POSTGRES_DB"))
            .and_then(|value| value.to_str())
            .ok_or_else(|| "PostgreSQL runtime database is invalid".to_owned())?;
        let compose = compose_command(
            self.repo_root,
            &[
                "exec".to_owned(),
                "-T".to_owned(),
                "postgres".to_owned(),
                "env".to_owned(),
                format!("PGPASSWORD={password}"),
                "psql".to_owned(),
                "-v".to_owned(),
                "ON_ERROR_STOP=1".to_owned(),
                "-U".to_owned(),
                user.to_owned(),
                "-d".to_owned(),
                database.to_owned(),
                "-At".to_owned(),
                "-c".to_owned(),
                sql.to_owned(),
            ],
        );
        let args = compose.iter().map(String::as_str).collect::<Vec<_>>();
        let output = self
            .runner
            .run_with(
                "docker",
                &args,
                Some(self.repo_root),
                Some(&environment),
                Some(Duration::from_secs(120)),
            )
            .ok_or_else(|| "feed generation database command could not be started".to_owned())?;
        if !output.success {
            // Process output can include a PostgreSQL connection string or other
            // runtime diagnostics. Do not expose it to a lifecycle caller.
            return Err("feed generation database command failed".into());
        }
        Ok(output.stdout)
    }
}

fn read_query() -> String {
    format!(
        "SELECT CASE WHEN octet_length(value) > {MAX_BYTES} THEN '{OVERSIZED}' ELSE COALESCE(encode(convert_to(value, 'UTF8'), 'hex'), '') END FROM public.meta WHERE name = {};",
        sql_literal(META_NAME),
    )
}

fn write_query(encoded: &str) -> String {
    format!(
        "INSERT INTO public.meta (name, value) VALUES ({}, {}) ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;",
        sql_literal(META_NAME),
        sql_literal(encoded),
    )
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn psql_single_value(output: &str) -> Result<Option<String>, String> {
    let values = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            !matches!(
                line.split_once(':').map(|(prefix, _)| prefix),
                Some("WARNING" | "DETAIL" | "HINT" | "NOTICE")
            )
        })
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some((*value).to_owned())),
        _ => Err("feed generation database attestation query returned multiple rows".into()),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() > MAX_BYTES * 2
        || !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err("feed generation database attestation encoding is invalid".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("feed generation database attestation encoding is invalid".into()),
    }
}

fn parse_attestation_json(value: &str) -> Result<DatabaseAttestation, String> {
    let StrictObject(values) = serde_json::from_str(value)
        .map_err(|_| "feed generation database attestation is not valid JSON".to_owned())?;
    validate_attestation_values(&values)
}

struct StrictObject(BTreeMap<String, Value>);

impl<'de> Deserialize<'de> for StrictObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictObjectVisitor;

        impl<'de> Visitor<'de> for StrictObjectVisitor {
            type Value = StrictObject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with no duplicate keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(A::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                }
                Ok(StrictObject(values))
            }
        }

        deserializer.deserialize_map(StrictObjectVisitor)
    }
}

fn validate_attestation_values(
    values: &BTreeMap<String, Value>,
) -> Result<DatabaseAttestation, String> {
    const KEYS: [&str; 6] = [
        "schema_version",
        "generation_id",
        "feed_release",
        "manifest_schema_version",
        "import_contract",
        "completed_at",
    ];
    if values.len() != KEYS.len() || KEYS.iter().any(|key| !values.contains_key(*key)) {
        return Err("feed generation database attestation is invalid".into());
    }
    if values.get("schema_version").and_then(Value::as_u64) != Some(1)
        || values
            .get("manifest_schema_version")
            .and_then(Value::as_u64)
            != Some(1)
        || values.get("feed_release").and_then(Value::as_str) != Some(FEED_RELEASE)
        || values.get("import_contract").and_then(Value::as_str) != Some(IMPORT_CONTRACT)
    {
        return Err("feed generation database attestation is invalid".into());
    }
    let generation_id = values
        .get("generation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "feed generation database attestation is invalid".to_owned())?;
    let completed_at = values
        .get("completed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| "feed generation database attestation timestamp is invalid".to_owned())?;
    DatabaseAttestation::new(generation_id, completed_at)
}

fn validate_generation_id(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("feed generation database attestation is invalid".into())
    }
}

fn validate_completed_at(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let valid = bytes.len() >= 20
        && decimal(bytes, 0, 4)
        && bytes.get(4) == Some(&b'-')
        && decimal(bytes, 5, 2)
        && bytes.get(7) == Some(&b'-')
        && decimal(bytes, 8, 2)
        && matches!(bytes.get(10), Some(b'T'))
        && decimal(bytes, 11, 2)
        && bytes.get(13) == Some(&b':')
        && decimal(bytes, 14, 2)
        && bytes.get(16) == Some(&b':')
        && decimal(bytes, 17, 2)
        && valid_date(bytes)
        && number(bytes, 11, 2) < 24
        && number(bytes, 14, 2) < 60
        && number(bytes, 17, 2) < 60
        && valid_fraction_and_utc_offset(bytes, 19);
    valid
        .then_some(())
        .ok_or_else(|| "feed generation database attestation timestamp is invalid".to_owned())
}

fn valid_fraction_and_utc_offset(bytes: &[u8], mut position: usize) -> bool {
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        let start = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        if position == start {
            return false;
        }
    }
    matches!(
        bytes.get(position..),
        Some(b"Z") | Some(b"+00:00" | b"-00:00")
    )
}

fn valid_date(bytes: &[u8]) -> bool {
    let year = number(bytes, 0, 4);
    let month = number(bytes, 5, 2);
    let day = number(bytes, 8, 2);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    };
    year != 0 && (1..=days).contains(&day)
}

fn decimal(bytes: &[u8], start: usize, width: usize) -> bool {
    bytes
        .get(start..start + width)
        .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit))
}

fn number(bytes: &[u8], start: usize, width: usize) -> u32 {
    bytes[start..start + width]
        .iter()
        .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
}
