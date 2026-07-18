// SPDX-FileCopyrightText: 2023 Greenbone AG
// TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::BTreeMap;
use std::fmt::Debug;

use std::str::FromStr;

use super::dberror::DbError;
use super::dberror::RedisStorageResult;
use itertools::Itertools;
use redis::*;

use crate::notus::advisories::Vulnerability;
use crate::notus::advisories::VulnerabilityData;
use crate::storage::StorageError;
use crate::storage::items::nvt;
use crate::storage::items::nvt::ACT;
use crate::storage::items::nvt::NvtKey;
use crate::storage::items::nvt::NvtPreference;
use crate::storage::items::nvt::NvtRef;
use crate::storage::items::nvt::TagKey;
use crate::storage::items::nvt::TagValue;
use greenbone_scanner_framework::models::VTData;

enum KbNvtPos {
    Filename,
    RequiredKeys,
    MandatoryKeys,
    ExcludedKeys,
    RequiredUDPPorts,
    RequiredPorts,
    Dependencies,
    Tags,
    Cves,
    Bids,
    Xrefs,
    Category,
    Family,
    Name,
}

impl TryFrom<NvtKey> for KbNvtPos {
    type Error = StorageError;

    fn try_from(value: NvtKey) -> Result<Self, Self::Error> {
        Ok(match value {
            NvtKey::FileName => Self::Filename,
            NvtKey::Name => Self::Name,
            NvtKey::Dependencies => Self::Dependencies,
            NvtKey::RequiredKeys => Self::RequiredKeys,
            NvtKey::MandatoryKeys => Self::MandatoryKeys,
            NvtKey::ExcludedKeys => Self::ExcludedKeys,
            NvtKey::RequiredPorts => Self::RequiredPorts,
            NvtKey::RequiredUdpPorts => Self::RequiredUDPPorts,
            NvtKey::Category => Self::Category,
            NvtKey::Family => Self::Family,
            // tags must also be handled manually due to differentiation
            _ => {
                return Err(StorageError::UnexpectedData(format!(
                    "{value:?} is not a redis position and must be handled differently"
                )));
            }
        })
    }
}
#[derive(Default)]
pub struct RedisCtx {
    kb: Option<Connection>, //a redis connection
    pub db: u32,            // the name space
    owner_token: Option<String>,
}

impl Debug for RedisCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Redis connection. Db {}", self.db)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RedisValueHandler {
    v: String,
}

impl FromRedisValue for RedisValueHandler {
    fn from_redis_value(v: &Value) -> redis::RedisResult<RedisValueHandler> {
        match v {
            Value::Nil => Ok(RedisValueHandler { v: String::new() }),
            _ => {
                let new_var: String = from_redis_value(v).unwrap_or_default();
                Ok(RedisValueHandler { v: new_var })
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
/// Defines how the RedixCtx should select the namespace
pub enum NameSpaceSelector {
    /// Selects an exact DB only while its original owner token still matches.
    Owned(u32, String),
    /// Next free
    Free,
    /// Uses a DB that contains this key
    Key(&'static str),
}

pub const CACHE_KEY: &str = "nvticache";
pub const NOTUS_KEY: &str = "notuscache";
const DB_INDEX: &str = "GVM.__GlobalDBIndex";
const NAMESPACE_RELEASE_ATTEMPTS: usize = 3;

enum NamespaceReleaseOutcome {
    Released,
    Retry,
    OwnerMismatch,
}

impl NameSpaceSelector {
    fn max_db(kb: &mut redis::Connection) -> RedisStorageResult<u32> {
        Cmd::new()
            .arg("CONFIG")
            .arg("GET")
            .arg("databases")
            .query::<(String, u32)>(kb)
            .map(|(_, max_db)| max_db)
            .map_err(|e| e.into())
    }

    fn select_namespace(kb: &mut redis::Connection, idx: u32) -> RedisStorageResult<()> {
        Cmd::new()
            .arg("SELECT")
            .arg(idx)
            .query(kb)
            .map_err(|e| e.into())
    }

    fn owner_token(kb: &mut redis::Connection, dbi: u32) -> RedisStorageResult<Option<String>> {
        Self::select_namespace(kb, 0)?;
        let owner_token = redis::Commands::hget(kb, DB_INDEX, dbi)?;
        Self::select_namespace(kb, dbi)?;
        Ok(owner_token)
    }

    fn select_owned_namespace(
        kb: &mut redis::Connection,
        dbi: u32,
        expected_owner: &str,
    ) -> RedisStorageResult<()> {
        for _ in 0..NAMESPACE_RELEASE_ATTEMPTS {
            Self::select_namespace(kb, 0)?;
            Cmd::new().arg("WATCH").arg(DB_INDEX).query::<()>(kb)?;
            let indexed_owner: Option<String> = match redis::Commands::hget(kb, DB_INDEX, dbi) {
                Ok(owner) => owner,
                Err(error) => {
                    let _ = Cmd::new().arg("UNWATCH").query::<()>(kb);
                    return Err(error.into());
                }
            };
            if indexed_owner.as_deref() != Some(expected_owner) {
                Cmd::new().arg("UNWATCH").query::<()>(kb)?;
                return Err(DbError::LibraryError(format!(
                    "Redis DB {dbi} owner changed before reconnect"
                )));
            }

            let result: Value = redis::pipe().atomic().cmd("SELECT").arg(dbi).query(kb)?;
            if !matches!(result, Value::Nil) {
                return Ok(());
            }
        }

        Err(DbError::Retry(format!(
            "Redis DB {dbi} reconnect transaction aborted too many times"
        )))
    }

    fn select(&self, kb: &mut redis::Connection) -> RedisStorageResult<(u32, Option<String>)> {
        let max_db = Self::max_db(kb)?;
        match self {
            NameSpaceSelector::Owned(dbi, expected_owner) => {
                Self::select_owned_namespace(kb, *dbi, expected_owner)?;
                Ok((*dbi, Some(expected_owner.clone())))
            }
            NameSpaceSelector::Free => {
                Self::select_namespace(kb, 0)?;
                let owner_token = uuid::Uuid::new_v4().to_string();
                for dbi in 1..max_db {
                    match redis::Commands::hset_nx(kb, DB_INDEX, dbi, &owner_token) {
                        Ok(1) => {
                            Self::select_namespace(kb, dbi)?;
                            return Ok((dbi, Some(owner_token)));
                        }
                        Ok(_) => {}
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(DbError::NoAvailDbErr)
            }
            NameSpaceSelector::Key(key) => {
                for dbi in 1..max_db {
                    Self::select_namespace(kb, dbi)?;
                    match redis::Commands::exists(kb, key) {
                        Ok(1) => return Ok((dbi, Self::owner_token(kb, dbi)?)),
                        Ok(_) => {}
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(DbError::NoAvailDbErr)
            }
        }
    }
}

/// Default selector for a feed-update run
pub const FEEDUPDATE_SELECTOR: &[NameSpaceSelector] =
    &[NameSpaceSelector::Key(CACHE_KEY), NameSpaceSelector::Free];
pub const NOTUSUPDATE_SELECTOR: &[NameSpaceSelector] =
    &[NameSpaceSelector::Key(NOTUS_KEY), NameSpaceSelector::Free];

pub trait RedisWrapper {
    fn rpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()>;
    fn lpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()>;
    fn del(&mut self, key: &str) -> RedisStorageResult<()>;
    fn lindex(&mut self, key: &str, index: isize) -> RedisStorageResult<String>;
    fn lrange(&mut self, key: &str, start: isize, end: isize) -> RedisStorageResult<Vec<String>>;
    fn keys(&mut self, pattern: &str) -> RedisStorageResult<Vec<String>>;
    fn pop(&mut self, pattern: &str) -> RedisStorageResult<Vec<String>>;
}

impl RedisWrapper for RedisCtx {
    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn rpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
        redis::Commands::rpush(self.kb.as_mut().expect("Valid redis connection"), key, val)
            .map_err(DbError::from)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
        redis::Commands::lpush(self.kb.as_mut().expect("Valid redis connection"), key, val)
            .map_err(DbError::from)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn del(&mut self, key: &str) -> RedisStorageResult<()> {
        redis::Commands::del(self.kb.as_mut().expect("Valid redis connection"), key)
            .map_err(DbError::from)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lindex(&mut self, key: &str, index: isize) -> RedisStorageResult<String> {
        let ret: RedisValueHandler = redis::Commands::lindex(
            self.kb.as_mut().expect("Valid redis connection"),
            key,
            index,
        )
        .map_err(DbError::from)?;
        Ok(ret.v)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lrange(&mut self, key: &str, start: isize, end: isize) -> RedisStorageResult<Vec<String>> {
        let ret = redis::Commands::lrange(
            self.kb.as_mut().expect("Valid redis connection"),
            key,
            start,
            end,
        )
        .map_err(DbError::from)?;
        Ok(ret)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn keys(&mut self, pattern: &str) -> RedisStorageResult<Vec<String>> {
        let ret: Vec<String> =
            redis::Commands::keys(self.kb.as_mut().expect("Valid redis connection"), pattern)
                .map_err(DbError::from)?;
        Ok(ret)
    }

    fn pop(&mut self, key: &str) -> RedisStorageResult<Vec<String>> {
        let ret: (Vec<String>,) = redis::pipe()
            .cmd("LRANGE")
            .arg(key)
            .arg("0")
            .arg("-1")
            .cmd("DEL")
            .arg(key)
            .ignore()
            .query(&mut self.kb.as_mut().unwrap())
            .unwrap();
        // Since items are lpushed, the returned vector must be reversed to keep the order.
        let mut status = ret.0;
        status.reverse();

        Ok(status)
    }
}

pub trait RedisAddAdvisory: RedisWrapper {
    /// Add an NVT in the redis cache.
    ///
    /// The NVT metadata is stored in two different keys:
    ///
    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    ///
    /// To call with None is only required when using ospd-openvas and updating the feed into
    /// redis.
    fn redis_add_advisory(&mut self, adv: Option<VulnerabilityData>) -> RedisStorageResult<()> {
        match adv {
            Some(data) => {
                let key = format!("internal/notus/advisories/{}", &data.adv.oid);
                let value = Vulnerability::from(data);
                let value = serde_json::to_string(&value)
                    .map_err(|e| DbError::Unknown(format!("Serialization error: {e}")))?;
                self.rpush(&key, value)?;
            }
            None => self.rpush(NOTUS_KEY, "1".to_string())?,
        };
        Ok(())
    }
}

impl RedisAddAdvisory for RedisCtx {}

pub trait RedisGetNvt: RedisWrapper {
    #[inline(always)]
    fn get_refs(bids: &str, cves: &str, xrefs: &str) -> Vec<NvtRef> {
        let f = |x: &str| match x.split_once(':') {
            Some((a, b)) => NvtRef::from((a, b)),
            None => NvtRef::from(("", "")),
        };
        let mut bid_refs: Vec<NvtRef> =
            bids.split(", ").map(|r| NvtRef::from(("bid", r))).collect();
        let mut cve_refs: Vec<NvtRef> =
            cves.split(", ").map(|r| NvtRef::from(("cve", r))).collect();
        let mut xrefs_refs = xrefs.split(", ").map(f).collect();

        let mut refs: Vec<NvtRef> = Vec::new();
        refs.append(&mut bid_refs);
        refs.append(&mut cve_refs);
        refs.append(&mut xrefs_refs);
        refs
    }

    #[inline(always)]
    fn get_prefs(&mut self, oid: &str) -> RedisStorageResult<Vec<NvtPreference>> {
        let keyname = format!("oid:{oid}:prefs");
        let mut prefs_list = self.lrange(&keyname, 0, -1)?;
        let mut prefs: Vec<NvtPreference> = Vec::new();
        for p in prefs_list.iter_mut() {
            if let Some(sp) = p
                .splitn(4, "|||")
                .collect_tuple::<(&str, &str, &str, &str)>()
            {
                prefs.push(NvtPreference::from(sp));
            }
        }
        Ok(prefs)
    }

    #[inline(always)]
    fn get_tags(tags: &str) -> BTreeMap<TagKey, TagValue> {
        let mut tag_map = BTreeMap::new();

        let tag_list = tags.split('|').map(|x| {
            x.splitn(2, '=')
                .collect_tuple::<(&str, &str)>()
                .unwrap_or_default()
        });

        for (k, v) in tag_list.into_iter() {
            if let Ok(tk) = TagKey::from_str(k) {
                match tk {
                    TagKey::CreationDate | TagKey::LastModification | TagKey::SeverityDate => {
                        tag_map.insert(
                            tk,
                            TagValue::from(i64::from_str(v).expect("Valid timestamp")),
                        )
                    }
                    _ => tag_map.insert(tk, TagValue::from(v)),
                };
            }
        }

        tag_map
    }

    fn redis_get_advisory(&mut self, oid: &str) -> RedisStorageResult<Option<VTData>> {
        let keyname = format!("internal/notus/advisories/{oid}");
        let nvt_data = self.lindex(&keyname, 0)?;
        if nvt_data.is_empty() {
            return Ok(None);
        }

        if let Ok(adv) = serde_json::from_str::<Vulnerability>(&nvt_data) {
            Ok(Some(nvt::Nvt::from((oid, adv)).data))
        } else {
            Ok(None)
        }
    }
    /// Nvt metadata is stored under two different keys
    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    fn redis_get_vt(&mut self, oid: &str) -> RedisStorageResult<Option<VTData>> {
        let keyname = format!("nvt:{oid}");
        let nvt_data = self.lrange(&keyname, 0, -1)?;

        if nvt_data.is_empty() {
            return Ok(None);
        }

        let nvt = VTData {
            oid: oid.to_string(),
            name: nvt_data[KbNvtPos::Name as usize].clone(),
            filename: nvt_data[KbNvtPos::Filename as usize].clone(),
            tag: Self::get_tags(&nvt_data[KbNvtPos::Tags as usize].clone()),
            dependencies: nvt_data[KbNvtPos::Dependencies as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            required_keys: nvt_data[KbNvtPos::RequiredKeys as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            mandatory_keys: nvt_data[KbNvtPos::MandatoryKeys as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            excluded_keys: nvt_data[KbNvtPos::ExcludedKeys as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            required_ports: nvt_data[KbNvtPos::RequiredPorts as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            required_udp_ports: nvt_data[KbNvtPos::RequiredUDPPorts as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            references: Self::get_refs(
                &nvt_data[KbNvtPos::Bids as usize].clone(),
                &nvt_data[KbNvtPos::Cves as usize].clone(),
                &nvt_data[KbNvtPos::Xrefs as usize].clone(),
            ),
            preferences: Self::get_prefs(self, oid)?,
            category: {
                match ACT::from_str(&nvt_data[KbNvtPos::Category as usize]) {
                    Ok(c) => c,
                    Err(_) => return Err(DbError::Unknown("Invalid nvt category".to_string())),
                }
            },
            family: nvt_data[KbNvtPos::Family as usize].clone(),
        };

        Ok(Some(nvt))
    }
}

impl RedisGetNvt for RedisCtx {}

pub trait RedisAddNvt: RedisWrapper {
    /// Get References. It returns a tuple of three strings
    /// Each string is a references type, and each string
    /// can contain a list of references of the same type.
    /// The string contains in the following types:
    /// (cve_types, bid_types, other_types)
    /// cve and bid strings are CSC strings containing only
    /// "id, id, ...", while other custom types includes the type
    /// and the string is in the format "type:id, type:id, ..."
    #[inline(always)]
    fn refs(references: &[NvtRef]) -> (String, String, String) {
        let (bids, cves, xrefs): (Vec<String>, Vec<String>, Vec<String>) =
            references
                .iter()
                .fold((vec![], vec![], vec![]), |(bids, cves, xrefs), b| {
                    match b.class() {
                        "bid" => {
                            let mut new_bids = bids;
                            new_bids.push(b.id().to_string());
                            (new_bids, cves, xrefs)
                        }
                        "cve" => {
                            let mut new_cves = cves;
                            new_cves.push(b.id().to_string());
                            (bids, new_cves, xrefs)
                        }
                        _ => {
                            let mut new_xref: Vec<String> = xrefs;
                            new_xref.push(format!("{}:{}", b.class(), b.id()));
                            (bids, cves, new_xref)
                        }
                    }
                });

        // Some references include a comma. Therefore the refs separator is ", ".
        // The string ", " is not accepted as reference value, since it will misunderstood
        // as ref separator.

        (
            cves.iter().as_ref().join(", "),
            bids.iter().as_ref().join(", "),
            xrefs.iter().as_ref().join(", "),
        )
    }

    /// Transforms prefs to string representation {id}:{name}:{id}:{default} so that it can be stored into redis
    #[inline(always)]
    fn prefs(preferences: &[NvtPreference]) -> Vec<String> {
        let mut prefs = Vec::from(preferences);
        prefs.sort_by_key(|b| std::cmp::Reverse(b.id.unwrap_or_default()));
        let results: Vec<String> = prefs
            .iter()
            .map(|pref| {
                format!(
                    "{}|||{}|||{}|||{}",
                    pref.id().unwrap_or_default(),
                    pref.name(),
                    pref.class().as_ref(),
                    pref.default()
                )
            })
            .collect();
        results
    }

    /// Add an NVT in the redis cache.
    ///
    /// The NVT metadata is stored in two different keys:
    ///
    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    fn redis_add_nvt(&mut self, nvt: VTData) -> RedisStorageResult<()> {
        let oid = nvt.oid;
        let name = nvt.name;
        let required_keys = nvt.required_keys.join(", ");
        let mandatory_keys = nvt.mandatory_keys.join(", ");
        let excluded_keys = nvt.excluded_keys.join(", ");
        let required_udp_ports = nvt.required_udp_ports.join(", ");
        let required_ports = nvt.required_ports.join(", ");
        let dependencies = nvt.dependencies.join(", ");
        let tags = nvt
            .tag
            .iter()
            .map(|(key, val)| format!("{key}={val}"))
            .collect::<Vec<String>>()
            .join("|");
        let category = (nvt.category as i64).to_string();
        let family = nvt.family;
        let filename = nvt.filename;

        // Get the references
        let (cves, bids, xrefs) = Self::refs(&nvt.references);

        let key_name = format!("nvt:{oid}");
        let values = [
            &filename,
            &required_keys,
            &mandatory_keys,
            &excluded_keys,
            &required_udp_ports,
            &required_ports,
            &dependencies,
            &tags,
            &cves,
            &bids,
            &xrefs,
            &category,
            &family,
            &name,
        ];
        self.del(&key_name)?;
        self.rpush(&key_name, &values)?;

        // Add preferences
        let prefs = Self::prefs(&nvt.preferences);
        if !prefs.is_empty() {
            let key_name = format!("oid:{oid}:prefs");
            self.del(&key_name)?;
            self.lpush(&key_name, prefs)?;
            //self.kb.lpush(&key_name, prefs)?;
        }

        // Stores the OID under the filename key. This key is currently used
        // for the dependency autoload, where the filename is used to fetch the OID.
        //
        // TODO: since openvas get the oid by position and it is stored in the second position,
        // for backward compatibility a dummy item (it is the plugin's upload timestamp)
        // under the filename key is added.
        // Once openvas is no longer used, the dummy item can be removed.
        let key_name = format!("filename:{filename}");
        self.rpush(&key_name, &["1", &oid])?;
        Ok(())
    }
}

impl RedisAddNvt for RedisCtx {}

impl RedisCtx {
    pub fn owner_token(&self) -> Option<&str> {
        self.owner_token.as_deref()
    }

    fn invalidate_namespace(&mut self) {
        self.db = 0;
        self.owner_token = None;
    }

    fn release_namespace_attempt(
        kb: &mut Connection,
        db: u32,
        owner_token: &str,
    ) -> RedisStorageResult<NamespaceReleaseOutcome> {
        NameSpaceSelector::select_namespace(kb, 0)?;
        Cmd::new().arg("WATCH").arg(DB_INDEX).query::<()>(kb)?;

        let indexed_owner: Option<String> = match redis::Commands::hget(kb, DB_INDEX, db) {
            Ok(owner) => owner,
            Err(error) => {
                let _ = Cmd::new().arg("UNWATCH").query::<()>(kb);
                return Err(error.into());
            }
        };
        if indexed_owner.as_deref() != Some(owner_token) {
            Cmd::new().arg("UNWATCH").query::<()>(kb)?;
            return Ok(NamespaceReleaseOutcome::OwnerMismatch);
        }

        let result: Value = redis::pipe()
            .atomic()
            .cmd("SELECT")
            .arg(db)
            .ignore()
            .cmd("FLUSHDB")
            .ignore()
            .cmd("SELECT")
            .arg(0)
            .ignore()
            .cmd("HDEL")
            .arg(DB_INDEX)
            .arg(db)
            .ignore()
            .query(kb)?;

        if matches!(result, Value::Nil) {
            Ok(NamespaceReleaseOutcome::Retry)
        } else {
            Ok(NamespaceReleaseOutcome::Released)
        }
    }

    pub fn open(address: &str, selector: &[NameSpaceSelector]) -> RedisStorageResult<Self> {
        let client = redis::Client::open(address)?;

        let mut kb = client.get_connection()?;
        for s in selector {
            match s.select(&mut kb) {
                Ok((db, owner_token)) => {
                    return Ok(RedisCtx {
                        kb: Some(kb),
                        db,
                        owner_token,
                    });
                }
                Err(DbError::NoAvailDbErr) => {}
                Err(x) => return Err(x),
            }
        }
        Err(DbError::NoAvailDbErr)
    }

    /// Delete all keys in the namespace, release it, and fence this context in DB 0.
    pub fn delete_namespace(&mut self) -> RedisStorageResult<()> {
        let owner_token = self.owner_token.clone().ok_or_else(|| {
            DbError::LibraryError(format!(
                "Redis DB {} has no owner token and cannot be released",
                self.db
            ))
        })?;
        let db = self.db;

        for _ in 0..NAMESPACE_RELEASE_ATTEMPTS {
            let outcome = {
                let kb = self.kb.as_mut().expect("Valid redis connection");
                Self::release_namespace_attempt(kb, db, &owner_token)
            };
            match outcome {
                Ok(NamespaceReleaseOutcome::Released) => {
                    self.invalidate_namespace();
                    return Ok(());
                }
                Ok(NamespaceReleaseOutcome::Retry) => {}
                Ok(NamespaceReleaseOutcome::OwnerMismatch) => {
                    self.invalidate_namespace();
                    return Err(DbError::LibraryError(format!(
                        "Redis DB {db} owner changed before cleanup"
                    )));
                }
                Err(error) => {
                    self.kb = None;
                    self.invalidate_namespace();
                    return Err(error);
                }
            }
        }

        self.kb = None;
        self.invalidate_namespace();
        Err(DbError::Retry(format!(
            "Redis DB {db} cleanup transaction aborted too many times"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{DB_INDEX, NameSpaceSelector, RedisCtx};

    #[test]
    fn invalidating_namespace_fences_the_connection_in_db_zero() {
        let mut ctx = RedisCtx {
            kb: None,
            db: 3,
            owner_token: Some("owner".to_string()),
        };

        ctx.invalidate_namespace();

        assert_eq!(ctx.db, 0);
        assert_eq!(ctx.owner_token, None);
    }

    #[test]
    #[ignore = "requires YAFVS_TEST_REDIS_URL pointing to a disposable Redis"]
    fn stale_owned_selector_cannot_adopt_replacement_namespace() {
        assert_eq!(
            std::env::var("YAFVS_TEST_REDIS_DEDICATED").as_deref(),
            Ok("1"),
            "refusing to modify a Redis instance not marked disposable"
        );
        let address = std::env::var("YAFVS_TEST_REDIS_URL")
            .expect("YAFVS_TEST_REDIS_URL must name the disposable Redis");
        let client = redis::Client::open(address.as_str()).expect("valid Redis URL");
        let mut connection = client
            .get_connection()
            .expect("connect to disposable Redis");
        redis::cmd("FLUSHALL")
            .query::<()>(&mut connection)
            .expect("reset disposable Redis");

        let owner_a = "11111111-1111-4111-8111-111111111111";
        let owner_b = "22222222-2222-4222-8222-222222222222";
        redis::cmd("HSET")
            .arg(DB_INDEX)
            .arg(3)
            .arg(owner_a)
            .query::<()>(&mut connection)
            .expect("reserve owner A");
        redis::cmd("SELECT")
            .arg(3)
            .query::<()>(&mut connection)
            .expect("select test namespace");
        redis::cmd("SET")
            .arg("sentinel")
            .arg("replacement-owner-data")
            .query::<()>(&mut connection)
            .expect("seed replacement data");
        redis::cmd("SELECT")
            .arg(0)
            .query::<()>(&mut connection)
            .expect("select management namespace");
        redis::cmd("HSET")
            .arg(DB_INDEX)
            .arg(3)
            .arg(owner_b)
            .query::<()>(&mut connection)
            .expect("replace owner token");

        assert!(
            RedisCtx::open(
                address.as_str(),
                &[NameSpaceSelector::Owned(3, owner_a.to_string())]
            )
            .is_err(),
            "stale owner unexpectedly reconnected"
        );
        redis::cmd("SELECT")
            .arg(3)
            .query::<()>(&mut connection)
            .expect("reselect test namespace");
        let sentinel: String = redis::cmd("GET")
            .arg("sentinel")
            .query(&mut connection)
            .expect("read replacement data");
        assert_eq!(sentinel, "replacement-owner-data");
        redis::cmd("SELECT")
            .arg(0)
            .query::<()>(&mut connection)
            .expect("reselect management namespace");
        let indexed_owner: String = redis::cmd("HGET")
            .arg(DB_INDEX)
            .arg(3)
            .query(&mut connection)
            .expect("read replacement owner");
        assert_eq!(indexed_owner, owner_b);

        redis::cmd("FLUSHALL")
            .query::<()>(&mut connection)
            .expect("clean disposable Redis");
    }
}
