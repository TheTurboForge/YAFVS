// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::process::CommandRunner;
use crate::result::{Finding, Metadata};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use time::OffsetDateTime;
use time::format_description;
use time::format_description::well_known::Rfc3339;

pub(crate) fn run_git(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    args: &[&str],
) -> Option<String> {
    let root = repo_root.to_string_lossy();
    let mut git_args = vec!["-C", root.as_ref()];
    git_args.extend_from_slice(args);
    runner
        .run("git", &git_args)
        .and_then(|output| output.success.then(|| output.stdout.trim().to_string()))
}

pub(crate) fn ensure_real_directory_tree(root: &Path, relative: &Path) -> std::io::Result<PathBuf> {
    let root_metadata = std::fs::symlink_metadata(root)?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("directory root is not a real directory: {}", root.display()),
        ));
    }
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "directory descendant is not a safe relative path: {}",
                    relative.display()
                ),
            ));
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "directory descendant is not a real directory: {}",
                        current.display()
                    ),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)?;
                let metadata = std::fs::symlink_metadata(&current)?;
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "created directory descendant is unsafe: {}",
                            current.display()
                        ),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(current)
}

pub(crate) fn executable_path(program: &str) -> Option<PathBuf> {
    let candidate = Path::new(program);
    if candidate.components().count() > 1 {
        return is_executable(candidate).then(|| candidate.to_path_buf());
    }
    env::split_paths(&env::var_os("PATH")?)
        .map(|directory| directory.join(program))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    path.is_file()
        && path
            .metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

pub(crate) fn output_tail(output: &str, lines: usize) -> Vec<String> {
    let rows = output.lines().collect::<Vec<_>>();
    rows[rows.len().saturating_sub(lines)..]
        .iter()
        .map(|line| (*line).to_string())
        .collect()
}

pub(crate) fn build_env(repo_root: &Path) -> BTreeMap<OsString, OsString> {
    let mut environment = env::vars_os().collect::<BTreeMap<_, _>>();
    let prefix = repo_root.join("build/prefix");
    let current_pkg = environment.get(&OsString::from("PKG_CONFIG_PATH"));
    let mut pkg_paths = vec![
        prefix.join("lib/pkgconfig").display().to_string(),
        prefix.join("lib64/pkgconfig").display().to_string(),
    ];
    if let Some(current) = current_pkg.and_then(|value| value.to_str())
        && !current.is_empty()
    {
        pkg_paths.push(current.to_string());
    }
    environment.insert(
        OsString::from("PKG_CONFIG_PATH"),
        OsString::from(pkg_paths.join(":")),
    );
    environment.insert(
        OsString::from("CMAKE_PREFIX_PATH"),
        OsString::from(prefix.display().to_string()),
    );
    let current_ld = environment.get(&OsString::from("LD_LIBRARY_PATH"));
    let mut ld_paths = vec![
        prefix.join("lib").display().to_string(),
        prefix.join("lib64").display().to_string(),
    ];
    if let Some(current) = current_ld.and_then(|value| value.to_str())
        && !current.is_empty()
    {
        ld_paths.push(current.to_string());
    }
    environment.insert(
        OsString::from("LD_LIBRARY_PATH"),
        OsString::from(ld_paths.join(":")),
    );
    environment
}

pub(crate) fn iso_system_time(timestamp: SystemTime) -> Option<String> {
    let timestamp = OffsetDateTime::from(timestamp);
    let format = format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]T[hour]:[minute]:[second]+00:00",
    )
    .ok()?;
    timestamp.format(&format).ok()
}

pub(crate) fn runtime_dir(repo_root: &Path) -> PathBuf {
    let configured = env::var_os("YAFVS_RUNTIME_DIR").map(PathBuf::from);
    let path = configured.map(expand_home).unwrap_or_else(|| {
        repo_root
            .parent()
            .unwrap_or(repo_root)
            .join("YAFVS-runtime")
    });
    let absolute = if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .unwrap_or_else(|_| repo_root.to_path_buf())
            .join(path)
    };
    absolute.canonicalize().unwrap_or(absolute)
}

pub(crate) fn expand_home(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    if text == "~" {
        return env::var_os("HOME").map(PathBuf::from).unwrap_or(path);
    }
    let Some(remainder) = text.strip_prefix("~/") else {
        return path;
    };
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(remainder))
        .unwrap_or(path)
}

pub(crate) fn compact_finding(finding: &Finding) -> Finding {
    let mut compact = Finding::new(&finding.status, &finding.check, finding.message.clone());
    if let Some(path) = &finding.path
        && !path.is_empty()
    {
        compact.path = Some(path.clone());
    }
    if let Some(Value::Object(details)) = &finding.details {
        let compact_details = details
            .iter()
            .map(|(key, value)| {
                let value = match value {
                    Value::Array(items) => json!({ "type": "list", "count": items.len() }),
                    Value::Object(items) => {
                        json!({ "type": "object", "key_count": items.len() })
                    }
                    scalar => scalar.clone(),
                };
                (key.clone(), value)
            })
            .collect();
        compact.details = Some(Value::Object(compact_details));
    }
    compact
}

pub(crate) fn git_tracked_files(
    runner: &dyn CommandRunner,
    repo_root: &Path,
) -> Option<Vec<String>> {
    run_git(runner, repo_root, &["ls-files", "-z"]).map(|output| {
        let mut paths = output
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        paths.sort();
        paths
    })
}

pub(crate) fn metadata(repo_root: &Path, command: &str, runner: &dyn CommandRunner) -> Metadata {
    Metadata {
        command: command.to_string(),
        generated_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        repo_root: repo_root.display().to_string(),
        head: run_git(runner, repo_root, &["rev-parse", "--short", "HEAD"]),
    }
}
