// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{executable_path, metadata, run_git, runtime_dir};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use glob::glob;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const EXPECTED_ARTIFACT_COUNT: usize = 20;
const RETAINED_ARTIFACTS: usize = 30;
const COMPONENTS: [&str; 6] = [
    "gvm-libs",
    "openvas-smb",
    "openvas-scanner",
    "pg-gvm",
    "gvmd",
    "gsad",
];
const RETIRED_PREFIX_ARTIFACTS: [&str; 6] = [
    "include/gvm/agent_controller",
    "include/gvm/container_image_scanner",
    "lib/libgvm_agent_controller.so*",
    "lib/libgvm_container_image_scanner.so*",
    "lib/pkgconfig/libgvm_agent_controller.pc",
    "lib/pkgconfig/libgvm_container_image_scanner.pc",
];
const HARDENED_CONFIGURATION: &str = "build/hardened/hardening-configuration.json";
const HARDENED_CMAKE_INJECTION: &str = "build/hardened/turbovas-hardening.cmake";
const HARDENED_BUILD_MANIFEST: &str = "build/hardened/hardening-manifest.json";
static NEXT_MANIFEST_TEMP: AtomicU64 = AtomicU64::new(0);

const GVM_LIBS: [&str; 9] = [
    "build/gvm-libs/base/libgvm_base.so.*",
    "build/gvm-libs/boreas/libgvm_boreas.so.*",
    "build/gvm-libs/gmp/libgvm_gmp.so.*",
    "build/gvm-libs/http/libgvm_http.so.*",
    "build/gvm-libs/http_scanner/libgvm_http_scanner.so.*",
    "build/gvm-libs/openvasd/libgvm_openvasd.so.*",
    "build/gvm-libs/osp/libgvm_osp.so.*",
    "build/gvm-libs/security_intelligence/libgvm_security_intelligence.so.*",
    "build/gvm-libs/util/libgvm_util.so.*",
];
const OPENVAS_SMB: [&str; 2] = [
    "build/openvas-smb/wmi/wmic",
    "build/openvas-smb/wmi/libopenvas_wmiclient.so.*",
];
const OPENVAS_SCANNER: [&str; 5] = [
    "build/openvas-scanner/src/openvas",
    "build/openvas-scanner/misc/libopenvas_misc.so.*",
    "build/openvas-scanner/nasl/libopenvas_nasl.so.*",
    "build/openvas-scanner/nasl/openvas-nasl",
    "build/openvas-scanner/nasl/openvas-nasl-lint",
];
const PG_GVM: [&str; 1] = ["build/pg-gvm/libpg-gvm.so"];
const GVMD: [&str; 2] = [
    "build/gvmd/src/gvmd",
    "build/gvmd/src/libgvm-pg-server.so.*",
];
const GSAD: [&str; 1] = ["build/gsad/src/gsad"];

fn specs() -> [(&'static str, &'static [&'static str]); 6] {
    [
        ("gvm-libs", &GVM_LIBS),
        ("openvas-smb", &OPENVAS_SMB),
        ("openvas-scanner", &OPENVAS_SCANNER),
        ("pg-gvm", &PG_GVM),
        ("gvmd", &GVMD),
        ("gsad", &GSAD),
    ]
}

fn profile_pattern(pattern: &str, profile: Option<&str>) -> String {
    profile
        .map(|profile| pattern.replacen("build/", &format!("build/{profile}/"), 1))
        .unwrap_or_else(|| pattern.to_string())
}

fn build_root(repo_root: &Path, profile: Option<&str>) -> PathBuf {
    profile
        .map(|profile| repo_root.join("build").join(profile))
        .unwrap_or_else(|| repo_root.join("build"))
}

fn glob_paths(repo_root: &Path, pattern: &str) -> Vec<PathBuf> {
    let Some(pattern) = repo_root.join(pattern).to_str().map(str::to_string) else {
        return Vec::new();
    };
    let Ok(paths) = glob(&pattern) else {
        return Vec::new();
    };
    let mut paths = paths.filter_map(Result::ok).collect::<Vec<_>>();
    paths.sort();
    paths
}

fn artifact_spec_matches(
    repo_root: &Path,
    profile: Option<&str>,
) -> BTreeMap<String, BTreeMap<String, usize>> {
    specs()
        .into_iter()
        .map(|(component, patterns)| {
            let matches = patterns
                .iter()
                .map(|pattern| {
                    let pattern = profile_pattern(pattern, profile);
                    let count = glob_paths(repo_root, &pattern)
                        .iter()
                        .filter(|path| path.is_file())
                        .count();
                    (pattern, count)
                })
                .collect();
            (component.to_string(), matches)
        })
        .collect()
}

fn artifact_paths(repo_root: &Path, profile: Option<&str>) -> Vec<(String, PathBuf)> {
    let Ok(resolved_root) = repo_root.canonicalize() else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut artifacts = Vec::new();
    for (component, patterns) in specs() {
        for pattern in patterns {
            for path in glob_paths(repo_root, &profile_pattern(pattern, profile)) {
                if !path.is_file() {
                    continue;
                }
                let Ok(resolved) = path.canonicalize() else {
                    continue;
                };
                if !resolved.starts_with(&resolved_root) || !seen.insert(resolved.clone()) {
                    continue;
                }
                let mut magic = [0_u8; 4];
                if fs::File::open(&resolved)
                    .and_then(|mut file| file.read_exact(&mut magic))
                    .is_err()
                    || magic != *b"\x7fELF"
                {
                    continue;
                }
                artifacts.push((component.to_string(), resolved));
            }
        }
    }
    artifacts
}

fn retired_prefix_artifacts(repo_root: &Path, profile: Option<&str>) -> Vec<String> {
    let prefix = build_root(repo_root, profile).join("prefix");
    let mut artifacts = BTreeSet::new();
    for pattern in RETIRED_PREFIX_ARTIFACTS {
        for path in glob_paths(&prefix, pattern) {
            if (path.exists() || path.is_symlink())
                && let Ok(relative) = path.strip_prefix(repo_root)
            {
                artifacts.insert(relative.display().to_string());
            }
        }
    }
    artifacts.into_iter().collect()
}

fn cmake_state(repo_root: &Path, component: &str, profile: Option<&str>) -> Value {
    let build = build_root(repo_root, profile).join(component);
    let cache = build.join("CMakeCache.txt");
    let build_type = fs::read_to_string(&cache).ok().and_then(|text| {
        text.lines()
            .find(|line| line.starts_with("CMAKE_BUILD_TYPE:"))
            .and_then(|line| line.split_once('='))
            .map(|(_, value)| value.to_string())
            .filter(|value| !value.is_empty())
    });
    json!({
        "build_dir": build.strip_prefix(repo_root).unwrap_or(&build).display().to_string(),
        "build_present": build.is_dir(),
        "build_type": build_type,
        "compile_commands": build.join("compile_commands.json").strip_prefix(repo_root).unwrap_or(&build).display().to_string(),
        "compile_commands_present": build.join("compile_commands.json").is_file(),
    })
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice::<Value>(&fs::read(path).ok()?)
        .ok()
        .filter(Value::is_object)
}

fn git_source_state(repo_root: &Path, runner: &dyn CommandRunner) -> Option<String> {
    let root = repo_root.to_string_lossy();
    runner
        .run_with(
            "git",
            &[
                "-C",
                root.as_ref(),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            None,
            None,
            Some(PROCESS_TIMEOUT),
        )
        .filter(|output| output.success)
        .map(|output| output.stdout.trim_end_matches('\n').to_string())
}

fn file_record(repo_root: &Path, path: &Path) -> Option<Value> {
    let mut file = fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut block = [0_u8; 1024 * 1024];
    loop {
        let size = file.read(&mut block).ok()?;
        if size == 0 {
            break;
        }
        digest.update(&block[..size]);
    }
    let metadata = path.metadata().ok()?;
    let mtime_ns =
        i128::from(metadata.mtime()) * 1_000_000_000_i128 + i128::from(metadata.mtime_nsec());
    Some(json!({
        "path": path.strip_prefix(repo_root).unwrap_or(path).display().to_string(),
        "sha256": format!("{:x}", digest.finalize()),
        "size_bytes": metadata.len(),
        "mtime_ns": mtime_ns,
    }))
}

fn cmake_cache(repo_root: &Path, component: &str) -> BTreeMap<String, String> {
    let cache = repo_root
        .join("build/hardened")
        .join(component)
        .join("CMakeCache.txt");
    fs::read_to_string(cache)
        .ok()
        .into_iter()
        .flat_map(|text| {
            text.lines()
                .filter_map(|line| {
                    if line.starts_with("//")
                        || line.starts_with('#')
                        || !line.contains(':')
                        || !line.contains('=')
                    {
                        return None;
                    }
                    let key = line.split_once(':')?.0.to_string();
                    let value = line.split_once('=')?.1.to_string();
                    Some((key, value))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn configured_toolchain(repo_root: &Path, component: &str) -> Option<Value> {
    let build = repo_root.join("build/hardened").join(component);
    let cache = cmake_cache(repo_root, component);
    let compiler_value = cache.get("CMAKE_C_COMPILER")?;
    let compiler = PathBuf::from(compiler_value);
    let compiler = if compiler.is_absolute() {
        compiler
    } else {
        build.join(compiler)
    }
    .canonicalize()
    .ok()?;
    let compiler_record = file_record(repo_root, &compiler)?;
    let config_pattern = build
        .join("CMakeFiles/*/CMakeCCompiler.cmake")
        .to_string_lossy()
        .into_owned();
    let compiler_config = glob(&config_pattern).ok()?.filter_map(Result::ok).min()?;
    let compiler_text = fs::read_to_string(compiler_config).ok()?;
    let cmake_set = |name: &str| -> Option<String> {
        Regex::new(&format!(r#"(?m)^set\({} "([^"]*)"\)"#, regex::escape(name)))
            .ok()?
            .captures(&compiler_text)?
            .get(1)
            .map(|value| value.as_str().to_string())
    };
    Some(json!({
        "compiler": compiler_record,
        "compiler_id": cmake_set("CMAKE_C_COMPILER_ID"),
        "compiler_version": cmake_set("CMAKE_C_COMPILER_VERSION"),
        "build_type": cache.get("CMAKE_BUILD_TYPE"),
        "generator": cache.get("CMAKE_GENERATOR"),
    }))
}

fn manifest_payload(repo_root: &Path, runner: &dyn CommandRunner) -> Result<Value, String> {
    let head = run_git(runner, repo_root, &["rev-parse", "HEAD"]);
    let source_status = git_source_state(repo_root, runner);
    let configuration_path = repo_root.join(HARDENED_CONFIGURATION);
    let injection_path = repo_root.join(HARDENED_CMAKE_INJECTION);
    if head.is_none()
        || source_status.is_none()
        || !configuration_path.is_file()
        || !injection_path.is_file()
    {
        return Err("source state or hardened configuration artifacts are unavailable".into());
    }
    let mut compile_databases = Map::new();
    let mut toolchains = Map::new();
    for component in COMPONENTS {
        let database = repo_root
            .join("build/hardened")
            .join(component)
            .join("compile_commands.json");
        let toolchain = configured_toolchain(repo_root, component);
        if !database.is_file() || toolchain.is_none() {
            return Err(format!(
                "{component} compile database or configured toolchain is unavailable"
            ));
        }
        compile_databases.insert(
            component.into(),
            file_record(repo_root, &database)
                .ok_or_else(|| format!("{component} compile database identity is unavailable"))?,
        );
        toolchains.insert(component.into(), toolchain.unwrap());
    }
    let artifact_pairs = artifact_paths(repo_root, Some("hardened"));
    let matches = artifact_spec_matches(repo_root, Some("hardened"));
    if artifact_pairs.len() != EXPECTED_ARTIFACT_COUNT
        || matches
            .values()
            .flat_map(BTreeMap::values)
            .any(|count| *count == 0)
    {
        return Err(
            "the exact hardened ELF registry is incomplete or has unexpected cardinality".into(),
        );
    }
    let artifacts = artifact_pairs
        .iter()
        .map(|(_, path)| {
            file_record(repo_root, path)
                .ok_or_else(|| format!("could not identify {}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let configuration = file_record(repo_root, &configuration_path)
        .ok_or_else(|| "hardened configuration identity is unavailable".to_string())?;
    let cmake_injection = file_record(repo_root, &injection_path)
        .ok_or_else(|| "hardened CMake injection identity is unavailable".to_string())?;
    Ok(json!({
        "schema_version": 1,
        "profile": "hardened",
        "head": head,
        "source_status": source_status,
        "configuration": configuration,
        "cmake_injection": cmake_injection,
        "toolchains": toolchains,
        "compile_databases": compile_databases,
        "artifacts": artifacts,
    }))
}

fn write_manifest_atomically(repo_root: &Path, payload: &Value) -> Result<(), String> {
    let canonical_root = repo_root
        .canonicalize()
        .map_err(|_| "repository root is unavailable".to_string())?;
    let expected_root = fs::metadata(&canonical_root)
        .map_err(|_| "repository root identity is unavailable".to_string())?;
    let root_name = CString::new(canonical_root.as_os_str().as_bytes())
        .map_err(|_| "repository root has an invalid path".to_string())?;
    // SAFETY: root_name is NUL-terminated and O_NOFOLLOW requires the final
    // component to remain the expected directory rather than a symlink.
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err("repository root could not be opened safely".into());
    }
    // SAFETY: open returned a new owned descriptor.
    let root = unsafe { OwnedFd::from_raw_fd(root_fd) };
    let mut root_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: root is open and root_stat points to writable storage.
    if unsafe { libc::fstat(root.as_raw_fd(), root_stat.as_mut_ptr()) } != 0 {
        return Err("repository root identity could not be verified".into());
    }
    // SAFETY: successful fstat initialized root_stat.
    let root_stat = unsafe { root_stat.assume_init() };
    if root_stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || root_stat.st_dev != expected_root.dev()
        || root_stat.st_ino != expected_root.ino()
    {
        return Err("repository root identity changed while opening it".into());
    }
    let open_child_directory = |parent: &OwnedFd, name: &'static [u8]| -> Result<OwnedFd, String> {
        let name = CString::new(name).expect("static directory name");
        // SAFETY: parent is an open directory descriptor, name is valid, and
        // O_NOFOLLOW rejects a substituted symlink.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err("hardened build directory could not be opened safely".into());
        }
        // SAFETY: openat returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    };
    let build = open_child_directory(&root, b"build")?;
    let parent = open_child_directory(&build, b"hardened")?;
    let target_name = CString::new("hardening-manifest.json").expect("static manifest name");
    let mut target_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent and target_name are valid and target_stat is writable;
    // AT_SYMLINK_NOFOLLOW inspects rather than follows the destination.
    let target_status = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            target_name.as_ptr(),
            target_stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if target_status == 0 {
        // SAFETY: successful fstatat initialized target_stat.
        let target_stat = unsafe { target_stat.assume_init() };
        if target_stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err("manifest target is not a regular file".into());
        }
    } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err("manifest target could not be inspected safely".into());
    }
    let text = serde_json::to_string_pretty(payload)
        .map(|text| format!("{text}\n"))
        .map_err(|_| "manifest payload could not be serialized".to_string())?;
    let temporary_name = CString::new(format!(
        ".hardening-manifest.json.tmp-{}-{}",
        std::process::id(),
        NEXT_MANIFEST_TEMP.fetch_add(1, Ordering::Relaxed)
    ))
    .expect("generated manifest temporary name");
    let write_result = (|| -> Result<(), String> {
        // SAFETY: the held directory descriptor and temporary name are valid;
        // O_EXCL/O_NOFOLLOW prevent replacing or following an attacker entry.
        let temporary_fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if temporary_fd < 0 {
            return Err("manifest temporary file could not be created".into());
        }
        // SAFETY: openat returned a new descriptor transferred to File.
        let mut file = unsafe { File::from_raw_fd(temporary_fd) };
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| "manifest temporary file could not be persisted".to_string())?;
        drop(file);
        // SAFETY: both names are relative to the same held directory
        // descriptor, so rename atomically replaces only the verified target.
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                temporary_name.as_ptr(),
                parent.as_raw_fd(),
                target_name.as_ptr(),
            )
        } != 0
        {
            return Err("manifest could not be atomically installed".into());
        }
        // SAFETY: fsync accepts the held directory descriptor.
        if unsafe { libc::fsync(parent.as_raw_fd()) } != 0 {
            return Err("manifest directory update could not be persisted".into());
        }
        Ok(())
    })();
    if write_result.is_err() {
        // SAFETY: unlinkat is constrained to the held directory and exact
        // generated temporary name; failure means cleanup is unnecessary.
        unsafe { libc::unlinkat(parent.as_raw_fd(), temporary_name.as_ptr(), 0) };
    }
    write_result
}

fn command_manifest_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let finding = match manifest_payload(repo_root, runner) {
        Ok(payload) => match write_manifest_atomically(repo_root, &payload) {
            Ok(()) => Finding::new(
                "pass",
                "build-c-services.hardening-manifest",
                "Hardened build manifest recorded source, toolchain, compile database, and exact ELF identities.".into(),
            )
            .with_path(HARDENED_BUILD_MANIFEST),
            Err(error) => Finding::new(
                "fail",
                "build-c-services.hardening-manifest",
                format!("Hardened build manifest was not written: {error}."),
            )
            .with_path(HARDENED_BUILD_MANIFEST),
        },
        Err(error) => Finding::new(
            "fail",
            "build-c-services.hardening-manifest",
            format!("Hardened build manifest was not written: {error}."),
        )
        .with_path(HARDENED_BUILD_MANIFEST),
    };
    let passed = finding.status == "pass";
    let result = make_result(
        metadata(repo_root, "c-hardening-manifest-write", runner),
        if passed {
            "Hardened build manifest recorded."
        } else {
            "Hardened build manifest could not be recorded."
        }
        .into(),
        vec![finding],
    );
    if passed {
        result.with_artifacts(vec![HARDENED_BUILD_MANIFEST.into()])
    } else {
        result
    }
}

pub fn command_c_hardening_manifest_write(repo_root: &Path) -> ResultEnvelope {
    command_manifest_with(repo_root, &SystemCommandRunner)
}

fn property(status: &str, evidence: String) -> Value {
    json!({"status": status, "evidence": evidence})
}

fn elf_properties(
    component: &str,
    relative_path: &str,
    header: &str,
    program_headers: &str,
    dynamic: &str,
    symbols: &str,
    notes: &str,
) -> Value {
    let elf_type = Regex::new(r"(?m)^\s*Type:\s+(\S+)")
        .unwrap()
        .captures(header)
        .and_then(|row| row.get(1))
        .map(|value| value.as_str())
        .unwrap_or("unknown");
    let machine = Regex::new(r"(?m)^\s*Machine:\s+(.+?)\s*$")
        .unwrap()
        .captures(header)
        .and_then(|row| row.get(1))
        .map(|value| value.as_str())
        .unwrap_or("unknown");
    let flattened = format!(" {} ", program_headers.replace('\n', " "));
    let has_interpreter = flattened.contains(" INTERP ")
        || Regex::new(r"(?m)^\s*INTERP\s")
            .unwrap()
            .is_match(program_headers);
    let file_name = Path::new(relative_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_lowercase();
    let looks_like_shared_library = file_name.contains(".so");
    let is_test = Path::new(relative_path).components().any(|part| {
        matches!(
            part.as_os_str().to_str().map(str::to_lowercase).as_deref(),
            Some("test" | "tests")
        )
    }) || file_name.contains("test");
    let kind = if has_interpreter
        || (matches!(elf_type, "DYN" | "EXEC")
            && !looks_like_shared_library
            && component != "pg-gvm")
    {
        if is_test {
            "test-executable"
        } else {
            "executable"
        }
    } else if component == "pg-gvm" {
        "module"
    } else if elf_type == "DYN" {
        "shared-library"
    } else {
        "other"
    };
    let pie = if matches!(kind, "executable" | "test-executable") {
        property(
            if elf_type == "DYN" {
                "present"
            } else {
                "missing"
            },
            format!(
                "ELF type is {elf_type}; executable {} an interpreter",
                if has_interpreter {
                    "has"
                } else {
                    "does not have"
                }
            ),
        )
    } else {
        property("not_applicable", format!("artifact kind is {kind}"))
    };
    let stack_line = program_headers
        .lines()
        .find(|line| line.contains("GNU_STACK"));
    let nx_stack = stack_line.map_or_else(
        || property("unknown", "GNU_STACK program header was not found".into()),
        |line| {
            let words = line.split_whitespace().collect::<Vec<_>>();
            let flags = words
                .get(words.len().saturating_sub(2))
                .copied()
                .unwrap_or("");
            property(
                if flags.contains('E') {
                    "missing"
                } else {
                    "present"
                },
                format!(
                    "GNU_STACK flags are {}",
                    if flags.is_empty() { "unparsed" } else { flags }
                ),
            )
        },
    );
    let has_relro = program_headers.contains("GNU_RELRO");
    let has_now = dynamic.contains("BIND_NOW")
        || Regex::new(r"FLAGS(?:_1)?[^\n]*\bNOW\b")
            .unwrap()
            .is_match(dynamic);
    let full_relro = property(
        if has_relro && has_now {
            "present"
        } else {
            "missing"
        },
        format!(
            "GNU_RELRO={}, immediate binding={}",
            if has_relro { "yes" } else { "no" },
            if has_now { "yes" } else { "no" }
        ),
    );
    let has_textrel = dynamic.contains("(TEXTREL)")
        || Regex::new(r"FLAGS[^\n]*\bTEXTREL\b")
            .unwrap()
            .is_match(dynamic);
    let no_text_relocations = property(
        if has_textrel { "missing" } else { "present" },
        if has_textrel {
            "dynamic section declares TEXTREL".into()
        } else {
            "dynamic section has no TEXTREL marker".into()
        },
    );
    let stack_symbol = symbols.contains("__stack_chk_fail");
    let stack_protector = property(
        "unknown",
        if stack_symbol {
            "__stack_chk_fail symbol reference found, but whole-artifact compiler coverage is not proven".into()
        } else {
            "no stack-check symbol reference; compile flags and applicability are not proven".into()
        },
    );
    let fortify_match = Regex::new(r"\b__[A-Za-z0-9_]+_chk(?:@|\b)")
        .unwrap()
        .find(symbols)
        .map(|value| value.as_str());
    let fortify = property(
        "unknown",
        fortify_match.map_or_else(
            || "no fortified libc symbol reference; applicability and compile flags are not proven".into(),
            |value| format!("fortified symbol {value} found, but whole-artifact compiler coverage is not proven"),
        ),
    );
    let upper_machine = machine.to_uppercase();
    let control_flow = if upper_machine.contains("X86-64") {
        let ibt = notes.contains("IBT");
        let shstk = notes.contains("SHSTK");
        property(
            if ibt && shstk { "present" } else { "unknown" },
            format!(
                "x86 feature notes: IBT={}, SHSTK={}",
                if ibt { "yes" } else { "no" },
                if shstk { "yes" } else { "no" }
            ),
        )
    } else if upper_machine.contains("AARCH64") {
        let present = notes.contains("BTI") || notes.contains("PAC");
        property(
            if present { "present" } else { "unknown" },
            if present {
                "AArch64 branch-protection note found".into()
            } else {
                "no recognized AArch64 branch-protection note".into()
            },
        )
    } else {
        property("unsupported", format!("no detector for machine {machine}"))
    };
    json!({
        "component": component,
        "path": relative_path,
        "kind": kind,
        "elf_type": elf_type,
        "machine": machine,
        "properties": {
            "pie": pie,
            "nx_stack": nx_stack,
            "full_relro": full_relro,
            "stack_protector": stack_protector,
            "fortify": fortify,
            "control_flow_protection": control_flow,
            "no_text_relocations": no_text_relocations,
        }
    })
}

fn readelf(path: &Path, arg: &str, runner: &dyn CommandRunner, program: &Path) -> (bool, String) {
    let path = path.to_string_lossy();
    let program = program.to_string_lossy();
    runner
        .run_with(
            program.as_ref(),
            &["-W", arg, path.as_ref()],
            None,
            None,
            Some(PROCESS_TIMEOUT),
        )
        .map(|output| (output.success, output.stdout))
        .unwrap_or_default()
}

fn inspect_artifact(
    repo_root: &Path,
    component: &str,
    path: &Path,
    runner: &dyn CommandRunner,
    readelf_program: &Path,
) -> Value {
    let relative_path = path
        .strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string();
    let (header_ok, header) = readelf(path, "-h", runner, readelf_program);
    let (program_headers_ok, program_headers) = readelf(path, "-l", runner, readelf_program);
    let file_evidence = file_record(repo_root, path).unwrap_or_else(|| json!({}));
    if !header_ok || !program_headers_ok {
        let unknown = property(
            "unknown",
            "readelf could not inspect the ELF header and program headers".into(),
        );
        return json!({
            "component": component,
            "path": relative_path,
            "kind": "unknown",
            "elf_type": "unknown",
            "machine": "unknown",
            "file_evidence": {
                "sha256": file_evidence["sha256"],
                "size_bytes": file_evidence["size_bytes"],
                "mtime_ns": file_evidence["mtime_ns"],
            },
            "properties": {
                "pie": unknown,
                "nx_stack": unknown,
                "full_relro": unknown,
                "stack_protector": unknown,
                "fortify": unknown,
                "control_flow_protection": unknown,
                "no_text_relocations": unknown,
            }
        });
    }
    let (dynamic_ok, dynamic) = readelf(path, "-d", runner, readelf_program);
    let (symbols_ok, symbols) = readelf(path, "-s", runner, readelf_program);
    let (notes_ok, notes) = readelf(path, "-n", runner, readelf_program);
    let mut result = elf_properties(
        component,
        &relative_path,
        &header,
        &program_headers,
        &dynamic,
        &symbols,
        &notes,
    );
    result["file_evidence"] = json!({
        "sha256": file_evidence["sha256"],
        "size_bytes": file_evidence["size_bytes"],
        "mtime_ns": file_evidence["mtime_ns"],
    });
    if !dynamic_ok {
        let evidence = property(
            "unknown",
            "readelf could not inspect the dynamic section".into(),
        );
        result["properties"]["full_relro"] = evidence.clone();
        result["properties"]["no_text_relocations"] = evidence;
    }
    if !symbols_ok {
        result["properties"]["stack_protector"] =
            property("unknown", "readelf could not inspect symbols".into());
        result["properties"]["fortify"] =
            property("unknown", "readelf could not inspect symbols".into());
    }
    if !notes_ok {
        result["properties"]["control_flow_protection"] =
            property("unknown", "readelf could not inspect ELF notes".into());
    }
    result
}

fn failed_compile_evidence(
    path: String,
    entry_count: usize,
    c_entries: usize,
    valid: usize,
    malformed: usize,
) -> Value {
    json!({
        "status": "fail",
        "path": path,
        "properties": {},
        "entry_count": entry_count,
        "c_entry_count": c_entries,
        "validated_command_count": valid,
        "malformed_entry_count": malformed,
    })
}

fn compile_evidence(repo_root: &Path, component: &str, configuration: Option<&Value>) -> Value {
    let database = repo_root
        .join("build/hardened")
        .join(component)
        .join("compile_commands.json");
    let database_path = database
        .strip_prefix(repo_root)
        .unwrap_or(&database)
        .display()
        .to_string();
    let Some(entries) = fs::read(&database)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.as_array().cloned())
        .filter(|entries| !entries.is_empty())
    else {
        return failed_compile_evidence(database_path, 0, 0, 0, 1);
    };
    let mut commands = Vec::new();
    let mut c_entry_count = 0;
    let mut malformed_entry_count = 0;
    for entry in &entries {
        let Some(object) = entry.as_object() else {
            malformed_entry_count += 1;
            continue;
        };
        let Some(source) = object.get("file").and_then(Value::as_str) else {
            malformed_entry_count += 1;
            continue;
        };
        if Path::new(source)
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_lowercase)
            .as_deref()
            != Some("c")
        {
            continue;
        }
        c_entry_count += 1;
        if let Some(arguments) = object.get("arguments").and_then(Value::as_array)
            && arguments.iter().all(Value::is_string)
        {
            commands.push(
                arguments
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
            );
        } else if let Some(command) = object.get("command").and_then(Value::as_str) {
            if let Some(words) = shlex::split(command) {
                commands.push(words);
            } else {
                malformed_entry_count += 1;
            }
        } else {
            malformed_entry_count += 1;
        }
    }
    if commands.is_empty() || c_entry_count != commands.len() {
        return failed_compile_evidence(
            database_path,
            entries.len(),
            c_entry_count,
            commands.len(),
            malformed_entry_count,
        );
    }
    let configuration = configuration
        .cloned()
        .or_else(|| read_json(&repo_root.join(HARDENED_CONFIGURATION)));
    let Some(features) = configuration
        .as_ref()
        .and_then(|value| value.get("features"))
        .and_then(Value::as_object)
    else {
        return failed_compile_evidence(
            database_path,
            entries.len(),
            c_entry_count,
            commands.len(),
            malformed_entry_count,
        );
    };

    let last_matching = |command: &[String], predicate: &dyn Fn(&str) -> bool| {
        command
            .iter()
            .rev()
            .find(|option| predicate(option))
            .cloned()
    };
    let effective = |name: &str,
                     predicate: &dyn Fn(&str) -> bool,
                     accepted: &BTreeSet<String>,
                     required: bool|
     -> Value {
        let feature = features.get(name).and_then(Value::as_object);
        if feature
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            != Some("present")
        {
            if !required
                && feature
                    .and_then(|value| value.get("status"))
                    .and_then(Value::as_str)
                    == Some("unsupported")
            {
                return property(
                    "unsupported",
                    format!(
                        "optional configured {name} feature is unsupported on this architecture"
                    ),
                );
            }
            return property(
                "missing",
                format!("required configured {name} feature is absent or unsupported"),
            );
        }
        let options = commands
            .iter()
            .map(|command| last_matching(command, predicate))
            .collect::<Vec<_>>();
        let present = options.iter().all(|option| {
            option
                .as_ref()
                .is_some_and(|option| accepted.contains(option))
        });
        let observed = options
            .into_iter()
            .map(|option| option.unwrap_or_else(|| "absent".into()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        property(
            if present { "present" } else { "missing" },
            format!(
                "{} {} compilation command(s) have an accepted effective {name} option; observed: {}",
                if present { "all" } else { "not all" },
                commands.len(),
                observed.join(", ")
            ),
        )
    };
    let optimization_regex = Regex::new(r"^-O(?:[0-9]+|fast|g|s|z)?$").unwrap();
    let optimization_options = commands
        .iter()
        .map(|command| last_matching(command, &|option| optimization_regex.is_match(option)))
        .collect::<Vec<_>>();
    let optimization_present = optimization_options
        .iter()
        .all(|option| option.as_deref() == Some("-O2"));
    let optimization_observed = optimization_options
        .into_iter()
        .map(|option| option.unwrap_or_else(|| "absent".into()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let optimization = property(
        if optimization_present {
            "present"
        } else {
            "missing"
        },
        format!(
            "{} {} compilation command(s) have effective -O2; observed: {}",
            if optimization_present {
                "all"
            } else {
                "not all"
            },
            commands.len(),
            optimization_observed.join(", ")
        ),
    );
    let fortify_define = features
        .get("fortify")
        .and_then(|value| value.get("flags"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .rev()
        .find(|flag| flag.starts_with("-D_FORTIFY_SOURCE="))
        .unwrap_or("")
        .to_string();
    let mut fortify = effective(
        "fortify",
        &|option| option == "-U_FORTIFY_SOURCE" || option.starts_with("-D_FORTIFY_SOURCE="),
        &BTreeSet::from([fortify_define]),
        true,
    );
    if optimization["status"] != "present" && fortify["status"] == "present" {
        fortify = property(
            "missing",
            "Fortify define is effective, but required optimization is not effective".into(),
        );
    }
    let architecture = configuration
        .as_ref()
        .and_then(|value| value.get("architecture"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let control_flow_required = architecture.is_empty()
        || matches!(
            architecture.to_lowercase().as_str(),
            "x86_64" | "amd64" | "aarch64" | "arm64"
        );
    let control_flags = features
        .get("control_flow_protection")
        .and_then(|value| value.get("flags"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let properties = json!({
        "optimization": optimization,
        "fortify": fortify,
        "stack_protector": effective("stack_protector", &|option| matches!(option, "-fno-stack-protector" | "-fstack-protector" | "-fstack-protector-all" | "-fstack-protector-explicit" | "-fstack-protector-strong"), &BTreeSet::from(["-fstack-protector-strong".into(), "-fstack-protector-all".into()]), true),
        "stack_clash": effective("stack_clash", &|option| matches!(option, "-fstack-clash-protection" | "-fno-stack-clash-protection"), &BTreeSet::from(["-fstack-clash-protection".into()]), true),
        "format_security": effective("format_security", &|option| matches!(option, "-Werror=format-security" | "-Wno-error=format-security" | "-Wformat-security" | "-Wno-format-security"), &BTreeSet::from(["-Werror=format-security".into()]), true),
        "control_flow_protection": effective("control_flow_protection", &|option| option.starts_with("-fcf-protection=") || option.starts_with("-mbranch-protection="), &control_flags, control_flow_required),
    });
    let complete = malformed_entry_count == 0 && c_entry_count == commands.len();
    let accepted = properties.as_object().unwrap().iter().all(|(name, value)| {
        value["status"] == "present"
            || (name == "control_flow_protection"
                && !control_flow_required
                && value["status"] == "unsupported")
    });
    json!({
        "status": if complete && accepted { "pass" } else { "fail" },
        "path": database_path,
        "command_count": commands.len(),
        "entry_count": entries.len(),
        "c_entry_count": c_entry_count,
        "validated_command_count": commands.len(),
        "malformed_entry_count": malformed_entry_count,
        "properties": properties,
    })
}

fn manifest_finding(
    repo_root: &Path,
    manifest: Option<&Value>,
    runner: &dyn CommandRunner,
) -> Finding {
    let current = manifest_payload(repo_root, runner);
    let Ok(current) = current else {
        return Finding::new(
            "fail",
            "c-hardening.build-manifest",
            "Hardened build manifest is missing or current build identity cannot be collected."
                .into(),
        )
        .with_path(HARDENED_BUILD_MANIFEST)
        .with_details(json!({
            "error": current.err(),
            "manifest_present": manifest.is_some(),
        }));
    };
    let Some(manifest) = manifest else {
        return Finding::new(
            "fail",
            "c-hardening.build-manifest",
            "Hardened build manifest is missing or current build identity cannot be collected."
                .into(),
        )
        .with_path(HARDENED_BUILD_MANIFEST)
        .with_details(json!({"error": Value::Null, "manifest_present": false}));
    };
    let identity_keys = [
        "configuration",
        "cmake_injection",
        "toolchains",
        "compile_databases",
        "artifacts",
    ];
    let mismatches = identity_keys
        .iter()
        .filter(|key| manifest.get(**key) != current.get(**key))
        .copied()
        .collect::<Vec<_>>();
    let head_matches = manifest.get("head") == current.get("head");
    let status_matches = manifest.get("source_status") == current.get("source_status");
    let source_clean = current.get("source_status").and_then(Value::as_str) == Some("");
    let schema_matches = manifest.get("schema_version") == Some(&json!(1))
        && manifest.get("profile") == Some(&json!("hardened"));
    let passed =
        schema_matches && head_matches && status_matches && source_clean && mismatches.is_empty();
    Finding::new(
        if passed { "pass" } else { "fail" },
        "c-hardening.build-manifest",
        if passed {
            "Hardened build manifest matches the clean current source, configured toolchains, compile databases, and exact ELF artifacts.".into()
        } else {
            "Hardened build manifest does not match a clean current build identity.".into()
        },
    )
    .with_path(HARDENED_BUILD_MANIFEST)
    .with_details(json!({
        "schema_matches": schema_matches,
        "head_matches": head_matches,
        "source_status_matches": status_matches,
        "source_clean": source_clean,
        "identity_mismatches": mismatches,
    }))
}

fn tool_version(program: &str, runner: &dyn CommandRunner) -> Option<String> {
    let output = runner.run_with(program, &["--version"], None, None, Some(PROCESS_TIMEOUT))?;
    if !output.success {
        return None;
    }
    output
        .stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn artifact_timestamp() -> String {
    let format = format_description::parse_borrowed::<2>(
        "[year][month][day]T[hour][minute][second][subsecond digits:6]Z",
    )
    .expect("valid artifact timestamp format");
    OffsetDateTime::now_utc()
        .format(&format)
        .unwrap_or_else(|_| "19700101T000000000000Z".into())
}

fn artifact_paths_for_result(repo_root: &Path, profile: Option<&str>) -> (PathBuf, PathBuf) {
    let mut directory = runtime_dir(repo_root).join("artifacts/c-hardening");
    if let Some(profile) = profile {
        directory.push(profile);
    }
    let timestamp = artifact_timestamp();
    let mut timestamped = directory.join(format!("c-hardening-{timestamp}.json"));
    let mut counter = 1;
    while timestamped.exists() {
        timestamped = directory.join(format!("c-hardening-{timestamp}-{counter}.json"));
        counter += 1;
    }
    (directory.join("c-hardening.json"), timestamped)
}

fn write_retained(result: &ResultEnvelope, latest: &Path, timestamped: &Path) -> Result<(), ()> {
    fs::create_dir_all(latest.parent().ok_or(())?).map_err(|_| ())?;
    let text = serde_json::to_string_pretty(result)
        .map(|text| format!("{text}\n"))
        .map_err(|_| ())?;
    fs::write(latest, &text).map_err(|_| ())?;
    fs::write(timestamped, text).map_err(|_| ())?;
    let directory = latest.parent().ok_or(())?;
    let mut candidates = fs::read_dir(directory)
        .map_err(|_| ())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("c-hardening-") && name.ends_with(".json"))
        })
        .collect::<Vec<_>>();
    candidates.sort();
    let remove_count = candidates.len().saturating_sub(RETAINED_ARTIFACTS);
    for path in candidates.into_iter().take(remove_count) {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

pub fn command_c_hardening_check(
    repo_root: &Path,
    status_only: bool,
    profile: Option<&str>,
) -> ResultEnvelope {
    command_with(
        repo_root,
        status_only,
        profile,
        executable_path("readelf"),
        &SystemCommandRunner,
        true,
    )
}

fn command_with(
    repo_root: &Path,
    status_only: bool,
    profile: Option<&str>,
    readelf_program: Option<PathBuf>,
    runner: &dyn CommandRunner,
    persist: bool,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    findings.push(Finding::new(
        if readelf_program.is_some() {
            "pass"
        } else {
            "fail"
        },
        "c-hardening.readelf",
        readelf_program.as_ref().map_or_else(
            || "readelf is required to inspect ELF hardening properties.".into(),
            |path| format!("readelf is available at {}.", path.display()),
        ),
    ));
    let retired = retired_prefix_artifacts(repo_root, profile);
    findings.push(
        Finding::new(
            if retired.is_empty() { "pass" } else { "fail" },
            "c-hardening.retired-prefix-artifacts",
            if retired.is_empty() {
                "No known retired C build-prefix artifacts are present.".into()
            } else {
                format!(
                    "Found {} known retired C build-prefix artifact(s).",
                    retired.len()
                )
            },
        )
        .with_details(json!({"artifacts": retired})),
    );
    let configuration = (profile == Some("hardened"))
        .then(|| read_json(&repo_root.join(HARDENED_CONFIGURATION)))
        .flatten();
    let manifest = (profile == Some("hardened"))
        .then(|| read_json(&repo_root.join(HARDENED_BUILD_MANIFEST)))
        .flatten();
    if profile == Some("hardened") {
        findings.push(manifest_finding(repo_root, manifest.as_ref(), runner));
    }
    let build_state = COMPONENTS
        .into_iter()
        .map(|component| {
            (
                component.to_string(),
                cmake_state(repo_root, component, profile),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let matches = artifact_spec_matches(repo_root, profile);
    let pairs = readelf_program
        .as_ref()
        .map(|_| artifact_paths(repo_root, profile))
        .unwrap_or_default();
    let mut component_counts = COMPONENTS
        .into_iter()
        .map(|component| (component.to_string(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for (component, _) in &pairs {
        *component_counts.entry(component.clone()).or_default() += 1;
    }
    for component in COMPONENTS {
        let state = &build_state[component];
        let missing_patterns = matches[component]
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(pattern, _)| pattern.clone())
            .collect::<Vec<_>>();
        let build_dir = state["build_dir"].as_str().unwrap_or("");
        findings.push(if state["build_present"] != true {
            Finding::new(
                "fail",
                "c-hardening.build",
                format!("{component} has no current build directory."),
            )
            .with_path(build_dir)
        } else if !missing_patterns.is_empty() {
            Finding::new(
                "fail",
                "c-hardening.artifact-spec",
                format!(
                    "{component} is missing {} declared final artifact pattern(s).",
                    missing_patterns.len()
                ),
            )
            .with_path(build_dir)
            .with_details(json!({"missing_patterns": missing_patterns}))
        } else if component_counts[component] == 0 {
            Finding::new(
                "fail",
                "c-hardening.artifacts",
                format!("{component} has no declared final ELF artifact."),
            )
            .with_path(build_dir)
        } else {
            Finding::new(
                "pass",
                "c-hardening.artifacts",
                format!(
                    "{component} has {} final ELF artifact(s).",
                    component_counts[component]
                ),
            )
            .with_path(build_dir)
        });
    }
    let artifacts = readelf_program.as_ref().map_or_else(Vec::new, |program| {
        pairs
            .iter()
            .map(|(component, path)| inspect_artifact(repo_root, component, path, runner, program))
            .collect::<Vec<_>>()
    });
    findings.push(
        Finding::new(
            if artifacts.len() == EXPECTED_ARTIFACT_COUNT { "pass" } else { "fail" },
            "c-hardening.artifact-count",
            format!(
                "Hardening registry resolved {} unique final ELF artifact(s); expected {EXPECTED_ARTIFACT_COUNT}.",
                artifacts.len()
            ),
        )
        .with_details(json!({"actual": artifacts.len(), "expected": EXPECTED_ARTIFACT_COUNT})),
    );
    let compile = if profile == Some("hardened") {
        COMPONENTS
            .into_iter()
            .map(|component| {
                (
                    component.to_string(),
                    compile_evidence(repo_root, component, configuration.as_ref()),
                )
            })
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    for component in COMPONENTS {
        let Some(evidence) = compile.get(component) else {
            continue;
        };
        findings.push(
            Finding::new(
                evidence["status"].as_str().unwrap_or("fail"),
                "c-hardening.compile-commands",
                format!(
                    "{component} hardened compilation evidence is {}.",
                    evidence["status"].as_str().unwrap_or("fail")
                ),
            )
            .with_path(evidence["path"].as_str().unwrap_or(""))
            .with_details(json!({
                "properties": evidence["properties"],
                "entry_count": evidence["entry_count"].as_u64().unwrap_or(0),
                "c_entry_count": evidence["c_entry_count"].as_u64().unwrap_or(0),
                "validated_command_count": evidence["validated_command_count"].as_u64().unwrap_or(0),
                "malformed_entry_count": evidence["malformed_entry_count"].as_u64().unwrap_or(0),
            })),
        );
    }
    let mut property_counts = BTreeMap::from([
        ("present".to_string(), 0_usize),
        ("missing".to_string(), 0),
        ("unsupported".to_string(), 0),
        ("not_applicable".to_string(), 0),
        ("unknown".to_string(), 0),
    ]);
    let mut runtime_missing = Vec::new();
    let mut runtime_unknown = Vec::new();
    let property_order = [
        "pie",
        "nx_stack",
        "full_relro",
        "stack_protector",
        "fortify",
        "control_flow_protection",
        "no_text_relocations",
    ];
    for artifact in &artifacts {
        let runtime_scope = artifact["kind"] != "test-executable";
        if let Some(properties) = artifact["properties"].as_object() {
            for name in property_order {
                let value = &properties[name];
                let status = value["status"].as_str().unwrap_or("unknown");
                *property_counts.entry(status.to_string()).or_default() += 1;
                let row = json!({
                    "path": artifact["path"],
                    "property": name,
                    "evidence": value["evidence"],
                });
                if runtime_scope && status == "missing" {
                    runtime_missing.push(row);
                } else if runtime_scope
                    && status == "unknown"
                    && !(profile == Some("hardened")
                        && matches!(name, "stack_protector" | "fortify"))
                {
                    runtime_unknown.push(row);
                }
            }
        }
    }
    let compile_failed = compile.values().any(|value| value["status"] != "pass");
    let baseline_failed = !runtime_missing.is_empty()
        || !runtime_unknown.is_empty()
        || artifacts.is_empty()
        || compile_failed;
    findings.push(
        Finding::new(
            if baseline_failed { "fail" } else { "pass" },
            "c-hardening.current-baseline",
            format!(
                "Current ELF baseline has {} missing and {} unknown runtime-artifact protection result(s).",
                runtime_missing.len(),
                runtime_unknown.len()
            ),
        )
        .with_details(json!({
            "missing_count": runtime_missing.len(),
            "unknown_count": runtime_unknown.len(),
            "missing_examples": runtime_missing.iter().take(5).collect::<Vec<_>>(),
            "unknown_examples": runtime_unknown.iter().take(5).collect::<Vec<_>>(),
        })),
    );
    let source_status = git_source_state(repo_root, runner);
    if source_status.is_none() {
        findings.push(Finding::new(
            "fail",
            "c-hardening.source-state",
            "Git source state could not be determined.".into(),
        ));
    } else if source_status
        .as_ref()
        .is_some_and(|status| !status.is_empty())
    {
        findings.push(Finding::new(
            "fail",
            "c-hardening.source-state",
            "Tracked or untracked nonignored source changes are present; hardening evidence cannot be attributed to a clean source state.".into(),
        ));
    }
    let (latest, timestamped) = artifact_paths_for_result(repo_root, profile);
    let profile_name = profile.unwrap_or("current");
    let details = json!({
        "schema_version": 1,
        "profile": profile_name,
        "source_state": {
            "head": run_git(runner, repo_root, &["rev-parse", "HEAD"]),
            "dirty": source_status.as_ref().map(|status| !status.is_empty()),
        },
        "toolchain": {
            "architecture": std::env::consts::ARCH,
            "gcc": tool_version("gcc", runner),
            "clang": tool_version("clang", runner),
            "cmake": tool_version("cmake", runner),
            "linker": tool_version("ld", runner),
            "readelf": tool_version("readelf", runner),
        },
        "build_state": build_state,
        "artifact_count": artifacts.len(),
        "component_artifact_counts": component_counts,
        "artifact_spec_matches": matches,
        "property_status_counts": property_counts,
        "artifacts": artifacts,
        "compile_evidence": compile,
    });
    let summary = format!(
        "{profile_name} C hardening baseline inspected {} final ELF artifact(s); {} missing and {} unknown runtime protection result(s).",
        pairs.len(),
        runtime_missing.len(),
        runtime_unknown.len()
    );
    let mut result = make_result(
        metadata(repo_root, "c-hardening-check", runner),
        summary,
        findings,
    )
    .with_artifacts(vec![
        latest.display().to_string(),
        timestamped.display().to_string(),
    ])
    .with_details(details);
    if persist && write_retained(&result, &latest, &timestamped).is_err() {
        result.findings.push(Finding::new(
            "fail",
            "c-hardening.artifact-write",
            "C hardening evidence artifacts could not be retained.".into(),
        ));
        result.status = "fail".into();
    }
    if status_only {
        let details = result.details.take().unwrap_or_else(|| json!({}));
        result.findings.retain(|finding| finding.status != "pass");
        result.details = Some(json!({
            "profile": details["profile"],
            "source_state": details["source_state"],
            "artifact_count": details["artifact_count"],
            "component_artifact_counts": details["component_artifact_counts"],
            "property_status_counts": details["property_status_counts"],
            "compile_evidence": details["compile_evidence"],
        }));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::cell::RefCell;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "turbovasctl-c-hardening-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    #[test]
    fn manifest_install_is_atomic_private_and_refuses_symlinks() {
        let temporary = TestDir::new();
        let repo = temporary.path();
        let parent = repo.join("build/hardened");
        fs::create_dir_all(&parent).unwrap();
        let target = parent.join("hardening-manifest.json");
        fs::write(&target, "old").unwrap();
        write_manifest_atomically(repo, &json!({"schema_version": 1})).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&fs::read_to_string(&target).unwrap()).unwrap(),
            json!({"schema_version": 1})
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o077,
            0
        );
        assert!(
            fs::read_dir(&parent)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".hardening-manifest.json.tmp-"))
        );

        fs::remove_file(&target).unwrap();
        let outside = repo.join("outside-manifest.json");
        fs::write(&outside, "outside").unwrap();
        symlink(&outside, &target).unwrap();
        assert!(write_manifest_atomically(repo, &json!({"schema_version": 2})).is_err());
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn manifest_install_refuses_symlinked_build_parent() {
        let temporary = TestDir::new();
        let repo = temporary.path();
        let outside = repo.join("outside/hardened");
        fs::create_dir_all(&outside).unwrap();
        symlink(outside.parent().unwrap(), repo.join("build")).unwrap();
        assert!(write_manifest_atomically(repo, &json!({"schema_version": 1})).is_err());
        assert!(!outside.join("hardening-manifest.json").exists());
    }

    #[test]
    fn manifest_command_fails_closed_with_stable_bridge_envelope() {
        let temporary = TestDir::new();
        let repo = temporary.path();
        fs::create_dir_all(repo.join("build/hardened")).unwrap();
        let runner = FakeRunner {
            outputs: RefCell::new(vec![
                output(true, "0123456789abcdef\n"),
                output(true, ""),
                output(true, "01234567\n"),
            ]),
        };
        let result = command_manifest_with(repo, &runner);
        assert_eq!(result.status, "fail");
        assert!(result.artifacts.is_empty());
        assert_eq!(result.metadata.command, "c-hardening-manifest-write");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].check,
            "build-c-services.hardening-manifest"
        );
        assert_eq!(
            result.findings[0].path.as_deref(),
            Some(HARDENED_BUILD_MANIFEST)
        );
        assert!(!repo.join(HARDENED_BUILD_MANIFEST).exists());
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct FakeRunner {
        outputs: RefCell<Vec<ProcessOutput>>,
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            Some(self.outputs.borrow_mut().remove(0))
        }
    }

    fn output(success: bool, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn hardening_registry_is_exact_and_profile_aware() {
        assert_eq!(
            specs()
                .iter()
                .map(|(_, patterns)| patterns.len())
                .sum::<usize>(),
            20
        );
        assert!(
            artifact_spec_matches(Path::new("/not-present"), Some("hardened"))
                .values()
                .flat_map(BTreeMap::keys)
                .all(|pattern| pattern.starts_with("build/hardened/"))
        );
    }

    #[test]
    fn elf_properties_keep_unknown_distinct_from_missing() {
        let row = elf_properties(
            "gvmd",
            "build/gvmd/src/gvmd",
            "  Type: DYN\n  Machine: Advanced Micro Devices X86-64\n",
            "  INTERP 0 0 0\n  GNU_STACK 0 0 0 0 0 RW 0x10\n  GNU_RELRO 0 0 0\n",
            " (FLAGS) BIND_NOW\n",
            "__stack_chk_fail@GLIBC_2.4 __snprintf_chk@GLIBC_2.3.4",
            "x86 feature: IBT, SHSTK",
        );
        assert_eq!(row["kind"], "executable");
        assert_eq!(row["properties"]["pie"]["status"], "present");
        assert_eq!(row["properties"]["nx_stack"]["status"], "present");
        assert_eq!(row["properties"]["full_relro"]["status"], "present");
        assert_eq!(row["properties"]["stack_protector"]["status"], "unknown");
        assert_eq!(row["properties"]["fortify"]["status"], "unknown");
        assert_eq!(
            row["properties"]["control_flow_protection"]["status"],
            "present"
        );

        let weak = elf_properties(
            "gvmd",
            "build/gvmd/src/gvmd",
            "  Type: EXEC\n  Machine: Advanced Micro Devices X86-64\n",
            "  INTERP 0 0 0\n  GNU_STACK 0 0 0 0 0 RWE 0x10\n",
            " (TEXTREL) 0x0\n",
            "",
            "",
        );
        assert_eq!(weak["properties"]["pie"]["status"], "missing");
        assert_eq!(weak["properties"]["nx_stack"]["status"], "missing");
        assert_eq!(weak["properties"]["full_relro"]["status"], "missing");
        assert_eq!(
            weak["properties"]["no_text_relocations"]["status"],
            "missing"
        );
    }

    #[test]
    fn failed_dynamic_read_is_unknown_not_clean() {
        let temporary = TestDir::new();
        let repo = temporary.path();
        let artifact = repo.join("build/gvmd/src/gvmd");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        fs::write(&artifact, b"\x7fELFpayload").unwrap();
        let runner = FakeRunner {
            outputs: RefCell::new(vec![
                output(
                    true,
                    "  Type: DYN\n  Machine: Advanced Micro Devices X86-64\n",
                ),
                output(true, "  INTERP 0 0 0\n  GNU_STACK 0 0 0 0 0 RW 0x10\n"),
                output(false, "readelf error"),
                output(true, ""),
                output(true, ""),
            ]),
        };
        let row = inspect_artifact(repo, "gvmd", &artifact, &runner, Path::new("readelf"));
        assert_eq!(row["properties"]["full_relro"]["status"], "unknown");
        assert_eq!(
            row["properties"]["no_text_relocations"]["status"],
            "unknown"
        );
        assert_eq!(row["file_evidence"]["size_bytes"], 11);
    }

    #[test]
    fn compile_evidence_uses_last_effective_security_option() {
        let temporary = TestDir::new();
        let repo = temporary.path();
        let database = repo.join("build/hardened/gvmd/compile_commands.json");
        fs::create_dir_all(database.parent().unwrap()).unwrap();
        let required = vec![
            "cc",
            "-O2",
            "-D_FORTIFY_SOURCE=3",
            "-fstack-protector-strong",
            "-fstack-clash-protection",
            "-Werror=format-security",
            "-fcf-protection=full",
            "-c",
            "source.c",
        ];
        fs::write(
            &database,
            serde_json::to_vec(&json!([{"file":"source.c","arguments":required}])).unwrap(),
        )
        .unwrap();
        let configuration = json!({
            "architecture": "x86_64",
            "features": {
                "fortify": {"status":"present","flags":["-D_FORTIFY_SOURCE=3"]},
                "stack_protector": {"status":"present","flags":["-fstack-protector-strong"]},
                "stack_clash": {"status":"present","flags":["-fstack-clash-protection"]},
                "format_security": {"status":"present","flags":["-Werror=format-security"]},
                "control_flow_protection": {"status":"present","flags":["-fcf-protection=full"]},
            }
        });
        assert_eq!(
            compile_evidence(repo, "gvmd", Some(&configuration))["status"],
            "pass"
        );
        let mut weakened = required;
        weakened.push("-fno-stack-protector");
        fs::write(
            &database,
            serde_json::to_vec(&json!([{"file":"source.c","arguments":weakened}])).unwrap(),
        )
        .unwrap();
        let evidence = compile_evidence(repo, "gvmd", Some(&configuration));
        assert_eq!(evidence["status"], "fail");
        assert_eq!(
            evidence["properties"]["stack_protector"]["status"],
            "missing"
        );
    }

    #[test]
    fn artifact_registry_deduplicates_and_rejects_outside_symlinks() {
        let temporary = TestDir::new();
        let repo = temporary.path();
        let artifact = repo.join("build/gvmd/src/gvmd");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        fs::write(&artifact, b"\x7fELFpayload").unwrap();
        let duplicate = repo.join("build/gvmd/src/libgvm-pg-server.so.1");
        std::os::unix::fs::symlink(&artifact, &duplicate).unwrap();
        assert_eq!(artifact_paths(repo, None).len(), 1);

        let external = std::env::temp_dir().join(format!(
            "turbovasctl-c-hardening-outside-{}",
            std::process::id()
        ));
        fs::write(&external, b"\x7fELFoutside").unwrap();
        fs::remove_file(&artifact).unwrap();
        std::os::unix::fs::symlink(&external, &artifact).unwrap();
        assert!(artifact_paths(repo, None).is_empty());
        let _ = fs::remove_file(external);
    }

    #[test]
    fn missing_readelf_fails_cleanly_and_compacts() {
        let temporary = TestDir::new();
        let repo = temporary.path();
        fs::create_dir_all(repo.join(".git")).unwrap();
        let runner = FakeRunner {
            outputs: RefCell::new(vec![
                output(true, ""),
                output(true, "abc123\n"),
                output(true, "abc123\n"),
                output(true, "gcc\n"),
                output(true, "clang\n"),
                output(true, "cmake\n"),
                output(true, "ld\n"),
                output(true, "readelf\n"),
                output(true, "abc123\n"),
            ]),
        };
        let result = command_with(repo, true, None, None, &runner, false);
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["artifact_count"], 0);
        assert_eq!(result.findings[0].check, "c-hardening.readelf");
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.status != "pass")
        );
    }

    #[test]
    fn retired_prefix_registry_is_profile_aware() {
        let temporary = TestDir::new();
        let repo = temporary.path();
        let stale = repo.join("build/prefix/lib/libgvm_agent_controller.so.99");
        fs::create_dir_all(stale.parent().unwrap()).unwrap();
        fs::write(&stale, b"stale").unwrap();
        assert_eq!(
            retired_prefix_artifacts(repo, None),
            vec!["build/prefix/lib/libgvm_agent_controller.so.99"]
        );
        assert!(retired_prefix_artifacts(repo, Some("hardened")).is_empty());
    }
}
