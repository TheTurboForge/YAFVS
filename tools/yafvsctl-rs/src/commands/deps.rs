// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{build_env, executable_path, metadata};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::env;
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) struct BuildMeta {
    pub(crate) name: &'static str,
    pub(crate) build_system: &'static str,
    pub(crate) order: u16,
    pub(crate) pkg_config: &'static [&'static str],
    pub(crate) programs: &'static [&'static str],
    pub(crate) package_hints: &'static [&'static str],
    pub(crate) cmake_args: &'static [&'static str],
    pub(crate) install_for_dependents: bool,
    pub(crate) node_scripts: &'static [&'static str],
    pub(crate) python_imports: &'static [&'static str],
    pub(crate) python_local_deps: &'static [&'static str],
}

pub(crate) const BUILD_META: &[BuildMeta] = &[
    BuildMeta {
        name: "gvm-libs",
        build_system: "cmake",
        order: 10,
        pkg_config: &[
            "glib-2.0",
            "gio-2.0",
            "gnutls",
            "uuid",
            "libssh",
            "hiredis",
            "libxml-2.0",
            "gpgme",
            "libgcrypt",
            "libcjson",
            "libcurl",
            "zlib",
        ],
        programs: &[
            "cmake",
            "ninja",
            "pkg-config",
            "gcc",
            "libnet-config",
            "pcap-config",
        ],
        package_hints: &[
            "libcjson-dev",
            "libcrypt-dev",
            "libcurl4-gnutls-dev",
            "libgcrypt20-dev",
            "libglib2.0-dev",
            "libgnutls28-dev",
            "libgpgme-dev",
            "libhiredis-dev",
            "libnet1-dev",
            "libpaho-mqtt-dev",
            "libpcap-dev",
            "libssh-dev",
            "libxml2-dev",
            "uuid-dev",
        ],
        cmake_args: &["-DBUILD_TESTS=OFF"],
        install_for_dependents: true,
        node_scripts: &[],
        python_imports: &[],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "openvas-smb",
        build_system: "cmake",
        order: 20,
        pkg_config: &["gnutls", "heimdal-gssapi", "popt"],
        programs: &[
            "cmake",
            "ninja",
            "pkg-config",
            "gcc",
            "perl",
            "xmltoman",
            "xmlmantohtml",
        ],
        package_hints: &[
            "gcc-mingw-w64",
            "heimdal-dev",
            "libpopt-dev",
            "libunistring-dev",
            "xmltoman",
        ],
        cmake_args: &[],
        install_for_dependents: true,
        node_scripts: &[],
        python_imports: &[],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "openvas-scanner",
        build_system: "cmake",
        order: 30,
        pkg_config: &[
            "glib-2.0",
            "gio-2.0",
            "json-glib-1.0",
            "gnutls",
            "libssh",
            "ksba",
            "gpgme",
            "libgcrypt",
            "libbsd",
            "libcurl",
            "mit-krb5",
            "mit-krb5-gssapi",
            "libgvm_base",
            "libgvm_util",
            "libgvm_boreas",
        ],
        programs: &[
            "cmake",
            "ninja",
            "pkg-config",
            "gcc",
            "bison",
            "flex",
            "pcap-config",
        ],
        package_hints: &[
            "bison",
            "flex",
            "libjson-glib-dev",
            "redis-server",
            "libksba-dev",
            "libbsd-dev",
            "krb5-multidev",
            "libmagic-dev",
            "libsnmp-dev",
            "nmap",
            "pnscan",
            "python3-impacket",
        ],
        cmake_args: &["-DCMAKE_C_FLAGS=-isystem /usr/include/mit-krb5"],
        install_for_dependents: false,
        node_scripts: &[],
        python_imports: &[],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "pg-gvm",
        build_system: "cmake",
        order: 35,
        pkg_config: &["libical", "glib-2.0", "libgvm_base"],
        programs: &["cmake", "ninja", "pkg-config", "gcc", "pg_config"],
        package_hints: &[
            "postgresql-server-dev-all",
            "postgresql-server-dev-16",
            "libical-dev",
            "libglib2.0-dev",
        ],
        cmake_args: &[],
        install_for_dependents: true,
        node_scripts: &[],
        python_imports: &[],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "gvmd",
        build_system: "cmake",
        order: 40,
        pkg_config: &[
            "libcjson",
            "libgvm_base",
            "libgvm_util",
            "libgvm_osp",
            "libgvm_gmp",
            "gnutls",
            "glib-2.0",
            "libbsd",
            "libical",
            "gpgme",
        ],
        programs: &[
            "cmake",
            "ninja",
            "pkg-config",
            "gcc",
            "pg_config",
            "xsltproc",
            "xmltoman",
            "xmlmantohtml",
        ],
        package_hints: &[
            "postgresql-server-dev-all",
            "postgresql-server-dev-16",
            "libical-dev",
            "xsltproc",
            "xmltoman",
        ],
        cmake_args: &[
            "-DENABLE_AGENTS=0",
            "-DENABLE_JWT_AUTH=0",
            "-DENABLE_OPENVASD=0",
        ],
        install_for_dependents: true,
        node_scripts: &[],
        python_imports: &[],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "gsad",
        build_system: "cmake",
        order: 50,
        pkg_config: &[
            "libmicrohttpd",
            "libxml-2.0",
            "glib-2.0",
            "libgvm_base",
            "libgvm_util",
            "libgvm_gmp",
            "gnutls",
            "zlib",
            "libbrotlienc",
            "libgcrypt",
        ],
        programs: &[
            "cmake",
            "ninja",
            "pkg-config",
            "gcc",
            "xmltoman",
            "xmlmantohtml",
        ],
        package_hints: &["libmicrohttpd-dev", "libbrotli-dev", "xmltoman"],
        cmake_args: &[],
        install_for_dependents: true,
        node_scripts: &[],
        python_imports: &[],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "gsa",
        build_system: "node-npm",
        order: 60,
        pkg_config: &[],
        programs: &["node", "npm"],
        package_hints: &["Node.js 22 official binary install", "npm 11"],
        cmake_args: &[],
        install_for_dependents: false,
        node_scripts: &["build"],
        python_imports: &[],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "greenbone-feed-sync",
        build_system: "python-uv",
        order: 90,
        pkg_config: &[],
        programs: &["python3", "uv"],
        package_hints: &["uv"],
        cmake_args: &[],
        install_for_dependents: false,
        node_scripts: &[],
        python_imports: &["greenbone.feed.sync"],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "ospd-openvas",
        build_system: "python-poetry-core",
        order: 100,
        pkg_config: &[],
        programs: &["python3", "uv"],
        package_hints: &["uv", "poetry-core"],
        cmake_args: &[],
        install_for_dependents: false,
        node_scripts: &[],
        python_imports: &["ospd", "ospd_openvas"],
        python_local_deps: &[],
    },
    BuildMeta {
        name: "notus-scanner",
        build_system: "python-poetry-core",
        order: 110,
        pkg_config: &[],
        programs: &["python3", "uv"],
        package_hints: &["uv", "poetry-core"],
        cmake_args: &[],
        install_for_dependents: false,
        node_scripts: &[],
        python_imports: &["notus.scanner"],
        python_local_deps: &[],
    },
];

pub(crate) const CORE_C_CHAIN: &[&str] = &["gvm-libs", "openvas-smb", "openvas-scanner"];
pub(crate) const C_SERVICES_CHAIN: &[&str] = &[
    "gvm-libs",
    "openvas-smb",
    "openvas-scanner",
    "pg-gvm",
    "gvmd",
    "gsad",
];
pub(crate) const PYTHON_CHAIN: &[&str] = &["greenbone-feed-sync", "ospd-openvas", "notus-scanner"];
pub(crate) const BASELINE_CHAIN: &[&str] = &[
    "gvm-libs",
    "openvas-smb",
    "openvas-scanner",
    "pg-gvm",
    "gvmd",
    "gsad",
    "gsa",
    "greenbone-feed-sync",
    "ospd-openvas",
    "notus-scanner",
];

pub(crate) fn build_meta(name: &str) -> Option<&'static BuildMeta> {
    BUILD_META.iter().find(|meta| meta.name == name)
}

pub fn command_deps(repo_root: &Path, component: Option<&str>) -> ResultEnvelope {
    command_deps_with_runner(repo_root, component, &SystemCommandRunner)
}

fn command_deps_with_runner(
    repo_root: &Path,
    component: Option<&str>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let selected = match component {
        Some(name) => match BUILD_META.iter().find(|meta| meta.name == name) {
            Some(meta) => vec![meta],
            None => {
                return make_result(
                    metadata(repo_root, "deps", runner),
                    format!("Unknown component {name}."),
                    vec![Finding::new(
                        "fail",
                        "component.known",
                        format!("Unknown component {name}."),
                    )],
                );
            }
        },
        None => BUILD_META.iter().collect(),
    };
    let environment = build_env(repo_root);
    let cwd = env::current_dir().unwrap_or_else(|_| repo_root.to_path_buf());
    let mut findings = Vec::new();
    for meta in selected {
        findings.push(
            Finding::new(
                "pass",
                "build.metadata",
                format!("{}: {}", meta.name, meta.build_system),
            )
            .with_path(&format!("components/{}", meta.name))
            .with_details(json!({
                "order": meta.order,
                "package_hints": meta.package_hints,
            })),
        );
        for program in meta.programs {
            let found = executable_path(program);
            let message = found.as_ref().map_or_else(
                || format!("{}: {program} not found", meta.name),
                |path| format!("{}: {program} at {}", meta.name, path.display()),
            );
            findings.push(
                Finding::new(
                    if found.is_some() { "pass" } else { "fail" },
                    "program.available",
                    message,
                )
                .with_details(json!({ "component": meta.name, "program": program })),
            );
            if let Some(version) = tool_version(runner, program, &cwd) {
                findings.push(
                    Finding::new(
                        "pass",
                        "program.version",
                        format!("{}: {program} {version}", meta.name),
                    )
                    .with_details(json!({
                        "component": meta.name,
                        "program": program,
                        "version": version,
                    })),
                );
            }
        }
        for module in meta.pkg_config {
            let version = pkg_config_version(runner, module, &cwd, &environment);
            let message = version.as_ref().map_or_else(
                || format!("{}: {module} not found", meta.name),
                |version| format!("{}: {module} {version}", meta.name),
            );
            findings.push(
                Finding::new(
                    if version.is_some() { "pass" } else { "fail" },
                    "pkg-config.module",
                    message,
                )
                .with_details(json!({ "component": meta.name, "module": module })),
            );
        }
        if meta.build_system == "node-npm" {
            let node_version = tool_version(runner, "node", &cwd);
            let npm_version = tool_version(runner, "npm", &cwd);
            let node_ok = node_version
                .as_deref()
                .is_some_and(|version| version_tuple(version) >= vec![22, 0]);
            let npm_ok = npm_version
                .as_deref()
                .is_some_and(|version| version_tuple(version) >= vec![11, 0]);
            findings.push(
                Finding::new(
                    if node_ok { "pass" } else { "fail" },
                    "node.version",
                    format!(
                        "{}: node {}; required >=22.0",
                        meta.name,
                        node_version.as_deref().unwrap_or("not found")
                    ),
                )
                .with_details(json!({
                    "component": meta.name,
                    "required": ">=22.0",
                    "actual": node_version,
                })),
            );
            findings.push(
                Finding::new(
                    if npm_ok { "pass" } else { "fail" },
                    "npm.version",
                    format!(
                        "{}: npm {}; required >=11.0",
                        meta.name,
                        npm_version.as_deref().unwrap_or("not found")
                    ),
                )
                .with_details(json!({
                    "component": meta.name,
                    "required": ">=11.0",
                    "actual": npm_version,
                })),
            );
        }
    }
    make_result(
        metadata(repo_root, "deps", runner),
        "Dependency readiness checked.".to_string(),
        findings,
    )
}

fn pkg_config_version(
    runner: &dyn CommandRunner,
    module: &str,
    cwd: &Path,
    environment: &std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Option<String> {
    runner
        .run_with(
            "pkg-config",
            &["--modversion", module],
            Some(cwd),
            Some(environment),
            None,
        )
        .filter(|output| output.success)
        .map(|output| output.stdout.trim().to_string())
}

fn tool_version(runner: &dyn CommandRunner, program: &str, cwd: &Path) -> Option<String> {
    let args: &[&str] = match program {
        "clang" | "cmake" | "gcc" | "ld" | "node" | "npm" | "python3" | "readelf" | "uv" => {
            &["--version"]
        }
        _ => return None,
    };
    executable_path(program)?;
    runner
        .run_with(program, args, Some(cwd), None, None)
        .filter(|output| output.success)
        .and_then(|output| output.stdout.trim().lines().next().map(str::to_string))
}

fn version_tuple(version: &str) -> Vec<u64> {
    version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map_while(|piece| {
            let digits = piece
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
            (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_component_without_probing_dependencies() {
        let result = command_deps(Path::new("/not/a/repository"), Some("unknown"));
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "component.known");
    }

    #[test]
    fn parses_node_style_versions() {
        assert_eq!(version_tuple("v22.14.0"), vec![22, 14, 0]);
        assert_eq!(version_tuple("11.2.0-beta"), vec![11, 2, 0]);
        assert!(version_tuple("v22.1") >= vec![22, 0]);
    }

    #[test]
    fn build_only_metadata_matches_the_characterized_contract() {
        assert_eq!(
            build_meta("gvm-libs").expect("gvm-libs").cmake_args,
            ["-DBUILD_TESTS=OFF"]
        );
        assert!(
            build_meta("gvm-libs")
                .expect("gvm-libs")
                .install_for_dependents
        );
        assert_eq!(
            build_meta("openvas-scanner")
                .expect("openvas-scanner")
                .cmake_args,
            ["-DCMAKE_C_FLAGS=-isystem /usr/include/mit-krb5"]
        );
        assert_eq!(
            build_meta("gvmd").expect("gvmd").cmake_args,
            [
                "-DENABLE_AGENTS=0",
                "-DENABLE_JWT_AUTH=0",
                "-DENABLE_OPENVASD=0",
            ]
        );
        assert_eq!(build_meta("gsa").expect("gsa").node_scripts, ["build"]);
        assert_eq!(
            build_meta("ospd-openvas")
                .expect("ospd-openvas")
                .python_imports,
            ["ospd", "ospd_openvas"]
        );
        assert!(
            BUILD_META
                .iter()
                .all(|meta| meta.python_local_deps.is_empty())
        );
    }

    #[test]
    fn build_chains_preserve_dependency_order() {
        assert_eq!(CORE_C_CHAIN, ["gvm-libs", "openvas-smb", "openvas-scanner"]);
        assert_eq!(&BASELINE_CHAIN[..C_SERVICES_CHAIN.len()], C_SERVICES_CHAIN);
        assert_eq!(&BASELINE_CHAIN[7..], PYTHON_CHAIN);
    }
}
