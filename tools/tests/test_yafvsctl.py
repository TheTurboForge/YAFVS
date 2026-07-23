# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import csv
import hashlib
import inspect
import io
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
from pathlib import Path


METRIC_FIXTURE_HOSTS = [
    {"host": "192.0.2.10", "credential_path": True, "auth_success": True, "auth_failure": True, "source_reports": {"raw-a"}},
    {"host": "192.0.2.11", "credential_path": True, "auth_success": False, "auth_failure": True, "source_reports": {"raw-b"}},
    {"host": "192.0.2.12", "credential_path": True, "auth_success": False, "auth_failure": False, "source_reports": {"raw-b"}},
    {"host": "192.0.2.13", "credential_path": False, "auth_success": False, "auth_failure": False, "source_reports": {"raw-c"}},
    {"host": "192.0.2.99", "credential_path": True, "auth_success": True, "auth_failure": False, "source_reports": {"raw-extra"}},
]

METRIC_FIXTURE_RESULTS = [
    {"host": "192.0.2.10", "nvt": "nvt-a", "name": "Shared high finding", "severity": 7.0, "source_report": "raw-a", "port": "80/tcp"},
    {"host": "192.0.2.10", "nvt": "nvt-a", "name": "Shared high finding", "severity": 7.0, "source_report": "raw-a", "port": "443/tcp"},
    {"host": "192.0.2.10", "nvt": "nvt-b", "name": "Single medium finding", "severity": 4.0, "source_report": "raw-a", "port": "22/tcp"},
    {"host": "192.0.2.10", "nvt": "nvt-log", "name": "Log row", "severity": 0.0, "source_report": "raw-a", "port": "general/tcp"},
    {"host": "192.0.2.10", "nvt": "nvt-error", "name": "Scanner execution error", "severity": 9.0, "source_report": "raw-a", "scanner_error": True},
    {"host": "192.0.2.10", "nvt": "nvt-fp", "name": "False positive row", "severity": 9.0, "source_report": "raw-a", "false_positive": True},
    {"host": "192.0.2.11", "nvt": "nvt-a", "name": "Shared high finding", "severity": 7.0, "source_report": "raw-b", "port": "80/tcp"},
    {"host": "192.0.2.12", "nvt": "nvt-c", "name": "Low finding", "severity": 1.0, "source_report": "raw-b", "port": "161/udp"},
    {"host": "192.0.2.99", "nvt": "nvt-d", "name": "Global-only finding", "severity": 10.0, "source_report": "raw-extra", "port": "443/tcp"},
]


def metric_contract(scope_hosts=None):
    scope = {host.lower() for host in scope_hosts} if scope_hosts is not None else None

    def included_host(host):
        return scope is None or host.lower() in scope

    hosts = [host for host in METRIC_FIXTURE_HOSTS if included_host(host["host"])]
    findings = [
        result
        for result in METRIC_FIXTURE_RESULTS
        if included_host(result["host"])
        and result.get("severity", 0) > 0
        and not result.get("scanner_error", False)
        and not result.get("false_positive", False)
    ]

    by_system = {host["host"].lower(): {} for host in hosts}
    for result in findings:
        host_key = result["host"].lower()
        nvt = result["nvt"]
        current = by_system.setdefault(host_key, {}).get(nvt)
        if current is None or result["severity"] > current["severity"]:
            by_system[host_key][nvt] = {
                "name": result["name"],
                "severity": result["severity"],
                "source_reports": {result["source_report"]},
            }
        else:
            current["source_reports"].add(result["source_report"])

    systems = []
    for host in hosts:
        host_key = host["host"].lower()
        vulns = by_system.get(host_key, {})
        if host["auth_success"]:
            auth_state = "authenticated"
        elif host["auth_failure"]:
            auth_state = "authentication_failed"
        elif host["credential_path"]:
            auth_state = "unknown"
        else:
            auth_state = "no_credential_path"
        systems.append(
            {
                "host": host["host"],
                "cvss_load": sum(item["severity"] for item in vulns.values()),
                "max_cvss": max([item["severity"] for item in vulns.values()] or [0.0]),
                "vulnerability_count": len(vulns),
                "authentication_state": auth_state,
                "source_report_count": len(host["source_reports"]),
            }
        )

    vulnerability_map = {}
    for host_key, vulns in by_system.items():
        for nvt, item in vulns.items():
            entry = vulnerability_map.setdefault(
                nvt,
                {"nvt": nvt, "name": item["name"], "cvss_score": item["severity"], "hosts": set(), "source_reports": set()},
            )

            entry["cvss_score"] = max(entry["cvss_score"], item["severity"])
            entry["hosts"].add(host_key)
            entry["source_reports"].update(item["source_reports"])

    alive_count = len(systems)
    vulnerabilities = []
    for entry in vulnerability_map.values():
        affected = len(entry["hosts"])
        cvss_load = entry["cvss_score"] * affected
        vulnerabilities.append(
            {
                "nvt": entry["nvt"],
                "name": entry["name"],
                "cvss_score": entry["cvss_score"],
                "affected_system_count": affected,
                "cvss_load": cvss_load,
                "average_contribution": cvss_load / alive_count if alive_count else 0.0,
                "source_report_count": len(entry["source_reports"]),
            }
        )

    systems.sort(key=lambda system: (-system["cvss_load"], system["host"]))
    vulnerabilities.sort(key=lambda vuln: (-vuln["cvss_load"], -vuln["cvss_score"], vuln["name"]))
    auth_counts = {state: sum(1 for system in systems if system["authentication_state"] == state) for state in ("authenticated", "authentication_failed", "no_credential_path", "unknown")}
    total_load = sum(system["cvss_load"] for system in systems)
    return {
        "summary": {
            "alive_system_count": alive_count,
            "total_system_cvss_load": total_load,
            "average_system_cvss_load": total_load / alive_count if alive_count else 0.0,
            "vulnerability_count": len(vulnerabilities),
            "authenticated_system_count": auth_counts["authenticated"],
            "authentication_failed_system_count": auth_counts["authentication_failed"],
            "no_credential_path_system_count": auth_counts["no_credential_path"],
            "unknown_authentication_system_count": auth_counts["unknown"],
            "authenticated_scan_coverage_percent": (100.0 * auth_counts["authenticated"] / alive_count) if alive_count else 0.0,
        },
        "systems": systems,
        "vulnerabilities": vulnerabilities,
    }


YAFVSCTL_PATH = Path(__file__).resolve().parents[1] / "yafvsctl"
SPEC = importlib.util.spec_from_loader("yafvsctl", SourceFileLoader("yafvsctl", str(YAFVSCTL_PATH)))
yafvsctl = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["yafvsctl"] = yafvsctl
SPEC.loader.exec_module(yafvsctl)

GMP_SMOKE_PATH = Path(__file__).resolve().parents[1] / "runtime_gmp_smoke.py"
GMP_SPEC = importlib.util.spec_from_loader("runtime_gmp_smoke", SourceFileLoader("runtime_gmp_smoke", str(GMP_SMOKE_PATH)))
runtime_gmp_smoke = importlib.util.module_from_spec(GMP_SPEC)
assert GMP_SPEC.loader is not None
sys.modules["runtime_gmp_smoke"] = runtime_gmp_smoke
GMP_SPEC.loader.exec_module(runtime_gmp_smoke)

FULL_TEST_SCAN_PATH = Path(__file__).resolve().parents[1] / "runtime_full_test_scan.py"
FULL_TEST_SCAN_SPEC = importlib.util.spec_from_loader("runtime_full_test_scan", SourceFileLoader("runtime_full_test_scan", str(FULL_TEST_SCAN_PATH)))
runtime_full_test_scan = importlib.util.module_from_spec(FULL_TEST_SCAN_SPEC)
assert FULL_TEST_SCAN_SPEC.loader is not None
sys.modules["runtime_full_test_scan"] = runtime_full_test_scan
FULL_TEST_SCAN_SPEC.loader.exec_module(runtime_full_test_scan)
TEST_FULL_TEST_TARGET = runtime_full_test_scan.parse_full_test_target("192.0.2.0/24")


def credential_smoke_material_run(command, **kwargs):
    if len(command) > 1 and command[1] == "genpkey":
        Path(command[command.index("-out") + 1]).write_text(
            "synthetic client key fixture\n",
            encoding="utf-8",
        )
    if len(command) > 1 and command[1] == "req":
        Path(command[command.index("-out") + 1]).write_text(
            "-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n",
            encoding="utf-8",
        )
    return subprocess.CompletedProcess(command, 0, "")

RUNTIME_SCOPE_PATH = Path(__file__).resolve().parents[1] / "runtime_scope.py"
RUNTIME_SCOPE_SPEC = importlib.util.spec_from_loader("runtime_scope", SourceFileLoader("runtime_scope", str(RUNTIME_SCOPE_PATH)))
runtime_scope = importlib.util.module_from_spec(RUNTIME_SCOPE_SPEC)
assert RUNTIME_SCOPE_SPEC.loader is not None
sys.modules["runtime_scope"] = runtime_scope
RUNTIME_SCOPE_SPEC.loader.exec_module(runtime_scope)

RUNTIME_RBAC_PATH = Path(__file__).resolve().parents[1] / "runtime_rbac_smoke.py"
RUNTIME_RBAC_SPEC = importlib.util.spec_from_loader("runtime_rbac_smoke", SourceFileLoader("runtime_rbac_smoke", str(RUNTIME_RBAC_PATH)))
runtime_rbac_smoke = importlib.util.module_from_spec(RUNTIME_RBAC_SPEC)
assert RUNTIME_RBAC_SPEC.loader is not None
sys.modules["runtime_rbac_smoke"] = runtime_rbac_smoke
RUNTIME_RBAC_SPEC.loader.exec_module(runtime_rbac_smoke)

BROWSER_SMOKE_PATH = Path(__file__).resolve().parents[1] / "runtime_browser_smoke.py"
BROWSER_SMOKE_SPEC = importlib.util.spec_from_loader("runtime_browser_smoke", SourceFileLoader("runtime_browser_smoke", str(BROWSER_SMOKE_PATH)))
runtime_browser_smoke = importlib.util.module_from_spec(BROWSER_SMOKE_SPEC)
assert BROWSER_SMOKE_SPEC.loader is not None
sys.modules["runtime_browser_smoke"] = runtime_browser_smoke
BROWSER_SMOKE_SPEC.loader.exec_module(runtime_browser_smoke)

CREDENTIAL_SMOKE_PATH = Path(__file__).resolve().parents[1] / "runtime_credential_smoke.py"
CREDENTIAL_SMOKE_SPEC = importlib.util.spec_from_loader("runtime_credential_smoke", SourceFileLoader("runtime_credential_smoke", str(CREDENTIAL_SMOKE_PATH)))
runtime_credential_smoke = importlib.util.module_from_spec(CREDENTIAL_SMOKE_SPEC)
assert CREDENTIAL_SMOKE_SPEC.loader is not None
sys.modules["runtime_credential_smoke"] = runtime_credential_smoke
CREDENTIAL_SMOKE_SPEC.loader.exec_module(runtime_credential_smoke)


class YAFVSCtlTests(unittest.TestCase):
    def test_rust_runtime_data_state_bridge_accepts_valid_envelopes(self):
        for status, returncode in (("pass", 0), ("warn", 0), ("fail", 1)):
            payload = {
                "status": status,
                "summary": "data-state summary",
                "findings": [
                    {
                        "status": status,
                        "check": "data-state.example",
                        "message": "data-state result",
                    }
                ],
                "artifacts": ["data-state.json"],
                "details": {"database": {}},
                "metadata": {"command": "runtime-data-state"},
            }
            with self.subTest(status=status), unittest.mock.patch.object(
                yafvsctl,
                "run_command",
                return_value=subprocess.CompletedProcess(
                    ["cargo"], returncode, json.dumps(payload), "ignored stderr"
                ),
            ) as run_command:
                observed = yafvsctl.rust_runtime_data_state_result(Path("/tmp/TurboVAS"))

            self.assertEqual(observed, payload)
            self.assertEqual(
                run_command.call_args.args[0],
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--locked",
                    "--target-dir",
                    "/tmp/TurboVAS/build/yafvsctl-rs",
                    "--manifest-path",
                    "/tmp/TurboVAS/tools/yafvsctl-rs/Cargo.toml",
                    "--",
                    "runtime-data-state",
                    "--json",
                ],
            )
            self.assertEqual(run_command.call_args.kwargs["timeout"], 300)

    def test_rust_runtime_data_state_bridge_rejects_invalid_results(self):
        valid_item = {
            "status": "pass",
            "check": "data-state.example",
            "message": "data-state result",
        }
        valid_payload = {
            "status": "pass",
            "summary": "data-state summary",
            "findings": [valid_item],
            "artifacts": ["data-state.json"],
            "details": {"database": {}},
            "metadata": {"command": "runtime-data-state"},
        }
        secret = "SECRET_RUST_DATA_STATE_OUTPUT"
        cases = {
            "invalid-json": (0, f"not-json {secret}"),
            "duplicate-keys": (0, '{"status":"pass","status":"fail"}'),
            "oversized-stdout": (0, " " * (yafvsctl.YAFVSCTL_RUST_BRIDGE_MAX_OUTPUT_BYTES + 1)),
            "wrong-metadata": (0, json.dumps({**valid_payload, "metadata": {"command": "status"}})),
            "malformed-envelope-types": (0, json.dumps({**valid_payload, "artifacts": [1]})),
            "malformed-finding": (0, json.dumps({**valid_payload, "findings": [{**valid_item, "message": 1}]})),
            "aggregate-mismatch": (0, json.dumps({**valid_payload, "status": "warn"})),
            "bad-exit-code": (1, json.dumps(valid_payload)),
        }
        for name, (returncode, stdout) in cases.items():
            with self.subTest(name=name), unittest.mock.patch.object(
                yafvsctl,
                "run_command",
                return_value=subprocess.CompletedProcess(
                    ["cargo", "secret-command"], returncode, stdout, f"stderr {secret}"
                ),
            ):
                observed = yafvsctl.rust_runtime_data_state_result(Path("/tmp/TurboVAS"))

            self.assertEqual(observed["status"], "fail")
            self.assertEqual(observed["metadata"]["command"], "runtime-data-state")
            self.assertEqual(observed["findings"][0]["check"], "data-state.rust-bridge")
            self.assertNotIn(secret, str(observed))
            self.assertNotIn("secret-command", str(observed))
            self.assertNotIn(stdout, str(observed))

    def test_rust_runtime_data_state_bridge_handles_os_error(self):
        secret = "SECRET_RUST_DATA_STATE_EXCEPTION"
        with unittest.mock.patch.object(
            yafvsctl, "run_command", side_effect=OSError(secret)
        ):
            observed = yafvsctl.rust_runtime_data_state_result(Path("/tmp/TurboVAS"))

        self.assertEqual(observed["status"], "fail")
        self.assertEqual(observed["findings"][0]["check"], "data-state.rust-bridge")
        self.assertNotIn(secret, str(observed))

    def test_aggregate_status_prefers_highest_severity(self):
        findings = [
            {"status": "pass"},
            {"status": "warn"},
            {"status": "fail"},
        ]
        self.assertEqual(yafvsctl.aggregate_status(findings), "fail")

    def test_result_json_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = yafvsctl.make_result("status", root, "summary", [{"status": "pass", "check": "x", "message": "ok"}])
            encoded = json.dumps(result)
            decoded = json.loads(encoded)
            self.assertEqual(decoded["status"], "pass")
            self.assertIn("summary", decoded)
            self.assertIn("findings", decoded)
            self.assertIn("artifacts", decoded)
            self.assertIn("metadata", decoded)

    def test_deployed_app_env_reuses_running_hosts_by_default(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=True), unittest.mock.patch.object(
            yafvsctl,
            "runtime_app_env",
            return_value={yafvsctl.GSAD_HOSTS_ENV: yafvsctl.DEFAULT_GSAD_HOST},
        ), unittest.mock.patch.object(
            yafvsctl,
            "current_gsad_published_hosts",
            return_value=("192.0.2.10", "198.51.100.20"),
        ), unittest.mock.patch.object(
            yafvsctl,
            "current_native_api_direct_published_bindings",
            return_value=(),
        ):
            env = yafvsctl.deployed_app_env(Path("/tmp"))

        self.assertEqual(
            env[yafvsctl.GSAD_HOSTS_ENV], "192.0.2.10,198.51.100.20"
        )

    def test_deployed_app_env_preserves_explicit_hosts(self):
        explicit = "203.0.113.30"
        with unittest.mock.patch.dict(
            os.environ, {yafvsctl.GSAD_HOSTS_ENV: explicit}, clear=True
        ), unittest.mock.patch.object(
            yafvsctl,
            "runtime_app_env",
            return_value={yafvsctl.GSAD_HOSTS_ENV: explicit},
        ), unittest.mock.patch.object(
            yafvsctl, "current_gsad_published_hosts"
        ) as current_hosts, unittest.mock.patch.object(
            yafvsctl,
            "current_native_api_direct_published_bindings",
            return_value=(),
        ):
            env = yafvsctl.deployed_app_env(Path("/tmp"))

        self.assertEqual(env[yafvsctl.GSAD_HOSTS_ENV], explicit)
        current_hosts.assert_not_called()

    def test_deployed_app_env_reuses_running_direct_binding_by_default(self):
        binding = {
            "host": "127.0.0.1",
            "host_port": "19080",
            "container_port": yafvsctl.YAFVS_API_DIRECT_CONTAINER_PORT,
        }
        with unittest.mock.patch.dict(os.environ, {}, clear=True), unittest.mock.patch.object(
            yafvsctl,
            "runtime_app_env",
            return_value={},
        ), unittest.mock.patch.object(
            yafvsctl,
            "current_gsad_published_hosts",
            return_value=(),
        ), unittest.mock.patch.object(
            yafvsctl,
            "current_native_api_direct_published_bindings",
            return_value=(binding,),
        ), unittest.mock.patch.object(
            yafvsctl,
            "ensure_native_api_direct_runtime_env_defaults",
            side_effect=lambda _root, env: env.update(
                {
                    yafvsctl.YAFVS_API_DIRECT_ENV: "1",
                    yafvsctl.YAFVS_API_DIRECT_BIND_ENV: "0.0.0.0:9081",
                }
            )
            or env,
        ):
            env = yafvsctl.deployed_app_env(Path("/tmp"))

        self.assertEqual(env[yafvsctl.YAFVS_API_DIRECT_ENV], "1")
        self.assertEqual(env[yafvsctl.YAFVS_API_DIRECT_HOST_ENV], "127.0.0.1")
        self.assertEqual(env[yafvsctl.YAFVS_API_DIRECT_PORT_ENV], "19080")

    def test_deployed_app_env_preserves_explicit_direct_disable(self):
        with unittest.mock.patch.dict(
            os.environ, {yafvsctl.YAFVS_API_DIRECT_ENV: "0"}, clear=True
        ), unittest.mock.patch.object(
            yafvsctl,
            "runtime_app_env",
            return_value={yafvsctl.YAFVS_API_DIRECT_ENV: "0"},
        ), unittest.mock.patch.object(
            yafvsctl,
            "current_gsad_published_hosts",
            return_value=(),
        ), unittest.mock.patch.object(
            yafvsctl, "current_native_api_direct_published_bindings"
        ) as current_bindings:
            env = yafvsctl.deployed_app_env(Path("/tmp"))

        self.assertEqual(env[yafvsctl.YAFVS_API_DIRECT_ENV], "0")
        current_bindings.assert_not_called()

    def test_deployed_app_env_brackets_running_direct_ipv6_binding(self):
        binding = {
            "host": "::1",
            "host_port": "19080",
            "container_port": yafvsctl.YAFVS_API_DIRECT_CONTAINER_PORT,
        }
        with unittest.mock.patch.dict(os.environ, {}, clear=True), unittest.mock.patch.object(
            yafvsctl,
            "runtime_app_env",
            return_value={},
        ), unittest.mock.patch.object(
            yafvsctl,
            "current_gsad_published_hosts",
            return_value=(),
        ), unittest.mock.patch.object(
            yafvsctl,
            "current_native_api_direct_published_bindings",
            return_value=(binding,),
        ), unittest.mock.patch.object(
            yafvsctl,
            "ensure_native_api_direct_runtime_env_defaults",
            side_effect=lambda _root, env: env.update(
                {
                    yafvsctl.YAFVS_API_DIRECT_ENV: "1",
                    yafvsctl.YAFVS_API_DIRECT_BIND_ENV: "0.0.0.0:9081",
                }
            )
            or env,
        ):
            env = yafvsctl.deployed_app_env(Path("/tmp"))

        self.assertEqual(env[yafvsctl.YAFVS_API_DIRECT_HOST_ENV], "[::1]")
        self.assertEqual(
            yafvsctl.native_api_direct_port_binding(env),
            "[::1]:19080:9081",
        )
        self.assertEqual(yafvsctl.native_api_direct_config_errors(env), ())

    def test_native_api_direct_runtime_env_preserves_deployed_hosts(self):
        deployed = {yafvsctl.GSAD_HOSTS_ENV: "192.0.2.10,198.51.100.20"}
        with unittest.mock.patch.object(
            yafvsctl, "deployed_app_env", return_value=deployed
        ) as deployed_env, unittest.mock.patch.object(
            yafvsctl,
            "ensure_native_api_direct_runtime_env_defaults",
            side_effect=lambda _root, env: env,
        ):
            env = yafvsctl.native_api_direct_runtime_env(Path("/tmp"))

        self.assertEqual(
            env[yafvsctl.GSAD_HOSTS_ENV], deployed[yafvsctl.GSAD_HOSTS_ENV]
        )
        deployed_env.assert_called_once_with(Path("/tmp"))

    def test_direct_write_smoke_validates_receipt_before_enabling_direct_api(self):
        source = Path(yafvsctl.__file__).read_text(encoding="utf-8")
        start = source.index(
            "def _command_runtime_native_api_direct_write_smoke_unlocked"
        )
        body = source[
            start : source.index(
                "\ndef command_runtime_native_api_direct_write_smoke", start
            )
        ]

        deployed_index = body.index("deployed_env = deployed_app_env(repo_root)")
        target_index = body.index(
            "base_env = ensure_native_api_direct_runtime_env_defaults("
        )
        receipt_index = body.index(
            "require_app_deployment_receipt(\n        repo_root, app_env=deployed_env"
        )
        self.assertLess(deployed_index, target_index)
        self.assertLess(target_index, receipt_index)
        self.assertNotIn(
            "require_app_deployment_receipt(\n        repo_root, app_env=base_env",
            body,
        )

    def test_gsad_ports_override_uses_passed_deployment_environment(self):
        env = {
            yafvsctl.GSAD_HOSTS_ENV: "192.0.2.10,198.51.100.20",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = yafvsctl.ensure_gsad_ports_override(Path(tmp), env)
            content = path.read_text(encoding="utf-8")

        self.assertIn("192.0.2.10:19392:9392", content)
        self.assertIn("198.51.100.20:19392:9392", content)
        self.assertNotIn("127.0.0.1:19392:9392", content)

    def test_direct_smoke_status_only_keeps_signal_without_pass_payloads(self):
        result = {
            "status": "warn",
            "summary": "Direct native API smoke checks completed.",
            "artifacts": ["/tmp/native-api-direct-smoke.json", "/tmp/native-api-smoke.json"],
            "details": {
                "base_url": "http://127.0.0.1:8081",
                "container_bind": "127.0.0.1:8081:8080",
                "token_source": "runtime-secret-file",
                "direct_request_example": "tools/yafvsctl native-api-request --direct --json --path '/api/v1/reports?page_size=1'",
            },
            "findings": [
                {
                    "status": "pass",
                    "check": "native-api-direct.valid-token",
                    "message": "Direct native API accepts the configured bearer token and returns JSON.",
                    "details": {"response_json": {"items": [{"id": "r1"}]}, "output_tail": "large"},
                },
                {
                    "status": "pass",
                    "check": "native-api-direct.scope-write-disabled",
                    "message": "Direct native API rejects scope writes while direct write-control is disabled.",
                    "details": {"http_status": 405, "response_json": {"error": {"code": "method_not_allowed"}}},
                },
                {
                    "status": "pass",
                    "check": "native-api-direct.port-list-patch-disabled",
                    "message": "Direct native API rejects port-list patches while direct write-control is disabled.",
                    "details": {"http_status": 405, "response_json": {"error": {"code": "method_not_allowed"}}},
                },
                {
                    "status": "pass",
                    "check": "native-api-direct.port-list-delete-disabled",
                    "message": "Direct native API rejects port-list deletes while direct write-control is disabled.",
                    "details": {"http_status": 405, "response_json": {"error": {"code": "method_not_allowed"}}},
                },
                {
                    "status": "pass",
                    "check": "native-api-direct.port-list-hard-delete-disabled",
                    "message": "Direct native API rejects port-list hard deletes while direct write-control is disabled.",
                    "details": {"http_status": 405, "response_json": {"error": {"code": "method_not_allowed"}}},
                },
                {
                    "status": "pass",
                    "check": "native-api-direct.schedule-patch-disabled",
                    "message": "Direct native API rejects schedule patches while direct write-control is disabled.",
                    "details": {"http_status": 405, "response_json": {"error": {"code": "method_not_allowed"}}},
                },
                {
                    "status": "pass",
                    "check": "native-api-direct.schedule-restore-disabled",
                    "message": "Direct native API rejects schedule restores while direct write-control is disabled.",
                    "details": {"http_status": 405, "response_json": {"error": {"code": "method_not_allowed"}}},
                },
                {
                    "status": "pass",
                    "check": "native-api-direct.override-patch-disabled",
                    "message": "Direct native API rejects override patches while direct write-control is disabled.",
                    "details": {"http_status": 405, "response_json": {"error": {"code": "method_not_allowed"}}},
                },
                {
                    "status": "warn",
                    "check": "native-api.internal-smoke",
                    "message": "Internal smoke skipped optional detail probes.",
                    "details": {"status": "warn", "artifacts": ["/tmp/a.json", "/tmp/b.json"]},
                },
            ],
        }

        compact = yafvsctl.direct_smoke_status_only_result(result)

        self.assertEqual(compact["status"], "warn")
        self.assertEqual(compact["details"]["finding_count"], 9)
        self.assertEqual(compact["details"]["non_pass_count"], 1)
        self.assertEqual(compact["details"]["artifact_count"], 2)
        self.assertEqual(compact["details"]["important_checks"]["native-api-direct.valid-token"], "pass")
        self.assertEqual(compact["details"]["important_checks"]["native-api-direct.scope-write-disabled"], "pass")
        self.assertEqual(compact["details"]["important_checks"]["native-api-direct.port-list-patch-disabled"], "pass")
        self.assertEqual(compact["details"]["important_checks"]["native-api-direct.port-list-delete-disabled"], "pass")
        self.assertEqual(compact["details"]["important_checks"]["native-api-direct.port-list-hard-delete-disabled"], "pass")
        self.assertEqual(compact["details"]["important_checks"]["native-api-direct.schedule-patch-disabled"], "pass")
        self.assertEqual(compact["details"]["important_checks"]["native-api-direct.schedule-restore-disabled"], "pass")
        self.assertEqual(compact["details"]["important_checks"]["native-api-direct.override-patch-disabled"], "pass")
        self.assertEqual(compact["details"]["important_checks"]["native-api.internal-smoke"], "warn")
        self.assertEqual(len(compact["findings"]), 1)
        self.assertEqual(compact["findings"][0]["check"], "native-api.internal-smoke")
        self.assertEqual(compact["findings"][0]["details"]["artifacts"], {"type": "list", "count": 2})
        self.assertNotIn("response_json", json.dumps(compact))

    def test_runtime_app_up_is_owned_directly_by_rust(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "feed_generation"
            / "app_up.rs"
        ).read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        recipe = justfile.split("runtime-app-up *args:\n", 1)[1].split(
            "\n\n", 1
        )[0]
        for surface in (
            'add_parser("runtime-app-up"',
            'args.command == "runtime-app-up"',
            "def command_runtime_app_up",
            "def _command_runtime_app_up_unlocked",
            "def compose_app_services_up_with_retry",
            "def runtime_app_up_status_only_result",
        ):
            self.assertNotIn(surface, python_source)
        self.assertIn("command_runtime_app_up", rust_source)
        self.assertIn("RuntimeOperationLock::acquire", rust_source)
        self.assertIn("FEED_ACTIVATION_LOCK", rust_source)
        self.assertIn("cargo run --quiet --locked", recipe)
        self.assertIn('-- runtime-app-up "$@"', recipe)
        self.assertNotIn("tools/yafvsctl ", recipe)

    def test_runtime_scanner_register_is_owned_directly_by_rust(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_scanner_register.rs"
        ).read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        recipe = justfile.split("runtime-scanner-register *args:\n", 1)[1].split(
            "\n\n", 1
        )[0]
        for surface in (
            'add_parser("runtime-scanner-register"',
            'args.command == "runtime-scanner-register"',
            "def command_runtime_scanner_register",
            "def _command_runtime_scanner_register_unlocked",
        ):
            self.assertNotIn(surface, python_source)
        self.assertIn("command_runtime_scanner_register", rust_source)
        self.assertIn("RuntimeOperationLock::acquire", rust_source)
        self.assertIn("FEED_ACTIVATION_LOCK", rust_source)
        self.assertIn("ENSURE_DEFAULT_SCANNER_SQL", rust_source)
        self.assertIn("ON CONFLICT (uuid) DO UPDATE", rust_source)
        self.assertIn("container_native_get", rust_source)
        self.assertIn("%{http_code}", rust_source)
        self.assertIn("BROWSER_PROXY_VERIFY_SCRIPT", rust_source)
        self.assertIn("YAFVS_API_BROWSER_PROXY_SECRET", rust_source)
        self.assertIn("SCANNER_VERIFY_PATH", rust_source)
        self.assertNotIn("run_pinned_gvmd", rust_source)
        self.assertNotIn("command_runtime_gmp_smoke", rust_source)
        self.assertNotIn("--get-scanners", rust_source)
        self.assertNotIn("--verify-scanner", rust_source)
        self.assertIn("cargo run --quiet --locked", recipe)
        self.assertIn('-- runtime-scanner-register "$@"', recipe)
        self.assertNotIn("tools/yafvsctl ", recipe)

    def test_feed_lifecycle_lock_serializes_stage_and_runtime_mutations(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(
            encoding="utf-8"
        )
        for function_name in ("command_runtime_native_api_direct_write_smoke",):
            start = source.index(f"def {function_name}")
            body = source[start : source.find("\ndef ", start + 5)]
            self.assertIn("acquire_runtime_lock", body)
            self.assertIn("FEED_ACTIVATION_LOCK", body)

        direct_smoke_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_native_api_direct_smoke.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RuntimeOperationLock::acquire", direct_smoke_source)
        self.assertIn("FEED_ACTIVATION_LOCK", direct_smoke_source)

        build_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "build.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RuntimeOperationLock::acquire", build_source)
        self.assertIn("FEED_ACTIVATION_LOCK", build_source)

        rebuild_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "feed_generation"
            / "native_api_rebuild.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RuntimeOperationLock::acquire", rebuild_source)
        self.assertIn("FEED_ACTIVATION_LOCK", rebuild_source)

        rust_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime.rs"
        ).read_text(encoding="utf-8")
        for function_name in (
            "command_down_with_runner_and_timeout",
            "command_runtime_app_down_with_runner_and_timeout",
        ):
            start = rust_source.index(f"fn {function_name}")
            body = rust_source[start : rust_source.find("\nfn ", start + 5)]
            self.assertIn("RuntimeOperationLock::acquire", body)
            self.assertIn("FEED_ACTIVATION_LOCK", body)

        gvmd_smoke_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "gvmd_smoke.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RuntimeOperationLock::acquire", gvmd_smoke_source)
        self.assertIn("FEED_ACTIVATION_LOCK", gvmd_smoke_source)

        scanner_redis_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_scanner_redis.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RuntimeOperationLock::acquire", scanner_redis_source)
        self.assertIn("FEED_ACTIVATION_LOCK", scanner_redis_source)

        scanner_register_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_scanner_register.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RuntimeOperationLock::acquire", scanner_register_source)
        self.assertIn("FEED_ACTIVATION_LOCK", scanner_register_source)

        runtime_manager_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_manager_init.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RuntimeOperationLock::acquire", runtime_manager_source)
        self.assertIn("FEED_ACTIVATION_LOCK", runtime_manager_source)
        self.assertIn("RUNTIME_MANAGER_LOCK", runtime_manager_source)

        app_up_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "feed_generation"
            / "app_up.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("RuntimeOperationLock::acquire", app_up_source)
        self.assertIn("FEED_ACTIVATION_LOCK", app_up_source)





    def assert_rust_yafvsctl_parity(
        self,
        argument_sets,
        *,
        rust_only_contracts=(),
        complete_surface=False,
        human_inventory=False,
        non_repository_status=False,
    ):
        repo_root = Path(__file__).resolve().parents[2]
        manifest = repo_root / "tools" / "yafvsctl-rs" / "Cargo.toml"
        target_dir = repo_root / "build" / "yafvsctl-rs"

        if complete_surface:
            reference = (repo_root / "docs" / "CLI_REFERENCE.md").read_text(encoding="utf-8")
            documented = {
                line.strip()
                for line in reference.split("<!-- rust-cli-commands:start -->", 1)[1]
                .split("<!-- rust-cli-commands:end -->", 1)[0]
                .splitlines()
                if line.strip() and not line.strip().startswith("```")
            }
            covered = {
                arguments[0]
                for arguments in argument_sets
            }
            covered.update(arguments[0] for arguments, _exit_code, _status in rust_only_contracts)
            self.assertEqual(covered, documented)

        def invoke(command, arguments, *, env=None):
            completed = subprocess.run(
                command + arguments,
                cwd=repo_root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            return completed

        def normalized_json(completed):
            payload = json.loads(completed.stdout)
            payload["metadata"].pop("generated_at", None)
            return payload

        python_command = [sys.executable, str(repo_root / "tools" / "yafvsctl")]
        rust_build_command = [
            "cargo",
            "build",
            "--quiet",
            "--locked",
            "--target-dir",
            str(target_dir),
            "--manifest-path",
            str(manifest),
        ]
        build = invoke(rust_build_command, [])
        self.assertEqual(build.returncode, 0, build.stderr)
        rust_command = [str(target_dir / "debug" / "yafvsctl")]
        with tempfile.TemporaryDirectory() as parity_runtime:
            feed_generation_env = os.environ.copy()
            feed_generation_env["YAFVS_RUNTIME_DIR"] = parity_runtime
            for arguments in argument_sets:
                env = feed_generation_env if arguments[0] in {"feed-generation-state", "feed-generation-stage"} else None
                python_result = invoke(python_command, arguments, env=env)
                rust_result = invoke(rust_command, arguments, env=env)
                self.assertEqual(python_result.returncode, rust_result.returncode, arguments)
                self.assertEqual(
                    normalized_json(python_result),
                    normalized_json(rust_result),
                    arguments,
                )
            for arguments, expected_exit_code, expected_status in rust_only_contracts:
                env = feed_generation_env.copy()
                if arguments[0] == "quality-gate-schedule":
                    env.pop("YAFVS_ENABLE_QUALITY_GATE_SCHEDULE", None)
                if arguments[0] in {"runtime-status", "runtime-smoke", "gvmd-smoke", "runtime-app-smoke", "runtime-native-api-smoke", "runtime-native-api-direct-smoke", "runtime-redis-state", "runtime-data-state", "runtime-db-introspect", "runtime-performance-snapshot", "runtime-report-summary", "runtime-report-export", "runtime-report-metrics", "runtime-scope-report-summary", "runtime-scope-report-metrics"}:
                    env["COMPOSE_PROJECT_NAME"] = "yafvsctl-parity-no-runtime"
                if arguments[0] in {
                    "up",
                    "runtime-init",
                    "runtime-manager-init",
                    "runtime-scanner-redis-init",
                    "runtime-scanner-register",
                    "runtime-app-build",
                    "runtime-native-api-rebuild",
                    "runtime-app-up",
                    "build-core-c",
                    "build-c-services",
                    "build-ui",
                    "build-python",
                    "build-baseline",
                }:
                    blocked_runtime = Path(parity_runtime) / arguments[0]
                    blocked_runtime.write_text(
                        "force runtime setup to fail before Docker\n",
                        encoding="utf-8",
                    )
                    env["YAFVS_RUNTIME_DIR"] = str(blocked_runtime)
                if arguments[0] in {"down", "runtime-app-down"}:
                    shutdown_runtime = Path(parity_runtime) / arguments[0]
                    shutdown_runtime.mkdir()
                    (shutdown_runtime / "run").write_text(
                        "force the lifecycle lock to fail closed before Docker\n",
                        encoding="utf-8",
                    )
                    env["YAFVS_RUNTIME_DIR"] = str(shutdown_runtime)
                if arguments[0] == "runtime-webui-smoke":
                    env["YAFVS_GSAD_HOSTS"] = "127.0.0.1:1"
                if arguments[0] == "runtime-native-api-direct-bootstrap":
                    for name in (
                        yafvsctl.YAFVS_API_DIRECT_ENV,
                        yafvsctl.YAFVS_API_DIRECT_HOST_ENV,
                        yafvsctl.YAFVS_API_DIRECT_PORT_ENV,
                        yafvsctl.YAFVS_API_DIRECT_BIND_ENV,
                        yafvsctl.YAFVS_API_BEARER_TOKEN_ENV,
                        yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV,
                    ):
                        env.pop(name, None)
                if arguments[0] == "runtime-feed-keyring-init":
                    keyring_runtime = Path(parity_runtime) / "runtime-feed-keyring-init"
                    key_artifact = (
                        keyring_runtime
                        / "artifacts"
                        / "feed-keyring"
                        / "GBCommunitySigningKey.asc"
                    )
                    key_artifact.parent.mkdir(parents=True)
                    outside_key = keyring_runtime / "unsafe-linked-key"
                    outside_key.write_text("not a trusted key\n", encoding="utf-8")
                    key_artifact.symlink_to(outside_key)
                    env["YAFVS_RUNTIME_DIR"] = str(keyring_runtime)
                if arguments[0] == "feed-cache-sync":
                    feed_sync_runtime = Path(parity_runtime) / "feed-cache-sync"
                    feed_sync_runtime.write_text(
                        "force directory preparation to fail before self-test or tmux\n",
                        encoding="utf-8",
                    )
                    env["YAFVS_RUNTIME_DIR"] = str(feed_sync_runtime)
                rust_result = invoke(rust_command, arguments, env=env)
                expected_exit_codes = (
                    expected_exit_code
                    if isinstance(expected_exit_code, tuple)
                    else (expected_exit_code,)
                )
                self.assertIn(
                    rust_result.returncode,
                    expected_exit_codes,
                    {
                        "arguments": arguments,
                        "stdout": rust_result.stdout,
                        "stderr": rust_result.stderr,
                    },
                )
                payload = normalized_json(rust_result)
                expected_statuses = (
                    expected_status
                    if isinstance(expected_status, tuple)
                    else (expected_status,)
                )
                self.assertIn(
                    payload["status"],
                    expected_statuses,
                    {"arguments": arguments, "payload": payload},
                )
                self.assertEqual(payload["metadata"]["command"], arguments[0], arguments)

        if human_inventory:
            human_arguments = ["inventory", "--scope", "components/gsa"]
            rust_result = invoke(rust_command, human_arguments)
            self.assertEqual(rust_result.returncode, 0)
            self.assertEqual(
                rust_result.stdout,
                "PASS: Inventory contains 1 expected component(s).\n"
                "[pass] component.exists: gsa: web user interface (components/gsa)\n",
            )

        if non_repository_status:
            with tempfile.TemporaryDirectory() as tmp:
                rust_result = subprocess.run(
                    rust_command + ["status", "--json"],
                    cwd=tmp,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            self.assertEqual(rust_result.returncode, 1)
            payload = normalized_json(rust_result)
            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["metadata"]["command"], "status")
            self.assertEqual(
                {item["check"]: item["status"] for item in payload["findings"]},
                {
                    "git.repository": "fail",
                    "git.head": "fail",
                    "git.upstream": "warn",
                    "git.worktree": "fail",
                },
            )

    def test_rust_yafvsctl_matches_python_migrated_command_contracts(self):
        self.assert_rust_yafvsctl_parity(
            (),
            rust_only_contracts=(
                (["status", "--json"], 0, ("pass", "warn")),
                (["license-report", "--json"], 0, "pass"),
                (["inventory", "--json"], 0, "pass"),
                (["inventory", "--scope", "components/gsa", "--json"], 0, "pass"),
                (["inventory", "--scope", "definitely-invalid", "--json"], 0, "warn"),
                (["branding-state", "--json"], 0, "pass"),
                (["rust-migration-state", "--json"], (0, 1), ("pass", "fail")),
                (["gvmd-retirement-state", "--json"], 0, "pass"),
                (["deps", "--json"], (0, 1), ("pass", "fail")),
                (["deps", "gsa", "--json"], 0, "pass"),
                (["deps", "definitely-invalid", "--json"], 1, "fail"),
                (["configure", "definitely-invalid", "--json"], 1, "fail"),
                (["build", "definitely-invalid", "--json"], 1, "fail"),
                (["build-core-c", "--json"], 1, "fail"),
                (["build-c-services", "--json"], 1, "fail"),
                (["build-ui", "--json"], 1, "fail"),
                (["build-python", "--json"], 1, "fail"),
                (["build-baseline", "--json"], 1, "fail"),
                (["runtime-plan", "--json"], 0, "warn"),
                (["runtime-status", "--json"], 0, "warn"),
                (["runtime-smoke", "--json"], 1, "fail"),
                (["gvmd-smoke", "--json"], 1, "fail"),
                (["up", "--json"], 1, "fail"),
                (["runtime-init", "--json"], 1, "fail"),
                (["runtime-manager-init", "--json"], 1, "fail"),
                (["runtime-scanner-redis-init", "--json"], 1, "fail"),
                (["runtime-scanner-register", "--json"], 1, "fail"),
                (["runtime-app-build", "--json"], 1, "fail"),
                (["runtime-app-smoke", "--status-only", "--json"], 1, "fail"),
                (["runtime-native-api-smoke", "--status-only", "--json"], 1, "fail"),
                (["runtime-native-api-direct-smoke", "--status-only", "--json"], 1, "fail"),
                (["runtime-native-api-rebuild", "--json"], 1, "fail"),
                (["runtime-app-up", "--json"], 1, "fail"),
                (["runtime-app-up", "--status-only", "--json"], 1, "fail"),
                (["native-api-request", "--path", "/not-api", "--json"], 1, "fail"),
                (["native-scan-new-system", "--host", "not-an-ip", "--json"], 1, "fail"),
                (["native-scan-with-delivery", "--host", "not-an-ip", "--alert-id", "not-a-uuid", "--json"], 1, "fail"),
                (["native-nvt-diagnostic-scan", "--host", "not-an-ip", "--nvt-id", "1.2.3", "--json"], 1, "fail"),
                (["native-export-report-bundle", "--report-id", "11111111-1111-4111-8111-111111111111", "--max-items", "0", "--json"], 1, "fail"),
                (["native-export-report-csv", "--report-id", "11111111-1111-4111-8111-111111111111", "--max-results", "0", "--json"], 1, "fail"),
                (["native-export-report-pdf", "--report-id", "11111111-1111-4111-8111-111111111111", "--max-bytes", "0", "--json"], 1, "fail"),
                (["native-start-task", "--task-id", "11111111-1111-4111-8111-111111111111", "--json"], 1, "fail"),
                (["native-stop-task", "--task-id", "not-a-uuid", "--allow-write-control", "--json"], 1, "fail"),
                (["native-start-tasks-from-csv", "--csv-file", "/definitely-missing-yafvs-tasks.csv", "--json"], 1, "fail"),
                (["native-stop-tasks-from-csv", "--csv-file", "/definitely-missing-yafvs-tasks.csv", "--json"], 1, "fail"),
                (["native-stop-all-tasks", "--json"], 1, "fail"),
                (["native-update-task-target", "--task-id", "11111111-1111-4111-8111-111111111111", "--host", "192.0.2.10", "--json"], 1, "fail"),
                (["native-delete-overrides-by-filter", "--filter", "CVE", "--allow-write-control", "--json"], 1, "fail"),
                (["native-bulk-modify-schedules", "--filter", "nightly", "--timezone", "UTC", "--allow-write-control", "--json"], 1, "fail"),
                (["native-empty-trash", "--allow-write-control", "--json"], 1, "fail"),
                (["native-verify-scanners", "--json"], 1, "fail"),
                (["native-targets-from-host-list", "--hosts-file", "/definitely-missing-yafvs-hosts.txt", "--json"], 1, "fail"),
                (["native-targets-from-csv", "--csv-file", "/definitely-missing-yafvs-targets.csv", "--json"], 1, "fail"),
                (["native-tags-from-csv", "--csv-file", "/definitely-missing-yafvs-tags.csv", "--json"], 1, "fail"),
                (["native-targets-from-xml", "--xml-file", "/definitely-missing-yafvs-targets.xml", "--json"], 1, "fail"),
                (["native-schedules-from-csv", "--csv-file", "/definitely-missing-yafvs-schedules.csv", "--json"], 1, "fail"),
                (["native-schedules-from-xml", "--xml-file", "/definitely-missing-yafvs-schedules.xml", "--json"], 1, "fail"),
                (["native-credentials-from-csv", "--csv-file", "/definitely-missing-yafvs-credentials.csv", "--json"], 1, "fail"),
                (["native-alerts-from-csv", "--csv-file", "/definitely-missing-yafvs-alerts.csv", "--json"], 1, "fail"),
                (["native-tasks-from-csv", "--csv-file", "/definitely-missing-yafvs-tasks-create.csv", "--json"], 1, "fail"),
                (["runtime-scope-smoke", "--json"], 1, "fail"),
                (["runtime-certs-init", "--json"], (0, 1), ("pass", "fail")),
                (["runtime-feed-keyring-init", "--json"], 1, "fail"),
                (["feed-cache-sync", "--json"], 1, "fail"),
                (["down", "--json"], 1, "fail"),
                (["runtime-app-down", "--json"], 1, "fail"),
                (["quality-gate-state", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["quality-gate-state", "--status-only", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["feed-state", "--json"], 0, ("pass", "warn")),
                (["doctor", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["doctor", "--status-only", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["logs", "--lines", "0", "--json"], 1, "fail"),
                (["logs", "definitely-invalid", "--lines", "1", "--json"], 0, "pass"),
                (["logs", "--service", "definitely-invalid", "--lines", "1", "--json"], 0, "pass"),
                (["quality-gate-schedule", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["quality-gate-schedule", "--status", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["quality-gate-schedule", "--install", "--json"], 1, "fail"),
                (["runtime-native-api-direct-token", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["runtime-native-api-direct-bootstrap", "--json"], 0, "pass"),
                (["production-posture-check", "--status-only", "--json"], 1, "fail"),
                (["feed-generation-state", "--json"], 0, "warn"),
                (["feed-generation-state", "--status-only", "--json"], 0, "warn"),
                (["feed-generation-stage", "--json"], 1, "fail"),
                (["feed-generation-activate", "invalid", "--json"], 1, "fail"),
                (["feed-generation-rollback", "invalid", "--json"], 1, "fail"),
                (["feed-copy-to-runtime", "--json"], 1, "fail"),
                (["runtime-feed-import-init", "--json"], 1, "fail"),
                (["runtime-redis-state", "--json"], 0, "warn"),
                (["runtime-identity-migrate", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["runtime-data-state", "--json"], 0, "warn"),
                (["runtime-db-introspect", "--json"], 0, "warn"),
                (["runtime-performance-snapshot", "--json"], 0, "warn"),
                (["runtime-report-summary", "--report-id", "report-1", "--max-results", "0", "--json"], 1, "fail"),
                (["runtime-report-export", "--report-id", "report-1", "--top-results", "100001", "--json"], 1, "fail"),
                (["runtime-report-metrics", "--report-id", "report-1", "--json"], 1, "fail"),
                (["runtime-scope-report-summary", "--json"], 1, "fail"),
                (["runtime-scope-report-metrics", "--scope-report-id", "Organization", "--json"], 1, "fail"),
                (["runtime-certbund-report", "--report-id", "report-1", "--task-id", "task-1", "--json"], 1, "fail"),
                (["runtime-log-review", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["runtime-scanner-capability-check", "--json"], (0, 1), ("pass", "fail")),
                (["runtime-scanner-process-check", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["runtime-nmap-capability-check", "--json"], (0, 1), ("pass", "fail")),
                (["runtime-gmp-smoke", "--json"], (0, 1), ("pass", "fail")),
                (["runtime-credential-smoke", "--json"], 1, "fail"),
                (["runtime-rbac-smoke", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["runtime-webui-smoke", "--json"], 1, "fail"),
                (["runtime-full-test-scan-preflight", "--target-cidr", "10.0.0.0/16", "--json"], 1, "fail"),
                (["runtime-full-test-scan-start", "--target-cidr", "192.0.2.0/24", "--json"], 1, "fail"),
                (["runtime-full-test-scan-status", "--target-cidr", "10.0.0.0/16", "--json"], 1, "fail"),
                (["c-hardening-check", "--status-only", "--json"], 1, "fail"),
                (["path-coupling-state", "--json"], 0, "pass"),
                (["path-coupling-state", "--status-only", "--json"], 0, "pass"),
                (["security-policy-check", "--json"], 0, "pass"),
                (["security-policy-check", "--status-only", "--json"], 0, "pass"),
                (["native-api-cargo-audit", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["native-api-cargo-audit", "--status-only", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["gsa-npm-audit", "--json"], 0, "pass"),
                (["gsa-npm-audit", "--status-only", "--json"], 0, "pass"),
                (["native-api-semgrep-audit", "--json"], (0, 1), ("pass", "warn", "fail")),
                (["native-api-semgrep-audit", "--status-only", "--json"], (0, 1), ("pass", "warn", "fail")),
                (
                    ["osv-lockfile-audit", "--json"],
                    (0, 1),
                    ("pass", "warn", "fail"),
                ),
                (
                    ["osv-lockfile-audit", "--status-only", "--json"],
                    (0, 1),
                    ("pass", "warn", "fail"),
                ),
            ),
            complete_surface=True,
            human_inventory=True,
            non_repository_status=True,
        )

    def test_gvmd_target_parser_consumes_target_elements(self):
        gmp_source = (Path(__file__).resolve().parents[2] / "components" / "gvmd" / "src" / "gmp.c").read_text(encoding="utf-8")
        start_handler = gmp_source[
            gmp_source.index("gmp_xml_handle_start_element"):
            gmp_source.index("/**\n * @brief Send XML for an NVT.")
        ]
        required_transitions = [
            "case CLIENT_CREATE_TARGET:",
            "set_client_state (CLIENT_CREATE_TARGET_NAME);",
            "set_client_state (CLIENT_CREATE_TARGET_HOSTS);",
            "set_client_state (CLIENT_CREATE_TARGET_PORT_LIST);",
            "set_client_state (CLIENT_CREATE_TARGET_ALIVE_TESTS);",
            "case CLIENT_MODIFY_TARGET:",
            "set_client_state (CLIENT_MODIFY_TARGET_NAME);",
            "set_client_state (CLIENT_MODIFY_TARGET_HOSTS);",
            "set_client_state (CLIENT_MODIFY_TARGET_PORT_LIST);",
            "set_client_state (CLIENT_MODIFY_TARGET_ALIVE_TESTS);",
        ]
        for transition in required_transitions:
            with self.subTest(transition=transition):
                self.assertIn(transition, start_handler)

    def test_get_targets_is_native_only_acl_not_public_gmp(self):
        repo_root = Path(__file__).resolve().parents[2]
        gmp_source = (repo_root / "components" / "gvmd" / "src" / "gmp.c").read_text(encoding="utf-8")
        commands = (repo_root / "components" / "gvmd" / "src" / "manage_commands.c").read_text(encoding="utf-8")
        schema = (repo_root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in").read_text(encoding="utf-8")
        self.assertNotIn("CLIENT_GET_TARGETS", gmp_source)
        self.assertNotIn('{"GET_TARGETS", "Get all targets."}', commands)
        self.assertIn('"GET_TARGETS",', commands)
        self.assertNotIn("<name>get_targets</name>", schema)
        self.assertIn("<command>GET_TARGETS</command>", schema)

    def test_gvmd_task_parser_consumes_task_elements(self):
        gmp_source = (Path(__file__).resolve().parents[2] / "components" / "gvmd" / "src" / "gmp.c").read_text(encoding="utf-8")
        start_handler = gmp_source[
            gmp_source.index("gmp_xml_handle_start_element"):
            gmp_source.index("/**\n * @brief Send XML for an NVT.")
        ]
        required_transitions = [
            "case CLIENT_CREATE_TASK:",
            "set_client_state (CLIENT_CREATE_TASK_NAME);",
            "set_client_state (CLIENT_CREATE_TASK_COMMENT);",
            "set_client_state (CLIENT_CREATE_TASK_SCANNER);",
            "set_client_state (CLIENT_CREATE_TASK_CONFIG);",
            "set_client_state (CLIENT_CREATE_TASK_TARGET);",
            "set_client_state (CLIENT_CREATE_TASK_PREFERENCES);",
            "case CLIENT_CREATE_TASK_PREFERENCES:",
            "set_client_state (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE);",
            "case CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE:",
            "set_client_state (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_NAME);",
            "set_client_state (CLIENT_CREATE_TASK_PREFERENCES_PREFERENCE_VALUE);",
            "case CLIENT_MODIFY_TASK:",
            "set_client_state (CLIENT_MODIFY_TASK_NAME);",
            "set_client_state (CLIENT_MODIFY_TASK_COMMENT);",
            "set_client_state (CLIENT_MODIFY_TASK_SCANNER);",
            "set_client_state (CLIENT_MODIFY_TASK_CONFIG);",
            "set_client_state (CLIENT_MODIFY_TASK_TARGET);",
            "set_client_state (CLIENT_MODIFY_TASK_PREFERENCES);",
            "case CLIENT_MODIFY_TASK_PREFERENCES:",
            "set_client_state (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE);",
            "case CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE:",
            "set_client_state (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_NAME);",
            "set_client_state (CLIENT_MODIFY_TASK_PREFERENCES_PREFERENCE_VALUE);",
        ]
        for transition in required_transitions:
            with self.subTest(transition=transition):
                self.assertIn(transition, start_handler)

    def test_gvmd_credential_parser_consumes_create_credential_elements(self):
        gmp_source = (Path(__file__).resolve().parents[2] / "components" / "gvmd" / "src" / "gmp.c").read_text(encoding="utf-8")
        start_handler = gmp_source[
            gmp_source.index("gmp_xml_handle_start_element"):
            gmp_source.index("/**\n * @brief Send XML for an NVT.")
        ]
        required_transitions = [
            "case CLIENT_CREATE_CREDENTIAL:",
            "set_client_state (CLIENT_CREATE_CREDENTIAL_NAME);",
            "set_client_state (CLIENT_CREATE_CREDENTIAL_TYPE);",
            "set_client_state (CLIENT_CREATE_CREDENTIAL_LOGIN);",
            "set_client_state (CLIENT_CREATE_CREDENTIAL_PASSWORD);",
            "set_client_state (CLIENT_CREATE_CREDENTIAL_KEY);",
            "case CLIENT_CREATE_CREDENTIAL_KEY:",
            "set_client_state (CLIENT_CREATE_CREDENTIAL_KEY_PRIVATE);",
            "case CLIENT_CREATE_CREDENTIAL_PRIVACY:",
            "set_client_state (CLIENT_CREATE_CREDENTIAL_PRIVACY_PASSWORD);",
            "case CLIENT_CREATE_CREDENTIAL_KDCS:",
            "set_client_state (CLIENT_CREATE_CREDENTIAL_KDCS_KDC);",
        ]
        for transition in required_transitions:
            with self.subTest(transition=transition):
                self.assertIn(transition, start_handler)

    def test_runtime_just_wrappers_forward_args(self):
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        wrappers = [
            "runtime-browser-smoke",
            "runtime-browser-regression",
        ]
        for wrapper in wrappers:
            with self.subTest(wrapper=wrapper):
                self.assertIn(f"{wrapper} *args:", justfile)
                self.assertIn(f"tools/yafvsctl {wrapper} \"$@\"", justfile)
        self.assertIn("runtime-app-smoke *args:", justfile)
        self.assertIn("-- runtime-app-smoke \"$@\"", justfile)
        self.assertNotIn("tools/yafvsctl runtime-app-smoke \"$@\"", justfile)



    def test_native_scope_report_finding_counts_exclude_scanner_errors(self):
        source = (Path(__file__).resolve().parents[2] / "services" / "yafvs-api" / "src" / "scope_reports.rs").read_text(encoding="utf-8")
        self.assertIn("WHERE coalesce(r.severity, 0) != -3.0", source)
        self.assertIn("count(*) FILTER (WHERE severity = -1.0)", source)

    def test_gsa_native_scope_report_parser_maps_severity(self):
        source = (Path(__file__).resolve().parents[2] / "components" / "gsa" / "src" / "gmp" / "native-api" / "scope-reports.ts").read_text(encoding="utf-8")
        self.assertIn("const severity = item.severity ?? {}", source)
        self.assertIn("severityFalsePositive: integerValue(severity.false_positive)", source)

    def test_gsa_scope_report_list_is_routed_and_linked(self):
        root = Path(__file__).resolve().parents[2]
        routes = (root / "components" / "gsa" / "src" / "web" / "Routes.tsx").read_text(encoding="utf-8")
        scopes_page = (root / "components" / "gsa" / "src" / "web" / "pages" / "scopes" / "ScopeListPage.tsx").read_text(encoding="utf-8")
        menu = (root / "components" / "gsa" / "src" / "web" / "components" / "menu" / "Menu.tsx").read_text(encoding="utf-8")
        list_page = (root / "components" / "gsa" / "src" / "web" / "pages" / "scope-reports" / "ScopeReportListPage.tsx").read_text(encoding="utf-8")
        details_page = (root / "components" / "gsa" / "src" / "web" / "pages" / "scope-reports" / "ScopeReportDetailsPage.tsx").read_text(encoding="utf-8")
        self.assertIn("path: 'scopes/reports'", routes)
        self.assertIn("web/pages/scope-reports/ScopeReportListPage", routes)
        self.assertIn('to="/scopes/reports"', scopes_page)
        self.assertIn("to: '/scopes/reports'", menu)
        self.assertIn("_('Scope Reports')", menu)
        self.assertIn("<StatusBar status={TASK_STATUS.done} />", list_page)
        self.assertIn("<SeverityBar severity={report.maxSeverity} />", list_page)
        self.assertIn("report.resultsTotal", list_page)
        self.assertIn("scopeReportFilter", list_page)
        self.assertIn("fetchNativeScopeReports(gmp, filter)", list_page)
        self.assertIn("fetchNativeScopes(gmp)", list_page)
        self.assertIn("setCounts(reportResponse.counts", list_page)
        self.assertNotIn("gmp.scopereports.get({details: 1, filter})", list_page)
        self.assertNotIn("filteredReports", list_page)
        self.assertIn("_('Information')", details_page)
        self.assertIn("_('Results')", details_page)
        self.assertIn("_('Evidence Sources')", details_page)
        self.assertNotIn("ScopeReportResultsTab", details_page)
        self.assertFalse((root / "components" / "gsa" / "src" / "web" / "pages" / "scope-reports" / "ScopeReportResultsTab.tsx").exists())

    def test_scope_report_legacy_read_bridges_are_removed(self):
        root = Path(__file__).resolve().parents[2]
        gvmd_gmp = (root / "components" / "gvmd" / "src" / "gmp.c").read_text(encoding="utf-8")
        gvmd_scopes = (root / "components" / "gvmd" / "src" / "manage_sql_scopes.c").read_text(encoding="utf-8")
        gsad = (root / "components" / "gsad" / "src" / "gsad_gmp.c").read_text(encoding="utf-8")
        gsa_scopes = (root / "components" / "gsa" / "src" / "gmp" / "commands" / "scopes.ts").read_text(encoding="utf-8")
        gmp_schema = (root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in").read_text(encoding="utf-8")
        native_tooling = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        for marker in (
            "GET_SCOPE_REPORT",
            "handle_get_scope_reports_command",
            "scope_report_count_filtered",
            "buffer_scope_reports_xml",
        ):
            self.assertNotIn(marker, gvmd_gmp + gvmd_scopes)
        for marker in (
            "get_scope_report_gmp",
            "get_scope_report_metrics_gmp",
            "get_scope_reports_gmp",
        ):
            self.assertNotIn(marker, gsad)
        self.assertIn("fetchNativeScopeReports", gsa_scopes)
        self.assertIn("nativeScopeReportQueryFromFilter", gsa_scopes)
        self.assertNotIn("parseScopeReportCounts", gsa_scopes)
        self.assertFalse((root / "components" / "python-gvm").exists())
        self.assertNotIn("def command_native_api_request", native_tooling)
        self.assertFalse((root / "components" / "gvm-tools" / "scripts" / "list-scope-reports.gmp.py").exists())
        self.assertNotIn("<name>get_scope_reports</name>", gmp_schema)
        self.assertNotIn("<name>get_scope_report_metrics</name>", gmp_schema)

    def test_system_report_bridge_is_removed_but_scanner_performance_remains(self):
        root = Path(__file__).resolve().parents[2]
        for path in (
            "components/gsa/src/gmp/commands/performance.ts",
            "components/gsa/src/web/pages/performance/PerformancePage.tsx",
            "components/gsa/src/web/pages/performance/PerformanceReport.tsx",
        ):
            with self.subTest(path=path):
                self.assertFalse((root / path).exists())

        routes = (root / "components/gsa/src/web/Routes.tsx").read_text(encoding="utf-8")
        gsad = "\n".join(
            (root / path).read_text(encoding="utf-8")
            for path in (
                "components/gsad/src/gsad_gmp.c",
                "components/gsad/src/gsad_http_handle_request.c",
                "components/gsad/src/gsad_http_handler_functions.c",
            )
        )
        gvmd = "\n".join(
            (root / path).read_text(encoding="utf-8")
            for path in (
                "components/gvmd/src/gmp.c",
                "components/gvmd/src/manage.c",
                "components/gvmd/src/manage_commands.c",
                "components/gvmd/src/schema_formats/XML/GMP.xml.in",
            )
        )
        gvm_gmp = (root / "components/gvm-libs/gmp/gmp.c").read_text(encoding="utf-8")
        ospd = (root / "components/ospd-openvas/ospd/command/command.py").read_text(encoding="utf-8")

        self.assertNotIn("path: 'performance'", routes)
        self.assertNotIn("get_system_report", gsad)
        self.assertNotIn("GET_SYSTEM_REPORTS", gvmd)
        self.assertNotIn("get_system_reports", gvmd.lower())
        self.assertNotIn("gmp_get_system_reports", gvm_gmp)
        self.assertIn('name = "get_performance"', ospd)

    def test_report_finalization_ownership_includes_ordinary_scans(self):
        root = Path(__file__).resolve().parents[2]
        scan_handler = (root / "components/gvmd/src/manage_scan_handler.c").read_text(encoding="utf-8")
        manage = (root / "components/gvmd/src/manage.c").read_text(encoding="utf-8")
        manage_sql = (root / "components/gvmd/src/manage_sql.c").read_text(encoding="utf-8")
        registry = (root / "policy/gvmd-retirement.toml").read_text(encoding="utf-8")

        self.assertIn("report_set_processing_required (report, 1, in_assets_int);", scan_handler)
        self.assertIn("manage_process_report_finalizations ();", manage)
        self.assertIn("process_report_finalization (report)", manage)
        self.assertIn("process_report_finalization (report_t report)", manage_sql)
        self.assertIn('id = "report-finalization-projections"', registry)
        self.assertIn("manage_process_report_finalizations", registry)
        self.assertNotIn('id = "report-import-processing"', registry)
        self.assertNotIn("manage_process_report_imports", manage + registry)
        self.assertNotIn("process_report_import", manage + manage_sql)

    def test_asset_public_read_export_transport_is_retired(self):
        root = Path(__file__).resolve().parents[2]
        gsa_os = (root / "components/gsa/src/gmp/commands/os.js").read_text(encoding="utf-8")
        gsad = (root / "components/gsad/src/gsad_gmp.c").read_text(encoding="utf-8")
        validator = (root / "components/gsad/src/gsad_validator.c").read_text(encoding="utf-8")
        gvmd_gmp = (root / "components/gvmd/src/gmp.c").read_text(encoding="utf-8")
        inventory = (root / "components/gvmd/src/manage_commands.c").read_text(encoding="utf-8")
        schema = (root / "components/gvmd/src/schema_formats/XML/GMP.xml.in").read_text(encoding="utf-8")

        self.assertIn("fetchNativeOperatingSystem", gsa_os)
        self.assertIn("fetchNativeOperatingSystems", gsa_os)
        self.assertNotIn("get_assets_response", gsa_os)
        for retired in (
            "get_asset_gmp",
            "get_assets_gmp",
            "export_asset_gmp",
            "export_assets_gmp",
            "ELSE (get_asset)",
            "ELSE (get_assets)",
            "ELSE (export_asset)",
            "ELSE (export_assets)",
        ):
            self.assertNotIn(retired, gsad)
        for retired in ("|(get_asset)", "|(get_assets)", "|(export_asset)", "|(export_assets)"):
            self.assertNotIn(retired, validator)
        self.assertIn("ELSE (save_asset)", gsad)
        save_asset = gsad.split("save_asset_gmp (", 1)[1].split("change_password_gmp (", 1)[0]
        self.assertEqual(save_asset.count("<modify_asset"), 1)
        self.assertNotIn("<get_", save_asset)

        bulk_export = gsad.split("bulk_export_gmp (", 1)[1].split("save_asset_gmp (", 1)[0]
        rejection = bulk_export.index("g_ascii_strcasecmp (type, \"asset\") == 0")
        self.assertLess(rejection, bulk_export.index("if (bulk_select"))
        self.assertLess(rejection, bulk_export.index("params_add (params"))
        self.assertLess(rejection, bulk_export.index("export_many (connection"))
        self.assertIn("MHD_HTTP_BAD_REQUEST", bulk_export)
        self.assertNotIn("\"<get_assets\"", gsad)

        self.assertNotIn("CLIENT_GET_ASSETS", gvmd_gmp)
        self.assertNotIn("handle_get_assets", gvmd_gmp)
        self.assertNotIn("{\"GET_ASSETS\", \"Get all assets.\"}", inventory)
        self.assertIn("\"GET_ASSETS\",", inventory)
        self.assertNotIn("<name>get_assets</name>", schema)
        self.assertIn("instead use the GET_ASSETS command", schema)
        self.assertIn("GET_ASSETS should be used instead", schema)

    def test_native_report_evidence_reads_have_no_legacy_command_surface(self):
        root = Path(__file__).resolve().parents[2]
        gvmd_commands = (root / "components" / "gvmd" / "src" / "manage_commands.c").read_text(encoding="utf-8")
        gvmd_gmp = (root / "components" / "gvmd" / "src" / "gmp.c").read_text(encoding="utf-8")
        gsad = (root / "components" / "gsad" / "src" / "gsad_gmp.c").read_text(encoding="utf-8")
        gsa_report = (root / "components" / "gsa" / "src" / "gmp" / "commands" / "report.ts").read_text(encoding="utf-8")
        gsa_native_reports = (root / "components" / "gsa" / "src" / "gmp" / "native-api" / "reports.ts").read_text(encoding="utf-8")
        gsa_native_metrics = (root / "components" / "gsa" / "src" / "gmp" / "native-api" / "report-metrics.ts").read_text(encoding="utf-8")
        schema = (root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in").read_text(encoding="utf-8")
        commands = (
            "get_results",
            "get_report_applications",
            "get_report_cves",
            "get_report_errors",
            "get_report_hosts",
            "get_report_operating_systems",
            "get_report_ports",
            "get_report_tls_certificates",
            "get_report_vulns",
            "get_report_metrics",
        )
        for command in commands:
            self.assertNotIn(command.upper(), gvmd_commands)
            self.assertNotIn(command, gvmd_gmp.lower())
            self.assertNotIn(command, gsad.lower())
            self.assertNotIn(f"<name>{command}</name>", schema.lower())
        for native_loader in (
            "fetchNativeReportResults",
            "fetchNativeReportHosts",
            "fetchNativeReportPorts",
            "fetchNativeReportApplications",
            "fetchNativeReportOperatingSystems",
            "fetchNativeReportCves",
            "fetchNativeReportTlsCertificates",
            "fetchNativeReportErrors",
        ):
            self.assertIn(native_loader, gsa_native_reports)
        self.assertIn("fetchNativeReportMetrics", gsa_native_metrics)
        self.assertNotIn("getMetrics", gsa_report)

    def test_report_metrics_sql_deduplicates_and_filters_findings(self):
        source = (Path(__file__).resolve().parents[2] / "components" / "gvmd" / "src" / "manage_sql_metrics.c").read_text(encoding="utf-8")
        self.assertIn("METRIC_FINDING_CLAUSE", source)
        self.assertIn("coalesce (r.severity, 0) > 0", source)
        self.assertIn("SEVERITY_ERROR", source)
        self.assertIn("GROUP BY host_key, nvt_oid", source)
        self.assertIn("sum (cvss_score) AS cvss_load", source)
        self.assertIn("max (v.cvss_score) * count (DISTINCT v.host_key)", source)
        self.assertIn("targets_login_data", source)
        self.assertIn("no_credential_path", source)
        self.assertIn("authenticated_scan_coverage_percent", source)
        self.assertIn("append_summary_from_queries", source)
        self.assertIn("SELECT count (*)", source)
        self.assertIn("FROM scope_report_vulnerability_metrics", source)
        self.assertNotIn("SELECT coalesce (sum (vulnerability_count), 0)", source)

    def test_report_metrics_sql_auth_success_precedes_failure(self):
        source = (Path(__file__).resolve().parents[2] / "components" / "gvmd" / "src" / "manage_sql_metrics.c").read_text(encoding="utf-8")
        case_expr = source[source.index("CASE WHEN alive.auth_success"):source.index("alive.source_report_count", source.index("CASE WHEN alive.auth_success"))]
        self.assertLess(case_expr.index("alive.auth_success"), case_expr.index("alive.auth_failure"))
        self.assertLess(case_expr.index("alive.auth_failure"), case_expr.index("alive.has_credential_path"))

    def test_metric_contract_fixture_custom_scope_counts(self):
        metrics = metric_contract(scope_hosts=["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"])
        summary = metrics["summary"]
        self.assertEqual(summary["alive_system_count"], 4)
        self.assertEqual(summary["vulnerability_count"], 3)
        self.assertAlmostEqual(summary["total_system_cvss_load"], 19.0)
        self.assertAlmostEqual(summary["average_system_cvss_load"], 4.75)
        self.assertEqual(summary["authenticated_system_count"], 1)
        self.assertEqual(summary["authentication_failed_system_count"], 1)
        self.assertEqual(summary["unknown_authentication_system_count"], 1)
        self.assertEqual(summary["no_credential_path_system_count"], 1)
        self.assertAlmostEqual(summary["authenticated_scan_coverage_percent"], 25.0)

        systems = {system["host"]: system for system in metrics["systems"]}
        self.assertAlmostEqual(systems["192.0.2.10"]["cvss_load"], 11.0)
        self.assertEqual(systems["192.0.2.10"]["vulnerability_count"], 2)
        self.assertEqual(systems["192.0.2.10"]["authentication_state"], "authenticated")
        self.assertAlmostEqual(systems["192.0.2.11"]["cvss_load"], 7.0)
        self.assertEqual(systems["192.0.2.11"]["authentication_state"], "authentication_failed")
        self.assertEqual(systems["192.0.2.12"]["authentication_state"], "unknown")
        self.assertEqual(systems["192.0.2.13"]["authentication_state"], "no_credential_path")

        vulnerabilities = {vulnerability["nvt"]: vulnerability for vulnerability in metrics["vulnerabilities"]}
        self.assertEqual(set(vulnerabilities), {"nvt-a", "nvt-b", "nvt-c"})
        self.assertEqual(vulnerabilities["nvt-a"]["affected_system_count"], 2)
        self.assertAlmostEqual(vulnerabilities["nvt-a"]["cvss_load"], 14.0)
        self.assertAlmostEqual(vulnerabilities["nvt-a"]["average_contribution"], 3.5)
        self.assertEqual(vulnerabilities["nvt-a"]["source_report_count"], 2)

    def test_metric_contract_fixture_raw_and_organization_scope_agree(self):
        raw = metric_contract()
        organization = metric_contract(scope_hosts=None)
        self.assertEqual(raw, organization)
        summary = organization["summary"]
        self.assertEqual(summary["alive_system_count"], 5)
        self.assertEqual(summary["vulnerability_count"], 4)
        self.assertAlmostEqual(summary["total_system_cvss_load"], 29.0)
        self.assertAlmostEqual(summary["average_system_cvss_load"], 5.8)
        self.assertAlmostEqual(summary["authenticated_scan_coverage_percent"], 40.0)
        self.assertIn("192.0.2.99", {system["host"] for system in organization["systems"]})
        self.assertIn("nvt-d", {vulnerability["nvt"] for vulnerability in organization["vulnerabilities"]})

    def test_runtime_metrics_commands_use_native_api_not_legacy_xml_helper(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        runtime_scope_source = (root / "tools" / "runtime_scope.py").read_text(encoding="utf-8")
        browser_smoke_command = source.split("def command_runtime_browser_smoke", 1)[1].split("def command_runtime_browser_regression", 1)[0]
        browser_regression_command = source.split("def command_runtime_browser_regression", 1)[1].split("def quality_gate_doctor_status", 1)[0]
        scope_command_action = next(action for action in runtime_scope.build_parser()._actions if action.dest == "command")
        self.assertFalse((root / "tools" / "runtime_metrics.py").exists())
        self.assertEqual(scope_command_action.choices, ("smoke",))
        self.assertNotIn("def command_summary", runtime_scope_source)
        self.assertNotIn("get_scopes", runtime_scope_source)
        self.assertNotIn("get_targets", runtime_scope_source)
        self.assertNotIn("get_hosts", runtime_scope_source)
        self.assertIn("native_named_rows", runtime_scope_source)
        self.assertNotIn("get_scope_reports", runtime_scope_source)
        self.assertNotIn("get_scope(", runtime_scope_source)
        self.assertIn("native_scope_details", runtime_scope_source)
        self.assertIn("native_scopes", runtime_scope_source)
        self.assertIn("native_scope_reports", runtime_scope_source)
        self.assertIn("native_api_browser_proxy_delete", runtime_scope_source)
        self.assertIn("native_api_browser_proxy_json", runtime_scope_source)
        self.assertIn("native_generate_scope_report", runtime_scope_source)
        self.assertNotIn("runtime_full_test_scan", runtime_scope_source)
        self.assertNotIn("xml.etree.ElementTree", runtime_scope_source)
        self.assertNotIn("gmp.create_scope(", runtime_scope_source)
        self.assertNotIn("gmp.modify_scope(", runtime_scope_source)
        self.assertNotIn("gmp.delete_scope(", runtime_scope_source)
        self.assertNotIn("gmp.delete_scope_report", runtime_scope_source)
        rust_report_source = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_report.rs").read_text(encoding="utf-8")
        rust_scope_report_source = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_scope_report.rs").read_text(encoding="utf-8")
        self.assertNotIn("runtime_metrics_probe_path", source)
        self.assertNotIn("def command_runtime_scope_report_summary_native", source)
        self.assertIn("def native_scope_report_browser_target", source)
        self.assertNotIn("def command_runtime_report_summary_native", source)
        self.assertNotIn("def command_runtime_report_metrics_native", source)
        self.assertNotIn("def command_runtime_scope_report_metrics_native", source)
        self.assertIn("/api/v1/scope-reports?page_size=1&sort=-creation_time&filter=Organization", source)
        self.assertNotIn("def native_report_results_pages", source)
        self.assertIn('format!("/api/v1/reports/{encoded_report_id}/results")', rust_report_source)
        self.assertIn('"/api/v1/reports/{}/metrics"', rust_report_source)
        self.assertIn('"/api/v1/scopes/{}/reports/{}/metrics"', rust_scope_report_source)
        self.assertIn("native_scope_report_browser_target", browser_smoke_command)
        self.assertIn("native_scope_report_browser_target", browser_regression_command)
        self.assertNotIn("runtime_scope_probe_path", browser_smoke_command)
        self.assertNotIn("runtime_scope_probe_path", browser_regression_command)
        self.assertNotIn("scope_python", browser_smoke_command)
        self.assertNotIn("scope_python", browser_regression_command)
        self.assertNotIn("str(scope_probe)", browser_smoke_command)
        self.assertNotIn("str(scope_probe)", browser_regression_command)

    def test_legacy_scope_mutation_commands_are_removed_full_stack(self):
        root = Path(__file__).resolve().parents[2]
        retired_sources = {
            "gvm-libs GMP client": root / "components" / "gvm-libs" / "gmp" / "gmp.c",
            "gvm-libs GMP declarations": root / "components" / "gvm-libs" / "gmp" / "gmp.h",
            "gsad dispatch": root / "components" / "gsad" / "src" / "gsad_gmp.c",
            "gsad declarations": root / "components" / "gsad" / "src" / "gsad_gmp.h",
            "gsad validation": root / "components" / "gsad" / "src" / "gsad_validator.c",
            "gvmd parser": root / "components" / "gvmd" / "src" / "gmp.c",
            "gvmd scope SQL": root / "components" / "gvmd" / "src" / "manage_sql_scopes.c",
            "gvmd scope declarations": root / "components" / "gvmd" / "src" / "manage_sql_scopes.h",
        }
        retired_markers = (
            "create_scope_gmp",
            "modify_scope_gmp",
            "delete_scope_gmp",
            "ELSE (create_scope)",
            "ELSE (modify_scope)",
            "ELSE (delete_scope)",
            "CLIENT_CREATE_SCOPE",
            "CLIENT_MODIFY_SCOPE",
            "CLIENT_DELETE_SCOPE",
            "handle_create_scope",
            "handle_modify_scope",
            "handle_delete_scope",
            "create_scope (",
            "modify_scope (",
            "delete_scope (",
            "'create_scope'",
            "'modify_scope'",
            "'delete_scope'",
        )

        for label, path in retired_sources.items():
            source = path.read_text(encoding="utf-8")
            for marker in retired_markers:
                self.assertNotIn(marker, source, f"{label} still exposes {marker}")

        gsad_source = retired_sources["gsad dispatch"].read_text(encoding="utf-8")
        gvmd_source = retired_sources["gvmd parser"].read_text(encoding="utf-8")
        scope_sql_source = retired_sources["gvmd scope SQL"].read_text(encoding="utf-8")
        native_write_source = (root / "services" / "yafvs-api" / "src" / "scope_writes.rs").read_text(encoding="utf-8")
        self.assertIn("ensure_organization_scope", scope_sql_source)
        self.assertIn("pub(crate) async fn create_scope", native_write_source)
        self.assertIn("pub(crate) async fn patch_scope", native_write_source)
        self.assertIn("pub(crate) async fn delete_scope", native_write_source)

    def test_legacy_filter_mutation_commands_are_removed_full_stack(self):
        root = Path(__file__).resolve().parents[2]
        retired_sources = {
            "gvm-libs GMP client": root / "components" / "gvm-libs" / "gmp" / "gmp.c",
            "gvm-libs GMP declarations": root / "components" / "gvm-libs" / "gmp" / "gmp.h",
            "gsa capabilities": root / "components" / "gsa" / "src" / "gmp" / "capabilities" / "capabilities.ts",
            "gsad dispatch": root / "components" / "gsad" / "src" / "gsad_gmp.c",
            "gsad declarations": root / "components" / "gsad" / "src" / "gsad_gmp.h",
            "gsad validation": root / "components" / "gsad" / "src" / "gsad_validator.c",
            "gvmd parser": root / "components" / "gvmd" / "src" / "gmp.c",
            "gvmd filter SQL": root / "components" / "gvmd" / "src" / "manage_sql_filters.c",
            "gvmd filter declarations": root / "components" / "gvmd" / "src" / "manage_filters.h",
            "GMP schema": root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in",
        }
        retired_markers = (
            "create_filter_gmp",
            "delete_filter_gmp",
            "save_filter_gmp",
            "ELSE (create_filter)",
            "ELSE (delete_filter)",
            "ELSE (save_filter)",
            "CLIENT_CREATE_FILTER",
            "CLIENT_DELETE_FILTER",
            "CLIENT_MODIFY_FILTER",
            "create_filter (",
            "copy_filter (",
            "delete_filter (",
            "modify_filter (",
            "'create_filter'",
            "'delete_filter'",
            "'modify_filter'",
            "<name>create_filter</name>",
            "<name>delete_filter</name>",
            "<name>modify_filter</name>",
        )

        for label, path in retired_sources.items():
            source = path.read_text(encoding="utf-8")
            for marker in retired_markers:
                self.assertNotIn(marker, source, f"{label} still exposes {marker}")

        gsad_source = retired_sources["gsad dispatch"].read_text(encoding="utf-8")
        gsad_header = retired_sources["gsad declarations"].read_text(encoding="utf-8")
        gsad_validator = retired_sources["gsad validation"].read_text(encoding="utf-8")
        gvmd_source = retired_sources["gvmd parser"].read_text(encoding="utf-8")
        filter_sql_source = retired_sources["gvmd filter SQL"].read_text(encoding="utf-8")
        filter_header = retired_sources["gvmd filter declarations"].read_text(encoding="utf-8")
        capabilities_source = retired_sources["gsa capabilities"].read_text(encoding="utf-8")
        schema_source = retired_sources["GMP schema"].read_text(encoding="utf-8")
        native_write_source = (root / "services" / "yafvs-api" / "src" / "filter_writes.rs").read_text(encoding="utf-8")
        for marker in ("get_filter_gmp", "get_filters_gmp", "ELSE (get_filter)", "ELSE (get_filters)"):
            self.assertNotIn(marker, gsad_source)
            self.assertNotIn(marker, gsad_header)
        self.assertNotIn("|(get_filter)", gsad_validator)
        self.assertNotIn("|(get_filters)", gsad_validator)
        for marker in ("get_filters_data", "CLIENT_GET_FILTERS", "handle_get_filters"):
            self.assertNotIn(marker, gvmd_source)
        for marker in (
            "filter_count (",
            "filter_iterator_type (",
            "filter_iterator_term",
            "init_filter_alert_iterator",
            "filter_alert_iterator_",
            "filter_in_use (",
            "trash_filter_in_use (",
            "filter_writable (",
            "trash_filter_writable (",
        ):
            self.assertNotIn(marker, filter_sql_source)
            self.assertNotIn(marker, filter_header)
        self.assertNotIn("<name>get_filters</name>", schema_source)
        self.assertIn("GET_FILTERS, CREATE_FILTER, MODIFY_FILTER", schema_source)
        self.assertIn("'get_filters'", capabilities_source)
        self.assertIn("init_filter_iterator", filter_sql_source)
        self.assertIn("find_filter_with_permission", filter_sql_source)
        self.assertIn("filter_term_sql", filter_sql_source)
        self.assertIn("init_filter_iterator", gvmd_source)
        self.assertIn('"get_filters"', gvmd_source)
        self.assertIn("pub(crate) async fn create_filter", native_write_source)
        self.assertIn("pub(crate) async fn patch_filter", native_write_source)
        self.assertIn("pub(crate) async fn delete_filter", native_write_source)
        self.assertIn("pub(crate) async fn clone_filter", native_write_source)
        self.assertIn("pub(crate) async fn restore_filter", native_write_source)
        self.assertIn("pub(crate) async fn hard_delete_filter", native_write_source)

    def test_legacy_port_list_mutation_commands_are_removed_full_stack(self):
        root = Path(__file__).resolve().parents[2]
        retired_sources = {
            "gsa capabilities": root / "components" / "gsa" / "src" / "gmp" / "capabilities" / "capabilities.ts",
            "gsad dispatch": root / "components" / "gsad" / "src" / "gsad_gmp.c",
            "gsad declarations": root / "components" / "gsad" / "src" / "gsad_gmp.h",
            "gsad validation": root / "components" / "gsad" / "src" / "gsad_validator.c",
            "gvmd parser": root / "components" / "gvmd" / "src" / "gmp.c",
            "gvmd build": root / "components" / "gvmd" / "src" / "CMakeLists.txt",
            "gvmd port-list SQL": root / "components" / "gvmd" / "src" / "manage_sql_port_lists.c",
            "gvmd port-list declarations": root / "components" / "gvmd" / "src" / "manage_port_lists.h",
            "GMP schema": root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in",
        }
        retired_markers = (
            "gmp_delete_port_list_ext",
            "<delete_port_list",
            "create_port_list_gmp",
            "create_port_range_gmp",
            "save_port_list_gmp",
            "delete_port_list_gmp",
            "delete_port_range_gmp",
            "import_port_list_gmp",
            "ELSE (create_port_list)",
            "ELSE (create_port_range)",
            "ELSE (save_port_list)",
            "ELSE (delete_port_list)",
            "ELSE (delete_port_range)",
            "ELSE (import_port_list)",
            "CLIENT_CREATE_PORT_LIST",
            "CLIENT_CREATE_PORT_RANGE",
            "CLIENT_DELETE_PORT_LIST",
            "CLIENT_DELETE_PORT_RANGE",
            "CLIENT_MODIFY_PORT_LIST",
            "gmp_port_lists.c",
            "create_port_list (",
            "copy_port_list (",
            "modify_port_list (",
            "create_port_range (",
            "delete_port_list (",
            "delete_port_range (",
            "'create_port_list'",
            "'create_port_range'",
            "'modify_port_list'",
            "'delete_port_list'",
            "'delete_port_range'",
            "<name>create_port_list</name>",
            "<name>create_port_range</name>",
            "<name>modify_port_list</name>",
            "<name>delete_port_list</name>",
            "<name>delete_port_range</name>",
        )

        for label, path in retired_sources.items():
            source = path.read_text(encoding="utf-8")
            for marker in retired_markers:
                self.assertNotIn(marker, source, f"{label} still exposes {marker}")

        self.assertFalse((root / "components" / "gvmd" / "src" / "gmp_port_lists.c").exists())
        self.assertFalse((root / "components" / "gvmd" / "src" / "gmp_port_lists.h").exists())

        gsad_source = retired_sources["gsad dispatch"].read_text(encoding="utf-8")
        gvmd_source = retired_sources["gvmd parser"].read_text(encoding="utf-8")
        port_list_sql = retired_sources["gvmd port-list SQL"].read_text(encoding="utf-8")
        feed_source = (root / "components" / "gvmd" / "src" / "manage_port_lists.c").read_text(encoding="utf-8")
        native_write_source = (root / "services" / "yafvs-api" / "src" / "port_list_writes.rs").read_text(encoding="utf-8")
        self.assertNotIn("get_port_list_gmp", gsad_source)
        self.assertNotIn("get_port_lists_gmp", gsad_source)
        self.assertNotIn("CLIENT_GET_PORT_LISTS", gvmd_source)
        self.assertNotIn("GET_PORT_LISTS", retired_sources["GMP schema"].read_text(encoding="utf-8"))
        self.assertIn('"GET_PORT_LISTS",', (root / "components" / "gvmd" / "src" / "manage_commands.c").read_text(encoding="utf-8"))
        self.assertIn("CLIENT_CREATE_TARGET_PORT_RANGE", gvmd_source)
        self.assertIn("create_port_list_no_acl", port_list_sql)
        self.assertIn("create_port_list_unique", port_list_sql)
        self.assertIn("insert_port_range", port_list_sql)
        self.assertNotIn("restore_port_list", port_list_sql)
        self.assertIn("empty_trashcan_port_lists", port_list_sql)
        self.assertIn("parse_port_list_entity", feed_source)
        self.assertIn("manage_sync_port_lists", feed_source)
        for marker in (
            "pub(crate) async fn create_port_list",
            "pub(crate) async fn import_port_list",
            "pub(crate) async fn clone_port_list",
            "pub(crate) async fn patch_port_list",
            "pub(crate) async fn create_port_list_range",
            "pub(crate) async fn delete_port_list_range",
            "pub(crate) async fn delete_port_list",
            "pub(crate) async fn hard_delete_port_list",
            "pub(crate) async fn restore_port_list",
        ):
            self.assertIn(marker, native_write_source)

    def test_legacy_override_mutation_commands_are_removed_full_stack(self):
        root = Path(__file__).resolve().parents[2]
        retired_sources = {
            "gvm-libs GMP client": root / "components" / "gvm-libs" / "gmp" / "gmp.c",
            "gvm-libs GMP declarations": root / "components" / "gvm-libs" / "gmp" / "gmp.h",
            "gsa capabilities": root / "components" / "gsa" / "src" / "gmp" / "capabilities" / "capabilities.ts",
            "gsad dispatch": root / "components" / "gsad" / "src" / "gsad_gmp.c",
            "gsad declarations": root / "components" / "gsad" / "src" / "gsad_gmp.h",
            "gsad validation": root / "components" / "gsad" / "src" / "gsad_validator.c",
            "gvmd command inventory": root / "components" / "gvmd" / "src" / "manage_commands.c",
            "gvmd parser": root / "components" / "gvmd" / "src" / "gmp.c",
            "gvmd override SQL": root / "components" / "gvmd" / "src" / "manage_sql_overrides.c",
            "gvmd override declarations": root / "components" / "gvmd" / "src" / "manage_overrides.h",
            "GMP schema": root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in",
        }
        retired_markers = (
            "create_override_gmp",
            "delete_override_gmp",
            "save_override_gmp",
            "ELSE (create_override)",
            "ELSE (delete_override)",
            "ELSE (save_override)",
            "CLIENT_CREATE_OVERRIDE",
            "CLIENT_DELETE_OVERRIDE",
            "CLIENT_MODIFY_OVERRIDE",
            "create_override (",
            "copy_override (",
            "delete_override (",
            "modify_override (",
            '"CREATE_OVERRIDE"',
            '"DELETE_OVERRIDE"',
            '"MODIFY_OVERRIDE"',
            "'create_override'",
            "'delete_override'",
            "'modify_override'",
            "<name>create_override</name>",
            "<name>delete_override</name>",
            "<name>modify_override</name>",
        )

        for label, path in retired_sources.items():
            source = path.read_text(encoding="utf-8")
            for marker in retired_markers:
                self.assertNotIn(marker, source, f"{label} still exposes {marker}")

        gsad_source = retired_sources["gsad dispatch"].read_text(encoding="utf-8")
        gvmd_source = retired_sources["gvmd parser"].read_text(encoding="utf-8")
        override_sql = retired_sources["gvmd override SQL"].read_text(encoding="utf-8")
        manage_sql = (root / "components" / "gvmd" / "src" / "manage_sql.c").read_text(encoding="utf-8")
        native_write_source = (root / "services" / "yafvs-api" / "src" / "override_writes.rs").read_text(encoding="utf-8")
        for marker in (
            "get_override_gmp",
            "get_overrides_gmp",
            "export_override_gmp",
            "export_overrides_gmp",
            "CLIENT_GET_OVERRIDES",
            "get_overrides_data",
            "handle_get_overrides",
        ):
            self.assertNotIn(marker, gsad_source)
            self.assertNotIn(marker, gvmd_source)
        self.assertNotIn("<name>get_overrides</name>", retired_sources["GMP schema"].read_text(encoding="utf-8"))
        manage_commands = (root / "components" / "gvmd" / "src" / "manage_commands.c").read_text(encoding="utf-8")
        self.assertNotIn('{"GET_OVERRIDES", "Get all overrides."}', manage_commands)
        self.assertIn('"GET_OVERRIDES",', manage_commands)
        self.assertIn("override_count", override_sql)
        self.assertIn("init_override_iterator", override_sql)
        self.assertNotIn('find_trash ("override"', manage_sql)
        self.assertNotIn("reports_for_override (override)", manage_sql)
        for marker in (
            "pub(crate) async fn create_override",
            "pub(crate) async fn patch_override",
            "pub(crate) async fn clone_override",
            "pub(crate) async fn delete_override",
            "pub(crate) async fn restore_override",
            "pub(crate) async fn hard_delete_override",
        ):
            self.assertIn(marker, native_write_source)

    def test_legacy_scanner_mutation_and_verify_commands_are_removed_full_stack(self):
        root = Path(__file__).resolve().parents[2]
        retired_sources = {
            "gsa capabilities": root / "components" / "gsa" / "src" / "gmp" / "capabilities" / "capabilities.ts",
            "gsad dispatch": root / "components" / "gsad" / "src" / "gsad_gmp.c",
            "gsad declarations": root / "components" / "gsad" / "src" / "gsad_gmp.h",
            "gsad validation": root / "components" / "gsad" / "src" / "gsad_validator.c",
            "gvmd parser": root / "components" / "gvmd" / "src" / "gmp.c",
            "GMP schema": root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in",
        }
        retired_markers = (
            "create_scanner_gmp",
            "save_scanner_gmp",
            "delete_scanner_gmp",
            "verify_scanner_gmp",
            "ELSE (create_scanner)",
            "ELSE (save_scanner)",
            "ELSE (delete_scanner)",
            "CLIENT_CREATE_SCANNER",
            "CLIENT_MODIFY_SCANNER",
            "CLIENT_DELETE_SCANNER",
            "CLIENT_VERIFY_SCANNER",
            "<name>create_scanner</name>",
            "<name>modify_scanner</name>",
            "<name>delete_scanner</name>",
            "<name>verify_scanner</name>",
        )

        for label, path in retired_sources.items():
            source = path.read_text(encoding="utf-8")
            for marker in retired_markers:
                self.assertNotIn(marker, source, f"{label} still exposes {marker}")

        gsa_scanner = (root / "components" / "gsa" / "src" / "gmp" / "commands" / "scanner.ts").read_text(encoding="utf-8")
        gvmd_cli = (root / "components" / "gvmd" / "src" / "gvmd.c").read_text(encoding="utf-8")
        manage_sql = (root / "components" / "gvmd" / "src" / "manage_sql.c").read_text(encoding="utf-8")
        manage_h = (root / "components" / "gvmd" / "src" / "manage.h").read_text(encoding="utf-8")
        native_write_source = (root / "services" / "yafvs-api" / "src" / "scanner_writes.rs").read_text(encoding="utf-8")

        self.assertNotIn("super.clone({id})", gsa_scanner)
        self.assertNotIn("super.delete({id})", gsa_scanner)
        self.assertNotIn("cmd: 'verify_scanner'", gsa_scanner)
        capabilities = (root / "components" / "gsa" / "src" / "gmp" / "capabilities" / "capabilities.ts").read_text(encoding="utf-8")
        for retained in ("'create_scanner'", "'modify_scanner'", "'delete_scanner'"):
            self.assertIn(retained, capabilities)
        self.assertNotIn("copy_scanner (", manage_sql)
        self.assertNotIn("copy_scanner (", manage_h)
        for retired in (
            "manage_create_scanner (",
            "manage_modify_scanner (",
            "manage_delete_scanner (",
            "create_scanner (",
            "modify_scanner (",
            "delete_scanner (",
            "insert_scanner (",
        ):
            self.assertNotIn(retired, manage_sql)
            self.assertNotIn(retired, manage_h)
        for retired in (
            "--create-scanner",
            "--modify-scanner",
            "--delete-scanner",
            "--get-scanners",
            "--scanner-ca-pub",
            "--scanner-credential",
            "--scanner-host",
            "--scanner-key-priv",
            "--scanner-key-pub",
            "--scanner-name",
            "--scanner-port",
            "--scanner-relay-host",
            "--scanner-relay-port",
            "--scanner-type",
            "--no-default-certs",
        ):
            self.assertNotIn(retired, gvmd_cli)
        for retained in ("verify_scanner (", "manage_verify_scanner ("):
            self.assertIn(retained, manage_sql)
        self.assertIn("manage_verify_scanner (", manage_h)
        self.assertIn("verify_scanner (", manage_h)
        self.assertIn("\"verify-scanner\"", gvmd_cli)
        self.assertIn("ret = manage_verify_scanner (", gvmd_cli)
        gsad_source = retired_sources["gsad dispatch"].read_text(encoding="utf-8")
        gvmd_source = retired_sources["gvmd parser"].read_text(encoding="utf-8")
        for retired in (
            "get_scanner_gmp",
            "get_scanners_gmp",
            "export_scanner_gmp",
            "export_scanners_gmp",
        ):
            self.assertNotIn(retired, gsad_source)
        self.assertNotIn("get_trash_scanners_gmp", gsad_source)
        self.assertNotIn("CLIENT_GET_SCANNERS", gvmd_source)
        self.assertNotIn("manage_get_scanners (", manage_sql)
        self.assertNotIn("manage_get_scanners (", manage_h)
        self.assertNotIn("get-scanners", gvmd_cli)
        for marker in (
            "pub(crate) async fn create_scanner",
            "pub(crate) async fn clone_scanner",
            "pub(crate) async fn patch_scanner",
            "pub(crate) async fn replace_scanner_configuration",
            "pub(crate) async fn delete_scanner",
            "pub(crate) async fn restore_scanner",
            "pub(crate) async fn hard_delete_scanner",
        ):
            self.assertIn(marker, native_write_source)

    def test_full_test_scan_load_state_uses_native_api_when_repo_root_is_available(self):
        root = Path("/tmp/yafvs-test")
        payloads = {
            "/api/v1/scan-configs?page_size=500": {"items": [{"id": runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID, "name": "Full and fast"}]},
            "/api/v1/port-lists?page_size=500": {"items": [{"id": runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID, "name": "All IANA assigned TCP and UDP"}]},
            "/api/v1/scanners?page_size=500": {"items": [{"id": "scanner-1", "name": runtime_full_test_scan.OPENVAS_SCANNER_NAME}]},
            "/api/v1/targets?page_size=500": {"items": [{"id": "target-1", "name": TEST_FULL_TEST_TARGET.target_name}]},
            "/api/v1/tasks?page_size=500": {"items": [{"id": "task-1", "name": TEST_FULL_TEST_TARGET.task_name, "status": "Done", "progress": 100, "target": {"id": "target-1"}, "scanner": {"id": "scanner-1"}, "config": {"id": runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID}, "last_report": {"id": "report-1"}}]},
        }

        with unittest.mock.patch.object(runtime_full_test_scan, "native_api_json", side_effect=lambda _root, path: payloads[path]):
            state = runtime_full_test_scan.load_state(root)

        self.assertEqual(state["scan_configs"][0]["id"], runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID)
        self.assertEqual(state["port_lists"][0]["id"], runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID)
        self.assertEqual(state["scanners"][0]["name"], runtime_full_test_scan.OPENVAS_SCANNER_NAME)
        self.assertEqual(state["targets"][0]["name"], TEST_FULL_TEST_TARGET.target_name)
        self.assertEqual(state["tasks"][0]["report_id"], "report-1")
        self.assertEqual(state["tasks"][0]["progress"], "100")

    def test_full_test_scan_ensure_target_uses_native_create_when_repo_root_is_available(self):
        root = Path("/tmp/yafvs-test")
        state = {"targets": []}

        with unittest.mock.patch.object(
            runtime_full_test_scan,
            "native_api_browser_proxy_json",
            return_value={"id": "target-1", "name": TEST_FULL_TEST_TARGET.target_name},
        ) as native_create:
            target_id, error = runtime_full_test_scan.ensure_target(
                root,
                state,
                TEST_FULL_TEST_TARGET,
                operator_name="admin",
            )

        self.assertEqual(target_id, "target-1")
        self.assertIsNone(error)
        native_create.assert_called_once()
        _repo_root, path = native_create.call_args.args
        payload = native_create.call_args.kwargs["payload"]
        self.assertEqual(path, "/api/v1/targets")
        self.assertEqual(payload["hosts"], [TEST_FULL_TEST_TARGET.cidr])
        self.assertEqual(payload["port_list_id"], runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID)
        self.assertEqual(payload["alive_tests"], ["Scan Config Default"])
        self.assertNotIn("credentials", payload)

    def test_full_test_scan_browser_proxy_uses_resolved_operator_identity(self):
        root = Path("/tmp/yafvs-test")
        operator_uuid = "123e4567-e89b-12d3-a456-426614174000"
        completed = unittest.mock.Mock(
            returncode=0,
            stdout='{"id":"target-1"}\n201',
            stderr="",
        )
        with unittest.mock.patch.object(
            runtime_full_test_scan,
            "native_operator_uuid",
            return_value=operator_uuid,
        ) as resolve_operator:
            with unittest.mock.patch.object(
                runtime_full_test_scan.subprocess,
                "run",
                return_value=completed,
            ) as run:
                response = runtime_full_test_scan.native_api_browser_proxy_json(
                    root,
                    "/api/v1/targets",
                    method="POST",
                    payload={"name": "target"},
                    operator_name="admin",
                    expected_statuses={"201"},
                )

        self.assertEqual(response, {"id": "target-1"})
        resolve_operator.assert_called_once_with(root, "admin")
        command = run.call_args.args[0]
        self.assertIn("YAFVS_FULL_TEST_OPERATOR_UUID", command)
        self.assertIn("x-yafvs-operator-uuid", command[-1])
        self.assertEqual(
            run.call_args.kwargs["env"]["YAFVS_FULL_TEST_OPERATOR_UUID"],
            operator_uuid,
        )

    def test_full_test_scan_operator_identity_requires_one_valid_uuid(self):
        root = Path("/tmp/yafvs-test")
        valid = "123e4567-e89b-12d3-a456-426614174000"
        with unittest.mock.patch.object(
            runtime_full_test_scan,
            "native_items",
            return_value=[{"id": valid, "name": "admin"}],
        ):
            self.assertEqual(
                runtime_full_test_scan.native_operator_uuid(root, "admin"),
                valid,
            )

        for users, message in (
            ([], "found 0"),
            ([{"id": "not-a-uuid", "name": "admin"}], "invalid UUID"),
        ):
            with unittest.mock.patch.object(
                runtime_full_test_scan, "native_items", return_value=users
            ):
                with self.assertRaisesRegex(RuntimeError, message):
                    runtime_full_test_scan.native_operator_uuid(root, "admin")

    def test_full_test_scan_ensure_task_uses_native_create_when_repo_root_is_available(self):
        root = Path("/tmp/yafvs-test")
        state = {"tasks": []}

        with unittest.mock.patch.object(
            runtime_full_test_scan,
            "native_api_browser_proxy_json",
            return_value={"id": "task-1", "name": TEST_FULL_TEST_TARGET.task_name},
        ) as native_create:
            task_id, error = runtime_full_test_scan.ensure_task(
                root,
                state,
                TEST_FULL_TEST_TARGET,
                "target-1",
                "scanner-1",
                operator_name="admin",
            )

        self.assertEqual(task_id, "task-1")
        self.assertIsNone(error)
        native_create.assert_called_once()
        _repo_root, path = native_create.call_args.args
        payload = native_create.call_args.kwargs["payload"]
        self.assertEqual(path, "/api/v1/tasks")
        self.assertEqual(payload["target_id"], "target-1")
        self.assertEqual(payload["config_id"], runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID)
        self.assertEqual(payload["scanner_id"], "scanner-1")
        self.assertNotIn("schedule_id", payload)
        self.assertNotIn("alert_ids", payload)

    def test_full_test_scan_reports_for_task_uses_native_api_when_repo_root_is_available(self):
        root = Path("/tmp/yafvs-test")
        payload = {
            "items": [
                {
                    "id": "report-1",
                    "name": "Full test report",
                    "status": "Done",
                    "scan_start": "2026-07-08T12:00:00Z",
                    "scan_end": "2026-07-08T12:30:00Z",
                    "result_count": 7,
                    "host_count": 2,
                    "vulnerability_count": 3,
                    "cve_count": 4,
                    "task": {"id": "task-1"},
                },
                {"id": "other-report", "task": {"id": "other-task"}},
            ]
        }

        with unittest.mock.patch.object(runtime_full_test_scan, "native_api_json", return_value=payload) as native_json:
            reports, error = runtime_full_test_scan.reports_for_task(root, "task-1")

        self.assertIsNone(error)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["id"], "report-1")
        self.assertEqual(reports[0]["scan_run_status"], "Done")
        self.assertEqual(reports[0]["result_count"], "7")
        native_json.assert_called_once_with(root, "/api/v1/reports?page_size=100&sort=-creation_time")

    def test_report_metrics_ui_is_exposed_on_raw_and_scope_report_details(self):
        root = Path(__file__).resolve().parents[2]
        raw_details = (root / "components" / "gsa" / "src" / "web" / "pages" / "reports" / "DetailsContent.tsx").read_text(encoding="utf-8")
        scope_details = (root / "components" / "gsa" / "src" / "web" / "pages" / "scope-reports" / "ScopeReportDetailsPage.tsx").read_text(encoding="utf-8")
        metrics_tab = (root / "components" / "gsa" / "src" / "web" / "pages" / "reports" / "details" / "MetricsTab.tsx").read_text(encoding="utf-8")
        native_metrics = (root / "components" / "gsa" / "src" / "gmp" / "native-api" / "report-metrics.ts").read_text(encoding="utf-8")
        self.assertIn("MetricsTab", raw_details)
        self.assertIn("MetricsTab", scope_details)
        self.assertIn("fetchNativeReportMetrics", metrics_tab)
        self.assertIn("fetchNativeScopeReportMetrics", metrics_tab)
        self.assertIn("api/v1/reports/", native_metrics)
        self.assertIn("api/v1/scopes/", native_metrics)
        self.assertIn("Average System CVSS Load", metrics_tab)
        self.assertIn("Authenticated Scan Coverage", metrics_tab)
        self.assertIn("No Credential Path", metrics_tab)

    def test_scope_report_evidence_tabs_use_native_collections(self):
        root = Path(__file__).resolve().parents[2]
        scope_details = (root / "components" / "gsa" / "src" / "web" / "pages" / "scope-reports" / "ScopeReportDetailsPage.tsx").read_text(encoding="utf-8")
        native_tab = (root / "components" / "gsa" / "src" / "web" / "pages" / "scope-reports" / "NativeScopeReportEvidenceTab.tsx").read_text(encoding="utf-8")
        native_client = (root / "components" / "gsa" / "src" / "gmp" / "native-api" / "scope-report-collections.ts").read_text(encoding="utf-8")
        self.assertIn("NativeScopeReportEvidenceTab", scope_details)
        self.assertIn('kind="results"', scope_details)
        self.assertIn('kind="hosts"', scope_details)
        self.assertIn('kind="ports"', scope_details)
        self.assertIn('kind="applications"', scope_details)
        self.assertIn('kind="operatingSystems"', scope_details)
        self.assertIn('kind="cves"', scope_details)
        self.assertIn('kind="tlsCertificates"', scope_details)
        self.assertIn('kind="errors"', scope_details)
        self.assertIn("fetchNativeScopeReportResults", native_tab)
        self.assertIn("fetchNativeScopeReportHosts", native_tab)
        self.assertIn("fetchNativeScopeReportPorts", native_tab)
        self.assertIn("fetchNativeScopeReportApplications", native_tab)
        self.assertIn("fetchNativeScopeReportOperatingSystems", native_tab)
        self.assertIn("fetchNativeScopeReportCves", native_tab)
        self.assertIn("fetchNativeScopeReportTlsCertificates", native_tab)
        self.assertIn("fetchNativeScopeReportErrors", native_tab)
        self.assertIn("api/v1/scopes/", native_client)
        self.assertIn("scopeReportPath(scopeId, scopeReportId, 'results')", native_client)
        self.assertIn("scopeReportPath(scopeId, scopeReportId, 'hosts')", native_client)
        self.assertIn("scopeReportPath(scopeId, scopeReportId, 'ports')", native_client)
        self.assertIn("scopeReportPath(scopeId, scopeReportId, 'applications')", native_client)
        self.assertIn("scopeReportPath(scopeId, scopeReportId, 'operating-systems')", native_client)
        self.assertIn("scopeReportPath(scopeId, scopeReportId, 'cves')", native_client)
        self.assertIn("scopeReportPath(scopeId, scopeReportId, 'tls-certificates')", native_client)
        self.assertIn("scopeReportPath(scopeId, scopeReportId, 'errors')", native_client)

    def test_scope_report_evidence_api_handlers_remain_scope_source_scoped(self):
        root = Path(__file__).resolve().parents[2]
        handlers = [
            ("scope_report_results.rs", "pub(crate) async fn scope_report_results", "srs.source_report_uuid AS source_report_id"),
            ("scope_report_errors.rs", "pub(crate) async fn scope_report_errors", "srs.source_report_uuid AS source_report_id"),
            ("scope_report_hosts.rs", "pub(crate) async fn scope_report_hosts", "source_report_ids"),
            ("scope_report_ports.rs", "pub(crate) async fn scope_report_ports", "source_report_ids"),
            ("scope_report_applications.rs", "pub(crate) async fn scope_report_applications", "source_report_ids"),
            ("scope_report_operating_systems.rs", "pub(crate) async fn scope_report_operating_systems", "source_report_ids"),
            ("scope_report_tls_certificates.rs", "pub(crate) async fn scope_report_tls_certificates", "source_report_ids"),
            ("scope_report_cves.rs", "pub(crate) async fn scope_report_cves", "source_report_ids"),
        ]
        for filename, handler, source_identity in handlers:
            with self.subTest(handler=handler):
                source = (root / "services" / "yafvs-api" / "src" / filename).read_text(encoding="utf-8")
                self.assertIn(handler, source)
                self.assertIn("Path((scope_id, scope_report_id)): Path<(String, String)>", source)
                self.assertIn("parse_uuid(&scope_id)?", source)
                self.assertIn("parse_uuid(&scope_report_id)?", source)
                self.assertIn("WHERE sr.uuid = $1 AND sr.scope_uuid = $2", source)
                self.assertIn("JOIN scope_report_sources srs ON srs.scope_report = sr.id", source)
                self.assertIn(source_identity, source)
                self.assertIn("scope_report_exists(&client, &scope_report_id, &scope_id)", source)

    def test_scope_report_source_reports_are_excluded_from_raw_report_deletion(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "components" / "gvmd" / "src" / "manage_sql.c").read_text(encoding="utf-8")

        def section(start, end):
            self.assertIn(start, source)
            self.assertIn(end, source)
            return source.split(start, 1)[1].split(end, 1)[0]

        auto_delete = section("auto_delete_reports ()", "delete_report_internal (report_t report)")
        delete_internal = section("delete_report_internal (report_t report)", "delete_report (const char *report_id")
        source_reference_query = "SELECT count(*) FROM scope_report_sources"
        destructive_delete = "DELETE FROM report_host_details"

        self.assertIn("AND NOT EXISTS (SELECT 1 FROM scope_report_sources", auto_delete)
        self.assertIn("WHERE source_report = reports.id)", auto_delete)
        self.assertLess(
            auto_delete.index("AND NOT EXISTS (SELECT 1 FROM scope_report_sources"),
            auto_delete.index("g_array_append_val (reports_to_delete, report)"),
        )

        self.assertIn("4 report is referenced by a scope", delete_internal)
        self.assertIn(source_reference_query, delete_internal)
        self.assertIn("WHERE source_report = %llu;", delete_internal)
        self.assertIn("return 4;", delete_internal)
        self.assertIn(destructive_delete, delete_internal)
        self.assertLess(delete_internal.index(source_reference_query), delete_internal.index(destructive_delete))

    def test_gsad_native_api_proxy_is_authenticated_and_allowlisted(self):
        root = Path(__file__).resolve().parents[2]
        request_router = (root / "components" / "gsad" / "src" / "gsad_http_handle_request.c").read_text(encoding="utf-8")
        native_api = (root / "components" / "gsad" / "src" / "gsad_native_api.c").read_text(encoding="utf-8")
        validator = (root / "components" / "gsad" / "src" / "gsad_validator.c").read_text(encoding="utf-8")
        cmake = (root / "components" / "gsad" / "src" / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn('"^/api/v1/.+$"', request_router)
        self.assertIn("gsad_http_handle_setup_user", request_router)
        self.assertIn("gsad_http_handle_setup_credentials", request_router)
        self.assertIn("gsad_http_handle_native_api_get", request_router)
        self.assertIn("next = url_handlers;", request_router)
        self.assertIn("next = gsad_http_handler_add (next, native_api_url_handler);", request_router)
        self.assertNotIn("url_handlers = gsad_http_handler_add (url_handlers, native_api_url_handler);", request_router)
        self.assertIn("gsad_native_api.c", cmake)
        self.assertIn("DEFAULT_NATIVE_API_HOST \"yafvs-api\"", native_api)
        self.assertIn("DEFAULT_NATIVE_API_PORT \"9080\"", native_api)
        self.assertIn("native_api_path_is_allowed", native_api)
        self.assertIn("/api/v1/scope-reports", native_api)
        self.assertIn("/api/v1/reports/", native_api)
        self.assertIn("/api/v1/scopes/", native_api)
        self.assertIn("/metrics", native_api)
        self.assertIn("/results", native_api)
        self.assertIn("/hosts", native_api)
        self.assertIn("/ports", native_api)
        self.assertIn("/cves", native_api)
        self.assertIn("/cpes", native_api)
        self.assertIn("/api/v1/nvts", native_api)
        self.assertIn('operating_system_prefix = "/api/v1/operating-systems/"', native_api)
        self.assertIn('path + strlen (operating_system_prefix)', native_api)
        self.assertIn("/api/v1/cert-bund-advisories", native_api)
        self.assertIn("/api/v1/dfn-cert-advisories", native_api)
        self.assertIn('cert_bund_advisory_prefix = "/api/v1/cert-bund-advisories/"', native_api)
        self.assertIn('dfn_cert_advisory_prefix = "/api/v1/dfn-cert-advisories/"', native_api)
        self.assertIn("is_advisory_id_segment", native_api)
        self.assertIn('scan_config_families_suffix = "/families"', native_api)
        self.assertIn("/errors", native_api)
        self.assertIn("native_api_request_target", native_api)
        self.assertIn('append_query_param (target, params, "page")', native_api)
        self.assertIn('append_query_param (target, params, "page_size")', native_api)
        self.assertIn('append_query_param (target, params, "sort")', native_api)
        self.assertIn('append_query_param (target, params, "filter")', native_api)
        self.assertIn('gvm_validator_add (validator, "page_size", "^[0-9]+$");', validator)
        self.assertIn('gvm_validator_add (validator, "sort", "^-?[_[:alpha:]][_[:alnum:]]*$");', validator)
        self.assertNotIn('append_query_param (target, params, "token")', native_api)
        self.assertNotIn("MHD_POSTDATA_KIND", native_api)

    def test_user_management_native_contracts_cover_reads_writes_and_proxy_allowlists(self):
        root = Path(__file__).resolve().parents[2]
        expected_operations = {
            ("get", "/user-management/users"): "user-management-list-read",
            ("post", "/user-management/users"): "user-account-create",
            ("get", "/user-management/users/{user_id}"): "user-management-detail-read",
            ("patch", "/user-management/users/{user_id}"): "user-account-modify",
            ("delete", "/user-management/users/{user_id}"): "user-account-delete",
            ("post", "/user-management/users/{user_id}/clone"): "user-account-clone",
        }
        operations = {
            (operation["method"], operation["path"]): operation
            for operation in yafvsctl.openapi_contract_operations(root)
            if operation["path"].startswith("/user-management/users")
        }
        self.assertEqual(set(operations), set(expected_operations))
        for key, replaces in expected_operations.items():
            operation = operations[key]
            values = operation["x_yafvs_values"]
            method, _path = key
            expected_exposure = (
                "direct-read"
                if method == "get"
                else "direct-write"
                if method == "post"
                else "browser-write"
            )
            self.assertEqual(values["x-yafvs-exposure"], expected_exposure)
            self.assertEqual(values["x-yafvs-replaces"], replaces)
            if method != "get":
                self.assertEqual(values["x-yafvs-owner-semantics"], "gvmd-authoritative-operator-authorization")
                self.assertEqual(values["x-yafvs-safety-contract"], "write-control-v1")
                self.assertEqual(values["x-yafvs-side-effect"], "account-auth-control")

        direct_reads = set(yafvsctl.DIRECT_API_SCRIPTABLE_ENDPOINTS)
        self.assertIn("/api/v1/user-management/users", direct_reads)
        self.assertIn("/api/v1/user-management/users/{}", direct_reads)
        self.assertNotIn("/api/v1/auth/settings", direct_reads)

        proxy_templates, proxy_errors = yafvsctl.native_api_gsad_proxy_allowlist_templates(root)
        write_operations, write_errors = yafvsctl.native_api_gsad_proxy_write_allowlist_operations(root)
        self.assertEqual(proxy_errors, [])
        self.assertEqual(write_errors, [])
        self.assertIn("/api/v1/user-management/users", proxy_templates)
        self.assertIn("/api/v1/user-management/users/{}", proxy_templates)
        self.assertIn("POST /api/v1/user-management/users", write_operations)
        self.assertIn("POST /api/v1/user-management/users/{}/clone", write_operations)
        self.assertIn("PATCH /api/v1/user-management/users/{}", write_operations)
        self.assertIn("DELETE /api/v1/user-management/users/{}", write_operations)
        self.assertNotIn("/api/v1/auth/settings", proxy_templates)
        self.assertFalse(any("/api/v1/auth/settings" in operation for operation in write_operations))
        source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        self.assertIn('"native-api-direct.user-management-list"', source)
        self.assertIn('"/api/v1/user-management/users?page_size=1"', source)

        rows = {
            (row["method"], row["endpoint"]): row
            for row in yafvsctl.native_api_migration_matrix_rows(root)
            if row["endpoint"].startswith("/api/v1/user-management/users")
        }
        self.assertEqual(set(rows), {(method, f"/api/v1{path}") for method, path in expected_operations})
        self.assertEqual(
            yafvsctl.native_api_migration_matrix_contract_summary(list(rows.values())),
            {"rows_missing_openapi": [], "rows_missing_inventory": [], "rows_missing_migration_metadata": [], "direct_exposure_mismatches": [], "direct_marker_mismatches": []},
        )

    def test_runtime_browser_smoke_is_registered(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        browser_smoke = (Path(__file__).resolve().parents[1] / "runtime_browser_smoke.py").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertIn("def command_runtime_browser_smoke", source)
        self.assertIn("browser_smoke_run_artifact_dir(repo_root, routes)", source)
        self.assertIn("browser_native_api_readiness_finding(repo_root, check=\"browser-smoke.native-api-ready\")", source)
        self.assertIn("browser_gmp_readiness_finding(repo_root, check=\"browser-smoke.gmp-ready\")", source)
        self.assertNotIn("browser-smoke.cleanup-gvmd-socket", source)
        self.assertNotIn("--cleanup-gmp-socket", source)
        self.assertIn("runtime_browser_smoke_probe_path", source)
        self.assertIn("runtime-browser-smoke", source)
        self.assertIn("raw-report.list-native-api", browser_smoke)
        self.assertIn("scope.list-native-api", browser_smoke)
        self.assertIn("nvt.list-native-api", browser_smoke)
        self.assertIn("scan-config.list-native-api", browser_smoke)
        self.assertIn("tag.list-native-api", browser_smoke)
        self.assertIn("override.list-native-api", browser_smoke)
        self.assertIn("cert-bund-advisory.list-native-api", browser_smoke)
        self.assertIn("trashcan.items-native-api", browser_smoke)
        invalid_sort_helper = browser_smoke.split("async function assertNativeApiInvalidSortProxy", 1)[1].split("async function assertTagResourceNameProxy", 1)[0]
        invalid_page_helper = browser_smoke.split("async function assertNativeApiInvalidPageProxy", 1)[1].split("async function assertTagResourceNameProxy", 1)[0]
        malformed_page_helper = browser_smoke.split("async function assertNativeApiMalformedPageProxy", 1)[1].split("async function assertTagResourceNameProxy", 1)[0]
        focused_route_catalog = browser_smoke.split("function focusedRouteCatalog", 1)[1].split("function routeLabelFromPath", 1)[0]
        self.assertIn("400 && errorCode === 'bad_request'", invalid_sort_helper)
        self.assertIn("`${spec.label}.invalid-sort-native-api`", invalid_sort_helper)
        self.assertIn("400 && errorCode === 'bad_request'", invalid_page_helper)
        self.assertIn("`${spec.label}.invalid-page-native-api`", invalid_page_helper)
        self.assertIn("400 && errorCode === 'bad_request'", malformed_page_helper)
        self.assertIn("`${spec.label}.malformed-page-native-api`", malformed_page_helper)
        self.assertIn("/api/v1/vulnerabilities?page_size=1&sort=not_a_vulnerability_sort", focused_route_catalog)
        self.assertIn("/api/v1/vulnerabilities?page=0&page_size=1", focused_route_catalog)
        self.assertIn("/api/v1/vulnerabilities?page=abc&page_size=1", focused_route_catalog)
        self.assertIn("/api/v1/alerts?page_size=1&sort=not_an_alert_sort", focused_route_catalog)
        self.assertIn("/api/v1/alerts?page=0&page_size=1", focused_route_catalog)
        self.assertIn("/api/v1/alerts?page=abc&page_size=1", focused_route_catalog)
        self.assertIn("Raw-report list loaded through same-origin native API", browser_smoke)
        self.assertIn("browser_smoke.add_argument(\"--route\"", source)
        self.assertIn("browser_smoke.add_argument(\"--status-only\"", source)
        self.assertIn("browser_smoke.add_argument(\"--write-filter-smoke\"", source)
        self.assertIn("parser.add_argument(\"--repo-root\"", browser_smoke)
        self.assertIn('args.extend(["--repo-root", str(repo_root)])', source)
        self.assertIn("filter.write-create-native-api", browser_smoke)
        self.assertIn("filter.write-clone-native-api", browser_smoke)
        self.assertIn("filter.write-delete-${label}-native-api", browser_smoke)
        self.assertIn("filter.write-hard-delete-${label}-native-api", browser_smoke)
        self.assertIn("filter.write-cleanup", browser_smoke)
        self.assertNotIn("cleanup_gmp_socket", browser_smoke)
        self.assertNotIn("runtime_full_test_scan", browser_smoke)
        self.assertIn('args.extend(["--route", route])', source)
        self.assertIn("runtime-browser-smoke *args:", justfile)
        self.assertIn('tools/yafvsctl runtime-browser-smoke "$@"', justfile)

    def test_browser_smoke_filter_write_cleanup_uses_native_api(self):
        filter_id = "11111111-1111-1111-1111-111111111111"
        args = unittest.mock.Mock(
            write_filter_smoke=True,
            repo_root="/repo",
            username="admin",
        )
        payload = {"status": "fail", "summary": "needs cleanup", "findings": [{"details": {"created_id": filter_id}}]}

        with unittest.mock.patch.object(runtime_browser_smoke, "native_api_browser_proxy_delete") as native_delete:
            runtime_browser_smoke.cleanup_filter_write_smoke(args, payload)

        native_delete.assert_has_calls([
            unittest.mock.call(Path("/repo"), f"/api/v1/filters/{filter_id}", operator_name="admin"),
            unittest.mock.call(Path("/repo"), f"/api/v1/filters/{filter_id}/trash", operator_name="admin"),
        ])
        cleanup_finding = payload["findings"][-1]
        self.assertEqual(cleanup_finding["status"], "pass")
        self.assertEqual(cleanup_finding["details"], {"native_deleted_ids": [filter_id]})

    def test_browser_smoke_filter_write_cleanup_reports_native_error_without_fallback(self):
        filter_id = "22222222-2222-2222-2222-222222222222"
        args = unittest.mock.Mock(
            write_filter_smoke=True,
            repo_root="/repo",
            username="admin",
        )
        payload = {"status": "fail", "summary": "needs cleanup", "findings": [{"details": {"created_id": filter_id}}]}

        with unittest.mock.patch.object(runtime_browser_smoke, "native_api_browser_proxy_delete", side_effect=RuntimeError("boom")):
            runtime_browser_smoke.cleanup_filter_write_smoke(args, payload)

        cleanup_finding = payload["findings"][-1]
        self.assertEqual(cleanup_finding["status"], "fail")
        self.assertEqual(cleanup_finding["details"]["native_error_type"], "RuntimeError")
        self.assertIn(filter_id, cleanup_finding["details"]["filter_ids"])

    def test_browser_smoke_run_artifact_dir_isolates_route_focused_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            run_dir = yafvsctl.browser_smoke_run_artifact_dir(
                root,
                ["reports", "/scopes/reports?filter=rows=10"],
                now=datetime(2026, 6, 21, 19, 45, 1, 123456, tzinfo=timezone.utc),
                pid=4242,
            )

            parent = Path(tmp) / "YAFVS-runtime" / "artifacts" / "browser-smoke"
            self.assertEqual(run_dir.parent, parent)
            self.assertEqual(run_dir.name, "20260621T194501123456Z-pid4242-routes-reports-scopes-reports-filter-rows-10")

    def test_runtime_browser_smoke_passes_isolated_artifact_dir_to_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            probe = root / "tools" / "runtime_browser_smoke.py"
            secret = root.parent / "YAFVS-runtime" / "secrets" / "admin-password"
            probe.parent.mkdir(parents=True)
            secret.parent.mkdir(parents=True)
            probe.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            secret.write_text("admin\n", encoding="utf-8")
            captured: dict[str, list[str]] = {}
            original_run_dir = yafvsctl.browser_smoke_run_artifact_dir

            def fake_run_command(command, *_args, **_kwargs):
                captured["command"] = command
                payload = {"status": "pass", "summary": "Browser smoke passed.", "artifacts": ["helper-artifact.json"]}
                return subprocess.CompletedProcess(command, 0, json.dumps(payload) + "\n")

            with unittest.mock.patch.object(yafvsctl, "runtime_secret_path", return_value=secret), \
                unittest.mock.patch.object(yafvsctl, "runtime_browser_smoke_probe_path", return_value=probe), \
                unittest.mock.patch.object(yafvsctl.shutil, "which", return_value="/usr/bin/node"), \
                unittest.mock.patch.object(yafvsctl, "gsad_base_urls", return_value=("https://127.0.0.1:19392",)), \
                unittest.mock.patch.object(yafvsctl, "runtime_gsa_freshness_findings", return_value=[]), \
                unittest.mock.patch.object(yafvsctl, "browser_native_api_readiness_finding", return_value=yafvsctl.finding("pass", "browser-smoke.native-api-ready", "ready")), \
                unittest.mock.patch.object(yafvsctl, "browser_gmp_readiness_finding", return_value=yafvsctl.finding("pass", "browser-smoke.gmp-ready", "ready")), \
                unittest.mock.patch.object(yafvsctl, "native_scope_report_browser_target", return_value=(None, False, yafvsctl.finding("pass", "browser-smoke.scope-report-target", "target"))), \
                unittest.mock.patch.object(yafvsctl, "runtime_env", return_value={}), \
                unittest.mock.patch.object(yafvsctl, "run_command", side_effect=fake_run_command), \
                unittest.mock.patch.object(
                    yafvsctl,
                    "browser_smoke_run_artifact_dir",
                    side_effect=lambda repo_root, routes: original_run_dir(repo_root, routes, now=datetime(2026, 6, 21, 19, 45, 1, tzinfo=timezone.utc), pid=4242),
                ):
                result = yafvsctl.command_runtime_browser_smoke(root, ["reports"])

            artifact_arg = captured["command"][captured["command"].index("--artifact-dir") + 1]
            parent = str(root.parent / "YAFVS-runtime" / "artifacts" / "browser-smoke")
            self.assertEqual(result["status"], "pass")
            self.assertTrue(artifact_arg.startswith(parent + os.sep), artifact_arg)
            self.assertTrue(artifact_arg.endswith("20260621T194501000000Z-pid4242-routes-reports"), artifact_arg)
            self.assertNotEqual(artifact_arg, parent)

    def test_runtime_browser_smoke_status_only_compacts_helper_output(self):
        helper_payload = {
            "status": "warn",
            "summary": "Browser smoke warning.",
            "findings": [
                {"status": "pass", "check": "browser.login", "message": "logged in", "details": {"url": "https://example/"}},
                {"status": "warn", "check": "reports.empty", "message": "no rows", "details": {"samples": ["a", "b"]}},
            ],
            "artifacts": ["shot.png", "result.json"],
        }
        result = yafvsctl.make_result(
            "runtime-browser-smoke",
            Path("/tmp/TurboVAS"),
            "Browser smoke warning.",
            [
                yafvsctl.finding("pass", "browser-smoke.artifact-dir", "ready", details={"routes": ["/reports"]}),
                yafvsctl.finding("pass", "gsad.urls", "urls", details={"base_urls": ["https://one", "https://two"]}),
                yafvsctl.finding(
                    "warn",
                    "browser-smoke.run",
                    "Browser smoke warning.",
                    details={"helper": helper_payload, "output_tail": "very noisy browser stdout"},
                ),
            ],
            ["shot.png", "result.json"],
        )

        compact = yafvsctl.runtime_browser_smoke_status_only_result(result)

        self.assertEqual(compact["status"], "warn")
        self.assertEqual(compact["details"]["finding_count"], 3)
        self.assertEqual(compact["details"]["non_pass_count"], 1)
        self.assertEqual(compact["details"]["helper_status"], "warn")
        self.assertEqual(compact["details"]["helper_finding_count"], 2)
        self.assertEqual(compact["details"]["helper_non_pass_count"], 1)
        self.assertEqual(compact["details"]["artifact_count"], 2)
        self.assertEqual(compact["details"]["routes"], ["/reports"])
        self.assertEqual(compact["details"]["base_url_count"], 2)
        self.assertEqual(compact["artifacts"], ["result.json"])
        self.assertEqual(len(compact["findings"]), 2)
        self.assertNotIn("output_tail", json.dumps(compact["findings"]))
        self.assertNotIn("very noisy browser stdout", json.dumps(compact["findings"]))

    def test_runtime_browser_smoke_status_only_flag_returns_compact_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            probe = root / "tools" / "runtime_browser_smoke.py"
            secret = root.parent / "YAFVS-runtime" / "secrets" / "admin-password"
            probe.parent.mkdir(parents=True)
            secret.parent.mkdir(parents=True)
            probe.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            secret.write_text("admin\n", encoding="utf-8")

            def fake_run_command(command, *_args, **_kwargs):
                payload = {"status": "pass", "summary": "Browser smoke passed.", "findings": [], "artifacts": ["helper-artifact.json"]}
                return subprocess.CompletedProcess(command, 0, json.dumps(payload) + "\n")

            with unittest.mock.patch.object(yafvsctl, "runtime_secret_path", return_value=secret), \
                unittest.mock.patch.object(yafvsctl, "runtime_browser_smoke_probe_path", return_value=probe), \
                unittest.mock.patch.object(yafvsctl.shutil, "which", return_value="/usr/bin/node"), \
                unittest.mock.patch.object(yafvsctl, "gsad_base_urls", return_value=("https://127.0.0.1:19392",)), \
                unittest.mock.patch.object(yafvsctl, "runtime_gsa_freshness_findings", return_value=[]), \
                unittest.mock.patch.object(yafvsctl, "browser_native_api_readiness_finding", return_value=yafvsctl.finding("pass", "browser-smoke.native-api-ready", "ready")), \
                unittest.mock.patch.object(yafvsctl, "browser_gmp_readiness_finding", return_value=yafvsctl.finding("pass", "browser-smoke.gmp-ready", "ready")), \
                unittest.mock.patch.object(yafvsctl, "native_scope_report_browser_target", return_value=(None, False, yafvsctl.finding("pass", "browser-smoke.scope-report-target", "target"))), \
                unittest.mock.patch.object(yafvsctl, "runtime_env", return_value={}), \
                unittest.mock.patch.object(yafvsctl, "run_command", side_effect=fake_run_command):
                result = yafvsctl.command_runtime_browser_smoke(root, ["reports"], status_only=True)

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["details"]["routes"], ["reports"])
            self.assertEqual(result["details"]["helper_status"], "pass")
            self.assertEqual(result["findings"][0]["check"], "runtime-browser-smoke.status-only")

    def test_runtime_browser_regression_is_registered(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        browser_regression = (Path(__file__).resolve().parents[1] / "runtime_browser_regression.py").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertIn("def command_runtime_browser_regression", source)
        self.assertIn("browser_native_api_readiness_finding(repo_root, check=\"browser-regression.native-api-ready\")", source)
        self.assertIn("browser_gmp_readiness_finding(repo_root, check=\"browser-regression.gmp-ready\")", source)
        self.assertIn("runtime_browser_regression_probe_path", source)
        self.assertIn("runtime-browser-regression", source)
        self.assertIn("browser_regression.add_argument(\"--status-only\"", source)
        self.assertIn("command_runtime_browser_regression(repo_root, status_only=args.status_only)", source)
        self.assertIn("scope-report.result-evidence-route", browser_regression)
        self.assertIn("checkVulnerabilitiesRoute", browser_regression)
        self.assertIn("vulnerabilities.inline-details-route", browser_regression)
        self.assertIn("vulnerabilities.inline-details-content", browser_regression)
        self.assertIn("pagination-counts", browser_regression)
        self.assertIn("route-stability", browser_regression)
        self.assertIn("single-page-no-enabled-next", browser_regression)
        self.assertIn("No enabled Next pagination control was available because the live data appears to fit on one page", browser_regression)
        self.assertIn("no-live-detail-data", browser_regression)
        self.assertIn("no-live-detail-rows", browser_regression)
        self.assertIn("no-live-pagination-rows", browser_regression)
        self.assertIn("selector-failure-visible-details-link-mismatch", browser_regression)
        self.assertIn("selector-failure-expanded-details-link-mismatch", browser_regression)
        self.assertIn("selector-failure-no-row-details-toggle", browser_regression)
        self.assertIn("async function gotoStable", browser_regression)
        self.assertIn("waitUntil: 'domcontentloaded'", browser_regression)
        self.assertNotIn("waitForLoadState('networkidle', { timeout: config.timeoutMs }", browser_regression)
        self.assertIn("network.native-api-expected-absences", browser_regression)
        self.assertIn("browser.console-expected-absences", browser_regression)
        self.assertIn("expectedAbsenceConsoleCount", browser_regression)
        self.assertIn("/users\\/current\\/settings\\/[^/]+$", browser_regression)
        self.assertIn("start_new_session=True", browser_regression)
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", browser_regression)
        self.assertIn("min(300,", browser_regression)
        self.assertIn("network.native-api-failures", browser_regression)
        self.assertIn("runtime-browser-regression *args:", justfile)
        self.assertIn('tools/yafvsctl runtime-browser-regression "$@"', justfile)

    def test_runtime_browser_regression_status_only_compacts_helper_output(self):
        helper_payload = {
            "status": "warn",
            "summary": "Browser regression warning.",
            "findings": [
                {"status": "pass", "check": "browser.login", "message": "logged in", "details": {"url": "https://example/"}},
                {"status": "warn", "check": "pagination-counts", "message": "count mismatch", "details": {"samples": ["a", "b"]}},
            ],
            "artifacts": ["regression.json", "screenshot.png"],
        }
        result = yafvsctl.make_result(
            "runtime-browser-regression",
            Path("/tmp/TurboVAS"),
            "Browser regression warning.",
            [
                yafvsctl.finding("pass", "browser-regression.artifact-dir", "ready"),
                yafvsctl.finding("pass", "gsad.urls", "urls", details={"base_urls": ["https://one", "https://two"]}),
                yafvsctl.finding(
                    "warn",
                    "browser-regression.run",
                    "Browser regression warning.",
                    details={"helper": helper_payload, "output_tail": "very noisy browser stdout"},
                ),
            ],
            ["regression.json", "screenshot.png"],
        )

        compact = yafvsctl.runtime_browser_regression_status_only_result(result)

        self.assertEqual(compact["status"], "warn")
        self.assertEqual(compact["details"]["finding_count"], 3)
        self.assertEqual(compact["details"]["non_pass_count"], 1)
        self.assertEqual(compact["details"]["helper_status"], "warn")
        self.assertEqual(compact["details"]["helper_finding_count"], 2)
        self.assertEqual(compact["details"]["helper_non_pass_count"], 1)
        self.assertEqual(compact["details"]["artifact_count"], 2)
        self.assertEqual(compact["details"]["base_url_count"], 2)
        self.assertEqual(compact["artifacts"], ["regression.json"])
        self.assertEqual(len(compact["findings"]), 2)
        self.assertNotIn("output_tail", json.dumps(compact["findings"]))
        self.assertNotIn("very noisy browser stdout", json.dumps(compact["findings"]))
        self.assertNotIn("screenshot.png", json.dumps(compact["artifacts"]))

    def test_runtime_browser_regression_status_only_flag_returns_compact_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            probe = root / "tools" / "runtime_browser_regression.py"
            secret = root.parent / "YAFVS-runtime" / "secrets" / "admin-password"
            probe.parent.mkdir(parents=True)
            secret.parent.mkdir(parents=True)
            probe.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            secret.write_text("admin\n", encoding="utf-8")

            def fake_run_command(command, *_args, **_kwargs):
                payload = {"status": "pass", "summary": "Browser regression passed.", "findings": [], "artifacts": ["helper-artifact.json"]}
                return subprocess.CompletedProcess(command, 0, json.dumps(payload) + "\n")

            with unittest.mock.patch.object(yafvsctl, "runtime_secret_path", return_value=secret), \
                unittest.mock.patch.object(yafvsctl, "runtime_browser_regression_probe_path", return_value=probe), \
                unittest.mock.patch.object(yafvsctl.shutil, "which", return_value="/usr/bin/node"), \
                unittest.mock.patch.object(yafvsctl, "gsad_base_urls", return_value=("https://127.0.0.1:19392",)), \
                unittest.mock.patch.object(yafvsctl, "runtime_gsa_freshness_findings", return_value=[]), \
                unittest.mock.patch.object(yafvsctl, "browser_native_api_readiness_finding", return_value=yafvsctl.finding("pass", "browser-regression.native-api-ready", "ready")), \
                unittest.mock.patch.object(yafvsctl, "browser_gmp_readiness_finding", return_value=yafvsctl.finding("pass", "browser-regression.gmp-ready", "ready")), \
                unittest.mock.patch.object(yafvsctl, "native_scope_report_browser_target", return_value=(None, False, yafvsctl.finding("pass", "browser-regression.scope-report-target", "target"))), \
                unittest.mock.patch.object(yafvsctl, "runtime_env", return_value={}), \
                unittest.mock.patch.object(yafvsctl, "run_command", side_effect=fake_run_command):
                result = yafvsctl.command_runtime_browser_regression(root, status_only=True)

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["details"]["helper_status"], "pass")
            self.assertEqual(result["findings"][0]["check"], "runtime-browser-regression.status-only")

    def test_browser_gmp_readiness_retries_until_authenticated(self):
        with unittest.mock.patch.object(
            yafvsctl,
            "command_runtime_gmp_smoke",
            side_effect=[
                {"status": "fail", "summary": "not ready", "findings": [{"status": "fail", "check": "gvmd.gmp"}]},
                {"status": "pass", "summary": "ready", "findings": []},
            ],
        ) as smoke, unittest.mock.patch.object(yafvsctl.time, "sleep") as sleep:
            item = yafvsctl.browser_gmp_readiness_finding(Path("/tmp"), check="browser-smoke.gmp-ready")

        self.assertEqual(item["status"], "pass")
        self.assertEqual(item["check"], "browser-smoke.gmp-ready")
        self.assertEqual(item["details"]["attempts"], 2)
        self.assertEqual(smoke.call_count, 2)
        sleep.assert_called_once_with(5)

    def test_browser_native_api_readiness_retries_until_authenticated(self):
        with unittest.mock.patch.object(
            yafvsctl,
            "rust_result_envelope",
            side_effect=[
                {"status": "fail", "summary": "not ready", "findings": [{"status": "fail", "check": "native-api.healthz"}]},
                {"status": "pass", "summary": "ready", "findings": []},
            ],
        ) as smoke, unittest.mock.patch.object(yafvsctl.time, "sleep") as sleep:
            item = yafvsctl.browser_native_api_readiness_finding(Path("/tmp"), check="browser-smoke.native-api-ready")

        self.assertEqual(item["status"], "pass")
        self.assertEqual(item["check"], "browser-smoke.native-api-ready")
        self.assertEqual(item["details"]["attempts"], 2)
        self.assertEqual(smoke.call_count, 2)
        sleep.assert_called_once_with(3)

    def test_browser_native_api_readiness_accepts_data_aware_smoke_warnings(self):
        native_result = {
            "status": "warn",
            "summary": "ready with empty-data skips",
            "findings": [
                {
                    "status": "warn",
                    "check": "native-api.filter-detail",
                    "message": "No filters exist yet, so detail was skipped.",
                }
            ],
        }
        with unittest.mock.patch.object(
            yafvsctl,
            "rust_result_envelope",
            return_value=native_result,
        ) as smoke, unittest.mock.patch.object(yafvsctl.time, "sleep") as sleep:
            item = yafvsctl.browser_native_api_readiness_finding(
                Path("/tmp"), check="browser-smoke.native-api-ready"
            )

        self.assertEqual(item["status"], "pass")
        self.assertEqual(item["details"]["status"], "warn")
        self.assertEqual(item["details"]["failed_checks"], [])
        smoke.assert_called_once()
        sleep.assert_not_called()

    def test_runtime_credential_smoke_is_rust_owned(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        helper = (Path(__file__).resolve().parents[1] / "runtime_credential_smoke.py").read_text(encoding="utf-8")
        self.assertNotIn("def command_runtime_credential_smoke", source)
        self.assertNotIn("runtime_credential_smoke_probe_path", source)
        self.assertNotIn("--credential-password", helper)
        self.assertIn("runtime-credential-smoke *args:", justfile)
        self.assertIn('tools/yafvsctl-rs/Cargo.toml -- runtime-credential-smoke "$@"', justfile)

    def test_direct_write_smoke_covers_lossless_native_credential_delete_lifecycle(self):
        source = inspect.getsource(yafvsctl.native_api_direct_credential_clone_findings)
        for marker in [
            "native-api-direct.credential-delete",
            "native-api-direct.credential-delete-database-state",
            "native-api-direct.credential-delete-restore",
            "native-api-direct.credential-delete-hard-delete",
            "native-api-direct.credential-delete-ownerless",
            "credentials_trash_data",
            "allow_insecure = 1",
            "resource_location = 1",
            "delete_again_http_status",
        ]:
            self.assertIn(marker, source)
        self.assertIn('trash_state_value == "1|0|1|0"', source)
        self.assertIn('restore_state_value == "1|0|1"', source)

    def test_technical_foundation_commands_are_registered(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        rust_smoke = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_native_api_smoke.rs"
        ).read_text(encoding="utf-8")
        rust_direct_smoke = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_native_api_direct_smoke.rs"
        ).read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        rust_only_commands = {"status", "inventory", "branding-state", "rust-migration-state", "deps", "runtime-plan", "native-api-request", "native-start-task", "native-scan-new-system", "native-scan-with-delivery", "native-nvt-diagnostic-scan", "native-stop-task", "native-start-tasks-from-csv", "native-stop-tasks-from-csv", "native-stop-all-tasks", "native-update-task-target", "native-targets-from-host-list", "native-targets-from-csv", "native-tags-from-csv", "native-targets-from-xml", "native-schedules-from-csv", "native-schedules-from-xml", "native-credentials-from-csv", "native-alerts-from-csv", "native-tasks-from-csv", "native-delete-overrides-by-filter", "native-bulk-modify-schedules", "native-empty-trash", "native-verify-scanners", "native-api-cargo-audit", "gsa-npm-audit", "native-api-semgrep-audit", "osv-lockfile-audit", "path-coupling-state", "runtime-data-state", "runtime-db-introspect", "runtime-performance-snapshot", "runtime-log-review", "runtime-scope-smoke", "runtime-certs-init", "runtime-feed-keyring-init", "runtime-app-build", "runtime-native-api-smoke", "runtime-native-api-direct-smoke", "runtime-native-api-rebuild", "security-policy-check", "feed-state", "feed-cache-sync", "quality-gate-state", "quality-gate-schedule", "production-posture-check"}
        for command in ("native-tooling-state", "native-api-request", "native-start-task", "native-scan-new-system", "native-scan-with-delivery", "native-nvt-diagnostic-scan", "native-stop-task", "native-update-task-target", "native-stop-tasks-from-csv", "native-stop-all-tasks", "native-start-tasks-from-csv", "native-tasks-from-csv", "native-verify-scanners", "native-targets-from-host-list", "native-targets-from-csv", "native-targets-from-xml", "native-tags-from-csv", "native-schedules-from-csv", "native-schedules-from-xml", "native-credentials-from-csv", "native-alerts-from-csv", "native-api-migration-matrix", "native-api-client-contract", "native-api-replacement-dashboard", "closeout-readiness", "native-api-cargo-audit", "native-api-semgrep-audit", "gsa-npm-audit", "osv-lockfile-audit", "rust-migration-state", "branding-state", "production-posture-check", "runtime-log-review", "runtime-data-state", "runtime-db-introspect", "runtime-performance-snapshot", "security-policy-check", "path-coupling-state", "runtime-app-build", "runtime-native-api-smoke", "runtime-native-api-direct-smoke", "runtime-native-api-direct-write-smoke", "runtime-native-api-rebuild", "quality-gate", "quality-gate-state", "quality-gate-schedule"):
            if command in rust_only_commands:
                continue
            with self.subTest(command=command):
                self.assertIn(command, source)
                self.assertIn(f"{command} *args:", justfile)
                self.assertIn(f'tools/yafvsctl {command} "$@"', justfile)
        for command in (
            "native-start-tasks-from-csv",
            "native-stop-tasks-from-csv",
            "native-stop-all-tasks",
            "native-tasks-from-csv",
            "native-credentials-from-csv",
            "native-alerts-from-csv",
            "native-delete-overrides-by-filter",
            "native-bulk-modify-schedules",
            "native-empty-trash",
            "native-verify-scanners",
            "native-scan-new-system",
            "native-scan-with-delivery",
            "native-nvt-diagnostic-scan",
        ):
            self.assertNotIn(f'add_parser("{command}"', source)
            self.assertNotIn(f'elif args.command == "{command}":', source)
        for function in (
            "command_native_scan_new_system",
            "command_native_scan_with_delivery",
            "command_native_nvt_diagnostic_scan",
            "native_scan_new_system_preflight",
            "native_nvt_diagnostic_reconcile_config",
        ):
            self.assertNotIn(f"def {function}", source)
        self.assertIn(
            'tools/yafvsctl-rs/Cargo.toml -- native-nvt-diagnostic-scan "$@"',
            justfile,
        )

        self.assertIn("def command_native_tooling_state", source)
        self.assertNotIn("def command_native_export_report_csv", source)
        self.assertNotIn('subparsers.add_parser("native-export-report-csv"', source)
        self.assertNotIn("def command_native_export_report_bundle", source)
        self.assertNotIn('subparsers.add_parser("native-export-report-bundle"', source)
        self.assertIn('tools/yafvsctl-rs/Cargo.toml -- native-export-report-bundle "$@"', justfile)
        self.assertNotIn("def command_native_api_request", source)
        self.assertNotIn('subparsers.add_parser("native-api-request"', source)
        self.assertIn('migration_matrix.add_argument("--summary"', source)
        self.assertIn("args.status_only or args.compact or args.summary", source)
        self.assertIn("status_only=args.status_only", source)
        self.assertIn("def command_native_api_client_contract", source)
        self.assertIn("def command_native_api_replacement_dashboard", source)
        self.assertIn("def command_closeout_readiness", source)
        self.assertIn("def rust_runtime_log_review_result", source)
        self.assertIn('rust_result_envelope(repo_root, "runtime-log-review", ["runtime-log-review"])', source)
        self.assertNotIn("def command_runtime_native_api_smoke", source)
        self.assertNotIn('subparsers.add_parser("runtime-native-api-smoke"', source)
        self.assertNotIn('args.command == "runtime-native-api-smoke"', source)
        self.assertNotIn("def command_runtime_native_api_direct_smoke", source)
        self.assertNotIn('subparsers.add_parser("runtime-native-api-direct-smoke"', source)
        self.assertNotIn('args.command == "runtime-native-api-direct-smoke"', source)
        self.assertIn("pub fn command_runtime_native_api_direct_smoke", rust_direct_smoke)
        self.assertIn("def command_runtime_native_api_direct_write_smoke", source)
        self.assertNotIn("def command_runtime_native_api_rebuild", source)
        self.assertIn("native-api.scope-report-hosts", rust_smoke)
        self.assertIn("native-api.scope-report-ports", rust_smoke)
        self.assertIn("native-api.scope-report-cves", rust_smoke)
        self.assertIn("native-api.scan-configs", rust_smoke)
        self.assertIn("native-api.tags", rust_smoke)
        self.assertIn("native-api.overrides", rust_smoke)
        self.assertIn("native-api.trashcan-summary", rust_smoke)
        self.assertIn("native-api.alerts", rust_smoke)
        self.assertIn("/api/v1/alerts/{alert_id}/definition", source)
        self.assertIn("native-api-direct.alert-definition-put-disabled", rust_direct_smoke)
        self.assertIn("native-api-direct.alert-definition-read", source)
        self.assertIn("native-api-direct.alert-definition-replace", source)
        self.assertIn("native-api-direct.alert-definition-read-after-replace", source)
        self.assertIn("/api/v1/scan-configs", source)
        self.assertIn("/api/v1/scan-configs/{scan_config_id}", source)
        self.assertIn("/api/v1/trashcan/summary", source)
        self.assertIn("/api/v1/alerts", source)
        self.assertIn("/api/v1/alerts/{alert_id}", source)
        self.assertIn("/api/v1/tags", source)
        self.assertIn("/api/v1/tags/resource-names/{resource_type}", source)
        self.assertIn("native-api.tag-resource-names", rust_smoke)
        self.assertIn("native-api.tag-resource-names.alert", rust_smoke)
        self.assertIn("native-api.tag-resource-names.scanner", rust_smoke)
        self.assertIn("native-api.tag-resource-names.schedule", rust_smoke)
        self.assertIn("/api/v1/tags/resource-names/alert", rust_smoke)
        self.assertIn("/api/v1/tags/resource-names/scanner", rust_smoke)
        self.assertIn("/api/v1/tags/resource-names/schedule", rust_smoke)
        self.assertIn("/api/v1/tags/{tag_id}", source)
        self.assertIn("/api/v1/tags/{tag_id}/resources", source)
        self.assertIn("/api/v1/overrides", source)
        self.assertIn("/api/v1/overrides/{override_id}", source)
        self.assertNotIn("def native_api_request_display_command", source)
        self.assertIn("--allow-write-control", source)
        self.assertNotIn("def command_production_posture_check", source)
        self.assertIn("def command_quality_gate", source)
        self.assertNotIn("def command_quality_gate_state", source)
        self.assertNotIn("Use: just native-api-request -- --json --path '/api/v1/...';", justfile)

    def test_rust_only_foundation_commands_have_no_python_ownership(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        direct_recipe = 'cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml --'
        for command in ("status", "inventory", "branding-state", "rust-migration-state", "deps", "runtime-plan", "logs", "runtime-log-review", "runtime-scope-smoke", "runtime-certs-init", "feed-state", "feed-cache-sync", "quality-gate-state", "doctor", "quality-gate-schedule", "runtime-native-api-direct-token", "runtime-native-api-direct-bootstrap", "production-posture-check", "license-report", "runtime-app-build", "runtime-native-api-smoke", "runtime-native-api-direct-smoke", "runtime-native-api-rebuild", "native-api-request", "native-start-task", "native-stop-task", "native-update-task-target", "native-tasks-from-csv", "native-empty-trash", "native-verify-scanners"):
            with self.subTest(command=command):
                self.assertNotIn(f'subparsers.add_parser("{command}"', source)
                self.assertNotRegex(
                    source,
                    rf"(?m)^def command_{re.escape(command.replace('-', '_'))}\(",
                )
                self.assertNotIn(f'args.command == "{command}"', source)
                self.assertIn(f"{command} *args:", justfile)
                self.assertIn(f'{direct_recipe} {command} "$@"', justfile)

    def test_runtime_feed_keyring_init_is_owned_directly_by_rust(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-feed-keyring-init"', source)
        self.assertNotIn('args.command == "runtime-feed-keyring-init"', source)
        self.assertNotIn("def command_runtime_feed_keyring_init", source)
        self.assertIn("runtime-feed-keyring-init *args:", justfile)
        self.assertIn(
            'tools/yafvsctl-rs/Cargo.toml -- runtime-feed-keyring-init "$@"',
            justfile,
        )

    def test_rust_license_report_bridge_validates_envelopes_and_forwards_flags(self):
        def envelope(status: str) -> str:
            return json.dumps({
                "status": status,
                "summary": "ok",
                "findings": [{"status": status, "check": "license.check", "message": "ok"}],
                "artifacts": ["build/license.json"],
                "metadata": {"command": "license-report"},
            })

        root = Path("/tmp/repo")
        with unittest.mock.patch.object(
            yafvsctl,
            "run_command",
            return_value=subprocess.CompletedProcess(["unit"], 0, envelope("pass"), ""),
        ) as run_command:
            result = yafvsctl.rust_license_report_result(
                root,
                public_release=True,
                mode="container",
                diff_scope="staged",
                modified_imported_only=True,
                status_only=True,
            )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            run_command.call_args.args[0][-9:],
            ["license-report", "--public-release", "--mode", "container", "--diff-scope", "staged", "--modified-imported-only", "--status-only", "--json"],
        )
        with unittest.mock.patch.object(
            yafvsctl,
            "run_command",
            return_value=subprocess.CompletedProcess(["unit"], 1, envelope("fail"), ""),
        ):
            self.assertEqual(yafvsctl.rust_license_report_result(root)["status"], "fail")

    def test_rust_license_report_bridge_fails_closed_without_process_output(self):
        valid = {
            "status": "pass",
            "summary": "ok",
            "findings": [{"status": "pass", "check": "license.check", "message": "ok"}],
            "artifacts": [],
            "metadata": {"command": "license-report"},
        }
        malformed = [
            ("not-json SECRET_STDOUT", 0),
            ("{" + '"status":"pass","status":"fail"' + "}", 0),
            (json.dumps({**valid, "status": "fail"}), 1),
            (json.dumps({**valid, "metadata": {"command": "doctor"}}), 0),
            ("x" * (yafvsctl.YAFVSCTL_RUST_BRIDGE_MAX_OUTPUT_BYTES + 1), 0),
        ]
        root = Path("/tmp/repo")
        for stdout, returncode in malformed:
            with self.subTest(stdout_size=len(stdout)), unittest.mock.patch.object(
                yafvsctl,
                "run_command",
                return_value=subprocess.CompletedProcess(["unit"], returncode, stdout, "SECRET_STDERR"),
            ):
                result = yafvsctl.rust_license_report_result(root)
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["findings"][0]["check"], "license-report.rust-bridge")
            self.assertNotIn("SECRET_STDOUT", json.dumps(result))
            self.assertNotIn("SECRET_STDERR", json.dumps(result))

        with unittest.mock.patch.object(yafvsctl, "run_command", side_effect=OSError("SECRET_ERROR")):
            result = yafvsctl.rust_license_report_result(root)
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("SECRET_ERROR", json.dumps(result))
        with unittest.mock.patch.object(yafvsctl, "run_command", side_effect=subprocess.SubprocessError("SECRET_SUBPROCESS_ERROR")):
            result = yafvsctl.rust_license_report_result(root)
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("SECRET_SUBPROCESS_ERROR", json.dumps(result))

    def test_rust_quality_gate_state_bridge_forwards_status_only(self):
        envelope = json.dumps(
            {
                "status": "pass",
                "summary": "ok",
                "findings": [
                    {
                        "status": "pass",
                        "check": "quality-gate-state.ok",
                        "message": "ok",
                    }
                ],
                "artifacts": ["artifacts/quality-gate.json"],
                "metadata": {"command": "quality-gate-state"},
            }
        )
        root = Path("/tmp/repo")
        with unittest.mock.patch.object(
            yafvsctl,
            "run_command",
            return_value=subprocess.CompletedProcess(["unit"], 0, envelope, ""),
        ) as run_command:
            result = yafvsctl.rust_quality_gate_state_result(root, status_only=True)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            run_command.call_args.args[0][-3:],
            ["quality-gate-state", "--status-only", "--json"],
        )

        with unittest.mock.patch.object(
            yafvsctl,
            "run_command",
            return_value=subprocess.CompletedProcess(["unit"], 0, envelope, ""),
        ) as run_command:
            result = yafvsctl.rust_quality_gate_state_result(root)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            run_command.call_args.args[0][-2:],
            ["quality-gate-state", "--json"],
        )


    def test_rust_doctor_bridge_forwards_status_only(self):
        envelope = json.dumps(
            {
                "status": "warn",
                "summary": "Monorepo health checks completed.",
                "findings": [
                    {
                        "status": "warn",
                        "check": "surface.deferred",
                        "message": "deferred",
                    }
                ],
                "artifacts": [],
                "metadata": {"command": "doctor"},
            }
        )
        root = Path("/tmp/repo")
        with unittest.mock.patch.object(
            yafvsctl,
            "run_command",
            return_value=subprocess.CompletedProcess(["unit"], 0, envelope, ""),
        ) as run_command:
            result = yafvsctl.rust_doctor_result(root, status_only=True)

        self.assertEqual(result["status"], "warn")
        self.assertEqual(
            run_command.call_args.args[0][-3:],
            ["doctor", "--status-only", "--json"],
        )

    def test_rust_runtime_log_review_bridge_uses_fixed_arguments(self):
        envelope = json.dumps(
            {
                "status": "warn",
                "summary": "Runtime log review completed.",
                "findings": [
                    {
                        "status": "warn",
                        "check": "log-review.container",
                        "message": "app container is not running.",
                    }
                ],
                "artifacts": ["/runtime/artifacts/log-review/log-review.json"],
                "metadata": {"command": "runtime-log-review"},
            }
        )
        root = Path("/tmp/repo")
        with unittest.mock.patch.object(
            yafvsctl,
            "run_command",
            return_value=subprocess.CompletedProcess(["unit"], 0, envelope, ""),
        ) as run_command:
            result = yafvsctl.rust_runtime_log_review_result(root)

        self.assertEqual(result["status"], "warn")
        self.assertEqual(
            run_command.call_args.args[0][-2:],
            ["runtime-log-review", "--json"],
        )

    def test_rust_capability_bridges_and_direct_ownership(self):
        root = Path("/tmp/repo")
        for command, wrapper in [
            (
                "runtime-gmp-smoke",
                yafvsctl.command_runtime_gmp_smoke,
            ),
        ]:
            envelope = json.dumps(
                {
                    "status": "pass",
                    "summary": "ok",
                    "findings": [
                        {
                            "status": "pass",
                            "check": "ospd.running",
                            "message": "ok",
                        }
                    ],
                    "artifacts": [],
                    "metadata": {"command": command},
                }
            )
            with self.subTest(command=command), unittest.mock.patch.object(
                yafvsctl,
                "run_command",
                return_value=subprocess.CompletedProcess(["unit"], 0, envelope, ""),
            ) as run_command:
                result = wrapper(root)
            self.assertEqual(result["status"], "pass")
            self.assertEqual(run_command.call_args.args[0][-2:], [command, "--json"])

        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(
            encoding="utf-8"
        )
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(
            encoding="utf-8"
        )
        direct_recipe = "cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml --"
        for command in (
            "runtime-scanner-capability-check",
            "runtime-scanner-process-check",
            "runtime-nmap-capability-check",
            "runtime-gmp-smoke",
            "runtime-rbac-smoke",
        ):
            self.assertNotIn(f'subparsers.add_parser("{command}"', source)
            self.assertNotIn(f'args.command == "{command}"', source)
            self.assertIn(f'{direct_recipe} {command} "$@"', justfile)
        for helper in (
            "command_runtime_scanner_capability_check",
            "command_runtime_scanner_process_check",
            "command_runtime_nmap_capability_check",
        ):
            self.assertNotIn(f"def {helper}", source)
        for helper in (
            "parse_proc_status",
            "cap_hex_has",
            "missing_required_caps",
            "hostname_looks_like_docker_short_id",
            "ospd_setpriv_raw_socket_probe_command",
            "ospd_setpriv_nmap_probe_commands",
            "nmap_privilege_warning_present",
            "running_service_env_secret_exposure",
            "running_service_read_only_mount_matches",
            "running_service_config_secret_exposure",
            "mqtt_runtime_environment_evidence",
            "mqtt_runtime_mount_evidence",
            "parse_process_table",
            "summarize_scanner_processes",
            "mqtt_file_secret_exposure_probe_command",
            "mqtt_authenticated_probe_command",
        ):
            self.assertNotIn(f"def {helper}", source)

    def test_license_report_consumers_use_rust_wrapper_with_expected_options(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "production_posture.rs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("command_license_report", source)
        self.assertIn(
            'rust_license_report_result(repo_root, modified_imported_only=True, diff_scope="staged", status_only=True)',
            source,
        )
        self.assertNotIn(
            'rust_license_report_result(repo_root, public_release=True, mode="source-public")',
            source,
        )
        self.assertIn("command_license_report_with_runner(", rust_source)
        self.assertIn('"source-public"', rust_source)
        self.assertEqual(source.count("license_result = rust_license_report_result(repo_root)"), 1)

    def test_runtime_redis_state_is_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-redis-state"', source)
        self.assertNotIn("def command_runtime_redis_state", source)
        self.assertIn("runtime-redis-state *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- runtime-redis-state", justfile)

    def test_runtime_db_introspect_is_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-db-introspect"', source)
        self.assertNotIn("def command_runtime_db_introspect", source)
        self.assertIn("runtime-db-introspect *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- runtime-db-introspect", justfile)

    def test_runtime_data_state_is_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-data-state"', source)
        self.assertNotIn("def command_runtime_data_state", source)
        self.assertIn("runtime-data-state *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- runtime-data-state", justfile)

    def test_runtime_performance_snapshot_is_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-performance-snapshot"', source)
        self.assertNotIn("def command_runtime_performance_snapshot", source)
        self.assertIn("runtime-performance-snapshot *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- runtime-performance-snapshot", justfile)

    def test_runtime_status_is_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-status"', source)
        self.assertNotIn("def command_runtime_status", source)
        self.assertIn("runtime-status *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- runtime-status", justfile)

    def test_runtime_smoke_is_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-smoke"', source)
        self.assertNotIn("def command_runtime_smoke", source)
        self.assertIn("runtime-smoke *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- runtime-smoke", justfile)

    def test_gvmd_smoke_is_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("gvmd-smoke"', source)
        self.assertNotIn("def command_gvmd_smoke", source)
        self.assertNotIn("def _command_gvmd_smoke_unlocked", source)
        self.assertIn("gvmd-smoke *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- gvmd-smoke", justfile)

    def test_up_is_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("up"', source)
        self.assertNotIn("def command_up", source)
        self.assertNotIn('rust_result_envelope(repo_root, "up", ["up"])', source)
        self.assertIn("up *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- up", justfile)

    def test_runtime_init_is_owned_directly_by_rust(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-init"', source)
        self.assertNotIn('args.command == "runtime-init"', source)
        self.assertNotIn("def command_runtime_init", source)
        self.assertIn("runtime-init *args:", justfile)
        self.assertIn("tools/yafvsctl-rs/Cargo.toml -- runtime-init", justfile)

    def test_runtime_scanner_redis_init_is_owned_directly_by_rust(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertNotIn('subparsers.add_parser("runtime-scanner-redis-init"', source)
        self.assertNotIn('args.command == "runtime-scanner-redis-init"', source)
        self.assertNotIn("def _command_runtime_scanner_redis_init_unlocked", source)
        self.assertNotIn("def command_runtime_scanner_redis_init", source)
        self.assertIn("runtime-scanner-redis-init *args:", justfile)
        self.assertIn(
            "tools/yafvsctl-rs/Cargo.toml -- runtime-scanner-redis-init",
            justfile,
        )

    def test_audit_commands_are_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        for command, function_name in (
            ("native-api-cargo-audit", "command_native_api_cargo_audit"),
            ("gsa-npm-audit", "command_gsa_npm_audit"),
            ("native-api-semgrep-audit", "command_native_api_semgrep_audit"),
            ("osv-lockfile-audit", "command_osv_lockfile_audit"),
        ):
            with self.subTest(command=command):
                self.assertNotIn(f'subparsers.add_parser("{command}"', source)
                self.assertNotIn(f"def {function_name}", source)
                self.assertIn(f"{command} *args:", justfile)
                self.assertIn(f"tools/yafvsctl-rs/Cargo.toml -- {command}", justfile)

    def test_policy_diagnostics_are_rust_only(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        for command, function_name in (
            ("path-coupling-state", "command_path_coupling_state"),
            ("security-policy-check", "command_security_policy_check"),
        ):
            with self.subTest(command=command):
                self.assertNotIn(f'subparsers.add_parser("{command}"', source)
                self.assertNotIn(f"def {function_name}", source)
                self.assertIn(f"{command} *args:", justfile)
                self.assertIn(f"tools/yafvsctl-rs/Cargo.toml -- {command}", justfile)






    def test_native_api_semgrep_policy_covers_the_tokio_postgres_query_surface(self):
        policy = (
            YAFVSCTL_PATH.parents[1] / "policy" / "semgrep-native-api.yml"
        ).read_text(encoding="utf-8")

        self.assertNotIn("sqlx::", policy)
        for method in (
            "query",
            "query_one",
            "query_opt",
            "query_raw",
            "execute",
            "batch_execute",
            "simple_query",
            "prepare",
            "prepare_typed",
        ):
            self.assertIn(f"$CLIENT.{method}", policy)








    def test_native_api_request_just_recipe_is_rust_direct(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        recipe = 'cargo run --quiet --locked --target-dir build/yafvsctl-rs --manifest-path tools/yafvsctl-rs/Cargo.toml -- native-api-request "$@"'
        self.assertIn('native-api-request *args:', justfile)
        self.assertIn(recipe, justfile)
        self.assertNotIn('tools/yafvsctl native-api-request "$@"', justfile)
        for surface in (
            'def command_native_api_request',
            'def validate_native_api_request_path',
            'def validate_native_api_request_method',
            'def validate_native_api_request_body_json',
            'def validate_native_api_request_shape',
            'def native_api_request_display_command',
            'def compact_native_api_request_finding',
            'def native_api_request_status_only_result',
            'subparsers.add_parser("native-api-request"',
            'args.command == "native-api-request"',
        ):
            with self.subTest(surface=surface):
                self.assertNotIn(surface, source)

    def test_native_api_rust_test_recipe_serializes_filters(self):
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertIn('native-api-rust-test *filters:', justfile)
        self.assertIn('cargo test --manifest-path services/yafvs-api/Cargo.toml --locked;', justfile)
        self.assertIn('for filter in "$@"; do', justfile)
        self.assertIn('cargo test --manifest-path services/yafvs-api/Cargo.toml --locked "$filter";', justfile)

    def test_gsa_vitest_recipe_runs_from_gsa_package(self):
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertIn('gsa-vitest *args:', justfile)
        self.assertIn('usage: just gsa-vitest -- <vitest-run-args>', justfile)
        self.assertIn('cd components/gsa && npm exec vitest -- run "$@"', justfile)
        self.assertNotIn('npm --prefix components/gsa exec vitest', justfile)

    def test_gsa_tests_do_not_restore_console_to_wrong_method(self):
        repo_root = Path(__file__).resolve().parents[2]
        source_roots = [
            repo_root / "components/gsa/src/web",
            repo_root / "components/gsa/src/gmp",
        ]
        forbidden = (
            "console.warn = consoleError",
            "console.warn = originalConsoleError",
            "console.error = consoleWarn",
            "const consoleError = console.log",
        )
        offenders: list[str] = []
        for source_root in source_roots:
            for path in source_root.rglob("*"):
                if not path.is_file() or path.suffix not in {".js", ".jsx", ".ts", ".tsx"}:
                    continue
                text = path.read_text(encoding="utf-8")
                for marker in forbidden:
                    if marker in text:
                        offenders.append(f"{path.relative_to(repo_root)}: {marker}")

        self.assertEqual(offenders, [])

    def test_native_api_smoke_summarizes_large_responses(self):
        payload = {
            "summary": {"alive_system_count": 4, "vulnerability_count": 2},
            "systems": [
                {"host": "192.0.2.10", "cvss_load": 11.0},
                {"host": "192.0.2.11", "cvss_load": 7.0},
                {"host": "192.0.2.12", "cvss_load": 1.0},
                {"host": "192.0.2.13", "cvss_load": 0.0},
            ],
            "vulnerabilities": [
                {"nvt_oid": "nvt-a", "name": "Finding A", "cvss_load": 14.0},
                {"nvt_oid": "nvt-b", "name": "Finding B", "cvss_load": 4.0},
                {"nvt_oid": "nvt-c", "name": "Finding C", "cvss_load": 1.0},
                {"nvt_oid": "nvt-d", "name": "Finding D", "cvss_load": 0.5},
            ],
        }
        summary = yafvsctl.summarize_native_api_response(payload)
        self.assertEqual(summary["summary"], payload["summary"])
        self.assertEqual(summary["systems_count"], 4)
        self.assertEqual(summary["vulnerabilities_count"], 4)
        self.assertEqual(len(summary["systems_sample"]), 3)
        self.assertEqual(len(summary["vulnerabilities_sample"]), 3)
        self.assertNotIn("systems", summary)
        self.assertNotIn("vulnerabilities", summary)

    def test_native_api_alert_metadata_validation_rejects_delivery_values(self):
        safe = {
            "id": "alert-1",
            "name": "Daily report",
            "comment": "operator note",
            "owner_id": "11111111-1111-4111-8111-111111111111",
            "owner": {"name": "admin"},
            "active": True,
            "event_type": "Task run status changed",
            "condition_type": "Always",
            "method_type": "Email",
            "filter": {"id": "filter-1", "name": "High"},
            "task_count": 2,
            "method_data_redacted": True,
            "created_at": "2026-06-21T00:00:00Z",
            "modified_at": "2026-06-21T00:00:00Z",
        }
        self.assertTrue(yafvsctl.alert_metadata_item_ok(safe))
        leaked_method = dict(safe, alert_method_data={"email": "operator@example.invalid"})
        self.assertFalse(yafvsctl.alert_metadata_item_ok(leaked_method))
        unredacted = dict(safe, method_data_redacted=False)
        self.assertFalse(yafvsctl.alert_metadata_item_ok(unredacted))
        invalid_owner = dict(safe, owner_id="not-a-uuid")
        self.assertFalse(yafvsctl.alert_metadata_item_ok(invalid_owner))

    def test_native_api_probe_finding_uses_response_summary(self):
        result = yafvsctl.subprocess.CompletedProcess(
            ["curl"],
            0,
            stdout=json.dumps({"systems": [{"host": f"192.0.2.{i}"} for i in range(20)]}),
            stderr="",
        )
        finding = yafvsctl.native_api_probe_finding(
            "pass",
            "native-api.example",
            "Example probe.",
            result,
            ["curl", "http://example.invalid"],
            json.loads(result.stdout),
        )
        details = finding["details"]
        self.assertEqual(details["response_summary"]["systems_count"], 20)
        self.assertEqual(len(details["response_summary"]["systems_sample"]), 3)
        self.assertNotIn("output_tail", details)

    def test_native_tooling_state_classifies_dependency_surfaces(self):
        root = Path(__file__).resolve().parents[2]
        result = yafvsctl.command_native_tooling_state(root)
        details = result["details"]
        self.assertEqual(result["status"], "pass")
        self.assertEqual(details["by_category"]["required_runtime"]["count"], 0)
        self.assertEqual(details["by_category"]["required_test"]["count"], 0)
        self.assertEqual(details["by_category"]["product_workflow"]["count"], 0)
        self.assertGreater(details["by_category"]["compatibility_bridge"]["count"], 0)
        self.assertIn("tools/yafvsctl", details["by_category"]["compatibility_bridge"]["paths"])
        self.assertIn("tools/tests/test_yafvsctl.py", details["by_category"]["compatibility_bridge"]["paths"])
        self.assertNotIn("tools/runtime_browser_smoke.py", details["by_category"]["required_runtime"]["paths"])
        self.assertFalse(any("tools/runtime_browser_smoke.py" in category["paths"] for category in details["by_category"].values()))
        self.assertNotIn("tools/runtime_report.py", details["by_category"]["required_runtime"]["paths"])
        self.assertNotIn("components/gvm-tools/scripts/list-reports.gmp.py", details["by_category"]["product_workflow"]["paths"])
        self.assertNotIn("components/gvm-tools/scripts/list-scopes.gmp.py", details["by_category"]["product_workflow"]["paths"])
        self.assertNotIn("components/gvm-tools/scripts/list-scope-reports.gmp.py", details["by_category"]["product_workflow"]["paths"])
        self.assertNotIn("components/gvm-tools/scripts/list-scope-report-results.gmp.py", details["by_category"]["product_workflow"]["paths"])
        self.assertNotIn("components/gvm-tools/scripts/generate-scope-report.gmp.py", details["by_category"]["product_workflow"]["paths"])
        self.assertFalse((root / "components" / "python-gvm").exists())
        self.assertFalse((root / "components" / "gvm-tools").exists())
        all_paths = {path for category in details["by_category"].values() for path in category["paths"]}
        self.assertNotIn("tools/runtime_metrics.py", all_paths)
        self.assertNotIn("components/gvm-tools/scripts/report-metrics.gmp.py", all_paths)
        self.assertNotIn("components/gvm-tools/scripts/scope-report-metrics.gmp.py", all_paths)
        for removed_wrapper in (
            "components/gvm-tools/scripts/application-detection.gmp.py",
            "components/gvm-tools/scripts/certbund-report.gmp.py",
            "components/gvm-tools/scripts/export-certificates.gmp.py",
            "components/gvm-tools/scripts/export-hosts-csv.gmp.py",
            "components/gvm-tools/scripts/export-operatingsystems-csv.gmp.py",
            "components/gvm-tools/scripts/list-alerts.gmp.py",
            "components/gvm-tools/scripts/list-credentials.gmp.py",
            "components/gvm-tools/scripts/list-feeds.gmp.py",
            "components/gvm-tools/scripts/list-hosts.gmp.py",
            "components/gvm-tools/scripts/list-filters.gmp.py",
            "components/gvm-tools/scripts/list-portlists.gmp.py",
            "components/gvm-tools/scripts/list-report-formats.gmp.py",
            "components/gvm-tools/scripts/list-scanners.gmp.py",
            "components/gvm-tools/scripts/list-schedules.gmp.py",
            "components/gvm-tools/scripts/list-targets.gmp.py",
            "components/gvm-tools/scripts/list-tasks.gmp.py",
            "components/gvm-tools/scripts/create-credentials-from-csv.gmp.py",
        ):
            self.assertNotIn(removed_wrapper, all_paths)
        self.assertNotIn("remaining gvm-tools write/control scripts", {item["workflow"] for item in details["next_replacement_candidates"]})
        endpoints = {item["endpoint"] for item in details["implemented_native_endpoints"]}
        self.assertIn("/api/v1/cpes", endpoints)
        self.assertIn("/api/v1/cpes/{cpe_id}", endpoints)
        self.assertIn("/api/v1/nvts", endpoints)

    def test_native_tooling_state_compact_omits_large_inventories(self):
        root = Path(__file__).resolve().parents[2]
        full = yafvsctl.command_native_tooling_state(root)
        compact = yafvsctl.command_native_tooling_state(root, compact=True)
        details = compact["details"]
        self.assertEqual(compact["status"], "pass")
        self.assertEqual(details["total_items"], full["details"]["total_items"])
        self.assertNotIn("items", details)
        self.assertNotIn("implemented_native_endpoints", details)
        self.assertIn("implemented_native_endpoint_count", details)
        self.assertIn("direct_api_contract", details)
        self.assertIn("browser_proxy_contract", details)
        self.assertNotIn("product_workflow_residue", details)
        self.assertNotIn("by_category", details)
        self.assertNotIn("candidate_for_removal_paths", details)
        self.assertIn("candidate_for_removal_review", details)
        review = details["candidate_for_removal_review"]
        self.assertEqual(review["safe_removal_count"], 0)
        self.assertEqual(review["total"], 0)
        self.assertEqual(review["blocked_or_review_count"], 0)
        self.assertEqual(review["tracked_baseline_count"], 26)
        self.assertEqual(review["tracked_removed_count"], 26)
        self.assertNotIn("write_or_mutation", review["bucket_counts"])
        self.assertNotIn("scanner_or_task_control", review["bucket_counts"])
        self.assertNotIn("export_or_report_generation", review["bucket_counts"])
        self.assertNotIn("credential_or_account", review["bucket_counts"])
        self.assertEqual(
            compact["findings"],
            [
                {
                    "status": "pass",
                    "check": "native-tooling.status-only",
                    "message": "Native tooling state passed; no non-pass findings.",
                }
            ],
        )

        for item in compact["findings"]:
            finding_details = item.get("details", {})
            self.assertNotIn("inventory_endpoints", finding_details)
            self.assertNotIn("rust_routes", finding_details)
            self.assertNotIn("operation_ids", finding_details)
            self.assertNotIn("openapi_collection_paths", finding_details)
        self.assertLess(len(json.dumps(compact)), len(json.dumps(full)))
        details = full["details"]
        product_residue = details["product_workflow_residue"]
        residue_count = sum(item["count"] for item in product_residue.values())
        self.assertEqual(residue_count, details["by_category"]["product_workflow"]["count"])
        self.assertNotIn("scan-config-import-or-xml-export", product_residue)
        self.assertNotIn("user-account-or-session", product_residue)
        self.assertEqual(residue_count, 0)
        self.assertNotIn("compatibility-parser-model-or-test", product_residue)
        self.assertIn(
            "components/gsa/src/gmp/locale/date.ts",
            details["by_category"]["compatibility_bridge"]["paths"],
        )
        self.assertNotIn("alert-delivery-and-credentials", product_residue)
        self.assertNotIn("task-target-scan-control-or-credential", product_residue)
        self.assertNotIn("scope-report-generation", product_residue)
        endpoints = {item["endpoint"] for item in details["implemented_native_endpoints"]}
        self.assertIn("/api/v1/cert-bund-advisories", endpoints)
        self.assertIn("/api/v1/cert-bund-advisories/{advisory_id}", endpoints)
        self.assertIn("/api/v1/dfn-cert-advisories", endpoints)
        self.assertIn("/api/v1/dfn-cert-advisories/{advisory_id}", endpoints)
        self.assertIn("/api/v1/results/{result_id}", endpoints)
        self.assertIn("/api/v1/reports", endpoints)
        self.assertIn("/api/v1/reports/{report_id}", endpoints)
        self.assertIn("/api/v1/reports/{report_id}/results", endpoints)
        self.assertIn("/api/v1/reports/{report_id}/ports", endpoints)
        self.assertIn("/api/v1/port-lists", endpoints)
        self.assertIn("/api/v1/port-lists/{port_list_id}", endpoints)
        self.assertIn("/api/v1/scan-configs", endpoints)
        self.assertIn("/api/v1/scan-configs/import", endpoints)
        self.assertIn("/api/v1/scan-configs/{scan_config_id}", endpoints)
        self.assertIn("/api/v1/scan-configs/{scan_config_id}/backup", endpoints)
        self.assertIn("/api/v1/scan-configs/{scan_config_id}/families", endpoints)
        self.assertIn(
            "/api/v1/scan-configs/{scan_config_id}/families/{family}/nvts",
            endpoints,
        )
        self.assertIn("/api/v1/feeds", endpoints)
        self.assertIn("/api/v1/alerts", endpoints)
        self.assertIn("/api/v1/alerts/{alert_id}", endpoints)
        self.assertIn("/api/v1/tags", endpoints)
        self.assertIn("/api/v1/tags/resource-names/{resource_type}", endpoints)
        self.assertIn("/api/v1/tags/{tag_id}", endpoints)
        self.assertIn("/api/v1/tags/{tag_id}/resources", endpoints)
        self.assertIn("/api/v1/overrides", endpoints)
        self.assertIn("/api/v1/overrides/{override_id}", endpoints)
        self.assertIn("/api/v1/schedules", endpoints)
        self.assertIn("/api/v1/schedules/{schedule_id}", endpoints)
        self.assertIn("/api/v1/trashcan/summary", endpoints)
        self.assertIn("/api/v1/scopes", endpoints)
        self.assertIn("/api/v1/scopes/{scope_id}", endpoints)
        self.assertIn("/api/v1/targets", endpoints)
        self.assertIn("/api/v1/targets/{target_id}", endpoints)
        self.assertIn("/api/v1/tasks", endpoints)
        self.assertIn("/api/v1/tasks/{task_id}", endpoints)
        self.assertIn("/api/v1/scope-reports", endpoints)
        self.assertIn("/api/v1/scope-reports/{scope_report_id}", endpoints)
        self.assertIn("/api/v1/scope-reports/{scope_report_id}/results", endpoints)
        self.assertIn("/api/v1/scopes/{scope_id}/reports/{scope_report_id}/hosts", endpoints)
        self.assertIn("/api/v1/scopes/{scope_id}/reports/{scope_report_id}/ports", endpoints)
        self.assertIn("/api/v1/scopes/{scope_id}/reports/{scope_report_id}/results", endpoints)
        self.assertIn("/api/v1/scopes/{scope_id}/reports/{scope_report_id}/cves", endpoints)
        self.assertIn("/api/v1/scopes/{scope_id}/reports/{scope_report_id}/errors", endpoints)
        self.assertIn("/api/v1/scopes/{scope_id}/reports/{scope_report_id}/metrics", endpoints)
        self.assertIn("/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan", endpoints)
        self.assertIn("/api/v1/reports/{report_id}/metrics", endpoints)
        result_detail = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/results/{result_id}")
        self.assertEqual(result_detail["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA Result detail metadata overlay (migrated through gsad same-origin proxy)", result_detail["replacement_candidates"])
        result_export = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/results/{result_id}/export")
        self.assertEqual(result_export["status"], "implemented_internal_browser_proxied_and_scriptable_read")
        self.assertIn("GSA result metadata export (migrated through gsad same-origin proxy)", result_export["replacement_candidates"])
        raw_reports = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/reports")
        self.assertEqual(raw_reports["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA raw report list (migrated through gsad same-origin proxy)", raw_reports["replacement_candidates"])
        raw_report_detail = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/reports/{report_id}")
        self.assertEqual(raw_report_detail["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA raw report detail summary (migrated through gsad same-origin proxy)", raw_report_detail["replacement_candidates"])
        scopes = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/scopes")
        self.assertEqual(scopes["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA scope list reads (migrated through gsad same-origin proxy)", scopes["replacement_candidates"])
        targets = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/targets/{target_id}")
        self.assertEqual(targets["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA target detail reads (migrated through gsad same-origin proxy)", targets["replacement_candidates"])
        target_export = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/targets/{target_id}/export")
        self.assertEqual(target_export["status"], "implemented_internal_browser_proxied_and_scriptable_read")
        self.assertIn("GSA target metadata export (migrated through gsad same-origin proxy)", target_export["replacement_candidates"])
        tasks = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/tasks/{task_id}")
        self.assertEqual(tasks["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA task detail reads (migrated through gsad same-origin proxy)", tasks["replacement_candidates"])
        scope_report_candidates = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/scope-reports")
        self.assertEqual(scope_report_candidates["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("runtime-scope-report-summary helper (migrated)", scope_report_candidates["replacement_candidates"])
        self.assertIn("GSA scope-report list reads (migrated through gsad same-origin proxy)", scope_report_candidates["replacement_candidates"])
        scope_report_detail = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/scope-reports/{scope_report_id}")
        self.assertEqual(scope_report_detail["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA scope-report detail summary and source reads (migrated through gsad same-origin proxy)", scope_report_detail["replacement_candidates"])
        cert_bund_detail = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/cert-bund-advisories/{advisory_id}")
        self.assertEqual(cert_bund_detail["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA Security Information CERT-Bund advisory rich detail reads (migrated through gsad same-origin proxy)", cert_bund_detail["replacement_candidates"])
        dfn_cert_detail = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/dfn-cert-advisories/{advisory_id}")
        self.assertEqual(dfn_cert_detail["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("GSA Security Information DFN-CERT advisory rich detail reads (migrated through gsad same-origin proxy)", dfn_cert_detail["replacement_candidates"])
        alerts = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/alerts")
        alert_create = next(
            item
            for item in details["implemented_native_endpoints"]
            if item.get("method") == "post" and item["endpoint"] == "/api/v1/alerts"
        )
        self.assertEqual(alert_create["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(alert_create["direct_access"], "direct_write_control")
        self.assertIn("direct native EMAIL/SMB/Syslog/SNMP/SCP/Start Task alert creation", alert_create["replacement_candidates"])
        self.assertIn("Delivery-payload mutations remain inherited.", alert_create["residual_inherited"])
        self.assertNotIn("Inherited test actions and delivery-payload mutations remain inherited.", alert_create["residual_inherited"])
        alert_test = next(
            item
            for item in details["implemented_native_endpoints"]
            if item.get("method") == "post"
            and item["endpoint"] == "/api/v1/alerts/{alert_id}/test"
        )
        self.assertEqual(alert_test["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(alert_test["direct_access"], "direct_write_control")
        self.assertIn("This is a real delivery action, not a validation preview.", alert_test["notes"])
        api_source = (root / "services" / "yafvs-api" / "src" / "read_api_routes.rs").read_text(encoding="utf-8")
        proxy_source = (root / "components" / "gsad" / "src" / "gsad_native_api.c").read_text(encoding="utf-8")
        alerts_api_declared = '.route("/api/v1/alerts"' in api_source
        alerts_proxy_declared = "/api/v1/alerts" in proxy_source
        if alerts_api_declared and alerts_proxy_declared:
            self.assertEqual(alerts["status"], "implemented_internal_and_browser_proxied")
        elif alerts_api_declared or alerts_proxy_declared:
            self.assertEqual(alerts["status"], "partial_internal_browser_proxy_mismatch")
        else:
            self.assertEqual(alerts["status"], "planned_internal_and_browser_proxied")
        self.assertIn("Metadata list only; alert delivery payload detail remains redacted.", alerts["notes"])
        alert_detail = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/alerts/{alert_id}")
        self.assertEqual(alert_detail["status"], "implemented_internal_and_browser_proxied")
        self.assertIn("Redacted metadata detail only; alert delivery and payload detail remain inherited.", alert_detail["notes"])
        alert_export = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/alerts/{alert_id}/export")
        self.assertEqual(alert_export["status"], "implemented_internal_browser_proxied_and_scriptable_read")
        self.assertIn("GSA alert metadata export (migrated through gsad same-origin proxy)", alert_export["replacement_candidates"])
        feeds = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/feeds")
        self.assertEqual(feeds["status"], "implemented_internal_browser_proxied_and_scriptable_read")
        self.assertIn("GSA Feed Status reads now use this same-origin native endpoint.", feeds["notes"])
        self.assertIn("/api/v1/feeds", proxy_source)
        trashcan_summary = next(item for item in details["implemented_native_endpoints"] if item["endpoint"] == "/api/v1/trashcan/summary")
        self.assertIn('/api/v1/tags/resource-names/', proxy_source)
        self.assertIn('is_tag_resource_type_segment', proxy_source)
        if "/api/v1/trashcan/summary" in api_source or "/api/v1/trashcan/summary" in proxy_source:
            self.assertEqual(trashcan_summary["status"], "implemented_internal_and_browser_proxied")
        else:
            self.assertEqual(trashcan_summary["status"], "planned_internal_and_browser_proxied")
        self.assertIn("row-level Trashcan data remains inherited/deferred", trashcan_summary["replacement_candidates"])
        contract = details["direct_api_contract"]
        self.assertEqual(contract["alignment_status"], "pass")
        self.assertGreater(contract["scriptable_read_count"], 0)
        self.assertEqual(contract["internal_only_count"], 0)

    def test_native_tooling_state_summary_is_low_noise(self):
        root = Path(__file__).resolve().parents[2]
        compact = yafvsctl.command_native_tooling_state(root, compact=True)
        summary = yafvsctl.command_native_tooling_state(root, summary_only=True)
        details = summary["details"]

        self.assertEqual(summary["status"], "pass")
        self.assertEqual(details["total_items"], compact["details"]["total_items"])
        self.assertIn("direct_api_contract", details)
        self.assertIn("browser_proxy_contract", details)
        self.assertIn("openapi_contract", details)
        self.assertNotIn("items", details)
        self.assertNotIn("implemented_native_endpoints", details)
        self.assertNotIn("candidate_for_removal_paths", details)
        self.assertNotIn("next_replacement_candidates", details)
        findings = {item["check"]: item for item in summary["findings"]}
        self.assertNotIn("paths", findings["native-tooling.unknown"]["details"])
        self.assertEqual(findings["native-tooling.unknown"]["details"], {"count": 0})
        self.assertLess(len(json.dumps(compact)), len(json.dumps(summary)))

    def test_native_tooling_state_status_only_is_chat_safe(self):
        root = Path(__file__).resolve().parents[2]
        summary = yafvsctl.command_native_tooling_state(root, summary_only=True)
        status_only = yafvsctl.command_native_tooling_state(root, status_only=True)

        self.assertEqual(status_only["status"], "pass")
        self.assertEqual(status_only["details"]["total_items"], summary["details"]["total_items"])
        self.assertEqual(
            set(status_only["details"]),
            {
                "total_items",
                "by_category_counts",
                "implemented_native_endpoint_count",
                "candidate_for_removal_review",
                "direct_api_contract",
                "browser_proxy_contract",
                "openapi_contract",
                "module_ownership",
            },
        )
        self.assertEqual(status_only["details"]["candidate_for_removal_review"]["safe_removal_count"], 0)
        self.assertIn("bucket_counts", status_only["details"]["candidate_for_removal_review"])
        self.assertNotIn("paths", json.dumps(status_only["details"]["candidate_for_removal_review"]))
        self.assertIn("direct_api_contract", status_only["details"])
        self.assertEqual(
            set(status_only["details"]["direct_api_contract"]),
            {
                "alignment_status",
                "rust_route_count",
                "openapi_marked_direct_count",
                "openapi_marked_direct_operation_count",
                "openapi_marked_direct_read_operation_count",
                "openapi_marked_direct_write_control_count",
                "non_get_openapi_marked_direct_count",
                "rust_direct_allowlist_count",
                "scriptable_read_count",
                "internal_only_count",
                "missing_openapi_direct_marker_count",
                "unexpected_openapi_direct_marker_count",
                "missing_rust_route_count",
                "untracked_rust_route_count",
                "missing_rust_direct_allowlist_count",
                "unexpected_rust_direct_allowlist_count",
                "segment_guard_alignment_status",
                "segment_guard_missing_property_count",
                "body_limit_alignment_status",
                "body_limit_missing_property_count",
            },
        )
        self.assertEqual(status_only["details"]["direct_api_contract"]["missing_openapi_direct_marker_count"], 0)
        self.assertEqual(status_only["details"]["direct_api_contract"]["unexpected_openapi_direct_marker_count"], 0)
        self.assertEqual(status_only["details"]["direct_api_contract"]["openapi_marked_direct_operation_count"], 215)
        self.assertEqual(status_only["details"]["direct_api_contract"]["openapi_marked_direct_read_operation_count"], 115)
        self.assertEqual(status_only["details"]["direct_api_contract"]["openapi_marked_direct_write_control_count"], 100)
        self.assertEqual(status_only["details"]["direct_api_contract"]["non_get_openapi_marked_direct_count"], 100)
        self.assertEqual(status_only["details"]["direct_api_contract"]["missing_rust_route_count"], 0)
        self.assertEqual(status_only["details"]["direct_api_contract"]["untracked_rust_route_count"], 0)
        self.assertEqual(status_only["details"]["direct_api_contract"]["missing_rust_direct_allowlist_count"], 0)
        self.assertEqual(status_only["details"]["direct_api_contract"]["unexpected_rust_direct_allowlist_count"], 0)
        self.assertEqual(status_only["details"]["direct_api_contract"]["segment_guard_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["direct_api_contract"]["segment_guard_missing_property_count"], 0)
        self.assertEqual(status_only["details"]["direct_api_contract"]["body_limit_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["direct_api_contract"]["body_limit_missing_property_count"], 0)
        self.assertEqual(
            set(status_only["details"]["browser_proxy_contract"]),
            {
                "alignment_status",
                "browser_proxied_count",
                "browser_write_proxy_count",
                "direct_write_control_count",
                "openapi_internal_only_count",
                "internal_only_count",
                "gsad_proxy_allowlist_count",
                "gsad_proxy_methods",
                "write_proxy_boundary_status",
                "write_proxy_requires_design",
                "browser_delete_proxy_requires_design",
                "browser_delete_proxy_design_count",
                "missing_gsad_proxy_allowlist_count",
                "missing_gsad_proxy_write_allowlist_count",
                "unexpected_gsad_proxy_allowlist_count",
                "unexpected_gsad_proxy_write_allowlist_count",
                "internal_only_gsad_proxy_allowlist_count",
                "parse_error_count",
                "write_parse_error_count",
                "method_parse_error_count",
            },
        )
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["browser_write_proxy_count"], 102)
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["direct_write_control_count"], 100)
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["gsad_proxy_methods"], ["DELETE", "PATCH", "POST", "PUT"])
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["write_proxy_boundary_status"], "pass")
        self.assertFalse(status_only["details"]["browser_proxy_contract"]["write_proxy_requires_design"])
        self.assertFalse(status_only["details"]["browser_proxy_contract"]["browser_delete_proxy_requires_design"])
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["browser_delete_proxy_design_count"], 0)
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["missing_gsad_proxy_allowlist_count"], 0)
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["unexpected_gsad_proxy_allowlist_count"], 0)
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["internal_only_gsad_proxy_allowlist_count"], 0)
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["parse_error_count"], 0)
        self.assertEqual(status_only["details"]["browser_proxy_contract"]["method_parse_error_count"], 0)
        self.assertEqual(
            set(status_only["details"]["openapi_contract"]),
            {
                "alignment_status",
                "operation_count",
                "missing_operation_id_count",
                "missing_operation_summary_count",
                "operation_request_body_count",
                "get_request_body_count",
                "duplicate_operation_id_count",
                "nondeterministic_operation_id_count",
                "missing_shared_error_response_count",
                "invalid_shared_error_response_count",
                "operations_missing_error_response_count",
                "missing_error_schema_field_count",
                "invalid_error_schema_field_count",
                "request_body_schema_ref_count",
                "missing_request_body_schema_ref_count",
                "invalid_request_body_schema_ref_count",
                "auth_contract_alignment_status",
                "missing_server_count",
                "unexpected_server_count",
                "missing_security_requirement_count",
                "unexpected_security_requirement_count",
                "missing_security_scheme_count",
                "unexpected_security_scheme_count",
                "security_scheme_mismatch_count",
                "collection_query_alignment_status",
                "openapi_collection_operation_count",
                "rust_collection_contract_count",
                "collection_limit_mismatch_count",
                "incomplete_collection_parameter_count",
                "missing_openapi_collection_parameter_count",
                "missing_rust_collection_contract_count",
                "write_control_alignment_status",
                "write_control_operation_count",
                "direct_write_control_operation_count",
                "missing_write_control_metadata_count",
                "invalid_write_control_metadata_count",
                "invalid_write_control_path_parameter_count",
            },
        )
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_operation_id_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["operation_request_body_count"], 54)
        self.assertEqual(status_only["details"]["openapi_contract"]["get_request_body_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["duplicate_operation_id_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["nondeterministic_operation_id_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_shared_error_response_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["invalid_shared_error_response_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["operations_missing_error_response_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_error_schema_field_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["invalid_error_schema_field_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["request_body_schema_ref_count"], 51)
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_request_body_schema_ref_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["invalid_request_body_schema_ref_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["auth_contract_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_server_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["unexpected_server_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_security_requirement_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["unexpected_security_requirement_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_security_scheme_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["unexpected_security_scheme_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["security_scheme_mismatch_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["collection_query_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["openapi_contract"]["collection_limit_mismatch_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["incomplete_collection_parameter_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_openapi_collection_parameter_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_rust_collection_contract_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["write_control_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["openapi_contract"]["write_control_operation_count"], 103)
        self.assertEqual(status_only["details"]["openapi_contract"]["direct_write_control_operation_count"], 100)
        self.assertEqual(status_only["details"]["openapi_contract"]["missing_write_control_metadata_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["invalid_write_control_metadata_count"], 0)
        self.assertEqual(status_only["details"]["openapi_contract"]["invalid_write_control_path_parameter_count"], 0)
        self.assertEqual(
            status_only["findings"],
            [
                {
                    "status": "pass",
                    "check": "native-tooling.status-only",
                    "message": "Native tooling state passed; no non-pass findings.",
                }
            ],
        )
        self.assertLess(len(json.dumps(status_only)), len(json.dumps(summary)) // 2)

    def test_native_tooling_state_tracks_direct_api_contract_alignment(self):
        root = Path(__file__).resolve().parents[2]
        result = yafvsctl.command_native_tooling_state(root)
        details = result["details"]
        endpoints = {item["endpoint"]: item for item in details["implemented_native_endpoints"]}
        endpoint_operations = {
            (item.get("method", "get"), item["endpoint"]): item
            for item in details["implemented_native_endpoints"]
        }
        contract = details["direct_api_contract"]
        findings = {item["check"]: item for item in result["findings"]}

        self.assertEqual(contract["alignment_status"], "pass")
        self.assertEqual(findings["native-tooling.direct-api-contract"]["status"], "pass")
        self.assertEqual(contract["missing_openapi_direct_markers"], [])
        self.assertEqual(contract["unexpected_openapi_direct_markers"], [])
        self.assertEqual(contract["missing_rust_routes"], [])
        self.assertEqual(contract["untracked_rust_routes"], [])
        self.assertEqual(contract["missing_rust_direct_allowlist"], [])
        self.assertEqual(contract["unexpected_rust_direct_allowlist"], [])
        self.assertEqual(contract["openapi_marked_direct_operation_count"], len(contract["openapi_marked_direct_operations"]))
        self.assertEqual(contract["openapi_marked_direct_read_operation_count"], 115)
        self.assertEqual(contract["openapi_marked_direct_write_control_count"], 100)
        self.assertEqual(
            contract["openapi_marked_direct_write_control_operations"],
            [
                "DELETE /api/v1/alerts/{alert_id}",
                "DELETE /api/v1/alerts/{alert_id}/trash",
                "DELETE /api/v1/credentials/{credential_id}",
                "DELETE /api/v1/credentials/{credential_id}/trash",
                "DELETE /api/v1/filters/{filter_id}",
                "DELETE /api/v1/filters/{filter_id}/trash",
                "DELETE /api/v1/host-identifiers/{identifier_id}",
                "DELETE /api/v1/host-operating-systems/{host_operating_system_id}",
                "DELETE /api/v1/hosts/{host_id}",
                "DELETE /api/v1/overrides/{override_id}",
                "DELETE /api/v1/overrides/{override_id}/trash",
                "DELETE /api/v1/port-lists/{port_list_id}",
                "DELETE /api/v1/port-lists/{port_list_id}/ranges/{port_range_id}",
                "DELETE /api/v1/port-lists/{port_list_id}/trash",
                "DELETE /api/v1/scan-configs/{scan_config_id}",
                "DELETE /api/v1/scan-configs/{scan_config_id}/trash",
                "DELETE /api/v1/scanners/{scanner_id}",
                "DELETE /api/v1/scanners/{scanner_id}/trash",
                "DELETE /api/v1/schedules/{schedule_id}",
                "DELETE /api/v1/schedules/{schedule_id}/trash",
                "DELETE /api/v1/scope-reports/{scope_report_id}",
                "DELETE /api/v1/scopes/{scope_id}",
                "DELETE /api/v1/tags/{tag_id}",
                "DELETE /api/v1/tags/{tag_id}/trash",
                "DELETE /api/v1/targets/{target_id}",
                "DELETE /api/v1/targets/{target_id}/trash",
                "DELETE /api/v1/tasks/{task_id}",
                "DELETE /api/v1/tasks/{task_id}/trash",
                "DELETE /api/v1/tls-certificates/{certificate_id}",
                "PATCH /api/v1/alerts/{alert_id}",
                "PATCH /api/v1/credentials/{credential_id}",
                "PATCH /api/v1/filters/{filter_id}",
                "PATCH /api/v1/hosts/{host_id}",
                "PATCH /api/v1/overrides/{override_id}",
                "PATCH /api/v1/port-lists/{port_list_id}",
                "PATCH /api/v1/scan-configs/{scan_config_id}",
                "PATCH /api/v1/scan-configs/{scan_config_id}/families/{family}/nvts",
                "PATCH /api/v1/scanners/{scanner_id}",
                "PATCH /api/v1/schedules/{schedule_id}",
                "PATCH /api/v1/scopes/{scope_id}",
                "PATCH /api/v1/tags/{tag_id}",
                "PATCH /api/v1/targets/{target_id}",
                "PATCH /api/v1/tasks/{task_id}",
                "POST /api/v1/alerts",
                "POST /api/v1/alerts/{alert_id}/clone",
                "POST /api/v1/alerts/{alert_id}/deliver-report",
                "POST /api/v1/alerts/{alert_id}/restore",
                "POST /api/v1/alerts/{alert_id}/test",
                "POST /api/v1/credentials",
                "POST /api/v1/credentials/{credential_id}/clone",
                "POST /api/v1/credentials/{credential_id}/restore",
                "POST /api/v1/filters",
                "POST /api/v1/filters/{filter_id}/clone",
                "POST /api/v1/filters/{filter_id}/restore",
                "POST /api/v1/hosts",
                "POST /api/v1/overrides",
                "POST /api/v1/overrides/{override_id}/clone",
                "POST /api/v1/overrides/{override_id}/restore",
                "POST /api/v1/port-list-imports",
                "POST /api/v1/port-lists",
                "POST /api/v1/port-lists/{port_list_id}/clone",
                "POST /api/v1/port-lists/{port_list_id}/ranges",
                "POST /api/v1/port-lists/{port_list_id}/restore",
                "POST /api/v1/scan-configs",
                "POST /api/v1/scan-configs/import",
                "POST /api/v1/scan-configs/{scan_config_id}/clone",
                "POST /api/v1/scan-configs/{scan_config_id}/diagnostic-nvt-selection",
                "POST /api/v1/scan-configs/{scan_config_id}/restore",
                "POST /api/v1/scanners",
                "POST /api/v1/scanners/{scanner_id}/clone",
                "POST /api/v1/scanners/{scanner_id}/replace-configuration",
                "POST /api/v1/scanners/{scanner_id}/restore",
                "POST /api/v1/scanners/{scanner_id}/verify",
                "POST /api/v1/schedules",
                "POST /api/v1/schedules/{schedule_id}/clone",
                "POST /api/v1/schedules/{schedule_id}/restore",
                "POST /api/v1/scopes",
                "POST /api/v1/scopes/{scope_id}/reports",
                "POST /api/v1/tags",
                "POST /api/v1/tags/{tag_id}/clone",
                "POST /api/v1/tags/{tag_id}/resources",
                "POST /api/v1/tags/{tag_id}/restore",
                "POST /api/v1/targets",
                "POST /api/v1/targets/{target_id}/clone",
                "POST /api/v1/targets/{target_id}/restore",
                "POST /api/v1/tasks",
                "POST /api/v1/tasks/{task_id}/clone",
                "POST /api/v1/tasks/{task_id}/replace-configuration",
                "POST /api/v1/tasks/{task_id}/replace-target",
                "POST /api/v1/tasks/{task_id}/restore",
                "POST /api/v1/tasks/{task_id}/start",
                "POST /api/v1/tasks/{task_id}/stop",
                "POST /api/v1/trashcan/empty",
                "POST /api/v1/user-management/users",
                "POST /api/v1/user-management/users/{user_id}/clone",
                "PUT /api/v1/alerts/{alert_id}/definition",
                "PUT /api/v1/authentication-settings/ldap",
                "PUT /api/v1/authentication-settings/radius",
                "PUT /api/v1/users/current/settings/{setting_id}",
                "PUT /api/v1/users/current/timezone",
            ],
        )
        self.assertEqual(contract["non_get_openapi_marked_direct_count"], 100)
        self.assertEqual(
            contract["non_get_openapi_marked_direct_operations"],
            [
                "DELETE /api/v1/alerts/{alert_id}",
                "DELETE /api/v1/alerts/{alert_id}/trash",
                "DELETE /api/v1/credentials/{credential_id}",
                "DELETE /api/v1/credentials/{credential_id}/trash",
                "DELETE /api/v1/filters/{filter_id}",
                "DELETE /api/v1/filters/{filter_id}/trash",
                "DELETE /api/v1/host-identifiers/{identifier_id}",
                "DELETE /api/v1/host-operating-systems/{host_operating_system_id}",
                "DELETE /api/v1/hosts/{host_id}",
                "DELETE /api/v1/overrides/{override_id}",
                "DELETE /api/v1/overrides/{override_id}/trash",
                "DELETE /api/v1/port-lists/{port_list_id}",
                "DELETE /api/v1/port-lists/{port_list_id}/ranges/{port_range_id}",
                "DELETE /api/v1/port-lists/{port_list_id}/trash",
                "DELETE /api/v1/scan-configs/{scan_config_id}",
                "DELETE /api/v1/scan-configs/{scan_config_id}/trash",
                "DELETE /api/v1/scanners/{scanner_id}",
                "DELETE /api/v1/scanners/{scanner_id}/trash",
                "DELETE /api/v1/schedules/{schedule_id}",
                "DELETE /api/v1/schedules/{schedule_id}/trash",
                "DELETE /api/v1/scope-reports/{scope_report_id}",
                "DELETE /api/v1/scopes/{scope_id}",
                "DELETE /api/v1/tags/{tag_id}",
                "DELETE /api/v1/tags/{tag_id}/trash",
                "DELETE /api/v1/targets/{target_id}",
                "DELETE /api/v1/targets/{target_id}/trash",
                "DELETE /api/v1/tasks/{task_id}",
                "DELETE /api/v1/tasks/{task_id}/trash",
                "DELETE /api/v1/tls-certificates/{certificate_id}",
                "PATCH /api/v1/alerts/{alert_id}",
                "PATCH /api/v1/credentials/{credential_id}",
                "PATCH /api/v1/filters/{filter_id}",
                "PATCH /api/v1/hosts/{host_id}",
                "PATCH /api/v1/overrides/{override_id}",
                "PATCH /api/v1/port-lists/{port_list_id}",
                "PATCH /api/v1/scan-configs/{scan_config_id}",
                "PATCH /api/v1/scan-configs/{scan_config_id}/families/{family}/nvts",
                "PATCH /api/v1/scanners/{scanner_id}",
                "PATCH /api/v1/schedules/{schedule_id}",
                "PATCH /api/v1/scopes/{scope_id}",
                "PATCH /api/v1/tags/{tag_id}",
                "PATCH /api/v1/targets/{target_id}",
                "PATCH /api/v1/tasks/{task_id}",
                "POST /api/v1/alerts",
                "POST /api/v1/alerts/{alert_id}/clone",
                "POST /api/v1/alerts/{alert_id}/deliver-report",
                "POST /api/v1/alerts/{alert_id}/restore",
                "POST /api/v1/alerts/{alert_id}/test",
                "POST /api/v1/credentials",
                "POST /api/v1/credentials/{credential_id}/clone",
                "POST /api/v1/credentials/{credential_id}/restore",
                "POST /api/v1/filters",
                "POST /api/v1/filters/{filter_id}/clone",
                "POST /api/v1/filters/{filter_id}/restore",
                "POST /api/v1/hosts",
                "POST /api/v1/overrides",
                "POST /api/v1/overrides/{override_id}/clone",
                "POST /api/v1/overrides/{override_id}/restore",
                "POST /api/v1/port-list-imports",
                "POST /api/v1/port-lists",
                "POST /api/v1/port-lists/{port_list_id}/clone",
                "POST /api/v1/port-lists/{port_list_id}/ranges",
                "POST /api/v1/port-lists/{port_list_id}/restore",
                "POST /api/v1/scan-configs",
                "POST /api/v1/scan-configs/import",
                "POST /api/v1/scan-configs/{scan_config_id}/clone",
                "POST /api/v1/scan-configs/{scan_config_id}/diagnostic-nvt-selection",
                "POST /api/v1/scan-configs/{scan_config_id}/restore",
                "POST /api/v1/scanners",
                "POST /api/v1/scanners/{scanner_id}/clone",
                "POST /api/v1/scanners/{scanner_id}/replace-configuration",
                "POST /api/v1/scanners/{scanner_id}/restore",
                "POST /api/v1/scanners/{scanner_id}/verify",
                "POST /api/v1/schedules",
                "POST /api/v1/schedules/{schedule_id}/clone",
                "POST /api/v1/schedules/{schedule_id}/restore",
                "POST /api/v1/scopes",
                "POST /api/v1/scopes/{scope_id}/reports",
                "POST /api/v1/tags",
                "POST /api/v1/tags/{tag_id}/clone",
                "POST /api/v1/tags/{tag_id}/resources",
                "POST /api/v1/tags/{tag_id}/restore",
                "POST /api/v1/targets",
                "POST /api/v1/targets/{target_id}/clone",
                "POST /api/v1/targets/{target_id}/restore",
                "POST /api/v1/tasks",
                "POST /api/v1/tasks/{task_id}/clone",
                "POST /api/v1/tasks/{task_id}/replace-configuration",
                "POST /api/v1/tasks/{task_id}/replace-target",
                "POST /api/v1/tasks/{task_id}/restore",
                "POST /api/v1/tasks/{task_id}/start",
                "POST /api/v1/tasks/{task_id}/stop",
                "POST /api/v1/trashcan/empty",
                "POST /api/v1/user-management/users",
                "POST /api/v1/user-management/users/{user_id}/clone",
                "PUT /api/v1/alerts/{alert_id}/definition",
                "PUT /api/v1/authentication-settings/ldap",
                "PUT /api/v1/authentication-settings/radius",
                "PUT /api/v1/users/current/settings/{setting_id}",
                "PUT /api/v1/users/current/timezone",
            ],
        )
        self.assertEqual(contract["segment_guard"]["alignment_status"], "pass")
        self.assertEqual(contract["segment_guard"]["missing_guard_properties"], [])
        self.assertEqual(contract["body_limit"]["alignment_status"], "pass")
        self.assertEqual(contract["body_limit"]["missing_body_limit_properties"], [])
        self.assertEqual(endpoints["/api/v1/reports"]["direct_access"], "scriptable_read")
        self.assertEqual(endpoints["/api/v1/reports/{report_id}/results"]["direct_access"], "scriptable_read")
        self.assertEqual(
            endpoint_operations[("get", "/api/v1/scope-reports/{scope_report_id}")]["direct_access"],
            "scriptable_read",
        )
        self.assertEqual(
            endpoint_operations[("delete", "/api/v1/scope-reports/{scope_report_id}")]["direct_access"],
            "direct_write_control",
        )
        self.assertEqual(endpoints["/api/v1/tags/resource-names/{resource_type}"]["direct_access"], "scriptable_read")
        self.assertEqual(endpoints["/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan"]["direct_access"], "scriptable_read")
        expected_scriptable = {
            f"/api/v1{path}"
            for (method, path), exposure in yafvsctl.OPENAPI_REQUIRED_EXPOSURE.items()
            if method == "get" and exposure == "direct-read"
        }
        expected_scriptable = {
            yafvsctl.normalize_native_api_endpoint_template(endpoint)
            for endpoint in expected_scriptable
        }
        openapi_scriptable = {
            yafvsctl.normalize_native_api_endpoint_template(endpoint)
            for endpoint in yafvsctl.openapi_direct_endpoint_templates(root)
        }
        self.assertEqual(yafvsctl.DIRECT_API_SCRIPTABLE_ENDPOINTS, openapi_scriptable)
        self.assertLessEqual(expected_scriptable, openapi_scriptable)
        self.assertEqual(
            set(contract["scriptable_read_endpoints"]),
            {item["endpoint"] for item in details["implemented_native_endpoints"] if item["direct_access"] == "scriptable_read"},
        )
        self.assertIn(
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan",
            contract["openapi_marked_direct_endpoints"],
        )
        self.assertIn("/api/v1/reports", contract["rust_route_endpoints"])
        self.assertIn("/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan", contract["rust_route_endpoints"])
        self.assertIn("/api/v1/reports", contract["rust_direct_allowlist_endpoints"])
        self.assertIn(
            "/api/v1/scopes/{}/reports/{}/retention-plan",
            contract["rust_direct_allowlist_endpoints"],
        )

    def test_native_tooling_state_tracks_module_ownership_alignment(self):
        root = Path(__file__).resolve().parents[2]
        result = yafvsctl.command_native_tooling_state(root)
        details = result["details"]
        findings = {item["check"]: item for item in result["findings"]}

        self.assertEqual(details["module_ownership"]["alignment_status"], "pass")
        self.assertEqual(details["module_ownership"]["misplaced_symbols"], [])
        self.assertEqual(details["module_ownership"]["missing_owner_symbols"], [])
        self.assertEqual(findings["native-tooling.module-ownership"]["status"], "pass")

    def test_native_api_module_ownership_reports_missing_and_misplaced_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            owner = root / "services" / "yafvs-api" / "src" / "owner.rs"
            forbidden = root / "services" / "yafvs-api" / "src" / "handler.rs"
            owner.parent.mkdir(parents=True)
            owner.write_text("pub(crate) struct OwnedSymbol;\n", encoding="utf-8")
            forbidden.write_text("pub(crate) struct DriftedSymbol;\n", encoding="utf-8")
            contract = (
                {
                    "owner": "services/yafvs-api/src/owner.rs",
                    "forbidden": ("services/yafvs-api/src/handler.rs",),
                    "symbols": ("pub(crate) struct OwnedSymbol", "pub(crate) struct DriftedSymbol"),
                },
            )

            with unittest.mock.patch.object(yafvsctl, "NATIVE_API_MODULE_OWNERSHIP_CONTRACTS", contract):
                summary = yafvsctl.native_api_module_ownership_summary(root)

        self.assertEqual(summary["alignment_status"], "warn")
        self.assertEqual(summary["checked_symbol_count"], 2)
        self.assertEqual(
            summary["missing_owner_symbols"],
            [{"owner": "services/yafvs-api/src/owner.rs", "symbol": "pub(crate) struct DriftedSymbol"}],
        )
        self.assertEqual(
            summary["misplaced_symbols"],
            [
                {
                    "path": "services/yafvs-api/src/handler.rs",
                    "owner": "services/yafvs-api/src/owner.rs",
                    "symbol": "pub(crate) struct DriftedSymbol",
                }
            ],
        )

    def test_openapi_direct_operation_templates_are_method_aware(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "paths:\n"
                "  /reports:\n"
                "    get:\n"
                "      operationId: getReports\n"
                "      x-yafvs-direct: true\n"
                "      x-yafvs-exposure: direct-read\n"
                "  /scopes:\n"
                "    post:\n"
                "      operationId: postScopes\n"
                "      x-yafvs-direct: true\n"
                "      x-yafvs-exposure: direct-write\n",
                encoding="utf-8",
            )

            operations = yafvsctl.openapi_direct_operation_templates(root)
            direct_read_endpoints = yafvsctl.openapi_direct_endpoint_templates(root)

        self.assertEqual(
            operations,
            [
                {"method": "get", "endpoint": "/api/v1/reports", "exposure": "direct-read"},
                {"method": "post", "endpoint": "/api/v1/scopes", "exposure": "direct-write"},
            ],
        )
        self.assertEqual(direct_read_endpoints, ["/api/v1/reports"])

    def test_scope_create_openapi_schema_matches_native_write_dto(self):
        root = Path(__file__).resolve().parents[2]
        block = yafvsctl.openapi_component_schema_block(root, "ScopeCreateRequest")
        fields = yafvsctl.openapi_indented_scalar_fields(block)

        self.assertEqual(fields.get("type"), "object")
        self.assertEqual(fields.get("additionalProperties"), "false")
        self.assertEqual(fields.get("properties.name.type"), "string")
        self.assertEqual(fields.get("properties.protection_requirement.enum"), "[normal, high, very_high]")
        self.assertEqual(fields.get("properties.target_ids.type"), "array")
        self.assertEqual(fields.get("properties.host_ids.type"), "array")
        self.assertNotIn("properties.port_ranges.type", fields)

    def test_native_tooling_state_fails_on_direct_contract_drift(self):
        root = Path(__file__).resolve().parents[2]
        drift = {"alignment_status": "warn", "missing_rust_routes": ["/api/v1/example"]}
        with unittest.mock.patch.object(yafvsctl, "native_api_direct_contract_summary", return_value=drift):
            result = yafvsctl.command_native_tooling_state(root, status_only=True)

        findings = {item["check"]: item for item in result["findings"]}
        self.assertEqual(result["status"], "fail")
        self.assertEqual(findings["native-tooling.direct-api-contract"]["status"], "fail")
        self.assertEqual(result["details"]["direct_api_contract"]["alignment_status"], "warn")

    def test_native_tooling_state_tracks_browser_proxy_contract_alignment(self):
        root = Path(__file__).resolve().parents[2]
        result = yafvsctl.command_native_tooling_state(root)
        details = result["details"]
        contract = details["browser_proxy_contract"]
        findings = {item["check"]: item for item in result["findings"]}

        self.assertEqual(contract["alignment_status"], "pass")
        self.assertEqual(findings["native-tooling.browser-proxy-contract"]["status"], "pass")
        self.assertEqual(contract["browser_write_proxy_count"], 102)
        self.assertEqual(contract["direct_write_control_count"], 100)
        self.assertEqual(contract["gsad_proxy_methods"], ["DELETE", "PATCH", "POST", "PUT"])
        self.assertEqual(contract["gsad_proxy_method_parse_errors"], [])
        self.assertEqual(contract["write_proxy_boundary_status"], "pass")
        self.assertFalse(contract["write_proxy_requires_design"])
        self.assertFalse(contract["browser_delete_proxy_requires_design"])
        self.assertEqual(contract["browser_delete_proxy_design_operations"], [])
        self.assertIn("DELETE /api/v1/targets/{target_id}", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/host-identifiers/{identifier_id}", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/host-operating-systems/{host_operating_system_id}", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/hosts/{host_id}", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/port-lists/{port_list_id}/ranges/{port_range_id}", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/tls-certificates/{certificate_id}", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/filters/{filter_id}/trash", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/alerts/{alert_id}", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/alerts/{alert_id}/trash", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/credentials/{credential_id}", contract["browser_write_proxy_operations"])
        self.assertIn("DELETE /api/v1/credentials/{credential_id}/trash", contract["browser_write_proxy_operations"])
        self.assertIn("PATCH /api/v1/alerts/{alert_id}", contract["browser_write_proxy_operations"])
        self.assertIn("PATCH /api/v1/filters/{filter_id}", contract["browser_write_proxy_operations"])
        self.assertIn("PATCH /api/v1/port-lists/{port_list_id}", contract["browser_write_proxy_operations"])
        self.assertIn("PATCH /api/v1/tags/{tag_id}", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/alerts", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/alerts/{alert_id}/clone", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/alerts/{alert_id}/restore", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/tasks/{task_id}/restore", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/alerts/{alert_id}/test", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/users/current/password", contract["browser_write_proxy_operations"])
        self.assertIn("PUT /api/v1/users/current/settings/{setting_id}", contract["browser_write_proxy_operations"])
        self.assertIn("PUT /api/v1/users/current/timezone", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/filters", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/filters/{filter_id}/clone", contract["browser_write_proxy_operations"])
        normalized_gsad_writes = {
            yafvsctl.normalize_native_api_operation_template(operation)
            for operation in contract["gsad_proxy_write_allowlist_operations"]
        }
        for override_write in (
            "POST /api/v1/overrides",
            "PATCH /api/v1/overrides/{override_id}",
            "DELETE /api/v1/overrides/{override_id}",
            "POST /api/v1/overrides/{override_id}/clone",
            "POST /api/v1/overrides/{override_id}/restore",
            "DELETE /api/v1/overrides/{override_id}/trash",
        ):
            self.assertIn(override_write, contract["browser_write_proxy_operations"])
            self.assertIn(
                yafvsctl.normalize_native_api_operation_template(override_write),
                normalized_gsad_writes,
            )
        self.assertIn("POST /api/v1/port-lists", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/port-lists/{port_list_id}/ranges", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/port-lists/{port_list_id}/clone", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/scan-configs", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/scan-configs/{scan_config_id}/clone", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/schedules/{schedule_id}/clone", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/tags", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/tags/{tag_id}/clone", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/tags/{tag_id}/resources", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/targets", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/targets/{target_id}/clone", contract["browser_write_proxy_operations"])
        for scanner_lifecycle_write in (
            "DELETE /api/v1/scanners/{scanner_id}",
            "POST /api/v1/scanners/{scanner_id}/clone",
            "POST /api/v1/scanners/{scanner_id}/restore",
            "DELETE /api/v1/scanners/{scanner_id}/trash",
        ):
            self.assertIn(scanner_lifecycle_write, contract["browser_write_proxy_operations"])
            self.assertIn(
                yafvsctl.normalize_native_api_operation_template(scanner_lifecycle_write),
                normalized_gsad_writes,
            )
        self.assertIn("POST /api/v1/tasks", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/tasks/{task_id}/clone", contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/tasks/{task_id}/replace-configuration", contract["browser_write_proxy_operations"])
        for proxied_write in [
            "DELETE /api/v1/credentials/{credential_id}",
            "PATCH /api/v1/credentials/{credential_id}",
            "PATCH /api/v1/scan-configs/{scan_config_id}",
            "PATCH /api/v1/scanners/{scanner_id}",
            "PATCH /api/v1/schedules/{schedule_id}",
            "PATCH /api/v1/scopes/{scope_id}",
            "PATCH /api/v1/targets/{target_id}",
            "PATCH /api/v1/tasks/{task_id}",
            "POST /api/v1/tasks/{task_id}/replace-configuration",
            "POST /api/v1/scopes",
            "POST /api/v1/tasks",
        ]:
            self.assertIn(proxied_write, contract["direct_write_control_operations"])
            self.assertIn(proxied_write, contract["browser_write_proxy_operations"])
        self.assertIn("POST /api/v1/tags", contract["direct_write_control_operations"])
        self.assertEqual(contract["missing_gsad_proxy_allowlist"], [])
        self.assertEqual(contract["unexpected_gsad_proxy_allowlist"], [])
        self.assertEqual(contract["internal_only_gsad_proxy_allowlist"], [])
        self.assertEqual(contract["parse_errors"], [])
        self.assertGreaterEqual(contract["browser_proxied_count"], contract["gsad_proxy_allowlist_count"])
        self.assertIn("/api/v1/reports/{}", contract["gsad_proxy_allowlist_endpoints"])
        self.assertIn("/api/v1/overrides/{}/clone", contract["gsad_proxy_allowlist_endpoints"])
        self.assertIn("/api/v1/overrides/{}/restore", contract["gsad_proxy_allowlist_endpoints"])
        self.assertIn("/api/v1/overrides/{}/trash", contract["gsad_proxy_allowlist_endpoints"])
        self.assertIn("/api/v1/users/current/settings", contract["gsad_proxy_allowlist_endpoints"])
        self.assertIn("/api/v1/users/current/settings/{}", contract["gsad_proxy_allowlist_endpoints"])
        self.assertIn("/api/v1/users/current/timezone", contract["gsad_proxy_allowlist_endpoints"])
        self.assertNotIn("/api/v1/session/ping", contract["gsad_proxy_allowlist_endpoints"])
        self.assertNotIn("/api/v1/session/renew", contract["gsad_proxy_allowlist_endpoints"])
        self.assertIn("/api/v1/scopes/{}/reports/{}/metrics", contract["gsad_proxy_allowlist_endpoints"])
        self.assertIn("/api/v1/scopes/{}/reports/{}/retention-plan", contract["gsad_proxy_allowlist_endpoints"])
        self.assertNotIn(
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan",
            contract["internal_only_endpoints"],
        )
        self.assertNotIn(
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan",
            contract["openapi_internal_only_endpoints"],
        )
        self.assertNotIn("/api/v1/scopes", contract["openapi_internal_only_endpoints"])
        self.assertNotIn("/api/v1/scopes/{scope_id}", contract["openapi_internal_only_endpoints"])

    def test_native_tooling_state_reports_browser_proxy_contract_drift(self):
        endpoints = [
            {"endpoint": "/api/v1/reports", "status": "implemented_internal_and_browser_proxied"},
            {"endpoint": "/api/v1/targets", "status": "implemented_internal_and_browser_proxied"},
            {"endpoint": "/api/v1/scope-reports/{scope_report_id}", "status": "implemented_internal_and_browser_proxied"},
            {"endpoint": "/api/v1/scopes/{scope_id}", "status": "implemented_internal_and_browser_proxied"},
            {"endpoint": "/api/v1/scope-reports/{scope_report_id}/results", "status": "implemented_internal_and_browser_proxied"},
            {"endpoint": "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/results", "status": "implemented_internal_and_browser_proxied"},
            {"endpoint": "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan", "status": "implemented_internal"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "paths:\n"
                "  /scopes/{scope_id}/reports/{scope_report_id}/retention-plan:\n"
                "    get:\n"
                "      operationId: getScopesByScopeIdReportsByScopeReportIdRetentionPlan\n"
                "      x-yafvs-exposure: internal-only\n"
                "  /scopes/{scope_id}:\n"
                "    patch:\n"
                "      operationId: patchScopesByScopeId\n"
                "      x-yafvs-exposure: internal-only\n",
                encoding="utf-8",
            )
            proxy_source = root / "components" / "gsad" / "src" / "gsad_native_api.c"
            proxy_source.parent.mkdir(parents=True)
            proxy_source.write_text(
                "static gboolean\n"
                "native_api_path_is_allowed (const gchar *path)\n"
                "{\n"
                "  const gchar *reports_path = \"/api/v1/reports\";\n"
                "  const gchar *feeds_path = \"/api/v1/feeds\";\n"
                "  const gchar *scope_report_prefix = \"/api/v1/scope-reports/\";\n"
                "  const gchar *scope_report_results_suffix = \"/results\";\n"
                "  const gchar *scope_prefix = \"/api/v1/scopes/\";\n"
                "  const gchar *scope_collection_suffixes[] = { \"/results\", \"/retention-plan\", NULL };\n"
                "\n"
                "  if (g_strcmp0 (path, reports_path) == 0)\n"
                "    return TRUE;\n"
                "  if (g_strcmp0 (path, feeds_path) == 0)\n"
                "    return TRUE;\n"
                "  if (g_str_has_prefix (path, scope_report_prefix))\n"
                "    {\n"
                "      const gchar *id = path + strlen (scope_report_prefix);\n"
                "      if (g_str_has_suffix (id, scope_report_results_suffix))\n"
                "        return TRUE;\n"
                "      return TRUE;\n"
                "    }\n"
                "  if (g_str_has_prefix (path, scope_prefix))\n"
                "    return TRUE;\n"
                "\n"
                "  return FALSE;\n"
                "}\n",
                encoding="utf-8",
            )
            request_source = root / "components" / "gsad" / "src" / "gsad_http_handle_request.c"
            request_source.write_text(
                'gsad_http_url_handler_new ("^/api/v1/.+$", gsad_http_method_handler_new_get (native_api_get_handler));\n',
                encoding="utf-8",
            )

            summary = yafvsctl.native_api_browser_proxy_contract_summary(root, endpoints)

        self.assertEqual(summary["alignment_status"], "warn")
        self.assertEqual(summary["missing_gsad_proxy_allowlist"], ["/api/v1/targets"])
        self.assertNotIn("/api/v1/scope-reports/{scope_report_id}/results", summary["missing_gsad_proxy_allowlist"])
        self.assertEqual(summary["unexpected_gsad_proxy_allowlist"], ["/api/v1/feeds"])
        self.assertEqual(
            summary["internal_only_gsad_proxy_allowlist"],
            ["/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan"],
        )
        self.assertNotIn("/api/v1/scopes/{scope_id}", summary["openapi_internal_only_endpoints"])
        self.assertEqual(summary["parse_errors"], [])

    def test_native_tooling_state_reports_browser_write_proxy_boundary_drift(self):
        endpoints = [
            {
                "endpoint": "/api/v1/tags",
                "method": "post",
                "status": "implemented_internal_and_browser_proxied",
                "direct_access": "direct_write_control",
            },
            {
                "endpoint": "/api/v1/tags/{tag_id}/resources",
                "method": "post",
                "status": "implemented_internal_and_browser_proxied",
                "direct_access": "direct_write_control",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            proxy_source = root / "components" / "gsad" / "src" / "gsad_native_api.c"
            proxy_source.parent.mkdir(parents=True)
            proxy_source.write_text(
                "static gboolean\n"
                "native_api_path_is_allowed (const gchar *path)\n"
                "{\n"
                "  const gchar *tags_path = \"/api/v1/tags\";\n"
                "  if (g_strcmp0 (path, tags_path) == 0)\n"
                "    return TRUE;\n"
                "  return FALSE;\n"
                "}\n",
                encoding="utf-8",
            )
            request_source = root / "components" / "gsad" / "src" / "gsad_http_handle_request.c"
            request_source.write_text(
                'gsad_http_url_handler_new ("^/api/v1/.+$", gsad_http_method_handler_new_get (native_api_get_handler));\n',
                encoding="utf-8",
            )

            summary = yafvsctl.native_api_browser_proxy_contract_summary(root, endpoints)

        self.assertEqual(summary["alignment_status"], "warn")
        self.assertEqual(summary["write_proxy_boundary_status"], "warn")
        self.assertEqual(summary["gsad_proxy_methods"], ["GET"])
        self.assertFalse(summary["browser_delete_proxy_requires_design"])
        self.assertEqual(summary["browser_delete_proxy_design_operations"], [])
        self.assertEqual(summary["browser_write_proxy_operations"], ["POST /api/v1/tags", "POST /api/v1/tags/{tag_id}/resources"])
        self.assertEqual(summary["direct_write_control_operations"], ["POST /api/v1/tags", "POST /api/v1/tags/{tag_id}/resources"])

    def test_native_tooling_state_reports_browser_delete_proxy_design_gap(self):
        endpoints = [
            {
                "endpoint": "/api/v1/tags",
                "method": "post",
                "status": "implemented_internal_and_browser_proxied",
                "direct_access": "direct_write_control",
            },
            {
                "endpoint": "/api/v1/tags/{tag_id}",
                "method": "delete",
                "status": "implemented_direct_write_control",
                "direct_access": "direct_write_control",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            proxy_source = root / "components" / "gsad" / "src" / "gsad_native_api.c"
            proxy_source.parent.mkdir(parents=True)
            proxy_source.write_text(
                "static gboolean\n"
                "native_api_path_is_allowed (const gchar *path)\n"
                "{\n"
                "  return FALSE;\n"
                "}\n"
                "static gboolean\n"
                "native_api_post_path_is_allowed (const gchar *path)\n"
                "{\n"
                "  const gchar *tags_path = \"/api/v1/tags\";\n"
                "  if (g_strcmp0 (path, tags_path) == 0)\n"
                "    return TRUE;\n"
                "  return FALSE;\n"
                "}\n",
                encoding="utf-8",
            )
            request_source = root / "components" / "gsad" / "src" / "gsad_http_handle_request.c"
            request_source.write_text(
                'gsad_http_url_handler_new ("^/api/v1/.+$",\n'
                "  gsad_http_method_handler_new_with_post_handler (native_api_get_handler, native_api_post_handler));\n",
                encoding="utf-8",
            )

            summary = yafvsctl.native_api_browser_proxy_contract_summary(root, endpoints)

        self.assertEqual(summary["alignment_status"], "pass")
        self.assertEqual(summary["write_proxy_boundary_status"], "pass")
        self.assertTrue(summary["browser_delete_proxy_requires_design"])
        self.assertEqual(summary["browser_delete_proxy_design_operations"], ["DELETE /api/v1/tags/{tag_id}"])
        self.assertEqual(summary["browser_write_proxy_operations"], ["POST /api/v1/tags"])
        self.assertEqual(summary["missing_gsad_proxy_allowlist"], [])

    def test_native_tooling_state_reports_direct_api_contract_drift(self):
        endpoints = [
            {"endpoint": "/api/v1/reports", "direct_access": "scriptable_read"},
            {"endpoint": "/api/v1/targets", "direct_access": "scriptable_read"},
            {"endpoint": "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan", "direct_access": "internal_only"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "paths:\n"
                "  /feeds:\n"
                "    get:\n"
                "      x-yafvs-direct: true\n",
                encoding="utf-8",
            )
            source_dir = root / "services" / "yafvs-api" / "src"
            api_source = source_dir / "main.rs"
            api_contract_source = source_dir / "direct_api_contract.rs"
            routes_source = source_dir / "read_api_routes.rs"
            source_dir.mkdir(parents=True)
            routes_source.write_text(
                'fn router() { Router::new()\n'
                '    .route("/api/v1/reports", get(reports))\n'
                '    .route("/api/v1/orphans", get(orphans)); }\n'
                'fn direct_native_api_router() {}\n',
                encoding="utf-8",
            )
            api_source.write_text(
                "",
                encoding="utf-8",
            )
            api_contract_source.write_text(
                'fn direct_api_v1_path_is_allowed(path: &str) -> bool {\n'
                '    let parts = path.split(\'/\').collect::<Vec<_>>();\n'
                '    matches!(parts.as_slice(), ["", "api", "v1", "reports"] | ["", "api", "v1", "feeds"] if direct_api_segments_are_nonempty(&parts))\n'
                '}\n'
                'fn direct_api_segments_are_nonempty(parts: &[&str]) -> bool {\n'
                '    parts.iter().skip(4).all(|part| !part.is_empty())\n'
                '}\n'
                'fn direct_api_wildcard_detail_path_is_allowed(_path: &str) -> bool { false }\n',
                encoding="utf-8",
            )
            request_shapes = root / "services" / "yafvs-api" / "src" / "request_shapes.rs"
            request_shapes.write_text("", encoding="utf-8")
            summary = yafvsctl.native_api_direct_contract_summary(root, endpoints)

        self.assertEqual(summary["alignment_status"], "warn")
        self.assertEqual(summary["missing_openapi_direct_markers"], ["/api/v1/reports", "/api/v1/targets"])
        self.assertEqual(summary["unexpected_openapi_direct_markers"], ["/api/v1/feeds"])
        self.assertEqual(summary["missing_rust_routes"], ["/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan", "/api/v1/targets"])
        self.assertEqual(summary["untracked_rust_routes"], ["/api/v1/orphans"])
        self.assertEqual(summary["missing_rust_direct_allowlist"], ["/api/v1/targets"])
        self.assertEqual(summary["unexpected_rust_direct_allowlist"], ["/api/v1/feeds"])
        missing_guard_properties = {
            (item["guard"], item["property"])
            for item in summary["segment_guard"]["missing_guard_properties"]
        }
        self.assertIn(("direct_api_segments_are_nonempty", "rejects_dot"), missing_guard_properties)
        self.assertIn(("direct_api_segments_are_nonempty", "rejects_dotdot"), missing_guard_properties)
        self.assertIn(("direct_api_wildcard_tail_is_allowed", "rejects_empty"), missing_guard_properties)
        self.assertEqual(summary["body_limit"]["alignment_status"], "warn")
        self.assertIn("uses_default_body_limit", summary["body_limit"]["missing_body_limit_properties"])
        self.assertIn("uses_shared_write_limit", summary["body_limit"]["missing_body_limit_properties"])

    def test_native_tooling_state_tracks_openapi_contract_alignment(self):
        root = Path(__file__).resolve().parents[2]
        result = yafvsctl.command_native_tooling_state(root)
        details = result["details"]
        contract = details["openapi_contract"]
        findings = {item["check"]: item for item in result["findings"]}

        self.assertEqual(contract["alignment_status"], "pass")
        self.assertEqual(findings["native-tooling.openapi-contract"]["status"], "pass")
        self.assertEqual(contract["operation_count"], 218)
        self.assertEqual(contract["missing_operation_ids"], [])
        self.assertEqual(contract["missing_operation_summaries"], [])
        self.assertIn(
            "POST /tasks/{task_id}/replace-target",
            contract["operations_with_request_bodies"],
        )
        self.assertIn(
            "POST /tasks/{task_id}/replace-configuration",
            contract["operations_with_request_bodies"],
        )
        self.assertEqual(
            [
                operation
                for operation in contract["operations_with_request_bodies"]
                if operation not in {
                    "POST /tasks/{task_id}/replace-target",
                    "POST /tasks/{task_id}/replace-configuration",
                }
            ],
            [
                "POST /hosts",
                "PATCH /hosts/{host_id}",
                "POST /scanners",
                "PATCH /scanners/{scanner_id}",
                "POST /scanners/{scanner_id}/replace-configuration",
                "POST /scanners/{scanner_id}/clone",
                "POST /credentials",
                "PATCH /credentials/{credential_id}",
                "POST /filters",
                "PATCH /filters/{filter_id}",
                "POST /filters/{filter_id}/clone",
                "POST /alerts",
                "PATCH /alerts/{alert_id}",
                "PUT /alerts/{alert_id}/definition",
                "POST /alerts/{alert_id}/clone",
                "POST /alerts/{alert_id}/deliver-report",
                "POST /tags",
                "PATCH /tags/{tag_id}",
                "POST /tags/{tag_id}/clone",
                "POST /tags/{tag_id}/resources",
                "POST /overrides",
                "PATCH /overrides/{override_id}",
                "POST /overrides/{override_id}/clone",
                "POST /port-lists",
                "POST /port-list-imports",
                "PATCH /port-lists/{port_list_id}",
                "POST /port-lists/{port_list_id}/ranges",
                "POST /port-lists/{port_list_id}/clone",
                "POST /schedules",
                "PATCH /schedules/{schedule_id}",
                "POST /schedules/{schedule_id}/clone",
                "PUT /authentication-settings/ldap",
                "PUT /authentication-settings/radius",
                "POST /user-management/users",
                "PATCH /user-management/users/{user_id}",
                "PUT /users/current/settings/{setting_id}",
                "PUT /users/current/timezone",
                "POST /users/current/password",
                "POST /scan-configs",
                "PATCH /scan-configs/{scan_config_id}",
                "POST /scan-configs/{scan_config_id}/diagnostic-nvt-selection",
                "POST /scan-configs/{scan_config_id}/clone",
                "PATCH /scan-configs/{scan_config_id}/families/{family}/nvts",
                "POST /scan-configs/import",
                "POST /trashcan/empty",
                "POST /scopes",
                "PATCH /scopes/{scope_id}",
                "POST /targets",
                "PATCH /targets/{target_id}",
                "POST /targets/{target_id}/clone",
                "POST /tasks",
                "PATCH /tasks/{task_id}",
            ],
        )
        self.assertEqual(contract["duplicate_operation_ids"], [])
        self.assertEqual(contract["nondeterministic_operation_ids"], [])

        self.assertEqual(
            contract["allowed_yafvs_operation_fields"],
            [
                "x-yafvs-direct",
                "x-yafvs-exposure",
                "x-yafvs-inherited-still-owns",
                "x-yafvs-maturity",
                "x-yafvs-operator-identity",
                "x-yafvs-owner-semantics",
                "x-yafvs-profile",
                "x-yafvs-replaces",
                "x-yafvs-safety-contract",
                "x-yafvs-side-effect",
                "x-yafvs-team-authority",
            ],
        )
        self.assertEqual(contract["unexpected_yafvs_operation_fields"], [])
        self.assertEqual(contract["allowed_exposure_values"], ["browser-write", "direct-read", "direct-write", "internal-only"])
        actual_exposure_values = sorted(
            {operation["x_yafvs_values"]["x-yafvs-exposure"] for operation in yafvsctl.openapi_contract_operations(root)}
        )
        self.assertTrue(set(actual_exposure_values).issubset(set(contract["allowed_exposure_values"])))
        self.assertEqual(contract["allowed_maturity_values"], ["live-control", "live-read", "live-write", "preview-control", "preview-read", "preview-write"])
        actual_maturity_values = sorted(
            {operation["x_yafvs_values"]["x-yafvs-maturity"] for operation in yafvsctl.openapi_contract_operations(root)}
        )
        self.assertTrue(set(actual_maturity_values).issubset(set(contract["allowed_maturity_values"])))
        expected_replaces_values = ['alert-clone',
         'alert-deliver-report',
         'alert-email-smb-syslog-snmp-scp-start-task-create',
         'alert-metadata-detail-read',
         'alert-metadata-export-read',
         'alert-metadata-list-read',
         'alert-metadata-modify',
         'alert-retained-definition-modify',
         'alert-retained-definition-read',
         'alert-test-actions',
         'alert-trash-hard-delete',
         'alert-trash-move',
         'alert-trash-restore',
         'authentication-provider-settings-read',
         'cert-bund-advisory-catalog-detail-read',
         'cert-bund-advisory-list-read',
         'cert-bund-advisory-metadata-export-read',
         'cpe-catalog-detail-read',
         'cpe-catalog-list-read',
         'credential-client-certificate-download-read',
         'credential-clone',
         'credential-live-move-to-trash',
         'credential-metadata-modify',
         'credential-redacted-metadata-detail-read',
         'credential-redacted-metadata-export-read',
         'credential-redacted-metadata-list-read',
         'credential-ssh-public-key-download-read',
         'credential-trash-hard-delete',
         'credential-trash-restore',
         'credential-up-usk-create',
         'current-user-setting-read',
         'current-user-setting-write',
         'current-user-settings-read',
         'current-user-timezone-write',
         'cve-catalog-detail-epss-reference-configuration-read',
         'cve-catalog-list-read',
         'cve-catalog-metadata-export-read',
         'dfn-cert-advisory-catalog-detail-read',
         'dfn-cert-advisory-list-read',
         'dfn-cert-advisory-metadata-export-read',
         'feed-status-read',
         'host-asset-detail-info-read',
         'host-asset-list-read',
         'host-asset-metadata-export-read',
         'host-comment-modify',
         'host-hard-delete',
         'host-identifier-delete',
         'host-manual-create',
         'host-operating-system-delete',
         'ldap-authentication-provider-settings-write',
         'native-evidence-pdf-report-download',
         'none',
         'nvt-catalog-detail-read',
         'nvt-catalog-list-read',
         'nvt-catalog-metadata-export-read',
         'nvt-family-list-read',
         'operating-system-asset-detail-info-read',
         'operating-system-asset-list-read',
         'operating-system-asset-metadata-export-read',
         'override-clone',
         'override-create',
         'override-hard-delete',
         'override-metadata-detail-read',
         'override-metadata-export-read',
         'override-metadata-list-read',
         'override-metadata-modify',
         'override-restore',
         'override-trash-move',
         'port-list-clone',
         'port-list-create',
         'port-list-hard-delete',
         'port-list-import',
         'port-list-metadata-and-range-modify',
         'port-list-metadata-detail-read',
         'port-list-metadata-export-read',
         'port-list-metadata-list-read',
         'port-list-range-create',
         'port-list-range-delete',
         'port-list-restore',
         'port-list-trash-move',
         'radius-authentication-provider-settings-write',
         'raw-report-application-evidence-read',
         'raw-report-cve-evidence-read',
         'raw-report-detail-summary-read',
         'raw-report-error-message-evidence-read',
         'raw-report-host-evidence-read',
         'raw-report-list-read',
         'raw-report-lossless-result-evidence-read',
         'raw-report-metrics-read',
         'raw-report-operating-system-evidence-read',
         'raw-report-port-evidence-read',
         'raw-report-result-evidence-read',
         'raw-report-tls-certificate-evidence-read',
         'report-format-metadata-detail-read',
         'report-format-metadata-export-read',
         'report-format-metadata-list-read',
         'result-detail-metadata-tags-and-overrides-read',
         'result-list-and-effective-overrides-read',
         'result-metadata-export-read',
         'saved-filter-clone',
         'saved-filter-create',
         'saved-filter-hard-delete',
         'saved-filter-metadata-detail-read',
         'saved-filter-metadata-export-read',
         'saved-filter-metadata-list-read',
         'saved-filter-metadata-modify',
         'saved-filter-restore',
         'saved-filter-trash-move',
         'scan-config-clone',
         'scan-config-create-from-base',
         'scan-config-detail-info-tags-task-backlinks-and-preferences-read',
         'scan-config-diagnostic-nvt-selection',
         'scan-config-family-mode-and-preference-mutation',
         'scan-config-family-nvt-selection-mutation',
         'scan-config-family-nvt-selection-read',
         'scan-config-family-summary-read',
         'scan-config-hard-delete',
         'scan-config-metadata-export-read',
         'scan-config-metadata-list-read',
         'scan-config-restore',
         'scan-config-trash-move',
         'scan-config-versioned-json-backup',
         'scan-config-versioned-json-import',
         'scanner-clone',
         'scanner-complete-retained-editor-configuration-modify',
         'scanner-create',
         'scanner-hard-delete',
         'scanner-metadata-detail-info-tags-and-task-backlink-read',
         'scanner-metadata-export-read',
         'scanner-metadata-list-read',
         'scanner-metadata-modify',
         'scanner-restore',
         'scanner-trash-move',
         'scanner-verify',
         'schedule-clone',
         'schedule-create',
         'schedule-hard-delete',
         'schedule-metadata-detail-read',
         'schedule-metadata-export-read',
         'schedule-metadata-list-read',
         'schedule-metadata-modify',
         'schedule-restore',
         'schedule-trash-move',
         'scope-detail-membership-read',
         'scope-list-read',
         'scope-metadata-membership-write',
         'scope-report-application-evidence-read',
         'scope-report-cve-evidence-read',
         'scope-report-delete',
         'scope-report-detail-summary-read',
         'scope-report-error-message-evidence-read',
         'scope-report-generation',
         'scope-report-host-evidence-read',
         'scope-report-list-read',
         'scope-report-metrics-read',
         'scope-report-operating-system-evidence-read',
         'scope-report-port-evidence-read',
         'scope-report-result-evidence-read',
         'scope-report-tls-certificate-evidence-read',
         'tag-active-resource-assignment-write',
         'tag-clone',
         'tag-hard-delete',
         'tag-metadata-and-explicit-resource-assignment-write',
         'tag-metadata-export-read',
         'tag-metadata-read',
         'tag-metadata-resource-type-and-atomic-assignment-write',
         'tag-resource-name-read',
         'tag-resource-reference-read',
         'tag-restore',
         'tag-trash-move',
         'target-clone',
         'target-create-with-optional-credential-references',
         'target-detail-summary-read',
         'target-hard-delete',
         'target-list-read',
         'target-metadata-export-read',
         'target-metadata-simple-scan-inputs-and-credential-links-modify',
         'target-restore',
         'target-trash-move',
         'task-clone',
         'task-create-with-retained-editor-configuration',
         'task-detail-summary-read',
         'task-list-read',
         'task-metadata-export-read',
         'task-metadata-modify',
         'task-retained-editor-configuration-modify',
         'task-start',
         'task-stop',
         'task-target-clone-rebind-delete',
         'task-trash-hard-delete',
         'task-trash-move',
         'task-trash-restore',
         'timezone-list-read',
         'tls-certificate-asset-detail-info-read',
         'tls-certificate-asset-list-read',
         'tls-certificate-asset-metadata-export-read',
         'tls-certificate-delete',
         'tls-certificate-pem-download-read',
         'trashcan-count-summary-read',
         'trashcan-empty',
         'trashcan-owner-empty-preview',
         'trashcan-redacted-row-metadata-read',
         'user-account-clone',
         'user-account-create',
         'user-account-delete',
         'user-account-modify',
         'user-current-password-change',
         'user-management-detail-read',
         'user-management-list-read',
         'user-redacted-detail-read',
         'user-redacted-list-read',
         'vulnerability-detail-read',
         'vulnerability-list-read',
         'vulnerability-metadata-export-read']
        expected_inherited_still_owns_values = ['credential-secret-updates-non-up-usk-types-allow-insecure-and-link-mutations',
         'credential-secrets-writes-and-deletes',
         'delivery-payload-mutations',
         'feed-sync-import-control',
         'host-os-catalog-target-creation-tags-export-and-rich-history',
         'non-pdf-custom-report-format-config-filter-and-script-rendering',
         'operating-system-writes-deletes-and-rich-history',
         'raw-gmp-alert-trash-control',
         'raw-report-generation-non-pdf-export-retention-and-mutations',
         'remote-scanner-tls-relay-verification',
         'report-format-file-import-export-verify-param-writes-and-deletes',
         'retention-mutations',
         'schedule-calendar-edit-and-task-recalculation',
         'target-credential-secrets-create-delete-restore-export',
         'target-credential-secrets-writes-and-deletes',
         'target-file-input-task-control-and-credential-secret-workflows',
         'task-resume-and-other-scanner-control',
         'task-resume-file-and-other-scanner-control',
         'task-scan-control-writes-and-deletes',
         'trashcan-deep-row-data-and-mutations',
         'trashcan-row-data-and-mutations',
         'trashcan-row-detail-restore-and-individual-hard-delete',
        ]
        self.assertEqual(contract["allowed_replaces_values"], expected_replaces_values)
        actual_replaces_values = sorted(
            {
                operation["x_yafvs_values"]["x-yafvs-replaces"]
                for operation in yafvsctl.openapi_contract_operations(root)
            }
        )
        self.assertEqual(contract["allowed_replaces_values"], actual_replaces_values)
        self.assertEqual(contract["allowed_inherited_still_owns_values"], expected_inherited_still_owns_values)
        actual_inherited_still_owns_values = sorted(
            {
                operation["x_yafvs_values"].get("x-yafvs-inherited-still-owns")
                for operation in yafvsctl.openapi_contract_operations(root)
                if operation["x_yafvs_values"].get("x-yafvs-inherited-still-owns") is not None
            }
        )
        self.assertTrue(set(actual_inherited_still_owns_values).issubset(set(contract["allowed_inherited_still_owns_values"])))
        self.assertIn("target-credential-secrets-writes-and-deletes", contract["allowed_inherited_still_owns_values"])
        self.assertNotIn("target-credential-secrets-writes-and-deletes", actual_inherited_still_owns_values)
        self.assertEqual(contract["missing_exposure_operations"], [])
        self.assertEqual(contract["invalid_exposure_operations"], [])
        self.assertEqual(contract["exposure_mismatches"], [])
        self.assertEqual(contract["missing_migration_metadata_operations"], [])
        self.assertEqual(contract["invalid_migration_metadata_operations"], [])
        self.assertEqual(contract["migration_metadata_mismatches"], [])
        self.assertEqual(contract["missing_shared_error_responses"], [])
        self.assertEqual(contract["invalid_shared_error_responses"], [])
        self.assertEqual(contract["operations_missing_error_responses"], [])
        self.assertEqual(contract["missing_error_schema_fields"], [])
        self.assertEqual(contract["invalid_error_schema_fields"], [])
        self.assertEqual(contract["error_schema_fields"]["type"], "object")
        self.assertEqual(contract["error_schema_fields"]["properties.error.required"], "[code, message]")
        collection_contract = contract["collection_query_contract"]
        self.assertEqual(collection_contract["alignment_status"], "pass")
        self.assertEqual(
            collection_contract["rust_collection_constants"],
            {"default_page_size": 50, "max_page_size": 500, "max_filter_length": 4096},
        )
        self.assertEqual(
            collection_contract["openapi_collection_values"],
            {"default_page_size": 50, "max_page_size": 500, "max_filter_length": 4096},
        )
        self.assertEqual(collection_contract["collection_limit_mismatches"], [])
        self.assertEqual(collection_contract["incomplete_collection_parameters"], [])
        self.assertEqual(collection_contract["rust_collection_contract_count"], 48)
        self.assertEqual(collection_contract["openapi_collection_operation_count"], 48)
        self.assertEqual(collection_contract["missing_openapi_collection_parameters"], [])
        self.assertEqual(collection_contract["missing_rust_collection_contracts"], [])
        compact = yafvsctl.compact_native_tooling_summary(details)
        self.assertEqual(compact["openapi_contract"]["missing_operation_summary_count"], 0)
        self.assertEqual(compact["openapi_contract"]["collection_query_alignment_status"], "pass")
        self.assertEqual(compact["openapi_contract"]["rust_collection_contract_count"], 48)
        self.assertEqual(compact["openapi_contract"]["openapi_collection_operation_count"], 48)
        self.assertEqual(compact["openapi_contract"]["collection_limit_mismatch_count"], 0)
        self.assertEqual(compact["openapi_contract"]["incomplete_collection_parameter_count"], 0)
        self.assertEqual(compact["openapi_contract"]["missing_openapi_collection_parameter_count"], 0)
        self.assertEqual(compact["openapi_contract"]["missing_rust_collection_contract_count"], 0)
        status_only = yafvsctl.native_tooling_status_only_details(details)
        self.assertEqual(status_only["openapi_contract"]["missing_operation_summary_count"], 0)
        self.assertIn("getResultsByResultId", contract["operation_ids"])
        self.assertIn("getAlertsByAlertId", contract["operation_ids"])
        self.assertIn("getScopesByScopeIdReportsByScopeReportIdRetentionPlan", contract["operation_ids"])

    def test_native_api_client_contract_is_generated_client_ready(self):
        root = Path(__file__).resolve().parents[2]
        result = yafvsctl.command_native_api_client_contract(root)
        details = result["details"]
        findings = {item["check"]: item for item in result["findings"]}

        self.assertEqual(result["status"], "pass", json.dumps(result, sort_keys=True))
        self.assertEqual(details["openapi_version"], "0.1.0-contract")
        self.assertEqual(details["operation_count"], 218)
        self.assertEqual(details["direct_operation_count"], 215)
        self.assertEqual(details["direct_read_operation_count"], 115)
        self.assertIn(
            "POST /tasks/{task_id}/replace-target",
            details["non_get_direct_operations"],
        )
        self.assertIn(
            "POST /tasks/{task_id}/replace-configuration",
            details["non_get_direct_operations"],
        )
        self.assertIn(
            "POST /tasks/{task_id}/clone",
            details["non_get_direct_operations"],
        )
        self.assertEqual(
            [
                operation
                for operation in details["non_get_direct_operations"]
                if operation not in {
                    "POST /tasks/{task_id}/replace-target",
                    "POST /tasks/{task_id}/replace-configuration",
                }
            ],
            [
                "POST /hosts",
                "PATCH /hosts/{host_id}",
                "DELETE /hosts/{host_id}",
                "DELETE /host-identifiers/{identifier_id}",
                "DELETE /host-operating-systems/{host_operating_system_id}",
                "DELETE /tls-certificates/{certificate_id}",
                "POST /scanners",
                "PATCH /scanners/{scanner_id}",
                "DELETE /scanners/{scanner_id}",
                "POST /scanners/{scanner_id}/replace-configuration",
                "POST /scanners/{scanner_id}/clone",
                "POST /scanners/{scanner_id}/restore",
                "DELETE /scanners/{scanner_id}/trash",
                "POST /scanners/{scanner_id}/verify",
                "POST /credentials",
                "PATCH /credentials/{credential_id}",
                "DELETE /credentials/{credential_id}",
                "POST /credentials/{credential_id}/clone",
                "POST /credentials/{credential_id}/restore",
                "DELETE /credentials/{credential_id}/trash",
                "POST /filters",
                "PATCH /filters/{filter_id}",
                "DELETE /filters/{filter_id}",
                "POST /filters/{filter_id}/clone",
                "POST /filters/{filter_id}/restore",
                "DELETE /filters/{filter_id}/trash",
                "POST /alerts",
                "PATCH /alerts/{alert_id}",
                "DELETE /alerts/{alert_id}",
                "POST /alerts/{alert_id}/restore",
                "DELETE /alerts/{alert_id}/trash",
                "PUT /alerts/{alert_id}/definition",
                "POST /alerts/{alert_id}/clone",
                "POST /alerts/{alert_id}/test",
                "POST /alerts/{alert_id}/deliver-report",
                "POST /tags",
                "PATCH /tags/{tag_id}",
                "DELETE /tags/{tag_id}",
                "POST /tags/{tag_id}/clone",
                "POST /tags/{tag_id}/restore",
                "DELETE /tags/{tag_id}/trash",
                "POST /tags/{tag_id}/resources",
                "POST /overrides",
                "DELETE /overrides/{override_id}",
                "PATCH /overrides/{override_id}",
                "POST /overrides/{override_id}/clone",
                "POST /overrides/{override_id}/restore",
                "DELETE /overrides/{override_id}/trash",
                "POST /port-lists",
                "POST /port-list-imports",
                "PATCH /port-lists/{port_list_id}",
                "DELETE /port-lists/{port_list_id}",
                "POST /port-lists/{port_list_id}/ranges",
                "DELETE /port-lists/{port_list_id}/ranges/{port_range_id}",
                "POST /port-lists/{port_list_id}/clone",
                "POST /port-lists/{port_list_id}/restore",
                "DELETE /port-lists/{port_list_id}/trash",
                "POST /schedules",
                "PATCH /schedules/{schedule_id}",
                "DELETE /schedules/{schedule_id}",
                "POST /schedules/{schedule_id}/clone",
                "POST /schedules/{schedule_id}/restore",
                "DELETE /schedules/{schedule_id}/trash",
                "PUT /authentication-settings/ldap",
                "PUT /authentication-settings/radius",
                "POST /user-management/users",
                "POST /user-management/users/{user_id}/clone",
                "PUT /users/current/settings/{setting_id}",
                "PUT /users/current/timezone",
                "POST /scan-configs",
                "PATCH /scan-configs/{scan_config_id}",
                "DELETE /scan-configs/{scan_config_id}",
                "POST /scan-configs/{scan_config_id}/diagnostic-nvt-selection",
                "POST /scan-configs/{scan_config_id}/clone",
                "POST /scan-configs/{scan_config_id}/restore",
                "DELETE /scan-configs/{scan_config_id}/trash",
                "PATCH /scan-configs/{scan_config_id}/families/{family}/nvts",
                "POST /scan-configs/import",
                "POST /trashcan/empty",
                "POST /scopes",
                "PATCH /scopes/{scope_id}",
                "DELETE /scopes/{scope_id}",
                "POST /scopes/{scope_id}/reports",
                "POST /targets",
                "PATCH /targets/{target_id}",
                "DELETE /targets/{target_id}",
                "POST /targets/{target_id}/clone",
                "POST /targets/{target_id}/restore",
                "DELETE /targets/{target_id}/trash",
                "POST /tasks",
                "PATCH /tasks/{task_id}",
                "DELETE /tasks/{task_id}",
                "POST /tasks/{task_id}/restore",
                "DELETE /tasks/{task_id}/trash",
                "POST /tasks/{task_id}/clone",
                "POST /tasks/{task_id}/start",
                "POST /tasks/{task_id}/stop",
                "DELETE /scope-reports/{scope_report_id}",
            ],
        )
        self.assertIn("/api/v1", details["servers"])
        self.assertIn("http://127.0.0.1:19080/api/v1", details["servers"])
        self.assertIn("operatorSession", details["security_requirements"])
        self.assertIn("bearerAuth", details["security_requirements"])
        self.assertEqual(details["security_schemes"]["bearerAuth"]["type"], "http")
        self.assertEqual(findings["native-api-client-contract.openapi"]["status"], "pass")
        self.assertEqual(findings["native-api-client-contract.auth"]["status"], "pass")
        self.assertEqual(findings["native-api-client-contract.direct-read"]["status"], "pass")
        self.assertEqual(findings["native-api-client-contract.write-control"]["status"], "pass")
        self.assertEqual(findings["native-api-client-contract.direct-runtime"]["status"], "pass")
        self.assertEqual(details["direct_runtime_alignment_status"], "pass")
        self.assertEqual(details["direct_segment_guard_alignment_status"], "pass")
        self.assertEqual(details["direct_segment_guard_missing_property_count"], 0)
        self.assertEqual(details["direct_body_limit_alignment_status"], "pass")
        self.assertEqual(details["direct_body_limit_missing_property_count"], 0)

    def test_native_api_client_contract_status_only_is_chat_safe(self):
        root = Path(__file__).resolve().parents[2]
        full = yafvsctl.command_native_api_client_contract(root)
        status_only = yafvsctl.command_native_api_client_contract(root, status_only=True)

        self.assertEqual(status_only["status"], "pass")
        self.assertEqual(status_only["details"]["operation_count"], full["details"]["operation_count"])
        self.assertEqual(status_only["details"]["direct_operation_count"], full["details"]["direct_operation_count"])
        self.assertEqual(status_only["details"]["direct_read_operation_count"], full["details"]["direct_read_operation_count"])
        self.assertEqual(status_only["details"]["non_get_direct_operation_count"], 100)
        self.assertEqual(status_only["details"]["write_control_operation_count"], 103)
        self.assertEqual(status_only["details"]["direct_write_control_operation_count"], 100)
        self.assertEqual(status_only["details"]["operation_request_body_count"], 54)
        self.assertEqual(status_only["details"]["get_request_body_count"], 0)
        self.assertEqual(status_only["details"]["openapi_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["auth_contract_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["write_control_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["direct_runtime_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["direct_segment_guard_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["direct_segment_guard_missing_property_count"], 0)
        self.assertEqual(status_only["details"]["direct_body_limit_alignment_status"], "pass")
        self.assertEqual(status_only["details"]["direct_body_limit_missing_property_count"], 0)
        self.assertEqual(status_only["details"]["missing_operation_id_count"], 0)
        self.assertEqual(status_only["details"]["duplicate_operation_id_count"], 0)
        self.assertEqual(status_only["details"]["operations_missing_error_response_count"], 0)
        self.assertEqual(status_only["details"]["missing_error_schema_field_count"], 0)
        self.assertEqual(status_only["details"]["missing_write_control_metadata_count"], 0)
        self.assertEqual(status_only["details"]["invalid_write_control_metadata_count"], 0)
        self.assertEqual(status_only["details"]["invalid_write_control_path_parameter_count"], 0)
        self.assertEqual(status_only["details"]["missing_server_count"], 0)
        self.assertEqual(status_only["details"]["missing_security_scheme_count"], 0)
        self.assertNotIn("servers", status_only["details"])
        self.assertNotIn("security_schemes", status_only["details"])
        self.assertEqual(
            status_only["findings"],
            [
                {
                    "status": "pass",
                    "check": "native-api-client-contract.status-only",
                    "message": "Native API generated-client contract passed; no non-pass findings.",
                }
            ],
        )
        self.assertLess(len(json.dumps(status_only)), len(json.dumps(full)))

    def test_native_api_client_contract_fails_on_openapi_drift(self):
        root = Path(__file__).resolve().parents[2]
        contract = {
            "alignment_status": "warn",
            "auth_contract": {"alignment_status": "pass"},
            "operation_count": 0,
            "missing_operation_ids": ["GET /example"],
            "duplicate_operation_ids": [],
            "operations_with_request_bodies": [],
            "operations_missing_error_responses": [],
            "missing_error_schema_fields": [],
        }
        with unittest.mock.patch.object(yafvsctl, "native_api_openapi_contract_summary", return_value=contract), unittest.mock.patch.object(yafvsctl, "openapi_contract_operations", return_value=[]):
            result = yafvsctl.command_native_api_client_contract(root, status_only=True)

        findings = {item["check"]: item for item in result["findings"]}
        self.assertEqual(result["status"], "fail")
        self.assertEqual(findings["native-api-client-contract.openapi"]["status"], "fail")
        self.assertEqual(findings["native-api-client-contract.direct-read"]["status"], "fail")
        self.assertEqual(result["details"]["openapi_alignment_status"], "warn")

    def test_native_api_client_contract_fails_on_direct_runtime_drift(self):
        root = Path(__file__).resolve().parents[2]
        drift = {
            "alignment_status": "warn",
            "segment_guard": {
                "alignment_status": "pass",
                "missing_guard_properties": [],
            },
            "body_limit": {
                "alignment_status": "warn",
                "missing_body_limit_properties": ["uses_default_body_limit"],
            },
        }
        with unittest.mock.patch.object(yafvsctl, "native_api_direct_contract_summary", return_value=drift):
            result = yafvsctl.command_native_api_client_contract(root, status_only=True)

        findings = {item["check"]: item for item in result["findings"]}
        self.assertEqual(result["status"], "fail")
        self.assertEqual(findings["native-api-client-contract.direct-runtime"]["status"], "fail")
        self.assertEqual(result["details"]["direct_runtime_alignment_status"], "warn")
        self.assertEqual(result["details"]["direct_body_limit_alignment_status"], "warn")
        self.assertEqual(result["details"]["direct_body_limit_missing_property_count"], 1)

    def test_native_api_migration_matrix_combines_inventory_and_openapi_metadata(self):
        root = Path(__file__).resolve().parents[2]
        result = yafvsctl.command_native_api_migration_matrix(root)
        details = result["details"]
        rows = {(item["method"], item["endpoint"]): item for item in details["items"]}
        findings = {item["check"]: item for item in result["findings"]}
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")

        self.assertEqual(result["status"], "pass")
        self.assertEqual(details["summary"]["total_rows"], 218)
        self.assertEqual(details["summary"]["openapi_operation_rows"], 218)
        self.assertEqual(details["summary"]["inventory_rows"], 218)
        self.assertEqual(details["summary"]["rows_with_checked_migration_metadata"], 218)
        self.assertEqual(details["summary"]["checked_migration_field_counts"]["x_yafvs_exposure"], 218)
        self.assertEqual(details["summary"]["rows_missing_openapi_count"], 0)
        self.assertEqual(details["summary"]["rows_missing_inventory_count"], 0)
        self.assertEqual(details["summary"]["rows_missing_migration_metadata_count"], 0)
        self.assertEqual(details["summary"]["direct_exposure_mismatch_count"], 0)
        self.assertEqual(details["summary"]["direct_marker_mismatch_count"], 0)
        self.assertEqual(findings["native-api-migration-matrix.coverage"]["status"], "pass")
        self.assertEqual(findings["native-api-migration-matrix.metadata"]["status"], "pass")
        self.assertIn("native-api-migration-matrix", source)
        self.assertIn("def command_native_api_migration_matrix", source)

        reports = rows[("get", "/api/v1/reports")]
        self.assertEqual(reports["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(reports["browser_access"], "browser_proxied")
        self.assertEqual(reports["direct_access"], "scriptable_read")
        self.assertEqual(reports["operation_id"], "getReports")
        self.assertTrue(reports["openapi_direct_marker"])
        self.assertEqual(reports["x_yafvs_exposure"], "direct-read")
        self.assertEqual(reports["x_yafvs_maturity"], "live-read")
        self.assertEqual(reports["x_yafvs_replaces"], "raw-report-list-read")
        self.assertEqual(reports["x_yafvs_inherited_still_owns"], "raw-report-generation-non-pdf-export-retention-and-mutations")
        self.assertIn("GSA raw report list (migrated through gsad same-origin proxy)", reports["replacement_candidates"])

        password_change = rows[("post", "/api/v1/users/current/password")]
        self.assertEqual(password_change["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(password_change["browser_access"], "browser_proxied")
        self.assertEqual(password_change["direct_access"], "browser_write")
        self.assertFalse(password_change["openapi_direct_marker"])
        self.assertEqual(password_change["x_yafvs_exposure"], "browser-write")
        self.assertEqual(password_change["x_yafvs_replaces"], "user-current-password-change")

        create_scope = rows[("post", "/api/v1/scopes")]
        self.assertEqual(create_scope["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(create_scope["browser_access"], "browser_proxied")
        self.assertEqual(create_scope["method"], "post")
        self.assertEqual(create_scope["inventory_endpoint"], "/api/v1/scopes")
        self.assertEqual(create_scope["direct_access"], "direct_write_control")
        self.assertTrue(create_scope["openapi_direct_marker"])
        self.assertEqual(create_scope["x_yafvs_maturity"], "live-write")
        self.assertEqual(create_scope["x_yafvs_exposure"], "direct-write")
        self.assertEqual(create_scope["x_yafvs_replaces"], "scope-metadata-membership-write")

        task_clone = rows[("post", "/api/v1/tasks/{task_id}/clone")]
        self.assertEqual(task_clone["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(task_clone["browser_access"], "browser_proxied")
        self.assertEqual(task_clone["direct_access"], "direct_write_control")
        self.assertEqual(task_clone["operation_id"], "postTasksByTaskIdClone")
        self.assertEqual(task_clone["x_yafvs_maturity"], "live-write")
        self.assertEqual(task_clone["x_yafvs_exposure"], "direct-write")
        self.assertEqual(task_clone["x_yafvs_replaces"], "task-clone")
        self.assertEqual(task_clone["x_yafvs_side_effect"], "scanner-control")
        self.assertIsNone(task_clone["x_yafvs_inherited_still_owns"])
        self.assertIn("Task resume, non-queue scanner side effects", source)
        self.assertNotIn("Task resume, hard-delete", source)
        self.assertIn("inherited file export", source)
        self.assertNotIn("Task resume, clone", source)

        update_scope = rows[("patch", "/api/v1/scopes/{scope_id}")]
        self.assertEqual(update_scope["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(update_scope["browser_access"], "browser_proxied")
        self.assertEqual(update_scope["direct_access"], "direct_write_control")
        self.assertEqual(update_scope["x_yafvs_maturity"], "live-write")
        self.assertEqual(update_scope["x_yafvs_exposure"], "direct-write")

        delete_scope = rows[("delete", "/api/v1/scopes/{scope_id}")]
        self.assertEqual(delete_scope["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(delete_scope["direct_access"], "direct_write_control")
        self.assertEqual(delete_scope["x_yafvs_maturity"], "live-write")
        self.assertEqual(delete_scope["x_yafvs_exposure"], "direct-write")

        delete_port_list = rows[("delete", "/api/v1/port-lists/{port_list_id}")]
        self.assertEqual(delete_port_list["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(delete_port_list["direct_access"], "direct_write_control")
        self.assertEqual(delete_port_list["x_yafvs_maturity"], "live-write")
        self.assertEqual(delete_port_list["x_yafvs_exposure"], "direct-write")
        self.assertEqual(delete_port_list["x_yafvs_replaces"], "port-list-trash-move")

        create_port_list_range = rows[("post", "/api/v1/port-lists/{port_list_id}/ranges")]
        self.assertEqual(create_port_list_range["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(create_port_list_range["direct_access"], "direct_write_control")
        self.assertEqual(create_port_list_range["x_yafvs_maturity"], "live-write")
        self.assertEqual(create_port_list_range["x_yafvs_exposure"], "direct-write")
        self.assertEqual(create_port_list_range["x_yafvs_replaces"], "port-list-range-create")

        delete_port_list_range = rows[("delete", "/api/v1/port-lists/{port_list_id}/ranges/{port_range_id}")]
        self.assertEqual(delete_port_list_range["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(delete_port_list_range["direct_access"], "direct_write_control")
        self.assertEqual(delete_port_list_range["x_yafvs_maturity"], "live-write")
        self.assertEqual(delete_port_list_range["x_yafvs_exposure"], "direct-write")
        self.assertEqual(delete_port_list_range["x_yafvs_replaces"], "port-list-range-delete")

        clone_port_list = rows[("post", "/api/v1/port-lists/{port_list_id}/clone")]
        self.assertEqual(clone_port_list["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(clone_port_list["direct_access"], "direct_write_control")
        self.assertEqual(clone_port_list["x_yafvs_maturity"], "live-write")
        self.assertEqual(clone_port_list["x_yafvs_exposure"], "direct-write")
        self.assertEqual(clone_port_list["x_yafvs_replaces"], "port-list-clone")

        import_port_list = rows[("post", "/api/v1/port-list-imports")]
        self.assertEqual(import_port_list["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(import_port_list["direct_access"], "direct_write_control")
        self.assertEqual(import_port_list["x_yafvs_maturity"], "live-write")
        self.assertEqual(import_port_list["x_yafvs_exposure"], "direct-write")
        self.assertEqual(import_port_list["x_yafvs_replaces"], "port-list-import")

        hard_delete_port_list = rows[("delete", "/api/v1/port-lists/{port_list_id}/trash")]
        self.assertEqual(hard_delete_port_list["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(hard_delete_port_list["direct_access"], "direct_write_control")
        self.assertEqual(hard_delete_port_list["x_yafvs_maturity"], "live-write")
        self.assertEqual(hard_delete_port_list["x_yafvs_exposure"], "direct-write")
        self.assertEqual(hard_delete_port_list["x_yafvs_replaces"], "port-list-hard-delete")

        export_port_list = rows[("get", "/api/v1/port-lists/{port_list_id}/export")]
        self.assertEqual(export_port_list["status"], "implemented_internal_browser_proxied_and_scriptable_read")
        self.assertEqual(export_port_list["direct_access"], "scriptable_read")
        self.assertEqual(export_port_list["x_yafvs_maturity"], "live-read")
        self.assertEqual(export_port_list["x_yafvs_exposure"], "direct-read")
        self.assertEqual(export_port_list["x_yafvs_replaces"], "port-list-metadata-export-read")

        delete_schedule = rows[("delete", "/api/v1/schedules/{schedule_id}")]
        self.assertEqual(delete_schedule["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(delete_schedule["direct_access"], "direct_write_control")
        self.assertEqual(delete_schedule["x_yafvs_maturity"], "live-write")
        self.assertEqual(delete_schedule["x_yafvs_exposure"], "direct-write")
        self.assertEqual(delete_schedule["x_yafvs_replaces"], "schedule-trash-move")

        clone_schedule = rows[("post", "/api/v1/schedules/{schedule_id}/clone")]
        self.assertEqual(clone_schedule["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(clone_schedule["direct_access"], "direct_write_control")
        self.assertEqual(clone_schedule["x_yafvs_maturity"], "live-write")
        self.assertEqual(clone_schedule["x_yafvs_exposure"], "direct-write")
        self.assertEqual(clone_schedule["x_yafvs_replaces"], "schedule-clone")

        patch_schedule = rows[("patch", "/api/v1/schedules/{schedule_id}")]
        self.assertEqual(patch_schedule["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(patch_schedule["browser_access"], "browser_proxied")
        self.assertEqual(patch_schedule["direct_access"], "direct_write_control")
        self.assertEqual(patch_schedule["x_yafvs_maturity"], "live-write")
        self.assertEqual(patch_schedule["x_yafvs_exposure"], "direct-write")
        self.assertEqual(patch_schedule["x_yafvs_replaces"], "schedule-metadata-modify")

        patch_filter = rows[("patch", "/api/v1/filters/{filter_id}")]
        self.assertEqual(patch_filter["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(patch_filter["direct_access"], "direct_write_control")
        self.assertEqual(patch_filter["x_yafvs_maturity"], "live-write")
        self.assertEqual(patch_filter["x_yafvs_exposure"], "direct-write")
        self.assertEqual(patch_filter["x_yafvs_replaces"], "saved-filter-metadata-modify")

        delete_filter = rows[("delete", "/api/v1/filters/{filter_id}")]
        self.assertEqual(delete_filter["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(delete_filter["direct_access"], "direct_write_control")
        self.assertEqual(delete_filter["x_yafvs_maturity"], "live-write")
        self.assertEqual(delete_filter["x_yafvs_exposure"], "direct-write")
        self.assertEqual(delete_filter["x_yafvs_replaces"], "saved-filter-trash-move")

        create_tag = rows[("post", "/api/v1/tags")]
        self.assertEqual(create_tag["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(create_tag["direct_access"], "direct_write_control")
        self.assertEqual(create_tag["x_yafvs_maturity"], "live-write")
        self.assertEqual(create_tag["x_yafvs_exposure"], "direct-write")
        self.assertEqual(create_tag["x_yafvs_replaces"], "tag-metadata-and-explicit-resource-assignment-write")
        self.assertIsNone(create_tag["x_yafvs_inherited_still_owns"])

        update_tag = rows[("patch", "/api/v1/tags/{tag_id}")]
        self.assertEqual(update_tag["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(update_tag["direct_access"], "direct_write_control")
        self.assertEqual(update_tag["x_yafvs_maturity"], "live-write")
        self.assertEqual(update_tag["x_yafvs_exposure"], "direct-write")
        self.assertEqual(update_tag["x_yafvs_replaces"], "tag-metadata-resource-type-and-atomic-assignment-write")
        self.assertIsNone(update_tag["x_yafvs_inherited_still_owns"])

        delete_tag = rows[("delete", "/api/v1/tags/{tag_id}")]
        self.assertEqual(delete_tag["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(delete_tag["direct_access"], "direct_write_control")
        self.assertEqual(delete_tag["x_yafvs_maturity"], "live-write")
        self.assertEqual(delete_tag["x_yafvs_exposure"], "direct-write")
        self.assertEqual(delete_tag["x_yafvs_replaces"], "tag-trash-move")

        update_tag_resources = rows[("post", "/api/v1/tags/{tag_id}/resources")]
        self.assertEqual(update_tag_resources["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(update_tag_resources["direct_access"], "direct_write_control")
        self.assertEqual(update_tag_resources["x_yafvs_maturity"], "live-write")
        self.assertEqual(update_tag_resources["x_yafvs_exposure"], "direct-write")

        scope_report_detail = rows[("get", "/api/v1/scope-reports/{scope_report_id}")]
        self.assertEqual(scope_report_detail["operation_id"], "getScopeReportsByScopeReportId")
        self.assertEqual(scope_report_detail["x_yafvs_exposure"], "direct-read")
        self.assertEqual(scope_report_detail["x_yafvs_maturity"], "live-read")
        self.assertEqual(scope_report_detail["x_yafvs_replaces"], "scope-report-detail-summary-read")
        self.assertIsNone(scope_report_detail["x_yafvs_inherited_still_owns"])

        delete_scope_report = rows[("delete", "/api/v1/scope-reports/{scope_report_id}")]
        self.assertEqual(delete_scope_report["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(delete_scope_report["direct_access"], "direct_write_control")
        self.assertEqual(delete_scope_report["x_yafvs_maturity"], "live-write")
        self.assertEqual(delete_scope_report["x_yafvs_exposure"], "direct-write")
        self.assertEqual(delete_scope_report["x_yafvs_replaces"], "scope-report-delete")
        self.assertIsNone(delete_scope_report["x_yafvs_inherited_still_owns"])

        scope_report_results_by_id = rows[("get", "/api/v1/scope-reports/{scope_report_id}/results")]
        self.assertEqual(scope_report_results_by_id["operation_id"], "getScopeReportsByScopeReportIdResults")
        self.assertEqual(scope_report_results_by_id["x_yafvs_exposure"], "direct-read")
        self.assertEqual(scope_report_results_by_id["x_yafvs_maturity"], "live-read")
        self.assertEqual(scope_report_results_by_id["x_yafvs_replaces"], "scope-report-result-evidence-read")
        self.assertIsNone(scope_report_results_by_id["x_yafvs_inherited_still_owns"])

        feeds = rows[("get", "/api/v1/feeds")]
        self.assertEqual(feeds["operation_id"], "getFeeds")
        self.assertEqual(feeds["x_yafvs_exposure"], "direct-read")
        self.assertEqual(feeds["x_yafvs_maturity"], "live-read")
        self.assertEqual(feeds["x_yafvs_replaces"], "feed-status-read")
        self.assertEqual(feeds["x_yafvs_inherited_still_owns"], "feed-sync-import-control")

        expected_catalog_metadata = {
            "/api/v1/cves": ("getCves", "cve-catalog-list-read", None),
            "/api/v1/cves/{cve_id}": ("getCvesByCveId", "cve-catalog-detail-epss-reference-configuration-read", None),
            "/api/v1/cves/{cve_id}/export": ("getCvesByCveIdExport", "cve-catalog-metadata-export-read", None),
            "/api/v1/vulnerabilities/{vulnerability_id}": ("getVulnerabilitiesByVulnerabilityId", "vulnerability-detail-read", None),
            "/api/v1/vulnerabilities/{vulnerability_id}/export": ("getVulnerabilitiesByVulnerabilityIdExport", "vulnerability-metadata-export-read", None),
            "/api/v1/cpes": ("getCpes", "cpe-catalog-list-read", None),
            "/api/v1/cpes/{cpe_id}": ("getCpesByCpeId", "cpe-catalog-detail-read", None),
            "/api/v1/cert-bund-advisories": ("getCertBundAdvisories", "cert-bund-advisory-list-read", None),
            "/api/v1/cert-bund-advisories/{cert_bund_advisory_id}": ("getCertBundAdvisoriesByCertBundAdvisoryId", "cert-bund-advisory-catalog-detail-read", None),
            "/api/v1/dfn-cert-advisories": ("getDfnCertAdvisories", "dfn-cert-advisory-list-read", None),
            "/api/v1/dfn-cert-advisories/{dfn_cert_advisory_id}": ("getDfnCertAdvisoriesByDfnCertAdvisoryId", "dfn-cert-advisory-catalog-detail-read", None),
            "/api/v1/nvts": ("getNvts", "nvt-catalog-list-read", None),
            "/api/v1/nvts/{nvt_id}": ("getNvtsByNvtId", "nvt-catalog-detail-read", None),
            "/api/v1/nvts/{nvt_id}/export": ("getNvtsByNvtIdExport", "nvt-catalog-metadata-export-read", None),
        }
        for endpoint, (operation_id, replaces, inherited_still_owns) in expected_catalog_metadata.items():
            row = rows[("get", endpoint)]
            self.assertEqual(row["operation_id"], operation_id)
            self.assertEqual(row["x_yafvs_exposure"], "direct-read")
            self.assertEqual(row["x_yafvs_maturity"], "live-read")
            self.assertEqual(row["x_yafvs_replaces"], replaces)
            self.assertEqual(row.get("x_yafvs_inherited_still_owns"), inherited_still_owns)

        expected_asset_metadata = {
            "/api/v1/operating-systems": ("getOperatingSystems", "operating-system-asset-list-read", None),
            "/api/v1/operating-systems/{os_id}": ("getOperatingSystemsByOsId", "operating-system-asset-detail-info-read", None),
            "/api/v1/operating-systems/{os_id}/export": ("getOperatingSystemsByOsIdExport", "operating-system-asset-metadata-export-read", None),
            "/api/v1/hosts": ("getHosts", "host-asset-list-read", None),
            "/api/v1/hosts/{host_id}": ("getHostsByHostId", "host-asset-detail-info-read", None),
            "/api/v1/hosts/{host_id}/export": ("getHostsByHostIdExport", "host-asset-metadata-export-read", None),
            "/api/v1/tls-certificates": ("getTlsCertificates", "tls-certificate-asset-list-read", None),
            "/api/v1/tls-certificates/{certificate_id}": ("getTlsCertificatesByCertificateId", "tls-certificate-asset-detail-info-read", None),
            "/api/v1/tls-certificates/{certificate_id}/export": ("getTlsCertificatesByCertificateIdExport", "tls-certificate-asset-metadata-export-read", None),
            "/api/v1/tls-certificates/{certificate_id}/certificate": ("getTlsCertificatesByCertificateIdCertificate", "tls-certificate-pem-download-read", None),
            "/api/v1/scanners": ("getScanners", "scanner-metadata-list-read", None),
            "/api/v1/scanners/{scanner_id}": ("getScannersByScannerId", "scanner-metadata-detail-info-tags-and-task-backlink-read", None),
            "/api/v1/scanners/{scanner_id}/export": ("getScannersByScannerIdExport", "scanner-metadata-export-read", None),
            "/api/v1/scan-configs": ("getScanConfigs", "scan-config-metadata-list-read", None),
            "/api/v1/scan-configs/{scan_config_id}": ("getScanConfigsByScanConfigId", "scan-config-detail-info-tags-task-backlinks-and-preferences-read", None),
            "/api/v1/scan-configs/{scan_config_id}/backup": ("getScanConfigsByScanConfigIdBackup", "scan-config-versioned-json-backup", None),
            "/api/v1/scan-configs/{scan_config_id}/families": ("getScanConfigsByScanConfigIdFamilies", "scan-config-family-summary-read", None),
            "/api/v1/scan-configs/{scan_config_id}/families/{family}/nvts": ("getScanConfigsByScanConfigIdFamiliesByFamilyNvts", "scan-config-family-nvt-selection-read", None),
        }
        for endpoint, (operation_id, replaces, inherited_still_owns) in expected_asset_metadata.items():
            row = rows[("get", endpoint)]
            self.assertEqual(row["operation_id"], operation_id)
            self.assertEqual(row["x_yafvs_exposure"], "direct-read")
            self.assertEqual(row["x_yafvs_maturity"], "live-read")
            self.assertEqual(row["x_yafvs_replaces"], replaces)
            self.assertEqual(row.get("x_yafvs_inherited_still_owns"), inherited_still_owns)

        expected_raw_report_metadata = {
            "/api/v1/reports/{report_id}/results": ("getReportsByReportIdResults", "raw-report-result-evidence-read"),
            "/api/v1/reports/{report_id}/hosts": ("getReportsByReportIdHosts", "raw-report-host-evidence-read"),
            "/api/v1/reports/{report_id}/ports": ("getReportsByReportIdPorts", "raw-report-port-evidence-read"),
            "/api/v1/reports/{report_id}/applications": ("getReportsByReportIdApplications", "raw-report-application-evidence-read"),
            "/api/v1/reports/{report_id}/operating-systems": ("getReportsByReportIdOperatingSystems", "raw-report-operating-system-evidence-read"),
            "/api/v1/reports/{report_id}/cves": ("getReportsByReportIdCves", "raw-report-cve-evidence-read"),
            "/api/v1/reports/{report_id}/tls-certificates": ("getReportsByReportIdTlsCertificates", "raw-report-tls-certificate-evidence-read"),
            "/api/v1/reports/{report_id}/errors": ("getReportsByReportIdErrors", "raw-report-error-message-evidence-read"),
            "/api/v1/reports/{report_id}/metrics": ("getReportsByReportIdMetrics", "raw-report-metrics-read"),
        }
        for endpoint, (operation_id, replaces) in expected_raw_report_metadata.items():
            row = rows[("get", endpoint)]
            self.assertEqual(row["operation_id"], operation_id)
            self.assertEqual(row["x_yafvs_exposure"], "direct-read")
            self.assertEqual(row["x_yafvs_maturity"], "live-read")
            self.assertEqual(row["x_yafvs_replaces"], replaces)
            self.assertIsNone(row["x_yafvs_inherited_still_owns"])

        expected_scope_report_metadata = {
            "/api/v1/scope-reports/{scope_report_id}/results": ("getScopeReportsByScopeReportIdResults", "scope-report-result-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/results": ("getScopesByScopeIdReportsByScopeReportIdResults", "scope-report-result-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/hosts": ("getScopesByScopeIdReportsByScopeReportIdHosts", "scope-report-host-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/ports": ("getScopesByScopeIdReportsByScopeReportIdPorts", "scope-report-port-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/applications": ("getScopesByScopeIdReportsByScopeReportIdApplications", "scope-report-application-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/operating-systems": ("getScopesByScopeIdReportsByScopeReportIdOperatingSystems", "scope-report-operating-system-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/cves": ("getScopesByScopeIdReportsByScopeReportIdCves", "scope-report-cve-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/tls-certificates": ("getScopesByScopeIdReportsByScopeReportIdTlsCertificates", "scope-report-tls-certificate-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/errors": ("getScopesByScopeIdReportsByScopeReportIdErrors", "scope-report-error-message-evidence-read"),
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/metrics": ("getScopesByScopeIdReportsByScopeReportIdMetrics", "scope-report-metrics-read"),
        }
        for endpoint, (operation_id, replaces) in expected_scope_report_metadata.items():
            row = rows[("get", endpoint)]
            self.assertEqual(row["operation_id"], operation_id)
            self.assertEqual(row["x_yafvs_exposure"], "direct-read")
            self.assertEqual(row["x_yafvs_maturity"], "live-read")
            self.assertEqual(row["x_yafvs_replaces"], replaces)
            self.assertIsNone(row["x_yafvs_inherited_still_owns"])

        tags = rows[("get", "/api/v1/tags")]
        self.assertEqual(tags["operation_id"], "getTags")
        self.assertEqual(tags["x_yafvs_exposure"], "direct-read")
        self.assertEqual(tags["x_yafvs_maturity"], "live-read")
        self.assertEqual(tags["x_yafvs_replaces"], "tag-metadata-read")
        self.assertIsNone(tags["x_yafvs_inherited_still_owns"])

        tag_detail = rows[("get", "/api/v1/tags/{tag_id}")]
        self.assertEqual(tag_detail["operation_id"], "getTagsByTagId")
        self.assertEqual(tag_detail["x_yafvs_exposure"], "direct-read")
        self.assertEqual(tag_detail["x_yafvs_maturity"], "live-read")
        self.assertEqual(tag_detail["x_yafvs_replaces"], "tag-metadata-read")
        self.assertIsNone(tag_detail["x_yafvs_inherited_still_owns"])

        tag_resources = rows[("get", "/api/v1/tags/{tag_id}/resources")]
        self.assertEqual(tag_resources["operation_id"], "getTagsByTagIdResources")
        self.assertEqual(tag_resources["x_yafvs_exposure"], "direct-read")
        self.assertEqual(tag_resources["x_yafvs_maturity"], "live-read")
        self.assertEqual(tag_resources["x_yafvs_replaces"], "tag-resource-reference-read")
        self.assertIsNone(tag_resources["x_yafvs_inherited_still_owns"])

        tag_export = rows[("get", "/api/v1/tags/{tag_id}/export")]
        self.assertEqual(tag_export["operation_id"], "getTagsByTagIdExport")
        self.assertEqual(tag_export["x_yafvs_exposure"], "direct-read")
        self.assertEqual(tag_export["x_yafvs_maturity"], "live-read")
        self.assertEqual(tag_export["x_yafvs_replaces"], "tag-metadata-export-read")
        self.assertIsNone(tag_export["x_yafvs_inherited_still_owns"])

        tag_clone = rows[("post", "/api/v1/tags/{tag_id}/clone")]
        self.assertEqual(tag_clone["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(tag_clone["direct_access"], "direct_write_control")
        self.assertEqual(tag_clone["x_yafvs_maturity"], "live-write")
        self.assertEqual(tag_clone["x_yafvs_exposure"], "direct-write")
        self.assertEqual(tag_clone["x_yafvs_replaces"], "tag-clone")
        self.assertIsNone(tag_clone["x_yafvs_inherited_still_owns"])

        tag_restore = rows[("post", "/api/v1/tags/{tag_id}/restore")]
        self.assertEqual(tag_restore["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(tag_restore["direct_access"], "direct_write_control")
        self.assertEqual(tag_restore["x_yafvs_replaces"], "tag-restore")
        self.assertIsNone(tag_restore["x_yafvs_inherited_still_owns"])

        tag_hard_delete = rows[("delete", "/api/v1/tags/{tag_id}/trash")]
        self.assertEqual(tag_hard_delete["status"], "implemented_internal_and_browser_proxied")
        self.assertEqual(tag_hard_delete["direct_access"], "direct_write_control")
        self.assertEqual(tag_hard_delete["x_yafvs_replaces"], "tag-hard-delete")
        self.assertIsNone(tag_hard_delete["x_yafvs_inherited_still_owns"])

        retention = rows[("get", "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan")]
        self.assertEqual(retention["status"], "implemented_internal_browser_proxied_and_scriptable_read")
        self.assertEqual(retention["browser_access"], "browser_proxied")
        self.assertEqual(retention["direct_access"], "scriptable_read")
        self.assertTrue(retention["openapi_direct_marker"])
        self.assertEqual(retention["x_yafvs_exposure"], "direct-read")
        self.assertEqual(retention["x_yafvs_maturity"], "preview-read")
        self.assertEqual(retention["x_yafvs_replaces"], "none")
        self.assertEqual(retention["x_yafvs_inherited_still_owns"], "retention-mutations")

        cert_bund_detail = rows[("get", "/api/v1/cert-bund-advisories/{cert_bund_advisory_id}")]
        self.assertEqual(cert_bund_detail["inventory_endpoint"], "/api/v1/cert-bund-advisories/{advisory_id}")
        self.assertIn("GSA Security Information CERT-Bund advisory rich detail reads (migrated through gsad same-origin proxy)", cert_bund_detail["replacement_candidates"])

        self.assertNotIn(("get", "/api/v1/scopes/{scope_id}/reports/{scope_report_id}"), rows)

    def test_native_api_migration_matrix_contract_reports_row_and_metadata_gaps(self):
        rows = [
            {
                "endpoint": "/api/v1/reports",
                "method": "get",
                "inventory_endpoint": "/api/v1/reports",
                "openapi_path": None,
                "direct_access": "scriptable_read",
                "openapi_direct_marker": False,
                "x_yafvs_exposure": "internal-only",
                "x_yafvs_maturity": "live-read",
                "x_yafvs_replaces": "raw-report-list-read",
                "x_yafvs_inherited_still_owns": "raw-report-generation-non-pdf-export-retention-and-mutations",
            },
            {
                "endpoint": "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan",
                "method": "get",
                "inventory_endpoint": None,
                "openapi_path": "/scopes/{scope_id}/reports/{scope_report_id}/retention-plan",
                "direct_access": "internal_only",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-read",
                "x_yafvs_maturity": None,
                "x_yafvs_replaces": "none",
                "x_yafvs_inherited_still_owns": "retention-mutations",
            },
        ]

        contract = yafvsctl.native_api_migration_matrix_contract_summary(rows)
        summary = yafvsctl.native_api_migration_matrix_summary(rows)

        self.assertEqual(contract["rows_missing_openapi"][0]["endpoint"], "/api/v1/reports")
        self.assertEqual(
            contract["rows_missing_inventory"][0]["endpoint"],
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan",
        )
        self.assertEqual(
            contract["rows_missing_migration_metadata"],
            [
                {
                    "endpoint": "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/retention-plan",
                    "method": "get",
                    "missing_fields": ["x_yafvs_maturity"],
                }
            ],
        )
        self.assertEqual({item["endpoint"] for item in contract["direct_exposure_mismatches"]}, {row["endpoint"] for row in rows})
        self.assertEqual({item["endpoint"] for item in contract["direct_marker_mismatches"]}, {row["endpoint"] for row in rows})
        self.assertEqual(summary["rows_missing_openapi_count"], 1)
        self.assertEqual(summary["rows_missing_inventory_count"], 1)
        self.assertEqual(summary["rows_missing_migration_metadata_count"], 1)
        self.assertEqual(summary["direct_exposure_mismatch_count"], 2)
        self.assertEqual(summary["direct_marker_mismatch_count"], 2)
        self.assertEqual(
            summary["progress_percentages"],
            {
                "openapi_operation_rows_percent": 50.0,
                "inventory_rows_percent": 50.0,
                "rows_with_replacement_candidates_percent": 0.0,
                "rows_with_checked_migration_metadata_percent": 100.0,
                "browser_proxied_percent": 0.0,
                "scriptable_read_percent": 50.0,
                "internal_only_percent": 50.0,
            },
        )

    def test_native_api_migration_matrix_status_only_omits_items(self):
        result = {
            "status": "pass",
            "summary": "ok",
            "details": {
                "summary": {"total_rows": 2},
                "contract": {"rows_missing_openapi": []},
                "items": [
                    {
                        "endpoint": "/api/v1/reports",
                        "x_yafvs_inherited_still_owns": "raw-report-generation-non-pdf-export-retention-and-mutations",
                    }
                ],
            },
            "findings": [
                {"status": "pass", "check": "native-api-migration-matrix.rows", "message": "ok"},
            ],
        }

        compact = yafvsctl.native_api_migration_matrix_status_only_result(result)

        self.assertEqual(compact["details"]["summary"], {"total_rows": 2})
        self.assertEqual(compact["details"]["contract"], {"rows_missing_openapi": []})
        self.assertNotIn("items", compact["details"])
        remaining = compact["details"]["remaining_inherited_surface"]
        self.assertEqual(remaining["rows_with_inherited_owner_tail"], 1)
        self.assertEqual(remaining["distinct_owner_tails"], 1)
        self.assertEqual(remaining["bucket_counts"]["export_or_download"], 1)
        self.assertEqual(remaining["bucket_counts"]["report_generation_or_retention"], 1)
        self.assertEqual(remaining["top_residuals"][0]["example_endpoint"], "/api/v1/reports")
        self.assertEqual(compact["findings"], [{"status": "pass", "check": "native-api-migration-matrix.status-only", "message": "Native API migration matrix passed; no non-pass findings."}])

    def test_native_api_migration_matrix_focus_filters_rows_before_summary(self):
        root = Path(__file__).resolve().parents[2]
        rows = [
            {
                "endpoint": "/api/v1/schedules",
                "method": "get",
                "inventory_endpoint": "/api/v1/schedules",
                "openapi_path": "/schedules",
                "direct_access": "scriptable_read",
                "browser_access": "browser_proxied",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-read",
                "x_yafvs_maturity": "live-read",
                "x_yafvs_replaces": "schedule-metadata-list-read",
                "x_yafvs_inherited_still_owns": "schedule-calendar-edit-and-task-recalculation",
                "replacement_candidates": ["read-only schedule automation"],
            },
            {
                "endpoint": "/api/v1/reports",
                "method": "get",
                "inventory_endpoint": "/api/v1/reports",
                "openapi_path": "/reports",
                "direct_access": "scriptable_read",
                "browser_access": "browser_proxied",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-read",
                "x_yafvs_maturity": "live-read",
                "x_yafvs_replaces": "raw-report-list-read",
                "x_yafvs_inherited_still_owns": "raw-report-generation-non-pdf-export-retention-and-mutations",
                "replacement_candidates": ["runtime-report-summary helper"],
            },
        ]

        with unittest.mock.patch.object(yafvsctl, "native_api_migration_matrix_rows", return_value=rows):
            result = yafvsctl.command_native_api_migration_matrix(root, focus="schedule")
        with unittest.mock.patch.object(yafvsctl, "native_api_migration_matrix_rows", return_value=rows):
            compact = yafvsctl.command_native_api_migration_matrix(root, status_only=True, focus="schedule")

        self.assertEqual(result["details"]["focus"], "schedule")
        self.assertEqual(result["details"]["focus_terms"], ["schedule"])
        self.assertEqual(result["details"]["focus_match_count"], 1)
        self.assertEqual(result["details"]["summary"]["total_rows"], 1)
        self.assertEqual(result["details"]["items"][0]["endpoint"], "/api/v1/schedules")
        self.assertEqual(compact["details"]["focus"], "schedule")
        self.assertEqual(compact["details"]["focus_terms"], ["schedule"])
        self.assertEqual(compact["details"]["focus_match_count"], 1)
        self.assertEqual(
            compact["details"]["focus_rows"],
            [
                {
                    "method": "get",
                    "endpoint": "/api/v1/schedules",
                    "direct_access": "scriptable_read",
                    "browser_access": "browser_proxied",
                    "x_yafvs_replaces": "schedule-metadata-list-read",
                    "x_yafvs_inherited_still_owns": "schedule-calendar-edit-and-task-recalculation",
                }
            ],
        )
        self.assertFalse(compact["details"]["focus_rows_truncated"])
        self.assertNotIn("items", compact["details"])

    def test_native_api_migration_matrix_compact_focus_rows_include_write_auth_metadata(self):
        row = {
            "method": "patch",
            "endpoint": "/api/v1/tasks/{task_id}",
            "status": "implemented_internal_and_browser_proxied",
            "direct_access": "direct_write_control",
            "browser_access": "browser_proxied",
            "x_yafvs_replaces": "task-metadata-modify",
            "x_yafvs_inherited_still_owns": "task-scan-control-writes-and-deletes",
            "x_yafvs_operator_identity": "direct-token-operator",
            "x_yafvs_owner_semantics": "preserve-existing-owner",
            "x_yafvs_side_effect": "metadata-write",
            "x_yafvs_safety_contract": "write-control-v1",
        }

        compact = yafvsctl.native_api_migration_matrix_compact_focus_row(row)

        self.assertEqual(compact["x_yafvs_operator_identity"], "direct-token-operator")
        self.assertEqual(compact["x_yafvs_owner_semantics"], "preserve-existing-owner")
        self.assertEqual(compact["x_yafvs_side_effect"], "metadata-write")
        self.assertEqual(compact["x_yafvs_safety_contract"], "write-control-v1")

    def test_native_api_migration_matrix_focus_accepts_repeated_terms(self):
        root = Path(__file__).resolve().parents[2]
        rows = [
            {
                "endpoint": "/api/v1/schedules",
                "method": "get",
                "inventory_endpoint": "/api/v1/schedules",
                "openapi_path": "/schedules",
                "direct_access": "scriptable_read",
                "browser_access": "browser_proxied",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-read",
                "x_yafvs_maturity": "live-read",
                "x_yafvs_replaces": "schedule-metadata-list-read",
                "x_yafvs_inherited_still_owns": "schedule-calendar-edit-and-task-recalculation",
                "replacement_candidates": ["read-only schedule automation"],
            },
            {
                "endpoint": "/api/v1/alerts",
                "method": "get",
                "inventory_endpoint": "/api/v1/alerts",
                "openapi_path": "/alerts",
                "direct_access": "scriptable_read",
                "browser_access": "browser_proxied",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-read",
                "x_yafvs_maturity": "live-read",
                "x_yafvs_replaces": "alert-metadata-list-read",
                "replacement_candidates": ["alert list automation"],
            },
            {
                "endpoint": "/api/v1/reports",
                "method": "get",
                "inventory_endpoint": "/api/v1/reports",
                "openapi_path": "/reports",
                "direct_access": "scriptable_read",
                "browser_access": "browser_proxied",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-read",
                "x_yafvs_maturity": "live-read",
                "x_yafvs_replaces": "raw-report-list-read",
                "x_yafvs_inherited_still_owns": "raw-report-generation-non-pdf-export-retention-and-mutations",
                "replacement_candidates": ["runtime-report-summary helper"],
            },
        ]

        with unittest.mock.patch.object(yafvsctl, "native_api_migration_matrix_rows", return_value=rows):
            result = yafvsctl.command_native_api_migration_matrix(root, focus=["schedule", "alert"])

        self.assertEqual(result["details"]["focus"], "schedule, alert")
        self.assertEqual(result["details"]["focus_terms"], ["schedule", "alert"])
        self.assertEqual(result["details"]["focus_match_count"], 2)
        self.assertEqual([row["endpoint"] for row in result["details"]["items"]], ["/api/v1/schedules", "/api/v1/alerts"])

    def test_native_api_migration_matrix_focus_accepts_residual_buckets(self):
        root = Path(__file__).resolve().parents[2]
        rows = [
            {
                "endpoint": "/api/v1/overrides",
                "method": "get",
                "inventory_endpoint": "/api/v1/overrides",
                "openapi_path": "/overrides",
                "direct_access": "scriptable_read",
                "browser_access": "browser_proxied",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-read",
                "x_yafvs_maturity": "live-read",
                "x_yafvs_replaces": "override-metadata-list-read",
                "replacement_candidates": ["override list automation"],
            },
            {
                "endpoint": "/api/v1/trashcan/reports",
                "method": "delete",
                "inventory_endpoint": "/api/v1/trashcan/reports",
                "openapi_path": "/trashcan/reports",
                "direct_access": "direct_write_control",
                "browser_access": "browser_proxied",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-write",
                "x_yafvs_maturity": "live-write",
                "x_yafvs_replaces": "trashcan-report-hard-delete",
                "x_yafvs_inherited_still_owns": "trashcan-deep-row-data-and-mutations",
                "replacement_candidates": ["deep Trashcan report delete semantics"],
            },
        ]

        with unittest.mock.patch.object(yafvsctl, "native_api_migration_matrix_rows", return_value=rows):
            result = yafvsctl.command_native_api_migration_matrix(root, focus="write_or_mutation")
        with unittest.mock.patch.object(yafvsctl, "native_api_migration_matrix_rows", return_value=rows):
            compact = yafvsctl.command_native_api_migration_matrix(root, status_only=True, focus="rich_context_or_history")

        self.assertEqual(result["details"]["focus_terms"], ["write_or_mutation"])
        self.assertEqual(result["details"]["focus_match_count"], 1)
        self.assertEqual(result["details"]["items"][0]["endpoint"], "/api/v1/trashcan/reports")
        self.assertEqual(compact["details"]["focus_terms"], ["rich_context_or_history"])
        self.assertEqual(compact["details"]["focus_match_count"], 1)
        self.assertEqual(
            [row["endpoint"] for row in compact["details"]["focus_rows"]],
            ["/api/v1/trashcan/reports"],
        )

    def test_native_api_migration_matrix_focus_warns_on_zero_matches(self):
        root = Path(__file__).resolve().parents[2]
        rows = [
            {
                "endpoint": "/api/v1/reports",
                "method": "get",
                "inventory_endpoint": "/api/v1/reports",
                "openapi_path": "/reports",
                "direct_access": "scriptable_read",
                "browser_access": "browser_proxied",
                "openapi_direct_marker": True,
                "x_yafvs_exposure": "direct-read",
                "x_yafvs_maturity": "live-read",
                "x_yafvs_replaces": "raw-report-list-read",
                "x_yafvs_inherited_still_owns": "raw-report-generation-non-pdf-export-retention-and-mutations",
                "replacement_candidates": ["runtime-report-summary helper"],
            }
        ]

        with unittest.mock.patch.object(yafvsctl, "native_api_migration_matrix_rows", return_value=rows):
            compact = yafvsctl.command_native_api_migration_matrix(
                root,
                status_only=True,
                focus=" schedule , no-such-term ",
            )

        self.assertEqual(compact["status"], "warn")
        self.assertEqual(compact["details"]["focus"], " schedule , no-such-term ")
        self.assertEqual(compact["details"]["focus_terms"], ["schedule", "no-such-term"])
        self.assertEqual(compact["details"]["focus_match_count"], 0)
        self.assertEqual(compact["details"]["focus_rows"], [])
        self.assertFalse(compact["details"]["focus_rows_truncated"])
        self.assertTrue(any(finding["check"] == "native-api-migration-matrix.focus" for finding in compact["findings"]))

    def test_native_api_migration_matrix_focus_parser_accepts_terms(self):
        args = yafvsctl.build_parser().parse_args(["--json", "native-api-migration-matrix", "--focus", "schedule,trash"])

        self.assertEqual(args.focus, ["schedule,trash"])

    def test_native_api_migration_matrix_focus_parser_accepts_repeated_terms(self):
        args = yafvsctl.build_parser().parse_args(["--json", "native-api-migration-matrix", "--focus", "schedule,trash", "--focus", "alerts"])

        self.assertEqual(args.focus, ["schedule,trash", "alerts"])

    def test_native_api_migration_matrix_fails_on_contract_drift(self):
        root = Path(__file__).resolve().parents[2]
        rows = [
            {
                "endpoint": "/api/v1/example",
                "method": "get",
                "inventory_endpoint": "/api/v1/example",
                "openapi_path": None,
                "direct_access": "scriptable_read",
                "openapi_direct_marker": None,
                "x_yafvs_exposure": None,
                "x_yafvs_maturity": None,
                "x_yafvs_replaces": None,
                "x_yafvs_inherited_still_owns": None,
            }
        ]
        with unittest.mock.patch.object(yafvsctl, "native_api_migration_matrix_rows", return_value=rows):
            result = yafvsctl.command_native_api_migration_matrix(root, status_only=True)

        findings = {item["check"]: item for item in result["findings"]}
        self.assertEqual(result["status"], "fail")
        self.assertEqual(findings["native-api-migration-matrix.coverage"]["status"], "fail")
        self.assertEqual(findings["native-api-migration-matrix.metadata"]["status"], "fail")

    def test_native_api_migration_matrix_compact_aliases_status_only(self):
        args = yafvsctl.build_parser().parse_args(["--json", "native-api-migration-matrix", "--compact"])

        self.assertTrue(args.compact)
        self.assertFalse(args.status_only)

    def test_native_api_migration_matrix_remaining_surface_buckets_owner_tails(self):
        rows = [
            {"endpoint": "/api/v1/tasks", "x_yafvs_inherited_still_owns": "task-scan-control-writes-and-deletes"},
            {"endpoint": "/api/v1/targets", "x_yafvs_inherited_still_owns": "target-credential-secrets-writes-and-deletes"},
            {"endpoint": "/api/v1/trashcan/reports", "x_yafvs_inherited_still_owns": "trashcan-deep-row-data-and-mutations"},
        ]

        remaining = yafvsctl.native_api_migration_matrix_remaining_surface(rows)

        self.assertEqual(remaining["rows_with_inherited_owner_tail"], 3)
        self.assertEqual(remaining["distinct_owner_tails"], 3)
        self.assertEqual(remaining["bucket_counts"]["write_or_mutation"], 3)
        self.assertEqual(remaining["bucket_counts"]["control_or_operation"], 1)
        self.assertEqual(remaining["bucket_counts"]["credential_or_secret"], 1)
        self.assertEqual(remaining["bucket_counts"]["rich_context_or_history"], 1)
        self.assertIn("dedicated design packet", remaining["planning_hint"])

    def test_native_api_replacement_dashboard_calculates_weighted_estimate(self):
        root = Path(__file__).resolve().parents[2]
        tooling = {
            "status": "pass",
            "summary": "tooling ok",
            "details": {
                "total_items": 100,
                "by_category_counts": {
                    "required_runtime": 2,
                    "required_test": 1,
                    "product_workflow": 7,
                },
                "candidate_for_removal_review": {
                    "total": 3,
                    "tracked_baseline_count": 4,
                    "tracked_removed_count": 1,
                    "safe_removal_count": 1,
                    "blocked_or_review_count": 2,
                    "bucket_counts": {"write_or_mutation": 2},
                }
            },
            "findings": [],
        }
        matrix = {
            "status": "pass",
            "summary": "matrix ok",
            "details": {
                "summary": {
                    "total_rows": 10,
                    "progress_percentages": {
                        "openapi_operation_rows_percent": 100.0,
                        "inventory_rows_percent": 90.0,
                        "rows_with_checked_migration_metadata_percent": 80.0,
                        "browser_proxied_percent": 70.0,
                    },
                    "by_direct_access": {"scriptable_read": 5, "direct_write_control": 2},
                },
                "remaining_inherited_surface": {
                    "rows_with_inherited_owner_tail": 4,
                    "bucket_counts": {"write_or_mutation": 4},
                    "top_residuals": [{"residue": "target-writes", "example_endpoint": "/api/v1/targets", "count": 4}],
                },
            },
            "findings": [],
        }

        source_teardown = {
            "percent": 0.0,
            "status": "in_progress",
            "components": {"python-gvm": "present", "gvm-tools": "present"},
        }
        with unittest.mock.patch.object(yafvsctl, "command_native_tooling_state", return_value=tooling), \
             unittest.mock.patch.object(yafvsctl, "command_native_api_migration_matrix", return_value=matrix), \
             unittest.mock.patch.object(yafvsctl, "legacy_component_source_teardown", return_value=source_teardown):
            result = yafvsctl.command_native_api_replacement_dashboard(root, status_only=True)

        weighted = result["weighted_estimate"]
        self.assertEqual(result["headline_replacement_percent"], 72.2)
        self.assertEqual(weighted["kind"], "weighted_estimate")
        self.assertEqual(weighted["components"]["contract_percent"], 90.0)
        self.assertEqual(weighted["components"]["direct_scriptable_percent"], 70.0)
        self.assertEqual(weighted["components"]["inherited_tail_burndown_percent"], 60.0)
        self.assertEqual(result["tooling_retirement_status"]["safe_removal_count"], 1)
        legacy = result["legacy_helper_removal_readiness"]
        self.assertEqual(result["legacy_helper_removal_readiness_percent"], 64.3)
        self.assertEqual(legacy["kind"], "weighted_estimate")
        self.assertEqual(legacy["components"]["stage1_replacement_percent"], 71.5)
        self.assertFalse(legacy["components"]["stage1_complete"])
        self.assertEqual(legacy["components"]["stage2_component_source_teardown_percent"], 0.0)
        self.assertEqual(legacy["components"]["direct_legacy_dependency_burndown_percent"], 79.7)
        self.assertEqual(legacy["components"]["gvm_tools_script_removal_percent"], 25.0)
        self.assertEqual(legacy["blockers"]["direct_legacy_blocker_count"], 12)
        self.assertEqual(legacy["blockers"]["direct_legacy_blocker_baseline_count"], 59)
        self.assertEqual(legacy["blockers"]["gvm_tools_blocked_or_review_count"], 2)
        self.assertEqual(legacy["blockers"]["gvm_tools_tracked_baseline_count"], 4)
        self.assertEqual(legacy["blockers"]["gvm_tools_tracked_removed_count"], 1)
        self.assertEqual(result["next_best_slices"][0]["focus"], "target-writes")

    def test_legacy_component_source_teardown_tracks_both_components(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "components" / "python-gvm").mkdir(parents=True)

            result = yafvsctl.legacy_component_source_teardown(root)

        self.assertEqual(result["percent"], 50.0)
        self.assertEqual(result["status"], "in_progress")
        self.assertEqual(result["components"]["python-gvm"], "present")
        self.assertEqual(result["components"]["gvm-tools"], "absent")

    def test_closeout_readiness_downgrades_optional_production_posture_to_watch(self):
        root = Path(__file__).resolve().parents[2]
        pass_result = {"status": "pass", "summary": "ok", "findings": []}
        prod_result = {"status": "fail", "summary": "production not ready", "findings": [{"status": "fail", "check": "production.default-credentials", "message": "bad"}]}

        with unittest.mock.patch.object(yafvsctl, "run_git", return_value=""), \
             unittest.mock.patch.object(yafvsctl, "rust_quality_gate_state_result", return_value=pass_result) as quality_state, \
             unittest.mock.patch.object(yafvsctl, "command_native_tooling_state", return_value=pass_result), \
             unittest.mock.patch.object(yafvsctl, "command_native_api_client_contract", return_value=pass_result), \
             unittest.mock.patch.object(yafvsctl, "command_native_api_migration_matrix", return_value=pass_result), \
             unittest.mock.patch.object(yafvsctl, "rust_license_report_result", return_value=pass_result) as license_report, \
             unittest.mock.patch.object(yafvsctl, "rust_production_posture_result", return_value=prod_result) as production_posture:
            result = yafvsctl.command_closeout_readiness(root, status_only=True)

        self.assertEqual(result["status"], "warn")
        self.assertEqual(result["details"]["steps"]["production-posture-check"]["status"], "warn")
        self.assertIn("hosted-workflow", result["details"]["unknown_steps"])
        self.assertTrue(any(item["check"] == "closeout-readiness.production-posture-check" for item in result["findings"]))
        quality_state.assert_called_once_with(root, status_only=True)
        license_report.assert_called_once_with(root, modified_imported_only=True, diff_scope="staged", status_only=True)
        production_posture.assert_called_once_with(root, status_only=True)

    def test_openapi_operation_id_generator_is_stable_and_collision_free(self):
        root = Path(__file__).resolve().parents[2]
        operations = yafvsctl.openapi_contract_operations(root)
        operation_ids = [
            yafvsctl.openapi_contract_operation_id(item["method"], item["path"])
            for item in operations
        ]

        self.assertEqual(len(operation_ids), 218)
        self.assertEqual(len(operation_ids), len(set(operation_ids)))
        self.assertEqual(yafvsctl.openapi_contract_operation_id("get", "/alerts/{alert_id}"), "getAlertsByAlertId")
        self.assertEqual(yafvsctl.openapi_contract_operation_id("patch", "/alerts/{alert_id}"), "patchAlertsByAlertId")
        self.assertEqual(yafvsctl.openapi_contract_operation_id("patch", "/credentials/{credential_id}"), "patchCredentialsByCredentialId")
        self.assertEqual(yafvsctl.openapi_contract_operation_id("get", "/reports/{report_id}/results"), "getReportsByReportIdResults")
        self.assertEqual(
            yafvsctl.openapi_contract_operation_id("get", "/filters/{filter_id}/export"),
            "getFiltersByFilterIdExport",
        )
        self.assertEqual(
            yafvsctl.openapi_contract_operation_id("get", "/scan-configs/{scan_config_id}/backup"),
            "getScanConfigsByScanConfigIdBackup",
        )
        self.assertEqual(
            yafvsctl.openapi_contract_operation_id("post", "/scan-configs/import"),
            "postScanConfigsImport",
        )
        self.assertEqual(
            yafvsctl.openapi_contract_operation_id("get", "/scopes/{scope_id}/reports/{scope_report_id}/retention-plan"),
            "getScopesByScopeIdReportsByScopeReportIdRetentionPlan",
        )

    def test_native_tooling_state_reports_openapi_contract_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "openapi: 3.1.0\n"
                "paths:\n"
                "  /reports:\n"
                "    get:\n"
                "      summary: Drifted reports\n"
                "      operationId: customReports\n"
                "      x-yafvs-direct: true\n"
                "      x-yafvs-exposure: banana\n"
                "      x-yafvs-maturity: stale\n"
                "      x-yafvs-replaces: everything\n"
                "      x-yafvs-inherited-still-owns: all-the-things\n"
                "      x-yafvs-team-authority: authenticated-stack-operator\n"
                "      x-yafvs-surprise: true\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Reports\n"
                "        '400':\n"
                "          $ref: '#/components/responses/BadRequest'\n"
                "components:\n"
                "  responses:\n"
                "    BadRequest:\n"
                "      content:\n"
                "        application/json:\n"
                "          schema:\n"
                "            $ref: '#/components/schemas/Other'\n"
                "  schemas:\n"
                "    Error:\n"
                "      type: object\n",
                encoding="utf-8",
            )
            summary = yafvsctl.native_api_openapi_contract_summary(root)

        self.assertEqual(summary["alignment_status"], "warn")
        self.assertEqual(summary["operation_count"], 1)
        self.assertEqual(summary["missing_operation_ids"], [])
        self.assertEqual(summary["missing_operation_summaries"], [])
        self.assertEqual(summary["duplicate_operation_ids"], [])
        self.assertEqual(summary["nondeterministic_operation_ids"][0]["operation"], "GET /reports")
        self.assertEqual(summary["nondeterministic_operation_ids"][0]["expected"], "getReports")
        self.assertEqual(summary["unexpected_yafvs_operation_fields"], [{"operation": "GET /reports", "fields": ["x-yafvs-surprise"]}])
        self.assertEqual(summary["invalid_exposure_operations"], [{"operation": "GET /reports", "actual": "banana", "allowed": ["browser-write", "direct-read", "direct-write", "internal-only"]}])
        missing_exposure = {item["operation"] for item in summary["missing_exposure_operations"]}
        self.assertEqual(
            missing_exposure,
            {
                "GET /alerts",
                "POST /alerts",
                "GET /alerts/{alert_id}",
                "GET /alerts/{alert_id}/definition",
                "GET /alerts/{alert_id}/export",
                "PATCH /alerts/{alert_id}",
                "PUT /alerts/{alert_id}/definition",
                "DELETE /alerts/{alert_id}",
                "POST /alerts/{alert_id}/clone",
                "POST /alerts/{alert_id}/deliver-report",
                "POST /alerts/{alert_id}/test",
                "GET /authentication-settings",
                "PUT /authentication-settings/ldap",
                "PUT /authentication-settings/radius",
                "POST /credentials",
                "DELETE /credentials/{credential_id}",
                "POST /credentials/{credential_id}/clone",
                "GET /credentials/{credential_id}/certificate",
                "GET /credentials/{credential_id}/public-key",
                "GET /user-management/users",
                "POST /user-management/users",
                "GET /user-management/users/{user_id}",
                "PATCH /user-management/users/{user_id}",
                "DELETE /user-management/users/{user_id}",
                "POST /user-management/users/{user_id}/clone",
                "GET /users/current/settings",
                "GET /users/current/settings/{setting_id}",
                "PUT /users/current/settings/{setting_id}",
                "PUT /users/current/timezone",
                "GET /cert-bund-advisories",
                "GET /cert-bund-advisories/{cert_bund_advisory_id}",
                "GET /cert-bund-advisories/{cert_bund_advisory_id}/export",
                "GET /cpes",
                "GET /cpes/{cpe_id}",
                "GET /cves",
                "GET /cves/{cve_id}",
                "GET /cves/{cve_id}/export",
                "GET /dfn-cert-advisories",
                "GET /dfn-cert-advisories/{dfn_cert_advisory_id}",
                "GET /dfn-cert-advisories/{dfn_cert_advisory_id}/export",
                "GET /feeds",
                "POST /hosts",
                "PATCH /hosts/{host_id}",
                "DELETE /hosts/{host_id}",
                "DELETE /host-identifiers/{identifier_id}",
                "DELETE /host-operating-systems/{host_operating_system_id}",
                "DELETE /tls-certificates/{certificate_id}",
                "GET /vulnerabilities/{vulnerability_id}",
                "GET /vulnerabilities/{vulnerability_id}/export",
                "GET /nvts",
                "GET /nvts/{nvt_id}",
                "GET /nvts/{nvt_id}/export",
                "GET /operating-systems",
                "GET /operating-systems/{os_id}",
                "POST /overrides",
                "GET /overrides",
                "GET /overrides/{override_id}",
                "PATCH /overrides/{override_id}",
                "DELETE /overrides/{override_id}",
                "POST /overrides/{override_id}/clone",
                "POST /overrides/{override_id}/restore",
                "DELETE /overrides/{override_id}/trash",
                "GET /overrides/{override_id}/export",
                "POST /filters",
                "DELETE /filters/{filter_id}/trash",
                "POST /filters/{filter_id}/clone",
                "POST /filters/{filter_id}/restore",
                "GET /tags/{tag_id}/export",
                "POST /tags/{tag_id}/clone",
                "DELETE /port-lists/{port_list_id}",
                "DELETE /port-lists/{port_list_id}/ranges/{port_range_id}",
                "DELETE /port-lists/{port_list_id}/trash",
                "PATCH /port-lists/{port_list_id}",
                "POST /port-lists",
                "POST /port-lists/{port_list_id}/ranges",
                "POST /port-lists/{port_list_id}/clone",
                "GET /port-lists/{port_list_id}/export",
                "POST /port-lists/{port_list_id}/restore",
                "DELETE /schedules/{schedule_id}",
                "PATCH /schedules/{schedule_id}",
                "GET /schedules/{schedule_id}/export",
                "POST /schedules/{schedule_id}/clone",
                "POST /schedules/{schedule_id}/restore",
                "DELETE /schedules/{schedule_id}/trash",
                "GET /hosts",
                "GET /hosts/{host_id}",
                "GET /tls-certificates",
                "GET /tls-certificates/{certificate_id}",
                "GET /tls-certificates/{certificate_id}/certificate",
                "GET /scanners",
                "GET /scanners/{scanner_id}",
                "PATCH /scanners/{scanner_id}",
                "POST /scanners/{scanner_id}/verify",
                "GET /credentials",
                "GET /credentials/{credential_id}",
                "PATCH /credentials/{credential_id}",
                "GET /scan-configs",
                "POST /scan-configs",
                "POST /scan-configs/import",
                "GET /scan-configs/{scan_config_id}",
                "GET /scan-configs/{scan_config_id}/backup",
                "GET /scan-configs/{scan_config_id}/export",
                "PATCH /scan-configs/{scan_config_id}",
                "DELETE /scan-configs/{scan_config_id}",
                "POST /scan-configs/{scan_config_id}/clone",
                "POST /scan-configs/{scan_config_id}/restore",
                "DELETE /scan-configs/{scan_config_id}/trash",
                "GET /scan-configs/{scan_config_id}/families",
                "GET /scan-configs/{scan_config_id}/families/{family}/nvts",
                "PATCH /scan-configs/{scan_config_id}/families/{family}/nvts",
                "GET /tags",
                "GET /tags/resource-names/{resource_type}",
                "GET /tags/{tag_id}",
                "GET /tags/{tag_id}/resources",
                "GET /trashcan/empty-preview",
                "GET /trashcan/items",
                "GET /trashcan/summary",
                "POST /trashcan/empty",
                "GET /users",
                "POST /users/current/password",
                "GET /users/{user_id}",
                "GET /reports/{report_id}",
                "GET /reports/{report_id}/download",
                "GET /reports/{report_id}/raw-results",
                "GET /reports/{report_id}/results",
                "GET /reports/{report_id}/hosts",
                "GET /reports/{report_id}/ports",
                "GET /reports/{report_id}/applications",
                "GET /reports/{report_id}/operating-systems",
                "GET /reports/{report_id}/cves",
                "GET /reports/{report_id}/tls-certificates",
                "GET /reports/{report_id}/errors",
                "GET /reports/{report_id}/metrics",
                "GET /results/{result_id}/export",
                "GET /scope-reports",
                "DELETE /scope-reports/{scope_report_id}",
                "GET /scope-reports/{scope_report_id}",
                "GET /scope-reports/{scope_report_id}/results",
                "GET /timezones",
                "GET /nvt-families",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/results",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/hosts",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/ports",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/applications",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/operating-systems",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/cves",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/tls-certificates",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/errors",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/metrics",
                "GET /scopes/{scope_id}/reports/{scope_report_id}/retention-plan",
                "POST /scopes/{scope_id}/reports",
                "POST /targets",
                "PATCH /targets/{target_id}",
                "DELETE /targets/{target_id}",
                "GET /targets/{target_id}/export",
                "POST /targets/{target_id}/clone",
                "POST /targets/{target_id}/restore",
                "DELETE /targets/{target_id}/trash",
                "POST /tasks",
                "POST /tasks/{task_id}/clone",
                "POST /tasks/{task_id}/start",
                "POST /tasks/{task_id}/replace-target",
                "POST /tasks/{task_id}/replace-configuration",
                "POST /tasks/{task_id}/stop",
                "PATCH /tasks/{task_id}",
                "DELETE /tasks/{task_id}",
                "GET /tasks/{task_id}/export",
                "GET /filters/{filter_id}/export",
                "PATCH /filters/{filter_id}",
                "DELETE /filters/{filter_id}",
                "POST /scopes",
                "PATCH /scopes/{scope_id}",
                "DELETE /scopes/{scope_id}",
                "POST /tags",
                "PATCH /tags/{tag_id}",
                "DELETE /tags/{tag_id}",
                "POST /tags/{tag_id}/resources",
            },
        )
        self.assertEqual(
            summary["invalid_migration_metadata_operations"],
            [
                {
                    "operation": "GET /reports",
                    "field": "x-yafvs-inherited-still-owns",
                    "actual": "all-the-things",
                    "allowed": sorted(yafvsctl.OPENAPI_ALLOWED_INHERITED_STILL_OWNS_VALUES),
                },
                {
                    "operation": "GET /reports",
                    "field": "x-yafvs-maturity",
                    "actual": "stale",
                    "allowed": ["live-control", "live-read", "live-write", "preview-control", "preview-read", "preview-write"],
                },
                {
                    "operation": "GET /reports",
                    "field": "x-yafvs-replaces",
                    "actual": "everything",
                    "allowed": sorted(yafvsctl.OPENAPI_ALLOWED_REPLACES_VALUES),
                },
            ],
        )
        missing_migration = {(item["operation"], item["field"]) for item in summary["missing_migration_metadata_operations"]}
        self.assertIn(("GET /alerts", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /alerts/{alert_id}", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /cert-bund-advisories", "x-yafvs-maturity"), missing_migration)
        self.assertIn(("GET /cpes", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /cves", "x-yafvs-maturity"), missing_migration)
        self.assertIn(("GET /cves/{cve_id}", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /dfn-cert-advisories", "x-yafvs-maturity"), missing_migration)
        self.assertIn(("GET /feeds", "x-yafvs-maturity"), missing_migration)
        self.assertIn(("GET /nvts", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /nvts/{nvt_id}", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /operating-systems", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /tls-certificates/{certificate_id}", "x-yafvs-maturity"), missing_migration)
        self.assertIn(("GET /scanners", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /tags", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /tags/{tag_id}", "x-yafvs-maturity"), missing_migration)
        self.assertIn(("GET /tags/{tag_id}/resources", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /trashcan/summary", "x-yafvs-inherited-still-owns"), missing_migration)
        self.assertIn(("GET /reports/{report_id}/results", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /scopes/{scope_id}/reports/{scope_report_id}/results", "x-yafvs-maturity"), missing_migration)
        self.assertIn(("GET /scopes/{scope_id}/reports/{scope_report_id}/metrics", "x-yafvs-replaces"), missing_migration)
        self.assertIn(("GET /scopes/{scope_id}/reports/{scope_report_id}/retention-plan", "x-yafvs-replaces"), missing_migration)
        self.assertEqual(
            summary["migration_metadata_mismatches"],
            [
                {
                    "operation": "GET /reports",
                    "field": "x-yafvs-inherited-still-owns",
                    "actual": "all-the-things",
                    "expected": "raw-report-generation-non-pdf-export-retention-and-mutations",
                },
                {
                    "operation": "GET /reports",
                    "field": "x-yafvs-maturity",
                    "actual": "stale",
                    "expected": "live-read",
                },
                {
                    "operation": "GET /reports",
                    "field": "x-yafvs-replaces",
                    "actual": "everything",
                    "expected": "raw-report-list-read",
                },
            ],
        )
        self.assertEqual(
            summary["exposure_mismatches"],
            [
                {
                    "operation": "GET /reports",
                    "field": "x-yafvs-exposure",
                    "actual": "banana",
                    "expected": "direct-read",
                },
            ],
        )
        self.assertIn("Unauthorized", summary["missing_shared_error_responses"])
        self.assertEqual(summary["invalid_shared_error_responses"], [{"response": "BadRequest", "actual": "#/components/schemas/Other", "expected": "#/components/schemas/Error"}])
        missing_statuses = {item["status"] for item in summary["operations_missing_error_responses"]}
        self.assertEqual(missing_statuses, {"401", "405", "413", "429", "500"})
        missing_error_schema = {item["field"] for item in summary["missing_error_schema_fields"]}
        self.assertIn("properties.error.required", missing_error_schema)
        self.assertIn("properties.error.properties.code.type", missing_error_schema)
        self.assertEqual(summary["invalid_error_schema_fields"], [])

    def test_openapi_contract_requires_summary_and_generic_direct_exposure_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "openapi: 3.1.0\n"
                "paths:\n"
                "  /future-direct:\n"
                "    get:\n"
                "      operationId: getFutureDirect\n"
                "      x-yafvs-exposure: direct-read\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Future\n"
                "  /future-internal:\n"
                "    post:\n"
                "      summary: Future internal\n"
                "      operationId: postFutureInternal\n"
                "      x-yafvs-direct: true\n"
                "      x-yafvs-exposure: internal-only\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Future\n"
                "  /future-metadata:\n"
                "    get:\n"
                "      summary: Future metadata\n"
                "      operationId: getFutureMetadata\n"
                "      x-yafvs-replaces: none\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Future\n"
                "  /future-body:\n"
                "    get:\n"
                "      summary: Future body\n"
                "      operationId: getFutureBody\n"
                "      x-yafvs-exposure: direct-read\n"
                "      requestBody:\n"
                "        required: true\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Future\n",
                encoding="utf-8",
            )

            summary = yafvsctl.native_api_openapi_contract_summary(root)

        self.assertEqual(summary["alignment_status"], "warn")
        self.assertEqual(summary["missing_operation_summaries"], ["GET /future-direct"])
        self.assertEqual(summary["operations_with_request_bodies"], ["GET /future-body"])
        self.assertIn(
            {
                "operation": "GET /future-metadata",
                "expected": ["browser-write", "direct-read", "direct-write", "internal-only"],
                "reason": "field_missing_for_yafvs_contract",
            },
            summary["missing_exposure_operations"],
        )
        self.assertIn(
            {
                "operation": "GET /future-direct",
                "field": "x-yafvs-direct",
                "actual": False,
                "expected": True,
            },
            summary["exposure_mismatches"],
        )
        self.assertIn(
            {
                "operation": "POST /future-internal",
                "field": "x-yafvs-direct",
                "actual": True,
                "expected": False,
            },
            summary["exposure_mismatches"],
        )

    def test_openapi_contract_checks_write_control_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "openapi: 3.1.0\n"
                "paths:\n"
                "  /future-tag:\n"
                "    post:\n"
                "      summary: Create future tag\n"
                "      operationId: postFutureTag\n"
                "      x-yafvs-direct: true\n"
                "      x-yafvs-exposure: direct-write\n"
                "      x-yafvs-maturity: preview-write\n"
                "      x-yafvs-replaces: none\n"
                "      x-yafvs-inherited-still-owns: tag-security-info-filter-actions-clone-export-trash\n"
                "      x-yafvs-operator-identity: direct-token-operator\n"
                "      x-yafvs-owner-semantics: request-operator-owner\n"
                "      x-yafvs-safety-contract: write-control-v1\n"
                "      x-yafvs-side-effect: metadata-write\n"
                "      requestBody:\n"
                "        required: true\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Future\n"
                "  /bad-write:\n"
                "    patch:\n"
                "      summary: Bad write\n"
                "      operationId: patchBadWrite\n"
                "      x-yafvs-direct: true\n"
                "      x-yafvs-exposure: direct-read\n"
                "      x-yafvs-side-effect: mystery\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Future\n"
                "  /bad-get-body:\n"
                "    get:\n"
                "      summary: Bad get body\n"
                "      operationId: getBadGetBody\n"
                "      x-yafvs-direct: true\n"
                "      x-yafvs-exposure: direct-write\n"
                "      x-yafvs-maturity: preview-write\n"
                "      x-yafvs-replaces: none\n"
                "      x-yafvs-inherited-still-owns: tag-security-info-filter-actions-clone-export-trash\n"
                "      x-yafvs-operator-identity: not-applicable-preview\n"
                "      x-yafvs-owner-semantics: not-applicable-preview\n"
                "      x-yafvs-safety-contract: write-control-v1\n"
                "      x-yafvs-side-effect: metadata-write\n"
                "      requestBody:\n"
                "        required: true\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Future\n",
                encoding="utf-8",
            )
            operations = yafvsctl.openapi_contract_operations(root)
            write_control = yafvsctl.openapi_write_control_contract_summary(operations)

        self.assertEqual(write_control["alignment_status"], "warn")
        self.assertEqual(
            write_control["write_control_operations"],
            ["POST /future-tag", "PATCH /bad-write", "GET /bad-get-body"],
        )
        self.assertEqual(write_control["direct_write_control_operations"], ["POST /future-tag", "PATCH /bad-write", "GET /bad-get-body"])
        self.assertEqual(write_control["request_body_operations"], ["POST /future-tag", "GET /bad-get-body"])
        self.assertEqual(write_control["get_request_body_operations"], ["GET /bad-get-body"])
        missing = {(item["operation"], item["field"]) for item in write_control["missing_write_control_metadata"]}
        self.assertIn(("PATCH /bad-write", "x-yafvs-maturity"), missing)
        self.assertIn(("PATCH /bad-write", "x-yafvs-operator-identity"), missing)
        self.assertIn(("PATCH /bad-write", "x-yafvs-owner-semantics"), missing)
        self.assertIn(("PATCH /bad-write", "x-yafvs-replaces"), missing)
        invalid = {(item["operation"], item["field"]): item for item in write_control["invalid_write_control_metadata"]}
        self.assertEqual(invalid[("PATCH /bad-write", "x-yafvs-exposure")]["actual"], "direct-read")
        self.assertEqual(invalid[("PATCH /bad-write", "x-yafvs-side-effect")]["actual"], "mystery")
        self.assertEqual(invalid[("GET /bad-get-body", "method")]["actual"], "get")
        self.assertEqual(invalid[("GET /bad-get-body", "x-yafvs-exposure")]["actual"], "direct-write")

    def test_openapi_contract_checks_direct_write_uuid_path_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "openapi: 3.1.0\n"
                "paths:\n"
                "  /future-tags/{tag_id}:\n"
                "    patch:\n"
                "      summary: Patch future tag\n"
                "      operationId: patchFutureTagsByTagId\n"
                "      x-yafvs-direct: true\n"
                "      x-yafvs-exposure: direct-write\n"
                "      x-yafvs-maturity: live-write\n"
                "      x-yafvs-replaces: tag-metadata-write\n"
                "      x-yafvs-inherited-still-owns: tag-security-info-filter-actions-clone-export-trash\n"
                "      x-yafvs-operator-identity: direct-token-operator\n"
                "      x-yafvs-owner-semantics: preserve-existing-owner\n"
                "      x-yafvs-safety-contract: write-control-v1\n"
                "      x-yafvs-side-effect: metadata-write\n"
                "      parameters:\n"
                "        - $ref: '#/components/parameters/TagId'\n"
                "      requestBody:\n"
                "        required: true\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Future\n"
                "components:\n"
                "  parameters:\n"
                "    TagId:\n"
                "      name: tag_id\n"
                "      in: path\n"
                "      required: true\n"
                "      schema:\n"
                "        type: string\n"
                "        format: slug\n",
                encoding="utf-8",
            )
            operations = yafvsctl.openapi_contract_operations(root)
            parameters = yafvsctl.openapi_parameter_components(root)
            write_control = yafvsctl.openapi_write_control_contract_summary(operations, parameters)

        self.assertEqual(write_control["alignment_status"], "warn")
        self.assertEqual(
            write_control["invalid_write_control_path_parameters"],
            [
                {
                    "operation": "PATCH /future-tags/{tag_id}",
                    "field": "components.parameters.TagId.format",
                    "actual": "slug",
                    "expected": "uuid",
                }
            ],
        )

    def test_native_tooling_state_reports_openapi_collection_query_contract_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            collections = root / "services" / "yafvs-api" / "src" / "collections.rs"
            main = root / "services" / "yafvs-api" / "src" / "main.rs"
            openapi.parent.mkdir(parents=True)
            collections.parent.mkdir(parents=True)
            collections.write_text(
                "pub(crate) const DEFAULT_COLLECTION_PAGE_SIZE: i64 = 50;\n"
                "pub(crate) const MAX_COLLECTION_PAGE_SIZE: i64 = 500;\n"
                "pub(crate) const MAX_COLLECTION_FILTER_LENGTH: usize = 4096;\n",
                encoding="utf-8",
            )
            main.write_text(
                'const COLLECTION_CONTRACTS: &[CollectionContract] = &[\n'
                '    CollectionContract { path: "/api/v1/reports" },\n'
                '];\n',
                encoding="utf-8",
            )
            openapi.write_text(
                "openapi: 3.1.0\n"
                "paths:\n"
                "  /reports:\n"
                "    get:\n"
                "      operationId: getReports\n"
                "      parameters:\n"
                "        - $ref: '#/components/parameters/Page'\n"
                "        - $ref: '#/components/parameters/PageSize'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Reports\n"
                "  /results:\n"
                "    get:\n"
                "      operationId: getResults\n"
                "      parameters:\n"
                "        - $ref: '#/components/parameters/Page'\n"
                "        - $ref: '#/components/parameters/PageSize'\n"
                "        - $ref: '#/components/parameters/Sort'\n"
                "        - $ref: '#/components/parameters/Filter'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Results\n"
                "components:\n"
                "  parameters:\n"
                "    Page:\n"
                "      name: page\n"
                "      in: query\n"
                "      schema:\n"
                "        type: integer\n"
                "        minimum: 1\n"
                "        default: 1\n"
                "    PageSize:\n"
                "      name: page_size\n"
                "      in: query\n"
                "      schema:\n"
                "        type: integer\n"
                "        minimum: 1\n"
                "        maximum: 499\n"
                "        default: 25\n"
                "    Sort:\n"
                "      name: sort\n"
                "      in: query\n"
                "      schema:\n"
                "        type: string\n"
                "    Filter:\n"
                "      name: filter\n"
                "      in: query\n"
                "      schema:\n"
                "        type: string\n"
                "        maxLength: 2048\n",
                encoding="utf-8",
            )
            operations = yafvsctl.openapi_contract_operations(root)
            summary = yafvsctl.openapi_collection_query_contract_summary(root, operations)

        self.assertEqual(summary["alignment_status"], "warn")
        mismatches = {item["field"]: item for item in summary["collection_limit_mismatches"]}
        self.assertEqual(mismatches["default_page_size"]["openapi"], 25)
        self.assertEqual(mismatches["default_page_size"]["rust"], 50)
        self.assertEqual(mismatches["max_page_size"]["openapi"], 499)
        self.assertEqual(mismatches["max_page_size"]["rust"], 500)
        self.assertEqual(mismatches["max_filter_length"]["openapi"], 2048)
        self.assertEqual(mismatches["max_filter_length"]["rust"], 4096)
        self.assertEqual(
            summary["incomplete_collection_parameters"],
            [{"operation": "GET /reports", "present": ["Page", "PageSize"], "missing": ["Filter", "Sort"]}],
        )
        self.assertEqual(summary["rust_collection_contract_count"], 1)
        self.assertEqual(summary["openapi_collection_operation_count"], 1)
        self.assertEqual(summary["missing_openapi_collection_parameters"], ["/api/v1/reports"])
        self.assertEqual(summary["missing_rust_collection_contracts"], ["/api/v1/results"])

    def test_native_tooling_state_reports_invalid_openapi_error_schema_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "openapi: 3.1.0\n"
                "paths: {}\n"
                "components:\n"
                "  schemas:\n"
                "    Error:\n"
                "      type: array\n"
                "      required: [message]\n"
                "      properties:\n"
                "        error:\n"
                "          type: string\n"
                "          required: [code]\n"
                "          properties:\n"
                "            code:\n"
                "              type: integer\n"
                "            message:\n"
                "              type: object\n"
                "            details:\n"
                "              type: string\n"
                "              additionalProperties: false\n",
                encoding="utf-8",
            )
            summary = yafvsctl.native_api_openapi_contract_summary(root)

        self.assertEqual(summary["alignment_status"], "warn")
        self.assertEqual(summary["missing_error_schema_fields"], [])
        invalid = {item["field"]: item for item in summary["invalid_error_schema_fields"]}
        self.assertEqual(invalid["type"]["actual"], "array")
        self.assertEqual(invalid["required"]["expected"], "[error]")
        self.assertEqual(invalid["properties.error.type"]["actual"], "string")
        self.assertEqual(invalid["properties.error.properties.code.type"]["actual"], "integer")
        self.assertEqual(invalid["properties.error.properties.details.additionalProperties"]["actual"], "false")

    def test_openapi_contract_checks_request_body_schema_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "openapi: 3.1.0\n"
                "paths:\n"
                "  /good:\n"
                "    post:\n"
                "      summary: Good body\n"
                "      operationId: postGood\n"
                "      requestBody:\n"
                "        required: true\n"
                "        content:\n"
                "          application/json:\n"
                "            schema:\n"
                "              $ref: '#/components/schemas/GoodRequest'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Good\n"
                "  /union:\n"
                "    post:\n"
                "      summary: Discriminated union body\n"
                "      operationId: postUnion\n"
                "      requestBody:\n"
                "        required: true\n"
                "        content:\n"
                "          application/json:\n"
                "            schema:\n"
                "              $ref: '#/components/schemas/UnionRequest'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Union\n"
                "  /empty:\n"
                "    post:\n"
                "      summary: Closed empty body\n"
                "      operationId: postEmpty\n"
                "      requestBody:\n"
                "        required: true\n"
                "        content:\n"
                "          application/json:\n"
                "            schema:\n"
                "              $ref: '#/components/schemas/EmptyRequest'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Empty\n"
                "  /nested:\n"
                "    post:\n"
                "      summary: Nested body\n"
                "      operationId: postNested\n"
                "      requestBody:\n"
                "        required: true\n"
                "        content:\n"
                "          application/json:\n"
                "            schema:\n"
                "              $ref: '#/components/schemas/NestedRequest'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Nested\n"
                "  /missing:\n"
                "    post:\n"
                "      summary: Missing body\n"
                "      operationId: postMissing\n"
                "      requestBody:\n"
                "        required: true\n"
                "        content:\n"
                "          application/json:\n"
                "            schema:\n"
                "              $ref: '#/components/schemas/MissingRequest'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Missing\n"
                "  /bad-shape:\n"
                "    post:\n"
                "      summary: Bad shape body\n"
                "      operationId: postBadShape\n"
                "      requestBody:\n"
                "        required: true\n"
                "        content:\n"
                "          application/json:\n"
                "            schema:\n"
                "              $ref: '#/components/schemas/BadShapeRequest'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: Bad shape\n"
                "components:\n"
                "  schemas:\n"
                "    GoodRequest:\n"
                "      type: object\n"
                "      additionalProperties: false\n"
                "      properties:\n"
                "        name:\n"
                "          type: string\n"
                "    EmptyRequest:\n"
                "      type: object\n"
                "      maxProperties: 0\n"
                "      additionalProperties: false\n"
                "    UnionRequest:\n"
                "      oneOf:\n"
                "        - $ref: '#/components/schemas/UnionEmailRequest'\n"
                "        - $ref: '#/components/schemas/UnionSmbRequest'\n"
                "      discriminator:\n"
                "        propertyName: method\n"
                "    UnionEmailRequest:\n"
                "      type: object\n"
                "      properties:\n"
                "        method:\n"
                "          const: EMAIL\n"
                "    UnionSmbRequest:\n"
                "      type: object\n"
                "      properties:\n"
                "        method:\n"
                "          const: SMB\n"
                "    ParentRequest:\n"
                "      type: object\n"
                "      additionalProperties: false\n"
                "      properties:\n"
                "        child:\n"
                "          type: object\n"
                "      NestedRequest:\n"
                "        type: object\n"
                "        properties:\n"
                "          value:\n"
                "            type: string\n"
                "    BadShapeRequest:\n"
                "      type: object\n"
                "      additionalProperties: false\n",
                encoding="utf-8",
            )

            summary = yafvsctl.native_api_openapi_contract_summary(root)

        self.assertEqual(summary["alignment_status"], "warn")
        self.assertIn("#/components/schemas/GoodRequest", summary["request_body_schema_refs"])
        self.assertIn("#/components/schemas/EmptyRequest", summary["request_body_schema_refs"])
        self.assertIn("#/components/schemas/UnionRequest", summary["request_body_schema_refs"])
        missing = {(item["operation"], item["field"]) for item in summary["missing_request_body_schema_refs"]}
        self.assertIn(("POST /missing", "components.schemas.MissingRequest"), missing)
        self.assertIn(("POST /nested", "components.schemas.NestedRequest"), missing)
        invalid = {(item["operation"], item["field"]): item for item in summary["invalid_request_body_schema_refs"]}
        self.assertEqual(
            invalid[("POST /bad-shape", "components.schemas.BadShapeRequest.properties")]["expected"],
            "top-level properties",
        )
        self.assertFalse(any(operation == "POST /empty" for operation, _field in invalid))
        self.assertNotIn(("POST /union", "components.schemas.UnionRequest.oneOf"), invalid)

    def test_openapi_contract_tracks_auth_and_server_boundary(self):
        root = Path(__file__).resolve().parents[2]
        summary = yafvsctl.native_api_openapi_contract_summary(root)
        auth = summary["auth_contract"]

        self.assertEqual(auth["alignment_status"], "pass")
        self.assertEqual(set(auth["servers"]), {"/api/v1", "http://127.0.0.1:19080/api/v1"})
        self.assertEqual(set(auth["security_requirements"]), {"operatorSession", "bearerAuth"})
        self.assertEqual(auth["security_schemes"]["operatorSession"]["name"], "yafvs_session")
        self.assertEqual(auth["security_schemes"]["bearerAuth"]["scheme"], "bearer")
        compact = yafvsctl.compact_native_tooling_summary({"openapi_contract": summary})["openapi_contract"]
        self.assertEqual(compact["auth_contract_alignment_status"], "pass")
        self.assertEqual(compact["missing_security_scheme_count"], 0)

    def test_openapi_contract_warns_on_auth_boundary_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            openapi = root / "api" / "openapi" / "yafvs-v1.yaml"
            openapi.parent.mkdir(parents=True)
            openapi.write_text(
                "openapi: 3.1.0\n"
                "info:\n"
                "  title: Drift\n"
                "  version: test\n"
                "servers:\n"
                "  - url: /wrong\n"
                "security:\n"
                "  - bearerAuth: []\n"
                "paths: {}\n"
                "components:\n"
                "  securitySchemes:\n"
                "    bearerAuth:\n"
                "      type: apiKey\n"
                "      in: header\n",
                encoding="utf-8",
            )
            auth = yafvsctl.openapi_auth_contract_summary(root)

        self.assertEqual(auth["alignment_status"], "warn")
        self.assertIn("/api/v1", auth["missing_servers"])
        self.assertIn("operatorSession", auth["missing_security_requirements"])
        self.assertIn("operatorSession", auth["missing_security_schemes"])
        mismatches = {(item["scheme"], item["field"]): item for item in auth["security_scheme_mismatches"]}
        self.assertEqual(mismatches[("bearerAuth", "type")]["actual"], "apiKey")
        self.assertIsNone(mismatches[("bearerAuth", "scheme")]["actual"])

    def test_runtime_certbund_report_command_is_rust_direct(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_certbund_report.rs").read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        self.assertNotIn("def command_runtime_certbund_report", source)
        self.assertNotIn('subparsers.add_parser("runtime-certbund-report"', source)
        self.assertIn("command_runtime_certbund_report", rust_source)
        self.assertIn("runtime-certbund-report *args:", justfile)
        self.assertIn('runtime-certbund-report "$@"', justfile)
        self.assertNotIn('tools/yafvsctl runtime-certbund-report "$@"', justfile)
    def test_direct_control_probe_retries_only_control_unavailable(self):
        unavailable = yafvsctl.subprocess.CompletedProcess(
            [],
            0,
            '{"error":{"code":"control_unavailable"}}\n503',
            "",
        )
        not_found = yafvsctl.subprocess.CompletedProcess(
            [],
            0,
            '{"error":{"code":"not_found"}}\n404',
            "",
        )
        with unittest.mock.patch.object(
            yafvsctl,
            "direct_native_api_curl",
            side_effect=[unavailable, not_found],
        ) as request, unittest.mock.patch.object(yafvsctl.time, "sleep") as sleep:
            response, parsed, status, attempts = (
                yafvsctl.direct_native_api_control_probe_with_retry(
                    Path("/repo"),
                    "/api/v1/tasks/00000000-0000-0000-0000-000000000000/stop",
                    token="x" * 32,
                    env={},
                )
            )
        self.assertIs(response, not_found)
        self.assertEqual(parsed, {"error": {"code": "not_found"}})
        self.assertEqual(status, 404)
        self.assertEqual(attempts, 2)
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(0.5)

        forbidden = yafvsctl.subprocess.CompletedProcess(
            [],
            0,
            '{"error":{"code":"forbidden"}}\n403',
            "",
        )
        with unittest.mock.patch.object(
            yafvsctl, "direct_native_api_curl", return_value=forbidden
        ) as request, unittest.mock.patch.object(yafvsctl.time, "sleep") as sleep:
            _response, _parsed, status, attempts = (
                yafvsctl.direct_native_api_control_probe_with_retry(
                    Path("/repo"),
                    "/api/v1/tasks/00000000-0000-0000-0000-000000000000/stop",
                    token="x" * 32,
                    env={},
                )
            )
        self.assertEqual(status, 403)
        self.assertEqual(attempts, 1)
        request.assert_called_once()
        sleep.assert_not_called()

    def test_native_empty_trash_preview_payload_is_complete_counts_only_contract(self):
        items = [
            {"resource_type": resource_type, "count": 0}
            for resource_type in sorted(yafvsctl.NATIVE_EMPTY_TRASH_RESOURCE_TYPES)
        ]
        items[0]["count"] = 3
        payload = {"scope": "operator", "items": items, "total": 3, "snapshot_digest": "a" * 64}
        self.assertEqual(yafvsctl.native_empty_trash_preview_payload(payload), payload)

        incomplete = dict(payload)
        incomplete["items"] = items[:-1]
        self.assertIsNone(yafvsctl.native_empty_trash_preview_payload(incomplete))
        unsafe = dict(payload)
        unsafe["items"] = [dict(item) for item in items]
        unsafe["items"][0]["name"] = "must-not-be-accepted"
        self.assertIsNone(yafvsctl.native_empty_trash_preview_payload(unsafe))

    def test_direct_trash_empty_smoke_uses_isolated_fixture_and_never_empties_preexisting_trash(self):
        operator_uuid = "11111111-1111-4111-8111-111111111111"

        def preview(total):
            items = [
                {"resource_type": resource_type, "count": 0}
                for resource_type in sorted(yafvsctl.NATIVE_EMPTY_TRASH_RESOURCE_TYPES)
            ]
            items[0]["count"] = total
            return {
                "scope": "operator",
                "items": items,
                "total": total,
                "snapshot_digest": "a" * 64,
            }

        calls = []
        previews = iter((preview(0), preview(1), preview(1), preview(0)))

        def fake_direct(_root, path, **kwargs):
            method = kwargs.get("method", "GET")
            calls.append((path, method, kwargs.get("body")))
            if path == yafvsctl.NATIVE_EMPTY_TRASH_PREVIEW_PATH:
                return subprocess.CompletedProcess(["curl"], 0, json.dumps(next(previews)) + "\n200", "")
            if path == "/api/v1/tags":
                return subprocess.CompletedProcess(["curl"], 0, '{"id":"fixture-tag"}\n201', "")
            if path == "/api/v1/tags/fixture-tag":
                return subprocess.CompletedProcess(["curl"], 0, "\n204", "")
            if path == yafvsctl.NATIVE_EMPTY_TRASH_PATH:
                body = json.loads(kwargs["body"])
                if body["expected_total"] == 0:
                    return subprocess.CompletedProcess(["curl"], 0, '{"error":{"code":"conflict"}}\n409', "")
                return subprocess.CompletedProcess(["curl"], 0, '{"scope":"operator","deleted_total":1}\n200', "")
            self.fail(f"unexpected direct call {method} {path}")

        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(yafvsctl, "direct_native_api_curl", side_effect=fake_direct), \
                unittest.mock.patch.object(
                    yafvsctl,
                    "psql",
                    side_effect=[
                        subprocess.CompletedProcess(["psql"], 0, "", ""),
                        subprocess.CompletedProcess(["psql"], 0, "0|0\n", ""),
                    ],
                ), \
                unittest.mock.patch.object(yafvsctl.time, "time", return_value=1):
                findings = yafvsctl.direct_trash_empty_runtime_findings(
                    Path(tmp),
                    token="t" * 64,
                    env={},
                    operator_uuid=operator_uuid,
                )

        self.assertTrue(all(item["status"] == "pass" for item in findings), findings)
        self.assertEqual(
            [(path, method) for path, method, _body in calls if path == yafvsctl.NATIVE_EMPTY_TRASH_PATH],
            [
                (yafvsctl.NATIVE_EMPTY_TRASH_PATH, "POST"),
                (yafvsctl.NATIVE_EMPTY_TRASH_PATH, "POST"),
            ],
        )
        self.assertEqual(
            [json.loads(body)["expected_total"] for path, _method, body in calls if path == yafvsctl.NATIVE_EMPTY_TRASH_PATH],
            [0, 1],
        )

        preexisting_calls = []

        def preexisting_direct(_root, path, **kwargs):
            preexisting_calls.append((path, kwargs.get("method", "GET")))
            if path == yafvsctl.NATIVE_EMPTY_TRASH_PATH:
                self.assertEqual(json.loads(kwargs["body"])["expected_total"], 0)
                return subprocess.CompletedProcess(
                    ["curl"], 0, '{"error":{"code":"conflict"}}\n409', ""
                )
            return subprocess.CompletedProcess(["curl"], 0, json.dumps(preview(2)) + "\n200", "")

        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(yafvsctl, "direct_native_api_curl", side_effect=preexisting_direct), \
                unittest.mock.patch.object(yafvsctl, "psql") as psql:
                skipped = yafvsctl.direct_trash_empty_runtime_findings(
                    Path(tmp),
                    token="t" * 64,
                    env={},
                    operator_uuid=operator_uuid,
                )
        self.assertEqual(
            preexisting_calls,
            [
                (yafvsctl.NATIVE_EMPTY_TRASH_PREVIEW_PATH, "GET"),
                (yafvsctl.NATIVE_EMPTY_TRASH_PATH, "POST"),
                (yafvsctl.NATIVE_EMPTY_TRASH_PREVIEW_PATH, "GET"),
            ],
        )
        psql.assert_not_called()
        self.assertEqual(
            [item["status"] for item in skipped[:-1]],
            ["pass", "pass", "pass"],
        )
        self.assertEqual(skipped[-1]["check"], "native-api-direct.trash-empty-preflight-skipped")
        self.assertEqual(skipped[-1]["status"], "warn")

    def test_native_bulk_modify_schedules_bridge_preserves_controls(self):
        expected = {"status": "pass", "details": {"snapshot_sha256": "a" * 64}}
        with unittest.mock.patch.object(yafvsctl, "rust_result_envelope", return_value=expected) as bridge:
            result = yafvsctl.command_native_bulk_modify_schedules(
                Path("/repo"),
                filter_value="nightly",
                timezone="UTC",
                icalendar_file=Path("/tmp/calendar.ics"),
                max_schedules=1,
                dry_run=True,
                allow_write_control=True,
                confirm_snapshot="a" * 64,
                status_only=True,
            )
        self.assertIs(result, expected)
        bridge.assert_called_once_with(
            Path("/repo"),
            "native-bulk-modify-schedules",
            [
                "native-bulk-modify-schedules",
                "--filter",
                "nightly",
                "--max-schedules",
                "1",
                "--timezone",
                "UTC",
                "--icalendar-file",
                "/tmp/calendar.ics",
                "--dry-run",
                "--allow-write-control",
                "--confirm-snapshot",
                "a" * 64,
                "--status-only",
            ],
        )

    def test_task_target_replace_runtime_cleanup_is_ordered_and_complete(self):
        source = inspect.getsource(yafvsctl.direct_task_target_replace_runtime_findings)
        self.assertIn(
            'task_precondition == f"2|0|{source_target_id}"',
            source,
        )
        self.assertIn(
            '|{scanner_id}|2|0"',
            source,
        )
        self.assertNotIn("deleted_tasks AS", source)
        self.assertIn('"BEGIN; "', source)
        self.assertIn("DELETE FROM tag_resources_trash WHERE resource_type = 'task'", source)
        self.assertIn("DELETE FROM tag_resources_trash WHERE resource_type = 'target'", source)
        self.assertLess(
            source.index("DELETE FROM task_preferences"),
            source.index("DELETE FROM tasks"),
        )
        self.assertLess(
            source.index("DELETE FROM targets_login_data"),
            source.index("DELETE FROM targets WHERE"),
        )
        self.assertLess(
            source.index("DELETE FROM targets_trash_login_data"),
            source.index("DELETE FROM targets_trash WHERE"),
        )


    def test_direct_write_smoke_covers_explicit_email_and_smb_methods_with_residue_cleanup(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count('"method": "EMAIL"'), 4)
        self.assertIn('"method": "SMB"', source)
        self.assertIn("native-api-direct.alert-smb-write-create", source)
        self.assertIn("deleted_method_data", source)

    def test_native_schedule_create_openapi_schema_is_exact(self):
        root = Path(__file__).resolve().parents[2]
        drift = yafvsctl.openapi_schedule_create_schema_contract_drift(root, yafvsctl.openapi_contract_operations(root))
        self.assertEqual(drift["schedule_create_schema_missing"], [])
        self.assertEqual(drift["schedule_create_schema_invalid"], [])

    def test_native_tag_write_openapi_schemas_are_exact(self):
        root = Path(__file__).resolve().parents[2]
        drift = yafvsctl.openapi_tag_write_schema_contract_drift(root)
        self.assertEqual(drift["tag_write_schema_missing"], [])
        self.assertEqual(drift["tag_write_schema_invalid"], [])

    def test_openapi_duplicate_field_paths_are_rejected(self):
        block = [
            "      type: object",
            "      properties:",
            "        resource_type:",
            "          type: string",
            "        resource_type:",
            "          type: string",
        ]
        self.assertEqual(
            yafvsctl.openapi_duplicate_field_paths(block),
            ["properties.resource_type"],
        )

    def test_openapi_tracks_direct_feed_security_information_and_alert_tag_lookup_contracts(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        contract = (root / "docs" / "API_CONTRACT.md").read_text(encoding="utf-8")
        boundary = (root / "docs" / "NATIVE_API_AUTH_BOUNDARY.md").read_text(encoding="utf-8")
        native_tooling = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        operations = {(item["method"], item["path"]): item for item in yafvsctl.openapi_contract_operations(root)}
        alerts = operations[("get", "/alerts")]
        alert_detail = operations[("get", "/alerts/{alert_id}")]
        alert_export = operations[("get", "/alerts/{alert_id}/export")]
        feeds = operations[("get", "/feeds")]
        cves = operations[("get", "/cves")]
        cve_detail = operations[("get", "/cves/{cve_id}")]
        cve_export = operations[("get", "/cves/{cve_id}/export")]
        cpes = operations[("get", "/cpes")]
        cpe_detail = operations[("get", "/cpes/{cpe_id}")]
        cert_bund_advisories = operations[("get", "/cert-bund-advisories")]
        cert_bund_detail = operations[("get", "/cert-bund-advisories/{cert_bund_advisory_id}")]
        dfn_cert_advisories = operations[("get", "/dfn-cert-advisories")]
        dfn_cert_detail = operations[("get", "/dfn-cert-advisories/{dfn_cert_advisory_id}")]
        nvts = operations[("get", "/nvts")]
        nvt_detail = operations[("get", "/nvts/{nvt_id}")]
        nvt_export = operations[("get", "/nvts/{nvt_id}/export")]
        operating_systems = operations[("get", "/operating-systems")]
        operating_system_detail = operations[("get", "/operating-systems/{os_id}")]
        operating_system_export = operations[("get", "/operating-systems/{os_id}/export")]
        hosts = operations[("get", "/hosts")]
        host_detail = operations[("get", "/hosts/{host_id}")]
        host_export = operations[("get", "/hosts/{host_id}/export")]
        tls_certificates = operations[("get", "/tls-certificates")]
        tls_certificate_detail = operations[("get", "/tls-certificates/{certificate_id}")]
        tls_certificate_export = operations[("get", "/tls-certificates/{certificate_id}/export")]
        tls_certificate_pem = operations[("get", "/tls-certificates/{certificate_id}/certificate")]
        scanners = operations[("get", "/scanners")]
        scanner_detail = operations[("get", "/scanners/{scanner_id}")]
        scanner_export = operations[("get", "/scanners/{scanner_id}/export")]
        scan_configs = operations[("get", "/scan-configs")]
        scan_config_detail = operations[("get", "/scan-configs/{scan_config_id}")]
        scan_config_families = operations[("get", "/scan-configs/{scan_config_id}/families")]
        scan_config_family_nvts = operations[("get", "/scan-configs/{scan_config_id}/families/{family}/nvts")]
        tag_resource_names = operations[("get", "/tags/resource-names/{resource_type}")]
        trashcan_summary = operations[("get", "/trashcan/summary")]

        expected_catalog_metadata = [
            (cves, "getCves", "cve-catalog-list-read", None),
            (cve_detail, "getCvesByCveId", "cve-catalog-detail-epss-reference-configuration-read", None),
            (cve_export, "getCvesByCveIdExport", "cve-catalog-metadata-export-read", None),
            (cpes, "getCpes", "cpe-catalog-list-read", None),
            (cpe_detail, "getCpesByCpeId", "cpe-catalog-detail-read", None),
            (cert_bund_advisories, "getCertBundAdvisories", "cert-bund-advisory-list-read", None),
            (cert_bund_detail, "getCertBundAdvisoriesByCertBundAdvisoryId", "cert-bund-advisory-catalog-detail-read", None),
            (dfn_cert_advisories, "getDfnCertAdvisories", "dfn-cert-advisory-list-read", None),
            (dfn_cert_detail, "getDfnCertAdvisoriesByDfnCertAdvisoryId", "dfn-cert-advisory-catalog-detail-read", None),
            (nvts, "getNvts", "nvt-catalog-list-read", None),
            (nvt_detail, "getNvtsByNvtId", "nvt-catalog-detail-read", None),
            (nvt_export, "getNvtsByNvtIdExport", "nvt-catalog-metadata-export-read", None),
        ]
        for operation, operation_id, replaces, inherited_still_owns in expected_catalog_metadata:
            self.assertEqual(operation["operation_id"], operation_id)
            self.assertIn("x-yafvs-direct", operation["x_yafvs_fields"])
            self.assertEqual(operation["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
            self.assertEqual(operation["x_yafvs_values"]["x-yafvs-maturity"], "live-read")
            self.assertEqual(operation["x_yafvs_values"]["x-yafvs-replaces"], replaces)
            self.assertEqual(operation["x_yafvs_values"].get("x-yafvs-inherited-still-owns"), inherited_still_owns)

        for operation in (
            operations[("get", "/filters")],
            operations[("get", "/filters/{filter_id}")],
            operations[("get", "/filters/{filter_id}/export")],
        ):
            self.assertNotIn("x-yafvs-inherited-still-owns", operation["x_yafvs_values"])

        self.assertIn('GSA CVE detail metadata export', native_tooling)
        self.assertIn('GSA NVT detail metadata export', native_tooling)
        self.assertIn('GSA CERT-Bund advisory metadata export', native_tooling)
        self.assertIn('GSA DFN-CERT advisory metadata export', native_tooling)
        self.assertIn('GSA task metadata export', native_tooling)
        self.assertIn('GSA scanner metadata export', native_tooling)

        expected_asset_metadata = [
            (operating_systems, "getOperatingSystems", "operating-system-asset-list-read", None),
            (operating_system_detail, "getOperatingSystemsByOsId", "operating-system-asset-detail-info-read", None),
            (operating_system_export, "getOperatingSystemsByOsIdExport", "operating-system-asset-metadata-export-read", None),
            (hosts, "getHosts", "host-asset-list-read", None),
            (host_detail, "getHostsByHostId", "host-asset-detail-info-read", None),
            (host_export, "getHostsByHostIdExport", "host-asset-metadata-export-read", None),
            (tls_certificates, "getTlsCertificates", "tls-certificate-asset-list-read", None),
            (tls_certificate_detail, "getTlsCertificatesByCertificateId", "tls-certificate-asset-detail-info-read", None),
            (tls_certificate_export, "getTlsCertificatesByCertificateIdExport", "tls-certificate-asset-metadata-export-read", None),
            (tls_certificate_pem, "getTlsCertificatesByCertificateIdCertificate", "tls-certificate-pem-download-read", None),
            (scanners, "getScanners", "scanner-metadata-list-read", None),
            (scanner_detail, "getScannersByScannerId", "scanner-metadata-detail-info-tags-and-task-backlink-read", None),
            (scanner_export, "getScannersByScannerIdExport", "scanner-metadata-export-read", None),
            (scan_configs, "getScanConfigs", "scan-config-metadata-list-read", None),
            (scan_config_detail, "getScanConfigsByScanConfigId", "scan-config-detail-info-tags-task-backlinks-and-preferences-read", None),
            (scan_config_families, "getScanConfigsByScanConfigIdFamilies", "scan-config-family-summary-read", None),
            (scan_config_family_nvts, "getScanConfigsByScanConfigIdFamiliesByFamilyNvts", "scan-config-family-nvt-selection-read", None),
        ]
        for operation, operation_id, replaces, inherited_still_owns in expected_asset_metadata:
            self.assertEqual(operation["operation_id"], operation_id)
            self.assertIn("x-yafvs-direct", operation["x_yafvs_fields"])
            self.assertEqual(operation["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
            self.assertEqual(operation["x_yafvs_values"]["x-yafvs-maturity"], "live-read")
            self.assertEqual(operation["x_yafvs_values"]["x-yafvs-replaces"], replaces)
            self.assertEqual(operation["x_yafvs_values"].get("x-yafvs-inherited-still-owns"), inherited_still_owns)

        self.assertEqual(alerts["operation_id"], "getAlerts")
        self.assertIn("x-yafvs-direct", alerts["x_yafvs_fields"])
        self.assertEqual(alerts["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
        self.assertEqual(alerts["x_yafvs_values"]["x-yafvs-maturity"], "live-read")
        self.assertEqual(alerts["x_yafvs_values"]["x-yafvs-replaces"], "alert-metadata-list-read")
        self.assertNotIn("x-yafvs-inherited-still-owns", alerts["x_yafvs_values"])
        self.assertEqual(alert_detail["operation_id"], "getAlertsByAlertId")
        self.assertIn("x-yafvs-direct", alert_detail["x_yafvs_fields"])
        self.assertEqual(alert_detail["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
        self.assertEqual(alert_detail["x_yafvs_values"]["x-yafvs-maturity"], "live-read")
        self.assertEqual(alert_detail["x_yafvs_values"]["x-yafvs-replaces"], "alert-metadata-detail-read")
        self.assertNotIn("x-yafvs-inherited-still-owns", alert_detail["x_yafvs_values"])
        self.assertEqual(alert_detail["responses"]["404"], "#/components/responses/NotFound")
        self.assertEqual(alert_export["operation_id"], "getAlertsByAlertIdExport")
        self.assertIn("x-yafvs-direct", alert_export["x_yafvs_fields"])
        self.assertEqual(alert_export["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
        self.assertEqual(alert_export["x_yafvs_values"]["x-yafvs-maturity"], "live-read")
        self.assertEqual(alert_export["x_yafvs_values"]["x-yafvs-replaces"], "alert-metadata-export-read")
        self.assertNotIn("x-yafvs-inherited-still-owns", alert_export["x_yafvs_values"])
        self.assertEqual(alert_export["responses"]["404"], "#/components/responses/NotFound")
        self.assertEqual(feeds["operation_id"], "getFeeds")
        self.assertIn("x-yafvs-direct", feeds["x_yafvs_fields"])
        self.assertEqual(feeds["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
        self.assertEqual(feeds["x_yafvs_values"]["x-yafvs-maturity"], "live-read")
        self.assertEqual(feeds["x_yafvs_values"]["x-yafvs-replaces"], "feed-status-read")
        self.assertEqual(feeds["x_yafvs_values"]["x-yafvs-inherited-still-owns"], "feed-sync-import-control")
        self.assertEqual(feeds["responses"]["400"], "#/components/responses/BadRequest")
        self.assertEqual(tag_resource_names["operation_id"], "getTagsResourceNamesByResourceType")
        self.assertIn("x-yafvs-direct", tag_resource_names["x_yafvs_fields"])
        self.assertEqual(tag_resource_names["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
        self.assertEqual(tag_resource_names["x_yafvs_values"]["x-yafvs-maturity"], "live-read")
        self.assertEqual(tag_resource_names["x_yafvs_values"]["x-yafvs-replaces"], "tag-resource-name-read")
        self.assertNotIn("x-yafvs-inherited-still-owns", tag_resource_names["x_yafvs_values"])
        self.assertEqual(tag_resource_names["responses"]["404"], "#/components/responses/NotFound")
        self.assertEqual(trashcan_summary["operation_id"], "getTrashcanSummary")
        self.assertIn("x-yafvs-direct", trashcan_summary["x_yafvs_fields"])
        self.assertEqual(trashcan_summary["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
        self.assertEqual(trashcan_summary["x_yafvs_values"]["x-yafvs-maturity"], "live-read")
        self.assertEqual(trashcan_summary["x_yafvs_values"]["x-yafvs-replaces"], "trashcan-count-summary-read")
    def test_openapi_tracks_raw_report_contracts(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        route_source = (root / "services" / "yafvs-api" / "src" / "read_api_routes.rs").read_text(encoding="utf-8")
        report_source = (root / "services" / "yafvs-api" / "src" / "report_payloads.rs").read_text(encoding="utf-8")
        smoke = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_native_api_smoke.rs").read_text(encoding="utf-8")
        self.assertIn("/reports:", openapi)
        self.assertIn("/reports/{report_id}:", openapi)
        self.assertIn("/reports/{report_id}/results:", openapi)
        self.assertIn("/reports/{report_id}/ports:", openapi)
        self.assertIn("description_excerpt", openapi)
        self.assertIn("nvt_family", openapi)
        self.assertIn("count(DISTINCT nullif(res.nvt, '')) FILTER (WHERE coalesce(res.severity, 0) != -3.0)", report_source)
        self.assertIn("ReportReference", openapi)
        self.assertIn("ReportSeverityCounts", openapi)
        self.assertIn("route(\"/api/v1/reports\", get(reports))", route_source)
        self.assertIn("route(\"/api/v1/reports/:report_id\", get(report_detail))", route_source)
        self.assertIn("route(\"/api/v1/reports/:report_id/results\", get(report_results))", route_source)
        self.assertIn("route(\"/api/v1/reports/:report_id/ports\", get(report_ports))", route_source)
        self.assertIn("native-api.raw-reports", smoke)
        self.assertIn("native-api.raw-report-detail", smoke)
        self.assertIn("native-api.raw-report-results", smoke)
        self.assertIn("native-api.raw-report-ports", smoke)

    def test_openapi_tracks_scope_report_retention_preview(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        route_source = (root / "services" / "yafvs-api" / "src" / "read_api_routes.rs").read_text(encoding="utf-8")
        handler_source = (root / "services" / "yafvs-api" / "src" / "scope_report_retention.rs").read_text(encoding="utf-8")
        smoke = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_native_api_smoke.rs").read_text(encoding="utf-8")
        self.assertIn("/scopes/{scope_id}/reports/{scope_report_id}/retention-plan:", openapi)
        operations = {(item["method"], item["path"]): item for item in yafvsctl.openapi_contract_operations(root)}
        retention = operations[("get", "/scopes/{scope_id}/reports/{scope_report_id}/retention-plan")]
        self.assertEqual(retention["x_yafvs_values"]["x-yafvs-exposure"], "direct-read")
        self.assertEqual(retention["x_yafvs_values"]["x-yafvs-maturity"], "preview-read")
        self.assertEqual(retention["x_yafvs_values"]["x-yafvs-replaces"], "none")
        self.assertEqual(retention["x_yafvs_values"]["x-yafvs-inherited-still-owns"], "retention-mutations")
        self.assertIn("x-yafvs-direct", retention["x_yafvs_fields"])
        self.assertIn("ScopeReportRetentionPlan", openapi)
        self.assertIn("detail_compacted", openapi)
        self.assertIn("aggregate_only", openapi)
        self.assertIn("future_tiered_retention_candidate", openapi)
        self.assertIn("scope_report_retention_plan", route_source)
        self.assertIn("destructive_actions: false", handler_source)
        self.assertIn("/api/v1/scopes/:scope_id/reports/:scope_report_id/retention-plan", route_source)
        self.assertIn("native-api.scope-report-retention-plan", smoke)

    def test_scope_report_retention_source_sql_preserves_source_identity_contract(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "services" / "yafvs-api" / "src" / "scope_report_retention.rs").read_text(encoding="utf-8")
        start = "fn scope_report_retention_sources_sql() -> &'static str {"
        self.assertIn(start, source)
        body = source.split(start, 1)[1]
        upper_body = body.upper()

        self.assertIn("SELECT DISTINCT ON (task.target)", body)
        self.assertIn("ORDER BY task.target, coalesce(reports.end_time, reports.creation_time) DESC, reports.id DESC", body)
        self.assertIn("SELECT srs.source_report, srs.source_report_uuid, srs.target,", body)
        self.assertIn("LEFT JOIN latest_completed lc ON lc.target = srs.target", body)
        self.assertIn("(lc.source_report = srs.source_report) AS kept_as_latest", body)
        self.assertIn("WHERE srs.scope_report = $1", body)
        self.assertIn("SELECT sr.source_report_uuid::text", body)
        self.assertIn("LEFT JOIN results res ON res.report = sr.source_report", body)
        self.assertIn("GROUP BY sr.source_report_uuid", body)
        self.assertIn("coalesce(sr.kept_as_latest, false) AS kept_as_latest", body)
        self.assertIn("ORDER BY target_name ASC, sr.target_uuid ASC, scan_end DESC, sr.source_report_uuid ASC", body)
        self.assertLess(body.index("SELECT srs.source_report, srs.source_report_uuid, srs.target,"), body.index("SELECT sr.source_report_uuid::text"))
        for forbidden in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            self.assertNotIn(forbidden, upper_body)

    def test_openapi_tracks_scope_read_contracts(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        source = (root / "services" / "yafvs-api" / "src" / "read_api_routes.rs").read_text(encoding="utf-8")
        smoke = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_native_api_smoke.rs").read_text(encoding="utf-8")
        native_client = (root / "components" / "gsa" / "src" / "gmp" / "native-api" / "scopes.ts").read_text(encoding="utf-8")
        scope_list = (root / "components" / "gsa" / "src" / "web" / "pages" / "scopes" / "ScopeListPage.tsx").read_text(encoding="utf-8")
        scope_details = (root / "components" / "gsa" / "src" / "web" / "pages" / "scopes" / "ScopeDetailsPage.tsx").read_text(encoding="utf-8")
        self.assertIn("/scopes:", openapi)
        self.assertIn("/scopes/{scope_id}:", openapi)
        self.assertIn("/scope-reports/{scope_report_id}:", openapi)
        self.assertNotIn("/scopes/{scope_id}/reports/{scope_report_id}:", openapi)
        self.assertIn("ScopeCandidateHost", openapi)
        self.assertIn("ScopeReportReference", openapi)
        self.assertIn("route(\"/api/v1/scopes\", get(scopes))", source)
        self.assertIn("route(\"/api/v1/scopes/:scope_id\", get(scope_detail))", source)
        self.assertIn("/api/v1/scope-reports/:scope_report_id", source)
        self.assertNotIn("/api/v1/scopes/:scope_id/reports/:scope_report_id\", get(scope_report_detail)", source)
        self.assertIn("native-api.scopes", smoke)
        self.assertIn("native-api.scope-detail", smoke)
        self.assertIn("fetchNativeScopes", native_client)
        self.assertIn("fetchNativeScope", native_client)
        self.assertIn("api/v1/scopes", native_client)
        self.assertIn("fetchNativeScopes(gmp)", scope_list)
        self.assertIn("fetchNativeScope(gmp, id)", scope_details)

    def test_native_tooling_category_keeps_scripts_and_docs_distinct(self):
        self.assertEqual(yafvsctl.native_tooling_category("tools/runtime_scope.py")[0], "required_runtime")
        self.assertEqual(yafvsctl.native_tooling_category("tools/yafvsctl")[0], "compatibility_bridge")
        self.assertEqual(
            yafvsctl.native_tooling_category("tools/yafvsctl-rs/src/commands/gvmd_retirement.rs")[0],
            "compatibility_bridge",
        )
        self.assertEqual(yafvsctl.native_tooling_category("tools/runtime_browser_smoke.py")[0], "compatibility_bridge")
        self.assertEqual(yafvsctl.native_tooling_category("tools/tests/test_yafvsctl.py")[0], "compatibility_bridge")
        self.assertEqual(yafvsctl.native_tooling_category("components/gsa/src/gmp/commands/scopes.ts")[0], "product_workflow")
        self.assertEqual(yafvsctl.native_tooling_category("components/gsa/src/gmp/commands/overrides.js")[0], "compatibility_bridge")
        self.assertEqual(yafvsctl.native_tooling_category("components/gsa/src/gmp/commands/entity.ts")[0], "compatibility_bridge")
        self.assertEqual(yafvsctl.native_tooling_category("components/gsa/src/gmp/locale/date.ts")[0], "compatibility_bridge")
        self.assertEqual(yafvsctl.native_tooling_category("components/gsa/src/gmp/http/transform/xml.ts")[0], "compatibility_bridge")
        self.assertEqual(yafvsctl.native_tooling_category("components/gsa/src/gmp/commands/__tests__/scanner.test.ts")[0], "compatibility_bridge")
        self.assertEqual(yafvsctl.native_tooling_category("components/gsa/src/gmp/__tests__/gmp.test.ts")[0], "compatibility_bridge")
        self.assertIsNone(yafvsctl.native_tooling_category("components/gsa/src/gmp/native-api/tags.ts"))
        self.assertFalse(yafvsctl.native_tooling_scan_candidate("components/gsa/src/gmp/native-api/tags.ts"))
        self.assertIsNone(yafvsctl.native_tooling_category("components/gvm-tools/scripts/list-scopes.gmp.py"))
        self.assertFalse(yafvsctl.native_tooling_scan_candidate("components/gvm-tools/scripts/list-scopes.gmp.py"))
        self.assertFalse((Path(__file__).resolve().parents[2] / "components/gvm-tools/scripts/generate-scope-report.gmp.py").exists())
        self.assertFalse((Path(__file__).resolve().parents[2] / "components/gvm-tools/scripts/empty-trash.gmp.py").exists())
        self.assertFalse((Path(__file__).resolve().parents[2] / "components/gvm-tools/scripts/export-pdf-report.gmp.py").exists())
        self.assertEqual(yafvsctl.native_tooling_category("docs/GMP_XML_STRANGLER.md")[0], "compatibility_bridge")

    def test_native_override_inventory_tracks_retained_native_contract(self):
        root = Path(__file__).resolve().parents[2]
        summary = yafvsctl.summarize_native_tooling([], root)
        rows = {
            (item.get("method", "get"), item["endpoint"]): item
            for item in summary["implemented_native_endpoints"]
            if "override" in item["endpoint"]
        }
        expected = {
            ("post", "/api/v1/overrides"),
            ("get", "/api/v1/overrides"),
            ("get", "/api/v1/overrides/{override_id}"),
            ("patch", "/api/v1/overrides/{override_id}"),
            ("delete", "/api/v1/overrides/{override_id}"),
            ("post", "/api/v1/overrides/{override_id}/clone"),
            ("post", "/api/v1/overrides/{override_id}/restore"),
            ("delete", "/api/v1/overrides/{override_id}/trash"),
            ("get", "/api/v1/overrides/{override_id}/export"),
        }
        self.assertEqual(set(rows), expected)
        for key, row in rows.items():
            with self.subTest(operation=key):
                self.assertEqual(row["status"], "implemented_internal_and_browser_proxied" if key[0] != "get" or not key[1].endswith("/export") else "implemented_internal_browser_proxied_and_scriptable_read")
                self.assertNotIn("residual_inherited", row)
                if key[0] != "get":
                    self.assertEqual(
                        yafvsctl.native_browser_proxy_operation_status(root, *key),
                        "implemented_internal_and_browser_proxied",
                    )
        export = rows[("get", "/api/v1/overrides/{override_id}/export")]
        self.assertIn("XML metadata export, aggregate dashboards, and filtered detail result expansion are intentionally not retained.", export["notes"])
        for operation in yafvsctl.openapi_contract_operations(root):
            if operation["path"].startswith("/overrides"):
                self.assertNotIn("x-yafvs-inherited-still-owns", operation["x_yafvs_values"])

    def test_native_schedule_csv_script_is_absent_after_native_retirement(self):
        root = Path(__file__).resolve().parents[2]
        self.assertFalse((root / "components/gvm-tools/scripts/create-schedules-from-csv.gmp.py").exists())

    def test_native_tooling_candidate_removal_review_splits_safety_buckets(self):
        review = yafvsctl.native_tooling_removal_review(
            [
                "components/gvm-tools/scripts/unclassified.gmp.py",
            ]
        )

        self.assertEqual(review["safe_removal_count"], 0)
        self.assertEqual(review["blocked_or_review_count"], 1)
        buckets = review["buckets"]
        self.assertEqual(buckets["needs_review"]["count"], 1)
        self.assertNotIn("write_or_mutation", buckets)

    def test_native_tooling_removal_review_counts_product_scripts_toward_full_removal(self):
        summary = yafvsctl.summarize_native_tooling(
            [
                {
                    "category": "product_workflow",
                    "path": "components/gvm-tools/scripts/retained-side-effect.gmp.py",
                    "markers": ["gmp."],
                }
            ]
        )

        review = summary["candidate_for_removal_review"]
        self.assertEqual(review["total"], 1)
        self.assertEqual(review["tracked_removed_count"], 25)
        self.assertEqual(review["buckets"]["needs_review"]["count"], 1)

    def test_native_pdf_export_script_leaves_no_candidate_accounting(self):
        root = Path(__file__).resolve().parents[2]
        candidates = set().union(*yafvsctl.NATIVE_TOOLING_GVM_TOOLS_REMOVAL_BUCKETS.values())
        self.assertNotIn("export-pdf-report.gmp.py", candidates)
        self.assertNotIn("export-pdf-report.gmp.py", yafvsctl.NATIVE_TOOLING_GVM_TOOLS_PATH_BLOCKERS)
        self.assertFalse((root / "components/gvm-tools/scripts/export-pdf-report.gmp.py").exists())
        result = yafvsctl.command_native_tooling_state(root, status_only=True)
        review = result["details"]["candidate_for_removal_review"]
        self.assertEqual(review["total"], 0)
        self.assertEqual(review["tracked_baseline_count"], 26)
        self.assertEqual(review["tracked_removed_count"], 26)

    def test_native_empty_trash_script_is_not_remaining_replacement_candidate(self):
        candidates = set().union(*yafvsctl.NATIVE_TOOLING_GVM_TOOLS_REMOVAL_BUCKETS.values())
        name = "empty-trash.gmp.py"
        self.assertNotIn(name, candidates)
        self.assertNotIn(name, yafvsctl.NATIVE_TOOLING_GVM_TOOLS_PATH_BLOCKERS)
        self.assertFalse(
            (Path(__file__).resolve().parents[2] / "components" / "gvm-tools" / "scripts" / name).exists()
        )

    def test_native_override_delete_script_is_not_remaining_replacement_candidate(self):
        candidates = set().union(*yafvsctl.NATIVE_TOOLING_GVM_TOOLS_REMOVAL_BUCKETS.values())
        name = "delete-overrides-by-filter.gmp.py"
        self.assertNotIn(name, candidates)
        self.assertNotIn(name, yafvsctl.NATIVE_TOOLING_GVM_TOOLS_PATH_BLOCKERS)
        self.assertFalse(
            (Path(__file__).resolve().parents[2] / "components" / "gvm-tools" / "scripts" / name).exists()
        )

    def test_retired_schedule_credential_alert_import_and_cert_config_scripts_leave_no_candidate_accounting(self):
        root = Path(__file__).resolve().parents[2]
        candidates = set().union(*yafvsctl.NATIVE_TOOLING_GVM_TOOLS_REMOVAL_BUCKETS.values())
        for name in ("bulk-modify-schedules.gmp.py", "cfg-gen-for-certs.gmp.py", "create-schedules-from-csv.gmp.py", "create-credentials-from-csv.gmp.py", "create-alerts-from-csv.gmp.py", "send-schedules.gmp.py"):
            self.assertNotIn(name, candidates)
            self.assertNotIn(name, yafvsctl.NATIVE_TOOLING_GVM_TOOLS_PATH_BLOCKERS)
            self.assertFalse((root / "components" / "gvm-tools" / "scripts" / name).exists())
            self.assertFalse((root / "components" / "gvm-tools" / "scripts" / name).exists())

    def test_gos_monthly_report_scripts_are_not_remaining_replacement_candidates(self):
        candidates = set().union(*yafvsctl.NATIVE_TOOLING_GVM_TOOLS_REMOVAL_BUCKETS.values())
        for name in (
            "monthly-report-gos3.gmp.py",
            "monthly-report-gos4.gmp.py",
            "monthly-report-gos24.10.gmp.py",
        ):
            self.assertNotIn(name, candidates)
            self.assertNotIn(name, yafvsctl.NATIVE_TOOLING_GVM_TOOLS_PATH_BLOCKERS)

    def test_native_tooling_residue_classifies_remaining_product_workflow(self):
        self.assertEqual(yafvsctl.native_tooling_residue("components/gsa/src/gmp/commands/alert.ts", "product_workflow")[0], "alert-delivery-and-credentials")
        self.assertIsNone(yafvsctl.native_tooling_category("components/gsa/src/gmp/native-api/task-command.ts"))
        self.assertEqual(yafvsctl.native_tooling_residue("components/gsa/src/gmp/collection/parser.ts", "product_workflow")[0], "compatibility-parser-model-or-test")
        self.assertIsNone(yafvsctl.native_tooling_residue("components/python-gvm/gvm/__init__.py", "compatibility_bridge"))

    def test_trashcan_contract_exposes_redacted_items_only(self):
        root = Path(__file__).resolve().parents[2]
        contract = (root / "docs" / "API_CONTRACT.md").read_text(encoding="utf-8")
        strangler = (root / "docs" / "GMP_XML_STRANGLER.md").read_text(encoding="utf-8")
        plan = (root / "docs" / "NATIVE_API_PROOF_PLAN.md").read_text(encoding="utf-8")
        native_tooling = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_smoke = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_native_api_smoke.rs").read_text(encoding="utf-8")
        browser_smoke = (root / "tools" / "runtime_browser_smoke.py").read_text(encoding="utf-8")
        docs = "\n".join([contract, strangler, plan])

        self.assertIn("/api/v1/trashcan/summary", docs)
        self.assertIn("redacted row inventory", docs)
        self.assertRegex(contract, r"intentionally excludes credential\s+secrets,\s+target\s+hosts")
        self.assertIn("generic GSA/gsad GMP restore bridge is removed", docs)
        self.assertIn("raw gvmd/GMP `RESTORE` parser", docs)
        self.assertIn("alert method data", docs)
        self.assertIn("/api/v1/trashcan/summary", native_tooling)
        self.assertIn("/api/v1/trashcan/items", native_tooling)
        self.assertIn("trashcan-redacted-row-metadata-read", native_tooling)
        self.assertIn("native-api.trashcan-summary", rust_smoke)
        self.assertIn("trashcan.items-native-api", browser_smoke)
        for forbidden in (
            "/api/v1/trashcan/credentials",
            "/api/v1/trashcan/targets",
            "/api/v1/trashcan/scanners",
        ):
            self.assertNotIn(forbidden, docs)

    def test_openapi_tracks_scope_report_evidence_contracts(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        plan = (root / "docs" / "NATIVE_API_PROOF_PLAN.md").read_text(encoding="utf-8")
        for suffix, schema in [
            ("ports", "PortCollection"),
            ("applications", "ApplicationCollection"),
            ("operating-systems", "OperatingSystemCollection"),
            ("tls-certificates", "TlsCertificateCollection"),
        ]:
            path = f"/scopes/{{scope_id}}/reports/{{scope_report_id}}/{suffix}"
            self.assertIn(path, openapi)
            self.assertIn(schema, openapi)
        for suffix in ("applications", "operating-systems", "tls-certificates"):
            self.assertIn(f"/scopes/{{scope_id}}/reports/{{scope_report_id}}/{suffix}", plan)
        self.assertIn("Completed Evidence Contracts", plan)
        self.assertIn("live internal endpoints", plan)
        self.assertIn("Browser-proxied coverage is noted below", plan)
        self.assertIn("complete native browser coverage for current scope-report evidence", plan)
        self.assertNotIn("not live endpoint promises yet", plan)

    def test_operating_system_asset_detail_contract_is_internal_and_parameterized(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        route_source = (root / "services" / "yafvs-api" / "src" / "read_api_routes.rs").read_text(encoding="utf-8")
        api_source = (root / "services" / "yafvs-api" / "src" / "operating_systems.rs").read_text(encoding="utf-8")
        query_source = (root / "services" / "yafvs-api" / "src" / "operating_system_query_sql.rs").read_text(encoding="utf-8")
        native_tooling = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_smoke = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_native_api_smoke.rs").read_text(encoding="utf-8")

        self.assertIn('/api/v1/operating-systems/:os_id', route_source)
        self.assertIn('/api/v1/operating-systems/:os_id/export', route_source)
        self.assertIn('parse_uuid(&os_id)?;', api_source)
        self.assertIn('WHERE oss.uuid = $1', query_source)
        self.assertIn('/operating-systems/{os_id}:', openapi)
        self.assertIn('/operating-systems/{os_id}/export:', openapi)
        self.assertIn("#/components/parameters/OperatingSystemId", openapi)
        self.assertIn('/api/v1/operating-systems/{os_id}', native_tooling)
        self.assertIn('/api/v1/operating-systems/{os_id}/export', native_tooling)
        self.assertIn('"status": "implemented_internal_and_browser_proxied"', native_tooling)
        self.assertIn('native-api.operating-system-detail', rust_smoke)

    def test_host_asset_detail_contract_is_internal_bounded_and_safe_metadata_only(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        route_source = (root / "services" / "yafvs-api" / "src" / "read_api_routes.rs").read_text(encoding="utf-8")
        api_source = (root / "services" / "yafvs-api" / "src" / "host_assets.rs").read_text(encoding="utf-8")
        query_source = (root / "services" / "yafvs-api" / "src" / "host_asset_query_sql.rs").read_text(encoding="utf-8")
        native_tooling = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_smoke = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_native_api_smoke.rs").read_text(encoding="utf-8")

        self.assertIn('/api/v1/hosts/:host_id', route_source)
        self.assertIn('/api/v1/hosts/:host_id/export', route_source)
        self.assertIn('parse_uuid(&host_id)?;', api_source)
        self.assertIn('WHERE h.uuid = $1', api_source)
        self.assertIn("JOIN host_identifiers hi ON hi.host = h.id", query_source)
        self.assertIn("AND hi.name IN ('ip', 'hostname', 'DNS-via-TargetDefinition', 'MAC', 'OS')", query_source)
        self.assertIn("JOIN host_oss ho ON ho.host = h.id", query_source)
        self.assertIn("JOIN oss ON oss.id = ho.os", query_source)
        self.assertIn("AND hd.name IN ('best_os_cpe', 'best_os_txt', 'traceroute')", query_source)
        self.assertIn("left(coalesce(hi.source_data, ''), 512)", query_source)
        self.assertIn("left(coalesce(hd.value, ''), 4096)", query_source)
        self.assertIn('/hosts/{host_id}:', openapi)
        self.assertIn('/hosts/{host_id}/export:', openapi)
        self.assertIn("#/components/parameters/HostId", openapi)
        self.assertIn('HostAssetDetail', openapi)
        self.assertIn('HostAssetOperatingSystem', openapi)
        self.assertIn('HostAssetDetailMetadata', openapi)
        self.assertIn('/api/v1/hosts/{host_id}', native_tooling)
        self.assertIn('/api/v1/hosts/{host_id}/export', native_tooling)
        self.assertIn('GSA top-level Host metadata export', native_tooling)
        self.assertIn('native-api.host-detail', rust_smoke)

    def test_tls_certificate_asset_detail_contract_is_internal_and_source_only(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        route_source = (root / "services" / "yafvs-api" / "src" / "read_api_routes.rs").read_text(encoding="utf-8")
        tls_source = (root / "services" / "yafvs-api" / "src" / "tls_certificates.rs").read_text(encoding="utf-8")
        tls_query_source = (root / "services" / "yafvs-api" / "src" / "tls_certificate_query_sql.rs").read_text(encoding="utf-8")
        tls_payload_source = (root / "services" / "yafvs-api" / "src" / "tls_certificate_payloads.rs").read_text(encoding="utf-8")
        native_tooling = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_smoke = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_native_api_smoke.rs").read_text(encoding="utf-8")
        tls_detail_source = tls_source.split("async fn tls_certificate_asset_detail", 1)[1].split("fn tls_certificate_sources", 1)[0]

        self.assertIn('/api/v1/tls-certificates/:certificate_id', route_source)
        self.assertIn('/api/v1/tls-certificates/:certificate_id/export', route_source)
        self.assertIn('parse_uuid(&certificate_id)?;', tls_detail_source)
        self.assertIn('WHERE c.uuid = $1', tls_query_source)
        self.assertIn('JOIN tls_certificate_sources src ON src.tls_certificate = c.id', tls_query_source)
        self.assertIn('TlsCertificateSourceItem', tls_payload_source)
        self.assertNotIn('c.certificate', tls_detail_source)
        self.assertIn('/tls-certificates/{certificate_id}:', openapi)
        self.assertIn('/tls-certificates/{certificate_id}/export:', openapi)
        self.assertIn('/tls-certificates/{certificate_id}/certificate:', openapi)
        self.assertIn("#/components/parameters/TlsCertificateId", openapi)
        self.assertIn('TlsCertificateAssetDetail', openapi)
        self.assertIn('TlsCertificatePem', openapi)
        self.assertIn('TlsCertificateSourceLocation', openapi)
        self.assertIn('/api/v1/tls-certificates/{certificate_id}', native_tooling)
        self.assertIn('/api/v1/tls-certificates/{certificate_id}/export', native_tooling)
        self.assertIn('/api/v1/tls-certificates/{certificate_id}/certificate', native_tooling)
        self.assertIn('GSA top-level TLS Certificate metadata export', native_tooling)
        self.assertIn('GSA top-level TLS Certificate PEM download', native_tooling)
        self.assertIn('native-api.tls-certificate-detail', rust_smoke)

    def test_scanner_asset_detail_contract_is_internal_metadata_only(self):
        root = Path(__file__).resolve().parents[2]
        openapi = (root / "api" / "openapi" / "yafvs-v1.yaml").read_text(encoding="utf-8")
        route_source = (root / "services" / "yafvs-api" / "src" / "read_api_routes.rs").read_text(encoding="utf-8")
        api_source = (root / "services" / "yafvs-api" / "src" / "scanner_assets.rs").read_text(encoding="utf-8")
        query_source = (root / "services" / "yafvs-api" / "src" / "scanner_asset_query_sql.rs").read_text(encoding="utf-8")
        native_tooling = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_smoke = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_native_api_smoke.rs").read_text(encoding="utf-8")
        scanner_detail_source = api_source.split("async fn scanner_asset_detail", 1)[1].split("fn scanner_task_references_sql", 1)[0]

        self.assertIn('/api/v1/scanners/:scanner_id', route_source)
        self.assertIn('/api/v1/scanners/:scanner_id/export', route_source)
        self.assertIn('let scanner_id = parse_uuid(&scanner_id)?.to_string();', scanner_detail_source)
        self.assertIn('WHERE s.uuid = $1', query_source)
        self.assertIn('LEFT JOIN credentials c ON c.id = s.credential', query_source)
        self.assertIn('nullif(c.uuid, \'\') AS credential_id', query_source)
        self.assertIn('nullif(c.name, \'\') AS credential_name', query_source)
        self.assertIn('scanner_task_references(&client, &scanner_id)', scanner_detail_source)
        self.assertIn('scanner_user_tags(&client, &scanner_id)', scanner_detail_source)
        self.assertNotIn('ca_pub', scanner_detail_source)
        self.assertNotIn('credential_value', scanner_detail_source)
        self.assertNotIn('password', scanner_detail_source)
        self.assertNotIn('private_key', scanner_detail_source)
        self.assertNotIn('certificate_info', scanner_detail_source)
        self.assertIn('/scanners/{scanner_id}:', openapi)
        self.assertIn('/scanners/{scanner_id}/export:', openapi)
        self.assertIn("#/components/parameters/ScannerId", openapi)
        self.assertIn('ScannerAssetDetail', openapi)
        self.assertIn('ScannerTaskReference', openapi)
        self.assertIn('/api/v1/scanners/{scanner_id}', native_tooling)
        self.assertIn('/api/v1/scanners/{scanner_id}/export', native_tooling)
        self.assertIn('native-api.scanner-detail', rust_smoke)

    def test_quality_gate_systemd_templates_are_present(self):
        root = Path(__file__).resolve().parents[2]
        service = root / "ops" / "systemd" / "yafvs-quality-gate.service.in"
        timer = root / "ops" / "systemd" / "yafvs-quality-gate.timer.in"
        service_text = service.read_text(encoding="utf-8")
        self.assertIn("SPDX-License-Identifier", service_text)
        self.assertIn("tools/yafvsctl quality-gate --json", service_text)
        self.assertNotIn("YAFVS_RUNTIME_DIR", service_text)
        self.assertIn("OnCalendar=*-*-* 03:30:00", timer.read_text(encoding="utf-8"))

    def test_github_quality_gate_workflow_is_source_only(self):
        root = Path(__file__).resolve().parents[2]
        workflow = root / ".github" / "workflows" / "quality-gate.yml"
        self.assertTrue(workflow.is_file())
        text = workflow.read_text(encoding="utf-8")
        required = [
            "SPDX-License-Identifier: GPL-3.0-or-later",
            "push:",
            "pull_request:",
            "workflow_dispatch:",
            "permissions:",
            "contents: read",
            "actions/checkout@v5",
            "actions/setup-python@v6",
            "actions/setup-node@v5",
            "ubuntu-24.04",
            "fetch-depth: 0",
            "python-version: \"3.12\"",
            "node-version: \"22\"",
            "npm install --global npm@11.16.0",
            "rustup toolchain install stable --profile minimal",
            "cache-dependency-path: components/gsa/package-lock.json",
            "npm ci",
            "YAFVS_RUNTIME_DIR=\"$RUNNER_TEMP/yafvs-runtime\"",
            "tools/yafvsctl quality-gate --json",
            "actions/upload-artifact@v7",
        ]
        for needle in required:
            self.assertIn(needle, text)
        forbidden = [
            "runtime-full-test-scan-start",
            "feed-cache-sync",
            "feed-copy-to-runtime",
            "feed-generation-stage",
            "docker compose up",
            "license-public-release-gate",
            "pull_request_target",
        ]
        for needle in forbidden:
            self.assertNotIn(needle, text)

    def test_github_codeql_workflow_is_least_privilege_source_only(self):
        root = Path(__file__).resolve().parents[2]
        workflow = root / ".github" / "workflows" / "codeql.yml"
        self.assertTrue(workflow.is_file())
        text = workflow.read_text(encoding="utf-8")
        required = [
            "SPDX-License-Identifier: GPL-3.0-or-later",
            "push:",
            "pull_request:",
            "schedule:",
            "workflow_dispatch:",
            "actions: read",
            "contents: read",
            "security-events: write",
            "actions/checkout@v5",
            "persist-credentials: false",
            "github/codeql-action/init@v4",
            "github/codeql-action/analyze@v4",
            "queries: security-extended",
            "- actions",
            "- javascript-typescript",
            "- python",
            "- c-cpp",
            "- rust",
            "build-mode: none",
        ]
        for needle in required:
            self.assertIn(needle, text)
        forbidden = [
            "pull_request_target",
            "secrets.",
            "runtime-full-test-scan-start",
            "feed-cache-sync",
            "feed-copy-to-runtime",
            "feed-generation-stage",
            "docker compose up",
            "github/codeql-action/autobuild",
        ]
        for needle in forbidden:
            self.assertNotIn(needle, text)

    def test_justfile_forwards_common_recipe_arguments(self):
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        rust_owned = {
            "status",
            "inventory",
            "deps",
            "runtime-plan",
            "up",
            "down",
            "logs",
            "doctor",
            "runtime-log-review",
            "runtime-app-down",
            "runtime-scanner-register",
            "runtime-app-build",
            "runtime-native-api-rebuild",
            "runtime-credential-smoke",
            "runtime-full-test-scan-preflight",
            "runtime-full-test-scan-start",
            "runtime-full-test-scan-status",
            "configure",
            "build",
            "build-core-c",
            "build-c-services",
            "build-ui",
            "build-python",
            "build-baseline",
        }
        for recipe in rust_owned:
            with self.subTest(recipe=recipe):
                self.assertIn(f"{recipe} *args:", justfile)
        for recipe in rust_owned:
            with self.subTest(recipe=recipe):
                self.assertIn(
                    f'tools/yafvsctl-rs/Cargo.toml -- {recipe} "$@"',
                    justfile,
                )

    def test_component_build_surface_is_owned_directly_by_rust(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root / "tools" / "yafvsctl-rs" / "src" / "commands" / "build.rs"
        ).read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        commands = (
            "configure",
            "build",
            "build-core-c",
            "build-c-services",
            "build-ui",
            "build-python",
            "build-baseline",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertNotIn(f'add_parser("{command}"', python_source)
                self.assertNotIn(f'args.command == "{command}"', python_source)
                recipe = justfile.split(f"{command} *args:\n", 1)[1].split(
                    "\n\n", 1
                )[0]
                self.assertIn(f'-- {command} "$@"', recipe)
                self.assertNotIn("tools/yafvsctl ", recipe)
        for function_name in (
            "command_configure",
            "command_build",
            "command_build_core_c",
            "command_build_c_services",
            "command_build_ui",
            "command_build_python",
            "command_build_baseline",
        ):
            self.assertNotIn(f"def {function_name}", python_source)
            self.assertIn(f"pub fn {function_name}", rust_source)
        self.assertNotIn("class BuildMeta", python_source)
        self.assertNotIn("BUILD_META", python_source)

    def test_quality_gate_downgrades_known_doctor_notes_only(self):
        status, summary = yafvsctl.quality_gate_doctor_status(
            {
                "status": "warn",
                "summary": "Monorepo health checks completed.",
                "findings": [
                    {"status": "warn", "check": "git.worktree"},
                    {"status": "warn", "check": "surface.deferred"},
                ],
            }
        )
        self.assertEqual(status, "pass")
        self.assertIn("worktree", summary)

    def test_quality_gate_preserves_unexpected_doctor_warning(self):
        status, summary = yafvsctl.quality_gate_doctor_status(
            {
                "status": "warn",
                "summary": "Monorepo health checks completed.",
                "findings": [
                    {"status": "warn", "check": "tool.available"},
                ],
            }
        )
        self.assertEqual(status, "warn")
        self.assertEqual(summary, "Monorepo health checks completed.")

    def test_quality_gate_serializes_doctor_non_pass_findings(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        self.assertIn("doctor_non_pass", source)
        self.assertIn("non_pass_findings", source)

    def test_quality_gate_compact_step_keeps_non_pass_findings(self):
        result = {
            "status": "fail",
            "summary": "contract drift",
            "details": {"large": ["not copied"]},
            "findings": [
                {"status": "pass", "check": "one", "message": "ok"},
                {"status": "fail", "check": "two", "message": "bad"},
            ],
        }

        step = yafvsctl.quality_gate_compact_step(result)
        quality_finding = yafvsctl.quality_gate_status_finding("quality.native-api-client-contract", result)

        self.assertEqual(step["status"], "fail")
        self.assertEqual(step["summary"], "contract drift")
        self.assertEqual(step["non_pass_findings"], [{"status": "fail", "check": "two", "message": "bad"}])
        self.assertNotIn("details", step)
        self.assertEqual(quality_finding["status"], "fail")
        self.assertEqual(quality_finding["details"]["non_pass_count"], 1)

    def test_quality_gate_runs_native_api_contract_checks(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        self.assertIn("quality.native-tooling-state", source)
        self.assertIn("quality.openapi-syntax", source)
        self.assertIn('["npm", "run", "check:openapi", "--prefix", "components/gsa"]', source)
        self.assertIn('"--test-threads=1"', source)
        self.assertIn("quality.native-api-client-contract", source)
        self.assertIn("quality.native-api-migration-matrix", source)
        self.assertIn("command_native_tooling_state(repo_root, status_only=True)", source)
        self.assertIn("command_native_api_client_contract(repo_root, status_only=True)", source)
        self.assertIn("command_native_api_migration_matrix(repo_root, status_only=True)", source)
        self.assertIn("(\"runtime-log-review\", rust_runtime_log_review_result(repo_root))", source)
        self.assertIn("(\"runtime-data-state\", rust_runtime_data_state_result(repo_root))", source)
        self.assertNotIn("command_runtime_log_review(repo_root)", source)
        self.assertNotIn("command_runtime_data_state(repo_root)", source)

    def test_quality_gate_includes_native_api_contract_steps(self):
        pass_result = {"status": "pass", "summary": "ok", "findings": []}
        completed = subprocess.CompletedProcess(["unit"], 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp, \
             unittest.mock.patch.object(yafvsctl, "rust_license_report_result", return_value=pass_result) as license_report, \
             unittest.mock.patch.object(yafvsctl, "rust_doctor_result", return_value=pass_result) as doctor, \
             unittest.mock.patch.object(yafvsctl, "command_native_tooling_state", return_value=pass_result), \
             unittest.mock.patch.object(yafvsctl, "command_native_api_client_contract", return_value=pass_result), \
             unittest.mock.patch.object(yafvsctl, "command_native_api_migration_matrix", return_value=pass_result), \
             unittest.mock.patch.object(yafvsctl, "run_command", return_value=completed):
            result = yafvsctl.command_quality_gate(Path(tmp))

        steps = result["details"]["steps"]
        self.assertEqual(result["status"], "pass")
        self.assertEqual(steps["openapi-syntax"]["exit_code"], 0)
        self.assertEqual(steps["native-tooling-state"]["status"], "pass")
        self.assertEqual(steps["native-api-client-contract"]["status"], "pass")
        self.assertEqual(steps["native-api-migration-matrix"]["status"], "pass")
        checks = {item["check"] for item in result["findings"]}
        self.assertIn("quality.openapi-syntax", checks)
        self.assertIn("quality.native-tooling-state", checks)
        self.assertIn("quality.native-api-client-contract", checks)
        self.assertIn("quality.native-api-migration-matrix", checks)
        license_report.assert_called_once_with(Path(tmp))
        doctor.assert_called_once_with(Path(tmp))

    def test_gsa_and_runtime_manager_locks_are_registered(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        build_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "build.rs"
        ).read_text(encoding="utf-8")
        manager_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_manager_init.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("GSA_OPERATION_LOCK", source)
        self.assertNotIn("RUNTIME_MANAGER_LOCK", source)
        self.assertIn("def acquire_runtime_lock", source)
        self.assertIn("quality-gate GSA checks", source)
        self.assertIn("GSA_OPERATION_LOCK", build_source)
        self.assertIn("RuntimeOperationLock::acquire", build_source)
        self.assertIn("RuntimeOperationLock::acquire", manager_source)
        self.assertIn("RUNTIME_MANAGER_LOCK", manager_source)

    def test_runtime_manager_init_is_owned_directly_by_rust(self):
        python_source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(
            encoding="utf-8"
        )
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(
            encoding="utf-8"
        )
        recipe = justfile.split("runtime-manager-init *args:\n", 1)[1].split(
            "\n\n", 1
        )[0]
        self.assertNotIn('add_parser("runtime-manager-init"', python_source)
        self.assertNotIn('args.command == "runtime-manager-init"', python_source)
        self.assertNotIn("def command_runtime_manager_init", python_source)
        self.assertIn("cargo run --quiet --locked", recipe)
        self.assertIn('-- runtime-manager-init "$@"', recipe)
        self.assertNotIn("tools/yafvsctl ", recipe)

    def test_runtime_app_smoke_is_owned_directly_by_rust(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_app_smoke.rs"
        ).read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        recipe = justfile.split("runtime-app-smoke *args:\n", 1)[1].split(
            "\n\n", 1
        )[0]
        for surface in (
            'add_parser("runtime-app-smoke"',
            'args.command == "runtime-app-smoke"',
            "def command_runtime_app_smoke",
            "def command_runtime_scanner_capability_check",
            "def command_runtime_scanner_process_check",
            "def command_runtime_nmap_capability_check",
        ):
            self.assertNotIn(surface, python_source)
        self.assertIn("pub fn command_runtime_app_smoke", rust_source)
        self.assertIn("MAX_COMPOSE_LOG_OUTPUT_BYTES", rust_source)
        self.assertIn("cargo run --quiet --locked", recipe)
        self.assertIn('-- runtime-app-smoke "$@"', recipe)
        self.assertNotIn("tools/yafvsctl ", recipe)

    def test_runtime_app_build_is_owned_directly_by_rust(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "feed_generation"
            / "app_build.rs"
        ).read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        recipe = justfile.split("runtime-app-build *args:\n", 1)[1].split(
            "\n\n", 1
        )[0]
        for surface in (
            'add_parser("runtime-app-build"',
            'args.command == "runtime-app-build"',
            "def command_runtime_app_build",
            "def _command_runtime_app_build_unlocked",
            "def stage_gsa_static",
        ):
            self.assertNotIn(surface, python_source)
        self.assertIn("command_runtime_app_build", rust_source)
        self.assertIn("RuntimeOperationLock::acquire", rust_source)
        self.assertIn("FEED_ACTIVATION_LOCK", rust_source)
        self.assertIn("cargo run --quiet --locked", recipe)
        self.assertIn('-- runtime-app-build "$@"', recipe)
        self.assertNotIn("tools/yafvsctl ", recipe)

    def test_runtime_native_api_rebuild_is_owned_directly_by_rust(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "feed_generation"
            / "native_api_rebuild.rs"
        ).read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        recipe = justfile.split("runtime-native-api-rebuild *args:\n", 1)[1].split(
            "\n\n", 1
        )[0]
        for surface in (
            'add_parser("runtime-native-api-rebuild"',
            'args.command == "runtime-native-api-rebuild"',
            "def command_runtime_native_api_rebuild",
            "def _command_runtime_native_api_rebuild_unlocked",
            "def runtime_native_api_rebuild_env",
        ):
            self.assertNotIn(surface, python_source)
        self.assertNotIn("def command_runtime_native_api_smoke", python_source)
        self.assertIn("RuntimeOperationLock::acquire", rust_source)
        self.assertIn("FEED_ACTIVATION_LOCK", rust_source)
        self.assertIn("require_current_app_deployment_snapshot", rust_source)
        self.assertIn("pinned_app_compose_command", rust_source)
        self.assertIn("cargo run --quiet --locked", recipe)
        self.assertIn('-- runtime-native-api-rebuild "$@"', recipe)
        self.assertNotIn("tools/yafvsctl ", recipe)

    def test_runtime_native_api_smoke_is_owned_directly_by_rust(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_native_api_smoke.rs"
        ).read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        recipe = justfile.split("runtime-native-api-smoke *args:\n", 1)[1].split(
            "\n\n", 1
        )[0]
        for surface in (
            'add_parser("runtime-native-api-smoke"',
            'args.command == "runtime-native-api-smoke"',
            "def command_runtime_native_api_smoke",
            "def native_api_smoke_status_only_result",
            "def native_api_expected_bad_request_finding",
            "def native_api_oversized_filter_path",
            "def latest_completed_full_test_report_id",
            "def summarize_native_alerts_response",
        ):
            self.assertNotIn(surface, python_source)
        for contract in (
            "pub fn command_runtime_native_api_smoke",
            "SCOPE_REPORT_COLLECTION_PROBES",
            "ALERT_FORBIDDEN_KEYS",
            "metrics_contract_ok",
            "destructive_actions",
            "runtime-native-api-smoke.status-only",
        ):
            self.assertIn(contract, rust_source)
        self.assertIn("cargo run --quiet --locked", recipe)
        self.assertIn('-- runtime-native-api-smoke "$@"', recipe)
        self.assertNotIn("tools/yafvsctl ", recipe)
        rebuild_source = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "feed_generation"
            / "native_api_rebuild.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("command_runtime_native_api_smoke_with_runner", rebuild_source)
        self.assertNotIn('repo_root.join("tools/yafvsctl")', rebuild_source)

    def test_runtime_native_api_direct_smoke_is_owned_directly_by_rust(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_native_api_direct_smoke.rs"
        ).read_text(encoding="utf-8")
        justfile = (root / "justfile").read_text(encoding="utf-8")
        recipe = justfile.split(
            "runtime-native-api-direct-smoke *args:\n", 1
        )[1].split("\n\n", 1)[0]
        for surface in (
            'add_parser("runtime-native-api-direct-smoke"',
            'args.command == "runtime-native-api-direct-smoke"',
            "def command_runtime_native_api_direct_smoke",
            "def _command_runtime_native_api_direct_smoke_unlocked",
            "def direct_api_response_request_id",
        ):
            self.assertNotIn(surface, python_source)
        for contract in (
            "pub fn command_runtime_native_api_direct_smoke",
            "DISABLED_WRITE_PROBES",
            "RuntimeOperationLock::acquire",
            "raw_direct_api_request",
            "command_runtime_native_api_smoke_with_runner",
            "runtime-native-api-direct-smoke.status-only",
        ):
            self.assertIn(contract, rust_source)
        self.assertIn("cargo run --quiet --locked", recipe)
        self.assertIn('-- runtime-native-api-direct-smoke "$@"', recipe)
        self.assertNotIn("tools/yafvsctl ", recipe)

    def test_gsa_web_fast_script_is_one_shot(self):
        package_path = Path(__file__).resolve().parents[2] / "components" / "gsa" / "package.json"
        package = json.loads(package_path.read_text(encoding="utf-8"))
        script = package["scripts"]["test:web-fast"]
        self.assertIn("vitest run", script)
        self.assertNotRegex(script, r"^vitest\s+--")


    def test_unix_socket_status_classifies_missing_regular_ready_and_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.sock"
            self.assertEqual(yafvsctl.unix_socket_status(missing)["state"], "missing")

            regular = root / "regular.sock"
            regular.write_text("not a socket", encoding="utf-8")
            self.assertEqual(yafvsctl.unix_socket_status(regular)["state"], "not-socket")

            ready = root / "ready.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(ready))
                server.listen(1)
                self.assertEqual(yafvsctl.unix_socket_status(ready)["state"], "ready")
            finally:
                server.close()

            self.assertEqual(yafvsctl.unix_socket_status(ready)["state"], "stale")

    def test_quality_gate_unit_env_ignores_runtime_dir_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            previous = os.environ.get("YAFVS_RUNTIME_DIR")
            os.environ["YAFVS_RUNTIME_DIR"] = "/tmp/not-the-test-runtime"
            try:
                env = yafvsctl.quality_gate_unit_env(root)
            finally:
                if previous is None:
                    os.environ.pop("YAFVS_RUNTIME_DIR", None)
                else:
                    os.environ["YAFVS_RUNTIME_DIR"] = previous
            self.assertNotIn("YAFVS_RUNTIME_DIR", env)

    def test_runtime_credential_smoke_uses_existing_playwright_paths(self):
        self.assertEqual(
            runtime_credential_smoke.playwright_node_path_candidates,
            runtime_browser_smoke.playwright_node_path_candidates,
        )
        self.assertIn(
            "async function gotoStable(page, route)",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertIn(
            "waitUntil: 'domcontentloaded'",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertIn(
            "Math.min(config.timeoutMs, 5000)",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertNotIn(
            "waitUntil: 'networkidle'",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertNotIn(
            "credential-smoke.cleanup-confirm",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertIn(
            "getByText(credentialName, {exact: true})",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertIn(
            "replace(/([?&](?:token|access_token|session|session_token|auth_token|jwt)=)",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertNotIn(
            "innerText.includes(name)",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertNotIn(
            "message: String(error && error.stack",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        for title in (
            "Download Public Key",
            "Download Windows Executable (.exe)",
            "Download RPM (.rpm) Package",
            "Download Debian (.deb) Package",
        ):
            self.assertIn(title, runtime_credential_smoke.BROWSER_SCRIPT)
        for contract_anchor in (
            "Username + SSH Key",
            "input[name=\"privateKey\"]",
            "input[name=\"comment\"]",
            "setInputFiles(config.sshPrivateKeyPath)",
            "page.waitForResponse",
            "isCredentialCreateResponse",
            "credentialIdFromCreateResponse",
            "id ? 'create-response' : null",
            "if (id) identitySource = 'list-response'",
            "if (id) identitySource = 'native-marker-recovery'",
            "Create Credential",
            "headers['content-type']",
            "headers['content-disposition']",
            "MAX_DECLARED_DOWNLOAD_BYTES",
            "declaredContentLength",
            "captureDownloadRequest",
            "'**/api/v1/credentials/*/public-key?*'",
            "request.method() !== 'GET'",
            "url.pathname === `/api/v1/credentials/${encodeURIComponent(credentialId)}/${suffix}`",
            "route.abort('blockedbyclient')",
            "boundedAuthenticatedGet",
            "'accept-encoding': 'identity'",
            "response.on('data'",
            "request.destroy(new Error",
            "bytes.length === 80",
            "removedDownloadActionsAreAbsent",
            "credential-smoke.download.removed-actions",
            "bytes.length <= 1024",
            "errorCode === 'credential_key_download_failed'",
            "hasExpectedSignature",
            "containsConfiguredSecret",
            "credential-smoke.${fixture.kind}.collision",
            "recordOwnedFixture(owned)",
            "credential-smoke-state.json",
            "config.cleanupOnly",
            "live.item.id !== fixture.id",
            "deleteNativeTrashCredential",
            "deleteNativeLiveCredential",
            "fetchNativeTrashCredential",
            "fetchNativeLiveCredential",
            "encodeURIComponent(id)",
            "'X-YAFVS-Token': token",
            "cache: 'no-store'",
            "url.searchParams.set('token', token)",
            "url.searchParams.set('id', id)",
            "url.searchParams.set('page_size', '2')",
            "url.searchParams.set('sort', 'id')",
            "_smoke_nonce",
            "owned.length !== 1",
            "liveResult.item !== null",
            "after.items.length === 0",
            "cleanup-purge-identity",
            "exact owned credential UUID was permanently deleted",
            "retainOwnedFixture",
            "releaseOwnedFixture",
            "fixture.baseUrl === baseUrl",
            "fixturesForBaseUrl",
            "credential-smoke.retry-cleanup",
            "fixture.ownershipMarker",
            "live.item.comment !== fixture.ownershipMarker",
            "exact owned credential UUID was moved to Trashcan",
            "safeStoredUrl",
        ):
            self.assertIn(contract_anchor, runtime_credential_smoke.BROWSER_SCRIPT)
        self.assertNotIn(
            "row.getByTitle('Delete')",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertNotIn(
            "row.getByTitle(/trashcan/i)",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        helper_source = CREDENTIAL_SMOKE_PATH.read_text(encoding="utf-8")
        for process_anchor in (
            "def run_node_process(",
            "os.killpg",
            "def timeout_cleanup(",
            "def sanitized_base_url(",
            "credential-smoke.recovery-authority",
        ):
            self.assertIn(process_anchor, helper_source)
        self.assertNotIn(
            "fs.writeFileSync(output, bytes",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )
        self.assertNotIn(
            "response.body()",
            runtime_credential_smoke.BROWSER_SCRIPT,
        )

    def test_runtime_credential_cleanup_policy_fails_closed_by_exact_identity(self):
        fixture = {
            "kind": "up",
            "name": "owned",
            "id": "00000000-0000-4000-8000-000000000001",
            "ownershipMarker": "yafvs-smoke:" + "a" * 43,
        }
        cases = [
            {"trash": []},
            {"trash": [], "live": None},
            {"trash": [], "live": {"ok": True, "item": fixture}},
            {"trash": [], "live": {"ok": True, "item": None}},
            {
                "trash": [
                    {
                        "entity_type": "credential",
                        "name": "other",
                        "id": fixture["id"],
                        "comment": fixture["ownershipMarker"],
                    }
                ]
            },
            {
                "trash": [
                    {
                        "entity_type": "credential",
                        "name": fixture["name"],
                        "id": fixture["id"],
                        "comment": fixture["ownershipMarker"],
                    }
                ]
            },
        ]
        script = (
            runtime_credential_smoke.CREDENTIAL_CLEANUP_POLICY
            + "\nconst fixture = "
            + json.dumps(fixture)
            + ";\nconst cases = "
            + json.dumps(cases)
            + ";\nconsole.log(JSON.stringify(cases.map(item => "
            + "credentialCleanupDecision(fixture, item.trash, item.live).action)));\n"
        )
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            [
                "verify-live",
                "live-unverified",
                "live-present",
                "absent",
                "identity-mismatch",
                "purge",
            ],
        )

    def test_runtime_credential_ownership_is_scoped_by_base_url_and_uuid(self):
        fixtures = [
            {
                "kind": "up",
                "name": "same-name",
                "id": "00000000-0000-4000-8000-000000000001",
                "baseUrl": "https://one.example/",
                "ownershipMarker": "yafvs-smoke:" + "a" * 43,
            },
            {
                "kind": "up",
                "name": "same-name",
                "id": "00000000-0000-4000-8000-000000000002",
                "baseUrl": "https://two.example/",
                "ownershipMarker": "yafvs-smoke:" + "b" * 43,
            },
            {
                "kind": "up",
                "name": "same-name",
                "id": "00000000-0000-4000-8000-000000000003",
                "baseUrl": "https://one.example/",
                "ownershipMarker": "yafvs-smoke:" + "c" * 43,
            },
        ]
        script = (
            runtime_credential_smoke.CREDENTIAL_CLEANUP_POLICY
            + "\nconst additions = "
            + json.dumps(fixtures)
            + ";\nlet owned = [];"
            + "\nfor (const fixture of additions) owned = retainOwnedFixture(owned, fixture);"
            + "\nconst retained = owned.length;"
            + "\nowned = releaseOwnedFixture(owned, additions[0]);"
            + "\nconst firstBase = fixturesForBaseUrl(owned, 'https://one.example/');"
            + "\nconsole.log(JSON.stringify({retained, remaining: owned.map(item => item.id), firstBase: firstBase.map(item => item.id)}));\n"
        )
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["retained"], 3)
        self.assertEqual(
            result["remaining"],
            [fixtures[1]["id"], fixtures[2]["id"]],
        )
        self.assertEqual(result["firstBase"], [fixtures[2]["id"]])

    def test_runtime_credential_smoke_recovers_valid_prior_owned_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            state_path = artifact_dir / "credential-smoke-state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "fixtures": [
                            {
                                "kind": "up",
                                "name": "yafvs-credential-smoke-001122aa",
                                "id": "00000000-0000-4000-8000-000000000001",
                                "baseUrl": "https://one.example/",
                                "ownershipMarker": "yafvs-smoke:" + "a" * 43,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                runtime_credential_smoke.load_owned_fixtures(
                    artifact_dir, {"https://one.example/"}
                ),
                [
                    {
                        "kind": "up",
                        "name": "yafvs-credential-smoke-001122aa",
                        "id": "00000000-0000-4000-8000-000000000001",
                        "baseUrl": "https://one.example/",
                        "ownershipMarker": "yafvs-smoke:" + "a" * 43,
                    }
                ],
            )

    def test_runtime_credential_cleanup_executes_marker_checks_before_deletion(self):
        start = runtime_credential_smoke.BROWSER_SCRIPT.index(
            "async function purgeCredentialFromTrash"
        )
        end = runtime_credential_smoke.BROWSER_SCRIPT.index(
            "async function runForBaseUrl", start
        )
        flow = runtime_credential_smoke.BROWSER_SCRIPT[start:end]
        fixture = {
            "kind": "up",
            "name": "yafvs-credential-smoke-001122aa",
            "id": "00000000-0000-4000-8000-000000000001",
            "baseUrl": "https://one.example/",
            "ownershipMarker": "yafvs-smoke:" + "a" * 43,
        }
        script = (
            runtime_credential_smoke.CREDENTIAL_CLEANUP_POLICY
            + "\n"
            + flow
            + "\nconst fixture = "
            + json.dumps(fixture)
            + """;
const config = {urlIndex: 0};
let liveDeleteCalls = 0;
let trashDeleteCalls = 0;
let trashFetchCalls = 0;
let liveItem = {...fixture, comment: 'wrong-marker'};
let trashItems = [{
  entity_type: 'credential',
  id: fixture.id,
  name: fixture.name,
  comment: fixture.ownershipMarker,
}];
function add() {}
async function gotoStable() {}
async function screenshot() {}
function forgetOwnedFixture() {}
async function fetchNativeLiveCredential() {
  return {ok: true, status: 200, item: liveItem};
}
async function deleteNativeLiveCredential() {
  liveDeleteCalls += 1;
  return {ok: true, status: 204};
}
async function fetchNativeTrashCredential() {
  trashFetchCalls += 1;
  return {
    ok: true,
    status: 200,
    items: trashFetchCalls === 1 ? trashItems : [],
  };
}
async function deleteNativeTrashCredential() {
  trashDeleteCalls += 1;
  return {ok: true, status: 204};
}
const page = {reload: async () => null};
(async () => {
  const rejected = await deleteCredential(page, fixture);
  liveItem = null;
  const purged = await purgeCredentialFromTrash(page, fixture);
  trashFetchCalls = 0;
  trashItems = [null];
  const malformedRejected = await purgeCredentialFromTrash(page, fixture);
  console.log(JSON.stringify({
    rejected,
    purged,
    malformedRejected,
    liveDeleteCalls,
    trashDeleteCalls,
  }));
})().catch(error => {
  console.error(error);
  process.exit(1);
});
"""
        )
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "rejected": False,
                "purged": True,
                "malformedRejected": False,
                "liveDeleteCalls": 0,
                "trashDeleteCalls": 1,
            },
        )

    def test_runtime_credential_client_certificate_characterization_contract(self):
        source = runtime_credential_smoke.BROWSER_SCRIPT
        helper_source = CREDENTIAL_SMOKE_PATH.read_text(encoding="utf-8")
        for anchor in (
            "Download Client Certificate",
            "format === 'certificate'",
            "'certificate'",
            "**/api/v1/credentials/*/certificate?*",
            "kind: 'cc'",
            "typeLabel: 'Client Certificate'",
            "input[name=\"certificate\"]",
            "input[name=\"passphrase\"]",
            "await passphrase.fill(credentialPassword)",
            "clientCertificateMetadata",
            "-----BEGIN CERTIFICATE-----",
            "containsPrivateKeyMarker",
            "containsConfiguredSecret",
            "contentEncoding === 'identity'",
            "certificateCleaned = certificateFixture ? await safelyDeleteCredential",
            "[upFixture, sshFixture, certificateFixture]",
            "credentialDownloadRequestMatches",
            "recoverOwnedCredentialIdentity",
            "item.comment === expected.ownershipMarker",
            "matches.length === 1",
            "async function safelyDeleteCredential",
        ):
            self.assertIn(anchor, source)
        for anchor in (
            'kind not in {"up", "usk", "cc"}',
            'name.endswith("-cert")',
            '"openssl"',
            '"genpkey"',
            '"-algorithm"',
            '"RSA"',
            '"rsa_keygen_bits:2048"',
            '"req"',
            '"-x509"',
            '"-out"',
            'timeout=30',
            'clientCertificateSha256',
        ):
            self.assertIn(anchor, helper_source)
        fixture = {
            "kind": "cc",
            "name": "yafvs-credential-smoke-001122aa-cert",
            "id": "a0000000-0000-4000-8000-000000000001",
            "baseUrl": "https://one.example/",
            "ownershipMarker": "yafvs-smoke:" + "a" * 43,
        }
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            (artifact_dir / "credential-smoke-state.json").write_text(
                json.dumps({"fixtures": [fixture]}), encoding="utf-8"
            )
            self.assertEqual(
                runtime_credential_smoke.load_owned_fixtures(
                    artifact_dir, {"https://one.example/"}
                ),
                [fixture],
            )
            fixture["name"] = "yafvs-credential-smoke-001122aa"
            (artifact_dir / "credential-smoke-state.json").write_text(
                json.dumps({"fixtures": [fixture]}), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                runtime_credential_smoke.load_owned_fixtures(
                    artifact_dir, {"https://one.example/"}
                )

    def test_runtime_credential_certificate_metadata_rejects_key_material_and_mismatch(self):
        source = runtime_credential_smoke.BROWSER_SCRIPT
        start = source.index("function clientCertificateMetadata")
        end = source.index("function declaredContentLength", start)
        helper = source[start:end]
        script = helper + r"""
const crypto = require('crypto');
const certificate = Buffer.from(
  '-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n',
);
const fingerprint = crypto.createHash('sha256').update(certificate).digest('hex');
const keyMarker = '-----BEGIN ' + 'PRIVATE KEY-----\nQUFBQQ==\n-----END ' + 'PRIVATE KEY-----\n';
const bundle = Buffer.concat([certificate, Buffer.from(keyMarker)]);
const chain = Buffer.concat([certificate, certificate]);
console.log(JSON.stringify({
  exact: clientCertificateMetadata(certificate, fingerprint),
  bundle: clientCertificateMetadata(bundle, fingerprint),
  chain: clientCertificateMetadata(chain, crypto.createHash('sha256').update(chain).digest('hex')),
  mismatch: clientCertificateMetadata(certificate, '0'.repeat(64)),
}));
"""
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["exact"],
            {
                "pemOnly": True,
                "containsPrivateKeyMarker": False,
                "fingerprintMatched": True,
            },
        )
        self.assertFalse(result["bundle"]["pemOnly"])
        self.assertTrue(result["bundle"]["containsPrivateKeyMarker"])
        self.assertFalse(result["bundle"]["fingerprintMatched"])
        self.assertTrue(result["chain"]["pemOnly"])
        self.assertFalse(result["chain"]["containsPrivateKeyMarker"])
        self.assertTrue(result["chain"]["fingerprintMatched"])
        self.assertFalse(result["mismatch"]["fingerprintMatched"])

    def test_runtime_credential_certificate_request_matcher_is_exact(self):
        source = runtime_credential_smoke.BROWSER_SCRIPT
        start = source.index("function credentialDownloadRequestMatches")
        end = source.index("async function captureDownloadRequest", start)
        helper = source[start:end]
        credential_id = "a0000000-0000-4000-8000-000000000001"
        script = helper + f"""
const config = {{baseUrl: 'https://one.example/'}};
const credentialId = {json.dumps(credential_id)};
function request(method, url) {{
  return {{method: () => method, url: () => url}};
}}
const expected = 'https://one.example/api/v1/credentials/' + credentialId + '/certificate?token=redacted';
console.log(JSON.stringify({{
  expected: credentialDownloadRequestMatches(request('GET', expected), 'certificate', credentialId),
  wrongMethod: credentialDownloadRequestMatches(request('POST', expected), 'certificate', credentialId),
  wrongOrigin: credentialDownloadRequestMatches(request('GET', expected.replace('one.example', 'two.example')), 'certificate', credentialId),
  wrongPath: credentialDownloadRequestMatches(request('GET', expected.replace('/certificate?', '/other?')), 'certificate', credentialId),
  wrongFormat: credentialDownloadRequestMatches(request('GET', expected.replace('/certificate?', '/public-key?')), 'certificate', credentialId),
  wrongId: credentialDownloadRequestMatches(request('GET', expected.replace(credentialId, 'b0000000-0000-4000-8000-000000000002')), 'certificate', credentialId),
}}));
"""
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "expected": True,
                "wrongMethod": False,
                "wrongOrigin": False,
                "wrongPath": False,
                "wrongFormat": False,
                "wrongId": False,
            },
        )

    def test_runtime_credential_create_response_identity_is_strict(self):
        source = runtime_credential_smoke.BROWSER_SCRIPT
        start = source.index("function isCredentialCreateResponse")
        end = source.index("async function deleteNativeTrashCredential", start)
        helper = source[start:end]
        credential_id = "a0000000-0000-4000-8000-000000000001"
        script = helper + f"""
const config = {{baseUrl: 'https://one.example/'}};
function response(method, url, body, status, text) {{
  return {{
    request: () => ({{method: () => method, postData: () => body}}),
    url: () => url,
    status: () => status,
    text: async () => text,
  }};
}}
const expected = response(
  'POST',
  'https://one.example/gmp',
  '',
  200,
  '<envelope><action_result><action>Create Credential</action><message>OK</message><id>{credential_id}</id></action_result></envelope>',
);
const wrongOrigin = response(
  'POST',
  'https://two.example/gmp?cmd=create_credential',
  '',
  200,
  '<action_result><action>Create Credential</action><id>{credential_id}</id></action_result>',
);
const ambiguous = response(
  'POST',
  'https://one.example/gmp?cmd=create_credential',
  '',
  200,
  '<action_result><action>Create Target</action><id>{credential_id}</id></action_result>',
);
Promise.all([
  credentialIdFromCreateResponse(expected),
  credentialIdFromCreateResponse(ambiguous),
]).then(([id, ambiguousId]) => {{
  console.log(JSON.stringify({{
    matches: isCredentialCreateResponse(expected),
    wrongOrigin: isCredentialCreateResponse(wrongOrigin),
    id,
    ambiguousId,
  }}));
}});
"""
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "matches": True,
                "wrongOrigin": False,
                "id": credential_id,
                "ambiguousId": None,
            },
        )

    def test_runtime_credential_cleanup_exception_is_bounded(self):
        source = runtime_credential_smoke.BROWSER_SCRIPT
        start = source.index("async function safelyDeleteCredential")
        end = source.index("async function runForBaseUrl", start)
        helper = source[start:end]
        script = helper + r"""
const findings = [];
function add(status, check, message, details) {
  findings.push({status, check, message, details});
}
function safeError(error) {
  return String(error);
}
async function deleteCredential() {
  throw new Error('bounded cleanup failure');
}
const fixture = {kind: 'cc', name: 'owned', id: 'a0000000-0000-4000-8000-000000000001'};
safelyDeleteCredential({}, fixture).then(result => {
  console.log(JSON.stringify({result, findings}));
});
"""
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        result = json.loads(completed.stdout)
        self.assertFalse(result["result"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(
            result["findings"][0]["check"],
            "credential-smoke.cc.cleanup-exception",
        )

    def test_runtime_credential_smoke_rejects_noncanonical_or_malformed_state(self):
        valid = {
            "kind": "up",
            "name": "yafvs-credential-smoke-001122aa",
            "id": "a0000000-0000-4000-8000-000000000001",
            "baseUrl": "https://one.example/",
            "ownershipMarker": "yafvs-smoke:" + "a" * 43,
        }
        invalid_payloads = [
            "{malformed",
            '{"fixtures":[],"fixtures":[]}',
            json.dumps({"fixtures": [], "unexpected": True}),
            json.dumps({"fixtures": [{**valid, "baseUrl": "https://ONE.example/"}]}),
            json.dumps({"fixtures": [{**valid, "id": valid["id"].upper()}]}),
            json.dumps({"fixtures": [{**valid, "unexpected": True}]}),
            json.dumps({"fixtures": [valid, valid]}),
            json.dumps(
                {
                    "fixtures": [
                        {key: value for key, value in valid.items() if key != "baseUrl"}
                    ]
                }
            ),
        ]
        for serialized in invalid_payloads:
            with self.subTest(serialized=serialized):
                with tempfile.TemporaryDirectory() as tmp:
                    artifact_dir = Path(tmp)
                    (artifact_dir / "credential-smoke-state.json").write_text(
                        serialized,
                        encoding="utf-8",
                    )
                    with self.assertRaises(ValueError):
                        runtime_credential_smoke.load_owned_fixtures(
                            artifact_dir, {"https://one.example/"}
                        )

    def test_runtime_credential_smoke_rejects_path_scoped_base_urls(self):
        self.assertEqual(
            runtime_credential_smoke.sanitized_base_url(
                "https://ONE.example:443/?token=redacted"
            ),
            "https://one.example/",
        )
        for value in (
            "https://one.example/instance-a",
            "https://one.example/instance-a/",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "path must be /"):
                    runtime_credential_smoke.sanitized_base_url(value)

    def test_runtime_credential_timeout_cleanup_uses_strict_owned_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            config_path = artifact_dir / "credential-smoke-config.json"
            config_path.write_text(
                json.dumps({"baseUrls": ["https://one.example/"]}),
                encoding="utf-8",
            )
            (artifact_dir / "credential-smoke-state.json").write_text(
                "{malformed",
                encoding="utf-8",
            )
            with unittest.mock.patch.object(
                runtime_credential_smoke, "run_node_process"
            ) as node_run:
                result = runtime_credential_smoke.timeout_cleanup(
                    script_path=artifact_dir / "credential-smoke.cjs",
                    config_path=config_path,
                    artifact_dir=artifact_dir,
                    env={},
                    redactions=[],
                )
            self.assertEqual(result["status"], "fail")
            self.assertIn("refused untrusted retained state", result["summary"])
            node_run.assert_not_called()

    def test_runtime_credential_smoke_rejects_untrusted_prior_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            (artifact_dir / "credential-smoke-state.json").write_text(
                json.dumps(
                    {
                        "fixtures": [
                            {
                                "kind": "up",
                                "name": "unrelated",
                                "id": "00000000-0000-4000-8000-000000000001",
                                "baseUrl": "https://other.example/",
                                "ownershipMarker": "forged",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                runtime_credential_smoke.load_owned_fixtures(
                    artifact_dir, {"https://one.example/"}
                )

    def test_runtime_credential_smoke_uses_environment_password_and_redacts_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password_file = root / "admin-password"
            password_file.write_text("admin-secret\n", encoding="utf-8")
            args = runtime_credential_smoke.build_parser().parse_args(
                [
                    "--base-url",
                    "https://127.0.0.1:19392/?session_token=url-secret",
                    "--username",
                    "admin",
                    "--password-file",
                    str(password_file),
                    "--artifact-dir",
                    str(root / "artifacts"),
                    "--credential-name",
                    "test",
                ]
            )
            completed = subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "status": "pass",
                        "summary": "environment-password admin-secret",
                        "artifacts": [],
                    }
                )
                + "\n",
            )

            with (
                unittest.mock.patch.object(
                    runtime_credential_smoke,
                    "playwright_node_path_candidates",
                    return_value=["/tmp/node_modules"],
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke.subprocess,
                    "run",
                    side_effect=credential_smoke_material_run,
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke,
                    "run_node_process",
                    return_value=completed,
                ) as node_run,
                unittest.mock.patch.dict(
                    os.environ,
                    {
                        "YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD": "environment-password"
                    },
                    clear=False,
                ),
            ):
                result = runtime_credential_smoke.run_credential_smoke(args)

            self.assertEqual(result["status"], "pass")
            self.assertEqual(
                node_run.call_args.kwargs["env"][
                    "YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD"
                ],
                "environment-password",
            )
            serialized = json.dumps(result)
            artifact = (root / "artifacts" / "credential-smoke-wrapper.json").read_text(
                encoding="utf-8"
            )
            config = json.loads(
                (root / "artifacts" / "credential-smoke-config.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(config["sshCredentialName"], "test-ssh")
            self.assertEqual(config["clientCertificateName"], "test-cert")
            self.assertTrue(config["sshPrivateKeyPath"].endswith("/id_ed25519"))
            self.assertTrue(config["clientCertificatePath"].endswith("/client-certificate.pem"))
            self.assertNotIn("clientCertificateSha256", json.dumps(result))
            self.assertEqual(config["baseUrls"], ["https://127.0.0.1:19392/"])
            for secret in ("environment-password", "admin-secret", "url-secret"):
                self.assertNotIn(secret, serialized)
                self.assertNotIn(secret, artifact)

    def test_runtime_credential_smoke_redacts_malformed_node_output_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password_file = root / "admin-password"
            password_file.write_text("admin-secret\n", encoding="utf-8")
            args = runtime_credential_smoke.build_parser().parse_args(
                [
                    "--base-url",
                    "https://127.0.0.1:19392",
                    "--username",
                    "admin",
                    "--password-file",
                    str(password_file),
                    "--artifact-dir",
                    str(root / "artifacts"),
                    "--credential-name",
                    "test",
                ]
            )
            completed = subprocess.CompletedProcess(
                [], 1, "not-json admin-secret environment-password\n"
            )
            with (
                unittest.mock.patch.object(
                    runtime_credential_smoke,
                    "playwright_node_path_candidates",
                    return_value=["/tmp/node_modules"],
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke.subprocess,
                    "run",
                    side_effect=credential_smoke_material_run,
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke,
                    "run_node_process",
                    return_value=completed,
                ),
                unittest.mock.patch.dict(
                    os.environ,
                    {
                        "YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD": "environment-password"
                    },
                    clear=False,
                ),
            ):
                result = runtime_credential_smoke.run_credential_smoke(args)

            artifact = (root / "artifacts" / "credential-smoke-wrapper.json").read_text(
                encoding="utf-8"
            )
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["findings"][0]["check"], "credential-smoke.output")
            for secret in ("environment-password", "admin-secret"):
                self.assertNotIn(secret, json.dumps(result))
                self.assertNotIn(secret, artifact)

    def test_runtime_credential_smoke_fails_before_node_without_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password_file = root / "admin-password"
            password_file.write_text("admin\n", encoding="utf-8")
            args = runtime_credential_smoke.build_parser().parse_args(
                [
                    "--base-url",
                    "https://127.0.0.1:19392",
                    "--username",
                    "admin",
                    "--password-file",
                    str(password_file),
                    "--artifact-dir",
                    str(root / "artifacts"),
                    "--credential-name",
                    "test",
                ]
            )
            with (
                unittest.mock.patch.object(
                    runtime_credential_smoke, "playwright_node_path_candidates"
                ) as paths,
                unittest.mock.patch.dict(
                    os.environ,
                    {"YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD": ""},
                    clear=False,
                ),
            ):
                result = runtime_credential_smoke.run_credential_smoke(args)

            self.assertEqual(result["status"], "fail")
            self.assertEqual(
                result["findings"][0]["check"],
                "credential-smoke.credential-password",
            )
            paths.assert_not_called()

    def test_runtime_credential_smoke_fails_before_node_without_ssh_keygen(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password_file = root / "admin-password"
            password_file.write_text("admin\n", encoding="utf-8")
            args = runtime_credential_smoke.build_parser().parse_args(
                [
                    "--base-url",
                    "https://127.0.0.1:19392",
                    "--username",
                    "admin",
                    "--password-file",
                    str(password_file),
                    "--artifact-dir",
                    str(root / "artifacts"),
                    "--credential-name",
                    "test",
                ]
            )
            with (
                unittest.mock.patch.object(
                    runtime_credential_smoke,
                    "playwright_node_path_candidates",
                    return_value=["/tmp/node_modules"],
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke.shutil, "which", return_value=None
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke.subprocess, "run"
                ) as run,
                unittest.mock.patch.dict(
                    os.environ,
                    {
                        "YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD": "credential-password"
                    },
                    clear=False,
                ),
            ):
                result = runtime_credential_smoke.run_credential_smoke(args)

            self.assertEqual(result["status"], "fail")
            self.assertEqual(
                result["findings"][0]["check"], "credential-smoke.ssh-keygen"
            )
            run.assert_not_called()

    def test_runtime_credential_smoke_fails_before_node_without_openssl(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password_file = root / "admin-password"
            password_file.write_text("admin\n", encoding="utf-8")
            args = runtime_credential_smoke.build_parser().parse_args(
                [
                    "--base-url",
                    "https://127.0.0.1:19392",
                    "--username",
                    "admin",
                    "--password-file",
                    str(password_file),
                    "--artifact-dir",
                    str(root / "artifacts"),
                    "--credential-name",
                    "test",
                ]
            )
            which_results = {
                "ssh-keygen": "/usr/bin/ssh-keygen",
                "openssl": None,
            }
            with (
                unittest.mock.patch.object(
                    runtime_credential_smoke,
                    "playwright_node_path_candidates",
                    return_value=["/tmp/node_modules"],
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke.shutil,
                    "which",
                    side_effect=which_results.get,
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke.subprocess, "run"
                ) as run,
                unittest.mock.patch.dict(
                    os.environ,
                    {
                        "YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD": "credential-password"
                    },
                    clear=False,
                ),
            ):
                result = runtime_credential_smoke.run_credential_smoke(args)

            self.assertEqual(result["status"], "fail")
            self.assertEqual(
                result["findings"][0]["check"], "credential-smoke.openssl"
            )
            run.assert_not_called()

    def test_runtime_credential_smoke_bounds_node_timeout_and_redacts_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password_file = root / "admin-password"
            password_file.write_text("admin-secret\n", encoding="utf-8")
            args = runtime_credential_smoke.build_parser().parse_args(
                [
                    "--base-url",
                    "https://127.0.0.1:19392",
                    "--username",
                    "admin",
                    "--password-file",
                    str(password_file),
                    "--artifact-dir",
                    str(root / "artifacts"),
                    "--credential-name",
                    "test",
                ]
            )
            node_calls = 0

            def run_node(command, *, env, timeout):
                nonlocal node_calls
                node_calls += 1
                state_path = root / "artifacts" / "credential-smoke-state.json"
                if node_calls == 1:
                    state_path.write_text(
                        json.dumps(
                            {
                                "fixtures": [
                                    {
                                        "kind": "up",
                                        "name": "yafvs-credential-smoke-001122aa",
                                        "id": "00000000-0000-4000-8000-000000000001",
                                        "baseUrl": "https://127.0.0.1:19392/",
                                        "ownershipMarker": "yafvs-smoke:" + "a" * 43,
                                    }
                                ]
                            }
                        ),
                        encoding="utf-8",
                    )
                    raise subprocess.TimeoutExpired(
                        cmd=command,
                        timeout=timeout,
                        output="admin-secret environment-password",
                    )
                state_path.write_text(
                    json.dumps({"fixtures": []}), encoding="utf-8"
                )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(
                        {
                            "status": "pass",
                            "summary": "Owned timeout fixtures were cleaned.",
                            "artifacts": [],
                        }
                    )
                    + "\n",
                )

            with (
                unittest.mock.patch.object(
                    runtime_credential_smoke,
                    "playwright_node_path_candidates",
                    return_value=["/tmp/node_modules"],
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke.subprocess,
                    "run",
                    side_effect=credential_smoke_material_run,
                ),
                unittest.mock.patch.object(
                    runtime_credential_smoke,
                    "run_node_process",
                    side_effect=run_node,
                ),
                unittest.mock.patch.dict(
                    os.environ,
                    {
                        "YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD": "environment-password"
                    },
                    clear=False,
                ),
            ):
                result = runtime_credential_smoke.run_credential_smoke(args)

            artifact = (
                root / "artifacts" / "credential-smoke-wrapper.json"
            ).read_text(encoding="utf-8")
            self.assertEqual(result["status"], "fail")
            self.assertEqual(
                result["findings"][0]["check"], "credential-smoke.timeout"
            )
            self.assertEqual(node_calls, 2)
            self.assertEqual(result["details"]["cleanup"]["status"], "pass")
            self.assertEqual(
                json.loads(
                    (
                        root / "artifacts" / "credential-smoke-state.json"
                    ).read_text(encoding="utf-8")
                )["fixtures"],
                [],
            )
            for secret in ("environment-password", "admin-secret"):
                self.assertNotIn(secret, json.dumps(result))
                self.assertNotIn(secret, artifact)

    def test_runtime_browser_smoke_checks_metrics_tabs(self):
        source = (Path(__file__).resolve().parents[1] / "runtime_browser_smoke.py").read_text(encoding="utf-8")
        self.assertIn("const waitUntil = options.waitUntil || 'domcontentloaded';", source)
        self.assertIn("Math.min(config.timeoutMs, 5000)", source)
        self.assertIn("runForBaseUrl(baseUrl, index === 0)", source)
        self.assertIn("browser.secondary-host-session-renew", source)
        self.assertIn("browser.secondary-host-native-api", source)
        self.assertIn("await gotoStable(page, new URL(rawReportHref", source)
        self.assertIn("if (match) return match.itemIds[0] || null;", source)
        self.assertIn("scope-report.metrics-tab", source)
        self.assertIn("scope-report.metrics-native-api", source)
        self.assertIn("scope-report.results-native-api", source)
        self.assertIn("scope-report.hosts-native-api", source)
        self.assertIn("scope-report.ports-native-api", source)
        self.assertIn("scope-report.cves-native-api", source)
        self.assertIn("scope-report.errors-native-api", source)
        self.assertIn("scope-report.results-aggregated-native-tab", source)
        self.assertIn("scope-report.hosts-aggregated-native-tab", source)
        self.assertIn("scope-report.ports-aggregated-native-tab", source)
        self.assertIn("scope-report.cves-aggregated-native-tab", source)
        self.assertIn("scope-report.errors-aggregated-native-tab", source)
        self.assertIn("raw-report.metrics-tab", source)
        self.assertIn("raw-report.metrics-native-api", source)
        self.assertIn("/api/v1/", source)
        self.assertIn("CVSS Load", source)
        self.assertIn("Authenticated Scan Coverage", source)

    def test_runtime_browser_smoke_playwright_search_paths(self):
        candidates = runtime_browser_smoke.PLAYWRIGHT_NODE_PATHS
        self.assertIn("/home/turboforge/.local/share/yafvs-tools/playwright/node_modules", candidates)
        self.assertIn("/home/turboforge/.local/nodejs/node-v22.22.3-linux-x64/lib/node_modules", candidates)

    def test_license_precommit_recipe_is_registered(self):
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")

        self.assertIn("license-precommit *args:", justfile)
        self.assertIn("--manifest-path tools/yafvsctl-rs/Cargo.toml", justfile)
        self.assertIn("license-report --diff-scope staged --modified-imported-only", justfile)

    def test_secret_precommit_recipe_is_registered(self):
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")

        self.assertIn("secret-precommit *args:", justfile)
        self.assertIn("gitleaks protect --staged --redact --no-banner", justfile)
        self.assertIn("--exit-code 7 --report-format json", justfile)

    def test_production_posture_tracks_password_rotation_gap(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl-rs" / "src" / "commands" / "production_posture.rs").read_text(encoding="utf-8")
        self.assertIn("production.first-login-password-rotation", source)
        self.assertIn("Production first-login/password-rotation bootstrap is not implemented yet", source)

    def test_rust_production_posture_bridge_forwards_status_only(self):
        root = Path("/tmp/repo")
        sentinel = {"status": "fail"}
        with unittest.mock.patch.object(
            yafvsctl, "rust_result_envelope", return_value=sentinel
        ) as bridge:
            result = yafvsctl.rust_production_posture_result(root, status_only=True)

        self.assertIs(result, sentinel)
        bridge.assert_called_once_with(
            root,
            "production-posture-check",
            ["production-posture-check", "--status-only"],
        )

    def test_gsa_browser_metadata_uses_yafvs_branding(self):
        index = (Path(__file__).resolve().parents[2] / "components" / "gsa" / "index.html").read_text(encoding="utf-8")
        self.assertIn("<title>YAFVS</title>", index)
        self.assertIn('href="/img/favicon.svg" type="image/svg+xml"', index)
        self.assertNotIn("<title>OPENVAS</title>", index)

    def test_gsa_quality_env_adds_node_heap_headroom(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with unittest.mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(yafvsctl.gsa_quality_env(root)["NODE_OPTIONS"], "--max-old-space-size=4096")
            with unittest.mock.patch.dict(os.environ, {"NODE_OPTIONS": "--trace-warnings"}, clear=True):
                self.assertEqual(yafvsctl.gsa_quality_env(root)["NODE_OPTIONS"], "--trace-warnings --max-old-space-size=4096")
            with unittest.mock.patch.dict(os.environ, {"NODE_OPTIONS": "--max-old-space-size=6144"}, clear=True):
                self.assertEqual(yafvsctl.gsa_quality_env(root)["NODE_OPTIONS"], "--max-old-space-size=6144")

    def test_runtime_dir_defaults_next_to_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(yafvsctl.runtime_dir(root), Path(tmp) / "YAFVS-runtime")

    def test_runtime_dir_rejects_relative_and_repository_nested_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "YAFVS"
            root.mkdir()
            alias = Path(tmp) / "repo-alias"
            alias.symlink_to(root, target_is_directory=True)
            for configured, message in (
                ("YAFVS-runtime", "must be an absolute path"),
                (str(root / "YAFVS-runtime"), "must be outside the repository"),
                (str(alias / "nested-runtime"), "must be outside the repository"),
                (
                    str(Path(tmp) / "missing" / ".." / "YAFVS" / "nested-runtime"),
                    "must not contain parent-directory components",
                ),
            ):
                with self.subTest(configured=configured), unittest.mock.patch.dict(
                    os.environ,
                    {"YAFVS_RUNTIME_DIR": configured},
                ):
                    with self.assertRaisesRegex(ValueError, message):
                        yafvsctl.runtime_dir(root)
            self.assertFalse((root / "YAFVS-runtime").exists())

    def test_cli_rejects_invalid_runtime_override_before_dispatch(self):
        repo_root = YAFVSCTL_PATH.parents[1]
        environment = os.environ.copy()
        environment["YAFVS_RUNTIME_DIR"] = "YAFVS-runtime"
        completed = subprocess.run(
            [sys.executable, str(YAFVSCTL_PATH), "native-tooling-state", "--json"],
            cwd=repo_root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["findings"][0]["check"], "runtime.configuration")
        self.assertFalse((repo_root / "YAFVS-runtime").exists())

    def test_app_services_are_experimental_profile_services(self):
        self.assertEqual(yafvsctl.APP_SERVICES, ("gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"))

    def test_dev_shell_source_and_build_mounts_remain_writable(self):
        compose = (Path(__file__).resolve().parents[2] / "compose" / "dev.yaml").read_text(encoding="utf-8")
        dev_shell = compose.split("  dev-shell:", 1)[1].split("  gvmd:", 1)[0]

        self.assertNotIn("read_only: true", dev_shell)

    def test_gsad_port_defaults_loopback_and_can_be_overridden(self):
        self.assertEqual(yafvsctl.DEFAULT_GSAD_HOST, "127.0.0.1")
        self.assertEqual(yafvsctl.GSAD_HOST_ENV, "YAFVS_GSAD_HOST")
        self.assertEqual(yafvsctl.GSAD_HOSTS_ENV, "YAFVS_GSAD_HOSTS")
        self.assertEqual(yafvsctl.YAFVS_API_CONTAINER_PORT, "9080")
        self.assertEqual(yafvsctl.YAFVS_API_DIRECT_CONTAINER_PORT, "9081")
        self.assertEqual(yafvsctl.YAFVS_API_DIRECT_DEFAULT_HOST, "127.0.0.1")
        self.assertEqual(yafvsctl.YAFVS_API_DIRECT_DEFAULT_PORT, "19080")
        self.assertEqual(yafvsctl.YAFVS_API_BEARER_TOKEN_MIN_LENGTH, 32)
        self.assertEqual(yafvsctl.YAFVS_API_OPERATOR_UUID_ENV, "YAFVS_API_OPERATOR_UUID")
        self.assertEqual(yafvsctl.YAFVS_API_OPERATOR_NAME_ENV, "YAFVS_API_OPERATOR_NAME")
        self.assertEqual(yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV, "YAFVS_API_DIRECT_WRITE_CONTROL")
        self.assertEqual(yafvsctl.DEV_ADMIN_USER, "admin")
        self.assertEqual(yafvsctl.DEV_ADMIN_PASSWORD, "admin")

    def test_runtime_gsa_freshness_warns_for_stale_static_assets(self):
        original_state = yafvsctl.docker_container_state
        try:
            yafvsctl.docker_container_state = lambda _root, _service: None
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "TurboVAS"
                source = root / "components" / "gsa" / "src" / "main.tsx"
                staged = root / yafvsctl.GSA_PRODUCTION_BUILD_PATH / "index.html"
                source.parent.mkdir(parents=True)
                staged.parent.mkdir(parents=True)
                source.write_text("console.log('new');\n", encoding="utf-8")
                staged.write_text("<div id='app'></div>", encoding="utf-8")
                os.utime(staged, (1000, 1000))
                os.utime(source, (2000, 2000))
                findings = yafvsctl.runtime_gsa_freshness_findings(root)
        finally:
            yafvsctl.docker_container_state = original_state

        stale = [finding for finding in findings if finding["check"] == "gsa.static-freshness"]
        self.assertEqual(stale[0]["status"], "warn")
        self.assertEqual(stale[0]["details"]["latest_source_path"], "components/gsa/src")
        self.assertEqual(stale[0]["details"]["latest_build_path"], yafvsctl.GSA_PRODUCTION_BUILD_PATH)

    def test_runtime_gsa_freshness_ignores_test_only_source_changes(self):
        original_state = yafvsctl.docker_container_state
        try:
            yafvsctl.docker_container_state = lambda _root, _service: None
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "TurboVAS"
                source = root / "components" / "gsa" / "src" / "web" / "pages" / "tasks" / "__tests__" / "Component.test.tsx"
                staged = root / yafvsctl.GSA_PRODUCTION_BUILD_PATH / "index.html"
                source.parent.mkdir(parents=True)
                staged.parent.mkdir(parents=True)
                source.write_text("test('new');\n", encoding="utf-8")
                staged.write_text("<div id='app'></div>", encoding="utf-8")
                os.utime(staged, (1000, 1000))
                os.utime(source, (2000, 2000))
                findings = yafvsctl.runtime_gsa_freshness_findings(root)
        finally:
            yafvsctl.docker_container_state = original_state

        stale = [finding for finding in findings if finding["check"] == "gsa.static-freshness"]
        self.assertEqual(stale[0]["status"], "pass")

    def test_runtime_gsa_freshness_warns_for_stale_gsad_container(self):
        original_state = yafvsctl.docker_container_state
        try:
            yafvsctl.docker_container_state = lambda _root, _service: {"container_id": "cid", "StartedAt": "2026-01-01T00:00:00Z"}
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "TurboVAS"
                build = root / "build" / "gsad" / "src" / "gsad"
                build.parent.mkdir(parents=True)
                build.write_text("binary", encoding="utf-8")
                os.utime(build, (2000000000, 2000000000))
                findings = yafvsctl.runtime_gsa_freshness_findings(root)
        finally:
            yafvsctl.docker_container_state = original_state

        stale = [finding for finding in findings if finding["check"] == "gsad.runtime-freshness"]
        self.assertEqual(stale[0]["status"], "warn")
        self.assertEqual(stale[0]["details"]["latest_gsad_build_path"], "build/gsad/src/gsad")

    def test_runtime_secret_reader_rejects_crlf_and_multiline_values(self):
        for content in ("secret\r\n", "first\nsecond\n", "\n"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "TurboVAS"
                root.mkdir()
                path = yafvsctl.runtime_secret_path(root, "example")
                yafvsctl.write_private_text(path, content)
                with self.assertRaises(ValueError):
                    yafvsctl.read_or_create_runtime_secret(root, "example")

    def test_private_writer_atomically_replaces_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            target = Path(tmp) / "target"
            target.write_text("outside\n", encoding="utf-8")
            target.chmod(0o600)
            secret_path = yafvsctl.runtime_secret_path(root, "example")
            secret_path.parent.mkdir(parents=True)
            secret_path.parent.chmod(0o700)
            secret_path.symlink_to(target)

            yafvsctl.write_private_text(secret_path, "replacement\n")

            self.assertFalse(secret_path.is_symlink())
            self.assertEqual(
                secret_path.read_text(encoding="utf-8"), "replacement\n"
            )
            self.assertEqual(target.read_text(encoding="utf-8"), "outside\n")
            self.assertEqual(secret_path.stat().st_mode & 0o777, 0o600)

    def test_private_writer_waits_for_cross_process_directory_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            secret_path = yafvsctl.runtime_secret_path(root, "example")
            yafvsctl.write_private_text(secret_path, "before\n")
            marker = Path(tmp) / "writer-ready"
            script = (
                "import sys;"
                "from importlib.machinery import SourceFileLoader;"
                "from pathlib import Path;"
                "module=SourceFileLoader('yafvsctl',sys.argv[1]).load_module();"
                "Path(sys.argv[3]).write_text('ready',encoding='utf-8');"
                "module.write_private_text(Path(sys.argv[2]),'after\\n')"
            )
            process = None
            with yafvsctl.locked_private_directory(secret_path.parent):
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        script,
                        str(YAFVSCTL_PATH),
                        str(secret_path),
                        str(marker),
                    ]
                )
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                time.sleep(0.1)
                self.assertIsNone(process.poll())
                self.assertEqual(
                    secret_path.read_text(encoding="utf-8"), "before\n"
                )
            self.assertEqual(process.wait(timeout=5), 0)
            self.assertEqual(
                secret_path.read_text(encoding="utf-8"), "after\n"
            )

    def test_short_secret_redaction_preserves_benign_identifier_names(self):
        text = '{"admin_uuid":"kept", "created_by":"admin", "check":"runtime.admin-secret", "flag":"admin-secret", "user":"admin"}'
        redacted = yafvsctl.redact_text(text, ["admin"])
        self.assertIn('"admin_uuid"', redacted)
        self.assertIn('"runtime.admin-secret"', redacted)
        self.assertIn('"admin-secret"', redacted)
        self.assertIn('"created_by":"[redacted]"', redacted)
        self.assertIn('"user":"[redacted]"', redacted)

    def test_short_secret_redaction_handles_log_tokens_without_path_mangling(self):
        text = "login admin failed; username=admin; home=/home/admin; key=admin_uuid"
        redacted = yafvsctl.redact_text(text, ["admin"])
        self.assertIn("login [redacted] failed", redacted)
        self.assertIn("username=[redacted]", redacted)
        self.assertIn("home=/home/admin", redacted)
        self.assertIn("key=admin_uuid", redacted)

    def test_long_secret_redaction_replaces_embedded_token(self):
        secret = "long-generated-token"
        text = f"prefix-{secret}-suffix token={secret}"
        redacted = yafvsctl.redact_text(text, [secret])
        self.assertEqual(redacted.count("[redacted]"), 2)
        self.assertNotIn(secret, redacted)

    def test_output_tail_uses_safe_secret_redaction(self):
        output = "first\nadmin_uuid=kept\npassword=admin\n"
        self.assertEqual(
            yafvsctl.output_tail(output, lines=2, secrets_to_redact=["admin"]),
            ["admin_uuid=kept", "password=[redacted]"],
        )

    def test_redaction_ignores_empty_secrets(self):
        self.assertEqual(yafvsctl.redact_text("username=admin", [""]), "username=admin")

    def test_runtime_dirs_include_application_state(self):
        self.assertIn("certs/CA", yafvsctl.RUNTIME_DIRS)
        self.assertIn("certs/private/CA", yafvsctl.RUNTIME_DIRS)
        self.assertIn("secrets", yafvsctl.RUNTIME_DIRS)
        self.assertIn("mosquitto/secrets", yafvsctl.RUNTIME_DIRS)
        self.assertIn("state/feed-gnupg", yafvsctl.RUNTIME_DIRS)
        self.assertIn("state/gvmd-bind-files", yafvsctl.RUNTIME_DIRS)
        self.assertNotIn("state/gvmd", yafvsctl.RUNTIME_DIRS)
        self.assertIn("state/ospd", yafvsctl.RUNTIME_DIRS)
        self.assertIn("state/ospd/result-spool", yafvsctl.RUNTIME_DIRS)
        self.assertIn("redis-openvas", yafvsctl.RUNTIME_DIRS)
        self.assertIn("run/gvmd-gmp", yafvsctl.RUNTIME_DIRS)
        self.assertIn("run/gvmd-control", yafvsctl.RUNTIME_DIRS)
        self.assertIn("run/gvmd", yafvsctl.RUNTIME_DIRS)
        self.assertIn("run/gsad", yafvsctl.RUNTIME_DIRS)
        self.assertIn("run/ospd", yafvsctl.RUNTIME_DIRS)
        self.assertIn("run/notus", yafvsctl.RUNTIME_DIRS)
        self.assertIn("run/redis-openvas", yafvsctl.RUNTIME_DIRS)
        self.assertIn("logs/notus", yafvsctl.RUNTIME_DIRS)
        self.assertIn("feeds/notus/products", yafvsctl.RUNTIME_DIRS)

    def test_gvmd_runtime_state_seed_copies_persistent_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            source = root / "build" / "var" / "lib" / "gvm" / "gvmd"
            runtime_state = Path(tmp) / "YAFVS-runtime" / "state"
            (source / "gnupg").mkdir(parents=True)
            runtime_state.mkdir(parents=True, mode=0o700)
            (runtime_state / "gvmd-bind-files").mkdir(mode=0o700)
            (source / "gnupg" / "private.key").write_text("key", encoding="utf-8")
            (source / "gvm-serving").write_text("", encoding="utf-8")

            with unittest.mock.patch.object(yafvsctl, "container_running", return_value=False):
                finding = yafvsctl.seed_gvmd_runtime_state(root)
            destination = Path(tmp) / "YAFVS-runtime" / "state" / "gvmd"
            key_text = (destination / "gnupg" / "private.key").read_text(encoding="utf-8")
            transient_exists = (destination / "gvm-serving").exists()
            semaphore_exists = (runtime_state / "gvmd-bind-files" / "gvmd.sem").is_file()

        self.assertEqual(finding["status"], "pass")
        self.assertIn("gnupg/private.key", finding["details"]["copied"])
        self.assertIn("gvm-serving", finding["details"]["skipped_transient"])
        self.assertEqual(key_text, "key")
        self.assertFalse(transient_exists)
        self.assertTrue(semaphore_exists)

    def test_gvmd_runtime_state_seed_missing_build_state_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            state = Path(tmp) / "YAFVS-runtime" / "state"
            state.mkdir(parents=True, mode=0o700)
            (state / "gvmd-bind-files").mkdir(mode=0o700)

            finding = yafvsctl.seed_gvmd_runtime_state(root)

        self.assertEqual(finding["status"], "pass")
        self.assertEqual(finding["check"], "runtime.gvmd-state-seed")
        self.assertIn("no runtime-state seed was needed", finding["message"])

    def test_gvmd_runtime_state_seed_rejects_symlink_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            state = Path(tmp) / "YAFVS-runtime" / "state"
            external = Path(tmp) / "external-state"
            root.mkdir()
            state.mkdir(parents=True, mode=0o700)
            (state / "gvmd-bind-files").mkdir(mode=0o700)
            external.mkdir()
            (state / "gvmd").symlink_to(external, target_is_directory=True)

            finding = yafvsctl.seed_gvmd_runtime_state(root)

        self.assertEqual(finding["status"], "fail")
        self.assertIn("symlink or special file", finding["message"])

    def test_gvmd_runtime_state_seed_rejects_symlink_semaphore_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            state = Path(tmp) / "YAFVS-runtime" / "state"
            bind_parent = state / "gvmd-bind-files"
            external = Path(tmp) / "external-sem"
            root.mkdir()
            (state / "gvmd").mkdir(parents=True, mode=0o700)
            bind_parent.mkdir(mode=0o700)
            external.write_text("external", encoding="utf-8")
            (bind_parent / "gvmd.sem").symlink_to(external)

            finding = yafvsctl.seed_gvmd_runtime_state(root)
            external_text = external.read_text(encoding="utf-8")

        self.assertEqual(finding["status"], "fail")
        self.assertIn("bind file is a symlink or special file", finding["message"])
        self.assertEqual(external_text, "external")

    def test_gvmd_runtime_state_seed_rejects_bind_parent_nested_under_app_writable_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            state = Path(tmp) / "YAFVS-runtime" / "state"
            root.mkdir()
            (state / "gvmd-bind-files").mkdir(parents=True, mode=0o700)

            with unittest.mock.patch.object(yafvsctl, "app_writable_runtime_sources", return_value=(state,)):
                finding = yafvsctl.seed_gvmd_runtime_state(root)

        self.assertEqual(finding["status"], "fail")
        self.assertIn("nested under app-writable source", finding["message"])

    def test_gvmd_runtime_state_seed_rejects_live_gvmd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            source = root / "build" / "var" / "lib" / "gvm" / "gvmd"
            state = Path(tmp) / "YAFVS-runtime" / "state"
            source.mkdir(parents=True)
            state.mkdir(parents=True, mode=0o700)
            (state / "gvmd-bind-files").mkdir(mode=0o700)
            (source / "persistent-state").write_text("state", encoding="utf-8")

            with unittest.mock.patch.object(yafvsctl, "container_running", return_value=True):
                finding = yafvsctl.seed_gvmd_runtime_state(root)

            destination_exists = (state / "gvmd").exists()
            temporary_entries = list(state.glob(".gvmd-seed-*"))

        self.assertEqual(finding["status"], "fail")
        self.assertIn("must be stopped", finding["message"])
        self.assertFalse(destination_exists)
        self.assertEqual(temporary_entries, [])

    def test_gvmd_runtime_state_seed_rejects_special_source_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            source = root / "build" / "var" / "lib" / "gvm" / "gvmd"
            state = Path(tmp) / "YAFVS-runtime" / "state"
            source.mkdir(parents=True)
            state.mkdir(parents=True, mode=0o700)
            (state / "gvmd-bind-files").mkdir(mode=0o700)
            os.mkfifo(source / "unexpected-fifo")

            with unittest.mock.patch.object(yafvsctl, "container_running", return_value=False):
                finding = yafvsctl.seed_gvmd_runtime_state(root)

            destination_exists = (state / "gvmd").exists()
            temporary_entries = list(state.glob(".gvmd-seed-*"))

        self.assertEqual(finding["status"], "fail")
        self.assertIn("symlink or special file", finding["message"])
        self.assertFalse(destination_exists)
        self.assertEqual(temporary_entries, [])

    def test_gvmd_runtime_state_seed_existing_directory_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            source = root / "build" / "var" / "lib" / "gvm" / "gvmd"
            destination = Path(tmp) / "YAFVS-runtime" / "state" / "gvmd"
            source.mkdir(parents=True)
            destination.mkdir(parents=True, mode=0o700)
            (destination.parent / "gvmd-bind-files").mkdir(mode=0o700)
            (source / "new-state").write_text("new", encoding="utf-8")
            (destination / "legacy-state").write_text("legacy", encoding="utf-8")

            with unittest.mock.patch.object(yafvsctl, "container_running") as running:
                finding = yafvsctl.seed_gvmd_runtime_state(root)

            legacy = (destination / "legacy-state").read_text(encoding="utf-8")
            new_exists = (destination / "new-state").exists()

        self.assertEqual(finding["status"], "pass")
        self.assertIn("left unchanged", finding["message"])
        self.assertEqual(legacy, "legacy")
        self.assertFalse(new_exists)
        running.assert_not_called()

    def test_compose_command_uses_dev_compose_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = yafvsctl.compose_command(root, "ps")
            self.assertEqual(command[:4], ["docker", "compose", "-f", str(root / "compose" / "dev.yaml")])
            self.assertEqual(command[-1], "ps")

    def test_compose_command_adds_gsad_ports_override_for_multiple_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compose").mkdir()
            (root / "compose" / "dev.yaml").write_text("services: {}\n", encoding="utf-8")
            original = yafvsctl.os.environ.get(yafvsctl.GSAD_HOSTS_ENV)
            try:
                yafvsctl.os.environ[yafvsctl.GSAD_HOSTS_ENV] = "192.168.178.42,100.80.139.13"
                command = yafvsctl.compose_command(root, "config")
            finally:
                if original is None:
                    yafvsctl.os.environ.pop(yafvsctl.GSAD_HOSTS_ENV, None)
                else:
                    yafvsctl.os.environ[yafvsctl.GSAD_HOSTS_ENV] = original
            override = yafvsctl.gsad_ports_override_file(root)
            self.assertIn(str(override), command)
            text = override.read_text(encoding="utf-8")
            self.assertIn("ports: !override", text)
            self.assertIn('"192.168.178.42:19392:9392"', text)
            self.assertIn('"100.80.139.13:19392:9392"', text)

    def test_direct_native_api_override_is_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compose").mkdir()
            (root / "compose" / "dev.yaml").write_text("services: {}\n", encoding="utf-8")
            token_only_env = yafvsctl.runtime_env(root)
            token_only_env[yafvsctl.YAFVS_API_BEARER_TOKEN_ENV] = "secret-token"
            self.assertFalse(yafvsctl.native_api_direct_requested(token_only_env))
            write_control_only_env = yafvsctl.runtime_env(root)
            write_control_only_env[yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV] = "1"
            self.assertFalse(yafvsctl.native_api_direct_requested(write_control_only_env))

            direct_env = dict(token_only_env)
            direct_env[yafvsctl.YAFVS_API_DIRECT_ENV] = "1"
            command = yafvsctl.compose_command(root, "config", env=direct_env)
            override = yafvsctl.native_api_direct_ports_override_file(root)
            self.assertIn(str(override), command)
            text = override.read_text(encoding="utf-8")
            self.assertIn('"127.0.0.1:19080:9081"', text)
            self.assertNotIn(yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV, text)
            self.assertNotIn("volumes:", text)

            file_env = yafvsctl.runtime_env(root)
            file_env.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV, None)
            file_env.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV, None)
            file_env[yafvsctl.YAFVS_API_DIRECT_ENV] = "1"
            command = yafvsctl.compose_command(root, "config", env=file_env)
            self.assertIn(str(override), command)
            text = override.read_text(encoding="utf-8")
            secret_path = yafvsctl.runtime_secret_path(root, yafvsctl.YAFVS_API_BEARER_TOKEN_SECRET)
            self.assertIn(yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV, text)
            self.assertIn(str(secret_path), text)
            self.assertIn(yafvsctl.YAFVS_API_BEARER_TOKEN_CONTAINER_FILE, text)
            self.assertIn("read_only: true", text)
            self.assertNotIn(secret_path.read_text(encoding="utf-8").strip(), text)

    def test_direct_native_api_runtime_env_uses_token_file_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            original_token = yafvsctl.os.environ.get(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV)
            original_token_file = yafvsctl.os.environ.get(yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV)
            try:
                yafvsctl.os.environ.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV, None)
                yafvsctl.os.environ.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV, None)
                env = yafvsctl.native_api_direct_runtime_env(root)
            finally:
                if original_token is None:
                    yafvsctl.os.environ.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV, None)
                else:
                    yafvsctl.os.environ[yafvsctl.YAFVS_API_BEARER_TOKEN_ENV] = original_token
                if original_token_file is None:
                    yafvsctl.os.environ.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV, None)
                else:
                    yafvsctl.os.environ[yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV] = original_token_file

            self.assertNotIn(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV, env)
            self.assertEqual(env[yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV], yafvsctl.YAFVS_API_BEARER_TOKEN_CONTAINER_FILE)
            self.assertTrue(env[yafvsctl.YAFVS_API_BROWSER_PROXY_SECRET_ENV])
            token = yafvsctl.native_api_direct_bearer_token(root, env)
            self.assertTrue(yafvsctl.direct_api_bearer_token_is_acceptable(token))

    def test_direct_native_api_runtime_env_preserves_configured_token_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            token_file = Path(tmp) / "custom-token"
            token_file.write_text("0123456789abcdef0123456789abcdef", encoding="utf-8")
            original_token = yafvsctl.os.environ.get(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV)
            original_token_file = yafvsctl.os.environ.get(yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV)
            try:
                yafvsctl.os.environ.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV, None)
                yafvsctl.os.environ[yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV] = str(token_file)
                env = yafvsctl.native_api_direct_runtime_env(root)
            finally:
                if original_token is None:
                    yafvsctl.os.environ.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV, None)
                else:
                    yafvsctl.os.environ[yafvsctl.YAFVS_API_BEARER_TOKEN_ENV] = original_token
                if original_token_file is None:
                    yafvsctl.os.environ.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV, None)
                else:
                    yafvsctl.os.environ[yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV] = original_token_file

            self.assertNotIn(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV, env)
            self.assertEqual(env[yafvsctl.YAFVS_API_BEARER_TOKEN_FILE_ENV], str(token_file))
            self.assertEqual(yafvsctl.native_api_direct_bearer_token(root, env), "0123456789abcdef0123456789abcdef")

    def test_direct_native_api_config_shape_validation(self):
        valid = {
            yafvsctl.YAFVS_API_DIRECT_HOST_ENV: "127.0.0.1",
            yafvsctl.YAFVS_API_DIRECT_PORT_ENV: "19080",
            yafvsctl.YAFVS_API_DIRECT_BIND_ENV: "0.0.0.0:9081",
            yafvsctl.YAFVS_API_OPERATOR_UUID_ENV: "12345678-1234-1234-1234-123456789abc",
            yafvsctl.YAFVS_API_OPERATOR_NAME_ENV: "admin",
        }
        self.assertEqual(yafvsctl.native_api_direct_config_errors(valid), ())
        write_control = dict(valid)
        write_control[yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV] = "1"
        self.assertEqual(yafvsctl.native_api_direct_config_errors(write_control), ())
        ipv6 = dict(valid)
        ipv6[yafvsctl.YAFVS_API_DIRECT_HOST_ENV] = "[::1]"
        ipv6[yafvsctl.YAFVS_API_DIRECT_BIND_ENV] = "[::]:9081"
        self.assertEqual(yafvsctl.native_api_direct_config_errors(ipv6), ())

        cases = [
            (yafvsctl.YAFVS_API_DIRECT_HOST_ENV, "http://127.0.0.1"),
            (yafvsctl.YAFVS_API_DIRECT_HOST_ENV, "127.0.0.1,100.80.139.13"),
            (yafvsctl.YAFVS_API_DIRECT_HOST_ENV, "::1"),
            (yafvsctl.YAFVS_API_DIRECT_PORT_ENV, "0"),
            (yafvsctl.YAFVS_API_DIRECT_PORT_ENV, "65536"),
            (yafvsctl.YAFVS_API_DIRECT_PORT_ENV, "19 080"),
            (yafvsctl.YAFVS_API_DIRECT_BIND_ENV, "0.0.0.0"),
            (yafvsctl.YAFVS_API_DIRECT_BIND_ENV, "0.0.0.0:not-a-port"),
            (yafvsctl.YAFVS_API_DIRECT_BIND_ENV, "0.0.0.0:9999"),
            (yafvsctl.YAFVS_API_OPERATOR_UUID_ENV, "not-a-uuid"),
            (yafvsctl.YAFVS_API_OPERATOR_NAME_ENV, "admin\nroot"),
            (yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV, "maybe"),
        ]
        for env_name, value in cases:
            with self.subTest(env_name=env_name, value=value):
                env = dict(valid)
                env[env_name] = value
                self.assertTrue(yafvsctl.native_api_direct_config_errors(env))

        name_without_uuid = dict(valid)
        name_without_uuid.pop(yafvsctl.YAFVS_API_OPERATOR_UUID_ENV)
        self.assertIn(
            f"{yafvsctl.YAFVS_API_OPERATOR_NAME_ENV} requires {yafvsctl.YAFVS_API_OPERATOR_UUID_ENV}",
            yafvsctl.native_api_direct_config_errors(name_without_uuid),
        )
        write_without_uuid = dict(valid)
        write_without_uuid.pop(yafvsctl.YAFVS_API_OPERATOR_UUID_ENV)
        write_without_uuid.pop(yafvsctl.YAFVS_API_OPERATOR_NAME_ENV)
        write_without_uuid[yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV] = "true"
        self.assertIn(
            f"{yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV} requires {yafvsctl.YAFVS_API_OPERATOR_UUID_ENV}",
            yafvsctl.native_api_direct_config_errors(write_without_uuid),
        )

        bad_bind = dict(valid)
        bad_bind[yafvsctl.YAFVS_API_DIRECT_BIND_ENV] = "0.0.0.0:9999"
        self.assertIn(
            f"{yafvsctl.YAFVS_API_DIRECT_BIND_ENV} must use container port {yafvsctl.YAFVS_API_DIRECT_CONTAINER_PORT}",
            yafvsctl.native_api_direct_config_errors(bad_bind)[0],
        )
    def test_direct_api_bearer_token_strength_contract(self):
        self.assertEqual(yafvsctl.YAFVS_API_BEARER_TOKEN_MAX_LENGTH, 1024)
        self.assertTrue(yafvsctl.direct_api_bearer_token_is_acceptable("0123456789abcdef0123456789abcdef"))
        self.assertTrue(yafvsctl.direct_api_bearer_token_is_acceptable("A" * yafvsctl.YAFVS_API_BEARER_TOKEN_MAX_LENGTH))
        for token in (
            "short-token",
            "A" * (yafvsctl.YAFVS_API_BEARER_TOKEN_MAX_LENGTH + 1),
            "0123456789abcdef 123456789abcdef",
            "0123456789abcdef0123456789abcde\n",
        ):
            with self.subTest(token=token):
                self.assertFalse(yafvsctl.direct_api_bearer_token_is_acceptable(token))

    def test_native_api_create_cleanup_state_marks_malformed_201_and_committed_502_uncertain(self):
        malformed_201 = yafvsctl.subprocess.CompletedProcess([], 0, '{"name":"unexpected"}\n201', "")
        malformed_parsed, malformed_status = yafvsctl.parse_json_output_with_http_status(malformed_201)
        self.assertEqual(
            yafvsctl.native_api_create_cleanup_state(
                malformed_201,
                malformed_parsed,
                malformed_status,
                False,
            ),
            (True, True),
        )
        generic_503 = yafvsctl.subprocess.CompletedProcess(
            [],
            0,
            '{"error":{"code":"service_unavailable"}}\n503',
            "",
        )
        generic_parsed, generic_status = yafvsctl.parse_json_output_with_http_status(generic_503)
        self.assertEqual(
            yafvsctl.native_api_create_cleanup_state(
                generic_503,
                generic_parsed,
                generic_status,
                False,
            ),
            (False, True),
        )
        missing_status = yafvsctl.subprocess.CompletedProcess([], 0, '{}', "")
        self.assertEqual(
            yafvsctl.native_api_create_cleanup_state(
                missing_status,
                {},
                None,
                False,
            ),
            (False, True),
        )

        committed_502 = yafvsctl.subprocess.CompletedProcess(
            [],
            0,
            '{"error":{"code":"committed_response_unavailable"}}\n502',
            "",
        )
        committed_parsed, committed_status = yafvsctl.parse_json_output_with_http_status(committed_502)
        self.assertEqual(
            yafvsctl.native_api_create_cleanup_state(
                committed_502,
                committed_parsed,
                committed_status,
                False,
            ),
            (True, True),
        )
        self.assertEqual(
            yafvsctl.native_api_cleanup_identity_predicate(None, "temporary alert"),
            "name = 'temporary alert'",
        )
        self.assertEqual(
            yafvsctl.native_api_cleanup_identity_predicate(
                "11111111-1111-1111-1111-111111111111",
                "temporary override",
                value_column="text",
            ),
            "uuid = '11111111-1111-1111-1111-111111111111' AND text = 'temporary override'",
        )
        with self.assertRaisesRegex(ValueError, "not allowed"):
            yafvsctl.native_api_cleanup_identity_predicate(
                None, "value", value_column="unsafe"
            )
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("native_api_create_cleanup_state("), 4)

    def test_smb_fixture_cleanup_failure_retains_report_format_and_credential(self):
        failed_cleanup = yafvsctl.subprocess.CompletedProcess(
            ["psql"],
            0,
            "1|0\n",
            "",
        )
        with unittest.mock.patch.object(yafvsctl, "psql", return_value=failed_cleanup) as psql:
            findings = yafvsctl.native_api_direct_write_smb_fixture_cleanup(
                Path("/tmp/TurboVAS"),
                admin_uuid="11111111-1111-1111-1111-111111111111",
                smb_alert_attempted=True,
                smb_alert_name="temporary SMB alert",
                smb_report_format_cleanup_required=True,
                smb_report_format_id="22222222-2222-2222-2222-222222222222",
                smb_report_format_name="temporary SMB format",
                credential_cleanup_required=True,
                credential_create_committed=True,
                credential_id=None,
                credential_name="temporary SMB credential",
            )

        self.assertEqual(psql.call_count, 1)
        cleanup_sql = psql.call_args.args[1]
        self.assertIn("name = 'temporary SMB alert'", cleanup_sql)
        self.assertIn("owner = (SELECT id FROM operator_owner)", cleanup_sql)
        checks = {item["check"]: item for item in findings}
        self.assertEqual(checks["native-api-direct.alert-smb-write-cleanup"]["status"], "fail")
        self.assertIn("retained", checks["native-api-direct.alert-smb-report-format-cleanup"]["message"])
        self.assertIn("retained", checks["native-api-direct.credential-fixture-cleanup"]["message"])

    def test_smb_fixture_cleanup_orders_alert_format_then_owner_name_credential(self):
        responses = (
            yafvsctl.subprocess.CompletedProcess(["psql"], 0, "0|0\n", ""),
            yafvsctl.subprocess.CompletedProcess(["psql"], 0, "1\n", ""),
            yafvsctl.subprocess.CompletedProcess(["psql"], 0, "1\n", ""),
        )
        with unittest.mock.patch.object(yafvsctl, "psql", side_effect=responses) as psql:
            findings = yafvsctl.native_api_direct_write_smb_fixture_cleanup(
                Path("/tmp/TurboVAS"),
                admin_uuid="11111111-1111-1111-1111-111111111111",
                smb_alert_attempted=True,
                smb_alert_name="temporary SMB alert",
                smb_report_format_cleanup_required=True,
                smb_report_format_id="22222222-2222-2222-2222-222222222222",
                smb_report_format_name="temporary SMB format",
                credential_cleanup_required=True,
                credential_create_committed=True,
                credential_id=None,
                credential_name="temporary SMB credential",
            )

        sql_calls = [call.args[1] for call in psql.call_args_list]
        self.assertIn("DELETE FROM alerts", sql_calls[0])
        self.assertIn("DELETE FROM report_formats", sql_calls[1])
        self.assertIn("DELETE FROM credentials", sql_calls[2])
        self.assertIn("name = 'temporary SMB credential'", sql_calls[2])
        self.assertIn("owner = (SELECT id FROM operator_owner)", sql_calls[2])
        self.assertTrue(all(item["status"] == "pass" for item in findings))

    def test_direct_admin_operator_uuid_uses_database_attestation(self):
        root = Path("/tmp/TurboVAS")
        operator_uuid = "11111111-1111-1111-1111-111111111111"
        users = yafvsctl.subprocess.CompletedProcess(
            [], 0, operator_uuid + "\n", ""
        )

        with unittest.mock.patch.object(
            yafvsctl, "psql", return_value=users
        ) as psql:
            result, parsed_uuid = yafvsctl.native_api_direct_admin_operator_uuid(root)

        self.assertIs(result, users)
        self.assertEqual(parsed_uuid, operator_uuid)
        psql.assert_called_once_with(
            root,
            "SELECT COALESCE((SELECT uuid::text FROM users WHERE name = 'admin' "
            "ORDER BY id LIMIT 1), 'missing');",
        )

    def test_direct_admin_operator_uuid_rejects_non_uuid_database_output(self):
        root = Path("/tmp/TurboVAS")
        users = yafvsctl.subprocess.CompletedProcess([], 0, "missing\n", "")

        with unittest.mock.patch.object(yafvsctl, "psql", return_value=users):
            _, parsed_uuid = yafvsctl.native_api_direct_admin_operator_uuid(root)

        self.assertIsNone(parsed_uuid)

    def test_direct_native_api_write_smoke_uses_guarded_operator_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            token = "0123456789abcdef0123456789abcdef"
            operator_uuid = "11111111-1111-1111-1111-111111111111"
            scope_uuid = "22222222-2222-2222-2222-222222222222"
            tag_uuid = "33333333-3333-3333-3333-333333333333"
            tag_clone_uuid = "33333333-3333-3333-3333-333333333334"
            report_format_uuid = "44444444-4444-4444-4444-444444444444"
            port_list_uuid = "66666666-6666-6666-6666-666666666666"
            temp_port_list_uuid = "66666666-6666-6666-6666-666666666667"
            temp_port_list_clone_uuid = "66666666-6666-6666-6666-666666666668"
            temp_port_range_uuid = "66666666-6666-6666-6666-666666666669"
            temp_port_list_ranges = {"value": []}
            temp_port_list_live = {"value": True}
            schedule_uuid = "77777777-7777-7777-7777-777777777777"
            schedule_clone_uuid = "77777777-7777-7777-7777-777777777778"
            scan_config_uuid = "77777777-7777-7777-7777-777777777779"
            scan_config_clone_uuid = "77777777-7777-7777-7777-777777777780"
            scan_config_import_uuid = "77777777-7777-7777-7777-777777777783"
            override_uuid = "77777777-7777-7777-7777-777777777781"
            override_clone_uuid = "77777777-7777-7777-7777-777777777782"
            override_nvt_id = "1.3.6.1.4.1.25623.1.0.100000"
            filter_uuid = "88888888-8888-8888-8888-888888888888"
            filter_clone_uuid = "88888888-8888-8888-8888-888888888889"
            alert_uuid = "99999999-9999-9999-9999-999999999999"
            alert_concurrent_uuid = "99999999-9999-4999-8999-999999999997"
            alert_tag_uuid = "99999999-9999-9999-9999-999999999998"
            credential_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            credential_helper_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaab"
            target_uuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
            target_clone_uuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbc"
            target_create_with_credential_uuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbd"
            target_live = {"value": True}
            target_clone_live = {"value": True}
            target_updated_comment = "YAFVS direct write smoke updated target metadata"
            scanner_uuid = "dddddddd-dddd-dddd-dddd-dddddddddddd"
            task_uuid = "cccccccc-cccc-cccc-cccc-cccccccccccc"
            task_clone_uuid = "cccccccc-cccc-cccc-cccc-cccccccccccd"
            task_schedule_uuid = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
            task_alert_uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
            task_tag_uuid = "abababab-abab-4bab-8bab-abababababab"
            task_updated_comment = "YAFVS direct write smoke updated task metadata"
            original_token = yafvsctl.os.environ.get(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV)
            commands: list[tuple[str, ...]] = []
            envs: list[dict[str, str]] = []
            probes: list[tuple[str, str]] = []
            tag_resource_count = {"value": 0}
            tag_deleted = {"value": False}
            alert_tag_resource_count = {"value": 0}
            alert_tag_deleted = {"value": False}
            alert_concurrent_calls = {"value": 0}
            alert_definition = {"value": None}
            scan_config_live = {"value": True}
            scan_config_import_live = {"value": False}
            scan_config_import_document = {"value": None}
            scan_config_definition = {"comment": "", "name": ""}
            scan_config_family_selected = {"value": True}
            scan_config_family_growing = {"value": True}
            scan_config_scanner_preference = {"configured": False, "value": "1"}
            scan_config_secret_preference = {"configured": False}
            schedule_live = {"value": True}
            schedule_fixture = {"comment": "", "icalendar": "", "timezone": ""}
            target_in_use = {"value": False}
            target_credential_link_count = {"value": 0}
            task_clone_live = {"value": False}
            task_configuration_replaced = {"value": False}
            override_source_live = {"value": False}
            override_clone_live = {"value": False}

            def fake_run_command(command, *_args, **kwargs):
                commands.append(tuple(command))
                env = kwargs.get("env")
                if isinstance(env, dict):
                    envs.append(dict(env))
                command_text = " ".join(command)
                if command and command[0] == "cargo" and "native-credentials-from-csv" in command:
                    self.assertIn("--allow-write-control", command)
                    self.assertIn("--status-only", command)
                    self.assertIn("--json", command)
                    return yafvsctl.subprocess.CompletedProcess(
                        command,
                        0,
                        json.dumps(
                            {
                                "status": "pass",
                                "summary": "Native credential CSV operation completed.",
                                "findings": [
                                    yafvsctl.finding(
                                        "pass",
                                        "native-credentials-from-csv.status-only",
                                        "Native credential CSV operation passed; details summarized.",
                                    )
                                ],
                                "artifacts": [],
                                "metadata": {
                                    "command": "native-credentials-from-csv",
                                    "generated_at": "2026-07-19T00:00:00+00:00",
                                    "repo_root": str(root),
                                    "head": None,
                                },
                                "details": {
                                    "created_credential_count": 1,
                                },
                            }
                        ),
                        "",
                    )
                if command and command[0] == "cargo" and "native-bulk-modify-schedules" in command:
                    self.assertIn("--filter", command)
                    self.assertIn("--max-schedules", command)
                    self.assertIn("1", command)
                    self.assertIn("--timezone", command)
                    self.assertIn("UTC", command)
                    self.assertIn("--json", command)
                    dry_run = "--dry-run" in command
                    if not dry_run:
                        self.assertIn("--allow-write-control", command)
                        self.assertIn("--confirm-snapshot", command)
                    details = {
                        "matched_count": 1,
                        "schedule_ids": [schedule_uuid],
                        "snapshot_sha256": "a" * 64,
                        "attempted_count": 0 if dry_run else 1,
                        "succeeded_count": 0 if dry_run else 1,
                        "failed_count": 0,
                        "unattempted_count": 0,
                    }
                    return yafvsctl.subprocess.CompletedProcess(
                        command,
                        0,
                        json.dumps(
                            {
                                "status": "pass",
                                "summary": "Native bulk schedule operation completed.",
                                "findings": [
                                    yafvsctl.finding(
                                        "pass",
                                        "native-bulk-modify-schedules.status-only",
                                        "Native bulk schedule operation passed.",
                                    )
                                ],
                                "artifacts": [],
                                "metadata": {
                                    "command": "native-bulk-modify-schedules",
                                    "generated_at": "2026-07-19T00:00:00+00:00",
                                    "repo_root": str(root),
                                    "head": None,
                                },
                                "details": details,
                            }
                        ),
                        "",
                    )
                if "inserted_schedule AS" in command_text and "inserted_alert AS" in command_text and "inserted_tag AS" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(
                        command,
                        0,
                        f"{task_schedule_uuid}|{task_alert_uuid}|{task_tag_uuid}\n",
                        "",
                    )
                if "INSERT INTO report_formats" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(command, 0, report_format_uuid + "\n", "")
                if "INSERT INTO filters" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(command, 0, filter_uuid + "\n", "")
                if "INSERT INTO schedules" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(command, 0, schedule_uuid + "\n", "")
                if "INSERT INTO configs" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(command, 0, scan_config_uuid + "\n", "")
                if "INSERT INTO port_lists" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(command, 0, temp_port_list_uuid + "\n", "")
                if "INSERT INTO alerts" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(command, 0, alert_uuid + "\n", "")
                if "INSERT INTO credentials" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(command, 0, credential_uuid + "\n", "")
                if "INSERT INTO targets" in command_text:
                    return yafvsctl.subprocess.CompletedProcess(command, 0, target_uuid + "\n", "")
                if any(part == "psql" for part in command):
                    if "fixed-override-smoke-cleanup" in command_text:
                        self.assertIn("resource_type = 'override'", command_text)
                        self.assertIn("owner = (SELECT id FROM operator_owner)", command_text)
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0|0\n", "")
                    if "fixed-override-smoke-residue" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0|0\n", "")
                    if "md5(string_agg" in command_text and "credentials_data" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "credential-secret-checksum\n", "")
                    if "SELECT uuid FROM credentials" in command_text and "-csv-helper" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, credential_helper_uuid + "\n", "")
                    if "coalesce(hosts, '') || '|' || coalesce(exclude_hosts, '') || '|' || coalesce(alive_test::text" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "192.0.2.42, 192.0.2.43|192.0.2.43|16|1|1|0|0\n", "")
                    if "md5" in command_text and "targets_login_data" in command_text and "FROM targets" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "target-adjacent-state-checksum\n", "")
                    if "SELECT count(*)::text || '|' || coalesce(max(port)::text" in command_text:
                        if target_create_with_credential_uuid in command_text:
                            return yafvsctl.subprocess.CompletedProcess(command, 0, "1|2222\n", "")
                        value = "1|22" if target_credential_link_count["value"] else "0|"
                        return yafvsctl.subprocess.CompletedProcess(command, 0, value + "\n", "")
                    if "SELECT count(*)::text FROM targets_login_data" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, str(target_credential_link_count["value"]) + "\n", "")
                    if "SELECT alive_test::text FROM targets" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "16\n", "")
                    if "SELECT allow_simultaneous_ips::text" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0|1|1\n", "")
                    if "SELECT pl.uuid::text FROM targets" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, port_list_uuid + "\n", "")
                    if "SELECT coalesce(port_list::text" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "42\n", "")
                    if "SELECT coalesce(hosts, '') || '|' || coalesce(exclude_hosts, '') FROM targets" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "192.0.2.42, 192.0.2.43|192.0.2.43\n", "")
                    if "FROM tasks" in command_text and "md5" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "task-adjacent-state-checksum\n", "")
                    if "FROM tasks t LEFT JOIN schedules s" in command_text:
                        if "assets_apply_overrides" in command_text:
                            return yafvsctl.subprocess.CompletedProcess(
                                command,
                                0,
                                f"{task_schedule_uuid}|2|1893456000|sequential|1|yes|6|10|60|0|0\n",
                                "",
                            )
                        relation_state = (
                            f"{task_schedule_uuid}|2|1893456000|sequential|1"
                            if task_configuration_replaced["value"]
                            else f"{task_schedule_uuid}|1|1893456000|reverse|1"
                        )
                        return yafvsctl.subprocess.CompletedProcess(
                            command,
                            0,
                            relation_state + "\n",
                            "",
                        )
                    if "FROM tag_resources tr" in command_text and task_tag_uuid in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "1\n", "")
                    if "FROM scan_queue q JOIN reports r" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0|0\n", "")
                    if "DELETE FROM credentials" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "1\n", "")
                    if "DELETE FROM targets" in command_text and "DELETE FROM targets_trash" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0|0\n", "")
                    if "DELETE FROM tasks" in command_text:
                        target_in_use["value"] = False
                        task_clone_live["value"] = False
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "2\n", "")
                    if "fixed-task-smoke-residue" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0\n", "")
                    if "deleted_alert AS" in command_text and "deleted_schedule AS" in command_text and "deleted_tag AS" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "1|1|1\n", "")
                    if "DELETE FROM alerts" in command_text and "-concurrent" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "1\n", "")
                    if "SELECT string_agg(name, ',' ORDER BY name) FROM alert_method_data" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "smb_credential,smb_file_path,smb_report_format,smb_share_path\n", "")
                    if "DELETE FROM alerts" in command_text and "smb-alert" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0|0\n", "")
                    if "DELETE FROM alerts" in command_text:
                        self.assertIn("DELETE FROM tags_trash", command_text)
                        self.assertIn("LOCK TABLE users IN ROW SHARE MODE", command_text)
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "1|1\n", "")
                    if "DELETE FROM schedules_trash" in command_text:
                        schedule_live["value"] = False
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0\n", "")
                    if "DELETE FROM configs" in command_text:
                        scan_config_live["value"] = False
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "1\n", "")
                    if "DELETE FROM filters_trash" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0\n", "")
                    if "DELETE FROM port_ranges_trash" in command_text:
                        return yafvsctl.subprocess.CompletedProcess(command, 0, "0\n", "")
                    return yafvsctl.subprocess.CompletedProcess(command, 0, "1\n", "")
                return yafvsctl.subprocess.CompletedProcess(command, 0, "", "")

            def fake_direct_curl(_root, path, *, method="GET", body=None, **_kwargs):
                probes.append((method, path))
                if method == "GET" and path == "/healthz":
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"status":"ok"}\n200', "")
                if method == "GET" and path == "/api/v1/user-management/users?page_size=1":
                    return yafvsctl.subprocess.CompletedProcess(
                        [],
                        0,
                        json.dumps(
                            {
                                "items": [{"id": operator_uuid, "name": "admin"}],
                                "page": {"total": 1},
                            }
                        )
                        + "\n200",
                        "",
                    )
                if method == "GET" and path == "/api/v1/nvts?page_size=1&sort=oid":
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"items": [{"id": override_nvt_id, "oid": override_nvt_id, "name": "fixture NVT"}], "page": {"total": 1}}) + "\n200", "")
                if method == "POST" and path == "/api/v1/overrides":
                    payload = json.loads(body)
                    self.assertEqual(payload, {"nvt_id": override_nvt_id, "text": f"yafvs-direct-write-smoke-override-1-{yafvsctl.os.getpid()}", "severity": 0.0, "new_severity": 4.2, "activation": {"mode": "inactive"}})
                    override_source_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": override_uuid, "text": payload["text"], "new_severity": 4.2, "active": False}) + "\n201", "")
                if method == "PATCH" and path == f"/api/v1/overrides/{override_uuid}":
                    self.assertEqual(json.loads(body), {"new_severity": 4.3, "activation": {"mode": "always"}})
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": override_uuid, "new_severity": 4.3, "active": True}) + "\n200", "")
                if method == "POST" and path == f"/api/v1/overrides/{override_uuid}/clone":
                    self.assertEqual(json.loads(body), {})
                    override_clone_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": override_clone_uuid, "text": f"yafvs-direct-write-smoke-override-1-{yafvsctl.os.getpid()}", "new_severity": 4.3}) + "\n201", "")
                if method == "POST" and path == f"/api/v1/overrides/{override_uuid}/restore":
                    override_source_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": override_uuid, "text": f"yafvs-direct-write-smoke-override-1-{yafvsctl.os.getpid()}"}) + "\n200", "")
                if method == "DELETE" and path == f"/api/v1/overrides/{override_uuid}/trash":
                    override_source_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path == f"/api/v1/overrides/{override_clone_uuid}/trash":
                    override_clone_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path == f"/api/v1/overrides/{override_uuid}":
                    override_source_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path == f"/api/v1/overrides/{override_clone_uuid}":
                    override_clone_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path == f"/api/v1/overrides/{override_uuid}":
                    if override_source_live["value"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": override_uuid}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "GET" and path == f"/api/v1/overrides/{override_clone_uuid}":
                    if override_clone_live["value"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": override_clone_uuid}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "POST" and path == "/api/v1/scopes":
                    payload = json.loads(body)
                    self.assertEqual(payload["target_ids"], [])
                    self.assertEqual(payload["host_ids"], [])
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scope_uuid, "name": payload["name"], "comment": payload["comment"]}) + "\n201", "")
                if method == "PATCH" and path.startswith("/api/v1/scopes/"):
                    if "?" in path:
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"request_too_large"}}\n413', "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scope_uuid, "comment": "YAFVS direct write smoke updated temporary scope"}) + "\n200", "")
                if method == "DELETE" and path.startswith("/api/v1/scopes/") and body is not None:
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"request_too_large"}}\n413', "")
                if method == "DELETE" and path.startswith("/api/v1/scopes/"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith("/api/v1/scopes/"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "POST" and path == "/api/v1/alerts":
                    if body == "{":
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"bad_request"}}\n400', "")
                    payload = json.loads(body)
                    if payload["name"].endswith("-concurrent"):
                        alert_concurrent_calls["value"] += 1
                        if alert_concurrent_calls["value"] == 1:
                            return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": alert_concurrent_uuid, "name": payload["name"], "active": False}) + "\n201", "")
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict"}}\n409', "")
                    if payload.get("recipient_credential_id") == "00000000-0000-0000-0000-000000000000":
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                    if payload.get("report_format_id") == "00000000-0000-0000-0000-000000000000":
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                    if payload.get("method") == "SMB":
                        self.assertEqual(payload["smb_credential_id"], credential_uuid)
                        self.assertEqual(payload["smb_max_protocol"], "default")
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": alert_uuid, "name": payload["name"], "active": False, "event": {"type": "Task run status changed"}, "condition": {"type": "Always"}, "method": {"type": "SMB"}, "method_data_redacted": True, "tasks": []}) + "\n201", "")
                    self.assertEqual(payload["active"], False)
                    self.assertEqual(payload["status"], "Done")
                    self.assertEqual(payload["notice"], "simple")
                    self.assertEqual(payload["to_address"], "yafvs-smoke@example.invalid")
                    alert_definition["value"] = {
                        "method": "EMAIL",
                        "name": payload["name"],
                        "to_address": payload["to_address"],
                        "subject": payload["subject"],
                        "revision": "1",
                    }
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": alert_uuid, "name": payload["name"], "comment": payload["comment"], "active": False, "event": {"type": "Task run status changed"}, "condition": {"type": "Always"}, "method": {"type": "Email"}, "method_data_redacted": True, "tasks": []}) + "\n201", "")
                if method == "GET" and path == f"/api/v1/alerts/{alert_uuid}/definition":
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps(alert_definition["value"]) + "\n200", "")
                if method == "PUT" and path == f"/api/v1/alerts/{alert_uuid}/definition":
                    payload = json.loads(body)
                    if payload.get("expected_revision") != alert_definition["value"]["revision"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict"}}\n409', "")
                    self.assertEqual(
                        payload,
                        {
                            "expected_revision": "1",
                            "definition": {
                                "method": "SYSLOG",
                                "name": alert_definition["value"]["name"],
                                "comment": "YAFVS direct write smoke replaced temporary alert definition",
                                "active": False,
                                "status": "Done",
                            },
                        },
                    )
                    alert_definition["value"] = {**payload["definition"], "revision": "2"}
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps(alert_definition["value"]) + "\n200", "")
                if method == "PATCH" and path.startswith(f"/api/v1/alerts/{alert_uuid}"):
                    payload = json.loads(body)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": alert_uuid, "comment": payload["comment"]}) + "\n200", "")
                if method == "PATCH" and path.startswith(f"/api/v1/credentials/{credential_uuid}"):
                    payload = json.loads(body)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": credential_uuid, "comment": payload["comment"]}) + "\n200", "")
                if method == "GET" and path.startswith("/api/v1/credentials?"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"page":{"total":0},"items":[]}\n200', "")
                if method == "POST" and path == "/api/v1/credentials":
                    payload = json.loads(body)
                    self.assertEqual(payload["type"], "up")
                    self.assertIn("password", payload)
                    if payload["login"] == "yafvs-helper-smoke":
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": credential_helper_uuid, "name": payload["name"], "comment": payload["comment"], "credential_type": "up", "owner": "admin", "owner_id": operator_uuid, "smb_compatible": True}) + "\n201", "")
                    self.assertEqual(payload["login"], "yafvs-direct-write-smoke-user")
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": credential_uuid, "name": payload["name"], "comment": payload["comment"], "credential_type": "up", "owner": "admin", "owner_id": operator_uuid, "smb_compatible": True}) + "\n201", "")
                if method == "POST" and path == "/api/v1/targets":
                    payload = json.loads(body)
                    self.assertEqual(payload["port_list_id"], port_list_uuid)
                    if payload["hosts"] == ["192.0.2.44"]:
                        self.assertEqual(payload["exclude_hosts"], [])
                        self.assertEqual(payload["alive_tests"], ["TCP-ACK Service Ping"])
                        self.assertEqual(
                            payload["credentials"],
                            {
                                "ssh": {
                                    "id": credential_uuid,
                                    "port": 2222,
                                    "host_key_pins": [
                                        {
                                            "host": "192.0.2.44",
                                            "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                                        }
                                    ],
                                }
                            },
                        )
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_create_with_credential_uuid, "name": payload["name"], "comment": payload["comment"], "credentials": payload["credentials"]}) + "\n201", "")
                    self.assertEqual(payload["hosts"], ["192.0.2.42"])
                    self.assertEqual(payload["exclude_hosts"], [])
                    self.assertEqual(payload["alive_tests"], ["TCP-ACK Service Ping"])
                    target_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "name": payload["name"], "comment": payload["comment"], "port_list": {"id": port_list_uuid, "name": "All IANA assigned TCP"}, "hosts": ["192.0.2.42"], "exclude_hosts": [], "alive_tests": payload["alive_tests"]}) + "\n201", "")
                if method == "PATCH" and path.startswith(f"/api/v1/targets/{target_uuid}"):
                    payload = json.loads(body)
                    if "alive_tests" in payload:
                        self.assertEqual(payload["alive_tests"], ["TCP-SYN Service Ping"])
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "comment": target_updated_comment, "alive_tests": payload["alive_tests"]}) + "\n200", "")
                    if "port_list_id" in payload:
                        self.assertEqual(payload["port_list_id"], port_list_uuid)
                        if target_in_use["value"]:
                            return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict"}}\n409', "")
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "port_list": {"id": port_list_uuid, "name": "All IANA assigned TCP"}}) + "\n200", "")
                    if "hosts" in payload:
                        if target_in_use["value"]:
                            return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict"}}\n409', "")
                        self.assertEqual(payload["hosts"], ["192.0.2.42", "192.0.2.43", "192.0.2.42"])
                        self.assertEqual(payload["exclude_hosts"], ["192.0.2.43"])
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "hosts": ["192.0.2.42", "192.0.2.43"], "exclude_hosts": ["192.0.2.43"]}) + "\n200", "")
                    if "allow_simultaneous_ips" in payload or "reverse_lookup_only" in payload or "reverse_lookup_unify" in payload:
                        if target_in_use["value"]:
                            return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict"}}\n409', "")
                        self.assertEqual(payload["allow_simultaneous_ips"], False)
                        self.assertEqual(payload["reverse_lookup_only"], True)
                        self.assertEqual(payload["reverse_lookup_unify"], True)
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "allow_simultaneous_ips": False, "reverse_lookup_only": True, "reverse_lookup_unify": True}) + "\n200", "")
                    if "credentials" in payload:
                        if target_in_use["value"]:
                            return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict"}}\n409', "")
                        if payload["credentials"].get("ssh") is None:
                            target_credential_link_count["value"] = 0
                            return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "credentials": {"ssh": None}}) + "\n200", "")
                        self.assertEqual(
                            payload["credentials"],
                            {
                                "ssh": {
                                    "id": credential_uuid,
                                    "host_key_pins": [
                                        {
                                            "host": "192.0.2.42",
                                            "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                                        }
                                    ],
                                }
                            },
                        )
                        target_credential_link_count["value"] = 1
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "credentials": {"ssh": {"id": credential_uuid, "port": 22, "host_key_pins": payload["credentials"]["ssh"]["host_key_pins"]}}}) + "\n200", "")
                    self.assertEqual(payload["comment"], target_updated_comment)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "comment": payload["comment"]}) + "\n200", "")
                if method == "POST" and path.startswith(f"/api/v1/targets/{target_uuid}/clone"):
                    payload = json.loads(body)
                    target_clone_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_clone_uuid, "name": payload["name"], "comment": payload["comment"], "hosts": ["192.0.2.42", "192.0.2.43"], "exclude_hosts": ["192.0.2.43"]}) + "\n201", "")
                if method == "POST" and path.startswith(f"/api/v1/targets/{target_uuid}/restore"):
                    target_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "name": "yafvs-direct-write-smoke-target", "comment": target_updated_comment}) + "\n200", "")
                if method == "DELETE" and path.startswith(f"/api/v1/targets/{target_clone_uuid}/trash"):
                    target_clone_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith(f"/api/v1/targets/{target_clone_uuid}"):
                    target_clone_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/targets/{target_clone_uuid}"):
                    if target_clone_live["value"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_clone_uuid, "name": target_clone_name}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "DELETE" and path.startswith(f"/api/v1/targets/{target_uuid}/trash"):
                    target_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith(f"/api/v1/targets/{target_uuid}"):
                    target_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/targets/{target_uuid}"):
                    if target_live["value"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": target_uuid, "name": target_name, "comment": target_updated_comment}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "GET" and path == "/api/v1/scanners?page_size=25&sort=name":
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"items": [{"id": "ffffffff-ffff-ffff-ffff-ffffffffffff", "name": "CVE", "scanner_type": 3}, {"id": scanner_uuid, "name": "OpenVAS Default", "scanner_type": 2}], "page": {"total": 2}}) + "\n200", "")
                if method == "POST" and path == f"/api/v1/scanners/{scanner_uuid}/verify":
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"scanner_id": scanner_uuid, "scanner_type": 2, "verified": True, "verification_mode": "osp-unix-socket", "version": "23.11"}) + "\n200", "")
                if method == "POST" and path == "/api/v1/tasks":
                    payload = json.loads(body)
                    self.assertEqual(payload["target_id"], target_uuid)
                    self.assertEqual(payload["config_id"], yafvsctl.FULL_AND_FAST_SCAN_CONFIG_ID)
                    self.assertEqual(payload["scanner_id"], scanner_uuid)
                    self.assertEqual(payload["schedule_id"], task_schedule_uuid)
                    self.assertEqual(payload["alert_ids"], [task_alert_uuid])
                    self.assertEqual(payload["tag_id"], task_tag_uuid)
                    self.assertEqual(payload["hosts_ordering"], "reverse")
                    target_in_use["value"] = True
                    return yafvsctl.subprocess.CompletedProcess(
                        [],
                        0,
                        json.dumps(
                            {
                                "id": task_uuid,
                                "name": payload["name"],
                                "comment": payload["comment"],
                                "apply_overrides": payload["apply_overrides"],
                                "max_checks": payload["max_checks"],
                                "max_hosts": payload["max_hosts"],
                                "min_qod": payload["min_qod"],
                                "hosts_ordering": payload["hosts_ordering"],
                            }
                        )
                        + "\n201",
                        "",
                    )
                if method == "POST" and path == f"/api/v1/tasks/{task_uuid}/replace-configuration":
                    payload = json.loads(body)
                    self.assertEqual(payload["schedule_periods"], 2)
                    self.assertEqual(payload["hosts_ordering"], "sequential")
                    self.assertEqual(payload["apply_overrides"], True)
                    task_configuration_replaced["value"] = True
                    return yafvsctl.subprocess.CompletedProcess(
                        [],
                        0,
                        json.dumps(
                            {
                                "id": task_uuid,
                                "name": payload["name"],
                                "comment": payload["comment"],
                                "schedule_periods": payload["schedule_periods"],
                                "apply_overrides": payload["apply_overrides"],
                                "max_checks": payload["max_checks"],
                                "max_hosts": payload["max_hosts"],
                                "min_qod": payload["min_qod"],
                                "hosts_ordering": payload["hosts_ordering"],
                                "alerts": [{"id": task_alert_uuid}],
                            }
                        )
                        + "\n200",
                        "",
                    )
                if method == "POST" and path == f"/api/v1/tasks/{task_uuid}/clone":
                    self.assertIsNone(body)
                    self.assertTrue(_kwargs.get("include_response_headers"))
                    task_clone_live["value"] = True
                    payload = {
                        "id": task_clone_uuid,
                        "name": f"yafvs-direct-write-smoke-task-1-{yafvsctl.os.getpid()} Clone 1",
                        "comment": task_updated_comment,
                        "status": "New",
                        "target": {"id": target_uuid, "name": "temporary target"},
                        "config": {"id": yafvsctl.FULL_AND_FAST_SCAN_CONFIG_ID, "name": "Full and fast"},
                        "scanner": {"id": scanner_uuid, "name": "OpenVAS Default"},
                        "schedule": {"id": task_schedule_uuid, "name": "temporary schedule"},
                    }
                    return yafvsctl.subprocess.CompletedProcess(
                        [],
                        0,
                        "HTTP/1.1 201 Created\r\n"
                        f"Location: /api/v1/tasks/{task_clone_uuid}\r\n"
                        "Content-Type: application/json\r\n"
                        "\r\n"
                        + json.dumps(payload)
                        + "\n201",
                        "",
                    )
                if method == "DELETE" and path == f"/api/v1/tasks/{task_clone_uuid}":
                    task_clone_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path == f"/api/v1/tasks/{task_clone_uuid}":
                    if task_clone_live["value"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": task_clone_uuid}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "PATCH" and path.startswith(f"/api/v1/tasks/{task_uuid}"):
                    payload = json.loads(body)
                    self.assertEqual(payload["comment"], task_updated_comment)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": task_uuid, "comment": payload["comment"]}) + "\n200", "")
                if method == "POST" and path == "/api/v1/tags":
                    payload = json.loads(body)
                    if payload["resource_type"] == "alert":
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": alert_tag_uuid, "name": payload["name"], "resource_type": "alert", "value": "initial", "active": True}) + "\n201", "")
                    self.assertEqual(payload["resource_type"], "cpe")
                    self.assertNotIn("resource_filter", payload)
                    tag_resource_count["value"] = 0
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": tag_uuid, "name": payload["name"], "resource_type": "cpe", "resource_count": 0, "value": "initial", "active": True}) + "\n201", "")
                if method == "POST" and path == "/api/v1/filters":
                    request_env = _kwargs.get("env") if isinstance(_kwargs.get("env"), dict) else {}
                    if request_env.get(yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV) != "1":
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"method_not_allowed"}}\n405', "")
                    payload = json.loads(body)
                    self.assertEqual(payload["filter_type"], "task")
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": filter_uuid, "name": payload["name"], "comment": payload["comment"], "filter_type": "task", "term": payload.get("term", "")}) + "\n201", "")
                if method == "PATCH" and path.startswith("/api/v1/filters/"):
                    payload = json.loads(body)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": filter_uuid, "comment": payload["comment"], "filter_type": payload.get("filter_type", "task"), "term": payload.get("term", "")}) + "\n200", "")
                if method == "POST" and path.startswith(f"/api/v1/filters/{filter_uuid}/clone"):
                    payload = json.loads(body)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": filter_clone_uuid, "name": payload["name"], "comment": payload["comment"]}) + "\n201", "")
                if method == "POST" and path.startswith(f"/api/v1/filters/{filter_uuid}/restore"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": filter_uuid, "comment": "YAFVS direct write smoke original saved-filter comment"}) + "\n200", "")
                if method == "DELETE" and path.startswith(f"/api/v1/filters/{filter_clone_uuid}/trash"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith(f"/api/v1/filters/{filter_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/filters/{filter_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "DELETE" and path.startswith("/api/v1/filters/"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith("/api/v1/filters/"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "GET" and path == "/api/v1/schedules?page_size=1":
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"items": [{"id": schedule_uuid, "name": "Daily", "comment": "original schedule comment"}], "page": {"total": 1}}) + "\n200", "")
                if method == "GET" and path.startswith("/api/v1/schedules?filter="):
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"items": [{"id": schedule_uuid}], "page": {"page": 1, "total": 1}}) + "\n200", "")
                if method == "POST" and path == "/api/v1/schedules":
                    payload = json.loads(body)
                    schedule_fixture["comment"] = payload["comment"]
                    schedule_fixture["icalendar"] = payload["icalendar"]
                    schedule_fixture["timezone"] = payload["timezone"]
                    schedule_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": schedule_uuid, "name": payload["name"], "comment": payload["comment"], "timezone": schedule_fixture["timezone"], "icalendar": schedule_fixture["icalendar"]}) + "\n201", "")
                if method == "PATCH" and path.startswith("/api/v1/schedules/"):
                    payload = json.loads(body)
                    if "comment" in payload:
                        schedule_fixture["comment"] = payload["comment"]
                    if "timezone" in payload:
                        schedule_fixture["timezone"] = payload["timezone"]
                    if "icalendar" in payload:
                        schedule_fixture["icalendar"] = payload["icalendar"]
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": schedule_uuid, "comment": schedule_fixture["comment"], "timezone": schedule_fixture["timezone"], "icalendar": schedule_fixture["icalendar"]}) + "\n200", "")
                if method == "POST" and path.startswith(f"/api/v1/schedules/{schedule_uuid}/clone"):
                    payload = json.loads(body)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": schedule_clone_uuid, "name": payload["name"], "comment": payload["comment"], "timezone": schedule_fixture["timezone"], "icalendar": schedule_fixture["icalendar"]}) + "\n201", "")
                if method == "POST" and path.startswith(f"/api/v1/schedules/{schedule_uuid}/restore"):
                    schedule_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": schedule_uuid, "comment": ""}) + "\n200", "")
                if method == "DELETE" and path.startswith(f"/api/v1/schedules/{schedule_clone_uuid}/trash"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith(f"/api/v1/schedules/{schedule_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/schedules/{schedule_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "DELETE" and path.startswith(f"/api/v1/schedules/{schedule_uuid}/trash"):
                    schedule_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith("/api/v1/schedules/"):
                    schedule_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith("/api/v1/schedules/"):
                    if schedule_live["value"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": schedule_uuid, "comment": ""}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "POST" and path == "/api/v1/scan-configs":
                    payload = json.loads(body)
                    assert payload["base_scan_config_id"] == yafvsctl.FULL_AND_FAST_SCAN_CONFIG_ID
                    scan_config_live["value"] = True
                    scan_config_definition.update({"comment": payload["comment"], "name": payload["name"]})
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scan_config_uuid, "comment": payload["comment"], "name": payload["name"], "predefined": False}) + "\n201", "")
                if method == "POST" and path == "/api/v1/scan-configs/import":
                    payload = json.loads(body)
                    self.assertEqual(payload["schema"], "yafvs.scan-config-backup")
                    self.assertEqual(payload["version"], 1)
                    self.assertTrue(payload["name"].endswith("-import"))
                    scan_config_import_document["value"] = payload
                    scan_config_import_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scan_config_import_uuid, "comment": payload["comment"], "name": payload["name"], "predefined": False}) + "\n201", "")
                if method == "PATCH" and path.startswith(f"/api/v1/scan-configs/{yafvsctl.FULL_AND_FAST_SCAN_CONFIG_ID}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict","message":"predefined scan configs cannot be patched"}}\n409', "")
                if method == "DELETE" and path.startswith(f"/api/v1/scan-configs/{yafvsctl.FULL_AND_FAST_SCAN_CONFIG_ID}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict","message":"predefined scan configs cannot be modified"}}\n409', "")
                scan_config_family_path = f"/api/v1/scan-configs/{scan_config_uuid}/families/Port%20scanners/nvts"
                if method == "PATCH" and path == scan_config_family_path:
                    if body == "{":
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"bad_request"}}\n400', "")
                    payload = json.loads(body)
                    self.assertEqual(payload["changes"][0]["oid"], override_nvt_id)
                    scan_config_family_selected["value"] = payload["changes"][0]["selected"]
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path == scan_config_family_path:
                    payload = {
                        "scan_config_id": scan_config_uuid,
                        "family": "Port scanners",
                        "items": [{"oid": override_nvt_id, "name": "fixture", "severity": 0.0, "selected": scan_config_family_selected["value"]}],
                    }
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n200", "")
                scan_config_families_path = f"/api/v1/scan-configs/{scan_config_uuid}/families"
                if method == "GET" and path == scan_config_families_path:
                    payload = {
                        "scan_config_id": scan_config_uuid,
                        "family_count": 2,
                        "families_growing": 1,
                        "families": [
                            {"name": "General", "growing": 1, "nvt_count": 1, "max_nvt_count": 1},
                            {"name": "Port scanners", "growing": int(scan_config_family_growing["value"]), "nvt_count": 1, "max_nvt_count": 1},
                        ],
                    }
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n200", "")
                if method == "PATCH" and path.startswith(f"/api/v1/scan-configs/{scan_config_uuid}"):
                    if body == "{":
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"bad_request"}}\n400', "")
                    payload = json.loads(body)
                    if "preferences" in payload:
                        for preference in payload["preferences"]:
                            if preference["name"] == "__yafvs_missing_preference__":
                                return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                            if preference["scope"] == "scanner":
                                self.assertEqual(preference["name"], "safe_checks")
                                scan_config_scanner_preference["configured"] = preference["action"] == "set"
                                scan_config_scanner_preference["value"] = preference.get("value", "1")
                            else:
                                self.assertEqual(preference["name"], "fixture password")
                                self.assertEqual(preference["nvt"], {"oid": override_nvt_id, "id": 2, "type": "password"})
                                scan_config_secret_preference["configured"] = preference["action"] == "set"
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scan_config_uuid}) + "\n200", "")
                    if "family_selection" in payload:
                        families = payload["family_selection"]["families"]
                        if len(families) != 2:
                            return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict"}}\n409', "")
                        port_family = next(item for item in families if item["name"] == "Port scanners")
                        scan_config_family_growing["value"] = port_family["growing"]
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scan_config_uuid}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scan_config_uuid, "comment": payload["comment"]}) + "\n200", "")
                if method == "POST" and path.startswith(f"/api/v1/scan-configs/{scan_config_uuid}/clone"):
                    payload = json.loads(body)
                    assert payload["comment"] == "YAFVS direct write smoke cloned scan-config comment"
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scan_config_clone_uuid, "comment": payload["comment"], "name": payload["name"], "predefined": False}) + "\n201", "")
                if method == "GET" and path == f"/api/v1/scan-configs/{scan_config_uuid}/backup":
                    payload = {
                        "schema": "yafvs.scan-config-backup",
                        "version": 1,
                        "usage_type": "scan",
                        "name": scan_config_definition["name"],
                        "comment": "YAFVS direct write smoke updated scan-config comment",
                        "families_growing": scan_config_family_growing["value"],
                        "family_inventory": ["General", "Port scanners"],
                        "selectors": [
                            {"type": 1, "exclude": False, "family_or_nvt": "General"},
                            {"type": 1, "exclude": False, "family_or_nvt": "Port scanners"},
                        ],
                        "preferences": [{"scope": "scanner", "name": "safe_checks", "value": "1"}],
                        "omitted_secret_preference_count": 1,
                        "omitted_secret_preferences": [
                            {
                                "scope": "nvt",
                                "name": "fixture password",
                                "nvt": {"oid": override_nvt_id, "id": 2, "type": "password"},
                            }
                        ],
                    }
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n200", "")
                if method == "GET" and path == f"/api/v1/scan-configs/{scan_config_import_uuid}/backup":
                    payload = dict(scan_config_import_document["value"])
                    payload["omitted_secret_preference_count"] = 0
                    payload["omitted_secret_preferences"] = []
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n200", "")
                if method == "DELETE" and path == f"/api/v1/scan-configs/{scan_config_import_uuid}/trash":
                    scan_config_import_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path == f"/api/v1/scan-configs/{scan_config_import_uuid}":
                    scan_config_import_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path == f"/api/v1/scan-configs/{scan_config_import_uuid}":
                    if scan_config_import_live["value"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scan_config_import_uuid}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "DELETE" and path.startswith(f"/api/v1/scan-configs/{scan_config_clone_uuid}/trash"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith(f"/api/v1/scan-configs/{scan_config_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/scan-configs/{scan_config_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "DELETE" and path.startswith(f"/api/v1/scan-configs/{scan_config_uuid}"):
                    scan_config_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "POST" and path.startswith(f"/api/v1/scan-configs/{scan_config_uuid}/restore"):
                    scan_config_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": scan_config_uuid, "comment": "YAFVS direct write smoke updated scan-config comment"}) + "\n200", "")
                if method == "GET" and path == f"/api/v1/scan-configs/{scan_config_uuid}":
                    if scan_config_live["value"]:
                        payload = {
                            "id": scan_config_uuid,
                            "comment": "YAFVS direct write smoke updated scan-config comment",
                            "preferences": {
                                "scanner": [{"name": "safe_checks", "configured": scan_config_scanner_preference["configured"], "redacted": False, "value": scan_config_scanner_preference["value"], "default": "1"}],
                                "nvt": [{"name": "fixture password", "id": 2, "type": "password", "configured": scan_config_secret_preference["configured"], "redacted": True, "value": "", "default": "", "nvt": {"oid": override_nvt_id, "name": "fixture NVT"}}],
                            },
                        }
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "GET" and path == "/api/v1/port-lists?page_size=1":
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"items": [{"id": port_list_uuid, "name": "All IANA assigned TCP", "predefined": True}], "page": {"total": 1}}) + "\n200", "")
                if method == "POST" and path == "/api/v1/port-lists":
                    payload = json.loads(body)
                    self.assertEqual(payload["port_ranges"][0]["protocol"], "tcp")
                    temp_port_list_ranges["value"] = [{"id": "initial-range", "protocol": "tcp", "start": 65000, "end": 65001}]
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": temp_port_list_uuid, "name": payload["name"]}) + "\n201", "")
                if method == "POST" and path == f"/api/v1/port-lists/{temp_port_list_uuid}/ranges":
                    payload = json.loads(body)
                    self.assertEqual(payload["protocol"], "udp")
                    if any(item["protocol"] == "udp" and item["start"] == 65002 and item["end"] == 65002 for item in temp_port_list_ranges["value"]):
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict","message":"port range overlaps an existing range"}}\n409', "")
                    temp_port_list_ranges["value"].append({"id": temp_port_range_uuid, "protocol": "udp", "start": 65002, "end": 65002})
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": temp_port_list_uuid, "name": "yafvs-direct-write-smoke-port-list-1-1", "predefined": False, "port_ranges": temp_port_list_ranges["value"]}) + "\n201", "")
                if method == "DELETE" and path == f"/api/v1/port-lists/{temp_port_list_uuid}/ranges/{temp_port_range_uuid}":
                    temp_port_list_ranges["value"] = [item for item in temp_port_list_ranges["value"] if item["id"] != temp_port_range_uuid]
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "POST" and path.startswith(f"/api/v1/port-lists/{temp_port_list_uuid}/clone"):
                    payload = json.loads(body)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": temp_port_list_clone_uuid, "name": payload["name"], "predefined": False, "port_ranges": temp_port_list_ranges["value"]}) + "\n201", "")
                if method == "DELETE" and path.startswith(f"/api/v1/port-lists/{temp_port_list_clone_uuid}/trash"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith(f"/api/v1/port-lists/{temp_port_list_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/port-lists/{temp_port_list_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "POST" and path.startswith(f"/api/v1/port-lists/{temp_port_list_uuid}/restore"):
                    temp_port_list_live["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": temp_port_list_uuid, "name": "yafvs-direct-write-smoke-port-list-1-" + str(yafvsctl.os.getpid())}) + "\n200", "")
                if method == "DELETE" and path.startswith(f"/api/v1/port-lists/{temp_port_list_uuid}/trash"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith(f"/api/v1/port-lists/{temp_port_list_uuid}"):
                    temp_port_list_live["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/port-lists/{temp_port_list_uuid}"):
                    if temp_port_list_live["value"]:
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": temp_port_list_uuid, "port_ranges": temp_port_list_ranges["value"]}) + "\n200", "")
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "PATCH" and path.startswith("/api/v1/port-lists/"):
                    payload = json.loads(body)
                    self.assertIn("predefined port lists", payload["comment"])
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict","message":"predefined port lists cannot be patched"}}\n409', "")
                if method == "DELETE" and path.startswith("/api/v1/port-lists/"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"conflict","message":"predefined port lists cannot be deleted"}}\n409', "")
                if method == "GET" and path == "/api/v1/cpes?page_size=1":
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"items": [{"id": report_format_uuid, "name": "cpe:/a:example:product:1"}], "page": {"total": 1}}) + "\n200", "")
                if method == "POST" and path.endswith("/resources"):
                    payload = json.loads(body)
                    if alert_tag_uuid in path:
                        self.assertEqual(payload["resource_ids"], [alert_uuid])
                        count = 1 if payload["action"] == "add" else 0
                        alert_tag_resource_count["value"] = count
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": alert_tag_uuid, "resource_count": count}) + "\n200", "")
                    if tag_clone_uuid in path:
                        self.assertEqual(payload["resource_ids"], [report_format_uuid])
                        count = 1 if payload["action"] == "add" else 0
                        return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": tag_clone_uuid, "resource_count": count}) + "\n200", "")
                    self.assertEqual(payload["resource_ids"], [report_format_uuid])
                    count = 1 if payload["action"] in {"add", "set"} else 0
                    tag_resource_count["value"] = count
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": tag_uuid, "resource_count": count}) + "\n200", "")
                if method == "POST" and path.startswith(f"/api/v1/tags/{tag_uuid}/clone"):
                    payload = json.loads(body)
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": tag_clone_uuid, "name": payload["name"], "comment": payload["comment"], "resource_type": "cpe", "resource_count": 1}) + "\n201", "")
                if method == "POST" and path.startswith(f"/api/v1/tags/{tag_uuid}/restore"):
                    tag_deleted["value"] = False
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": tag_uuid, "resource_count": tag_resource_count["value"]}) + "\n200", "")
                if method == "DELETE" and path.startswith(f"/api/v1/tags/{tag_clone_uuid}/trash"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "DELETE" and path.startswith(f"/api/v1/tags/{tag_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/tags/{tag_clone_uuid}"):
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "GET" and path.startswith(f"/api/v1/tags/{alert_tag_uuid}") and not alert_tag_deleted["value"]:
                    count = alert_tag_resource_count["value"]
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": alert_tag_uuid, "resource_count": count, "in_use": count > 0}) + "\n200", "")
                if method == "DELETE" and path.startswith(f"/api/v1/tags/{alert_tag_uuid}"):
                    alert_tag_deleted["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                if method == "GET" and path.startswith(f"/api/v1/tags/{alert_tag_uuid}") and alert_tag_deleted["value"]:
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")
                if method == "GET" and path.startswith("/api/v1/tags/") and not tag_deleted["value"]:
                    count = tag_resource_count["value"]
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": tag_uuid, "resource_count": count, "in_use": count > 0}) + "\n200", "")
                if method == "PATCH" and path.startswith("/api/v1/tags/"):
                    if "?" in path:
                        return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"request_too_large"}}\n413', "")
                    payload = json.loads(body)
                    self.assertEqual(payload["resource_type"], "target")
                    self.assertEqual(payload["resources"], {"action": "set", "resource_ids": []})
                    tag_resource_count["value"] = 0
                    return yafvsctl.subprocess.CompletedProcess([], 0, json.dumps({"id": tag_uuid, "resource_type": "target", "resource_count": 0, "value": "updated", "active": False}) + "\n200", "")
                if method == "DELETE" and path.startswith("/api/v1/tags/") and body is not None:
                    return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"request_too_large"}}\n413', "")
                if method == "DELETE" and path.startswith("/api/v1/tags/"):
                    tag_deleted["value"] = True
                    return yafvsctl.subprocess.CompletedProcess([], 0, "\n204", "")
                return yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"not_found"}}\n404', "")

            try:
                yafvsctl.os.environ[yafvsctl.YAFVS_API_BEARER_TOKEN_ENV] = token
                receipt = {
                    "image_ids": {
                        service: "sha256:" + f"{index + 1:x}" * 64
                        for index, service in enumerate(yafvsctl.APP_SERVICES)
                    }
                }
                with unittest.mock.patch.object(yafvsctl, "run_command", side_effect=fake_run_command), unittest.mock.patch.object(yafvsctl, "active_feed_generation_finding", return_value=yafvsctl.finding("pass", "feed-generation.current", "Mock completed activation.")), unittest.mock.patch.object(yafvsctl, "require_app_deployment_receipt", return_value=(receipt, None)), unittest.mock.patch.object(yafvsctl, "refresh_app_deployment_receipt_after_image_build", return_value=(receipt, None)), unittest.mock.patch.object(yafvsctl, "native_api_direct_admin_operator_uuid", return_value=(yafvsctl.subprocess.CompletedProcess([], 0, f"admin {operator_uuid}", ""), operator_uuid)), unittest.mock.patch.object(yafvsctl, "direct_native_api_curl", side_effect=fake_direct_curl), unittest.mock.patch.object(yafvsctl, "native_api_direct_credential_clone_findings", return_value=[yafvsctl.finding("pass", "native-api-direct.credential-clone-characterization", "ok")]), unittest.mock.patch.object(yafvsctl, "direct_trash_empty_runtime_findings", return_value=[]), unittest.mock.patch.object(yafvsctl, "direct_task_target_replace_runtime_findings", return_value=[yafvsctl.finding("pass", "native-api-direct.task-target-replace-acknowledgement", "ok"), yafvsctl.finding("pass", "native-api-direct.task-target-replace-fixture-cleanup", "ok")]), unittest.mock.patch.object(yafvsctl.time, "time", return_value=1):
                    result = yafvsctl.command_runtime_native_api_direct_write_smoke(root, status_only=True)
            finally:
                if original_token is None:
                    yafvsctl.os.environ.pop(yafvsctl.YAFVS_API_BEARER_TOKEN_ENV, None)
                else:
                    yafvsctl.os.environ[yafvsctl.YAFVS_API_BEARER_TOKEN_ENV] = original_token

        checks = result["details"]["important_checks"]
        self.assertEqual(result["status"], "pass", json.dumps(result, sort_keys=True))
        self.assertEqual(result["findings"][0]["check"], "runtime-native-api-direct-write-smoke.status-only")
        self.assertEqual(checks["native-api-direct.write-control-operator"], "pass")
        self.assertEqual(checks["native-api-direct.write-control-healthz"], "pass")
        self.assertEqual(checks["native-api-direct.user-management-list"], "pass")
        self.assertEqual(checks["native-api-direct.scope-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.scope-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.scope-write-query-denied"], "pass")
        self.assertEqual(checks["native-api-direct.scope-delete-body-denied"], "pass")
        self.assertEqual(checks["native-api-direct.scope-write-delete"], "pass")
        self.assertEqual(checks["native-api-direct.task-stop-missing"], "pass")
        self.assertEqual(checks["native-api-direct.scope-report-delete-missing"], "pass")
        self.assertEqual(checks["native-api-direct.task-target-replace-acknowledgement"], "pass")
        self.assertEqual(checks["native-api-direct.task-target-replace-fixture-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.task-write-clone"], "pass")
        self.assertEqual(checks["native-api-direct.task-write-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.task-write-post-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.scope-write-post-delete"], "pass")
        self.assertEqual(checks["native-api-direct.tag-write-create"], "pass")
        self.assertFalse(any(path.endswith("/start") for _method, path in probes))
        task_cleanup_command = next(" ".join(command) for command in commands if "fixed-task-smoke-cleanup" in " ".join(command))
        self.assertNotIn("DELETE FROM permissions", task_cleanup_command)
        self.assertIn(f"yafvs-direct-write-smoke-task-1-{yafvsctl.os.getpid()} Clone 1", task_cleanup_command)
        self.assertIn(task_updated_comment, task_cleanup_command)
        self.assertIn(operator_uuid, task_cleanup_command)
        self.assertEqual(checks["native-api-direct.filter-fixture"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-restore"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-clone"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-post-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-delete"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-trash-restore"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-delete-after-restore"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-post-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.filter-write-post-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-bulk-helper-dry-run"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-bulk-helper-write"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-restore"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-clone"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-post-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-delete"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-post-delete"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-trash-restore"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-delete-after-restore"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-post-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.schedule-write-post-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-predefined-patch-denied"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-predefined-delete-denied"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-preference-fixture"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-preference-set"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-preference-set-readback"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-preference-reset"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-preference-reset-readback"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-preference-unknown-denied"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-secret-preference-set"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-secret-preference-readback"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-secret-preference-reset"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-secret-preference-reset-readback"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-mode-fixture"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-mode-malformed-json-denied"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-mode-stale-denied"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-mode-toggle"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-mode-toggle-readback"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-mode-restore"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-mode-restore-readback"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-nvt-fixture"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-nvt-malformed-json-denied"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-nvt-toggle"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-nvt-toggle-readback"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-nvt-restore"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-family-nvt-restore-readback"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-backup"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-import"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-import-roundtrip"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-import-delete"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-import-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-import-post-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-clone"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-post-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-delete"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-post-delete"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-restore"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.scan-config-write-post-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-predefined-patch-denied"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-predefined-delete-denied"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-range-create"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-range-overlap-denied"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-range-delete"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-clone"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-post-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-delete"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-post-delete"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-restore"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-delete-after-restore"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-post-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.port-list-write-post-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.override-nvt-fixture"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-clone"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-delete"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-post-delete"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-restore"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-delete-after-restore"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-post-hard-delete"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-post-hard-delete-clone"], "pass")
        self.assertEqual(checks["native-api-direct.override-write-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.tag-resource-fixture"], "pass")
        self.assertEqual(checks["native-api-direct.tag-resource-add"], "pass")
        self.assertEqual(checks["native-api-direct.tag-resource-in-use-after-add"], "pass")
        self.assertEqual(checks["native-api-direct.tag-resource-set"], "pass")
        self.assertEqual(checks["native-api-direct.tag-resource-remove"], "pass")
        self.assertEqual(checks["native-api-direct.tag-resource-in-use-after-remove"], "pass")
        self.assertEqual(checks["native-api-direct.alert-malformed-json-denied"], "pass")
        self.assertEqual(checks["native-api-direct.alert-concurrent-name-serialized"], "pass")
        self.assertEqual(checks["native-api-direct.alert-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.alert-smb-report-format-fixture"], "pass")
        self.assertEqual(checks["native-api-direct.alert-smb-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.alert-smb-method-data-names"], "pass")
        self.assertEqual(checks["native-api-direct.alert-smb-write-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.alert-smb-report-format-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.alert-missing-format-denied"], "pass")
        self.assertEqual(checks["native-api-direct.alert-missing-recipient-credential-denied"], "pass")
        self.assertEqual(checks["native-api-direct.alert-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.alert-tag-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.alert-tag-resource-add"], "pass")
        self.assertEqual(checks["native-api-direct.alert-tag-resource-in-use-after-add"], "pass")
        self.assertEqual(checks["native-api-direct.alert-tag-resource-remove"], "pass")
        self.assertEqual(checks["native-api-direct.alert-tag-resource-in-use-after-remove"], "pass")
        self.assertEqual(checks["native-api-direct.alert-tag-write-delete"], "pass")
        self.assertEqual(checks["native-api-direct.alert-tag-write-post-delete"], "pass")
        self.assertEqual(checks["native-api-direct.alert-write-cleanup"], "pass")
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text()
        self.assertIn("alert_create_outcome_uncertain", source)
        self.assertIn("owner = (SELECT id FROM operator_owner)", source)
        self.assertIn("expected_alert_counts = {\"1\"} if alert_create_committed else {\"0\", \"1\"}", source)
        self.assertIn("LOCK TABLE users IN ROW SHARE MODE", source)
        self.assertIn('"SELECT count(*) FROM deleted_alert; "', source)
        self.assertIn('smb_alert_cleanup_counts == "0|0"', source)
        self.assertIn("trash_tag AS (SELECT id FROM tags_trash", source)
        self.assertIn("deleted_trash_tag AS (DELETE FROM tags_trash", source)
        self.assertIn("expected_tag_counts = {\"1\"} if alert_tag_id else {\"0\", \"1\"}", source)
        self.assertEqual(checks["native-api-direct.credential-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.credential-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.credential-fixture-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.credential-csv-helper-write"], "pass")
        self.assertEqual(checks["native-api-direct.credential-csv-helper-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.target-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.target-create-with-credential-link"], "pass")
        self.assertEqual(checks["native-api-direct.target-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.target-alive-test-update"], "pass")
        self.assertEqual(checks["native-api-direct.target-port-list-update"], "pass")
        self.assertEqual(checks["native-api-direct.target-hosts-update"], "pass")
        self.assertEqual(checks["native-api-direct.target-scan-settings-update"], "pass")
        self.assertEqual(checks["native-api-direct.target-scan-settings-in-use-denied"], "pass")
        self.assertEqual(checks["native-api-direct.target-port-list-in-use-denied"], "pass")
        self.assertEqual(checks["native-api-direct.target-hosts-in-use-denied"], "pass")
        self.assertEqual(checks["native-api-direct.target-write-clone"], "pass")
        self.assertEqual(checks["native-api-direct.target-fixture-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.scanner-verify"], "pass")
        self.assertEqual(checks["native-api-direct.task-relation-fixtures"], "pass")
        self.assertEqual(checks["native-api-direct.task-write-create"], "pass")
        self.assertEqual(checks["native-api-direct.task-write-replace-configuration"], "pass")
        self.assertEqual(checks["native-api-direct.task-relation-fixture-cleanup"], "pass")
        self.assertEqual(checks["native-api-direct.tag-write-update"], "pass")
        self.assertEqual(checks["native-api-direct.tag-write-query-denied"], "pass")
        self.assertEqual(checks["native-api-direct.tag-delete-body-denied"], "pass")
        self.assertEqual(checks["native-api-direct.tag-write-delete"], "pass")
        self.assertEqual(checks["native-api-direct.tag-write-post-delete"], "pass")
        self.assertEqual(checks["native-api-direct.write-control-restore"], "pass")
        self.assertIn(("POST", "/api/v1/tags"), probes)
        self.assertIn(("POST", f"/api/v1/tags/{tag_uuid}/clone"), probes)
        self.assertIn(("POST", "/api/v1/filters"), probes)
        self.assertIn(("POST", f"/api/v1/tags/{alert_tag_uuid}/resources"), probes)
        self.assertIn(("DELETE", f"/api/v1/tags/{alert_tag_uuid}"), probes)
        self.assertIn(("GET", f"/api/v1/tags/{alert_tag_uuid}"), probes)
        self.assertIn(("PATCH", f"/api/v1/targets/{target_uuid}"), probes)
        self.assertIn(("POST", f"/api/v1/targets/{target_uuid}/clone"), probes)
        self.assertIn(("POST", f"/api/v1/scanners/{scanner_uuid}/verify"), probes)
        self.assertIn(("POST", "/api/v1/tasks"), probes)
        self.assertIn(("GET", "/api/v1/nvts?page_size=1&sort=oid"), probes)
        self.assertIn(("POST", "/api/v1/overrides"), probes)
        self.assertIn(("POST", f"/api/v1/overrides/{override_uuid}/clone"), probes)
        self.assertIn(("DELETE", f"/api/v1/overrides/{override_uuid}/trash"), probes)
        self.assertIn(("DELETE", f"/api/v1/overrides/{override_clone_uuid}/trash"), probes)
        self.assertEqual(probes[0], ("GET", "/healthz"))
        self.assertTrue(any(method == "GET" for method, _path in probes))
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(token, rendered)
        self.assertTrue(any(env.get(yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV) == "1" for env in envs))
        self.assertTrue(any(env.get(yafvsctl.YAFVS_API_DIRECT_WRITE_CONTROL_ENV) is None for env in envs))

    def test_direct_write_smoke_keeps_bounded_override_lifecycle_and_cleanup(self):
        source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        start = source.index("def _command_runtime_native_api_direct_write_smoke_unlocked")
        body = source[start : source.index("\ndef command_runtime_native_api_direct_write_smoke", start)]

        self.assertIn('"/api/v1/nvts?page_size=1&sort=oid"', body)
        self.assertIn('"activation": {"mode": "inactive"}', body)
        self.assertIn('"activation": {"mode": "always"}', body)
        self.assertIn('override_clone_body = "{}"', body)
        for check in (
            "override-write-create",
            "override-write-update",
            "override-write-clone",
            "override-write-delete",
            "override-write-post-delete",
            "override-write-restore",
            "override-write-delete-after-restore",
            "override-write-hard-delete",
            "override-write-delete-clone",
            "override-write-hard-delete-clone",
            "override-write-cleanup",
        ):
            self.assertIn(check, body)
        self.assertIn("fixed-override-smoke-cleanup", body)
        self.assertIn("fixed-override-smoke-residue", body)
        self.assertIn("resource_type = 'override'", body)
        self.assertIn("owner = (SELECT id FROM operator_owner)", body)
        self.assertIn('native_api_cleanup_identity_predicate(override_id, override_text, value_column="text")', body)
        self.assertIn('native_api_cleanup_identity_predicate(override_clone_id, override_text, value_column="text")', body)
        self.assertIn("resource_location = 0", body)
        self.assertIn("resource_location = 1", body)

    def test_direct_native_api_display_command_redacts_token(self):
        env = {
            yafvsctl.YAFVS_API_DIRECT_HOST_ENV: "127.0.0.1",
            yafvsctl.YAFVS_API_DIRECT_PORT_ENV: "19080",
        }
        command = yafvsctl.direct_native_api_display_command("/api/v1/reports?page_size=1", token="secret-token", env=env)
        rendered = " ".join(command)
        self.assertIn("Authorization: Bearer <redacted>", rendered)
        self.assertNotIn("secret-token", rendered)

    def test_direct_native_api_display_command_includes_non_get_method(self):
        env = {
            yafvsctl.YAFVS_API_DIRECT_HOST_ENV: "127.0.0.1",
            yafvsctl.YAFVS_API_DIRECT_PORT_ENV: "19080",
        }
        command = yafvsctl.direct_native_api_display_command(
            "/api/v1/reports?page_size=1",
            token="secret-token",
            env=env,
            method="POST",
        )
        self.assertIn("-X", command)
        self.assertIn("POST", command)
        self.assertIn("Authorization: Bearer <redacted>", " ".join(command))

    def test_direct_native_api_display_command_includes_request_id(self):
        env = {
            yafvsctl.YAFVS_API_DIRECT_HOST_ENV: "127.0.0.1",
            yafvsctl.YAFVS_API_DIRECT_PORT_ENV: "19080",
        }
        command = yafvsctl.direct_native_api_display_command(
            "/api/v1/reports?page_size=1",
            token="secret-token",
            env=env,
            request_id="client-123_abc.4:5",
        )
        rendered = " ".join(command)
        self.assertIn("X-Request-Id: client-123_abc.4:5", rendered)
        self.assertNotIn("secret-token", rendered)

    def test_direct_native_api_display_command_redacts_body(self):
        env = {
            yafvsctl.YAFVS_API_DIRECT_HOST_ENV: "127.0.0.1",
            yafvsctl.YAFVS_API_DIRECT_PORT_ENV: "19080",
        }
        command = yafvsctl.direct_native_api_display_command(
            "/api/v1/reports?page_size=1",
            token="secret-token",
            env=env,
            body="probe-body",
        )
        rendered = " ".join(command)
        self.assertIn("-X GET", rendered)
        self.assertIn("--data-binary <redacted-body>", rendered)
        self.assertNotIn("probe-body", rendered)
        self.assertNotIn("secret-token", rendered)

    def test_direct_native_api_curl_sends_body_over_stdin_not_process_arguments(self):
        env = {
            yafvsctl.YAFVS_API_DIRECT_HOST_ENV: "127.0.0.1",
            yafvsctl.YAFVS_API_DIRECT_PORT_ENV: "19080",
        }
        captured = {}

        def fake_run(command, _cwd, **kwargs):
            captured["command"] = command
            captured["input_text"] = kwargs.get("input_text")
            captured["pass_fds"] = kwargs.get("pass_fds")
            header_path = next(Path(value[1:]) for value in command if value.startswith("@/proc/self/fd/"))
            self.assertTrue(header_path.exists())
            captured["header_path"] = header_path
            captured["header_content"] = header_path.read_text(encoding="utf-8")
            return yafvsctl.subprocess.CompletedProcess(command, 0, "{}\n200", "")

        secret_body = '{"password":"must-not-be-in-argv"}'
        with unittest.mock.patch.object(yafvsctl, "run_command", side_effect=fake_run):
            yafvsctl.direct_native_api_curl(
                Path.cwd(),
                "/api/v1/credentials",
                token="secret-token",
                env=env,
                method="POST",
                body=secret_body,
                extra_headers=(("Content-Type", "application/json"),),
            )

        rendered = " ".join(captured["command"])
        self.assertIn("--data-binary @-", rendered)
        self.assertNotIn("must-not-be-in-argv", rendered)
        self.assertNotIn("secret-token", rendered)
        self.assertEqual(captured["input_text"], secret_body)
        self.assertEqual(captured["header_content"], "Authorization: Bearer secret-token\n")
        self.assertEqual(captured["pass_fds"], (int(captured["header_path"].name),))
        self.assertFalse(captured["header_path"].exists())

    def test_direct_native_api_curl_cleans_header_file_when_command_fails(self):
        captured = {}

        def fake_run(command, _cwd, **_kwargs):
            captured["header_path"] = next(Path(value[1:]) for value in command if value.startswith("@/proc/self/fd/"))
            raise RuntimeError("simulated curl setup failure")

        with unittest.mock.patch.object(yafvsctl, "run_command", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "simulated curl setup failure"):
                yafvsctl.direct_native_api_curl(
                    Path.cwd(),
                    "/api/v1/credentials",
                    token="secret-token",
                    env={},
                )
        self.assertFalse(captured["header_path"].exists())

    def test_native_api_curl_sends_body_over_stdin_not_process_arguments(self):
        captured = {}

        def fake_run(command, _cwd, **kwargs):
            captured["command"] = command
            captured["input_text"] = kwargs.get("input_text")
            return yafvsctl.subprocess.CompletedProcess(command, 0, "{}", "")

        secret_body = '{"password":"must-not-be-in-argv"}'
        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.object(
            yafvsctl, "run_command", side_effect=fake_run
        ):
            root = Path(tmp) / "YAFVS"
            root.mkdir()
            yafvsctl.native_api_curl(
                root,
                "/api/v1/credentials",
                method="POST",
                body=secret_body,
            )

        rendered = " ".join(captured["command"])
        self.assertIn("--data-binary @-", rendered)
        self.assertNotIn("must-not-be-in-argv", rendered)
        self.assertEqual(captured["input_text"], secret_body)

    def test_direct_native_api_http_status_parser_keeps_json_error_body(self):
        completed = yafvsctl.subprocess.CompletedProcess([], 0, '{"error":{"code":"unauthorized"}}\n401', "")
        parsed, status = yafvsctl.parse_json_output_with_http_status(completed)
        self.assertEqual(status, 401)
        self.assertEqual(parsed["error"]["code"], "unauthorized")

    def test_direct_native_api_header_status_parser_keeps_request_id(self):
        completed = yafvsctl.subprocess.CompletedProcess(
            [],
            0,
            "HTTP/1.1 401 Unauthorized\r\nx-request-id: tv-123\r\ncontent-type: application/json\r\n\r\n{\"error\":{\"code\":\"unauthorized\"}}\n401",
            "",
        )
        parsed, status, headers = yafvsctl.parse_json_output_with_headers_and_http_status(completed)
        self.assertEqual(status, 401)
        self.assertEqual(parsed["error"]["code"], "unauthorized")
        self.assertEqual(headers["x-request-id"], "tv-123")

    def test_direct_native_api_direct_smoke_tracks_retention_plan_preview(self):
        root = Path(__file__).resolve().parents[2]
        direct_smoke = (
            root
            / "tools"
            / "yafvsctl-rs"
            / "src"
            / "commands"
            / "runtime_native_api_direct_smoke.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("native-api-direct.scope-report-retention-plan", direct_smoke)
        self.assertIn("native-api-direct.request-shape-guard", direct_smoke)
        self.assertIn("native-api-direct.request-id-unauthorized", direct_smoke)
        self.assertIn("native-api-direct.request-id-client", direct_smoke)
        self.assertIn("native-api-direct.cors-disabled", direct_smoke)
        self.assertIn("native-api-direct.security-headers", direct_smoke)
        self.assertIn("native-api-direct.request-id-unsafe-client", direct_smoke)
        self.assertIn("native-api-direct.scope-write-disabled", direct_smoke)
        self.assertIn("native-api-direct.request-shape-transfer-encoding", direct_smoke)
        self.assertIn("native-api-direct.request-shape-malformed-content-length", direct_smoke)
        self.assertIn("native-api-direct.request-shape-oversized-query", direct_smoke)
        self.assertIn("/retention-plan", direct_smoke)

    def test_openvas_config_path_lives_under_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(yafvsctl.openvas_runtime_config_path(root), Path(tmp) / "YAFVS-runtime" / "state" / "ospd" / "openvas.conf")

    def test_rust_feed_generation_runtime_guard_bridge_accepts_valid_envelopes(self):
        for selector_only, status, returncode in (
            (True, "pass", 0),
            (False, "fail", 1),
        ):
            expected_check = (
                "feed-generation.selector-journal"
                if selector_only
                else "feed-generation.current"
            )
            item = {
                "status": status,
                "check": expected_check,
                "message": "guard result",
                "details": {"selector_generation_id": "a" * 64},
            }
            payload = {
                "status": status,
                "findings": [item],
                "metadata": {"command": "feed-generation-runtime-guard"},
            }
            with self.subTest(selector_only=selector_only, status=status), unittest.mock.patch.object(
                yafvsctl,
                "run_command",
                return_value=subprocess.CompletedProcess(
                    ["cargo"], returncode, json.dumps(payload), ""
                ),
            ) as run_command:
                observed = yafvsctl.rust_feed_generation_runtime_guard_finding(
                    Path("/tmp/TurboVAS"), selector_only=selector_only
                )

            self.assertEqual(observed, item)
            arguments = run_command.call_args.args[0]
            self.assertEqual(arguments[-1], "--json")
            self.assertEqual("--selector-only" in arguments, selector_only)
            self.assertEqual(
                run_command.call_args.kwargs["timeout"],
                300 if selector_only else 1800,
            )

    def test_rust_feed_generation_runtime_guard_bridge_rejects_invalid_results(self):
        valid_item = {
            "status": "pass",
            "check": "feed-generation.current",
            "message": "guard result",
        }
        valid_payload = {
            "status": "pass",
            "findings": [valid_item],
            "metadata": {"command": "feed-generation-runtime-guard"},
        }
        cases = {
            "invalid-json": (0, "not-json"),
            "wrong-metadata": (
                0,
                json.dumps({**valid_payload, "metadata": {"command": "status"}}),
            ),
            "wrong-check": (
                0,
                json.dumps(
                    {
                        **valid_payload,
                        "findings": [{**valid_item, "check": "unexpected"}],
                    }
                ),
            ),
            "wrong-envelope-status": (
                0,
                json.dumps({**valid_payload, "status": "warn"}),
            ),
            "wrong-exit-code": (1, json.dumps(valid_payload)),
            "multiple-findings": (
                0,
                json.dumps({**valid_payload, "findings": [valid_item, valid_item]}),
            ),
        }
        for name, (returncode, stdout) in cases.items():
            with self.subTest(name=name), unittest.mock.patch.object(
                yafvsctl,
                "run_command",
                return_value=subprocess.CompletedProcess(
                    ["cargo"], returncode, stdout, ""
                ),
            ):
                observed = yafvsctl.rust_feed_generation_runtime_guard_finding(
                    Path("/tmp/TurboVAS"), selector_only=False
                )

            self.assertEqual(observed["status"], "fail")
            self.assertEqual(observed["check"], "feed-generation.current")
            self.assertIn("failed closed", observed["message"])

    def test_rust_feed_generation_runtime_guard_bridge_handles_subprocess_failure(self):
        with unittest.mock.patch.object(
            yafvsctl, "run_command", side_effect=OSError("cargo unavailable")
        ):
            observed = yafvsctl.rust_feed_generation_runtime_guard_finding(
                Path("/tmp/TurboVAS"), selector_only=True
            )

        self.assertEqual(observed["status"], "fail")
        self.assertEqual(observed["check"], "feed-generation.selector-journal")
        self.assertIn("failed closed", observed["message"])


    def test_app_feed_consumers_use_guarded_active_generation_mount(self):
        compose = (Path(__file__).resolve().parents[2] / "compose/dev.yaml").read_text(
            encoding="utf-8"
        )
        mounts = re.findall(
            r"source: \$\{YAFVS_RUNTIME_DIR:-../../YAFVS-runtime\}/feed-store/current\n"
            r"\s+target: /runtime/feeds",
            compose,
        )
        guarded_mounts = re.findall(
            r"source: \$\{YAFVS_RUNTIME_DIR:-../../YAFVS-runtime\}/feed-store/current\n"
            r"\s+target: /runtime/feeds\n"
            r"\s+bind:\n"
            r"\s+create_host_path: false",
            compose,
        )
        self.assertEqual(len(mounts), 4)
        self.assertEqual(len(guarded_mounts), 4)
        app_section = compose.split("  gvmd:\n", 1)[1]
        self.assertNotIn("restart: unless-stopped", app_section)
        self.assertNotIn(
            "source: ${YAFVS_RUNTIME_DIR:-../../YAFVS-runtime}/feeds/openvas",
            compose,
        )
        self.assertNotIn(
            "source: ${YAFVS_RUNTIME_DIR:-../../YAFVS-runtime}/feeds/notus",
            compose,
        )

    def test_public_feed_docs_expose_only_guarded_generation_workflow(self):
        root = Path(__file__).resolve().parents[2]
        docs = "\n".join(
            (root / path).read_text(encoding="utf-8")
            for path in (
                "README.md",
                "BUILDING.md",
                "docker/runtime/README.md",
                "docs/USER_MANUAL.md",
            )
        )
        for marker in (
            "feed-generation-stage",
            "feed-generation-activate",
            "feed-generation-rollback",
            "--allow-first-activation",
            "explicit acknowledgement",
            "service-coordinated",
            "compensating recovery",
            "database rollback",
        ):
            self.assertIn(marker, docs)
        self.assertNotIn("runtime-feed-import-init", docs)
        self.assertNotIn("feed-copy-to-runtime", docs)


    def test_runtime_app_env_keeps_mqtt_secrets_out_of_child_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            env = yafvsctl.runtime_app_env(root)

            self.assertNotEqual(
                env[yafvsctl.YAFVS_API_BROWSER_PROXY_SECRET_ENV],
                env[yafvsctl.YAFVS_GVMD_CONTROL_SECRET_ENV],
            )
            for env_name, secret_name in yafvsctl.YAFVS_MQTT_RUNTIME_SECRETS:
                self.assertNotIn(env_name, env)
                self.assertEqual(
                    yafvsctl.runtime_secret_path(root, secret_name).stat().st_mode & 0o777,
                    0o600,
                )

    def test_runtime_env_ignores_legacy_mqtt_password_environment_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            env_name, secret_name = yafvsctl.YAFVS_MQTT_RUNTIME_SECRETS[0]
            with unittest.mock.patch.dict(
                os.environ, {env_name: "legacy-environment-secret"}
            ):
                env = yafvsctl.runtime_env(root)
            self.assertNotIn(env_name, env)
            stored = yafvsctl.read_private_text(
                yafvsctl.runtime_secret_path(root, secret_name),
                yafvsctl.MAX_RUNTIME_SECRET_BYTES,
            )
            self.assertNotIn("legacy-environment-secret", stored)

    def test_runtime_artifact_manifest_is_deterministic_and_content_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "runtime"
            artifact_root.mkdir()
            executable = artifact_root / "service"
            executable.write_bytes(b"first")
            executable.chmod(0o755)
            (artifact_root / "service-link").symlink_to("service")
            ignored = artifact_root / "__pycache__"
            ignored.mkdir()
            bytecode = ignored / "service.pyc"
            bytecode.write_bytes(b"first-bytecode")
            with unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_ROOTS", (Path("runtime"),)
            ), unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_FILES", ()
            ):
                first = yafvsctl.app_runtime_artifact_manifest(root)
                second = yafvsctl.app_runtime_artifact_manifest(root)
                bytecode.write_bytes(b"second-bytecode")
                bytecode_changed = yafvsctl.app_runtime_artifact_manifest(root)
                bytecode.write_bytes(b"first-bytecode")
                executable.write_bytes(b"second")
                changed = yafvsctl.app_runtime_artifact_manifest(root)

        self.assertEqual(first, second)
        self.assertEqual(first["entry_count"], 3)
        self.assertNotEqual(first["digest"], bytecode_changed["digest"])
        self.assertNotEqual(first["digest"], changed["digest"])

    def test_runtime_artifact_manifest_rejects_host_external_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "runtime"
            artifact_root.mkdir()
            (artifact_root / "escape").symlink_to("/home/example/outside")
            with unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_ROOTS", (Path("runtime"),)
            ), unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_FILES", ()
            ):
                with self.assertRaisesRegex(OSError, "escapes"):
                    yafvsctl.app_runtime_artifact_manifest(root)

    def test_runtime_artifact_manifest_rejects_absolute_dot_segment_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "runtime"
            artifact_root.mkdir()
            (artifact_root / "escape").symlink_to(
                "/usr/../../workspace/unattested"
            )
            with unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_ROOTS", (Path("runtime"),)
            ), unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_FILES", ()
            ):
                with self.assertRaisesRegex(OSError, "escapes"):
                    yafvsctl.app_runtime_artifact_manifest(root)

    def test_runtime_artifact_manifest_accepts_attested_virtualenv_link_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "runtime"
            artifact_root.mkdir()
            (artifact_root / "python").symlink_to("/usr/bin/python3")
            (artifact_root / "python3").symlink_to("python")
            with unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_ROOTS", (Path("runtime"),)
            ), unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_FILES", ()
            ):
                manifest = yafvsctl.app_runtime_artifact_manifest(root)

        self.assertEqual(manifest["entry_count"], 2)

    def test_app_compose_contract_is_content_bound_without_storing_config(self):
        image_ids = {
            service: "sha256:" + f"{index + 1:x}" * 64
            for index, service in enumerate(yafvsctl.APP_SERVICES)
        }
        base_services = {
            service: {"image": image_ids[service], "command": [service]}
            for service in yafvsctl.APP_SERVICES
        }
        changed_services = json.loads(json.dumps(base_services))
        changed_services["gsad"]["command"] = ["gsad", "--changed"]
        rendered = [
            {"services": base_services, "networks": {"default": {}}},
            {"services": changed_services, "networks": {"default": {}}},
        ]
        with unittest.mock.patch.object(
            yafvsctl,
            "compose_command_with_app_images",
            return_value=["docker", "compose", "config"],
        ), unittest.mock.patch.object(
            yafvsctl,
            "run_command",
            side_effect=[
                subprocess.CompletedProcess([], 0, json.dumps(item), "")
                for item in rendered
            ],
        ):
            first = yafvsctl.app_compose_contract_manifest(
                Path("/tmp"), image_ids, app_env={}
            )
            changed = yafvsctl.app_compose_contract_manifest(
                Path("/tmp"), image_ids, app_env={}
            )

        self.assertNotEqual(first["digest"], changed["digest"])
        self.assertEqual(set(first), {"schema_version", "algorithm", "digest", "services"})
        self.assertNotIn("command", json.dumps(first))

    def test_app_compose_contract_ignores_port_declaration_order(self):
        image_ids = {
            service: "sha256:" + f"{index + 1:x}" * 64
            for index, service in enumerate(yafvsctl.APP_SERVICES)
        }
        services = {
            service: {"image": image_ids[service], "command": [service]}
            for service in yafvsctl.APP_SERVICES
        }
        services["gsad"]["ports"] = [
            {"host_ip": "192.168.178.42", "published": "19392", "target": 9392},
            {"host_ip": "100.80.139.13", "published": "19392", "target": 9392},
        ]
        reversed_services = json.loads(json.dumps(services))
        reversed_services["gsad"]["ports"].reverse()
        with unittest.mock.patch.object(
            yafvsctl,
            "compose_command_with_app_images",
            return_value=["docker", "compose", "config"],
        ), unittest.mock.patch.object(
            yafvsctl,
            "run_command",
            side_effect=[
                subprocess.CompletedProcess(
                    [], 0, json.dumps({"services": item}), ""
                )
                for item in (services, reversed_services)
            ],
        ):
            first = yafvsctl.app_compose_contract_manifest(
                Path("/tmp"), image_ids, app_env={}
            )
            reversed_order = yafvsctl.app_compose_contract_manifest(
                Path("/tmp"), image_ids, app_env={}
            )

        self.assertEqual(first["digest"], reversed_order["digest"])

    def test_app_deployment_receipt_requires_compose_contract(self):
        image_ids = {
            service: "sha256:" + f"{index + 1:x}" * 64
            for index, service in enumerate(yafvsctl.APP_SERVICES)
        }
        payload = {
            "schema_version": 1,
            "image_ids": image_ids,
            "runtime_artifacts": {
                "schema_version": 1,
                "algorithm": "sha256",
                "digest": "d" * 64,
                "entry_count": 1,
                "byte_count": 1,
                "roots": [
                    str(path)
                    for path in (
                        *yafvsctl.APP_RUNTIME_ARTIFACT_ROOTS,
                        *yafvsctl.APP_RUNTIME_ARTIFACT_FILES,
                    )
                ],
            },
            "compose_contract": {
                "schema_version": 1,
                "algorithm": "sha256",
                "digest": "e" * 64,
                "services": list(yafvsctl.APP_SERVICES),
            },
            "prepared_at": "2026-07-13T00:00:00+00:00",
        }
        self.assertEqual(
            yafvsctl.validate_app_deployment_receipt(dict(payload)), payload
        )
        payload.pop("compose_contract")
        with self.assertRaisesRegex(ValueError, "receipt"):
            yafvsctl.validate_app_deployment_receipt(payload)

    def test_app_oneoff_refuses_missing_receipt_without_running_compose(self):
        with unittest.mock.patch.object(
            yafvsctl, "deployed_app_env", return_value={}
        ), unittest.mock.patch.object(
            yafvsctl,
            "require_app_deployment_receipt",
            return_value=(None, "missing prepared receipt"),
        ), unittest.mock.patch.object(yafvsctl, "run_command") as run_command:
            result = yafvsctl.run_app_oneoff(
                Path("/tmp"), "gvmd", ["gvmd", "--migrate"]
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("missing prepared receipt", result.stderr)
        run_command.assert_not_called()


    def test_receipt_identity_can_precede_explicit_compose_mode_transition(self):
        image_ids = {
            service: "sha256:" + f"{index + 1:x}" * 64
            for index, service in enumerate(yafvsctl.APP_SERVICES)
        }
        receipt = {
            "schema_version": 1,
            "image_ids": image_ids,
            "runtime_artifacts": {
                "schema_version": 1,
                "algorithm": "sha256",
                "digest": "d" * 64,
                "entry_count": 1,
                "byte_count": 1,
                "roots": [
                    str(path)
                    for path in (
                        *yafvsctl.APP_RUNTIME_ARTIFACT_ROOTS,
                        *yafvsctl.APP_RUNTIME_ARTIFACT_FILES,
                    )
                ],
            },
            "compose_contract": {
                "schema_version": 1,
                "algorithm": "sha256",
                "digest": "e" * 64,
                "services": list(yafvsctl.APP_SERVICES),
            },
            "prepared_at": "2026-07-13T00:00:00+00:00",
        }
        with unittest.mock.patch.object(
            yafvsctl, "app_service_image_availability_error", return_value=None
        ), unittest.mock.patch.object(
            yafvsctl,
            "app_runtime_artifact_finding",
            return_value=yafvsctl.finding("pass", "artifacts", "ok"),
        ), unittest.mock.patch.object(
            yafvsctl, "app_compose_contract_finding"
        ) as compose_finding:
            error = yafvsctl.app_deployment_receipt_error(
                Path("/tmp"),
                receipt,
                app_env={},
                verify_compose_contract=False,
            )

        self.assertIsNone(error)
        compose_finding.assert_not_called()

    def test_runtime_artifact_manifest_rejects_relative_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.write_text("not attested", encoding="utf-8")
            artifact_root = root / "runtime"
            artifact_root.mkdir()
            (artifact_root / "escape").symlink_to("../outside")
            with unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_ROOTS", (Path("runtime"),)
            ), unittest.mock.patch.object(
                yafvsctl, "APP_RUNTIME_ARTIFACT_FILES", ()
            ):
                with self.assertRaisesRegex(OSError, "escapes"):
                    yafvsctl.app_runtime_artifact_manifest(root)

    def test_runtime_containment_compose_and_broker_policy(self):
        root = Path(__file__).resolve().parents[2]
        compose = (root / "compose" / "dev.yaml").read_text(encoding="utf-8")
        broker = (root / "docker" / "runtime" / "mosquitto.conf").read_text(encoding="utf-8")
        acl = (root / "docker" / "runtime" / "mosquitto.acl").read_text(encoding="utf-8")
        dev_shell = compose.split("  dev-shell:\n", 1)[1].split("\n  gvmd:", 1)[0]
        mosquitto = compose.split("  mosquitto:\n", 1)[1].split("\n  dev-shell:", 1)[0]

        self.assertIn("YAFVS_GVMD_CONTROL_SECRET: ${YAFVS_GVMD_CONTROL_SECRET:-}", compose)
        self.assertNotIn("YAFVS_GVMD_CONTROL_SECRET: ${YAFVS_API_BROWSER_PROXY_SECRET:-}", compose)
        gvmd = compose.split("  gvmd:\n", 1)[1].split("\n  ospd-openvas:", 1)[0]
        self.assertIn("/run/ospd", gvmd)
        self.assertNotIn("source: ${YAFVS_RUNTIME_DIR:-../../YAFVS-runtime}\n        target: /runtime", gvmd)
        gsad = compose.split("  gsad:\n", 1)[1].split("\n  yafvs-api:", 1)[0]
        yafvs_api = compose.split("  yafvs-api:\n", 1)[1]
        app_services = {
            "gvmd": compose.split("  gvmd:\n", 1)[1].split("\n  ospd-openvas:", 1)[0],
            "ospd-openvas": compose.split("  ospd-openvas:\n", 1)[1].split("\n  notus-scanner:", 1)[0],
            "notus-scanner": compose.split("  notus-scanner:\n", 1)[1].split("\n  gsad:", 1)[0],
            "gsad": gsad,
            "yafvs-api": yafvs_api,
        }
        broad_runtime_mount = "source: ${YAFVS_RUNTIME_DIR:-../../YAFVS-runtime}\n        target: /runtime"
        for service, block in app_services.items():
            self.assertNotIn(broad_runtime_mount, block, service)
            self.assertNotIn("/runtime/secrets", block, service)
        ospd = app_services["ospd-openvas"]
        self.assertIn(
            "source: ${YAFVS_RUNTIME_DIR:-../../YAFVS-runtime}/secrets/mqtt-ospd-password",
            ospd,
        )
        self.assertIn(
            "target: /run/secrets/yafvs-mqtt-ospd-password",
            ospd,
        )
        self.assertIn(
            "--mqtt-broker-password-file=/run/secrets/yafvs-mqtt-ospd-password",
            ospd,
        )
        self.assertNotIn("YAFVS_MQTT_OSPD_PASSWORD:", ospd)
        self.assertNotIn("--mqtt-broker-password=", ospd)
        self.assertIn(broad_runtime_mount, dev_shell)
        self.assertIn("/mosquitto/secrets", mosquitto)
        self.assertNotIn("YAFVS_MQTT_OPENVAS_PASSWORD:", mosquitto)
        self.assertNotIn("YAFVS_MQTT_NOTUS_PASSWORD:", mosquitto)
        self.assertNotIn("YAFVS_MQTT_OSPD_PASSWORD:", mosquitto)
        self.assertNotIn("YAFVS_MQTT_HEALTH_PASSWORD:", mosquitto)
        self.assertNotIn("mosquitto_passwd -b", mosquitto)
        self.assertIn("mosquitto_passwd -U", mosquitto)
        self.assertIn(
            '["CMD", "mosquitto_pub", "-o", "/tmp/yafvs-mqtt-health.options"]',
            mosquitto,
        )
        for secret_name in (
            "mqtt-openvas-password",
            "mqtt-notus-password",
            "mqtt-ospd-password",
            "mqtt-health-password",
        ):
            self.assertIn(
                f"source: ${{YAFVS_RUNTIME_DIR:-../../YAFVS-runtime}}/secrets/{secret_name}",
                mosquitto,
            )
        notus = app_services["notus-scanner"]
        self.assertNotIn("NOTUS_SCANNER_MQTT_BROKER_PASSWORD:", notus)
        self.assertIn(
            "--mqtt-broker-password-file=/run/secrets/yafvs-mqtt-notus-password",
            notus,
        )
        self.assertIn("/run/gvmd-gmp", gsad)
        self.assertIn("/run/gvmd-control", yafvs_api)
        self.assertNotIn("/run/gvmd-gmp", yafvs_api)
        self.assertIn("/run/ospd", app_services["ospd-openvas"])
        self.assertIn("/run/redis-openvas", app_services["ospd-openvas"])
        self.assertIn("/feed-store/current", app_services["ospd-openvas"])
        self.assertIn("target: /runtime/feeds", app_services["ospd-openvas"])
        self.assertIn("/state/ospd/openvas.conf", app_services["ospd-openvas"])
        self.assertIn(
            "/state/ospd/result-spool", app_services["ospd-openvas"]
        )
        self.assertIn(
            "--result-spool-dir=/runtime/state/ospd/result-spool",
            app_services["ospd-openvas"],
        )
        self.assertIn("/feed-store/current", app_services["notus-scanner"])
        self.assertIn("target: /runtime/feeds", app_services["notus-scanner"])
        self.assertIn("allow_anonymous false", broker)
        self.assertIn("password_file /mosquitto/config-secrets/passwords", broker)
        self.assertIn("acl_file /mosquitto/config-secrets/mosquitto.acl", broker)
        self.assertIn("max_packet_size 4194304", broker)
        for rule in (
            "topic write scanner/package/cmd/notus",
            "topic read scanner/status",
            "topic read scanner/package/cmd/notus",
            "topic write scanner/status",
            "topic write scanner/scan/info",
            "topic read scanner/scan/info",
        ):
            self.assertIn(rule, acl)

    def test_sql_escaping_helpers(self):
        self.assertEqual(yafvsctl.sql_literal("a'b"), "'a''b'")

    def test_gmp_smoke_parse_version_accepts_text_and_element(self):
        self.assertEqual(runtime_gmp_smoke.parse_version("<get_version_response><version>22.7</version></get_version_response>"), "22.7")
        element = ET.fromstring("<get_version_response><version>22.8</version></get_version_response>")
        self.assertEqual(runtime_gmp_smoke.parse_version(element), "22.8")

    def test_gmp_smoke_raw_xml_helper_escapes_credentials_and_reads_complete_response(self):
        xml = runtime_gmp_smoke.gmp_authenticate_xml("admin<&", "pass>&")
        self.assertIn("<username>admin&lt;&amp;</username>", xml)
        self.assertIn("<password>pass&gt;&amp;</password>", xml)

        class FakeSocket:
            def __init__(self):
                self.chunks = [b"<get_version_response>", b"<version>22.9</version></get_version_response>"]

            def recv(self, _size):
                return self.chunks.pop(0)

        payload = runtime_gmp_smoke.read_gmp_xml_response(FakeSocket())
        self.assertEqual(runtime_gmp_smoke.parse_version(payload), "22.9")

    def test_gmp_smoke_no_longer_imports_python_gvm_runtime_client(self):
        source = GMP_SMOKE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("from gvm.connections", source)
        self.assertNotIn("from gvm.protocols", source)
        self.assertIn("socket.AF_UNIX", source)

        wrapper_source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        gmp_smoke_wrapper = wrapper_source.split("def command_runtime_gmp_smoke", 1)[1].split("def wait_for_runtime_gmp_smoke", 1)[0]
        self.assertNotIn("venv_python(repo_root, \"python-gvm\")", gmp_smoke_wrapper)
        self.assertNotIn("python-gvm.venv", gmp_smoke_wrapper)
        self.assertNotIn("sys.executable", gmp_smoke_wrapper)
        self.assertIn("rust_result_envelope", gmp_smoke_wrapper)
        self.assertIn('"runtime-gmp-smoke"', gmp_smoke_wrapper)

    def test_full_test_scan_uses_only_native_api_lifecycle(self):
        source = FULL_TEST_SCAN_PATH.read_text(encoding="utf-8")
        self.assertNotIn("from gvm", source)
        self.assertNotIn("UnixSocketConnection", source)
        self.assertNotIn("GMP(", source)
        self.assertNotIn("gmp.", source)
        self.assertNotIn("RawGmpClient", source)
        self.assertNotIn("connect_raw_gmp_client", source)
        self.assertNotIn("socket.AF_UNIX", source)
        self.assertNotIn("xml.etree", source)
        self.assertNotIn('"--socket"', source)
        self.assertNotIn('"--password-file"', source)
        self.assertIn('parser.add_argument("--repo-root", required=True', source)
        self.assertIn('parser.add_argument("--operator-name", required=True', source)

    def test_full_test_scan_main_reports_native_preflight_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with unittest.mock.patch.object(runtime_full_test_scan, "native_api_json", side_effect=RuntimeError("native API boom")):
                with unittest.mock.patch("sys.stdout", stdout):
                    exit_code = runtime_full_test_scan.main(
                        [
                            "preflight",
                            "--operator-name",
                            "admin",
                            "--artifact-dir",
                            str(Path(tmp) / "artifacts"),
                            "--target-cidr",
                            TEST_FULL_TEST_TARGET.cidr,
                            "--repo-root",
                            tmp,
                        ]
                    )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["details"]["error"], "native API boom")

    def test_runtime_scope_uses_only_native_api(self):
        source = RUNTIME_SCOPE_PATH.read_text(encoding="utf-8")
        wrapper_source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        rust_wrapper_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs/src/commands/runtime_probe.rs"
        ).read_text(encoding="utf-8")
        scope_wrapper = rust_wrapper_source.split("fn command_runtime_scope_smoke_with", 1)[1].split(
            "fn runtime_scope_organization_proof_finding", 1
        )[0]
        self.assertNotIn("runtime_full_test_scan.connect_gmp", source)
        self.assertNotIn("gmp.", source)
        self.assertNotIn("connect_raw_gmp_client", source)
        self.assertNotIn("runtime_full_test_scan", source)
        self.assertIn("native_generate_scope_report", source)
        self.assertNotIn("def command_runtime_scope", wrapper_source)
        self.assertNotIn('add_parser("runtime-scope-smoke"', wrapper_source)
        self.assertIn("command_runtime_scope_smoke", rust_wrapper_source)
        self.assertIn("Duration::from_secs(180)", scope_wrapper)
        self.assertNotIn("python-gvm.venv", scope_wrapper)
        self.assertNotIn("gvmd_socket_path(repo_root)", scope_wrapper)

    def test_runtime_rbac_smoke_uses_only_native_api(self):
        source = RUNTIME_RBAC_PATH.read_text(encoding="utf-8")
        wrapper_source = (Path(__file__).resolve().parents[1] / "yafvsctl").read_text(encoding="utf-8")
        rust_wrapper_source = (
            Path(__file__).resolve().parents[1]
            / "yafvsctl-rs/src/commands/runtime_probe.rs"
        ).read_text(encoding="utf-8")
        rbac_wrapper = rust_wrapper_source.split(
            "fn command_runtime_rbac_smoke_with", 1
        )[1].split("fn command_runtime_scope_smoke_with", 1)[0]
        self.assertNotIn("runtime_full_test_scan.connect_gmp", source)
        self.assertNotIn("from gvm", source)
        self.assertNotIn("gmp.", source)
        self.assertNotIn("runtime_gmp_smoke", source)
        self.assertNotIn("RawGmpClient", source)
        self.assertNotIn("RbacGmpClient", source)
        self.assertNotIn("send_gmp_xml_command", source)
        self.assertNotIn("gmp_authenticate_xml", source)
        self.assertNotIn("<get_", source)
        self.assertNotIn("<delete_task", source)
        self.assertNotIn('"--socket"', source)
        self.assertIn("NativeBrowserClient", source)
        self.assertIn('"user-management/users"', source)
        self.assertIn("verify_native_user_lifecycle", source)
        self.assertIn("verify_native_cross_user_filter_admin", source)
        self.assertIn("verify_native_cross_user_target_task_admin", source)
        self.assertNotIn("verify_cross_user_filter_admin", source)
        self.assertNotIn("def create_filter", source)
        self.assertNotIn("def modify_filter", source)
        self.assertNotIn("def delete_filter", source)
        self.assertIn(
            'FULL_TEST_TASK_PREFIXES = ("YAFVS full test scan ", "TurboVAS full test scan ")',
            source,
        )
        self.assertNotIn("FULL_TEST_TASK_NAME", source)
        self.assertNotIn("def create_user", source)
        self.assertNotIn("def modify_user", source)
        self.assertNotIn("def command_runtime_rbac_smoke", wrapper_source)
        self.assertIn("command_runtime_rbac_smoke", rust_wrapper_source)
        self.assertNotIn("gvmd_socket_path", rbac_wrapper)
        self.assertNotIn('"--socket"', rbac_wrapper)

    def test_runtime_rbac_native_login_parses_session_token(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self):
                return b"<response><token>native-session-token</token></response>"

        class FakeOpener:
            def __init__(self):
                self.request = None

            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return FakeResponse()

        client = runtime_rbac_smoke.NativeBrowserClient("https://127.0.0.1:19392", 17)
        opener = FakeOpener()
        client.opener = opener

        client.login("admin", "test-password")

        self.assertEqual(client.token, "native-session-token")
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.timeout, 17)

    def test_runtime_rbac_native_user_lifecycle_cleans_up(self):
        calls = []

        class FakeNativeClient:
            def request_json(self, method, path, *, payload=None, query=None):
                calls.append((method, path, payload, query))
                if method in ("POST", "PATCH"):
                    return {"id": "user-1"}
                if method == "GET":
                    return {"items": []}
                return {}

        result = runtime_rbac_smoke.verify_native_user_lifecycle(FakeNativeClient())

        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["absent_after_delete"])
        self.assertEqual(
            [(method, path) for method, path, _payload, _query in calls],
            [
                ("POST", "user-management/users"),
                ("PATCH", "user-management/users/user-1"),
                ("DELETE", "user-management/users/user-1"),
                ("GET", "user-management/users"),
            ],
        )
        self.assertEqual(calls[0][2]["name"], calls[1][2]["name"])
        self.assertNotEqual(calls[0][2]["comment"], calls[1][2]["comment"])

    def test_runtime_rbac_failure_writes_artifact_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp) / "artifacts"
            stdout = io.StringIO()
            with unittest.mock.patch("sys.stdout", new=stdout):
                exit_code = runtime_rbac_smoke.main(
                    [
                        "--username",
                        "admin",
                        "--password-file",
                        str(Path(tmp) / "missing-secret"),
                        "--base-url",
                        "https://127.0.0.1:19392",
                        "--artifact-dir",
                        str(artifact_dir),
                    ]
                )

            payload = json.loads(stdout.getvalue())
            artifact = artifact_dir / "rbac-smoke.json"
            self.assertEqual(exit_code, 1)
            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["artifacts"], [str(artifact)])
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8")), payload)

    def test_runtime_rbac_native_filter_check_uses_secondary_for_full_lifecycle(self):
        calls = []

        class FakeNativeClient:
            def __init__(self, role):
                self.role = role

            def request_json(self, method, path, *, payload=None, query=None):
                calls.append((self.role, method, path, payload, query))
                if method == "POST" and path == "filters":
                    return {"id": "filter-1"}
                return {}

        result = runtime_rbac_smoke.verify_native_cross_user_filter_admin(
            FakeNativeClient("admin"),
            FakeNativeClient("secondary"),
        )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            [(role, method, path) for role, method, path, _payload, _query in calls],
            [
                ("admin", "POST", "filters"),
                ("secondary", "PATCH", "filters/filter-1"),
                ("secondary", "DELETE", "filters/filter-1"),
                ("secondary", "DELETE", "filters/filter-1/trash"),
            ],
        )

    def test_runtime_rbac_full_test_visibility_uses_native_task_scoped_reports(self):
        calls = []

        class FakeNativeClient:
            def request_json(self, method, path, *, payload=None, query=None):
                calls.append((method, path, payload, query))
                if path == "tasks":
                    return {
                        "items": [
                            {
                                "id": "task-1",
                                "name": "YAFVS full test scan 192.0.2.0/24",
                            }
                        ]
                    }
                return {"items": [{"id": "report-1", "task": {"id": "task-1"}}]}

        result = runtime_rbac_smoke.verify_full_test_visibility(FakeNativeClient())

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["task"]["id"], "task-1")
        self.assertEqual(result["latest_report"]["id"], "report-1")
        self.assertEqual(
            [(method, path) for method, path, _payload, _query in calls],
            [("GET", "tasks"), ("GET", "reports")],
        )
        self.assertEqual(calls[1][3]["task_id"], "task-1")
        self.assertEqual(calls[1][3]["sort"], "-creation_time")

    def test_runtime_rbac_native_target_task_check_uses_secondary_without_starting_scan(self):
        calls = []

        class FakeNativeClient:
            def __init__(self, role):
                self.role = role

            def request_json(self, method, path, *, payload=None, query=None):
                calls.append((self.role, method, path, payload, query))
                if method == "GET":
                    item = {"id": f"{path}-1"}
                    if path == "scanners":
                        item["scanner_type"] = 2
                    return {"items": [item]}
                if method == "POST" and path == "targets":
                    return {"id": "target-1"}
                if method == "POST" and path == "tasks":
                    return {"id": "task-1"}
                return {}

        result = runtime_rbac_smoke.verify_native_cross_user_target_task_admin(
            FakeNativeClient("admin"),
            FakeNativeClient("secondary"),
        )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["scans_started"], 0)
        operations = [(role, method, path) for role, method, path, _payload, _query in calls]
        self.assertNotIn(("admin", "POST", "tasks/task-1/start"), operations)
        self.assertIn(("secondary", "POST", "tasks"), operations)
        self.assertIn(("admin", "PATCH", "tasks/task-1"), operations)
        self.assertIn(("admin", "DELETE", "tasks/task-1"), operations)
        self.assertIn(("secondary", "DELETE", "tasks/task-1/trash"), operations)
        self.assertIn(("secondary", "PATCH", "targets/target-1"), operations)
        self.assertIn(("secondary", "POST", "targets/target-1/restore"), operations)
        self.assertEqual(
            operations[-2:],
            [
                ("secondary", "DELETE", "targets/target-1"),
                ("secondary", "DELETE", "targets/target-1/trash"),
            ],
        )

    def test_feed_activation_commits_journal_before_restarting_services(self):
        transition_source = (
            YAFVSCTL_PATH.parent
            / "yafvsctl-rs/src/commands/feed_generation/transition.rs"
        ).read_text(encoding="utf-8")
        success = transition_source[
            transition_source.index("fn commit_target") : transition_source.index(
                "fn compensate"
            )
        ]
        active_journal = success.index("write_completed_journal")
        restart = success.index("restart_and_verify_apps(false)")

        self.assertLess(active_journal, restart)

    def test_retired_feed_refusals_are_rust_only_cli_ownership(self):
        python_source = YAFVSCTL_PATH.read_text(encoding="utf-8")
        rust_cli = (
            YAFVSCTL_PATH.parent / "yafvsctl-rs/src/cli.rs"
        ).read_text(encoding="utf-8")
        cli_reference = (
            YAFVSCTL_PATH.parent.parent / "docs/CLI_REFERENCE.md"
        ).read_text(encoding="utf-8")
        for command in ("runtime-feed-import-init", "feed-copy-to-runtime"):
            definition = "command_" + command.replace("-", "_")
            self.assertNotIn(f'add_parser("{command}"', python_source)
            self.assertNotIn(f"def {definition}", python_source)
            self.assertNotIn(f'args.command == "{command}"', python_source)
            self.assertIn(command, rust_cli)
            self.assertIn(command, cli_reference)

    def test_operator_acl_keeps_global_maintenance_settings_visible(self):
        acl = (
            Path(__file__).resolve().parents[2]
            / "components"
            / "gvmd"
            / "src"
            / "manage_acl.h"
        ).read_text(encoding="utf-8")
        macro = acl.split("#define ACL_GLOBAL_OR_USER_OWNS()", 1)[1].split(
            "\n\n", 1
        )[0]

        self.assertIn("ACL_IS_GLOBAL", macro)
        self.assertIn("EXISTS (SELECT 1 FROM users", macro)

    def test_full_test_scan_target_is_explicit_canonical_and_bounded(self):
        self.assertEqual(TEST_FULL_TEST_TARGET.cidr, "192.0.2.0/24")
        self.assertEqual(TEST_FULL_TEST_TARGET.target_name, "YAFVS full test target 192.0.2.0/24")
        self.assertEqual(TEST_FULL_TEST_TARGET.task_name, "YAFVS full test scan 192.0.2.0/24")
        with self.assertRaisesRegex(ValueError, "canonical CIDR"):
            runtime_full_test_scan.parse_full_test_target("192.0.2.1/24")
        with self.assertRaisesRegex(ValueError, "at most 256"):
            runtime_full_test_scan.parse_full_test_target("10.0.0.0/16")
        with self.assertRaisesRegex(ValueError, "at most 256"):
            runtime_full_test_scan.parse_full_test_target("2001:db8::/64")
        with self.assertRaisesRegex(ValueError, "unspecified or multicast"):
            runtime_full_test_scan.parse_full_test_target("0.0.0.0/32")
        with self.assertRaisesRegex(ValueError, "unspecified or multicast"):
            runtime_full_test_scan.parse_full_test_target("ff02::1/128")
        self.assertEqual(runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID, yafvsctl.FULL_AND_FAST_SCAN_CONFIG_ID)

    def test_full_test_scan_detects_active_duplicate_task(self):
        rows = [
            {"name": TEST_FULL_TEST_TARGET.task_name, "status": "Running", "id": "active"},
            {"name": TEST_FULL_TEST_TARGET.task_name, "status": "New", "id": "created-not-started"},
            {"name": TEST_FULL_TEST_TARGET.task_name, "status": "Done", "id": "done"},
        ]
        active = runtime_full_test_scan.active_full_test_tasks(rows, TEST_FULL_TEST_TARGET)
        self.assertEqual([row["id"] for row in active], ["active"])

    def test_full_test_scan_start_requires_exact_target_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = runtime_full_test_scan.command_start(
                Path(tmp),
                TEST_FULL_TEST_TARGET,
                None,
                Path(tmp),
            )
            self.assertEqual(payload["status"], "fail")
            self.assertIn("--confirm-authorized-target", payload["summary"])
            self.assertTrue((Path(tmp) / "start-refused.json").is_file())

        with tempfile.TemporaryDirectory() as tmp:
            payload = runtime_full_test_scan.command_start(
                Path(tmp),
                TEST_FULL_TEST_TARGET,
                "192.0.2.1/32",
                Path(tmp),
            )
        self.assertEqual(payload["status"], "fail")
        self.assertIn("does not match", payload["summary"])

    def test_full_test_scan_wrapper_is_rust_only_cli_ownership(self):
        root = Path(__file__).resolve().parents[2]
        python_source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_source = (
            root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_probe.rs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("def command_runtime_full_test_scan", python_source)
        self.assertNotIn("def validated_full_test_target_cidr", python_source)
        self.assertIn("command_runtime_full_test_scan_with", rust_source)
        self.assertIn("validated_full_test_target_cidr", rust_source)
        wrapper = rust_source.split("fn command_runtime_full_test_scan_with", 1)[1].split(
            "fn system_full_test_capability_findings", 1
        )[0]
        self.assertNotIn("gvmd_socket_path", wrapper)
        self.assertNotIn("append_secret_prerequisite", wrapper)
        self.assertNotIn('"--socket"', wrapper)
        self.assertNotIn('"--password-file"', wrapper)
        self.assertIn('"--operator-name"', wrapper)
        self.assertIn('"--repo-root"', wrapper)
        self.assertIn("run_probe_with_env(", wrapper)
        self.assertIn("runtime_environment(repo_root)", wrapper)

    def test_full_test_scan_failed_start_rejects_stale_task_and_ospd_evidence(self):
        state = {
            "scan_configs": [
                {
                    "id": runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID,
                    "name": "Full and fast",
                }
            ],
            "port_lists": [
                {
                    "id": runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID,
                    "name": "All IANA assigned TCP and UDP",
                }
            ],
            "scanners": [
                {"id": "scanner-1", "name": runtime_full_test_scan.OPENVAS_SCANNER_NAME}
            ],
            "targets": [
                {"id": "target-1", "name": TEST_FULL_TEST_TARGET.target_name}
            ],
            "tasks": [
                {
                    "id": "task-1",
                    "name": TEST_FULL_TEST_TARGET.task_name,
                    "status": "Done",
                }
            ],
        }
        old_report = {"id": "report-old", "task_id": "task-1", "scan_run_status": "Done"}
        stale_snapshot = {
            "task": state["tasks"][0],
            "ospd_handoff_evidence": {"matched": True, "matched_lines": ["old task-1"]},
        }

        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(runtime_full_test_scan, "load_state", return_value=state):
                with unittest.mock.patch.object(
                    runtime_full_test_scan,
                    "reports_for_task",
                    return_value=([old_report], None),
                ):
                    with unittest.mock.patch.object(
                        runtime_full_test_scan,
                        "native_api_browser_proxy_json",
                        side_effect=RuntimeError("native API POST failed with HTTP unknown"),
                    ):
                        with unittest.mock.patch.object(
                            runtime_full_test_scan,
                            "task_status_snapshot",
                            return_value=stale_snapshot,
                        ):
                            payload = runtime_full_test_scan.command_start(
                                Path(tmp),
                                TEST_FULL_TEST_TARGET,
                                TEST_FULL_TEST_TARGET.cidr,
                                Path(tmp),
                                poll_seconds=1,
                                poll_interval=0,
                            )

        self.assertEqual(payload["status"], "fail")
        self.assertFalse(payload["details"]["start_evidence"])
        self.assertFalse(payload["details"]["observed_new_report"])
        self.assertIsNone(payload["details"]["observed_report"])
        self.assertIn("no accepted start or new report", payload["summary"])

    def test_full_test_scan_native_start_observes_new_report_handoff(self):
        state = {
            "scan_configs": [
                {"id": runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID}
            ],
            "port_lists": [
                {"id": runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID}
            ],
            "scanners": [
                {"id": "scanner-1", "name": runtime_full_test_scan.OPENVAS_SCANNER_NAME}
            ],
            "targets": [
                {"id": "target-1", "name": TEST_FULL_TEST_TARGET.target_name}
            ],
            "tasks": [
                {
                    "id": "task-1",
                    "name": TEST_FULL_TEST_TARGET.task_name,
                    "status": "Done",
                }
            ],
        }
        old_report = {
            "id": "report-old",
            "task_id": "task-1",
            "scan_run_status": "Done",
        }
        new_report = {
            "id": "report-new",
            "task_id": "task-1",
            "scan_run_status": "Queued",
        }
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(
                runtime_full_test_scan, "load_state", return_value=state
            ):
                with unittest.mock.patch.object(
                    runtime_full_test_scan,
                    "reports_for_task",
                    side_effect=[
                        ([old_report], None),
                        ([new_report], None),
                        ([new_report], None),
                    ],
                ):
                    with unittest.mock.patch.object(
                        runtime_full_test_scan,
                        "current_full_test_task",
                        side_effect=[
                            RuntimeError("transient native API failure"),
                            (state["tasks"][0], None),
                        ],
                    ):
                        with unittest.mock.patch.object(
                            runtime_full_test_scan,
                            "native_api_browser_proxy_json",
                            return_value={"report_id": "report-new"},
                        ) as native_start:
                            payload = runtime_full_test_scan.command_start(
                                Path(tmp),
                                TEST_FULL_TEST_TARGET,
                                TEST_FULL_TEST_TARGET.cidr,
                                Path(tmp),
                                poll_seconds=1,
                                poll_interval=0,
                            )
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["details"]["report_id"], "report-new")
        self.assertTrue(payload["details"]["observed_new_report"])
        self.assertEqual(payload["details"]["observed_report"]["id"], "report-new")
        self.assertEqual(len(payload["details"]["poll_errors"]), 1)
        self.assertEqual(
            native_start.call_args.args[1], "/api/v1/tasks/task-1/start"
        )
        self.assertEqual(native_start.call_args.kwargs["expected_statuses"], {"202"})

    def test_full_test_scan_preflight_parses_required_objects(self):
        state = {
            "scan_configs": [{"id": runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID, "name": "Full and fast"}],
            "port_lists": [{"id": runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID, "name": "All IANA assigned TCP and UDP"}],
            "scanners": [{"id": "scanner-1", "name": runtime_full_test_scan.OPENVAS_SCANNER_NAME}],
            "targets": [],
            "tasks": [],
        }
        payload = runtime_full_test_scan.preflight_state(state, TEST_FULL_TEST_TARGET)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["details"]["scanner"]["id"], "scanner-1")

    def test_full_test_scan_report_handoff_excludes_requested_only(self):
        self.assertFalse(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Requested"}))
        self.assertTrue(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Queued"}))
        self.assertTrue(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Running"}))
        self.assertFalse(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Done"}))
        self.assertTrue(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Done", "scan_start": "2026-06-06T20:05:00Z"}))

    def test_full_test_scan_detects_interrupted_report_before_handoff(self):
        report = {
            "id": "report-1",
            "task_id": "task-1",
            "scan_run_status": "Interrupted",
            "scan_start": None,
            "scan_end": None,
            "result_count": "0",
            "hosts_count": "0",
            "vulns_count": "0",
            "cves_count": "0",
            "os_count": "0",
        }
        self.assertTrue(runtime_full_test_scan.interrupted_before_scanner_handoff(report))
        report["scan_start"] = "2026-06-04T17:00:00Z"
        self.assertFalse(runtime_full_test_scan.interrupted_before_scanner_handoff(report))

    def test_full_test_scan_status_includes_native_report_evidence(self):
        state = {
            "scan_configs": [],
            "port_lists": [],
            "scanners": [],
            "targets": [],
            "tasks": [
                {
                    "id": "task-1",
                    "name": TEST_FULL_TEST_TARGET.task_name,
                    "status": "Done",
                }
            ],
        }
        reports = [
            {
                "id": "report-1",
                "task_id": "task-1",
                "scan_run_status": "Done",
                "scan_start": "2026-06-06T19:25:56Z",
                "result_count": "23",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(
                runtime_full_test_scan, "load_state", return_value=state
            ):
                with unittest.mock.patch.object(
                    runtime_full_test_scan,
                    "reports_for_task",
                    return_value=(reports, None),
                ) as report_lookup:
                    payload = runtime_full_test_scan.command_status(
                        Path(tmp), Path(tmp), TEST_FULL_TEST_TARGET
                    )
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["details"]["latest_report"]["id"], "report-1")
        self.assertEqual(payload["details"]["latest_report"]["result_count"], "23")
        report_lookup.assert_called_once_with(Path(tmp), "task-1")

    def test_full_test_scan_status_separates_no_start_completed_report(self):
        state = {
            "scan_configs": [],
            "port_lists": [],
            "scanners": [],
            "targets": [],
            "tasks": [
                {
                    "id": "task-1",
                    "name": TEST_FULL_TEST_TARGET.task_name,
                    "status": "Done",
                }
            ],
        }
        reports = [
            {
                "id": "report-bad",
                "task_id": "task-1",
                "scan_run_status": "Done",
                "scan_start": None,
                "result_count": "0",
            },
            {
                "id": "report-good",
                "task_id": "task-1",
                "scan_run_status": "Done",
                "scan_start": "2026-06-06T19:25:56Z",
                "result_count": "42",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(
                runtime_full_test_scan, "load_state", return_value=state
            ):
                with unittest.mock.patch.object(
                    runtime_full_test_scan,
                    "reports_for_task",
                    return_value=(reports, None),
                ):
                    payload = runtime_full_test_scan.command_status(
                        Path(tmp), Path(tmp), TEST_FULL_TEST_TARGET
                    )
        self.assertEqual(payload["details"]["latest_report"]["id"], "report-bad")
        self.assertEqual(payload["details"]["latest_completed_report"]["id"], "report-good")
        self.assertEqual(payload["details"]["latest_no_start_completed_report"]["id"], "report-bad")

    def test_runtime_report_paths_live_under_runtime_dir(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "tools" / "yafvsctl").read_text(encoding="utf-8")
        rust_report_source = (root / "tools" / "yafvsctl-rs" / "src" / "commands" / "runtime_report.rs").read_text(encoding="utf-8")
        self.assertFalse((root / "tools" / "runtime_report.py").exists())
        self.assertNotIn("def report_artifact_dir", source)
        self.assertIn('runtime_dir(repo_root).join("artifacts/reports")', rust_report_source)
        self.assertIn("artifacts/reports", yafvsctl.RUNTIME_DIRS)


if __name__ == "__main__":
    unittest.main()
