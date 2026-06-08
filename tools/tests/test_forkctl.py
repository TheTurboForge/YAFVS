# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from importlib.machinery import SourceFileLoader
from pathlib import Path


TURBOVASCTL_PATH = Path(__file__).resolve().parents[1] / "turbovasctl"
SPEC = importlib.util.spec_from_loader("turbovasctl", SourceFileLoader("turbovasctl", str(TURBOVASCTL_PATH)))
turbovasctl = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["turbovasctl"] = turbovasctl
SPEC.loader.exec_module(turbovasctl)

GMP_SMOKE_PATH = Path(__file__).resolve().parents[1] / "runtime_gmp_smoke.py"
GMP_SPEC = importlib.util.spec_from_loader("runtime_gmp_smoke", SourceFileLoader("runtime_gmp_smoke", str(GMP_SMOKE_PATH)))
runtime_gmp_smoke = importlib.util.module_from_spec(GMP_SPEC)
assert GMP_SPEC.loader is not None
sys.modules["runtime_gmp_smoke"] = runtime_gmp_smoke
GMP_SPEC.loader.exec_module(runtime_gmp_smoke)

FEED_OBJECTS_PATH = Path(__file__).resolve().parents[1] / "runtime_feed_objects.py"
FEED_OBJECTS_SPEC = importlib.util.spec_from_loader("runtime_feed_objects", SourceFileLoader("runtime_feed_objects", str(FEED_OBJECTS_PATH)))
runtime_feed_objects = importlib.util.module_from_spec(FEED_OBJECTS_SPEC)
assert FEED_OBJECTS_SPEC.loader is not None
sys.modules["runtime_feed_objects"] = runtime_feed_objects
FEED_OBJECTS_SPEC.loader.exec_module(runtime_feed_objects)

FULL_TEST_SCAN_PATH = Path(__file__).resolve().parents[1] / "runtime_full_test_scan.py"
FULL_TEST_SCAN_SPEC = importlib.util.spec_from_loader("runtime_full_test_scan", SourceFileLoader("runtime_full_test_scan", str(FULL_TEST_SCAN_PATH)))
runtime_full_test_scan = importlib.util.module_from_spec(FULL_TEST_SCAN_SPEC)
assert FULL_TEST_SCAN_SPEC.loader is not None
sys.modules["runtime_full_test_scan"] = runtime_full_test_scan
FULL_TEST_SCAN_SPEC.loader.exec_module(runtime_full_test_scan)

RUNTIME_REPORT_PATH = Path(__file__).resolve().parents[1] / "runtime_report.py"
RUNTIME_REPORT_SPEC = importlib.util.spec_from_loader("runtime_report", SourceFileLoader("runtime_report", str(RUNTIME_REPORT_PATH)))
runtime_report = importlib.util.module_from_spec(RUNTIME_REPORT_SPEC)
assert RUNTIME_REPORT_SPEC.loader is not None
sys.modules["runtime_report"] = runtime_report
RUNTIME_REPORT_SPEC.loader.exec_module(runtime_report)


class TurboVASCtlTests(unittest.TestCase):
    def test_component_registry_has_expected_components(self):
        names = [component.name for component in turbovasctl.COMPONENTS]
        self.assertEqual(len(names), 12)
        self.assertEqual(len(set(names)), 12)
        self.assertIn("openvas-scanner", names)
        self.assertIn("pg-gvm", names)
        self.assertIn("gvm-tools", names)

    def test_build_metadata_covers_all_components(self):
        component_names = {component.name for component in turbovasctl.COMPONENTS}
        self.assertEqual(set(turbovasctl.BUILD_META), component_names)

    def test_core_c_chain_order_is_stable(self):
        self.assertEqual(turbovasctl.CORE_C_CHAIN, ("gvm-libs", "openvas-smb", "openvas-scanner"))

    def test_expanded_chains_are_stable(self):
        self.assertEqual(turbovasctl.C_SERVICES_CHAIN, ("gvm-libs", "openvas-smb", "openvas-scanner", "pg-gvm", "gvmd", "gsad"))
        self.assertEqual(turbovasctl.PYTHON_CHAIN, ("python-gvm", "gvm-tools", "greenbone-feed-sync", "ospd-openvas", "notus-scanner"))

    def test_aggregate_status_prefers_highest_severity(self):
        findings = [
            {"status": "pass"},
            {"status": "warn"},
            {"status": "fail"},
        ]
        self.assertEqual(turbovasctl.aggregate_status(findings), "fail")

    def test_result_json_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = turbovasctl.make_result("status", root, "summary", [{"status": "pass", "check": "x", "message": "ok"}])
            encoded = json.dumps(result)
            decoded = json.loads(encoded)
            self.assertEqual(decoded["status"], "pass")
            self.assertIn("summary", decoded)
            self.assertIn("findings", decoded)
            self.assertIn("artifacts", decoded)
            self.assertIn("metadata", decoded)

    def test_inventory_reports_missing_components(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = turbovasctl.command_inventory(root)
            self.assertEqual(result["status"], "fail")
            missing = [item for item in result["findings"] if item["status"] == "fail"]
            self.assertEqual(len(missing), 12)

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

    def test_license_helpers_detect_modified_imported_notice_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "components" / "gvmd" / "src" / "example.c"
            data = root / "components" / "gsa" / "package.json"
            source.parent.mkdir(parents=True)
            data.parent.mkdir(parents=True)
            source.write_text("/* SPDX-FileCopyrightText: 2024 Greenbone AG\n *\n * SPDX-License-Identifier: AGPL-3.0-or-later\n */\n", encoding="utf-8")
            data.write_text("{}\n", encoding="utf-8")
            rows = [("M", "components/gvmd/src/example.c"), ("M", "components/gsa/package.json")]
            missing, review = turbovasctl.modified_imported_notice_gaps(root, rows)
            self.assertEqual(missing, ["components/gvmd/src/example.c"])
            self.assertEqual(review, ["components/gsa/package.json"])
            source.write_text(source.read_text(encoding="utf-8").replace(" *\n", " * Modified by TurboVAS contributors, 2026.\n *\n", 1), encoding="utf-8")
            missing, review = turbovasctl.modified_imported_notice_gaps(root, rows)
            self.assertEqual(missing, [])
            self.assertEqual(review, ["components/gsa/package.json"])

    def test_no_comment_manifest_requires_current_documented_paths(self):
        review = ["components/gsa/package.json", "components/gsa/public/locales/gsa-en.json", "components/gsa/new-data.json"]
        manifest = {
            "components/gsa/package.json": "JSON package manifest.",
            "components/gsa/public/locales/gsa-en.json": "JSON locale catalog.",
            "components/gsa/stale.json": "No longer modified.",
        }
        documented, undocumented, stale = turbovasctl.modified_imported_no_comment_manifest_gaps(review, manifest)
        self.assertEqual(documented, ["components/gsa/package.json", "components/gsa/public/locales/gsa-en.json"])
        self.assertEqual(undocumented, ["components/gsa/new-data.json"])
        self.assertEqual(stale, ["components/gsa/stale.json"])

    def test_public_readiness_gate_is_explicit(self):
        self.assertEqual(turbovasctl.public_readiness_finding()["status"], "pass")
        self.assertEqual(turbovasctl.public_readiness_finding(public_release=True)["status"], "fail")

    def test_license_helpers_require_spdx_for_new_turbovas_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "tools" / "example.py"
            imported = root / "components" / "pg-gvm" / "src" / "array.c"
            tool.parent.mkdir(parents=True)
            imported.parent.mkdir(parents=True)
            tool.write_text("print('missing header')\n", encoding="utf-8")
            imported.write_text("/* upstream imported file */\n", encoding="utf-8")
            rows = [("A", "tools/example.py"), ("A", "components/pg-gvm/src/array.c")]
            self.assertEqual(turbovasctl.added_turbovas_spdx_gaps(root, rows), ["tools/example.py"])
            tool.write_text("# SPDX-FileCopyrightText: 2026 TurboVAS contributors\n# SPDX-License-Identifier: GPL-3.0-or-later\n\nprint('ok')\n", encoding="utf-8")
            self.assertEqual(turbovasctl.added_turbovas_spdx_gaps(root, rows), [])

    def test_comment_notice_supported_distinguishes_data_files(self):
        self.assertTrue(turbovasctl.comment_notice_supported("components/gvmd/src/manage.c"))
        self.assertTrue(turbovasctl.comment_notice_supported("components/openvas-scanner/compose/tests/smoketest/Makefile"))
        self.assertFalse(turbovasctl.comment_notice_supported("components/gsa/package-lock.json"))
        self.assertFalse(turbovasctl.comment_notice_supported("components/openvas-scanner/rust/src/openvasd/config/snapshots/default.snap"))

    def test_nested_git_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "components" / "example" / ".git"
            nested.mkdir(parents=True)
            self.assertEqual(turbovasctl.nested_git_dirs(root), ["components/example/.git"])

    def test_unknown_component_dependency_check_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = turbovasctl.command_deps(root, "missing-component")
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["findings"][0]["check"], "component.known")

    def test_cmake_paths_use_ignored_build_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, build, prefix = turbovasctl.cmake_paths(root, "gvm-libs")
            self.assertEqual(source, root / "components" / "gvm-libs")
            self.assertEqual(build, root / "build" / "gvm-libs")
            self.assertEqual(prefix, root / "build" / "prefix")

    def test_python_venv_path_uses_ignored_build_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(turbovasctl.venv_python(root, "python-gvm"), root / "build" / "venvs" / "python-gvm" / "bin" / "python")

    def test_version_tuple_parses_tool_versions(self):
        self.assertGreaterEqual(turbovasctl.version_tuple("v22.12.0"), (22, 12, 0))
        self.assertEqual(turbovasctl.version_tuple("11.0.0"), (11, 0, 0))

    def test_runtime_dir_defaults_next_to_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(turbovasctl.runtime_dir(root), Path(tmp) / "TurboVAS-runtime")

    def test_runtime_services_include_scanner_redis(self):
        self.assertEqual(turbovasctl.RUNTIME_SERVICES, ("postgres", "redis", "redis-openvas", "mosquitto"))

    def test_app_services_are_experimental_profile_services(self):
        self.assertEqual(turbovasctl.APP_SERVICES, ("gvmd", "ospd-openvas", "notus-scanner", "gsad"))

    def test_gsad_port_defaults_loopback_and_can_be_overridden(self):
        self.assertEqual(turbovasctl.DEFAULT_GSAD_HOST, "127.0.0.1")
        self.assertEqual(turbovasctl.GSAD_HOST_ENV, "TURBOVAS_GSAD_HOST")
        self.assertEqual(turbovasctl.GSAD_HOSTS_ENV, "TURBOVAS_GSAD_HOSTS")
        self.assertEqual(turbovasctl.APP_PORTS["gsad"], "${TURBOVAS_GSAD_HOST:-127.0.0.1}:19392:9392")
        self.assertEqual(turbovasctl.DEV_ADMIN_USER, "admin")
        self.assertEqual(turbovasctl.DEV_ADMIN_PASSWORD, "admin")

    def test_runtime_secret_helper_accepts_default_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            secret, created = turbovasctl.read_or_create_runtime_secret(root, "example", "admin")
            self.assertTrue(created)
            self.assertEqual(secret, "admin")
            secret_path = turbovasctl.runtime_secret_path(root, "example")
            self.assertEqual(secret_path.read_text(encoding="utf-8").strip(), "admin")

    def test_runtime_dirs_include_application_state(self):
        self.assertIn("certs/CA", turbovasctl.RUNTIME_DIRS)
        self.assertIn("certs/private/CA", turbovasctl.RUNTIME_DIRS)
        self.assertIn("secrets", turbovasctl.RUNTIME_DIRS)
        self.assertIn("state/feed-gnupg", turbovasctl.RUNTIME_DIRS)
        self.assertIn("redis-openvas", turbovasctl.RUNTIME_DIRS)
        self.assertIn("run/gvmd", turbovasctl.RUNTIME_DIRS)
        self.assertIn("run/ospd", turbovasctl.RUNTIME_DIRS)
        self.assertIn("run/notus", turbovasctl.RUNTIME_DIRS)
        self.assertIn("run/redis-openvas", turbovasctl.RUNTIME_DIRS)
        self.assertIn("logs/notus", turbovasctl.RUNTIME_DIRS)
        self.assertIn("feeds/notus/products", turbovasctl.RUNTIME_DIRS)

    def test_cert_files_live_under_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            files = turbovasctl.cert_files(root)
            self.assertEqual(files["ca_cert"], Path(tmp) / "TurboVAS-runtime" / "certs" / "CA" / "cacert.pem")
            self.assertEqual(files["client_key"], Path(tmp) / "TurboVAS-runtime" / "certs" / "private" / "CA" / "clientkey.pem")

    def test_compose_command_uses_dev_compose_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = turbovasctl.compose_command(root, "ps")
            self.assertEqual(command[:4], ["docker", "compose", "-f", str(root / "compose" / "dev.yaml")])
            self.assertEqual(command[-1], "ps")

    def test_compose_command_adds_gsad_ports_override_for_multiple_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compose").mkdir()
            (root / "compose" / "dev.yaml").write_text("services: {}\n", encoding="utf-8")
            original = turbovasctl.os.environ.get(turbovasctl.GSAD_HOSTS_ENV)
            try:
                turbovasctl.os.environ[turbovasctl.GSAD_HOSTS_ENV] = "192.168.178.42,100.80.139.13"
                command = turbovasctl.compose_command(root, "config")
            finally:
                if original is None:
                    turbovasctl.os.environ.pop(turbovasctl.GSAD_HOSTS_ENV, None)
                else:
                    turbovasctl.os.environ[turbovasctl.GSAD_HOSTS_ENV] = original
            override = turbovasctl.gsad_ports_override_file(root)
            self.assertIn(str(override), command)
            text = override.read_text(encoding="utf-8")
            self.assertIn("ports: !override", text)
            self.assertIn('"192.168.178.42:19392:9392"', text)
            self.assertIn('"100.80.139.13:19392:9392"', text)

    def test_scanner_redis_paths_live_under_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(turbovasctl.scanner_redis_socket_path(root), Path(tmp) / "TurboVAS-runtime" / "run" / "redis-openvas" / "redis.sock")
            self.assertEqual(turbovasctl.openvas_runtime_config_path(root), root / "build" / "prefix" / "etc" / "openvas" / "openvas.conf")
            self.assertEqual(turbovasctl.runtime_feed_objects_probe_path(root), root / "tools" / "runtime_feed_objects.py")
            self.assertEqual(turbovasctl.runtime_full_test_scan_probe_path(root), root / "tools" / "runtime_full_test_scan.py")
            self.assertEqual(turbovasctl.full_test_scan_artifact_dir(root), Path(tmp) / "TurboVAS-runtime" / "artifacts" / "full-test-scan")

    def test_feed_paths_live_under_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(turbovasctl.feed_cache_var_lib(root), Path(tmp) / "TurboVAS-runtime" / "feed-cache" / "community" / "22.04" / "var-lib")
            self.assertEqual(turbovasctl.feed_runtime_root(root), Path(tmp) / "TurboVAS-runtime" / "feeds")
            self.assertEqual(turbovasctl.feed_sync_log_dir(root), Path(tmp) / "TurboVAS-runtime" / "logs" / "feed-sync")

    def test_feed_keyring_paths_live_under_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(turbovasctl.feed_gnupg_home(root), Path(tmp) / "TurboVAS-runtime" / "state" / "feed-gnupg")
            self.assertEqual(turbovasctl.feed_keyring_artifact_dir(root), Path(tmp) / "TurboVAS-runtime" / "artifacts" / "feed-keyring")
            self.assertEqual(turbovasctl.feed_community_key_path(root), Path(tmp) / "TurboVAS-runtime" / "artifacts" / "feed-keyring" / "GBCommunitySigningKey.asc")
            self.assertEqual(turbovasctl.gvm_cli_path(root), root / "build" / "venvs" / "gvm-tools" / "bin" / "gvm-cli")

    def test_feed_keyring_constants_match_greenbone_community_key(self):
        self.assertEqual(turbovasctl.GREENBONE_COMMUNITY_KEY_FPR, "8AE4BE429B60A59B311C2E739823FAA60ED1E580")
        self.assertEqual(turbovasctl.GREENBONE_COMMUNITY_KEY_URL, "https://www.greenbone.net/GBCommunitySigningKey.asc")

    def test_capability_helpers_detect_required_scanner_caps(self):
        self.assertTrue(turbovasctl.cap_hex_has("0000000000003000", 12))
        self.assertTrue(turbovasctl.cap_hex_has("0000000000003000", 13))
        self.assertEqual(turbovasctl.missing_required_caps("0000000000003000"), [])
        self.assertEqual(turbovasctl.missing_required_caps("0000000000001000"), ["NET_RAW"])

    def test_scanner_hostname_guard_rejects_docker_short_ids(self):
        self.assertEqual(turbovasctl.OSPD_STABLE_HOSTNAME, "turbovas-ospd-openvas")
        self.assertTrue(turbovasctl.hostname_looks_like_docker_short_id("b758d8ce41ff"))
        self.assertFalse(turbovasctl.hostname_looks_like_docker_short_id("turbovas-ospd-openvas"))
        self.assertFalse(turbovasctl.hostname_looks_like_docker_short_id("scan-node-01"))

    def test_proc_status_helpers_parse_ids(self):
        values = turbovasctl.parse_proc_status("Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
        self.assertEqual(turbovasctl.first_proc_status_id(values["Uid"]), "1000")
        self.assertEqual(turbovasctl.first_proc_status_id(values["Gid"]), "1000")

    def test_ospd_setpriv_raw_socket_probe_uses_non_root_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            command = turbovasctl.ospd_setpriv_raw_socket_probe_command(root)
            self.assertEqual(command[:2], ["setpriv", "--reuid"])
            self.assertIn("--ambient-caps", command)
            self.assertIn("+net_raw,+net_admin", command)
            self.assertIn("socket.SOCK_RAW", command[-1])

    def test_ospd_setpriv_nmap_probes_use_privileged_env_and_non_root_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            probes = turbovasctl.ospd_setpriv_nmap_probe_commands(root)
            self.assertEqual([check for check, _ in probes], ["nmap.raw-syn", "nmap.os-detection"])
            for _, command in probes:
                self.assertEqual(command[:2], ["setpriv", "--reuid"])
                self.assertIn("--ambient-caps", command)
                self.assertIn("+net_raw,+net_admin", command)
                self.assertIn("NMAP_PRIVILEGED=1", command[-1])
                self.assertIn("127.0.0.1", command[-1])
            self.assertIn("http.server 18080", probes[1][1][-1])
            self.assertIn("18080", probes[1][1][-1])

    def test_nmap_privilege_warning_detection(self):
        self.assertTrue(turbovasctl.nmap_privilege_warning_present("You requested a scan type which requires root privileges."))
        self.assertFalse(turbovasctl.nmap_privilege_warning_present("Nmap done: 1 IP address scanned."))

    def test_scanner_process_summary_counts_zombies_and_active_children(self):
        output = """    PID    PPID STAT COMMAND         COMMAND
      1       0 Ss   ospd-openvas    /workspace/build/venvs/ospd-openvas/bin/ospd-openvas --foreground
    115       1 Z    python3         [python3] <defunct>
    444       1 ZN   nmap            [nmap] <defunct>
    800       1 SN   nmap            nmap -sS -O 127.0.0.1
    900       1 S    openvas         openvas --scan-start
"""
        summary = turbovasctl.summarize_scanner_processes(output)
        self.assertEqual(summary["process_count"], 5)
        self.assertEqual(summary["zombie_count"], 2)
        self.assertEqual(summary["active_scanner_child_count"], 2)
        self.assertEqual([process["comm"] for process in summary["zombies"]], ["python3", "nmap"])

    def test_scanner_process_summary_ignores_zombies_as_active_children(self):
        output = """    PID    PPID STAT COMMAND         COMMAND
      1       0 Ss   ospd-openvas    /workspace/build/venvs/ospd-openvas/bin/ospd-openvas --foreground
    444       1 ZN   nmap            [nmap] <defunct>
"""
        summary = turbovasctl.summarize_scanner_processes(output)
        self.assertEqual(summary["zombie_count"], 1)
        self.assertEqual(summary["active_scanner_child_count"], 0)

    def test_scanner_process_summary_does_not_count_docker_init_as_scanner_child(self):
        output = """    PID    PPID STAT COMMAND         COMMAND
      1       0 Ss   docker-init     /sbin/docker-init -- sh -lc exec setpriv /workspace/build/venvs/ospd-openvas/bin/ospd-openvas --foreground
      7       1 Sl   ospd-openvas    /workspace/build/venvs/ospd-openvas/bin/ospd-openvas --foreground
"""
        summary = turbovasctl.summarize_scanner_processes(output)
        self.assertEqual(summary["zombie_count"], 0)
        self.assertEqual(summary["active_scanner_child_count"], 0)

    def test_gsa_static_staging_writes_browser_relative_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            build = root / "components" / "gsa" / "build"
            (build / "assets").mkdir(parents=True)
            (build / "index.html").write_text('<script src="/assets/index.js"></script><div id="app"></div>', encoding="utf-8")
            (build / "assets" / "index.js").write_text("console.log('ok');\n", encoding="utf-8")
            original = turbovasctl.os.environ.get(turbovasctl.GSAD_HOSTS_ENV)
            try:
                turbovasctl.os.environ[turbovasctl.GSAD_HOSTS_ENV] = "192.168.178.42,100.80.139.13"
                findings = turbovasctl.stage_gsa_static(root)
            finally:
                if original is None:
                    turbovasctl.os.environ.pop(turbovasctl.GSAD_HOSTS_ENV, None)
                else:
                    turbovasctl.os.environ[turbovasctl.GSAD_HOSTS_ENV] = original
            self.assertEqual(turbovasctl.aggregate_status(findings), "pass")
            config = turbovasctl.gsad_static_dir(root) / "config.js"
            config_text = config.read_text(encoding="utf-8")
            self.assertIn("apiServer: window.location.host || '192.168.178.42:19392'", config_text)
            self.assertIn("apiProtocol: (window.location.protocol || 'https:').replace(':', '')", config_text)
            self.assertEqual(turbovasctl.first_gsa_asset_rel((turbovasctl.gsad_static_dir(root) / "index.html").read_text(encoding="utf-8")), "assets/index.js")

    def test_feed_community_key_download_command_targets_runtime_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            command = turbovasctl.feed_community_key_download_command(root)
            self.assertEqual(command[:3], ["curl", "-fsSL", "-o"])
            self.assertEqual(command[3], str(turbovasctl.feed_community_key_path(root)))
            self.assertEqual(command[4], turbovasctl.GREENBONE_COMMUNITY_KEY_URL)

    def test_notus_signature_files_use_runtime_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            signature_files = turbovasctl.notus_signature_files(root)
            self.assertEqual(
                signature_files,
                [
                    (
                        "advisories",
                        Path(tmp) / "TurboVAS-runtime" / "feeds" / "notus" / "advisories" / "sha256sums",
                        Path(tmp) / "TurboVAS-runtime" / "feeds" / "notus" / "advisories" / "sha256sums.asc",
                    ),
                    (
                        "products",
                        Path(tmp) / "TurboVAS-runtime" / "feeds" / "notus" / "products" / "sha256sums",
                        Path(tmp) / "TurboVAS-runtime" / "feeds" / "notus" / "products" / "sha256sums.asc",
                    ),
                ],
            )

    def test_feed_sync_command_uses_full_22_04_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            command = turbovasctl.feed_sync_command(root)
            self.assertIn("--type", command)
            self.assertEqual(command[command.index("--type") + 1], "all")
            self.assertEqual(command[command.index("--feed-release") + 1], "22.04")
            self.assertEqual(command[command.index("--destination-prefix") + 1], str(turbovasctl.feed_cache_var_lib(root)))

    def test_feed_copy_pairs_are_known_subtrees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            pairs = [
                (feed_class.key, source.relative_to(turbovasctl.feed_cache_var_lib(root)), destination.relative_to(turbovasctl.feed_runtime_root(root)))
                for feed_class, source, destination in turbovasctl.feed_copy_pairs(root)
            ]
            self.assertEqual(
                pairs,
                [
                    ("nasl", Path("openvas/plugins"), Path("openvas/plugins")),
                    ("notus", Path("notus"), Path("notus")),
                    ("scap", Path("gvm/scap-data"), Path("gvm/scap-data")),
                    ("cert", Path("gvm/cert-data"), Path("gvm/cert-data")),
                    ("gvmd", Path("gvm/data-objects/gvmd/22.04"), Path("gvm/data-objects/gvmd/22.04")),
                ],
            )

    def test_runtime_feed_mappings_point_to_runtime_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            mappings = turbovasctl.runtime_feed_mapping_paths(root)
            self.assertEqual(
                [(mapping.key, path.relative_to(root), mapping.container_target) for mapping, path in mappings],
                [
                    ("nasl", Path("build/var/lib/openvas/plugins"), "/runtime/feeds/openvas/plugins"),
                    ("gvmd", Path("build/var/lib/gvm/data-objects/gvmd"), "/runtime/feeds/gvm/data-objects/gvmd/22.04"),
                    ("scap", Path("build/var/lib/gvm/scap-data"), "/runtime/feeds/gvm/scap-data"),
                    ("cert", Path("build/var/lib/gvm/cert-data"), "/runtime/feeds/gvm/cert-data"),
                ],
            )
            self.assertTrue(all("feed-cache" not in mapping.container_target for mapping, _path in mappings))

    def test_runtime_feed_mapping_creates_missing_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            findings = turbovasctl.ensure_runtime_feed_mappings(root)
            self.assertEqual(turbovasctl.aggregate_status(findings), "pass")
            for mapping, path in turbovasctl.runtime_feed_mapping_paths(root):
                self.assertTrue(path.is_symlink())
                self.assertEqual(path.readlink(), Path(mapping.container_target))

    def test_runtime_feed_mapping_retargets_stale_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            first_mapping, first_path = turbovasctl.runtime_feed_mapping_paths(root)[0]
            first_path.parent.mkdir(parents=True)
            first_path.symlink_to("/runtime/feeds/old")
            findings = turbovasctl.ensure_runtime_feed_mappings(root)
            first_finding = next(item for item in findings if item["check"] == f"feed-map.{first_mapping.key}")
            self.assertEqual(first_finding["status"], "pass")
            self.assertEqual(first_path.readlink(), Path(first_mapping.container_target))

    def test_runtime_feed_mapping_refuses_non_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            first_mapping, first_path = turbovasctl.runtime_feed_mapping_paths(root)[0]
            first_path.mkdir(parents=True)
            marker = first_path / "keep.txt"
            marker.write_text("do not replace\n", encoding="utf-8")
            findings = turbovasctl.ensure_runtime_feed_mappings(root)
            first_finding = next(item for item in findings if item["check"] == f"feed-map.{first_mapping.key}")
            self.assertEqual(first_finding["status"], "fail")
            self.assertTrue(marker.is_file())

    def test_ospd_vt_load_status_from_logs(self):
        self.assertEqual(
            turbovasctl.ospd_vt_load_status_from_logs(["OSPD: Loading VTs. Scans will be queued"])[0],
            "wait",
        )
        self.assertEqual(
            turbovasctl.ospd_vt_load_status_from_logs(["OSPD: VTs were up to date. Feed version is 202605221736."])[0],
            "pass",
        )
        self.assertEqual(
            turbovasctl.ospd_vt_load_status_from_logs(["OSPD: OpenVAS Scanner failed to load VTs."])[0],
            "fail",
        )

    def test_ospd_vts_version_probe_uses_runtime_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            command = turbovasctl.ospd_vts_version_probe_command(root)
            self.assertEqual(command[0], str(turbovasctl.gvm_cli_path(root)))
            self.assertIn("--protocol", command)
            self.assertEqual(command[command.index("--protocol") + 1], "OSP")
            self.assertIn("--socketpath", command)
            self.assertEqual(command[command.index("--socketpath") + 1], str(turbovasctl.ospd_socket_path(root)))
            self.assertIn('<get_vts version_only="1"/>', command)

    def test_parse_ospd_vts_version(self):
        response = (
            '<get_vts_response status="200" status_text="OK">'
            '<vts vts_version="202605221736" feed_vendor="Greenbone AG" total="" />'
            "</get_vts_response>"
        )
        self.assertEqual(turbovasctl.parse_ospd_vts_version(response), "202605221736")
        self.assertIsNone(turbovasctl.parse_ospd_vts_version("<get_vts_response/>"))
        self.assertIsNone(turbovasctl.parse_ospd_vts_version("not xml"))

    def test_wait_for_ospd_vts_version_retries_still_starting(self):
        responses = [
            '<error_response status="400" status_text="OSPd OpenVAS is still starting" />',
            '<get_vts_response status="200" status_text="OK"><vts vts_version="202605221736" /></get_vts_response>',
        ]
        original_run_command = turbovasctl.run_command
        original_sleep = turbovasctl.time.sleep

        def fake_run_command(*_args, **_kwargs):
            return turbovasctl.subprocess.CompletedProcess([], 0, responses.pop(0), "")

        try:
            turbovasctl.run_command = fake_run_command
            turbovasctl.time.sleep = lambda _seconds: None
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "TurboVAS"
                root.mkdir()
                version, output = turbovasctl.wait_for_ospd_vts_version(root)
        finally:
            turbovasctl.run_command = original_run_command
            turbovasctl.time.sleep = original_sleep

        self.assertEqual(version, "202605221736")
        self.assertIn("202605221736", "\n".join(output))

    def test_nvts_feed_version_query_targets_meta_table(self):
        self.assertIn("nvts_feed_version", turbovasctl.nvts_feed_version_query())
        self.assertIn("meta", turbovasctl.nvts_feed_version_query())

    def test_feed_state_reports_missing_cache_and_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            result = turbovasctl.command_feed_state(root)
            self.assertEqual(result["status"], "warn")
            checks = {item["check"]: item["status"] for item in result["findings"]}
            self.assertEqual(checks["feed.cache.nasl"], "warn")
            self.assertEqual(checks["feed.runtime.nasl"], "warn")

    def test_openvas_runtime_config_includes_feed_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            path = turbovasctl.write_openvas_runtime_config(root)
            text = path.read_text(encoding="utf-8")
            self.assertIn("db_address = /runtime/run/redis-openvas/redis.sock", text)
            self.assertIn("plugins_folder = /runtime/feeds/openvas/plugins", text)
            self.assertIn("include_folders = /runtime/feeds/openvas/plugins", text)

    def test_runtime_plan_json_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = turbovasctl.command_runtime_plan(root)
            self.assertEqual(result["status"], "warn")
            self.assertIn("Persistent Docker runtime plan", result["summary"])
            self.assertIn(str(root.parent / "TurboVAS-runtime"), result["artifacts"])

    def test_postgres_collation_databases_include_runtime_and_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(turbovasctl.postgres_collation_databases(root), ("turbovas", "postgres", "template1"))

    def test_postgres_collation_checks_all_development_databases(self):
        calls = []
        original_psql = turbovasctl.psql

        def fake_psql(_root, sql, database=None):
            calls.append((sql, database))
            return turbovasctl.subprocess.CompletedProcess([], 0, "2.41|2.41\n", "")

        try:
            turbovasctl.psql = fake_psql
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "TurboVAS"
                root.mkdir()
                findings = turbovasctl.ensure_postgres_collation(root, refresh_empty=False)
        finally:
            turbovasctl.psql = original_psql

        self.assertEqual([finding["details"]["database"] for finding in findings], ["turbovas", "postgres", "template1"])
        self.assertTrue(all(finding["status"] == "pass" for finding in findings))
        self.assertEqual([call[1] for call in calls], ["turbovas", "postgres", "template1"])

    def test_postgres_collation_refreshes_empty_database_from_alternate_connection(self):
        calls = []
        original_psql = turbovasctl.psql

        def fake_psql(_root, sql, database=None):
            calls.append((sql, database))
            if "datcollversion" in sql:
                return turbovasctl.subprocess.CompletedProcess([], 0, "2.36|2.41\n", "")
            if "count(*) FROM pg_class" in sql:
                return turbovasctl.subprocess.CompletedProcess([], 0, "0\n", "")
            if "ALTER DATABASE" in sql:
                return turbovasctl.subprocess.CompletedProcess([], 0, "ALTER DATABASE\n", "")
            return turbovasctl.subprocess.CompletedProcess([], 1, "unexpected\n", "")

        try:
            turbovasctl.psql = fake_psql
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "TurboVAS"
                root.mkdir()
                finding = turbovasctl.ensure_postgres_database_collation(root, "template1", refresh_empty=True)
        finally:
            turbovasctl.psql = original_psql

        self.assertEqual(finding["status"], "pass")
        self.assertEqual(finding["details"]["database"], "template1")
        self.assertEqual(calls[-1][1], "turbovas")
        self.assertIn('ALTER DATABASE "template1" REFRESH COLLATION VERSION', calls[-1][0])

    def test_sql_escaping_helpers(self):
        self.assertEqual(turbovasctl.sql_identifier('a"b'), '"a""b"')
        self.assertEqual(turbovasctl.sql_literal("a'b"), "'a''b'")

    def test_gmp_smoke_parse_version_accepts_text_and_element(self):
        self.assertEqual(runtime_gmp_smoke.parse_version("<get_version_response><version>22.7</version></get_version_response>"), "22.7")
        element = ET.fromstring("<get_version_response><version>22.8</version></get_version_response>")
        self.assertEqual(runtime_gmp_smoke.parse_version(element), "22.8")

    def test_runtime_feed_objects_detect_expected_ids(self):
        configs = (
            "<get_configs_response>"
            f"<config id=\"{runtime_feed_objects.FULL_AND_FAST_SCAN_CONFIG_ID}\"><name>Full and fast</name></config>"
            "</get_configs_response>"
        )
        port_lists = (
            "<get_port_lists_response>"
            f"<port_list id=\"{runtime_feed_objects.IANA_TCP_UDP_PORT_LIST_ID}\"><name>All IANA assigned TCP and UDP</name></port_list>"
            "</get_port_lists_response>"
        )
        config_rows = runtime_feed_objects.object_rows(configs, "config")
        port_list_rows = runtime_feed_objects.object_rows(port_lists, "port_list")
        self.assertTrue(runtime_feed_objects.expected_present(config_rows, runtime_feed_objects.FULL_AND_FAST_SCAN_CONFIG_ID))
        self.assertTrue(runtime_feed_objects.expected_present(port_list_rows, runtime_feed_objects.IANA_TCP_UDP_PORT_LIST_ID))
        self.assertEqual(config_rows[0]["name"], "Full and fast")
        self.assertEqual(port_list_rows[0]["name"], "All IANA assigned TCP and UDP")

    def test_full_test_scan_constants_are_fixed_to_authorized_lan(self):
        self.assertEqual(runtime_full_test_scan.AUTHORIZED_TARGET_CIDR, "192.168.178.0/24")
        self.assertEqual(runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID, turbovasctl.FULL_AND_FAST_SCAN_CONFIG_ID)
        self.assertEqual(runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID, turbovasctl.IANA_TCP_UDP_PORT_LIST_ID)

    def test_full_test_scan_detects_active_duplicate_task(self):
        rows = [
            {"name": runtime_full_test_scan.FULL_TEST_TASK_NAME, "status": "Running", "id": "active"},
            {"name": runtime_full_test_scan.FULL_TEST_TASK_NAME, "status": "New", "id": "created-not-started"},
            {"name": runtime_full_test_scan.FULL_TEST_TASK_NAME, "status": "Done", "id": "done"},
        ]
        active = runtime_full_test_scan.active_full_test_tasks(rows)
        self.assertEqual([row["id"] for row in active], ["active"])

    def test_full_test_scan_start_requires_authorization_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = runtime_full_test_scan.command_start(object(), Path(tmp), confirm_authorized_lan=False)
            self.assertEqual(payload["status"], "fail")
            self.assertIn("--confirm-authorized-lan", payload["summary"])
            self.assertTrue((Path(tmp) / "start-refused.json").is_file())

    def test_full_test_scan_start_records_broken_pipe_during_poll(self):
        class FakeGMP:
            broken = False

            def _raise_if_broken(self):
                if self.broken:
                    raise BrokenPipeError(32, "Broken pipe")

            def get_scan_configs(self):
                self._raise_if_broken()
                return (
                    "<get_configs_response>"
                    f"<config id=\"{runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID}\"><name>Full and fast</name></config>"
                    "</get_configs_response>"
                )

            def get_port_lists(self):
                self._raise_if_broken()
                return (
                    "<get_port_lists_response>"
                    f"<port_list id=\"{runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID}\"><name>All IANA assigned TCP and UDP</name></port_list>"
                    "</get_port_lists_response>"
                )

            def get_scanners(self, details=True):
                self._raise_if_broken()
                return (
                    "<get_scanners_response>"
                    f"<scanner id=\"scanner-1\"><name>{runtime_full_test_scan.OPENVAS_SCANNER_NAME}</name></scanner>"
                    "</get_scanners_response>"
                )

            def get_targets(self, tasks=True):
                self._raise_if_broken()
                return (
                    "<get_targets_response>"
                    f"<target id=\"target-1\"><name>{runtime_full_test_scan.FULL_TEST_TARGET_NAME}</name></target>"
                    "</get_targets_response>"
                )

            def get_tasks(self, details=True, ignore_pagination=True):
                self._raise_if_broken()
                return (
                    "<get_tasks_response>"
                    f"<task id=\"task-1\"><name>{runtime_full_test_scan.FULL_TEST_TASK_NAME}</name><status>Done</status></task>"
                    "</get_tasks_response>"
                )

            def get_reports(self, filter_string=None, details=True, ignore_pagination=True):
                self._raise_if_broken()
                return "<get_reports_response/>"

            def start_task(self, task_id):
                self.broken = True
                raise BrokenPipeError(32, "Broken pipe")

        with tempfile.TemporaryDirectory() as tmp:
            payload = runtime_full_test_scan.command_start(
                FakeGMP(),
                Path(tmp),
                confirm_authorized_lan=True,
                poll_seconds=1,
                poll_interval=0,
            )
            artifact_exists = (Path(tmp) / "start-failed.json").is_file()
        self.assertEqual(payload["status"], "fail")
        self.assertIn("before scanner handoff", payload["summary"])
        self.assertIn("BrokenPipeError", payload["details"]["start_error"])
        self.assertIn("BrokenPipeError", payload["details"]["observed_state"]["poll_error"])
        self.assertTrue(artifact_exists)

    def test_full_test_scan_start_reconnects_after_closed_start_response(self):
        class BaseFakeGMP:
            def get_scan_configs(self):
                return (
                    "<get_configs_response>"
                    f"<config id=\"{runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID}\"><name>Full and fast</name></config>"
                    "</get_configs_response>"
                )

            def get_port_lists(self):
                return (
                    "<get_port_lists_response>"
                    f"<port_list id=\"{runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID}\"><name>All IANA assigned TCP and UDP</name></port_list>"
                    "</get_port_lists_response>"
                )

            def get_scanners(self, details=True):
                return (
                    "<get_scanners_response>"
                    f"<scanner id=\"scanner-1\"><name>{runtime_full_test_scan.OPENVAS_SCANNER_NAME}</name></scanner>"
                    "</get_scanners_response>"
                )

            def get_targets(self, tasks=True):
                return (
                    "<get_targets_response>"
                    f"<target id=\"target-1\"><name>{runtime_full_test_scan.FULL_TEST_TARGET_NAME}</name></target>"
                    "</get_targets_response>"
                )

            def get_reports(self, filter_string=None, details=True, ignore_pagination=True):
                return "<get_reports_response/>"

        class InitialGMP(BaseFakeGMP):
            def get_tasks(self, details=True, ignore_pagination=True):
                return (
                    "<get_tasks_response>"
                    f"<task id=\"task-1\"><name>{runtime_full_test_scan.FULL_TEST_TASK_NAME}</name><status>Done</status></task>"
                    "</get_tasks_response>"
                )

            def start_task(self, task_id):
                raise RuntimeError("Remote closed the connection")

        class ReconnectedGMP(BaseFakeGMP):
            def get_tasks(self, details=True, ignore_pagination=True):
                return (
                    "<get_tasks_response>"
                    f"<task id=\"task-1\"><name>{runtime_full_test_scan.FULL_TEST_TASK_NAME}</name><status>Queued</status><progress>0</progress></task>"
                    "</get_tasks_response>"
                )

            def get_reports(self, filter_string=None, details=True, ignore_pagination=True):
                return (
                    "<get_reports_response>"
                    "<report id=\"report-new\"><task id=\"task-1\"/>"
                    "<report id=\"report-new\"><scan_run_status>Queued</scan_run_status></report>"
                    "</report>"
                    "</get_reports_response>"
                )

        reconnect_count = 0

        def reconnect():
            nonlocal reconnect_count
            reconnect_count += 1
            return ReconnectedGMP()

        with tempfile.TemporaryDirectory() as tmp:
            payload = runtime_full_test_scan.command_start(
                InitialGMP(),
                Path(tmp),
                confirm_authorized_lan=True,
                poll_seconds=1,
                poll_interval=0,
                reconnect_gmp=reconnect,
            )
        self.assertEqual(payload["status"], "pass")
        self.assertIn("Remote closed", payload["details"]["start_error"])
        self.assertEqual(payload["details"]["observed_report"]["id"], "report-new")
        self.assertEqual(reconnect_count, 1)

    def test_full_test_scan_preflight_parses_required_objects(self):
        state = {
            "scan_configs": [{"id": runtime_full_test_scan.FULL_AND_FAST_SCAN_CONFIG_ID, "name": "Full and fast"}],
            "port_lists": [{"id": runtime_full_test_scan.IANA_TCP_UDP_PORT_LIST_ID, "name": "All IANA assigned TCP and UDP"}],
            "scanners": [{"id": "scanner-1", "name": runtime_full_test_scan.OPENVAS_SCANNER_NAME}],
            "targets": [],
            "tasks": [],
        }
        payload = runtime_full_test_scan.preflight_state(state)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["details"]["scanner"]["id"], "scanner-1")

    def test_full_test_scan_object_rows_include_progress_and_report(self):
        response = (
            "<get_tasks_response>"
            "<task id=\"task-1\">"
            "<name>scan</name><status>Running</status><progress>42</progress>"
            "<report id=\"report-1\"/>"
            "</task>"
            "</get_tasks_response>"
        )
        row = runtime_full_test_scan.object_rows(response, "task")[0]
        self.assertEqual(row["progress"], "42")
        self.assertEqual(row["report_id"], "report-1")

    def test_full_test_scan_response_id_reads_start_task_report_id(self):
        response = "<start_task_response status=\"202\"><report_id>report-1</report_id></start_task_response>"
        self.assertEqual(runtime_full_test_scan.response_id(response), "report-1")

    def test_full_test_scan_report_handoff_excludes_requested_only(self):
        self.assertFalse(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Requested"}))
        self.assertTrue(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Queued"}))
        self.assertTrue(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Running"}))
        self.assertFalse(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Done"}))
        self.assertTrue(runtime_full_test_scan.report_handoff_observed({"scan_run_status": "Done", "scan_start": "2026-06-06T20:05:00Z"}))

    def test_full_test_scan_report_rows_parse_inner_report_summary(self):
        response = (
            "<get_reports_response>"
            "<report id=\"report-1\">"
            "<name>2026-06-02T15:59:28Z</name>"
            "<task id=\"task-1\"/>"
            "<report id=\"report-1\">"
            "<scan_run_status>Done</scan_run_status>"
            "<scan_start>2026-06-02T15:59:50Z</scan_start>"
            "<scan_end>2026-06-02T16:02:15Z</scan_end>"
            "<hosts><count>4</count></hosts>"
            "<vulns><count>6</count></vulns>"
            "<cves><count>3</count></cves>"
            "<os><count>2</count></os>"
            "<result_count><full>23</full></result_count>"
            "</report>"
            "</report>"
            "</get_reports_response>"
        )
        row = runtime_full_test_scan.report_rows(response)[0]
        self.assertEqual(row["id"], "report-1")
        self.assertEqual(row["task_id"], "task-1")
        self.assertEqual(row["scan_run_status"], "Done")
        self.assertEqual(row["scan_start"], "2026-06-02T15:59:50Z")
        self.assertEqual(row["scan_end"], "2026-06-02T16:02:15Z")
        self.assertEqual(row["result_count"], "23")
        self.assertEqual(row["hosts_count"], "4")
        self.assertEqual(row["vulns_count"], "6")

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

    def test_full_test_scan_status_includes_latest_report(self):
        class FakeGMP:
            def get_scan_configs(self):
                return "<get_configs_response/>"

            def get_port_lists(self):
                return "<get_port_lists_response/>"

            def get_scanners(self, details=True):
                return "<get_scanners_response/>"

            def get_targets(self, tasks=True):
                return "<get_targets_response/>"

            def get_tasks(self, details=True, ignore_pagination=True):
                return (
                    "<get_tasks_response>"
                    "<task id=\"task-1\">"
                    f"<name>{runtime_full_test_scan.FULL_TEST_TASK_NAME}</name>"
                    "<status>Done</status>"
                    "</task>"
                    "</get_tasks_response>"
                )

            def get_reports(self, filter_string=None, details=True, ignore_pagination=True):
                self.filter_string = filter_string
                return (
                    "<get_reports_response>"
                    "<report id=\"report-1\">"
                    "<task id=\"task-1\"/>"
                    "<report id=\"report-1\">"
                    "<scan_run_status>Done</scan_run_status>"
                    "<scan_start>2026-06-06T19:25:56Z</scan_start>"
                    "<result_count><full>23</full></result_count>"
                    "</report>"
                    "</report>"
                    "</get_reports_response>"
                )

        fake = FakeGMP()
        with tempfile.TemporaryDirectory() as tmp:
            payload = runtime_full_test_scan.command_status(fake, Path(tmp))
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["details"]["latest_report"]["id"], "report-1")
        self.assertEqual(payload["details"]["latest_report"]["result_count"], "23")
        self.assertIn("task_id=task-1", fake.filter_string)

    def test_full_test_scan_status_separates_no_start_completed_report(self):
        class FakeGMP:
            def get_scan_configs(self):
                return "<get_configs_response/>"

            def get_port_lists(self):
                return "<get_port_lists_response/>"

            def get_scanners(self, details=True):
                return "<get_scanners_response/>"

            def get_targets(self, tasks=True):
                return "<get_targets_response/>"

            def get_tasks(self, details=True, ignore_pagination=True):
                return (
                    "<get_tasks_response>"
                    "<task id=\"task-1\">"
                    f"<name>{runtime_full_test_scan.FULL_TEST_TASK_NAME}</name>"
                    "<status>Done</status>"
                    "</task>"
                    "</get_tasks_response>"
                )

            def get_reports(self, filter_string=None, details=True, ignore_pagination=True):
                return (
                    "<get_reports_response>"
                    "<report id=\"report-bad\"><task id=\"task-1\"/>"
                    "<report id=\"report-bad\"><scan_run_status>Done</scan_run_status>"
                    "<result_count><full>0</full></result_count></report></report>"
                    "<report id=\"report-good\"><task id=\"task-1\"/>"
                    "<report id=\"report-good\"><scan_run_status>Done</scan_run_status>"
                    "<scan_start>2026-06-06T19:25:56Z</scan_start>"
                    "<result_count><full>42</full></result_count></report></report>"
                    "</get_reports_response>"
                )

        with tempfile.TemporaryDirectory() as tmp:
            payload = runtime_full_test_scan.command_status(FakeGMP(), Path(tmp))
        self.assertEqual(payload["details"]["latest_report"]["id"], "report-bad")
        self.assertEqual(payload["details"]["latest_completed_report"]["id"], "report-good")
        self.assertEqual(payload["details"]["latest_no_start_completed_report"]["id"], "report-bad")



    def test_runtime_report_paths_live_under_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(turbovasctl.runtime_report_probe_path(root), root / "tools" / "runtime_report.py")
            self.assertEqual(turbovasctl.report_artifact_dir(root), Path(tmp) / "TurboVAS-runtime" / "artifacts" / "reports")
            self.assertIn("artifacts/reports", turbovasctl.RUNTIME_DIRS)

    def test_runtime_report_parser_summarizes_results(self):
        response = (
            "<get_reports_response>"
            "<report id=\"report-1\">"
            "<name>2026-06-02T15:59:28Z</name>"
            "<task id=\"task-1\"><name>scan task</name></task>"
            "<report id=\"report-1\">"
            "<scan_run_status>Done</scan_run_status>"
            "<scan_start>2026-06-02T15:59:50Z</scan_start>"
            "<scan_end>2026-06-02T16:02:15Z</scan_end>"
            "<hosts><count>2</count></hosts>"
            "<vulns><count>2</count></vulns>"
            "<cves><count>1</count></cves>"
            "<os><count>1</count></os>"
            "<result_count><full>2</full></result_count>"
            "<results start=\"1\" max=\"100\">"
            "<result id=\"result-low\">"
            "<name>ICMP Timestamp Reply Information Disclosure</name>"
            "<host>192.168.178.1<hostname>router.local</hostname></host>"
            "<port>general/icmp</port>"
            "<nvt oid=\"1.2.3\"><name>ICMP Timestamp</name><family>General</family></nvt>"
            "<threat>Low</threat><severity>2.1</severity>"
            "<qod><value>80</value></qod>"
            "<description>Timestamp reply was observed. This is a low severity finding.</description>"
            "</result>"
            "<result id=\"result-log\">"
            "<name>OS Detection Consolidation and Reporting</name>"
            "<host>192.168.178.42</host>"
            "<port>general/tcp</port>"
            "<nvt oid=\"1.2.4\"><name>OS Detection</name><family>Service detection</family></nvt>"
            "<threat>Log</threat><severity>0.0</severity>"
            "<qod><value>80</value></qod>"
            "<description>Detected a host.</description>"
            "</result>"
            "</results>"
            "</report>"
            "</report>"
            "</get_reports_response>"
        )
        listing = {
            "id": "report-1",
            "task_id": "task-1",
            "result_count": "2",
            "hosts_count": "2",
            "vulns_count": "2",
            "cves_count": "3",
            "os_count": "1",
        }
        parsed, error = runtime_report.parse_report_payload(response, listing, top_limit=1, max_results=100)
        self.assertIsNone(error)
        self.assertEqual(parsed["report"]["id"], "report-1")
        self.assertEqual(parsed["report"]["task_name"], "scan task")
        self.assertEqual(parsed["report"]["counts"]["cves"], 3)
        self.assertEqual(parsed["parsed_result_count"], 2)
        self.assertTrue(parsed["export_complete"])
        self.assertEqual(parsed["severity_counts"]["Low"], 1)
        self.assertEqual(parsed["severity_counts"]["Log"], 1)
        self.assertEqual(parsed["affected_hosts"][0]["host"], "192.168.178.1")
        self.assertEqual(parsed["affected_hosts"][0]["hostnames"], ["router.local"])
        self.assertEqual(parsed["top_results"][0]["id"], "result-low")
        self.assertEqual(parsed["result_filter"], "apply_overrides=0 min_qod=0 first=1 rows=100 sort-reverse=severity")

    def test_runtime_report_summary_defaults_to_latest_completed_full_test_report(self):
        report_response = (
            "<get_reports_response>"
            "<report id=\"report-done\">"
            "<name>2026-06-02T15:59:28Z</name>"
            "<task id=\"task-1\"><name>scan task</name></task>"
            "<report id=\"report-done\">"
            "<scan_run_status>Done</scan_run_status>"
            "<scan_start>2026-06-02T15:59:50Z</scan_start>"
            "<scan_end>2026-06-02T16:02:15Z</scan_end>"
            "<hosts><count>1</count></hosts>"
            "<vulns><count>1</count></vulns>"
            "<cves><count>0</count></cves>"
            "<os><count>0</count></os>"
            "<result_count><full>1</full></result_count>"
            "<results><result id=\"result-1\"><name>Finding</name><host>192.168.178.1</host><port>general/tcp</port><threat>Low</threat><severity>1.0</severity></result></results>"
            "</report>"
            "</report>"
            "</get_reports_response>"
        )

        class FakeGMP:
            def get_scan_configs(self):
                return "<get_configs_response/>"

            def get_port_lists(self):
                return "<get_port_lists_response/>"

            def get_scanners(self, details=True):
                return "<get_scanners_response/>"

            def get_targets(self, tasks=True):
                return "<get_targets_response/>"

            def get_tasks(self, details=True, ignore_pagination=True):
                return (
                    "<get_tasks_response>"
                    "<task id=\"task-1\">"
                    f"<name>{runtime_full_test_scan.FULL_TEST_TASK_NAME}</name>"
                    "<status>Done</status>"
                    "</task>"
                    "</get_tasks_response>"
                )

            def get_reports(self, filter_string=None, details=True, ignore_pagination=True):
                self.latest_filter = filter_string
                return (
                    "<get_reports_response>"
                    "<report id=\"report-interrupted\">"
                    "<task id=\"task-1\"/>"
                    "<report id=\"report-interrupted\"><scan_run_status>Interrupted</scan_run_status><result_count><full>0</full></result_count></report>"
                    "</report>"
                    "<report id=\"report-done-no-start\">"
                    "<task id=\"task-1\"/>"
                    "<report id=\"report-done-no-start\"><scan_run_status>Done</scan_run_status><result_count><full>0</full></result_count></report>"
                    "</report>"
                    "<report id=\"report-done\">"
                    "<task id=\"task-1\"/>"
                    "<report id=\"report-done\"><scan_run_status>Done</scan_run_status><scan_start>2026-06-02T15:59:50Z</scan_start><result_count><full>1</full></result_count></report>"
                    "</report>"
                    "</get_reports_response>"
                )

            def get_report(self, report_id, filter_string=None, details=True, ignore_pagination=False):
                self.report_id = report_id
                self.report_filter = filter_string
                return report_response

        fake = FakeGMP()
        with tempfile.TemporaryDirectory() as tmp:
            payload = runtime_report.command_summary(fake, Path(tmp), report_id=None, max_results=100, top_results_limit=1)
            artifact_exists = (Path(tmp) / "summary.json").is_file()
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["details"]["report"]["id"], "report-done")
        self.assertEqual(payload["details"]["top_results"][0]["id"], "result-1")
        self.assertEqual(fake.report_id, "report-done")
        self.assertIn("task_id=task-1", fake.latest_filter)
        self.assertIn("rows=100", fake.report_filter)
        self.assertTrue(artifact_exists)


if __name__ == "__main__":
    unittest.main()
