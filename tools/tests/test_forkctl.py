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
        self.assertEqual(turbovasctl.APP_SERVICES, ("gvmd", "ospd-openvas", "gsad"))

    def test_runtime_dirs_include_application_state(self):
        self.assertIn("certs/CA", turbovasctl.RUNTIME_DIRS)
        self.assertIn("certs/private/CA", turbovasctl.RUNTIME_DIRS)
        self.assertIn("secrets", turbovasctl.RUNTIME_DIRS)
        self.assertIn("state/ospd-gnupg", turbovasctl.RUNTIME_DIRS)
        self.assertIn("redis-openvas", turbovasctl.RUNTIME_DIRS)
        self.assertIn("run/gvmd", turbovasctl.RUNTIME_DIRS)
        self.assertIn("run/ospd", turbovasctl.RUNTIME_DIRS)
        self.assertIn("run/redis-openvas", turbovasctl.RUNTIME_DIRS)

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

    def test_scanner_redis_paths_live_under_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(turbovasctl.scanner_redis_socket_path(root), Path(tmp) / "TurboVAS-runtime" / "run" / "redis-openvas" / "redis.sock")
            self.assertEqual(turbovasctl.openvas_runtime_config_path(root), root / "build" / "prefix" / "etc" / "openvas" / "openvas.conf")

    def test_feed_paths_live_under_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            self.assertEqual(turbovasctl.feed_cache_var_lib(root), Path(tmp) / "TurboVAS-runtime" / "feed-cache" / "community" / "22.04" / "var-lib")
            self.assertEqual(turbovasctl.feed_runtime_root(root), Path(tmp) / "TurboVAS-runtime" / "feeds")
            self.assertEqual(turbovasctl.feed_sync_log_dir(root), Path(tmp) / "TurboVAS-runtime" / "logs" / "feed-sync")

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

    def test_sql_escaping_helpers(self):
        self.assertEqual(turbovasctl.sql_identifier('a"b'), '"a""b"')
        self.assertEqual(turbovasctl.sql_literal("a'b"), "'a''b'")

    def test_gmp_smoke_parse_version_accepts_text_and_element(self):
        self.assertEqual(runtime_gmp_smoke.parse_version("<get_version_response><version>22.7</version></get_version_response>"), "22.7")
        element = ET.fromstring("<get_version_response><version>22.8</version></get_version_response>")
        self.assertEqual(runtime_gmp_smoke.parse_version(element), "22.8")



if __name__ == "__main__":
    unittest.main()
