# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import json
import os
import sys
import tempfile
import unittest
import unittest.mock
import xml.etree.ElementTree as ET
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

RUNTIME_SCOPE_PATH = Path(__file__).resolve().parents[1] / "runtime_scope.py"
RUNTIME_SCOPE_SPEC = importlib.util.spec_from_loader("runtime_scope", SourceFileLoader("runtime_scope", str(RUNTIME_SCOPE_PATH)))
runtime_scope = importlib.util.module_from_spec(RUNTIME_SCOPE_SPEC)
assert RUNTIME_SCOPE_SPEC.loader is not None
sys.modules["runtime_scope"] = runtime_scope
RUNTIME_SCOPE_SPEC.loader.exec_module(runtime_scope)

RUNTIME_METRICS_PATH = Path(__file__).resolve().parents[1] / "runtime_metrics.py"
RUNTIME_METRICS_SPEC = importlib.util.spec_from_loader("runtime_metrics", SourceFileLoader("runtime_metrics", str(RUNTIME_METRICS_PATH)))
runtime_metrics = importlib.util.module_from_spec(RUNTIME_METRICS_SPEC)
assert RUNTIME_METRICS_SPEC.loader is not None
sys.modules["runtime_metrics"] = runtime_metrics
RUNTIME_METRICS_SPEC.loader.exec_module(runtime_metrics)

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

    def test_c_service_doc_generation_dependencies_are_explicit(self):
        for component in ("openvas-smb", "gvmd", "gsad"):
            with self.subTest(component=component):
                meta = turbovasctl.BUILD_META[component]
                self.assertIn("xmltoman", meta.programs)
                self.assertIn("xmlmantohtml", meta.programs)
                self.assertIn("xmltoman", meta.package_hints)

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
            "runtime-init",
            "runtime-certs-init",
            "runtime-manager-init",
            "runtime-scanner-redis-init",
            "runtime-gmp-smoke",
            "runtime-scanner-register",
            "runtime-app-up",
            "runtime-app-down",
            "runtime-app-smoke",
            "runtime-browser-smoke",
            "runtime-credential-smoke",
            "runtime-report-metrics",
            "runtime-scope-report-metrics",
            "gvmd-smoke",
        ]
        for wrapper in wrappers:
            with self.subTest(wrapper=wrapper):
                self.assertIn(f"{wrapper} *args:", justfile)
                self.assertIn(f"tools/turbovasctl {wrapper} \"$@\"", justfile)

    def test_build_ui_restarts_running_gsad_after_static_stage(self):
        source = (Path(__file__).resolve().parents[1] / "turbovasctl").read_text(encoding="utf-8")
        self.assertIn("def restart_gsad_after_static_stage", source)
        self.assertIn('compose_command(repo_root, "restart", "gsad")', source)
        self.assertIn("findings.append(restart_gsad_after_static_stage(repo_root))", source)

    def test_scope_report_finding_counts_exclude_scanner_errors(self):
        source = (Path(__file__).resolve().parents[2] / "components" / "gvmd" / "src" / "manage_sql_scopes.c").read_text(encoding="utf-8")
        self.assertIn("#include \"manage_utils.h\"", source)
        self.assertIn("SCOPE_REPORT_FINDING_CLAUSE", source)
        self.assertIn("SEVERITY_ERROR", source)
        self.assertIn("SEVERITY_FP", source)
        self.assertIn("WHERE s.scope_report = %llu AND \" SCOPE_REPORT_FINDING_CLAUSE \" AND", source)
        self.assertNotIn("append_xml_int64 (buffer, \"false_positive\", 0);", source)

    def test_gsa_scope_report_parser_accepts_top_level_severity(self):
        source = (Path(__file__).resolve().parents[2] / "components" / "gsa" / "src" / "gmp" / "commands" / "scopes.ts").read_text(encoding="utf-8")
        self.assertIn("counts.severity ?? data.severity", source)

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
        self.assertIn("gmp.scopereports.get({details: 1, filter})", list_page)
        self.assertIn("setCounts(reportResponse.meta.counts", list_page)
        self.assertNotIn("filteredReports", list_page)
        self.assertIn("_('Information')", details_page)
        self.assertIn("_('Results')", details_page)
        self.assertIn("_('Evidence Sources')", details_page)
        self.assertIn("ScopeReportResultsTab", details_page)
        results_tab = (root / "components" / "gsa" / "src" / "web" / "pages" / "scope-reports" / "ScopeReportResultsTab.tsx").read_text(encoding="utf-8")
        self.assertIn("_and_scope_report_id", results_tab)
        self.assertIn("<ResultsTable", results_tab)

    def test_scope_report_collection_filtering_is_wired_across_layers(self):
        root = Path(__file__).resolve().parents[2]
        gvmd_gmp = (root / "components" / "gvmd" / "src" / "gmp.c").read_text(encoding="utf-8")
        gvmd_scopes = (root / "components" / "gvmd" / "src" / "manage_sql_scopes.c").read_text(encoding="utf-8")
        gsad = (root / "components" / "gsad" / "src" / "gsad_gmp.c").read_text(encoding="utf-8")
        gsa_scopes = (root / "components" / "gsa" / "src" / "gmp" / "commands" / "scopes.ts").read_text(encoding="utf-8")
        python_scopes = (root / "components" / "python-gvm" / "gvm" / "protocols" / "gmp" / "requests" / "v226" / "_scopes.py").read_text(encoding="utf-8")
        gvm_tools_list = (root / "components" / "gvm-tools" / "scripts" / "list-scope-reports.gmp.py").read_text(encoding="utf-8")
        gmp_schema = (root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in").read_text(encoding="utf-8")
        self.assertIn("data->filter = g_strdup (attribute);", gvmd_gmp)
        self.assertIn("scope_report_count_filtered", gvmd_gmp)
        self.assertIn('<scope_reports start=\\"%i\\" max=\\"%i\\">%s', gvmd_gmp)
        self.assertIn("manage_filter_controls", gvmd_scopes)
        self.assertIn("filter_term_value (filter, \"search\")", gvmd_scopes)
        self.assertIn("scope_report_sort_column", gvmd_scopes)
        self.assertIn("ORDER BY %s %s, sr.id DESC%s", gvmd_scopes)
        self.assertIn("params_value (params, \"filter\")", gsad)
        self.assertIn("gmp_arguments_add (arguments, \"filter\", filter)", gsad)
        self.assertIn("parseScopeReportCounts", gsa_scopes)
        self.assertIn("response.set<ScopeReport[], EntitiesMeta>", gsa_scopes)
        self.assertIn("filter_string: str | None = None", python_scopes)
        self.assertIn('cmd.set_attribute("filter", filter_string)', python_scopes)
        self.assertIn("DEFAULT_FILTER = \"first=1 rows=25 sort-reverse=created\"", gvm_tools_list)
        self.assertIn("filter_string=parsed_args.filter", gvm_tools_list)
        self.assertIn("<name>get_scope_reports</name>", gmp_schema)
        self.assertIn("Filter term to use for paging, sorting, and searching scope reports", gmp_schema)

    def test_report_metrics_commands_are_registered_across_layers(self):
        root = Path(__file__).resolve().parents[2]
        gvmd_commands = (root / "components" / "gvmd" / "src" / "manage_commands.c").read_text(encoding="utf-8")
        gvmd_gmp = (root / "components" / "gvmd" / "src" / "gmp.c").read_text(encoding="utf-8")
        gsad = (root / "components" / "gsad" / "src" / "gsad_gmp.c").read_text(encoding="utf-8")
        python_gmp = (root / "components" / "python-gvm" / "gvm" / "protocols" / "gmp" / "_gmp226.py").read_text(encoding="utf-8")
        gsa_report = (root / "components" / "gsa" / "src" / "gmp" / "commands" / "report.ts").read_text(encoding="utf-8")
        gsa_scopes = (root / "components" / "gsa" / "src" / "gmp" / "commands" / "scopes.ts").read_text(encoding="utf-8")
        schema = (root / "components" / "gvmd" / "src" / "schema_formats" / "XML" / "GMP.xml.in").read_text(encoding="utf-8")
        for command in ("get_report_metrics", "get_scope_report_metrics"):
            with self.subTest(command=command):
                self.assertIn(command.upper(), gvmd_commands)
                self.assertIn(command, gvmd_gmp)
                self.assertIn(command, gsad)
                self.assertIn(command, python_gmp)
                self.assertIn(command, schema)
        self.assertIn("getMetrics", gsa_report)
        self.assertIn("getMetrics", gsa_scopes)

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

    def test_runtime_metrics_parser_preserves_summary_systems_and_vulnerabilities(self):
        xml = """
        <get_report_metrics_response status="200" status_text="OK">
          <report_metrics id="report-1">
            <summary>
              <alive_system_count>2</alive_system_count>
              <total_system_cvss_load>12.3</total_system_cvss_load>
              <average_system_cvss_load>6.15</average_system_cvss_load>
              <vulnerability_count>2</vulnerability_count>
              <authenticated_system_count>1</authenticated_system_count>
              <authentication_failed_system_count>0</authentication_failed_system_count>
              <no_credential_path_system_count>1</no_credential_path_system_count>
              <unknown_authentication_system_count>0</unknown_authentication_system_count>
              <authenticated_scan_coverage_percent>50.0</authenticated_scan_coverage_percent>
            </summary>
            <systems>
              <system><host>192.0.2.10</host><cvss_load>7.0</cvss_load><max_cvss>7.0</max_cvss><vulnerability_count>1</vulnerability_count><authentication_state>authenticated</authentication_state><source_report_count>1</source_report_count></system>
            </systems>
            <vulnerabilities>
              <vulnerability><nvt_oid>1.2.3</nvt_oid><name>Example</name><cvss_score>7.0</cvss_score><affected_system_count>1</affected_system_count><cvss_load>7.0</cvss_load><average_contribution>3.5</average_contribution><source_report_count>1</source_report_count></vulnerability>
            </vulnerabilities>
          </report_metrics>
        </get_report_metrics_response>
        """
        parsed = runtime_metrics.parse_metrics(xml, "report_metrics")
        self.assertEqual(parsed["id"], "report-1")
        self.assertEqual(parsed["summary"]["alive_system_count"], 2)
        self.assertEqual(parsed["summary"]["authenticated_scan_coverage_percent"], 50.0)
        self.assertEqual(parsed["systems"][0]["authentication_state"], "authenticated")
        self.assertEqual(parsed["vulnerabilities"][0]["average_contribution"], 3.5)

    def test_report_metrics_ui_is_exposed_on_raw_and_scope_report_details(self):
        root = Path(__file__).resolve().parents[2]
        raw_details = (root / "components" / "gsa" / "src" / "web" / "pages" / "reports" / "DetailsContent.tsx").read_text(encoding="utf-8")
        scope_details = (root / "components" / "gsa" / "src" / "web" / "pages" / "scope-reports" / "ScopeReportDetailsPage.tsx").read_text(encoding="utf-8")
        metrics_tab = (root / "components" / "gsa" / "src" / "web" / "pages" / "reports" / "details" / "MetricsTab.tsx").read_text(encoding="utf-8")
        self.assertIn("MetricsTab", raw_details)
        self.assertIn("MetricsTab", scope_details)
        self.assertIn("Average System CVSS Load", metrics_tab)
        self.assertIn("Authenticated Scan Coverage", metrics_tab)
        self.assertIn("No Credential Path", metrics_tab)

    def test_runtime_browser_smoke_is_registered(self):
        source = (Path(__file__).resolve().parents[1] / "turbovasctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertIn("def command_runtime_browser_smoke", source)
        self.assertIn("runtime_browser_smoke_probe_path", source)
        self.assertIn("runtime-browser-smoke", source)
        self.assertIn("runtime-browser-smoke *args:", justfile)
        self.assertIn('tools/turbovasctl runtime-browser-smoke "$@"', justfile)

    def test_runtime_credential_smoke_is_registered(self):
        source = (Path(__file__).resolve().parents[1] / "turbovasctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        self.assertIn("def command_runtime_credential_smoke", source)
        self.assertIn("runtime_credential_smoke_probe_path", source)
        self.assertIn("runtime-credential-smoke", source)
        self.assertIn("runtime-credential-smoke *args:", justfile)
        self.assertIn('tools/turbovasctl runtime-credential-smoke "$@"', justfile)

    def test_technical_foundation_commands_are_registered(self):
        source = (Path(__file__).resolve().parents[1] / "turbovasctl").read_text(encoding="utf-8")
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        for command in ("native-tooling-state", "rust-migration-state", "branding-state", "production-posture-check", "runtime-log-review", "runtime-data-state", "runtime-performance-snapshot", "runtime-redis-state", "security-policy-check", "path-coupling-state", "runtime-native-api-smoke", "quality-gate", "quality-gate-state", "quality-gate-schedule"):
            with self.subTest(command=command):
                self.assertIn(command, source)
                self.assertIn(f"{command} *args:", justfile)
                self.assertIn(f'tools/turbovasctl {command} "$@"', justfile)
        self.assertIn("def command_native_tooling_state", source)
        self.assertIn("def command_rust_migration_state", source)
        self.assertIn("def command_branding_state", source)
        self.assertIn("def command_runtime_log_review", source)
        self.assertIn("def command_runtime_data_state", source)
        self.assertIn("def command_runtime_performance_snapshot", source)
        self.assertIn("def command_runtime_redis_state", source)
        self.assertIn("def command_runtime_native_api_smoke", source)
        self.assertIn("def command_security_policy_check", source)
        self.assertIn("def command_path_coupling_state", source)
        self.assertIn("def command_production_posture_check", source)
        self.assertIn("def command_quality_gate", source)
        self.assertIn("def command_quality_gate_state", source)
        self.assertIn("def command_quality_gate_schedule", source)

    def test_security_policy_check_validates_seeded_policy(self):
        root = Path(__file__).resolve().parents[2]
        result = turbovasctl.command_security_policy_check(root)
        self.assertEqual(result["status"], "pass")
        area_ids = {area["id"] for area in result["details"]["areas"]}
        self.assertIn("protocol-parsing", area_ids)
        self.assertIn("scanner-execution", area_ids)
        self.assertIn("native-api", area_ids)
        self.assertGreaterEqual(result["details"]["area_count"], 7)

    def test_path_coupling_helpers_classify_expected_markers(self):
        self.assertEqual(turbovasctl.path_coupling_category("docs/README.md"), "documentation")
        self.assertEqual(turbovasctl.path_coupling_category("docker/runtime/README.md"), "documentation")
        self.assertEqual(turbovasctl.path_coupling_category("compose/dev.yaml"), "runtime_tooling")
        markers = turbovasctl.path_coupling_markers("/home/turboforge/Projects/TurboVAS build/prefix /runtime/state")
        self.assertIn("dev_checkout_path", markers)
        self.assertIn("build_prefix_path", markers)
        self.assertIn("container_runtime_path", markers)

    def test_native_tooling_state_classifies_dependency_surfaces(self):
        root = Path(__file__).resolve().parents[2]
        result = turbovasctl.command_native_tooling_state(root)
        details = result["details"]
        self.assertEqual(result["status"], "pass")
        self.assertGreater(details["by_category"]["required_runtime"]["count"], 0)
        self.assertGreater(details["by_category"]["product_workflow"]["count"], 0)
        self.assertGreater(details["by_category"]["compatibility_bridge"]["count"], 0)
        self.assertIn("tools/runtime_report.py", details["by_category"]["required_runtime"]["paths"])
        self.assertIn("components/gvm-tools/scripts/list-scope-reports.gmp.py", details["by_category"]["product_workflow"]["paths"])
        self.assertIn("components/python-gvm/gvm/protocols/gmp/requests/v226/_reports.py", details["by_category"]["compatibility_bridge"]["paths"])
        self.assertIn("gvm-tools scope/report scripts", {item["workflow"] for item in details["next_replacement_candidates"]})

    def test_rust_migration_state_tracks_tools_and_first_candidate(self):
        root = Path(__file__).resolve().parents[2]
        result = turbovasctl.command_rust_migration_state(root)
        details = result["details"]
        tool_names = {item["name"] for item in details["tools"]}
        self.assertIn("bindgen", tool_names)
        self.assertIn("c2rust", tool_names)
        self.assertIn("cargo-llvm-cov", tool_names)
        self.assertIn("cargo-mutants", tool_names)
        self.assertEqual(details["first_candidate"]["c_file"], "components/gvm-libs/base/version.c")
        self.assertFalse(details["first_candidate"]["production_replacement_allowed_in_current_slice"])
        self.assertIn("CMake/Rust integration", "\n".join(details["first_candidate"]["production_replacement_requirements"]))
        self.assertIn(result["status"], {"pass", "warn", "fail"})

    def test_native_tooling_category_keeps_scripts_and_docs_distinct(self):
        self.assertEqual(turbovasctl.native_tooling_category("tools/runtime_scope.py")[0], "required_runtime")
        self.assertEqual(turbovasctl.native_tooling_category("tools/tests/test_forkctl.py")[0], "required_test")
        self.assertEqual(turbovasctl.native_tooling_category("components/gsa/src/gmp/commands/scopes.ts")[0], "product_workflow")
        self.assertEqual(turbovasctl.native_tooling_category("components/gvm-tools/scripts/list-scopes.gmp.py")[0], "product_workflow")
        self.assertEqual(turbovasctl.native_tooling_category("components/gvm-tools/scripts/empty-trash.gmp.py")[0], "candidate_for_removal")
        self.assertEqual(turbovasctl.native_tooling_category("docs/GMP_XML_STRANGLER.md")[0], "compatibility_bridge")

    def test_redis_reference_summary_separates_scanner_and_generic_paths(self):
        references = [
            {"path": "compose/dev.yaml", "category": "scanner_kb", "markers": ["redis-openvas"]},
            {"path": "docker/dev/Dockerfile", "category": "dependency_build", "markers": ["redis-tools"]},
            {"path": "docs/DATABASE_GRAVITY.md", "category": "documentation", "markers": ["Redis"]},
            {"path": "components/gvmd/src/example.c", "category": "generic_runtime", "markers": ["redis"]},
        ]
        summary = turbovasctl.summarize_redis_references(references)
        self.assertEqual(summary["by_category"]["scanner_kb"]["paths"], ["compose/dev.yaml"])
        self.assertEqual(summary["by_category"]["dependency_build"]["count"], 1)
        self.assertEqual(summary["by_category"]["generic_runtime"]["paths"], ["components/gvmd/src/example.c"])

    def test_redis_reference_category_identifies_scanner_socket(self):
        self.assertEqual(turbovasctl.redis_reference_category("compose/dev.yaml", "/run/redis-openvas/redis.sock"), "scanner_kb")
        self.assertEqual(turbovasctl.redis_reference_category("docker/dev/Dockerfile", "redis-tools libhiredis-dev"), "dependency_build")
        self.assertEqual(turbovasctl.redis_reference_category("docs/ARCHITECTURE_FLOWS.md", "Redis"), "documentation")

    def test_redis_metric_parsers_extract_counts_without_keys(self):
        info = """
# Clients
connected_clients:2
blocked_clients:0
# Memory
used_memory:1024
used_memory_peak:4096
# Stats
total_commands_processed:42
instantaneous_ops_per_sec:3
keyspace_hits:10
keyspace_misses:1
# Keyspace
db0:keys=7,expires=2,avg_ttl=1000
db2:keys=5,expires=0,avg_ttl=0
"""
        metrics = turbovasctl.parse_redis_info(info)
        self.assertEqual(metrics["connected_clients"], 2)
        self.assertEqual(metrics["blocked_clients"], 0)
        self.assertEqual(metrics["used_memory"], 1024)
        self.assertEqual(metrics["used_memory_peak"], 4096)
        self.assertEqual(metrics["total_commands_processed"], 42)
        self.assertEqual(metrics["instantaneous_ops_per_sec"], 3)
        self.assertEqual(metrics["keyspace_hits"], 10)
        self.assertEqual(metrics["keyspace_misses"], 1)
        self.assertEqual(metrics["keyspace_keys"], 12)
        self.assertEqual(turbovasctl.parse_redis_dbsize("5\n"), 5)
        self.assertIsNone(turbovasctl.parse_redis_dbsize("not-an-int\n"))

    def test_redis_compose_boundaries_expect_generic_redis_removed(self):
        root = Path(__file__).resolve().parents[2]
        boundaries = turbovasctl.redis_compose_boundaries(root)
        self.assertFalse(boundaries["generic_redis_service_present"])
        self.assertFalse(boundaries["generic_redis_loopback_tcp"])
        self.assertFalse(boundaries["gvmd_depends_on_generic_redis"])
        self.assertTrue(boundaries["scanner_redis_no_tcp_port"])
        self.assertTrue(boundaries["scanner_redis_unix_socket"])
        self.assertTrue(boundaries["ospd_depends_on_scanner_redis"])

    def test_branding_state_separates_provenance_from_active_surfaces(self):
        root = Path(__file__).resolve().parents[2]
        result = turbovasctl.command_branding_state(root)
        details = result["details"]
        active_locale_items = [
            item
            for item in details["items"]
            if item["path"] == "components/gsa/public/locales/gsa-en.json"
            and item["category"] == "active_product_surface"
        ]
        technical_locale_items = [
            item
            for item in details["items"]
            if item["path"] == "components/gsa/public/locales/gsa-en.json"
            and item["category"] == "technical_doc_context"
        ]
        self.assertIn(result["status"], {"pass", "warn"})
        self.assertGreater(details["by_category"]["provenance_or_non_affiliation"]["count"], 0)
        self.assertIn("README.md", details["by_category"]["provenance_or_non_affiliation"]["paths"])
        self.assertIn("components/gsa/public/locales/gsa-en.json", details["by_category"]["active_product_surface"]["paths"])
        self.assertTrue(any("Greenbone Enterprise License" in item["text"] for item in active_locale_items))
        self.assertTrue(any("OpenVAS Scanner" in item["text"] for item in technical_locale_items))
        self.assertNotIn("components/gsa/package.json", details["by_category"]["active_product_surface"]["paths"])
        self.assertIn("components/gsa/package.json", details["by_category"]["technical_doc_context"]["paths"])
        self.assertEqual(details["by_category"]["unknown"]["count"], 0)

    def test_branding_category_classifies_known_contexts(self):
        self.assertEqual(turbovasctl.branding_category("README.md"), "provenance_or_non_affiliation")
        self.assertEqual(turbovasctl.branding_category("docs/ARCHITECTURE_FLOWS.md"), "technical_doc_context")
        self.assertEqual(turbovasctl.branding_category("components/gsa/public/locales/gsa-en.json"), "active_product_surface")
        self.assertEqual(turbovasctl.branding_category("components/gsa/public/img/os_ipfire.svg"), "technical_doc_context")
        self.assertEqual(turbovasctl.branding_item_category("components/gsa/package.json", ["greenbone"]), "technical_doc_context")
        self.assertEqual(turbovasctl.branding_locale_line_category('"OpenVAS Scanner": "OpenVAS Scanner",'), "technical_doc_context")
        self.assertEqual(turbovasctl.branding_locale_line_category('"Your Greenbone Enterprise License is invalid!": "Your Greenbone Enterprise License is invalid!",'), "active_product_surface")

    def test_retained_json_artifacts_write_latest_history_and_prune(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            latest, first = turbovasctl.retained_json_artifact_paths(artifact_dir, "quality-gate", "quality-gate.json")
            turbovasctl.write_retained_json_artifact(latest, first, {"status": "pass", "summary": "first", "metadata": {"generated_at": "one"}}, "quality-gate", 1)
            latest, second = turbovasctl.retained_json_artifact_paths(artifact_dir, "quality-gate", "quality-gate.json")
            turbovasctl.write_retained_json_artifact(latest, second, {"status": "fail", "summary": "second", "metadata": {"generated_at": "two"}}, "quality-gate", 1)

            self.assertTrue((artifact_dir / "quality-gate.json").is_file())
            history = turbovasctl.json_artifact_history(artifact_dir, "quality-gate")
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["status"], "fail")
            self.assertFalse(first.exists())
            self.assertTrue(second.exists())

    def test_data_outside_db_summary_groups_classifications(self):
        summary = turbovasctl.summarize_data_outside_db(
            {
                "reports": {"classification": "db_owned_export", "exists": True, "file_count": 2, "byte_count": 100},
                "logs": {"classification": "diagnostic_artifact", "exists": False, "file_count": 0, "byte_count": 0},
                "feeds": {"classification": "feed_content", "exists": True, "file_count": 3, "byte_count": 200},
            }
        )
        self.assertEqual(summary["total_file_count"], 5)
        self.assertEqual(summary["total_byte_count"], 300)
        self.assertEqual(summary["by_classification"]["db_owned_export"]["existing_path_count"], 1)
        self.assertEqual(summary["by_classification"]["diagnostic_artifact"]["existing_path_count"], 0)

    def test_product_data_audit_passes_for_db_owned_exports_with_tables(self):
        audit = turbovasctl.product_data_audit(
            {
                "database": {
                    "core_tables": {
                        "reports": {"exists": True},
                        "results": {"exists": True},
                        "report_hosts": {"exists": True},
                    },
                    "scope_tables": {},
                },
                "paths": {"reports": {"classification": "db_owned_export", "exists": True, "path": "/tmp/reports"}},
            }
        )
        self.assertEqual(audit["status"], "pass")
        self.assertEqual(audit["unowned_product_data"], [])
        self.assertEqual(audit["db_owned_exports"]["reports"]["source_of_record"], "gvmd/postgresql")

    def test_product_data_audit_warns_for_export_without_source_tables(self):
        audit = turbovasctl.product_data_audit(
            {
                "database": {"core_tables": {"reports": {"exists": True}}, "scope_tables": {}},
                "paths": {"metrics": {"classification": "db_owned_export", "exists": True, "path": "/tmp/metrics"}},
            }
        )
        self.assertEqual(audit["status"], "warn")
        self.assertEqual(audit["unowned_product_data"][0]["path"], "metrics")
        self.assertIn("scope_report_system_metrics", audit["unowned_product_data"][0]["missing_tables"])

    def test_performance_parses_docker_percent_and_byte_units(self):
        self.assertEqual(turbovasctl.parse_percent("40.18%"), 40.18)
        self.assertEqual(turbovasctl.parse_byte_quantity("60.22MiB"), int(60.22 * 1024 * 1024))
        self.assertEqual(turbovasctl.parse_byte_quantity("1.53GB"), int(1.53 * 1000 * 1000 * 1000))
        self.assertIsNone(turbovasctl.parse_byte_quantity("not-a-size"))

    def test_performance_normalizes_docker_stats_row(self):
        row = turbovasctl.normalize_docker_stat(
            {
                "Name": "turbovas-postgres-1",
                "ID": "abc123",
                "CPUPerc": "5.39%",
                "MemPerc": "0.39%",
                "MemUsage": "62.06MiB / 15.5GiB",
                "NetIO": "159MB / 1.79GB",
                "BlockIO": "1.53GB / 222MB",
                "PIDs": "7",
            }
        )
        self.assertEqual(row["name"], "turbovas-postgres-1")
        self.assertEqual(row["cpu_percent"], 5.39)
        self.assertEqual(row["pids"], 7)
        self.assertEqual(row["memory_usage_bytes"], int(62.06 * 1024 * 1024))
        self.assertEqual(row["network_tx_bytes"], int(1.79 * 1000 * 1000 * 1000))
        self.assertEqual(row["block_read_bytes"], int(1.53 * 1000 * 1000 * 1000))

    def test_performance_top_numeric_rows_orders_missing_values_last(self):
        rows = [{"name": "a", "cpu_percent": None}, {"name": "b", "cpu_percent": 2.0}, {"name": "c", "cpu_percent": 1.0}]
        self.assertEqual([row["name"] for row in turbovasctl.top_numeric_rows(rows, "cpu_percent")], ["b", "c", "a"])

    def test_parse_relation_size_rows(self):
        self.assertEqual(
            turbovasctl.parse_relation_size_rows("results|123\nreports|45\n"),
            [{"name": "results", "byte_count": 123}, {"name": "reports", "byte_count": 45}],
        )

    def test_parse_pipe_int_rows(self):
        self.assertEqual(
            turbovasctl.parse_pipe_int_rows("reports|13\nignored|not-int\nscope_reports|23\n"),
            {"reports": 13, "scope_reports": 23},
        )

    def test_performance_snapshot_captures_report_workflow_baseline(self):
        source = (Path(__file__).resolve().parents[1] / "turbovasctl").read_text(encoding="utf-8")
        self.assertIn("performance.report-workflow", source)
        self.assertIn("performance.scanner-redis", source)
        self.assertIn("scanner_redis_metrics", source)
        self.assertIn("max_sources_per_scope_report", source)
        self.assertIn("max_results_per_report", source)
        self.assertIn("max_scope_report_result_count", source)
        self.assertIn("parse_pipe_int_rows", source)

    def test_quality_gate_systemd_templates_are_present(self):
        root = Path(__file__).resolve().parents[2]
        service = root / "ops" / "systemd" / "turbovas-quality-gate.service.in"
        timer = root / "ops" / "systemd" / "turbovas-quality-gate.timer.in"
        service_text = service.read_text(encoding="utf-8")
        self.assertIn("SPDX-License-Identifier", service_text)
        self.assertIn("tools/turbovasctl quality-gate --json", service_text)
        self.assertNotIn("TURBOVAS_RUNTIME_DIR", service_text)
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
            "actions/checkout@v5",
            "actions/setup-python@v6",
            "actions/setup-node@v5",
            "ubuntu-24.04",
            "fetch-depth: 0",
            "python-version: \"3.12\"",
            "node-version: \"22\"",
            "rustup toolchain install stable --profile minimal",
            "cache-dependency-path: components/gsa/package-lock.json",
            "npm ci",
            "TURBOVAS_RUNTIME_DIR=\"$RUNNER_TEMP/turbovas-runtime\"",
            "tools/turbovasctl quality-gate --json",
            "actions/upload-artifact@v7",
        ]
        for needle in required:
            self.assertIn(needle, text)
        forbidden = [
            "runtime-full-test-scan-start",
            "feed-cache-sync",
            "feed-copy-to-runtime",
            "docker compose up",
            "license-public-release-gate",
        ]
        for needle in forbidden:
            self.assertNotIn(needle, text)

    def test_justfile_forwards_common_recipe_arguments(self):
        justfile = (Path(__file__).resolve().parents[2] / "justfile").read_text(encoding="utf-8")
        for recipe in (
            "status",
            "inventory",
            "doctor",
            "deps",
            "configure",
            "build",
            "build-core-c",
            "build-c-services",
            "build-ui",
            "build-python",
            "build-baseline",
            "runtime-plan",
            "up",
            "down",
            "logs",
        ):
            with self.subTest(recipe=recipe):
                self.assertIn(f"{recipe} *args:", justfile)
                self.assertIn(f'tools/turbovasctl {recipe} "$@"', justfile)

    def test_runtime_log_review_detects_known_regressions(self):
        matches = turbovasctl.log_review_matches(
            [
                "Nmap (NASL wrapper): You requested a scan type which requires root privileges.",
                "database collation version mismatch",
                "Error: Unable to open log file /mosquitto/log/mosquitto.log for writing.",
                "Traceback (most recent call last):",
            ]
        )
        keys = {match["key"] for match in matches}
        self.assertIn("nmap-root-privilege", keys)
        self.assertIn("postgres-collation", keys)
        self.assertIn("mosquitto-log-file", keys)
        self.assertIn("traceback", keys)

    def test_runtime_log_review_uses_service_specific_patterns(self):
        postgres_matches = turbovasctl.log_review_matches(
            ["2026-06-15 10:00:00.000 UTC [42] ERROR:  relation does not exist"],
            service="postgres",
        )
        self.assertIn("postgres-error", {match["key"] for match in postgres_matches})
        generic_matches = turbovasctl.log_review_matches(
            ["2026-06-15 10:00:00.000 UTC [42] ERROR:  relation does not exist"],
            service="redis",
        )
        self.assertNotIn("postgres-error", {match["key"] for match in generic_matches})
        notus_matches = turbovasctl.log_review_matches(
            ["notus-scanner: GPG error while verifying advisories"],
            service="notus-scanner",
        )
        self.assertIn("notus-feed", {match["key"] for match in notus_matches})

    def test_data_state_table_sets_capture_current_schema_expectations(self):
        self.assertIn("reports", turbovasctl.DATABASE_CORE_TABLES)
        self.assertIn("scope_reports", turbovasctl.DATABASE_SCOPE_TABLES)
        self.assertIn("scope_report_system_metrics", turbovasctl.DATABASE_SCOPE_TABLES)
        self.assertIn("roles", turbovasctl.DATABASE_REMOVED_TABLES)
        self.assertIn("agent_groups", turbovasctl.DATABASE_REMOVED_TABLES)

    def test_quality_gate_downgrades_known_doctor_notes_only(self):
        status, summary = turbovasctl.quality_gate_doctor_status(
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
        status, summary = turbovasctl.quality_gate_doctor_status(
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
        source = (Path(__file__).resolve().parents[1] / "turbovasctl").read_text(encoding="utf-8")
        self.assertIn("doctor_non_pass", source)
        self.assertIn("non_pass_findings", source)

    def test_quality_gate_unit_env_ignores_runtime_dir_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "TurboVAS"
            root.mkdir()
            previous = os.environ.get("TURBOVAS_RUNTIME_DIR")
            os.environ["TURBOVAS_RUNTIME_DIR"] = "/tmp/not-the-test-runtime"
            try:
                env = turbovasctl.quality_gate_unit_env(root)
            finally:
                if previous is None:
                    os.environ.pop("TURBOVAS_RUNTIME_DIR", None)
                else:
                    os.environ["TURBOVAS_RUNTIME_DIR"] = previous
            self.assertNotIn("TURBOVAS_RUNTIME_DIR", env)

    def test_runtime_credential_smoke_uses_existing_playwright_paths(self):
        self.assertEqual(
            runtime_credential_smoke.playwright_node_path_candidates,
            runtime_browser_smoke.playwright_node_path_candidates,
        )

    def test_runtime_browser_smoke_checks_metrics_tabs(self):
        source = (Path(__file__).resolve().parents[1] / "runtime_browser_smoke.py").read_text(encoding="utf-8")
        self.assertIn("scope-report.metrics-tab", source)
        self.assertIn("raw-report.metrics-tab", source)
        self.assertIn("CVSS Load", source)
        self.assertIn("Authenticated Scan Coverage", source)

    def test_runtime_browser_smoke_playwright_search_paths(self):
        candidates = runtime_browser_smoke.PLAYWRIGHT_NODE_PATHS
        self.assertIn("/home/turboforge/.local/share/turbovas-tools/playwright/node_modules", candidates)
        self.assertIn("/home/turboforge/.local/nodejs/node-v22.22.3-linux-x64/lib/node_modules", candidates)

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
        self.assertIn("Greenbone non-affiliation", "\n".join(turbovasctl.PUBLIC_READINESS_LICENSE_ITEMS))

    def test_production_posture_tracks_password_rotation_gap(self):
        source = (Path(__file__).resolve().parents[1] / "turbovasctl").read_text(encoding="utf-8")
        self.assertIn("production.first-login-password-rotation", source)
        self.assertIn("Production first-login/password-rotation bootstrap is not implemented yet", source)

    def test_gsa_browser_metadata_uses_turbovas_branding(self):
        index = (Path(__file__).resolve().parents[2] / "components" / "gsa" / "index.html").read_text(encoding="utf-8")
        self.assertIn("<title>TurboVAS</title>", index)
        self.assertIn('href="/img/favicon.svg" type="image/svg+xml"', index)
        self.assertNotIn("<title>OPENVAS</title>", index)

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
        self.assertFalse(turbovasctl.comment_notice_supported("components/gsa/index.html"))
        self.assertFalse(turbovasctl.comment_notice_supported("components/gsa/package-lock.json"))
        self.assertFalse(turbovasctl.comment_notice_supported("components/openvas-scanner/rust/src/openvasd/config/snapshots/default.snap"))

    def test_gsa_quality_env_adds_node_heap_headroom(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with unittest.mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(turbovasctl.gsa_quality_env(root)["NODE_OPTIONS"], "--max-old-space-size=4096")
            with unittest.mock.patch.dict(os.environ, {"NODE_OPTIONS": "--trace-warnings"}, clear=True):
                self.assertEqual(turbovasctl.gsa_quality_env(root)["NODE_OPTIONS"], "--trace-warnings --max-old-space-size=4096")
            with unittest.mock.patch.dict(os.environ, {"NODE_OPTIONS": "--max-old-space-size=6144"}, clear=True):
                self.assertEqual(turbovasctl.gsa_quality_env(root)["NODE_OPTIONS"], "--max-old-space-size=6144")

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
        self.assertEqual(turbovasctl.RUNTIME_SERVICES, ("postgres", "redis-openvas", "mosquitto"))

    def test_app_services_are_experimental_profile_services(self):
        self.assertEqual(turbovasctl.APP_SERVICES, ("gvmd", "ospd-openvas", "notus-scanner", "gsad", "turbovas-api"))

    def test_gsad_port_defaults_loopback_and_can_be_overridden(self):
        self.assertEqual(turbovasctl.DEFAULT_GSAD_HOST, "127.0.0.1")
        self.assertEqual(turbovasctl.GSAD_HOST_ENV, "TURBOVAS_GSAD_HOST")
        self.assertEqual(turbovasctl.GSAD_HOSTS_ENV, "TURBOVAS_GSAD_HOSTS")
        self.assertEqual(turbovasctl.APP_PORTS["gsad"], "${TURBOVAS_GSAD_HOST:-127.0.0.1}:19392:9392")
        self.assertNotIn("turbovas-api", turbovasctl.APP_PORTS)
        self.assertEqual(turbovasctl.TURBOVAS_API_CONTAINER_PORT, "9080")
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

    def test_short_secret_redaction_preserves_benign_identifier_names(self):
        text = '{"admin_uuid":"kept", "created_by":"admin", "check":"runtime.admin-secret", "flag":"admin-secret", "user":"admin"}'
        redacted = turbovasctl.redact_text(text, ["admin"])
        self.assertIn('"admin_uuid"', redacted)
        self.assertIn('"runtime.admin-secret"', redacted)
        self.assertIn('"admin-secret"', redacted)
        self.assertIn('"created_by":"[redacted]"', redacted)
        self.assertIn('"user":"[redacted]"', redacted)

    def test_short_secret_redaction_handles_log_tokens_without_path_mangling(self):
        text = "login admin failed; username=admin; home=/home/admin; key=admin_uuid"
        redacted = turbovasctl.redact_text(text, ["admin"])
        self.assertIn("login [redacted] failed", redacted)
        self.assertIn("username=[redacted]", redacted)
        self.assertIn("home=/home/admin", redacted)
        self.assertIn("key=admin_uuid", redacted)

    def test_long_secret_redaction_replaces_embedded_token(self):
        secret = "long-generated-token"
        text = f"prefix-{secret}-suffix token={secret}"
        redacted = turbovasctl.redact_text(text, [secret])
        self.assertEqual(redacted.count("[redacted]"), 2)
        self.assertNotIn(secret, redacted)

    def test_output_tail_uses_safe_secret_redaction(self):
        output = "first\nadmin_uuid=kept\npassword=admin\n"
        self.assertEqual(
            turbovasctl.output_tail(output, lines=2, secrets_to_redact=["admin"]),
            ["admin_uuid=kept", "password=[redacted]"],
        )

    def test_redaction_ignores_empty_secrets(self):
        self.assertEqual(turbovasctl.redact_text("username=admin", [""]), "username=admin")

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
