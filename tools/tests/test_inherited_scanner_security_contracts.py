# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-2.0-or-later

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class InheritedScannerSecurityContractTests(unittest.TestCase):
    def test_scanner_never_requests_unconditional_kerberos_delegation(self):
        source = (
            ROOT
            / "components/openvas-smb/samba/auth/gensec/gensec_gssapi.c"
        ).read_text(encoding="utf-8")

        self.assertNotRegex(
            source,
            r"want_flags\s*\|=\s*GSS_C_DELEG_FLAG",
            "scanner authentication must not delegate reusable credentials",
        )

    def test_dcerpc_parse_failure_stops_dispatch(self):
        source = (
            ROOT / "components/openvas-smb/samba/librpc/rpc/dcerpc.c"
        ).read_text(encoding="utf-8")
        function = source[
            source.index("static void dcerpc_recv_data") : source.index(
                "static void dcerpc_bind_recv_handler"
            )
        ]

        self.assertRegex(
            function,
            re.compile(
                r"status\s*=\s*ncacn_pull\([^;]+;"
                r"\s*if\s*\(!NT_STATUS_IS_OK\(status\)\)\s*\{"
                r"\s*data_blob_free\(blob\);"
                r"\s*dcerpc_connection_dead\(conn,\s*status\);"
                r"\s*return;\s*\}",
                re.DOTALL,
            ),
            "malformed DCE/RPC packets must not reach request dispatch",
        )

    def test_c_ssh_output_uses_one_aggregate_budget(self):
        ssh_source = (
            ROOT / "components/openvas-scanner/nasl/nasl_ssh.c"
        ).read_text(encoding="utf-8")
        budget_source = (
            ROOT / "components/openvas-scanner/nasl/nasl_ssh_output.c"
        ).read_text(encoding="utf-8")
        budget_header = (
            ROOT / "components/openvas-scanner/nasl/nasl_ssh_output.h"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "#define SSH_OUTPUT_MAX_SIZE (16U * 1024U * 1024U)",
            budget_header,
        )
        self.assertEqual(
            ssh_source.count("nasl_ssh_output_append"),
            8,
            "all SSH output reads and compatibility concatenation must use the budget",
        )
        self.assertNotIn("g_string_append_len", ssh_source)
        self.assertEqual(budget_source.count("g_string_append_len"), 1)
        self.assertIn("length > limit - retained", budget_source)

    def test_scanner_results_use_typed_framing(self):
        expected_producers = (
            "misc/network.c",
            "misc/plugutils.c",
            "src/attack.c",
            "src/hosts.c",
            "src/openvas.c",
            "src/pluginlaunch.c",
        )
        scanner = ROOT / "components/openvas-scanner"
        producers = []
        for path in scanner.rglob("*.c"):
            source = path.read_text(encoding="utf-8")
            if '"internal/results"' in source:
                producers.append(str(path.relative_to(scanner)))
        self.assertEqual(sorted(producers), sorted(expected_producers))

        for relative_path in producers:
            with self.subTest(path=relative_path):
                source = (scanner / relative_path).read_text(encoding="utf-8")
                self.assertIn(
                    "openvas_result_message_new",
                    source,
                    "every retained scanner-result producer must use typed framing",
                )

        ospd = (
            ROOT / "components/ospd-openvas/ospd_openvas/daemon.py"
        ).read_text(encoding="utf-8")
        rust = (
            scanner / "rust/src/openvas/result_collector.rs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("split('|||'", ospd)
        self.assertNotIn('split("|||")', rust)
        self.assertIn("result.get('version') != 1", ospd)
        self.assertIn("record.version == 1", rust)

    def test_scanner_result_queue_has_atomic_producer_admission(self):
        kb_source = (
            ROOT / "components/gvm-libs/util/kb.c"
        ).read_text(encoding="utf-8")
        ospd_source = (
            ROOT / "components/ospd-openvas/ospd_openvas/daemon.py"
        ).read_text(encoding="utf-8")

        self.assertIn("SCANNER_RESULT_ADMISSION_SCRIPT", kb_source)
        self.assertIn("SCANNER_RESULT_MAX_ITEM_BYTES", kb_source)
        self.assertIn("SCANNER_RESULT_MAX_PENDING_ITEMS", kb_source)
        self.assertIn("SCANNER_RESULT_MAX_PENDING_BYTES", kb_source)
        self.assertIn("SCANNER_RESULT_PENDING_COUNT_KEY", kb_source)
        self.assertIn("SCANNER_RESULT_PENDING_BYTES_KEY", kb_source)
        self.assertIn("SCANNER_RESULT_ADMISSION_IDS_KEY", kb_source)
        self.assertIn("SCANNER_RESULT_SIZES_KEY", kb_source)
        self.assertIn("gvm_uuid_make ()", kb_source)
        self.assertIn("redis.call('LPOS', KEYS[6], ARGV[1])", kb_source)
        self.assertIn("redis.call('LPUSH', KEYS[1], ARGV[2])", kb_source)
        self.assertIn("retry_warning_logged", kb_source)
        self.assertIn(
            "The idempotent admission ID makes retries safe", kb_source
        )
        self.assertIn("g_usleep (G_USEC_PER_SEC)", kb_source)
        self.assertIn("strcmp (name, SCANNER_RESULT_KEY) == 0", kb_source)
        self.assertIn("handle_result_admission_failure", ospd_source)
        self.assertIn("stop_scan_cleanup", ospd_source)

        scanner_control = (
            ROOT / "components/openvas-scanner/src/openvas.c"
        ).read_text(encoding="utf-8")
        self.assertIn('"scan-stop-pid"', scanner_control)
        self.assertIn("stop_scan_process_by_pid", scanner_control)
        self.assertIn("process_matches_scan (pid, scan_id)", scanner_control)

    def test_scanner_results_remain_durable_until_gvmd_acknowledges(self):
        spool_source = (
            ROOT / "components/ospd-openvas/ospd/result_spool.py"
        ).read_text(encoding="utf-8")
        daemon_source = (
            ROOT / "components/ospd-openvas/ospd_openvas/daemon.py"
        ).read_text(encoding="utf-8")
        compose_source = (ROOT / "compose/dev.yaml").read_text(
            encoding="utf-8"
        )
        report_function = daemon_source[
            daemon_source.index("    def report_openvas_results(") :
            daemon_source.index("    def drain_openvas_results(")
        ]
        ack_function = daemon_source[
            daemon_source.index("    def ack_result_batch(") :
            daemon_source.index("    def delete_scan(")
        ]

        self.assertIn("PRAGMA journal_mode = WAL", spool_source)
        self.assertIn("PRAGMA synchronous = FULL", spool_source)
        self.assertIn("STAGED = 'STAGED'", spool_source)
        self.assertIn("EXPOSED = 'EXPOSED'", spool_source)
        self.assertIn("ACKING = 'ACKING'", spool_source)
        self.assertIn("ACKED = 'ACKED'", spool_source)
        self.assertIn("claims_one_pending_per_scan", spool_source)
        self.assertLess(
            ack_function.index("begin_ack("),
            ack_function.index("release_spooled_redis_claim("),
        )
        self.assertLess(
            ack_function.index("release_spooled_redis_claim("),
            ack_function.index("complete_ack("),
        )
        self.assertLess(
            report_function.index("if self.result_spool is not None:"),
            report_function.index("db.ack_result_claim(claim_id)"),
        )
        self.assertIn(
            "--result-spool-dir=/runtime/state/ospd/result-spool",
            compose_source,
        )

    def test_notus_uses_only_the_authenticated_mqtt_scanner_path(self):
        scanner = ROOT / "components/openvas-scanner"
        nasl_init = (scanner / "nasl/nasl_init.c").read_text(encoding="utf-8")
        nasl_glue = (scanner / "nasl/nasl_scanner_glue.c").read_text(
            encoding="utf-8"
        )
        lsc_source = (scanner / "misc/table_driven_lsc.c").read_text(
            encoding="utf-8"
        )
        scanner_source = (scanner / "src/openvas.c").read_text(encoding="utf-8")
        attack_source = (scanner / "src/attack.c").read_text(encoding="utf-8")
        ospd_source = (
            ROOT / "components/ospd-openvas/ospd_openvas/daemon.py"
        ).read_text(encoding="utf-8")
        spool_source = (
            ROOT / "components/ospd-openvas/ospd/result_spool.py"
        ).read_text(encoding="utf-8")
        ospd_db_source = (
            ROOT / "components/ospd-openvas/ospd_openvas/db.py"
        ).read_text(encoding="utf-8")
        rust_notus = (
            scanner / "rust/src/nasl/builtin/notus/mod.rs"
        ).read_text(encoding="utf-8")
        rust_reporting = (
            scanner / "rust/src/nasl/builtin/report_functions/mod.rs"
        ).read_text(encoding="utf-8")

        self.assertIn('"update_table_driven_lsc_data"', nasl_init)
        for removed_builtin in ('"notus"', '"notus_type"', '"notus_error"'):
            self.assertNotIn(removed_builtin, nasl_init)
        self.assertNotIn('"security_notus"', nasl_init)
        self.assertNotIn("nasl_notus (", nasl_glue)
        self.assertNotIn("security_notus (", nasl_glue)

        for source in (lsc_source, scanner_source, attack_source, ospd_source):
            self.assertNotIn("openvasd_lsc_enabled", source)
            self.assertNotIn("openvasd_server", source)
        self.assertNotIn("CURLOPT_SSL_VERIFYPEER", lsc_source)
        self.assertNotIn("CURLOPT_SSL_VERIFYHOST", lsc_source)
        self.assertIn('prefs_get ("mqtt_server_uri")', scanner_source)
        self.assertIn("mqtt_init_auth", scanner_source)
        self.assertIn('prefs_get_bool ("mqtt_enabled")', attack_source)
        self.assertNotIn("OPENVASD = 'openvasd'", spool_source)
        self.assertNotIn("'mqtt', 'openvasd', 'none'", ospd_db_source)
        for retained_builtin in (
            'fn notus_type()',
            'fn notus_error(',
            'async fn notus(',
        ):
            self.assertIn(retained_builtin, rust_notus)
        self.assertIn("async fn security_notus(", rust_reporting)

        standalone_manifests = (
            scanner / "compose/base.yaml",
            scanner / "compose/tls.yaml",
            scanner / "compose/mtls.yaml",
            scanner / "charts/openvasd/templates/deployment.yaml",
        )
        for manifest in standalone_manifests:
            source = manifest.read_text(encoding="utf-8")
            self.assertIn("table_driven_lsc = no", source)
            self.assertNotIn("openvasd_server =", source)

        rust_root = scanner / "rust"
        rust_sources = {
            "context": rust_root / "src/nasl/utils/scan_ctx.rs",
            "notus": rust_root / "src/nasl/builtin/notus/mod.rs",
            "config": rust_root / "src/openvasd/config/mod.rs",
            "main": rust_root / "src/openvasd/main.rs",
            "scannerctl": rust_root / "src/scannerctl/execute/mod.rs",
            "openapi": rust_root / "api/openapi.yml",
        }
        rust_text = {
            name: path.read_text(encoding="utf-8")
            for name, path in rust_sources.items()
        }
        self.assertNotIn("NotusCtx::Address", "\n".join(rust_text.values()))
        self.assertNotIn("notus_extern", rust_text["notus"])
        self.assertNotIn("notus-address", rust_text["config"])
        self.assertNotIn("mod notus;", rust_text["main"])
        self.assertNotIn("/notus:", rust_text["openapi"])
        self.assertFalse((rust_root / "src/openvasd/notus/mod.rs").exists())
        self.assertEqual(
            list((scanner / "compose/tests/smoketest/notus").glob("*.hurl")),
            [],
        )

    def test_http2_requests_pin_the_authorized_scan_target(self):
        source = (
            ROOT / "components/openvas-scanner/nasl/nasl_http2.c"
        ).read_text(encoding="utf-8")

        self.assertIn("plug_get_host_ip (script_infos)", source)
        self.assertIn("CURLOPT_CONNECT_TO", source)
        self.assertIn('CURLOPT_PROXY, ""', source)
        self.assertIn('CURLOPT_NOPROXY, "*"', source)
        self.assertIn("CURLOPT_FOLLOWLOCATION, 0L", source)
        self.assertIn("configure_scoped_http2_transport", source)
        self.assertIn("http2_item_is_safe_path", source)
        self.assertIn("normalize_http2_hostname", source)


if __name__ == "__main__":
    unittest.main()
