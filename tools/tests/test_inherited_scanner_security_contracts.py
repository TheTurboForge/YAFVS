# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
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


if __name__ == "__main__":
    unittest.main()
