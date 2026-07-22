#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Focused checks for browser screenshot helper guards."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def load_tool_module(name: str, filename: str):
    path = TOOLS_DIR / filename
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RuntimeBrowserScreenshotTests(unittest.TestCase):
    def test_browser_scripts_warn_on_empty_screenshot_evidence(self) -> None:
        for filename in ["runtime_browser_smoke.py", "runtime_browser_regression.py"]:
            with self.subTest(filename=filename):
                source = (TOOLS_DIR / filename).read_text(encoding="utf-8")
                self.assertIn("async function screenshotContentEvidence", source)
                self.assertIn(".screenshot-content", source)
                self.assertIn("Screenshot page looked empty or weak at capture time.", source)
                self.assertIn("contentElementCount === 0", source)

    def test_embedded_browser_scripts_remain_valid_javascript(self) -> None:
        for module_name, filename in [
            ("runtime_browser_smoke_for_screenshot_test", "runtime_browser_smoke.py"),
            ("runtime_browser_regression_for_screenshot_test", "runtime_browser_regression.py"),
        ]:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                module = load_tool_module(module_name, filename)
                script = Path(tmp) / "browser-script.cjs"
                script.write_text(module.BROWSER_SCRIPT, encoding="utf-8")
                completed = subprocess.run(
                    ["node", "--check", str(script)],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_browser_regression_timeout_terminates_process_group(self) -> None:
        module = load_tool_module(
            "runtime_browser_regression_for_timeout_test",
            "runtime_browser_regression.py",
        )
        with tempfile.TemporaryDirectory() as tmp:
            ready_path = Path(tmp) / "child-ready"
            terminated_path = Path(tmp) / "child-terminated"
            child_script = (
                "import pathlib, signal, sys, time; "
                "ready = pathlib.Path(sys.argv[1]); "
                "terminated = pathlib.Path(sys.argv[2]); "
                "signal.signal(signal.SIGTERM, "
                "lambda *_: (terminated.write_text('terminated'), sys.exit(0))); "
                "ready.write_text('ready'); time.sleep(30)"
            )
            parent_script = (
                "import pathlib, subprocess, sys, time; "
                "ready = pathlib.Path(sys.argv[1]); "
                "subprocess.Popen([sys.executable, '-c', sys.argv[3], "
                "sys.argv[1], sys.argv[2]]); "
                "deadline = time.monotonic() + 5; "
                "\nwhile not ready.exists() and time.monotonic() < deadline: "
                "time.sleep(0.01); "
                "\ntime.sleep(30)"
            )
            completed = module.run_browser_process(
                [
                    sys.executable,
                    "-c",
                    parent_script,
                    str(ready_path),
                    str(terminated_path),
                    child_script,
                ],
                dict(os.environ),
                2,
            )

            self.assertEqual(completed.returncode, 124, completed.stdout)
            self.assertIn("Timed out after 2 seconds.", completed.stdout)
            self.assertTrue(ready_path.exists(), completed.stdout)
            self.assertTrue(terminated_path.exists(), completed.stdout)


if __name__ == "__main__":
    unittest.main()
