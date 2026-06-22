#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Focused checks for browser screenshot helper guards."""

from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
