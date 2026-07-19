#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
#
# SPDX-License-Identifier: GPL-2.0-only

"""Exercise the OpenVAS pidfd stop boundary against isolated Redis state."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OPENVAS = REPO_ROOT / "build/openvas-scanner/src/openvas"


def require_command(name: str) -> str:
    command = shutil.which(name)
    if command is None:
        raise RuntimeError(f"Required command is unavailable: {name}")
    return command


def wait_for_socket(socket_path: Path, server: subprocess.Popen) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if socket_path.is_socket():
            return
        if server.poll() is not None:
            raise RuntimeError("The isolated Redis server exited during startup")
        time.sleep(0.05)
    raise RuntimeError("The isolated Redis socket did not become ready")


def redis_command(
    redis_cli: str, socket_path: Path, *arguments: str, database: int = 0
) -> str:
    completed = subprocess.run(
        [
            redis_cli,
            "-s",
            str(socket_path),
            "-n",
            str(database),
            *arguments,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return completed.stdout.strip()


def target_code(mode: str) -> str:
    if mode == "clean":
        return "\n".join(
            (
                "import signal",
                "import subprocess",
                "import sys",
                "import time",
                "socket_path = sys.argv[1]",
                "scan_id = sys.argv[3]",
                "def finish(*_args):",
                "    subprocess.run(['redis-cli', '-s', socket_path, '-n', "
                "'1', 'RPUSH', f'internal/{scan_id}', 'finished'], "
                "check=True, stdout=subprocess.DEVNULL)",
                "    raise SystemExit(0)",
                "signal.signal(signal.SIGUSR1, finish)",
                "while True:",
                "    time.sleep(1)",
            )
        )
    if mode == "no-marker":
        return "\n".join(
            (
                "import signal",
                "import sys",
                "import time",
                "signal.signal(signal.SIGUSR1, lambda *_args: sys.exit(0))",
                "while True:",
                "    time.sleep(1)",
            )
        )
    if mode == "forced":
        return "\n".join(
            (
                "import signal",
                "import time",
                "signal.signal(signal.SIGUSR1, signal.SIG_IGN)",
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                "while True:",
                "    time.sleep(1)",
            )
        )
    return "import time\nwhile True:\n    time.sleep(1)\n"


def run_case(
    case: str,
    openvas_binary: Path,
    redis_server: str,
    redis_cli: str,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="yafvs-process-control-") as temp:
        temp_path = Path(temp)
        socket_path = temp_path / "redis.sock"
        redis = subprocess.Popen(
            [
                redis_server,
                "--port",
                "0",
                "--unixsocket",
                str(socket_path),
                "--unixsocketperm",
                "700",
                "--databases",
                "16",
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        target = None
        try:
            wait_for_socket(socket_path, redis)
            plugin_dir = temp_path / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "plugin_feed_info.inc").write_text(
                'PLUGIN_SET = "process-control-test";\n'
                'PLUGIN_FEED = "YAFVS isolated test";\n'
                'FEED_VENDOR = "YAFVS";\n'
                'FEED_HOME = "https://github.com/TheTurboForge/YAFVS";\n'
                'FEED_NAME = "TEST";\n'
                'FEED_COMMIT = "test";\n',
                encoding="utf-8",
            )
            requested_scan = f"process-control-{case}"
            target_scan = "different-scan" if case == "wrong-scan" else requested_scan
            target = subprocess.Popen(
                [
                    "openvas",
                    "-c",
                    target_code(case),
                    str(socket_path),
                    "--scan-start",
                    target_scan,
                ],
                executable=sys.executable,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.1)
            redis_command(
                redis_cli,
                socket_path,
                "HSET",
                "GVM.__GlobalDBIndex",
                "1",
                "1",
            )
            redis_command(
                redis_cli,
                socket_path,
                "RPUSH",
                f"internal/{requested_scan}",
                "stop_all",
                database=1,
            )
            redis_command(
                redis_cli,
                socket_path,
                "RPUSH",
                "internal/ovas_pid",
                str(target.pid),
                database=1,
            )
            config_path = temp_path / "openvas.conf"
            config_path.write_text(
                f"db_address = {socket_path}\n"
                f"plugins_folder = {plugin_dir}\n"
                f"include_folders = {plugin_dir}\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            library_path = str(REPO_ROOT / "build/prefix/lib")
            environment["LD_LIBRARY_PATH"] = (
                f'{library_path}:{environment["LD_LIBRARY_PATH"]}'
                if environment.get("LD_LIBRARY_PATH")
                else library_path
            )
            started = time.monotonic()
            helper = subprocess.run(
                [
                    str(openvas_binary),
                    f"--config-file={config_path}",
                    "--scan-stop",
                    requested_scan,
                ],
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=35,
            )
            elapsed = time.monotonic() - started
            target_alive = target.poll() is None
            status = redis_command(
                redis_cli,
                socket_path,
                "LINDEX",
                f"internal/{requested_scan}",
                "-1",
                database=1,
            )

            passed = {
                "clean": helper.returncode == 0
                and not target_alive
                and status == "finished",
                "no-marker": helper.returncode != 0
                and not target_alive
                and status == "stop_all",
                "wrong-scan": helper.returncode != 0 and target_alive,
                "forced": helper.returncode != 0
                and not target_alive
                and status == "stop_all"
                and elapsed >= 20,
            }[case]
            return {
                "case": case,
                "status": "pass" if passed else "fail",
                "helper_returncode": helper.returncode,
                "target_alive": target_alive,
                "redis_status": status,
                "elapsed_seconds": round(elapsed, 3),
                "helper_stderr_tail": helper.stderr.splitlines()[-5:],
            }
        finally:
            if target is not None and target.poll() is None:
                target.kill()
                target.wait(timeout=5)
            redis.terminate()
            try:
                redis.wait(timeout=5)
            except subprocess.TimeoutExpired:
                redis.kill()
                redis.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openvas", type=Path, default=DEFAULT_OPENVAS)
    parser.add_argument("--include-escalation", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.openvas.is_file():
        parser.error(f"OpenVAS binary does not exist: {args.openvas}")
    redis_server = require_command("redis-server")
    redis_cli = require_command("redis-cli")
    cases = ["clean", "no-marker", "wrong-scan"]
    if args.include_escalation:
        cases.append("forced")
    results = [run_case(case, args.openvas, redis_server, redis_cli) for case in cases]
    payload = {
        "status": (
            "pass" if all(result["status"] == "pass" for result in results) else "fail"
        ),
        "results": results,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for result in results:
            print(
                f"{result['status']}: {result['case']} "
                f"(helper={result['helper_returncode']}, "
                f"target_alive={result['target_alive']}, "
                f"redis={result['redis_status']})"
            )
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
