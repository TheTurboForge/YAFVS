# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import contextlib
import dataclasses
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.feed_transition import (
    FeedTransitionDependencies,
    run_feed_generation_transition,
)
from tools.tests.test_turbovasctl import turbovasctl


SOURCE_PATH = Path(__file__).resolve().parents[1] / "feed_transition.py"


class FeedTransitionModuleTests(unittest.TestCase):
    def test_engine_does_not_import_runtime_command_surface(self):
        source = SOURCE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_modules = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_modules.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )

        self.assertNotIn("turbovasctl", imported_modules)
        self.assertNotIn("importlib", imported_modules)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("docker", source.lower())
        self.assertNotIn("psql", source.lower())

    def test_dependencies_keep_security_sensitive_operations_in_adapter(self):
        fields = {
            field.name for field in dataclasses.fields(FeedTransitionDependencies)
        }

        self.assertTrue(
            {
                "acquire_runtime_lock",
                "read_feed_activation_state",
                "write_feed_activation_state",
                "read_feed_generation_db_attestation",
                "write_feed_generation_db_attestation",
                "stop_app_services_for_feed_transition",
                "command_runtime_feed_import_init",
                "restart_and_verify_feed_app_services",
                "transition_phase",
            }.issubset(fields)
        )

    def test_target_commit_orders_attestation_journal_and_restart(self):
        source = SOURCE_PATH.read_text(encoding="utf-8")
        commit = source[
            source.index("            completed_at: str | None = None") :
            source.index("            compensation_stop =")
        ]

        self.assertLess(
            commit.index('"database-attested"'),
            commit.index('"activation-journal-completed"'),
        )
        self.assertLess(
            commit.index('"activation-journal-completed"'),
            commit.index("restart_and_verify_feed_app_services("),
        )

    def test_compensation_orders_attestation_journal_and_restart(self):
        source = SOURCE_PATH.read_text(encoding="utf-8")
        compensation = source[source.index("            compensation_stop =") :]

        self.assertLess(
            compensation.index('"compensation-database-attested"'),
            compensation.index('"compensation-journal-completed"'),
        )
        self.assertLess(
            compensation.index('"compensation-journal-completed"'),
            compensation.index("restart_and_verify_feed_app_services("),
        )


class SimulatedProcessExit(BaseException):
    pass


class PersistentTransitionHarness:
    target_id = "a" * 64
    prior_id = "b" * 64
    older_id = "c" * 64

    def __init__(self, interrupt_phase, import_statuses):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "TurboVAS"
        self.root.mkdir()
        self.selector_path = self.root / "selector"
        self.database_path = self.root / "database-attestation"
        self.journal_path = self.root / "activation.json"
        self.selector_path.write_text(self.prior_id, encoding="ascii")
        self.database_path.write_text(self.prior_id, encoding="ascii")
        self._write_journal(
            {
                "schema_version": 1,
                "status": "active",
                "current_generation_id": self.prior_id,
                "target_generation_id": None,
                "previous_generation_id": None,
                "rollback_generation_id": self.older_id,
            }
        )
        self.interrupt_phase = interrupt_phase
        self.interrupt_armed = True
        self.import_statuses = list(import_statuses)
        self.events = []
        self.lock_held = False
        self.lock_acquisitions = 0
        self.running_services = set(turbovasctl.APP_SERVICES)
        self.image_ids = {
            service: "sha256:" + f"{index + 1:x}" * 64
            for index, service in enumerate(turbovasctl.APP_SERVICES)
        }
        self.runtime_artifacts = {"schema_version": 1, "digest": "d" * 64}
        self.compose_contract = {"schema_version": 1, "digest": "e" * 64}
        self.dependencies = dataclasses.replace(
            turbovasctl.feed_transition_dependencies(),
            acquire_runtime_lock=self.acquire_runtime_lock,
            verify_generation=self.verify_generation,
            read_current_generation=self.read_current_generation,
            select_generation=self.select_generation,
            clear_current_generation=self.clear_current_generation,
            read_feed_activation_state=self.read_feed_activation_state,
            write_feed_activation_state=self.write_feed_activation_state,
            read_feed_generation_db_attestation=self.read_database_attestation,
            write_feed_generation_db_attestation=self.write_database_attestation,
            feed_generation_specs=lambda: (),
            runtime_dir=lambda _root: self.root / "runtime",
            runtime_lock_dir=lambda _root: self.root / "locks",
            feed_activation_state_path=lambda _root: self.journal_path,
            app_deployment_receipt_path=lambda _root: self.root / "app-deployment.json",
            feed_transition_restore_app_env=lambda _root, _state: {
                turbovasctl.GSAD_HOSTS_ENV: "192.0.2.10"
            },
            gsad_hosts_from_env=lambda _env: ("192.0.2.10",),
            require_app_deployment_receipt=self.require_deployment_receipt,
            validate_app_service_image_ids=lambda value: value,
            validate_app_runtime_artifact_manifest=lambda value: value,
            validate_app_compose_contract=lambda value: value,
            container_running=lambda _root, service: service
            in self.running_services,
            app_service_image_findings=self.app_service_image_findings,
            app_service_image_availability_error=lambda _root, _ids: None,
            app_runtime_artifact_finding=self.pass_finding,
            app_compose_contract_finding=self.pass_finding,
            compose_command_with_app_images=lambda *_args, **_kwargs: ["true"],
            run_command=lambda *_args, **_kwargs: subprocess.CompletedProcess(
                [], 0, "", ""
            ),
            feed_activation_scan_quiescence_finding=lambda _root: turbovasctl.finding(
                "pass", "feed-generation.active-scans", "Mock scans are quiescent."
            ),
            stop_feed_control_services_for_preflight=self.stop_control_services,
            restart_feed_control_services_after_preflight=lambda *_args: turbovasctl.finding(
                "pass", "feed-generation.control-restore", "Mock controls restored."
            ),
            stop_app_services_for_feed_transition=self.stop_app_services,
            command_runtime_feed_import_init=self.import_feed,
            restart_and_verify_feed_app_services=self.restart_app_services,
            transition_phase=self.transition_phase,
        )

    def close(self):
        self.temporary.cleanup()

    def _read_id(self, path):
        return path.read_text(encoding="ascii").strip() if path.exists() else None

    def _write_id(self, path, value):
        if value is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(value, encoding="ascii")

    def _write_journal(self, payload):
        self.journal_path.write_text(
            json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
        )

    @contextlib.contextmanager
    def acquire_runtime_lock(self, *_args):
        if self.lock_held:
            raise AssertionError("transition lock was re-entered")
        self.lock_held = True
        self.lock_acquisitions += 1
        try:
            yield
        finally:
            self.lock_held = False

    def verify_generation(self, _root, generation_id, *_args):
        return {"generation_id": generation_id, "verified": True}

    def read_current_generation(self, *_args):
        generation_id = self._read_id(self.selector_path)
        return (
            {"generation_id": generation_id, "verified": True}
            if generation_id
            else None
        )

    def select_generation(self, _root, generation_id, *_args):
        previous = self._read_id(self.selector_path)
        self._write_id(self.selector_path, generation_id)
        self.events.append(("select", generation_id))
        return {
            "generation_id": generation_id,
            "current_generation_id": generation_id,
            "previous_generation_id": previous,
        }

    def clear_current_generation(self, _root, generation_id):
        if self._read_id(self.selector_path) == generation_id:
            self._write_id(self.selector_path, None)
        self.events.append(("clear", generation_id))

    def read_feed_activation_state(self, _root):
        return json.loads(self.journal_path.read_text(encoding="utf-8"))

    def write_feed_activation_state(self, _root, payload):
        self._write_journal({"schema_version": 1, **payload})
        self.events.append(("journal", payload["status"]))

    def read_database_attestation(self, _root):
        generation_id = self._read_id(self.database_path)
        return {"generation_id": generation_id} if generation_id else None

    def write_database_attestation(self, _root, generation_id, completed_at):
        self._write_id(self.database_path, generation_id)
        self.events.append(("attestation", generation_id))
        return {"generation_id": generation_id, "completed_at": completed_at}

    def require_deployment_receipt(self, *_args, **_kwargs):
        return (
            {
                "image_ids": self.image_ids,
                "runtime_artifacts": self.runtime_artifacts,
                "compose_contract": self.compose_contract,
            },
            None,
        )

    def app_service_image_findings(self, _root, _ids, **_kwargs):
        return [
            turbovasctl.finding(
                "pass",
                "feed-generation.running-app-image",
                f"Mock {service} image matches.",
            )
            for service in turbovasctl.APP_SERVICES
        ]

    def pass_finding(self, *_args, check, **_kwargs):
        return turbovasctl.finding("pass", check, "Mock identity matches.")

    def stop_control_services(self, _root):
        self.events.append(("controls", "stopped"))
        return turbovasctl.finding(
            "pass",
            "feed-generation.control-quiesce",
            "Mock controls stopped.",
            details={"previously_running_services": []},
        )

    def stop_app_services(self, _root, check):
        self.running_services.clear()
        self.events.append(("apps", "stopped"))
        return turbovasctl.finding("pass", check, "Mock app services stopped.")

    def import_feed(self, *_args, **_kwargs):
        status = self.import_statuses.pop(0) if self.import_statuses else "pass"
        self.events.append(("import", status))
        return {
            "status": status,
            "summary": f"Mock feed import {status}.",
            "findings": [],
            "artifacts": [],
        }

    def restart_app_services(self, *_args, **_kwargs):
        self.running_services = set(turbovasctl.APP_SERVICES)
        self.events.append(("apps", "restarted"))
        return {
            "status": "pass",
            "summary": "Mock app services restarted.",
            "findings": [],
            "artifacts": [],
        }

    def transition_phase(self, phase, details):
        self.events.append(("phase", phase, details["generation_id"]))
        if self.interrupt_armed and phase == self.interrupt_phase:
            self.interrupt_armed = False
            raise SimulatedProcessExit(phase)

    def run(self, generation_id, *, rollback=False):
        return run_feed_generation_transition(
            self.root,
            generation_id,
            rollback=rollback,
            dependencies=self.dependencies,
        )

    def durable_ids(self):
        journal = self.read_feed_activation_state(self.root)
        return (
            self._read_id(self.selector_path),
            journal.get("current_generation_id"),
            self._read_id(self.database_path),
        )


class FeedTransitionRestartRecoveryTests(unittest.TestCase):
    def test_forward_crash_points_release_lock_and_recover(self):
        phases = (
            "transition-journal-recorded",
            "selector-selected",
            "target-import-returned",
            "database-attested",
            "activation-journal-completed",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                harness = PersistentTransitionHarness(phase, ["pass"])
                self.addCleanup(harness.close)
                with self.assertRaisesRegex(SimulatedProcessExit, phase):
                    harness.run(harness.target_id)
                self.assertFalse(harness.lock_held)
                harness.import_statuses = ["pass"]
                if phase == "activation-journal-completed":
                    recovered = harness.run(harness.target_id)
                    expected_id = harness.target_id
                else:
                    recovered = harness.run(harness.prior_id, rollback=True)
                    expected_id = harness.prior_id
                self.assertIn(recovered["status"], {"pass", "warn"})
                self.assertEqual(
                    harness.durable_ids(), (expected_id, expected_id, expected_id)
                )
                self.assertEqual(
                    harness.running_services, set(turbovasctl.APP_SERVICES)
                )
                self.assertFalse(harness.lock_held)
                self.assertEqual(harness.lock_acquisitions, 2)

    def test_compensation_crash_points_release_lock_and_recover(self):
        phases = (
            "compensation-selector-selected",
            "compensation-import-returned",
            "compensation-database-attested",
            "compensation-journal-completed",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                harness = PersistentTransitionHarness(phase, ["fail", "pass"])
                self.addCleanup(harness.close)
                with self.assertRaisesRegex(SimulatedProcessExit, phase):
                    harness.run(harness.target_id)
                self.assertFalse(harness.lock_held)
                harness.import_statuses = ["pass"]
                if phase == "compensation-journal-completed":
                    recovered = harness.run(harness.prior_id)
                else:
                    recovered = harness.run(harness.prior_id, rollback=True)
                self.assertIn(recovered["status"], {"pass", "warn"})
                self.assertEqual(
                    harness.durable_ids(),
                    (harness.prior_id, harness.prior_id, harness.prior_id),
                )
                self.assertEqual(
                    harness.running_services, set(turbovasctl.APP_SERVICES)
                )
                self.assertFalse(harness.lock_held)
                self.assertEqual(harness.lock_acquisitions, 2)


if __name__ == "__main__":
    unittest.main()
