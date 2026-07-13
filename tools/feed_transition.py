# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed immutable feed-generation transition state machine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class FeedTransitionDependencies:
    """Security-sensitive runtime operations injected by turbovasctl."""

    app_services: tuple[str, ...]
    feed_activation_lock: str
    feed_release: str
    feed_generation_error: type[Exception]
    runtime_lock_timeout: type[Exception]
    acquire_runtime_lock: Callable[..., Any]
    app_compose_contract_finding: Callable[..., Any]
    app_deployment_receipt_path: Callable[..., Any]
    app_runtime_artifact_finding: Callable[..., Any]
    app_service_image_availability_error: Callable[..., Any]
    app_service_image_findings: Callable[..., Any]
    clear_current_generation: Callable[..., Any]
    command_runtime_feed_import_init: Callable[..., Any]
    compose_command_with_app_images: Callable[..., Any]
    container_running: Callable[..., Any]
    feed_activation_scan_quiescence_finding: Callable[..., Any]
    feed_activation_state_path: Callable[..., Any]
    feed_generation_specs: Callable[..., Any]
    feed_import_summary_finding: Callable[..., Any]
    feed_transition_restore_app_env: Callable[..., Any]
    finding: Callable[..., Any]
    gsad_hosts_from_env: Callable[..., Any]
    make_result: Callable[..., Any]
    process_step_finding: Callable[..., Any]
    read_current_generation: Callable[..., Any]
    read_feed_activation_state: Callable[..., Any]
    read_feed_generation_db_attestation: Callable[..., Any]
    require_app_deployment_receipt: Callable[..., Any]
    restart_and_verify_feed_app_services: Callable[..., Any]
    restart_feed_control_services_after_preflight: Callable[..., Any]
    run_command: Callable[..., Any]
    runtime_dir: Callable[..., Any]
    runtime_lock_dir: Callable[..., Any]
    runtime_lock_timeout_finding: Callable[..., Any]
    select_generation: Callable[..., Any]
    stop_app_services_for_feed_transition: Callable[..., Any]
    stop_feed_control_services_for_preflight: Callable[..., Any]
    transition_phase: Callable[..., Any]
    validate_app_compose_contract: Callable[..., Any]
    validate_app_runtime_artifact_manifest: Callable[..., Any]
    validate_app_service_image_ids: Callable[..., Any]
    verify_generation: Callable[..., Any]
    write_feed_activation_state: Callable[..., Any]
    write_feed_generation_db_attestation: Callable[..., Any]


def run_feed_generation_transition(
    repo_root: Path,
    generation_id: str,
    *,
    rollback: bool = False,
    allow_first_activation: bool = False,
    repair_attestation: bool = False,
    dependencies: FeedTransitionDependencies,
) -> dict[str, Any]:
    APP_SERVICES = dependencies.app_services
    FEED_ACTIVATION_LOCK = dependencies.feed_activation_lock
    FEED_RELEASE = dependencies.feed_release
    FeedGenerationError = dependencies.feed_generation_error
    RuntimeLockTimeout = dependencies.runtime_lock_timeout
    acquire_runtime_lock = dependencies.acquire_runtime_lock
    app_compose_contract_finding = dependencies.app_compose_contract_finding
    app_deployment_receipt_path = dependencies.app_deployment_receipt_path
    app_runtime_artifact_finding = dependencies.app_runtime_artifact_finding
    app_service_image_availability_error = dependencies.app_service_image_availability_error
    app_service_image_findings = dependencies.app_service_image_findings
    clear_current_generation = dependencies.clear_current_generation
    command_runtime_feed_import_init = dependencies.command_runtime_feed_import_init
    compose_command_with_app_images = dependencies.compose_command_with_app_images
    container_running = dependencies.container_running
    feed_activation_scan_quiescence_finding = dependencies.feed_activation_scan_quiescence_finding
    feed_activation_state_path = dependencies.feed_activation_state_path
    feed_generation_specs = dependencies.feed_generation_specs
    feed_import_summary_finding = dependencies.feed_import_summary_finding
    feed_transition_restore_app_env = dependencies.feed_transition_restore_app_env
    finding = dependencies.finding
    gsad_hosts_from_env = dependencies.gsad_hosts_from_env
    make_result = dependencies.make_result
    process_step_finding = dependencies.process_step_finding
    read_current_generation = dependencies.read_current_generation
    read_feed_activation_state = dependencies.read_feed_activation_state
    read_feed_generation_db_attestation = dependencies.read_feed_generation_db_attestation
    require_app_deployment_receipt = dependencies.require_app_deployment_receipt
    restart_and_verify_feed_app_services = dependencies.restart_and_verify_feed_app_services
    restart_feed_control_services_after_preflight = dependencies.restart_feed_control_services_after_preflight
    run_command = dependencies.run_command
    runtime_dir = dependencies.runtime_dir
    runtime_lock_dir = dependencies.runtime_lock_dir
    runtime_lock_timeout_finding = dependencies.runtime_lock_timeout_finding
    select_generation = dependencies.select_generation
    stop_app_services_for_feed_transition = dependencies.stop_app_services_for_feed_transition
    stop_feed_control_services_for_preflight = dependencies.stop_feed_control_services_for_preflight
    transition_phase = dependencies.transition_phase
    validate_app_compose_contract = dependencies.validate_app_compose_contract
    validate_app_runtime_artifact_manifest = dependencies.validate_app_runtime_artifact_manifest
    validate_app_service_image_ids = dependencies.validate_app_service_image_ids
    verify_generation = dependencies.verify_generation
    write_feed_activation_state = dependencies.write_feed_activation_state
    write_feed_generation_db_attestation = dependencies.write_feed_generation_db_attestation

    action = "rollback" if rollback else "activate"
    command_name = f"feed-generation-{action}"
    findings: list[dict[str, Any]] = []
    runtime_root = runtime_dir(repo_root)
    generations_root = runtime_root / "feed-store" / "generations"
    specs = feed_generation_specs()

    try:
        with acquire_runtime_lock(repo_root, FEED_ACTIVATION_LOCK, command_name):
            try:
                target = verify_generation(
                    generations_root,
                    generation_id,
                    FEED_RELEASE,
                    specs,
                )
                current = read_current_generation(runtime_root, FEED_RELEASE, specs)
                state = read_feed_activation_state(repo_root)
            except (FeedGenerationError, OSError, ValueError) as error:
                findings.append(
                    finding(
                        "fail",
                        "feed-generation.transition-preflight",
                        f"Feed generation transition preflight failed closed: {error}",
                        str(generations_root),
                    )
                )
                return make_result(command_name, repo_root, "Feed generation transition stopped at verification.", findings, [str(generations_root)])

            current_id = current["generation_id"] if current else None
            findings.append(finding("pass", "feed-generation.target", "Target feed generation is complete and verified.", target.get("generation_id"), target))
            interrupted = state is not None and state.get("status") == "transitioning"
            state_before = state if state is not None and state.get("status") == "active" else None
            recovery_only = False
            prior_rollback_id = state_before.get("rollback_generation_id") if state_before else None
            database_attestation: dict[str, Any] | None = None
            database_attestation_error: str | None = None

            if state_before is not None and state_before.get("current_generation_id") != current_id:
                findings.append(finding("fail", "feed-generation.journal-selector", "Completed feed activation journal does not match the verified selector.", details={"journal": state_before.get("current_generation_id"), "selector": current_id}))
                return make_result(command_name, repo_root, "Feed generation transition stopped because journal and selector disagree.", findings, [str(feed_activation_state_path(repo_root))])
            if state is None and current_id is not None:
                findings.append(finding("fail", "feed-generation.journal-missing", "A feed selector exists without a completed activation journal; refusing to infer database state.", details={"selector": current_id}))
                return make_result(command_name, repo_root, "Feed generation transition requires explicit recovery of unjournaled state.", findings, [str(feed_activation_state_path(repo_root))])
            if state_before is not None:
                try:
                    database_attestation = read_feed_generation_db_attestation(
                        repo_root
                    )
                except (OSError, ValueError) as error:
                    database_attestation_error = str(error)
                database_attestation_matches_current = (
                    database_attestation_error is None
                    and database_attestation is not None
                    and database_attestation.get("generation_id") == current_id
                )
                if not repair_attestation and not database_attestation_matches_current:
                    findings.append(
                        finding(
                            "fail",
                            "feed-generation.database-attestation-preflight",
                            "The active database import attestation does not match the selector and journal; explicitly re-import the active generation with --repair-attestation before another transition.",
                            details={
                                "current_generation_id": current_id,
                                "database_generation_id": database_attestation.get("generation_id")
                                if database_attestation
                                else None,
                                "error": database_attestation_error,
                            },
                        )
                    )
                    return make_result(
                        command_name,
                        repo_root,
                        "Feed generation transition stopped because the active database import is not attested.",
                        findings,
                        [str(feed_activation_state_path(repo_root))],
                    )
                if database_attestation_matches_current:
                    findings.append(
                        finding(
                            "pass",
                            "feed-generation.database-attestation-preflight",
                            "Active database import attestation matches the selector and journal.",
                            details={"generation_id": current_id},
                        )
                    )
            else:
                database_attestation_matches_current = False
            if repair_attestation:
                if rollback or interrupted or state_before is None or current_id != generation_id:
                    findings.append(
                        finding(
                            "fail",
                            "feed-generation.attestation-repair-scope",
                            "Database attestation repair is limited to explicitly re-importing the completed active generation.",
                            details={
                                "requested_generation_id": generation_id,
                                "current_generation_id": current_id,
                                "journal_status": state.get("status") if state else None,
                            },
                        )
                    )
                    return make_result(command_name, repo_root, "Feed generation attestation repair stopped outside its active-generation boundary.", findings, [str(feed_activation_state_path(repo_root))])
                findings.append(
                    finding(
                        "warn",
                        "feed-generation.attestation-repair",
                        "The active immutable generation will be re-imported before its database attestation is written; metadata is never fabricated.",
                        details={"generation_id": generation_id},
                    )
                )
            if interrupted:
                interrupted_target = state.get("target_generation_id")
                interrupted_previous = state.get("previous_generation_id")
                prior_rollback_id = state.get("rollback_generation_id")
                if interrupted_previous is None:
                    if rollback or generation_id != interrupted_target or not allow_first_activation:
                        findings.append(finding("fail", "feed-generation.interrupted-first", "Interrupted first activation may only resume the recorded target with --allow-first-activation.", details={"recorded_target": interrupted_target, "requested_target": generation_id}))
                        return make_result(command_name, repo_root, "Feed generation transition stopped at interrupted first-activation recovery.", findings, [str(feed_activation_state_path(repo_root))])
                else:
                    if not rollback or generation_id != interrupted_previous:
                        findings.append(finding("fail", "feed-generation.interrupted-recovery", "Interrupted transition must recover to its recorded prior generation through feed-generation-rollback.", details={"recorded_previous": interrupted_previous, "requested_target": generation_id}))
                        return make_result(command_name, repo_root, "Feed generation transition requires rollback to the recorded known-good generation.", findings, [str(feed_activation_state_path(repo_root))])
                    recovery_only = True
                findings.append(finding("warn", "feed-generation.interrupted", "Resuming explicit recovery from an interrupted feed transition journal.", details=state))
            elif rollback:
                recorded_previous = state_before.get("rollback_generation_id") if state_before else None
                if current is None or recorded_previous != generation_id:
                    findings.append(finding("fail", "feed-generation.rollback-source", "Rollback target must be the recorded prior known-good generation.", details={"recorded_previous": recorded_previous, "requested_target": generation_id}))
                    return make_result(command_name, repo_root, "Feed generation rollback stopped because the target is not the recorded predecessor.", findings, [str(feed_activation_state_path(repo_root))])
            elif current is None and not allow_first_activation:
                findings.append(
                    finding(
                        "fail",
                        "feed-generation.first-activation",
                        "First activation requires --allow-first-activation because no known-good active generation exists for compensation.",
                        details={"generation_id": generation_id},
                    )
                )
                return make_result(command_name, repo_root, "Feed generation activation requires explicit first-activation acknowledgement.", findings, [str(generations_root / generation_id)])

            if current is not None:
                findings.append(finding("pass", "feed-generation.current", "Existing active feed generation is verified for compensating recovery.", current_id, current))

            restore_app_env = feed_transition_restore_app_env(repo_root, state)
            restore_gsad_hosts = list(gsad_hosts_from_env(restore_app_env))
            running_services: list[str] = []
            if interrupted and state is not None:
                try:
                    app_image_ids = validate_app_service_image_ids(
                        state.get("app_image_ids")
                    )
                    app_runtime_artifacts = validate_app_runtime_artifact_manifest(
                        state.get("app_runtime_artifacts")
                    )
                    app_compose_contract = validate_app_compose_contract(
                        state.get("app_compose_contract")
                    )
                except ValueError as error:
                    findings.append(finding("fail", "feed-generation.app-images", f"Recorded application deployment identity is invalid: {error}"))
                    return make_result(command_name, repo_root, "Feed generation transition stopped at application image verification.", findings, [str(feed_activation_state_path(repo_root))])
            else:
                receipt, receipt_error = require_app_deployment_receipt(
                    repo_root, app_env=restore_app_env
                )
                if receipt_error is not None or receipt is None:
                    findings.append(finding("fail", "feed-generation.app-images", receipt_error or "Prepared application deployment receipt is unavailable"))
                    return make_result(command_name, repo_root, "Feed generation transition stopped because no verified application deployment was prepared.", findings, [str(app_deployment_receipt_path(repo_root))])
                app_image_ids = receipt["image_ids"]
                app_runtime_artifacts = receipt["runtime_artifacts"]
                app_compose_contract = receipt["compose_contract"]
                if state_before is not None:
                    running_services = [
                        service
                        for service in APP_SERVICES
                        if container_running(repo_root, service)
                    ]
                    if running_services:
                        running_image_findings = app_service_image_findings(
                            repo_root,
                            app_image_ids,
                            check="feed-generation.running-app-image",
                        )
                        findings.extend(running_image_findings)
                        if any(
                            item["status"] != "pass"
                            for item in running_image_findings
                        ):
                            return make_result(
                                command_name,
                                repo_root,
                                "Feed generation transition stopped because the active application deployment does not match the prepared receipt; run runtime-app-up first.",
                                findings,
                                [str(app_deployment_receipt_path(repo_root))],
                            )
                    else:
                        findings.append(
                            finding(
                                "pass",
                                "feed-generation.running-app-image",
                                "Application services are fully stopped; the pinned deployment receipt will govern restart after import.",
                                details={"running_services": []},
                            )
                        )
            image_error = app_service_image_availability_error(repo_root, app_image_ids)
            if image_error is not None:
                findings.append(finding("fail", "feed-generation.app-images", image_error))
                return make_result(command_name, repo_root, "Feed generation transition stopped because pinned application image objects are unavailable; restore the exact recorded images or perform explicit manual recovery.", findings, [str(runtime_dir(repo_root))])
            artifact_preflight = app_runtime_artifact_finding(
                repo_root,
                app_runtime_artifacts,
                check="feed-generation.app-artifacts",
            )
            findings.append(artifact_preflight)
            if artifact_preflight["status"] != "pass":
                return make_result(command_name, repo_root, "Feed generation transition stopped because runtime artifacts do not match the recorded deployment.", findings, [str(feed_activation_state_path(repo_root))])
            compose_preflight = app_compose_contract_finding(
                repo_root,
                app_image_ids,
                app_compose_contract,
                app_env=restore_app_env,
                check="feed-generation.app-compose",
            )
            findings.append(compose_preflight)
            if compose_preflight["status"] != "pass":
                return make_result(command_name, repo_root, "Feed generation transition stopped because the application execution contract does not match the recorded deployment.", findings, [str(feed_activation_state_path(repo_root))])
            try:
                override_command = compose_command_with_app_images(
                    repo_root,
                    app_image_ids,
                    "--profile",
                    "app",
                    "config",
                    "--quiet",
                    env=restore_app_env,
                )
                override_config = run_command(
                    override_command,
                    repo_root,
                    env=restore_app_env,
                    timeout=120,
                )
            except (OSError, ValueError) as error:
                findings.append(finding("fail", "feed-generation.app-image-override", f"Pinned application image override could not be prepared: {error}"))
                return make_result(command_name, repo_root, "Feed generation transition stopped before runtime changes because deployment pinning failed.", findings, [str(runtime_dir(repo_root))])
            findings.append(
                process_step_finding(
                    "pass" if override_config.returncode == 0 else "fail",
                    "feed-generation.app-image-override",
                    f"Pinned application image Compose validation exit code {override_config.returncode}.",
                    override_config,
                    override_command,
                )
            )
            if override_config.returncode != 0:
                return make_result(command_name, repo_root, "Feed generation transition stopped before runtime changes because deployment pinning failed.", findings, [str(runtime_dir(repo_root))])
            findings.append(
                finding(
                    "pass",
                    "feed-generation.app-images",
                    "Prepared application image and runtime artifact identities were verified before feed runtime changes.",
                    details={"image_ids": app_image_ids, "runtime_artifacts": app_runtime_artifacts},
                )
            )
            if current_id == generation_id and state_before is not None and not repair_attestation:
                if running_services:
                    findings.append(finding("pass", "feed-generation.noop", "Requested feed generation is already active and its pinned application services are running.", details={"generation_id": generation_id, "running_services": running_services}))
                    return make_result(command_name, repo_root, "Requested feed generation is already active.", findings, [str(generations_root / generation_id)])
                runtime_result = restart_and_verify_feed_app_services(
                    repo_root,
                    app_env=restore_app_env,
                    app_image_ids=app_image_ids,
                    app_runtime_artifacts=app_runtime_artifacts,
                    app_compose_contract=app_compose_contract,
                )
                findings.append(
                    feed_import_summary_finding(
                        runtime_result, "feed-generation.noop-runtime-verify"
                    )
                )
                return make_result(
                    command_name,
                    repo_root,
                    "Active feed generation runtime recovered without re-import."
                    if runtime_result.get("status") == "pass"
                    else "Active feed generation is durable, but application runtime recovery failed.",
                    findings,
                    [str(generations_root / generation_id)],
                )
            initial_scan_quiescence = feed_activation_scan_quiescence_finding(repo_root)
            findings.append(initial_scan_quiescence)
            if initial_scan_quiescence["status"] != "pass":
                return make_result(
                    command_name,
                    repo_root,
                    "Feed generation transition stopped before service changes because scan quiescence was not proven.",
                    findings,
                    [str(generations_root / generation_id)],
                )

            known_previous_id = state.get("previous_generation_id") if interrupted else current_id
            success_rollback_id = (
                prior_rollback_id if interrupted or repair_attestation else current_id
            )

            control_quiesce = stop_feed_control_services_for_preflight(repo_root)
            findings.append(control_quiesce)
            previous_control_services = control_quiesce.get("details", {}).get(
                "previously_running_services", []
            )
            if control_quiesce["status"] != "pass":
                findings.append(
                    restart_feed_control_services_after_preflight(
                        repo_root, previous_control_services
                    )
                )
                return make_result(
                    command_name,
                    repo_root,
                    "Feed generation transition stopped because scanner-control services could not be quiesced.",
                    findings,
                    [str(runtime_dir(repo_root))],
                )

            stable_scan_quiescence = feed_activation_scan_quiescence_finding(repo_root)
            findings.append(stable_scan_quiescence)
            if stable_scan_quiescence["status"] != "pass":
                findings.append(
                    restart_feed_control_services_after_preflight(
                        repo_root, previous_control_services
                    )
                )
                return make_result(
                    command_name,
                    repo_root,
                    "Feed generation transition stopped because scan quiescence changed before the scanner-control boundary closed.",
                    findings,
                    [str(generations_root / generation_id)],
                )

            if not interrupted:
                try:
                    write_feed_activation_state(
                        repo_root,
                        {
                            "status": "transitioning",
                            "action": action,
                            "target_generation_id": generation_id,
                            "previous_generation_id": current_id,
                            "rollback_generation_id": prior_rollback_id,
                            "restore_gsad_hosts": restore_gsad_hosts,
                            "app_image_ids": app_image_ids,
                            "app_runtime_artifacts": app_runtime_artifacts,
                            "app_compose_contract": app_compose_contract,
                            "current_generation_id": None,
                            "started_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                        },
                    )
                except (OSError, ValueError) as error:
                    findings.append(finding("fail", "feed-generation.journal", f"Could not record the transition journal before changing runtime state: {error}", str(feed_activation_state_path(repo_root))))
                    return make_result(
                        command_name,
                        repo_root,
                        "Feed generation transition stopped before selector changes; scanner-control services remain stopped because journal durability is uncertain.",
                        findings,
                        [str(feed_activation_state_path(repo_root))],
                    )
                findings.append(finding("pass", "feed-generation.journal", "Durable transition journal was recorded before service or selector changes.", str(feed_activation_state_path(repo_root))))
                transition_phase(
                    "transition-journal-recorded",
                    {"generation_id": generation_id},
                )

            stopped = stop_app_services_for_feed_transition(repo_root, "feed-generation.stop-app")
            findings.append(stopped)
            if stopped["status"] == "fail":
                return make_result(command_name, repo_root, "Feed generation transition stopped before changing the selector.", findings, [str(generations_root / generation_id)])

            try:
                selected = select_generation(runtime_root, generation_id, FEED_RELEASE, specs)
            except (FeedGenerationError, OSError) as error:
                findings.append(finding("fail", "feed-generation.select", f"Atomic feed generation selection failed closed: {error}", str(runtime_root / "feed-store" / "current")))
                try:
                    observed = read_current_generation(runtime_root, FEED_RELEASE, specs)
                except (FeedGenerationError, OSError) as selector_error:
                    findings.append(finding("fail", "feed-generation.select-state", f"Selector state is uncertain after failed selection: {selector_error}"))
                    return make_result(command_name, repo_root, "Feed generation selection failed with uncertain selector state; app services remain stopped for manual recovery.", findings, [str(runtime_root / "feed-store")])
                observed_id = observed.get("generation_id") if observed else None
                if observed_id != current_id:
                    findings.append(finding("fail", "feed-generation.select-state", "Failed selection did not retain the prior selector; app services remain stopped for manual recovery.", details={"expected": current_id, "observed": observed_id}))
                    return make_result(command_name, repo_root, "Feed generation selection failed without a verified prior selector; manual recovery is required.", findings, [str(runtime_root / "feed-store")])
                findings.append(finding("pass", "feed-generation.select-state", "Failed selection retained the verified prior selector.", details={"generation_id": observed_id}))
                if interrupted:
                    return make_result(command_name, repo_root, "Interrupted feed recovery could not select its target; app services remain stopped.", findings, [str(feed_activation_state_path(repo_root))])
                if state_before is None:
                    return make_result(
                        command_name,
                        repo_root,
                        "First feed generation selection failed; no active generation exists and app services remain removed.",
                        findings,
                        [str(runtime_root / "feed-store")],
                    )
                if not database_attestation_matches_current:
                    findings.append(
                        finding(
                            "fail",
                            "feed-generation.select-repair-state",
                            "Selection failed before database attestation repair; application services remain stopped because the prior database import is not attested.",
                            details={"generation_id": current_id},
                        )
                    )
                    return make_result(
                        command_name,
                        repo_root,
                        "Feed generation attestation repair failed before import; application services remain stopped.",
                        findings,
                        [str(feed_activation_state_path(repo_root))],
                    )
                try:
                    restored_state = {
                        key: value
                        for key, value in state_before.items()
                        if key != "schema_version"
                    }
                    restored_state["app_image_ids"] = app_image_ids
                    restored_state["app_runtime_artifacts"] = app_runtime_artifacts
                    restored_state["app_compose_contract"] = app_compose_contract
                    write_feed_activation_state(repo_root, restored_state)
                except (OSError, ValueError) as journal_error:
                    findings.append(
                        finding(
                            "fail",
                            "feed-generation.journal-restore",
                            f"Prior selector was retained but its active journal could not be restored: {journal_error}",
                            str(feed_activation_state_path(repo_root)),
                        )
                    )
                    return make_result(
                        command_name,
                        repo_root,
                        "Feed generation selection failed and the prior activation journal could not be restored; app services remain removed.",
                        findings,
                        [str(feed_activation_state_path(repo_root))],
                    )
                runtime_result = restart_and_verify_feed_app_services(
                    repo_root,
                    app_env=restore_app_env,
                    app_image_ids=app_image_ids,
                    app_runtime_artifacts=app_runtime_artifacts,
                    app_compose_contract=app_compose_contract,
                )
                findings.append(
                    feed_import_summary_finding(
                        runtime_result, "feed-generation.restart-unchanged"
                    )
                )
                return make_result(command_name, repo_root, "Feed generation transition failed before import; the prior selector was verified and retained.", findings, [str(generations_root / generation_id)])
            findings.append(finding("pass", "feed-generation.select", "Active feed selector changed atomically to the verified generation.", str(runtime_root / "feed-store" / "current"), selected))
            transition_phase(
                "selector-selected", {"generation_id": generation_id}
            )

            imported = command_runtime_feed_import_init(
                repo_root,
                activation_managed=True,
                restart_services=False,
                app_image_ids=app_image_ids,
            )
            findings.append(feed_import_summary_finding(imported, "feed-generation.import"))
            transition_phase(
                "target-import-returned",
                {"generation_id": generation_id, "status": imported.get("status")},
            )
            artifact_post_import = app_runtime_artifact_finding(
                repo_root,
                app_runtime_artifacts,
                check="feed-generation.app-artifacts-after-import",
            )
            findings.append(artifact_post_import)
            if artifact_post_import["status"] != "pass":
                findings.append(stop_app_services_for_feed_transition(repo_root, "feed-generation.artifact-change-stop"))
                return make_result(command_name, repo_root, "Feed generation transition requires manual recovery because runtime artifacts changed during import.", findings, [str(feed_activation_state_path(repo_root))])
            transition_succeeded = imported.get("status") == "pass"
            if imported.get("status") == "pass":
                try:
                    active = read_current_generation(runtime_root, FEED_RELEASE, specs)
                except (FeedGenerationError, OSError) as error:
                    findings.append(finding("fail", "feed-generation.post-verify", f"Active generation verification failed after import: {error}"))
                    transition_succeeded = False
                else:
                    active_ok = active is not None and active.get("generation_id") == generation_id
                    findings.append(finding("pass" if active_ok else "fail", "feed-generation.post-verify", "Active generation and imported runtime agree." if active_ok else "Active generation changed after import.", details={"expected": generation_id, "observed": active.get("generation_id") if active else None}))
                    transition_succeeded = active_ok
            completed_at: str | None = None
            if transition_succeeded:
                completed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
                try:
                    database_attestation = write_feed_generation_db_attestation(
                        repo_root, generation_id, completed_at
                    )
                except (OSError, ValueError) as error:
                    findings.append(
                        finding(
                            "fail",
                            "feed-generation.database-attestation",
                            f"Feed imports completed but database attestation failed closed: {error}",
                            details={"generation_id": generation_id},
                        )
                    )
                    transition_succeeded = False
                else:
                    findings.append(
                        finding(
                            "pass",
                            "feed-generation.database-attestation",
                            "Database import attestation matches the selected immutable generation.",
                            details=database_attestation,
                        )
                    )
                    transition_phase(
                        "database-attested", {"generation_id": generation_id}
                    )
            if transition_succeeded:
                try:
                    write_feed_activation_state(
                        repo_root,
                        {
                            "status": "active",
                            "current_generation_id": generation_id,
                            "target_generation_id": None,
                            "previous_generation_id": None,
                            "rollback_generation_id": success_rollback_id,
                            "restore_gsad_hosts": restore_gsad_hosts,
                            "app_image_ids": app_image_ids,
                            "app_runtime_artifacts": app_runtime_artifacts,
                            "app_compose_contract": app_compose_contract,
                            "completed_at": completed_at,
                        },
                    )
                except (OSError, ValueError) as error:
                    findings.append(finding("fail", "feed-generation.journal-complete", f"Feed import completed but durable activation completion could not be recorded: {error}", str(feed_activation_state_path(repo_root))))
                    transition_succeeded = False
                else:
                    findings.append(finding("pass", "feed-generation.journal-complete", "Durable activation journal matches the verified selector and completed import.", str(feed_activation_state_path(repo_root))))
                    transition_phase(
                        "activation-journal-completed",
                        {"generation_id": generation_id},
                    )
            if transition_succeeded:
                runtime_result = restart_and_verify_feed_app_services(
                    repo_root,
                    app_env=restore_app_env,
                    app_image_ids=app_image_ids,
                    app_runtime_artifacts=app_runtime_artifacts,
                    app_compose_contract=app_compose_contract,
                )
                findings.append(feed_import_summary_finding(runtime_result, "feed-generation.runtime-verify"))
                summary = "Feed generation activation and import completed." if not rollback else "Feed generation rollback and compensating import completed."
                if runtime_result.get("status") == "fail":
                    summary = "Feed generation activation is durable, but app restart or runtime verification failed."
                return make_result(command_name, repo_root, summary, findings, [str(generations_root / generation_id), *imported.get("artifacts", [])])

            compensation_stop = stop_app_services_for_feed_transition(repo_root, "feed-generation.compensation-stop")
            findings.append(compensation_stop)
            if compensation_stop["status"] == "fail":
                findings.append(finding("fail", "feed-generation.manual-recovery", "Could not stop app services before compensation; selector and database state require manual recovery.", details={"prior_generation_id": current_id, "failed_generation_id": generation_id}))
                return make_result(command_name, repo_root, "Feed generation transition failed and compensation could not start safely.", findings, [str(runtime_root / "feed-store")])
            if recovery_only:
                findings.append(finding("fail", "feed-generation.manual-recovery", "Recovery import failed; no further automatic selector transition is safe.", details={"recovery_generation_id": generation_id}))
                return make_result(command_name, repo_root, "Interrupted feed recovery failed and requires manual recovery.", findings, [str(feed_activation_state_path(repo_root))])
            if known_previous_id is None:
                try:
                    clear_current_generation(runtime_root, generation_id)
                except (FeedGenerationError, OSError) as error:
                    findings.append(finding("fail", "feed-generation.compensation-clear", f"Failed to clear the first-activation selector after import failure: {error}"))
                else:
                    findings.append(finding("pass", "feed-generation.compensation-clear", "Cleared failed first-activation selector; app services remain stopped for manual recovery."))
                return make_result(command_name, repo_root, "First feed activation failed; no database rollback is claimed and app services remain stopped.", findings, [str(runtime_root / "feed-store")])

            try:
                restored = select_generation(runtime_root, known_previous_id, FEED_RELEASE, specs)
            except (FeedGenerationError, OSError) as error:
                findings.append(finding("fail", "feed-generation.compensation-select", f"Failed to restore the prior selector: {error}", details={"prior_generation_id": known_previous_id, "failed_generation_id": generation_id}))
                return make_result(command_name, repo_root, "Feed activation and selector compensation failed; manual recovery is required.", findings, [str(runtime_root / "feed-store")])
            findings.append(finding("pass", "feed-generation.compensation-select", "Prior verified feed generation selector was restored.", details=restored))
            transition_phase(
                "compensation-selector-selected",
                {"generation_id": known_previous_id},
            )
            compensated = command_runtime_feed_import_init(
                repo_root,
                activation_managed=True,
                restart_services=False,
                app_image_ids=app_image_ids,
            )
            findings.append(feed_import_summary_finding(compensated, "feed-generation.compensation-import"))
            transition_phase(
                "compensation-import-returned",
                {
                    "generation_id": known_previous_id,
                    "status": compensated.get("status"),
                },
            )
            if compensated.get("status") == "pass":
                compensation_artifacts = app_runtime_artifact_finding(
                    repo_root,
                    app_runtime_artifacts,
                    check="feed-generation.app-artifacts-after-compensation",
                )
                findings.append(compensation_artifacts)
                if compensation_artifacts["status"] != "pass":
                    findings.append(stop_app_services_for_feed_transition(repo_root, "feed-generation.compensation-artifact-stop"))
                    return make_result(command_name, repo_root, "Compensating import completed, but changed runtime artifacts require manual recovery.", findings, [str(feed_activation_state_path(repo_root))])
                try:
                    compensated_active = read_current_generation(
                        runtime_root, FEED_RELEASE, specs
                    )
                except (FeedGenerationError, OSError) as error:
                    findings.append(finding("fail", "feed-generation.compensation-post-verify", f"Compensating selector verification failed: {error}"))
                    return make_result(command_name, repo_root, "Compensating import completed but selector verification failed; app startup remains blocked.", findings, [str(feed_activation_state_path(repo_root))])
                compensated_active_id = (
                    compensated_active.get("generation_id") if compensated_active else None
                )
                if compensated_active_id != known_previous_id:
                    findings.append(finding("fail", "feed-generation.compensation-post-verify", "Compensating import no longer matches the restored selector.", details={"expected": known_previous_id, "observed": compensated_active_id}))
                    return make_result(command_name, repo_root, "Compensating import completed against an uncertain selector; app startup remains blocked.", findings, [str(feed_activation_state_path(repo_root))])
                compensation_completed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
                try:
                    compensation_attestation = write_feed_generation_db_attestation(
                        repo_root, known_previous_id, compensation_completed_at
                    )
                except (OSError, ValueError) as error:
                    findings.append(finding("fail", "feed-generation.compensation-database-attestation", f"Compensating import database attestation failed closed: {error}"))
                    return make_result(command_name, repo_root, "Compensating import completed but database attestation is unavailable; app startup remains blocked.", findings, [str(feed_activation_state_path(repo_root))])
                findings.append(finding("pass", "feed-generation.compensation-database-attestation", "Database import attestation matches the restored immutable generation.", details=compensation_attestation))
                transition_phase(
                    "compensation-database-attested",
                    {"generation_id": known_previous_id},
                )
                try:
                    write_feed_activation_state(
                        repo_root,
                        {
                            "status": "active",
                            "current_generation_id": known_previous_id,
                            "target_generation_id": None,
                            "previous_generation_id": None,
                            "rollback_generation_id": prior_rollback_id,
                            "restore_gsad_hosts": restore_gsad_hosts,
                            "app_image_ids": app_image_ids,
                            "app_runtime_artifacts": app_runtime_artifacts,
                            "app_compose_contract": app_compose_contract,
                            "completed_at": compensation_completed_at,
                        },
                    )
                except (OSError, ValueError) as error:
                    findings.append(finding("fail", "feed-generation.compensation-journal", f"Prior generation was reimported but its completed activation state could not be recorded: {error}"))
                    return make_result(command_name, repo_root, "Compensating import completed but durable recovery state is unavailable; app startup remains blocked.", findings, [str(feed_activation_state_path(repo_root))])
                transition_phase(
                    "compensation-journal-completed",
                    {"generation_id": known_previous_id},
                )
                runtime_result = restart_and_verify_feed_app_services(
                    repo_root,
                    app_env=restore_app_env,
                    app_image_ids=app_image_ids,
                    app_runtime_artifacts=app_runtime_artifacts,
                    app_compose_contract=app_compose_contract,
                )
                findings.append(feed_import_summary_finding(runtime_result, "feed-generation.compensation-runtime-verify"))
                findings.append(finding("warn", "feed-generation.compensation", "Target activation failed; the prior generation was reselected and reimported. This is compensating recovery, not a transactional database rollback.", details={"restored_generation_id": known_previous_id, "failed_generation_id": generation_id}))
                return make_result(command_name, repo_root, "Feed generation transition failed, but compensating recovery restored and reimported the prior generation.", findings, [str(generations_root / known_previous_id), *compensated.get("artifacts", [])])
            findings.append(finding("fail", "feed-generation.manual-recovery", "Target activation and compensating reimport both failed; manual recovery is required.", details={"restored_generation_id": known_previous_id, "failed_generation_id": generation_id}))
            return make_result(command_name, repo_root, "Feed generation transition and compensating recovery failed.", findings, [str(runtime_root / "feed-store"), *compensated.get("artifacts", [])])
    except RuntimeLockTimeout as error:
        findings.append(runtime_lock_timeout_finding(error, "feed-generation.activation-lock"))
        return make_result(command_name, repo_root, "Feed generation transition stopped while waiting for the activation lock.", findings, [str(runtime_lock_dir(repo_root))])
