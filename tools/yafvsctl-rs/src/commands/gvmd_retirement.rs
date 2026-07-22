// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::metadata;
use crate::process::SystemCommandRunner;
use crate::result::{Finding, ResultEnvelope, make_result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

const COMMAND: &str = "gvmd-retirement-state";
const REGISTRY_PATH: &str = "policy/gvmd-retirement.toml";
const TARGET_OWNERS: [&str; 5] = [
    "api",
    "manager-worker",
    "scanner",
    "feed-intelligence",
    "delete",
];
const WORK_STATUSES: [&str; 5] = [
    "inventoried",
    "characterized",
    "migrating",
    "native-owned",
    "retired",
];
const CALLER_KINDS: [&str; 4] = ["product", "runtime", "tooling", "characterization"];
const EXIT_STATUSES: [&str; 2] = ["open", "verified"];
const REQUIRED_EXIT_CRITERIA: [&str; 6] = [
    "zero-required-gmp-calls",
    "zero-gvmd-database-writes",
    "no-gvmd-runtime-process",
    "native-schema-and-semantics-ownership",
    "lifecycle-behavior-proven",
    "gvmd-gmp-source-and-wiring-deleted",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Program {
    baseline_head: String,
    progress_percent: u8,
    next_update_percent: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExitCriterion {
    id: String,
    status: String,
    evidence: Vec<String>,
    notes: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Responsibility {
    id: String,
    target_owner: String,
    status: String,
    weight: u32,
    evidence: Vec<String>,
    independent_authority: Vec<String>,
    dependencies: Vec<String>,
    notes: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Caller {
    id: String,
    kind: String,
    status: String,
    evidence: Vec<String>,
    replacement: Vec<String>,
    notes: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema_version: u8,
    program: Program,
    exit_criteria: Vec<ExitCriterion>,
    responsibilities: Vec<Responsibility>,
    callers: Vec<Caller>,
}

#[derive(Debug, Serialize)]
struct Counts {
    by_owner: BTreeMap<String, usize>,
    responsibilities_by_status: BTreeMap<String, usize>,
    callers_by_kind: BTreeMap<String, usize>,
    callers_by_status: BTreeMap<String, usize>,
    exit_criteria_by_status: BTreeMap<String, usize>,
}

pub fn command_gvmd_retirement_state(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    let source = match read_safe_repository_text(repo_root, Path::new(REGISTRY_PATH)) {
        Ok(source) => source,
        Err(error) => {
            return make_result(
                metadata(repo_root, COMMAND, &SystemCommandRunner),
                "gvmd/GMP retirement registry could not be read.".to_string(),
                vec![
                    Finding::new(
                        "fail",
                        "gvmd-retirement.registry-read",
                        format!("{REGISTRY_PATH} could not be read: {error}"),
                    )
                    .with_path(REGISTRY_PATH),
                ],
            );
        }
    };
    let registry = match toml::from_str::<Registry>(&source) {
        Ok(registry) => registry,
        Err(error) => {
            return make_result(
                metadata(repo_root, COMMAND, &SystemCommandRunner),
                "gvmd/GMP retirement registry could not be parsed.".to_string(),
                vec![
                    Finding::new(
                        "fail",
                        "gvmd-retirement.registry-parse",
                        format!(
                            "{REGISTRY_PATH} is invalid TOML or has an invalid schema: {error}"
                        ),
                    )
                    .with_path(REGISTRY_PATH),
                ],
            );
        }
    };

    let mut findings = validate_registry(repo_root, &registry);
    if findings.is_empty() {
        findings.push(Finding::new(
            "pass",
            "gvmd-retirement.registry",
            "The machine-readable gvmd/GMP retirement registry is internally consistent."
                .to_string(),
        ));
    }
    let counts = registry_counts(&registry);
    let total_weight = registry
        .responsibilities
        .iter()
        .map(|row| row.weight)
        .sum::<u32>();
    let full_details = json!({
        "schema_version": registry.schema_version,
        "program": registry.program,
        "counts": counts,
        "total_responsibility_weight": total_weight,
        "exit_criteria": registry.exit_criteria,
        "responsibilities": registry.responsibilities,
        "callers": registry.callers,
    });
    let mut result = make_result(
        metadata(repo_root, COMMAND, &SystemCommandRunner),
        "gvmd/GMP responsibility and caller retirement state collected.".to_string(),
        findings,
    )
    .with_details(full_details);
    if status_only {
        compact_status_only(&mut result, &registry, &counts, total_weight);
    }
    result
}

fn validate_registry(repo_root: &Path, registry: &Registry) -> Vec<Finding> {
    let mut findings = Vec::new();
    if registry.schema_version != 1 {
        findings.push(fail(
            "gvmd-retirement.schema-version",
            "schema_version must be 1".to_string(),
        ));
    }
    validate_program(&registry.program, &registry.exit_criteria, &mut findings);

    let responsibility_ids = registry
        .responsibilities
        .iter()
        .map(|row| row.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut all_ids = BTreeSet::new();
    for row in &registry.responsibilities {
        validate_unique_id(&row.id, "responsibility", &mut all_ids, &mut findings);
        if !TARGET_OWNERS.contains(&row.target_owner.as_str()) {
            findings.push(fail(
                "gvmd-retirement.responsibility-owner",
                format!("{} has invalid target_owner {}", row.id, row.target_owner),
            ));
        }
        if !WORK_STATUSES.contains(&row.status.as_str()) {
            findings.push(fail(
                "gvmd-retirement.responsibility-status",
                format!("{} has invalid status {}", row.id, row.status),
            ));
        }
        if row.weight == 0 {
            findings.push(fail(
                "gvmd-retirement.responsibility-weight",
                format!("{} must have a positive weight", row.id),
            ));
        }
        validate_text(&row.id, &row.notes, "notes", &mut findings);
        validate_evidence(
            repo_root,
            &row.id,
            "evidence",
            &row.evidence,
            true,
            &mut findings,
        );
        validate_evidence(
            repo_root,
            &row.id,
            "independent_authority",
            &row.independent_authority,
            true,
            &mut findings,
        );
        for dependency in &row.dependencies {
            if dependency == &row.id || !responsibility_ids.contains(dependency.as_str()) {
                findings.push(fail(
                    "gvmd-retirement.responsibility-dependency",
                    format!("{} has invalid dependency {}", row.id, dependency),
                ));
            }
        }
    }

    for caller in &registry.callers {
        validate_unique_id(&caller.id, "caller", &mut all_ids, &mut findings);
        if !CALLER_KINDS.contains(&caller.kind.as_str()) {
            findings.push(fail(
                "gvmd-retirement.caller-kind",
                format!("{} has invalid kind {}", caller.id, caller.kind),
            ));
        }
        if !WORK_STATUSES.contains(&caller.status.as_str()) {
            findings.push(fail(
                "gvmd-retirement.caller-status",
                format!("{} has invalid status {}", caller.id, caller.status),
            ));
        }
        validate_text(&caller.id, &caller.notes, "notes", &mut findings);
        validate_evidence(
            repo_root,
            &caller.id,
            "evidence",
            &caller.evidence,
            true,
            &mut findings,
        );
        for replacement in &caller.replacement {
            if !responsibility_ids.contains(replacement.as_str()) {
                findings.push(fail(
                    "gvmd-retirement.caller-replacement",
                    format!(
                        "{} references unknown replacement {}",
                        caller.id, replacement
                    ),
                ));
            }
        }
    }
    for criterion in &registry.exit_criteria {
        validate_unique_id(&criterion.id, "exit criterion", &mut all_ids, &mut findings);
        if !EXIT_STATUSES.contains(&criterion.status.as_str()) {
            findings.push(fail(
                "gvmd-retirement.exit-status",
                format!("{} has invalid status {}", criterion.id, criterion.status),
            ));
        }
        validate_text(&criterion.id, &criterion.notes, "notes", &mut findings);
        validate_evidence(
            repo_root,
            &criterion.id,
            "evidence",
            &criterion.evidence,
            criterion.status == "verified",
            &mut findings,
        );
    }
    if registry.program.progress_percent == 100 {
        let incomplete_responsibilities = registry
            .responsibilities
            .iter()
            .filter(|row| {
                (row.target_owner == "delete" && row.status != "retired")
                    || (row.target_owner != "delete" && row.status != "native-owned")
            })
            .map(|row| row.id.clone())
            .collect::<Vec<_>>();
        let incomplete_callers = registry
            .callers
            .iter()
            .filter(|row| row.status != "retired")
            .map(|row| row.id.clone())
            .collect::<Vec<_>>();
        if !incomplete_responsibilities.is_empty() || !incomplete_callers.is_empty() {
            findings.push(
                fail(
                    "gvmd-retirement.program-completion",
                    "100% progress requires native ownership or retirement of every responsibility and retirement of every caller".to_string(),
                )
                .with_details(json!({
                    "incomplete_responsibilities": incomplete_responsibilities,
                    "incomplete_callers": incomplete_callers,
                })),
            );
        }
    }
    findings
}

fn validate_program(
    program: &Program,
    exit_criteria: &[ExitCriterion],
    findings: &mut Vec<Finding>,
) {
    if program.baseline_head.trim().is_empty() {
        findings.push(fail(
            "gvmd-retirement.program-baseline",
            "program baseline_head must not be empty".to_string(),
        ));
    }
    if program.progress_percent > 100
        || !program.progress_percent.is_multiple_of(5)
        || program.next_update_percent > 100
        || (program.progress_percent < 100
            && program.next_update_percent != program.progress_percent + 5)
        || (program.progress_percent == 100 && program.next_update_percent != 100)
    {
        findings.push(fail(
            "gvmd-retirement.program-progress",
            "progress must use five-point checkpoints and name the next checkpoint".to_string(),
        ));
    }
    let observed = exit_criteria
        .iter()
        .map(|criterion| criterion.id.as_str())
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_EXIT_CRITERIA {
        if !observed.contains(required) {
            findings.push(fail(
                "gvmd-retirement.required-exit-criterion",
                format!("required exit criterion {required} is missing"),
            ));
        }
    }
    if program.progress_percent == 100
        && exit_criteria
            .iter()
            .any(|criterion| criterion.status != "verified")
    {
        findings.push(fail(
            "gvmd-retirement.program-completion",
            "100% progress requires every exit criterion to be verified".to_string(),
        ));
    }
}

fn validate_unique_id(
    id: &str,
    row_type: &str,
    ids: &mut BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    if !is_kebab_case(id) || !ids.insert(id.to_string()) {
        findings.push(fail(
            "gvmd-retirement.unique-id",
            format!("{row_type} ID is empty, duplicated, or not kebab-case: {id}"),
        ));
    }
}

fn is_kebab_case(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_text(id: &str, value: &str, field: &str, findings: &mut Vec<Finding>) {
    if value.trim().is_empty() {
        findings.push(fail(
            "gvmd-retirement.required-text",
            format!("{id} has an empty {field}"),
        ));
    }
}

fn validate_evidence(
    repo_root: &Path,
    id: &str,
    field: &str,
    evidence: &[String],
    required: bool,
    findings: &mut Vec<Finding>,
) {
    if required && evidence.is_empty() {
        findings.push(fail(
            "gvmd-retirement.evidence-required",
            format!("{id} requires at least one {field} anchor"),
        ));
    }
    for item in evidence {
        if let Err(message) = validate_evidence_anchor(repo_root, item) {
            findings.push(fail(
                "gvmd-retirement.evidence-anchor",
                format!("{id} {field} {item}: {message}"),
            ));
        }
    }
}

fn validate_evidence_anchor(repo_root: &Path, item: &str) -> Result<(), String> {
    let (relative, anchor) = item
        .split_once("::")
        .ok_or_else(|| "must use path::literal-anchor syntax".to_string())?;
    let relative = Path::new(relative);
    if anchor.is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("path or literal anchor is empty or unsafe".to_string());
    }
    let contents = read_safe_repository_text(repo_root, relative)?;
    if !contents.contains(anchor) {
        return Err("literal anchor is absent".to_string());
    }
    Ok(())
}

fn read_safe_repository_text(repo_root: &Path, relative: &Path) -> Result<String, String> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("path is empty, absolute, or contains unsafe components".to_string());
    }
    let candidate = repo_root.join(relative);
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|error| format!("file cannot be inspected: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("path is not a regular non-symlink file".to_string());
    }
    let canonical_root = repo_root
        .canonicalize()
        .map_err(|error| format!("repository root cannot be resolved: {error}"))?;
    let canonical_candidate = candidate
        .canonicalize()
        .map_err(|error| format!("file cannot be resolved: {error}"))?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err("path resolves outside the repository".to_string());
    }
    fs::read_to_string(&candidate)
        .map_err(|error| format!("file is not readable UTF-8 text: {error}"))
}

fn registry_counts(registry: &Registry) -> Counts {
    Counts {
        by_owner: count_values(
            registry
                .responsibilities
                .iter()
                .map(|row| row.target_owner.as_str()),
        ),
        responsibilities_by_status: count_values(
            registry
                .responsibilities
                .iter()
                .map(|row| row.status.as_str()),
        ),
        callers_by_kind: count_values(registry.callers.iter().map(|row| row.kind.as_str())),
        callers_by_status: count_values(registry.callers.iter().map(|row| row.status.as_str())),
        exit_criteria_by_status: count_values(
            registry.exit_criteria.iter().map(|row| row.status.as_str()),
        ),
    }
}

fn count_values<'a>(values: impl Iterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.to_string()).or_insert(0) += 1;
    }
    counts
}

fn compact_status_only(
    result: &mut ResultEnvelope,
    registry: &Registry,
    counts: &Counts,
    total_weight: u32,
) {
    let finding_count = result.findings.len();
    let non_pass_count = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .count();
    result.findings.retain(|finding| finding.status != "pass");
    result.findings.truncate(20);
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            "gvmd-retirement.status-only",
            "Retirement registry is valid; detailed rows are suppressed.".to_string(),
        ));
    }
    result.details = Some(json!({
        "schema_version": registry.schema_version,
        "program": registry.program,
        "counts": counts,
        "total_responsibility_weight": total_weight,
        "finding_count": finding_count,
        "non_pass_count": non_pass_count,
        "returned_non_pass_count": non_pass_count.min(20),
        "truncated_count": non_pass_count.saturating_sub(20),
    }));
}

fn fail(check: &str, message: String) -> Finding {
    Finding::new("fail", check, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must follow Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "yafvs-gvmd-retirement-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("temporary root must be created");
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn valid_registry(root: &Path) {
        fs::create_dir(root.join("policy")).unwrap();
        fs::write(root.join("proof.txt"), "literal-anchor\n").unwrap();
        let mut source = String::from(
            r#"schema_version = 1
[program]
baseline_head = "abc123"
progress_percent = 5
next_update_percent = 10
"#,
        );
        for id in REQUIRED_EXIT_CRITERIA {
            source.push_str(&format!(
                r#"
[[exit_criteria]]
id = "{id}"
status = "open"
evidence = []
notes = "Not proven yet."
"#
            ));
        }
        source.push_str(
            r#"
[[responsibilities]]
id = "one-responsibility"
target_owner = "api"
status = "inventoried"
weight = 1
evidence = ["proof.txt::literal-anchor"]
independent_authority = ["proof.txt::literal-anchor"]
dependencies = []
notes = "A bounded responsibility."

[[callers]]
id = "one-caller"
kind = "characterization"
status = "characterized"
evidence = ["proof.txt::literal-anchor"]
replacement = ["one-responsibility"]
notes = "A bounded caller."
"#,
        );
        fs::write(root.join(REGISTRY_PATH), source).unwrap();
    }

    #[test]
    fn valid_registry_passes() {
        let root = TempRoot::new();
        valid_registry(&root.0);
        let result = command_gvmd_retirement_state(&root.0, false);
        assert_eq!(result.status, "pass");
        assert_eq!(
            result.details.as_ref().unwrap()["responsibilities"][0]["id"],
            "one-responsibility"
        );
    }

    #[test]
    fn duplicate_ids_fail() {
        let root = TempRoot::new();
        valid_registry(&root.0);
        let path = root.0.join(REGISTRY_PATH);
        let source = fs::read_to_string(&path)
            .unwrap()
            .replace("id = \"one-caller\"", "id = \"one-responsibility\"");
        fs::write(path, source).unwrap();
        assert_eq!(command_gvmd_retirement_state(&root.0, false).status, "fail");
    }

    #[test]
    fn invalid_owner_and_status_fail() {
        let root = TempRoot::new();
        valid_registry(&root.0);
        let path = root.0.join(REGISTRY_PATH);
        let source = fs::read_to_string(&path)
            .unwrap()
            .replace("target_owner = \"api\"", "target_owner = \"monolith\"")
            .replace("status = \"inventoried\"", "status = \"unknown\"");
        fs::write(path, source).unwrap();
        let result = command_gvmd_retirement_state(&root.0, false);
        assert_eq!(result.status, "fail");
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "gvmd-retirement.responsibility-owner")
        );
    }

    #[test]
    fn missing_path_or_anchor_fails() {
        let root = TempRoot::new();
        valid_registry(&root.0);
        let path = root.0.join(REGISTRY_PATH);
        let source = fs::read_to_string(&path)
            .unwrap()
            .replace("proof.txt::literal-anchor", "missing.txt::absent");
        fs::write(path, source).unwrap();
        assert_eq!(command_gvmd_retirement_state(&root.0, false).status, "fail");
    }

    #[test]
    fn parent_directory_evidence_is_rejected() {
        let root = TempRoot::new();
        valid_registry(&root.0);
        let path = root.0.join(REGISTRY_PATH);
        let source = fs::read_to_string(&path)
            .unwrap()
            .replace("proof.txt::literal-anchor", "../proof.txt::literal-anchor");
        fs::write(path, source).unwrap();
        assert_eq!(command_gvmd_retirement_state(&root.0, false).status, "fail");
    }

    #[test]
    fn status_only_suppresses_registry_rows() {
        let root = TempRoot::new();
        valid_registry(&root.0);
        let result = command_gvmd_retirement_state(&root.0, true);
        let details = result.details.unwrap();
        assert_eq!(result.status, "pass");
        assert_eq!(result.findings.len(), 1);
        assert!(details.get("responsibilities").is_none());
        assert_eq!(details["program"]["progress_percent"], 5);
        assert_eq!(details["truncated_count"], 0);
    }

    #[test]
    fn legacy_appliance_licensing_surface_is_absent() {
        const GSA_GMP: &str = include_str!("../../../../components/gsa/src/gmp/gmp.ts");
        const GSAD_GMP: &str = include_str!("../../../../components/gsad/src/gsad_gmp.c");
        const GSAD_HEADER: &str = include_str!("../../../../components/gsad/src/gsad_gmp.h");
        const GSAD_VALIDATOR: &str =
            include_str!("../../../../components/gsad/src/gsad_validator.c");
        const GVMD_GMP: &str = include_str!("../../../../components/gvmd/src/gmp.c");
        const GVMD_COMMANDS: &str =
            include_str!("../../../../components/gvmd/src/manage_commands.c");
        const GVMD_CMAKE: &str = include_str!("../../../../components/gvmd/src/CMakeLists.txt");
        const GVMD_SCHEMA: &str =
            include_str!("../../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");

        for (source, retired) in [
            (GSA_GMP, "gmp/commands/license"),
            (GSAD_GMP, "get_license_gmp"),
            (GSAD_GMP, "save_license_gmp"),
            (GSAD_HEADER, "get_license_gmp"),
            (GSAD_HEADER, "save_license_gmp"),
            (GSAD_VALIDATOR, "|(get_license)"),
            (GSAD_VALIDATOR, "|(save_license)"),
            (GVMD_GMP, "CLIENT_GET_LICENSE"),
            (GVMD_GMP, "CLIENT_MODIFY_LICENSE"),
            (GVMD_COMMANDS, "{\"GET_LICENSE\","),
            (GVMD_COMMANDS, "{\"MODIFY_LICENSE\","),
            (GVMD_CMAKE, "WITH_LIBTHEIA"),
            (GVMD_CMAKE, "OPT_THEIA_TGT"),
            (GVMD_SCHEMA, "<name>get_license</name>"),
            (GVMD_SCHEMA, "<name>modify_license</name>"),
        ] {
            assert!(
                !source.contains(retired),
                "retired appliance-licensing marker remains: {retired}"
            );
        }

        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for retired_path in [
            "components/gsa/src/gmp/commands/license.js",
            "components/gsa/src/gmp/models/license.ts",
            "components/gsa/src/web/components/provider/LicenseProvider.jsx",
            "components/gsa/src/web/components/notification/LicenseNotification.jsx",
            "components/gvmd/src/gmp_license.c",
            "components/gvmd/src/gmp_license.h",
            "components/gvmd/src/manage_license.c",
            "components/gvmd/src/manage_license.h",
            "components/gvmd/src/theia_dummy.h",
        ] {
            assert!(
                !repo.join(retired_path).exists(),
                "retired appliance-licensing file remains: {retired_path}"
            );
        }
    }

    #[test]
    fn optional_feature_inventory_transport_is_absent() {
        const GSA_USER: &str = include_str!("../../../../components/gsa/src/gmp/commands/user.ts");
        const GSA_USER_TEST: &str =
            include_str!("../../../../components/gsa/src/gmp/commands/__tests__/user.test.ts");
        const GSAD_GMP: &str = include_str!("../../../../components/gsad/src/gsad_gmp.c");
        const GSAD_HEADER: &str = include_str!("../../../../components/gsad/src/gsad_gmp.h");
        const GSAD_VALIDATOR: &str =
            include_str!("../../../../components/gsad/src/gsad_validator.c");
        const GVMD_GMP: &str = include_str!("../../../../components/gvmd/src/gmp.c");
        const GVMD_SCHEMA: &str =
            include_str!("../../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");

        for (source, retired) in [
            (GSAD_GMP, "get_features_gmp"),
            (GSAD_GMP, "ELSE (get_features)"),
            (GSAD_HEADER, "get_features_gmp"),
            (GSAD_VALIDATOR, "|(get_features)"),
            (GVMD_GMP, "CLIENT_GET_FEATURES"),
            (GVMD_GMP, "handle_get_features"),
            (GVMD_GMP, "strcasecmp (\"GET_FEATURES\""),
            (GVMD_SCHEMA, "<name>get_features</name>"),
        ] {
            assert!(
                !source.contains(retired),
                "retired optional-feature transport marker remains: {retired}"
            );
        }

        assert!(GSA_USER.contains("async currentFeatures()"));
        assert!(GSA_USER.contains("return new Response(new Features());"));
        assert!(
            GSA_USER_TEST
                .contains("should disable non-retained optional features without a GMP request")
        );
        assert!(GSA_USER_TEST.contains("expect(fakeHttp.request).not.toHaveBeenCalled();"));
    }

    #[test]
    fn unknown_top_level_fields_fail_schema_parsing() {
        let root = TempRoot::new();
        valid_registry(&root.0);
        let path = root.0.join(REGISTRY_PATH);
        let source = fs::read_to_string(&path).unwrap().replace(
            "schema_version = 1",
            "schema_version = 1\nprogress_percnt = 5",
        );
        fs::write(path, source).unwrap();
        let result = command_gvmd_retirement_state(&root.0, false);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "gvmd-retirement.registry-parse");
    }

    #[test]
    fn one_hundred_percent_requires_terminal_rows() {
        let root = TempRoot::new();
        valid_registry(&root.0);
        let path = root.0.join(REGISTRY_PATH);
        let source = fs::read_to_string(&path)
            .unwrap()
            .replace("progress_percent = 5", "progress_percent = 100")
            .replace("next_update_percent = 10", "next_update_percent = 100")
            .replace(
                "status = \"open\"\nevidence = []",
                "status = \"verified\"\nevidence = [\"proof.txt::literal-anchor\"]",
            );
        fs::write(path, source).unwrap();
        let result = command_gvmd_retirement_state(&root.0, false);
        assert_eq!(result.status, "fail");
        assert!(result.findings.iter().any(|finding| {
            finding.check == "gvmd-retirement.program-completion" && finding.details.is_some()
        }));
    }

    #[cfg(unix)]
    #[test]
    fn registry_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = TempRoot::new();
        valid_registry(&root.0);
        let path = root.0.join(REGISTRY_PATH);
        let replacement = root.0.join("registry-copy.toml");
        fs::rename(&path, &replacement).unwrap();
        symlink(&replacement, &path).unwrap();
        let result = command_gvmd_retirement_state(&root.0, false);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "gvmd-retirement.registry-read");
    }
}
