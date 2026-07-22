<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Distribution And License Compatibility

YAFVS is a collection of separately built programs, libraries, source trees,
and data inputs. Its public source repository is already available, but that
does not by itself authorize or complete a binary, container, hosted-service,
or feed-data distribution. Each distribution unit must have its own complete
source, notice, dependency, and license evidence.

## Enforced Boundaries

`policy/license-boundaries.toml` is the machine-readable source and artifact
boundary registry. The longest matching path rule governs newly added source.
The same policy distinguishes static/dynamic links from process and data
relationships. The Quality Gate fails when, for example, a new GPL-3.0 or
AGPL-3.0 source file is placed in the GPL-2.0 scanner boundary, or when a
GPL-2.0-only artifact is declared or actually configured to link any license
outside its explicit reviewed GPLv2-compatible allowlist. GPL-3.0/AGPL-3.0
dependencies can never enter that allowlist.

`policy/derivation-provenance.toml` fixes the policy epoch, accepted derivation
classes, DCO epoch, and unresolved classification reviews. New source must say
whether it is original, a behavioral reimplementation, an adaptation, or a
translation. Adaptations and translations must name their exact source and
license. This is intentionally independent of whether the source happens to be
publicly available.

The current `services/yafvs-api` relationship to AGPL-covered `gvmd` behavior
remains an explicit legal-classification review. Until resolved, the project
must not assume that a GPL-3.0 label alone settles the obligations of any code
that may constitute an adaptation. Non-source release modes remain blocked.

## Release Evidence Bundle

Run the manual **Release Compliance Evidence** workflow, or locally:

```sh
YAFVS_EVIDENCE_DIR=/absolute/private/output \
  tools/release-compliance-evidence binary
```

Accepted modes are `binary`, `container`, `hosted`, and
`feed-redistribution`. The command deliberately gathers evidence before
returning failure. Its bundle includes:

- the exact commit and mode-specific license-gate result;
- a source archive made from the exact commit;
- preserved license, notice, and policy files;
- Rust dependency metadata for the scanner, native API, and control CLI;
- separate SPDX SBOMs for the scanner, UI, Python services, native API, and
  control CLI source/dependency subjects;
- binary SBOMs and ELF dynamic-section evidence for built Rust artifacts;
- a container SBOM and build log when container mode is selected;
- REUSE lint output, a machine-readable manifest, failure list, and SHA-256
  checksums for every evidence file.

The workflow pins the Syft action by commit, uploads evidence even after a
failed review, and then fails closed. A green bundle is necessary but is not a
substitute for legal review of an unresolved derivation, feed term, trademark,
or source-offer question.

## Remaining Closure Work

The inherited aggregate does not yet pass whole-tree REUSE lint. That is an
explicit release blocker, not a reason to rewrite inherited headers casually.
Missing or malformed metadata must be repaired while preserving upstream
per-file licenses, exceptions, generated-file provenance, and the Samba-derived
`openvas-smb` record.

Before any binary or container release, verify all bundled system libraries,
base-image packages, Rust crates, npm packages, Python packages, generated
code, and vendored material. Supply the corresponding source or durable source
offer required by the governing copyleft license; include installation/build
scripts, license texts, notices, SBOMs, checksums, and release provenance. An
SBOM's `NOASSERTION` or missing license is a blocker until resolved.

Hosted deployments additionally need an exact-deployed-source procedure for
AGPL-covered network services. Feed mirroring, bundling, redistribution, or
derived-data publication uses a separate data-source license and attribution
review; source-code licensing does not answer those questions.
