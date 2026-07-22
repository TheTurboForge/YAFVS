// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: original

const CARGO_MANIFEST: &str = include_str!("../Cargo.toml");
const API_DOCKERFILE: &str = include_str!("../../../docker/yafvs-api/Dockerfile");

#[test]
fn api_container_copies_every_declared_local_domain_crate() {
    assert!(
        CARGO_MANIFEST.contains("yafvs-domain = { path = \"../../crates/yafvs-domain\" }"),
        "test must track the API's local domain dependency"
    );
    assert!(
        API_DOCKERFILE.contains("WORKDIR /workspace/services/yafvs-api")
            && API_DOCKERFILE.contains("COPY crates/yafvs-domain /workspace/crates/yafvs-domain")
            && API_DOCKERFILE.contains(
                "COPY --from=build /workspace/services/yafvs-api/target/release/yafvs-api",
            ),
        "the container build must preserve the repository-relative Cargo layout"
    );
}
