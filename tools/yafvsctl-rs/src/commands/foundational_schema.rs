// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later
// YAFVS-Derivation: behavioral-reimplementation
// YAFVS-Source-Provenance: observed version-288 PostgreSQL catalog contract for foundational meta/users/settings plus credentials/scanners tables; components/gvmd/src/manage_pg.c create_tables behavior (AGPL-3.0-or-later)

//! Fixed, fresh-schema ownership contract for the foundational public tables.

/// The exact catalog digest for the nine stage tables created by
/// [`FOUNDATIONAL_SCHEMA_SQL`].
pub(crate) const FOUNDATIONAL_SCHEMA_FINGERPRINT: &str =
    "d2d1de54355603502c47adaec9ec855290605edf6a4a05385f8b87ecb4ede800";

/// One idempotent transaction for the dependency-closed foundational table family.
///
/// `IF NOT EXISTS` intentionally leaves an existing same-named relation alone;
/// the separate fingerprint is the authority that accepts or rejects it.
pub(crate) const FOUNDATIONAL_SCHEMA_SQL: &str = r#"
BEGIN;
CREATE TABLE IF NOT EXISTS meta (
    id SERIAL PRIMARY KEY,
    name text UNIQUE NOT NULL,
    value text
);
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text UNIQUE NOT NULL,
    comment text,
    password text,
    timezone text,
    method text,
    creation_time integer,
    modification_time integer
);
CREATE TABLE IF NOT EXISTS settings (
    id SERIAL PRIMARY KEY,
    uuid text NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    value text,
    UNIQUE (uuid, owner)
);
CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    creation_time integer,
    modification_time integer,
    type text,
    allow_insecure integer
);
CREATE TABLE IF NOT EXISTS credentials_trash (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    creation_time integer,
    modification_time integer,
    type text,
    allow_insecure integer
);
CREATE TABLE IF NOT EXISTS credentials_data (
    id SERIAL PRIMARY KEY,
    credential integer REFERENCES credentials (id) ON DELETE RESTRICT,
    type text,
    value text
);
CREATE TABLE IF NOT EXISTS credentials_trash_data (
    id SERIAL PRIMARY KEY,
    credential integer REFERENCES credentials_trash (id) ON DELETE RESTRICT,
    type text,
    value text
);
CREATE TABLE IF NOT EXISTS scanners (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text,
    comment text,
    host text,
    port integer,
    type integer,
    ca_pub text,
    credential integer REFERENCES credentials (id) ON DELETE RESTRICT,
    creation_time integer,
    modification_time integer,
    relay_host text,
    relay_port integer
);
CREATE TABLE IF NOT EXISTS scanners_trash (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text,
    comment text,
    host text,
    port integer,
    type integer,
    ca_pub text,
    credential integer,
    credential_location integer,
    creation_time integer,
    modification_time integer,
    relay_host text,
    relay_port integer
);
COMMIT;
"#;

const FOUNDATIONAL_SCHEMA_ITEMS_SQL: &str = r#"
SELECT item
FROM (
    SELECT format(
        'column|%I|%I|%s|%s|%s|%s',
        table_name,
        column_name,
        normalized_position,
        udt_name,
        is_nullable,
        coalesce(column_default, '')
    ) AS item
    FROM (
        SELECT
            table_name,
            column_name,
            row_number() OVER (
                PARTITION BY table_name
                ORDER BY ordinal_position
            ) AS normalized_position,
            udt_name,
            is_nullable,
            column_default
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN (
              'meta', 'users', 'settings', 'credentials', 'credentials_trash',
              'credentials_data', 'credentials_trash_data', 'scanners', 'scanners_trash'
          )
    ) AS columns

    UNION ALL

    SELECT format(
        'constraint|%I|%I|%s|%s',
        relation.relname,
        con.conname,
        con.contype,
        pg_get_constraintdef(con.oid, true)
    ) AS item
    FROM pg_constraint AS con
    JOIN pg_class AS relation ON relation.oid = con.conrelid
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN (
          'meta', 'users', 'settings', 'credentials', 'credentials_trash',
          'credentials_data', 'credentials_trash_data', 'scanners', 'scanners_trash'
      )

    UNION ALL

    SELECT format('index|%I|%I|%s', tablename, indexname, indexdef)
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename IN (
          'meta', 'users', 'settings', 'credentials', 'credentials_trash',
          'credentials_data', 'credentials_trash_data', 'scanners', 'scanners_trash'
      )
) AS fingerprint
ORDER BY item
"#;

/// Returns one scalar query that hashes only this stage's structural contract.
pub(crate) fn foundational_schema_fingerprint_sql() -> String {
    format!(
        "SELECT encode(digest(COALESCE(string_agg(item || E'\\n', '' ORDER BY item), ''), 'sha256'), 'hex') FROM ({}) AS foundational_schema_items;",
        FOUNDATIONAL_SCHEMA_ITEMS_SQL.trim(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_is_transactional_and_has_no_data_or_runtime_side_effects() {
        assert!(FOUNDATIONAL_SCHEMA_SQL.trim_start().starts_with("BEGIN;"));
        assert!(FOUNDATIONAL_SCHEMA_SQL.trim_end().ends_with("COMMIT;"));
        for prohibited in [
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "database_version",
            "encryption",
            "encrypt",
            "decrypt",
            "DEFAULT_SCANNER",
            "6acd0832-df90-11e4-b9d5-28d24461215b",
        ] {
            assert!(!FOUNDATIONAL_SCHEMA_SQL.contains(prohibited));
        }
    }

    #[test]
    fn contract_owns_exactly_the_nine_stage_tables_in_dependency_order() {
        let tables = [
            "meta",
            "users",
            "settings",
            "credentials",
            "credentials_trash",
            "credentials_data",
            "credentials_trash_data",
            "scanners",
            "scanners_trash",
        ];
        let positions = tables.map(|table| {
            FOUNDATIONAL_SCHEMA_SQL
                .find(&format!("CREATE TABLE IF NOT EXISTS {table}"))
                .unwrap()
        });
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            FOUNDATIONAL_SCHEMA_SQL
                .matches("CREATE TABLE IF NOT EXISTS")
                .count(),
            9
        );
    }

    #[test]
    fn credential_and_scanner_foreign_keys_match_the_inherited_contract() {
        for clause in [
            "credentials (\n    id SERIAL PRIMARY KEY,\n    uuid text UNIQUE NOT NULL,\n    owner integer REFERENCES users (id) ON DELETE RESTRICT",
            "credentials_trash (\n    id SERIAL PRIMARY KEY,\n    uuid text UNIQUE NOT NULL,\n    owner integer REFERENCES users (id) ON DELETE RESTRICT",
            "credential integer REFERENCES credentials (id) ON DELETE RESTRICT",
            "credential integer REFERENCES credentials_trash (id) ON DELETE RESTRICT",
            "scanners (\n    id SERIAL PRIMARY KEY,\n    uuid text UNIQUE NOT NULL,\n    owner integer REFERENCES users (id) ON DELETE RESTRICT",
            "scanners_trash (\n    id SERIAL PRIMARY KEY,\n    uuid text UNIQUE NOT NULL,\n    owner integer REFERENCES users (id) ON DELETE RESTRICT",
        ] {
            assert!(FOUNDATIONAL_SCHEMA_SQL.contains(clause));
        }
    }

    #[test]
    fn scanner_trash_preserves_plain_credential_and_location_columns() {
        let scanners_trash = FOUNDATIONAL_SCHEMA_SQL
            .split("CREATE TABLE IF NOT EXISTS scanners_trash")
            .nth(1)
            .unwrap();
        assert!(scanners_trash.contains("credential integer,\n    credential_location integer,"));
        assert!(!scanners_trash.contains("credential integer REFERENCES"));
        assert!(scanners_trash.contains("relay_host text,\n    relay_port integer"));
    }

    #[test]
    fn fingerprint_is_normalized_and_limited_to_the_nine_stage_tables() {
        let sql = foundational_schema_fingerprint_sql();
        assert!(sql.contains("row_number() OVER"));
        for table in [
            "meta",
            "users",
            "settings",
            "credentials",
            "credentials_trash",
            "credentials_data",
            "credentials_trash_data",
            "scanners",
            "scanners_trash",
        ] {
            assert_eq!(sql.matches(&format!("'{table}'")).count(), 3);
        }
        assert!(sql.contains("digest("));
    }
}
