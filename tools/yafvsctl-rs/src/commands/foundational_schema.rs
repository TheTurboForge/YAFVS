// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later
// YAFVS-Derivation: behavioral-reimplementation
// YAFVS-Source-Provenance: observed version-288 PostgreSQL catalog contract for meta, users, and settings; components/gvmd/src/manage_pg.c create_tables behavior (AGPL-3.0-or-later)

//! Fixed, fresh-schema ownership contract for the foundational public tables.

/// The exact catalog digest for `meta`, `users`, and `settings` created by
/// [`FOUNDATIONAL_SCHEMA_SQL`].
pub(crate) const FOUNDATIONAL_SCHEMA_FINGERPRINT: &str =
    "4f7261a17400dd3a18daeb9089c0bac37953b679f431a45e3426d8e139465569";

/// One idempotent transaction for the smallest dependency-closed table family.
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
          AND table_name IN ('meta', 'users', 'settings')
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
      AND relation.relname IN ('meta', 'users', 'settings')

    UNION ALL

    SELECT format('index|%I|%I|%s', tablename, indexname, indexdef)
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename IN ('meta', 'users', 'settings')
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
    fn contract_is_transactional_and_has_no_seed_data() {
        assert!(FOUNDATIONAL_SCHEMA_SQL.trim_start().starts_with("BEGIN;"));
        assert!(FOUNDATIONAL_SCHEMA_SQL.trim_end().ends_with("COMMIT;"));
        assert!(!FOUNDATIONAL_SCHEMA_SQL.contains("INSERT"));
        assert!(!FOUNDATIONAL_SCHEMA_SQL.contains("database_version"));
        let meta = FOUNDATIONAL_SCHEMA_SQL
            .find("CREATE TABLE IF NOT EXISTS meta")
            .unwrap();
        let users = FOUNDATIONAL_SCHEMA_SQL
            .find("CREATE TABLE IF NOT EXISTS users")
            .unwrap();
        let settings = FOUNDATIONAL_SCHEMA_SQL
            .find("CREATE TABLE IF NOT EXISTS settings")
            .unwrap();
        assert!(meta < users && users < settings);
        assert!(!FOUNDATIONAL_SCHEMA_SQL.contains("scanners"));
        assert!(!FOUNDATIONAL_SCHEMA_SQL.contains("credentials"));
    }

    #[test]
    fn fingerprint_is_limited_to_foundational_tables() {
        let sql = foundational_schema_fingerprint_sql();
        assert!(sql.contains("row_number() OVER"));
        assert!(sql.contains("table_name IN ('meta', 'users', 'settings')"));
        assert!(sql.contains("relation.relname IN ('meta', 'users', 'settings')"));
        assert!(sql.contains("tablename IN ('meta', 'users', 'settings')"));
        assert!(sql.contains("digest("));
    }
}
