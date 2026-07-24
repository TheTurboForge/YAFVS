// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later
// YAFVS-Derivation: behavioral-reimplementation
// YAFVS-Source-Provenance: components/gvmd/src/manage_pg.c create_tables behavior (AGPL-3.0-or-later), limited to filters and filters_trash tables.

//! Fixed, fresh-schema ownership contract for filter tables.

/// The exact catalog digest for the two stage tables created by [`FILTER_SCHEMA_SQL`].
pub(crate) const FILTER_SCHEMA_FINGERPRINT: &str =
    "79ba19acf08520908d0f9e36035e4f1dbac90917f5c14ffeb22305b0c1c18373";

/// One idempotent transaction for the filter table family.
///
/// `IF NOT EXISTS` intentionally leaves an existing same-named relation alone;
/// the immediate separate fingerprint is authoritative for accepting or rejecting it.
pub(crate) const FILTER_SCHEMA_SQL: &str = r#"
BEGIN;
CREATE TABLE IF NOT EXISTS filters (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    type text,
    term text,
    creation_time integer,
    modification_time integer
);
CREATE TABLE IF NOT EXISTS filters_trash (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    type text,
    term text,
    creation_time integer,
    modification_time integer
);
COMMIT;
"#;

const FILTER_SCHEMA_ITEMS_SQL: &str = r#"
SELECT item
FROM (
    SELECT format(
        'column|%I|%I|%s|%s|%s|%s',
        table_name, column_name, normalized_position, udt_name, is_nullable,
        coalesce(column_default, '')
    ) AS item
    FROM (
        SELECT table_name, column_name,
            row_number() OVER (PARTITION BY table_name ORDER BY ordinal_position) AS normalized_position,
            udt_name, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN ('filters', 'filters_trash')
    ) AS columns
    UNION ALL
    SELECT format('constraint|%I|%I|%s|%s', relation.relname, con.conname, con.contype, pg_get_constraintdef(con.oid, true)) AS item
    FROM pg_constraint AS con
    JOIN pg_class AS relation ON relation.oid = con.conrelid
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN ('filters', 'filters_trash')
    UNION ALL
    SELECT format('index|%I|%I|%s', tablename, indexname, indexdef)
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename IN ('filters', 'filters_trash')
) AS fingerprint
ORDER BY item
"#;

/// Returns one scalar query that hashes only this stage's structural contract.
pub(crate) fn filter_schema_fingerprint_sql() -> String {
    format!(
        "SELECT encode(digest(COALESCE(string_agg(item || E'\\n', '' ORDER BY item), ''), 'sha256'), 'hex') FROM ({}) AS filter_schema_items;",
        FILTER_SCHEMA_ITEMS_SQL.trim(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILTER_COLUMNS: &str = "id SERIAL PRIMARY KEY,\n    uuid text UNIQUE NOT NULL,\n    owner integer REFERENCES users (id) ON DELETE RESTRICT,\n    name text NOT NULL,\n    comment text,\n    type text,\n    term text,\n    creation_time integer,\n    modification_time integer";

    #[test]
    fn contract_is_one_transaction_with_no_data_or_version_side_effects() {
        assert!(FILTER_SCHEMA_SQL.trim_start().starts_with("BEGIN;"));
        assert!(FILTER_SCHEMA_SQL.trim_end().ends_with("COMMIT;"));
        for prohibited in ["INSERT INTO", "UPDATE ", "DELETE FROM", "database_version"] {
            assert!(!FILTER_SCHEMA_SQL.contains(prohibited));
        }
    }

    #[test]
    fn contract_owns_exactly_the_two_filter_tables_with_the_inherited_columns() {
        assert_eq!(
            FILTER_SCHEMA_SQL
                .matches("CREATE TABLE IF NOT EXISTS")
                .count(),
            2
        );
        for table in ["filters", "filters_trash"] {
            assert!(FILTER_SCHEMA_SQL.contains(&format!(
                "CREATE TABLE IF NOT EXISTS {table} (\n    {FILTER_COLUMNS}"
            )));
        }
    }

    #[test]
    fn contract_has_only_the_owner_foreign_key_and_no_explicit_indexes_or_extra_surface() {
        assert_eq!(
            FILTER_SCHEMA_SQL
                .matches("REFERENCES users (id) ON DELETE RESTRICT")
                .count(),
            2
        );
        for prohibited in [
            "CREATE INDEX",
            "resource_location",
            "REFERENCES filters",
            "REFERENCES filters_trash",
        ] {
            assert!(!FILTER_SCHEMA_SQL.contains(prohibited));
        }
    }

    #[test]
    fn fingerprint_is_normalized_and_limited_to_the_two_filter_tables() {
        let sql = filter_schema_fingerprint_sql();
        assert!(sql.contains("row_number() OVER"));
        assert!(sql.contains("digest("));
        assert_eq!(FILTER_SCHEMA_FINGERPRINT.len(), 64);
        assert!(
            FILTER_SCHEMA_FINGERPRINT
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        for table in ["filters", "filters_trash"] {
            assert_eq!(sql.matches(&format!("'{table}'")).count(), 3);
        }
    }
}
