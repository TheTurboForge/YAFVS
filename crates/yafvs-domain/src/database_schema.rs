// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Exact compatibility contract for the currently supported gvmd public schema.
//!
//! This contract attests an existing version 288 schema. It deliberately does
//! not create a fresh database or reproduce historical migrations.

pub const DATABASE_VERSION: &str = "288";
pub const SCHEMA_FINGERPRINT: &str =
    "c9b9aed02c7ac9313957f17adfe1a6658f18b63c7600731e64d5bb2dd7135d62";

pub const DATABASE_VERSION_SQL: &str =
    "SELECT value FROM meta WHERE name = 'database_version' LIMIT 1;";
const PUBLIC_SCHEMA_ITEMS_SQL: &str = r#"
SELECT item
FROM (
    SELECT format(
        'column|%I|%I|%s|%s|%s|%s',
        table_name,
        column_name,
        ordinal_position,
        udt_name,
        is_nullable,
        coalesce(column_default, '')
    ) AS item
    FROM information_schema.columns
    WHERE table_schema = 'public'

    UNION ALL

    SELECT format(
        'constraint|%s|%s|%s',
        conrelid::regclass::text,
        contype,
        pg_get_constraintdef(oid, true)
    )
    FROM pg_constraint
    WHERE connamespace = 'public'::regnamespace

    UNION ALL

    SELECT format('index|%s|%s|%s', tablename, indexname, indexdef)
    FROM pg_indexes
    WHERE schemaname = 'public'
) AS fingerprint
ORDER BY item;
"#;

/// Builds one scalar PostgreSQL query for the same newline-delimited digest.
///
/// Runtime initialization uses this form so command output never has to carry
/// or parse the complete schema inventory. `pgcrypto` is a required runtime
/// extension and supplies the database-side SHA-256 implementation.
pub fn public_schema_fingerprint_sql() -> String {
    let items = PUBLIC_SCHEMA_ITEMS_SQL
        .trim()
        .strip_suffix(';')
        .expect("public schema inventory SQL ends in a semicolon");
    format!(
        "SELECT encode(digest(COALESCE(string_agg(item || E'\\n', '' ORDER BY item), ''), 'sha256'), 'hex') FROM ({items}) AS public_schema_items;"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_fingerprint_query_wraps_the_canonical_inventory() {
        let sql = public_schema_fingerprint_sql();
        assert!(sql.contains(PUBLIC_SCHEMA_ITEMS_SQL.trim().trim_end_matches(';')));
        assert!(sql.contains("string_agg(item || E'\\n', '' ORDER BY item)"));
        assert!(sql.contains("digest("));
    }
}
