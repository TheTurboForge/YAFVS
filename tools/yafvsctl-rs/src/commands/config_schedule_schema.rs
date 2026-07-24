// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later
// YAFVS-Derivation: behavioral-reimplementation
// YAFVS-Source-Provenance: components/gvmd/src/manage_pg.c create_tables and create_indexes behavior (AGPL-3.0-or-later), limited to nvt_selectors, configs, config preferences, and schedules tables.

//! Fixed, fresh-schema ownership contract for configuration and schedule tables.

/// The exact catalog digest for the seven stage tables created by [`CONFIG_SCHEDULE_SCHEMA_SQL`].
pub(crate) const CONFIG_SCHEDULE_SCHEMA_FINGERPRINT: &str =
    "701db0a17da5f07b11cbce266ff6b5cc07f41b88d8cc8bf868f7d65b36d6a93f";

/// One idempotent transaction for the configuration and schedule table family.
///
/// `IF NOT EXISTS` intentionally leaves an existing same-named relation alone;
/// the separate fingerprint is the authority that accepts or rejects it.
pub(crate) const CONFIG_SCHEDULE_SCHEMA_SQL: &str = r#"
BEGIN;
CREATE TABLE IF NOT EXISTS nvt_selectors (
    id SERIAL PRIMARY KEY,
    name text,
    exclude integer,
    type integer,
    family_or_nvt text,
    family text
);
CREATE TABLE IF NOT EXISTS configs (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    nvt_selector text,
    comment text,
    family_count integer,
    nvt_count integer,
    families_growing integer,
    nvts_growing integer,
    predefined integer,
    creation_time integer,
    modification_time integer,
    usage_type text
);
CREATE TABLE IF NOT EXISTS configs_trash (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    nvt_selector text,
    comment text,
    family_count integer,
    nvt_count integer,
    families_growing integer,
    nvts_growing integer,
    predefined integer,
    creation_time integer,
    modification_time integer,
    scanner_location integer,
    usage_type text
);
CREATE TABLE IF NOT EXISTS config_preferences (
    id SERIAL PRIMARY KEY,
    config integer REFERENCES configs (id) ON DELETE RESTRICT,
    type text,
    name text,
    value text,
    default_value text,
    pref_nvt text,
    pref_id integer,
    pref_type text,
    pref_name text
);
CREATE TABLE IF NOT EXISTS config_preferences_trash (
    id SERIAL PRIMARY KEY,
    config integer REFERENCES configs_trash (id) ON DELETE RESTRICT,
    type text,
    name text,
    value text,
    default_value text,
    pref_nvt text,
    pref_id integer,
    pref_type text,
    pref_name text
);
CREATE TABLE IF NOT EXISTS schedules (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    first_time integer,
    period integer,
    period_months integer,
    byday integer,
    duration integer,
    timezone text,
    creation_time integer,
    modification_time integer,
    icalendar text
);
CREATE TABLE IF NOT EXISTS schedules_trash (
    id SERIAL PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    first_time integer,
    period integer,
    period_months integer,
    byday integer,
    duration integer,
    timezone text,
    creation_time integer,
    modification_time integer,
    icalendar text
);
CREATE INDEX IF NOT EXISTS nvt_selectors_by_family_or_nvt ON nvt_selectors (type, family_or_nvt);
CREATE INDEX IF NOT EXISTS nvt_selectors_by_name ON nvt_selectors (name);
CREATE INDEX IF NOT EXISTS config_preferences_by_config ON config_preferences (config);
COMMIT;
"#;

const CONFIG_SCHEDULE_SCHEMA_ITEMS_SQL: &str = r#"
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
          AND table_name IN (
              'nvt_selectors', 'configs', 'configs_trash', 'config_preferences',
              'config_preferences_trash', 'schedules', 'schedules_trash'
          )
    ) AS columns
    UNION ALL
    SELECT format('constraint|%I|%I|%s|%s', relation.relname, con.conname, con.contype, pg_get_constraintdef(con.oid, true)) AS item
    FROM pg_constraint AS con
    JOIN pg_class AS relation ON relation.oid = con.conrelid
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN (
          'nvt_selectors', 'configs', 'configs_trash', 'config_preferences',
          'config_preferences_trash', 'schedules', 'schedules_trash'
      )
    UNION ALL
    SELECT format('index|%I|%I|%s', tablename, indexname, indexdef)
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename IN (
          'nvt_selectors', 'configs', 'configs_trash', 'config_preferences',
          'config_preferences_trash', 'schedules', 'schedules_trash'
      )
) AS fingerprint
ORDER BY item
"#;

/// Returns one scalar query that hashes only this stage's structural contract.
pub(crate) fn config_schedule_schema_fingerprint_sql() -> String {
    format!(
        "SELECT encode(digest(COALESCE(string_agg(item || E'\\n', '' ORDER BY item), ''), 'sha256'), 'hex') FROM ({}) AS config_schedule_schema_items;",
        CONFIG_SCHEDULE_SCHEMA_ITEMS_SQL.trim(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_is_transactional_and_has_no_data_or_version_side_effects() {
        assert!(
            CONFIG_SCHEDULE_SCHEMA_SQL
                .trim_start()
                .starts_with("BEGIN;")
        );
        assert!(CONFIG_SCHEDULE_SCHEMA_SQL.trim_end().ends_with("COMMIT;"));
        for prohibited in ["INSERT INTO", "UPDATE ", "DELETE FROM", "database_version"] {
            assert!(!CONFIG_SCHEDULE_SCHEMA_SQL.contains(prohibited));
        }
    }

    #[test]
    fn contract_owns_exactly_the_seven_requested_tables_in_dependency_order() {
        let tables = [
            "nvt_selectors",
            "configs",
            "configs_trash",
            "config_preferences",
            "config_preferences_trash",
            "schedules",
            "schedules_trash",
        ];
        let positions = tables.map(|table| {
            CONFIG_SCHEDULE_SCHEMA_SQL
                .find(&format!("CREATE TABLE IF NOT EXISTS {table}"))
                .unwrap()
        });
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            CONFIG_SCHEDULE_SCHEMA_SQL
                .matches("CREATE TABLE IF NOT EXISTS")
                .count(),
            7
        );
    }

    #[test]
    fn config_columns_foreign_keys_and_trash_location_match_the_inherited_contract() {
        assert!(CONFIG_SCHEDULE_SCHEMA_SQL.contains("configs (\n    id SERIAL PRIMARY KEY,\n    uuid text UNIQUE NOT NULL,\n    owner integer REFERENCES users (id) ON DELETE RESTRICT,\n    name text NOT NULL,\n    nvt_selector text,\n    comment text,\n    family_count integer,\n    nvt_count integer,\n    families_growing integer,\n    nvts_growing integer,\n    predefined integer,\n    creation_time integer,\n    modification_time integer,\n    usage_type text"));
        assert!(CONFIG_SCHEDULE_SCHEMA_SQL.contains(
            "modification_time integer,\n    scanner_location integer,\n    usage_type text"
        ));
        assert!(
            CONFIG_SCHEDULE_SCHEMA_SQL
                .contains("config integer REFERENCES configs (id) ON DELETE RESTRICT")
        );
        assert!(
            CONFIG_SCHEDULE_SCHEMA_SQL
                .contains("config integer REFERENCES configs_trash (id) ON DELETE RESTRICT")
        );
    }

    #[test]
    fn selectors_schedules_and_index_asymmetry_match_the_inherited_contract() {
        assert!(CONFIG_SCHEDULE_SCHEMA_SQL.contains("nvt_selectors (\n    id SERIAL PRIMARY KEY,\n    name text,\n    exclude integer,\n    type integer,\n    family_or_nvt text,\n    family text"));
        assert_eq!(
            CONFIG_SCHEDULE_SCHEMA_SQL.matches("icalendar text").count(),
            2
        );
        for index in [
            "CREATE INDEX IF NOT EXISTS nvt_selectors_by_family_or_nvt ON nvt_selectors (type, family_or_nvt);",
            "CREATE INDEX IF NOT EXISTS nvt_selectors_by_name ON nvt_selectors (name);",
            "CREATE INDEX IF NOT EXISTS config_preferences_by_config ON config_preferences (config);",
        ] {
            assert!(CONFIG_SCHEDULE_SCHEMA_SQL.contains(index));
        }
        assert!(!CONFIG_SCHEDULE_SCHEMA_SQL.contains("config_preferences_trash_by_config"));
    }

    #[test]
    fn fingerprint_is_normalized_and_limited_to_the_seven_stage_tables() {
        let sql = config_schedule_schema_fingerprint_sql();
        assert!(sql.contains("row_number() OVER"));
        assert_eq!(CONFIG_SCHEDULE_SCHEMA_FINGERPRINT.len(), 64);
        assert!(
            CONFIG_SCHEDULE_SCHEMA_FINGERPRINT
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        for table in [
            "nvt_selectors",
            "configs",
            "configs_trash",
            "config_preferences",
            "config_preferences_trash",
            "schedules",
            "schedules_trash",
        ] {
            assert_eq!(sql.matches(&format!("'{table}'")).count(), 3);
        }
        assert!(sql.contains("digest("));
    }
}
