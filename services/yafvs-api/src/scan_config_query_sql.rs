// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn scan_config_asset_list_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH scan_config_rows AS (
             SELECT c.id AS internal_id,
                    c.uuid AS id,
                    coalesce(c.name, '') AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(c.family_count, 0)::bigint AS family_count,
                    coalesce(c.nvt_count, 0)::bigint AS nvt_count,
                    coalesce(c.families_growing, 0)::integer AS families_growing,
                    coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
                    coalesce(c.predefined, 0)::integer AS predefined_int,
                    coalesce(c.usage_type, 'scan') AS usage_type,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM tasks t
                        WHERE t.config = c.id
                          AND t.config_location = 0
                          AND t.hidden = 0
                    ) THEN 1 ELSE 0 END AS in_use_int,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM deprecated_feed_data d
                        WHERE d.type = 'config' AND d.uuid = c.uuid
                    ) THEN 1 ELSE 0 END AS deprecated_int,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM configs c
          LEFT JOIN users u ON u.id = c.owner
              WHERE coalesce(c.usage_type, 'scan') = 'scan'
         ),
         filtered AS (
             SELECT * FROM scan_config_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND predefined_int = 1)
                     OR ($4 = '0' AND predefined_int = 0))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn scan_config_asset_detail_sql() -> &'static str {
    r#"SELECT c.id AS internal_id,
              c.uuid AS id,
              coalesce(c.name, '') AS name,
              coalesce(c.comment, '') AS comment,
              coalesce(u.name, '') AS owner_name,
              coalesce(c.family_count, 0)::bigint AS family_count,
              coalesce(c.nvt_count, 0)::bigint AS nvt_count,
              coalesce(c.families_growing, 0)::integer AS families_growing,
              coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
              coalesce(c.predefined, 0)::integer AS predefined_int,
              coalesce(c.usage_type, 'scan') AS usage_type,
              CASE WHEN EXISTS (
                 SELECT 1 FROM tasks t
                  WHERE t.config = c.id
                    AND t.config_location = 0
                    AND t.hidden = 0
              ) THEN 1 ELSE 0 END AS in_use_int,
              CASE WHEN EXISTS (
                 SELECT 1 FROM deprecated_feed_data d
                  WHERE d.type = 'config' AND d.uuid = c.uuid
              ) THEN 1 ELSE 0 END AS deprecated_int,
              coalesce(c.creation_time, 0)::bigint AS created_at_unix,
              coalesce(c.modification_time, 0)::bigint AS modified_at_unix
         FROM configs c
    LEFT JOIN users u ON u.id = c.owner
        WHERE c.uuid = $1
          AND coalesce(c.usage_type, 'scan') = 'scan'
        LIMIT 1;"#
}

pub(crate) fn scan_config_task_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.usage_type, 'scan') AS usage_type
         FROM configs c
         JOIN tasks t ON t.config = c.id
        WHERE lower(c.uuid) = lower($1)
          AND t.config_location = 0
          AND coalesce(t.hidden, 0) = 0
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn scan_config_preferences_sql() -> &'static str {
    r#"WITH config_row AS (
            SELECT c.id AS internal_id
              FROM configs c
             WHERE c.uuid = $1
               AND coalesce(c.usage_type, 'scan') = 'scan'
             LIMIT 1
        )
        SELECT CASE WHEN np.pref_nvt IS NULL THEN 'scanner' ELSE 'nvt' END AS preference_kind,
               CASE WHEN np.pref_nvt IS NULL
                    THEN np.name
                    ELSE coalesce(np.pref_name, '')
               END AS preference_name,
               CASE
                 WHEN np.pref_nvt IS NULL THEN np.name
                 WHEN coalesce(np.pref_name, '') = 'timeout' THEN 'Timeout'
                 ELSE coalesce(np.pref_name, '')
               END AS preference_hr_name,
               coalesce(np.pref_nvt, '') AS nvt_oid,
               coalesce(n.name, '') AS nvt_name,
               coalesce(np.pref_id, 0)::integer AS pref_id,
               coalesce(np.pref_type, '') AS pref_type,
               CASE
                 WHEN lower(coalesce(np.pref_type, '')) IN ('password', 'file') THEN ''
                 ELSE coalesce(cp.value, np.value, '')
               END AS value,
               CASE
                 WHEN lower(coalesce(np.pref_type, '')) IN ('password', 'file') THEN ''
                 ELSE coalesce(np.value, '')
               END AS default_value,
               cp.id IS NOT NULL AS configured,
               lower(coalesce(np.pref_type, '')) IN ('password', 'file') AS redacted
          FROM config_row c
          JOIN nvt_preferences np ON true
     LEFT JOIN nvts n ON n.oid = np.pref_nvt
     LEFT JOIN LATERAL (
               SELECT config_value.id, config_value.value
                 FROM config_preferences config_value
                WHERE config_value.config = c.internal_id
                  AND config_value.name = np.name
                ORDER BY config_value.type ASC NULLS LAST, config_value.id ASC
                LIMIT 1
          ) cp ON true
         WHERE np.name != 'cache_folder'
           AND np.name != 'include_folders'
           AND np.name != 'nasl_no_signature_check'
           AND np.name != 'network_targets'
           AND np.name != 'ntp_save_sessions'
           AND np.name NOT ILIKE 'server_info_%'
           AND np.name != 'max_checks'
           AND np.name != 'max_hosts'
         ORDER BY np.name ASC;"#
}

pub(crate) fn scan_config_families_sql() -> &'static str {
    r#"WITH config_row AS (
            SELECT c.uuid AS scan_config_id,
                   coalesce(c.nvt_selector, '') AS nvt_selector,
                   coalesce(c.family_count, 0)::bigint AS family_count,
                   coalesce(c.families_growing, 0)::integer AS families_growing
              FROM configs c
             WHERE c.uuid = $1
               AND coalesce(c.usage_type, 'scan') = 'scan'
             LIMIT 1
        ),
        family_rows AS (
            SELECT DISTINCT n.family
              FROM nvts n
             WHERE n.family IS NOT NULL
               AND n.family != ''
               AND n.family != 'Credentials'
        ),
        family_state AS (
            SELECT c.scan_config_id,
                   c.family_count,
                   c.families_growing,
                   f.family AS name,
                   CASE
                     WHEN c.families_growing <> 0 THEN
                       CASE WHEN EXISTS (
                              SELECT 1 FROM nvt_selectors ns
                               WHERE ns.name = c.nvt_selector
                                 AND ns.type = 1
                                 AND ns.family_or_nvt = f.family
                                 AND ns.exclude = 1
                            ) THEN 0 ELSE 1 END
                     ELSE
                       CASE WHEN EXISTS (
                              SELECT 1 FROM nvt_selectors ns
                               WHERE ns.name = c.nvt_selector
                                 AND ns.type = 1
                                 AND ns.family_or_nvt = f.family
                                 AND ns.exclude = 0
                            ) THEN 1 ELSE 0 END
                   END AS growing,
                   (SELECT count(*)::bigint
                      FROM nvts n
                     WHERE n.family = f.family) AS max_nvt_count
              FROM config_row c
              JOIN family_rows f ON f.family IS NOT NULL AND f.family != ''
        )
        SELECT scan_config_id,
               family_count,
               families_growing,
               name,
               growing::integer AS growing,
               CASE
                 WHEN growing <> 0 THEN
                   max_nvt_count -
                   (SELECT count(*)::bigint
                      FROM nvt_selectors ns
                      JOIN config_row c ON true
                     WHERE ns.name = c.nvt_selector
                       AND ns.exclude = 1
                       AND ns.type = 2
                       AND ns.family = family_state.name)
                 ELSE
                   (SELECT count(*)::bigint
                      FROM nvt_selectors ns
                      JOIN config_row c ON true
                     WHERE ns.name = c.nvt_selector
                       AND ns.exclude = 0
                       AND ns.type = 2
                       AND ns.family = family_state.name)
               END AS nvt_count,
               max_nvt_count
          FROM family_state
         ORDER BY lower(name), name;"#
}

pub(crate) fn scan_config_families_exists_sql() -> &'static str {
    "SELECT EXISTS (SELECT 1 FROM configs WHERE uuid = $1 AND coalesce(usage_type, 'scan') = 'scan');"
}

pub(crate) fn scan_config_family_nvts_sql() -> &'static str {
    r#"WITH config_row AS (
            SELECT coalesce(c.nvt_selector, '') AS nvt_selector,
                   coalesce(c.families_growing, 0)::integer AS families_growing,
                   coalesce(c.nvts_growing, 0)::integer AS nvts_growing
              FROM configs c
             WHERE c.uuid = $1
               AND coalesce(c.usage_type, 'scan') = 'scan'
             LIMIT 1
        ),
        family_state AS (
            SELECT c.nvt_selector,
                   CASE
                     WHEN c.nvts_growing = 0 THEN 0
                     WHEN c.families_growing <> 0 THEN
                       CASE WHEN EXISTS (
                              SELECT 1 FROM nvt_selectors ns
                               WHERE ns.name = c.nvt_selector
                                 AND ns.type = 1
                                 AND ns.family_or_nvt = $2
                                 AND ns.exclude = 1
                            ) THEN 0 ELSE 1 END
                     ELSE
                       CASE WHEN EXISTS (
                              SELECT 1 FROM nvt_selectors ns
                               WHERE ns.name = c.nvt_selector
                                 AND ns.type = 1
                                 AND ns.family_or_nvt = $2
                                 AND ns.exclude = 0
                            ) THEN 1 ELSE 0 END
                   END AS growing
              FROM config_row c
        )
        SELECT n.oid AS oid,
               coalesce(n.name, '') AS name,
               CASE
                 WHEN coalesce(n.cvss_base, '') ~ '^-?[0-9]+(\.[0-9]+)?$'
                 THEN n.cvss_base::double precision
                 ELSE 0::double precision
               END AS severity,
               CASE
                 WHEN f.growing <> 0 THEN NOT EXISTS (
                   SELECT 1 FROM nvt_selectors ns
                    WHERE ns.name = f.nvt_selector
                      AND ns.type = 2
                      AND ns.family = $2
                      AND ns.family_or_nvt = n.oid
                      AND ns.exclude = 1
                 )
                 ELSE EXISTS (
                   SELECT 1 FROM nvt_selectors ns
                    WHERE ns.name = f.nvt_selector
                      AND ns.type = 2
                      AND ns.family = $2
                      AND ns.family_or_nvt = n.oid
                      AND ns.exclude = 0
                 )
               END AS selected
          FROM family_state f
          JOIN nvts n ON n.family = $2
         ORDER BY lower(coalesce(n.name, '')), coalesce(n.name, ''), n.oid;"#
}

pub(crate) fn scan_config_family_nvts_exists_sql() -> &'static str {
    r#"SELECT EXISTS (
               SELECT 1 FROM configs
                WHERE uuid = $1
                  AND coalesce(usage_type, 'scan') = 'scan'
           ) AS config_exists,
           EXISTS (SELECT 1 FROM nvts WHERE family = $2) AS family_exists;"#
}
