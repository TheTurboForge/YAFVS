// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn scan_config_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn scan_config_preference_definition_sql() -> &'static str {
    "SELECT np.name,
            coalesce(np.value, ''),
            coalesce(np.pref_nvt, ''),
            coalesce(np.pref_id, 0)::integer,
            coalesce(np.pref_type, ''),
            coalesce(np.pref_name, '')
       FROM nvt_preferences np
      WHERE ($1 = 'scanner' AND np.pref_nvt IS NULL AND np.name = $2)
         OR ($1 = 'nvt'
             AND np.pref_nvt = $3
             AND coalesce(np.pref_id, 0) = $4
             AND coalesce(np.pref_type, '') = $5
             AND coalesce(np.pref_name, '') = $2)
      ORDER BY np.name
      LIMIT 1;"
}

pub(crate) fn scan_config_delete_preference_override_sql() -> &'static str {
    "DELETE FROM config_preferences
      WHERE config = $1
        AND type = $2
        AND name = $3;"
}

pub(crate) fn scan_config_insert_preference_override_sql() -> &'static str {
    "INSERT INTO config_preferences
        (config, type, name, value, pref_nvt, pref_id, pref_type, pref_name)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8);"
}

pub(crate) fn scan_config_known_family_names_sql() -> &'static str {
    "SELECT DISTINCT n.family
       FROM nvts n
      WHERE n.family IS NOT NULL
        AND n.family != ''
        AND n.family != 'Credentials'
      ORDER BY n.family;"
}

pub(crate) fn scan_config_replace_family_selection_sql() -> &'static str {
    r#"WITH desired AS MATERIALIZED (
            SELECT family, growing, selected
              FROM unnest($4::text[], $5::boolean[], $6::boolean[])
                   AS item(family, growing, selected)
        ),
        config_state AS MATERIALIZED (
            SELECT coalesce(c.families_growing, 0)::integer AS families_growing
              FROM configs c
             WHERE c.id = $1
        ),
        current_family_state AS MATERIALIZED (
            SELECT d.family,
                   d.growing AS desired_growing,
                   d.selected AS desired_all_selected,
                   CASE
                     WHEN c.families_growing <> 0 THEN NOT EXISTS (
                       SELECT 1
                         FROM nvt_selectors family_selector
                        WHERE family_selector.name = $2
                          AND family_selector.type = 1
                          AND family_selector.family_or_nvt = d.family
                          AND family_selector.exclude = 1
                     )
                     ELSE EXISTS (
                       SELECT 1
                         FROM nvt_selectors family_selector
                        WHERE family_selector.name = $2
                          AND family_selector.type = 1
                          AND family_selector.family_or_nvt = d.family
                          AND family_selector.exclude = 0
                     )
                   END AS current_growing
              FROM desired d
              CROSS JOIN config_state c
        ),
        current_nvt_state AS MATERIALIZED (
            SELECT family.family,
                   family.desired_growing,
                   family.desired_all_selected,
                   n.oid,
                   CASE
                     WHEN family.current_growing THEN NOT EXISTS (
                       SELECT 1
                         FROM nvt_selectors nvt_selector
                        WHERE nvt_selector.name = $2
                          AND nvt_selector.type = 2
                          AND nvt_selector.family = family.family
                          AND nvt_selector.family_or_nvt = n.oid
                          AND nvt_selector.exclude = 1
                     )
                     ELSE EXISTS (
                       SELECT 1
                         FROM nvt_selectors nvt_selector
                        WHERE nvt_selector.name = $2
                          AND nvt_selector.type = 2
                          AND nvt_selector.family = family.family
                          AND nvt_selector.family_or_nvt = n.oid
                          AND nvt_selector.exclude = 0
                     )
                   END AS current_selected
              FROM current_family_state family
              JOIN nvts n
                ON n.family = family.family
        ),
        current_counts AS MATERIALIZED (
            SELECT family,
                   count(*)::bigint AS max_nvt_count,
                   count(*) FILTER (WHERE current_selected)::bigint
                     AS selected_nvt_count
              FROM current_nvt_state
             GROUP BY family
        ),
        desired_nvt_state AS MATERIALIZED (
            SELECT current.family,
                   current.desired_growing,
                   current.oid,
                   CASE
                     WHEN current.desired_all_selected THEN true
                     WHEN counts.selected_nvt_count = counts.max_nvt_count
                       THEN false
                     ELSE current.current_selected
                   END AS selected
              FROM current_nvt_state current
              JOIN current_counts counts USING (family)
        ),
        deleted AS (
            DELETE FROM nvt_selectors
             WHERE name = $2
             RETURNING 1
        ),
        selector_rows AS (
            SELECT $2::text AS name,
                   0::integer AS exclude,
                   0::integer AS type,
                   '0'::text AS family_or_nvt,
                   NULL::text AS family
             WHERE $3::integer <> 0
            UNION ALL
            SELECT $2,
                   CASE WHEN $3::integer <> 0 THEN 1 ELSE 0 END,
                   1,
                   family,
                   NULL::text
              FROM desired
             WHERE growing <> ($3::integer <> 0)
            UNION ALL
            SELECT $2,
                   CASE WHEN desired_growing THEN 1 ELSE 0 END,
                   2,
                   oid,
                   family
              FROM desired_nvt_state
             WHERE (desired_growing AND NOT selected)
                OR (NOT desired_growing AND selected)
        ),
        inserted AS (
            INSERT INTO nvt_selectors
                   (name, exclude, type, family_or_nvt, family)
            SELECT rows.name,
                   rows.exclude,
                   rows.type,
                   rows.family_or_nvt,
                   rows.family
              FROM selector_rows rows
              CROSS JOIN (SELECT count(*) FROM deleted) deletion_barrier
            RETURNING 1
        )
        UPDATE configs
           SET families_growing = $3::integer
         WHERE id = $1
           AND (SELECT count(*) FROM inserted) >= 0;"#
}

pub(crate) fn scan_config_write_state_sql() -> &'static str {
    "SELECT id::integer, owner::integer, coalesce(predefined, 0)::integer,
            coalesce(nvt_selector, ''), coalesce(families_growing, 0)::integer
       FROM configs
      WHERE uuid = $1
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn scan_config_any_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE config = $1
        AND coalesce(config_location, 0) = 0;"
}

pub(crate) fn scan_config_selector_reference_count_sql() -> &'static str {
    "SELECT (
        (SELECT count(*) FROM configs WHERE nvt_selector = $1)
        + (SELECT count(*) FROM configs_trash WHERE nvt_selector = $1)
      )::bigint;"
}

pub(crate) fn scan_config_family_nvt_change_oid_count_sql() -> &'static str {
    "SELECT count(DISTINCT n.oid)::bigint
       FROM nvts n
      WHERE n.family = $1
        AND n.oid = ANY($2::text[]);"
}

pub(crate) fn scan_config_family_nvt_default_selected_sql() -> &'static str {
    "SELECT CASE
        WHEN $3::integer <> 0 THEN NOT EXISTS (
            SELECT 1
              FROM nvt_selectors ns
             WHERE ns.name = $1
               AND ns.type = 1
               AND ns.family_or_nvt = $2
               AND ns.exclude = 1
        )
        ELSE EXISTS (
            SELECT 1
              FROM nvt_selectors ns
             WHERE ns.name = $1
               AND ns.type = 1
               AND ns.family_or_nvt = $2
               AND ns.exclude = 0
        )
    END;"
}

pub(crate) fn scan_config_delete_family_nvt_selector_rows_sql() -> &'static str {
    "DELETE FROM nvt_selectors
      WHERE name = $1
        AND type = 2
        AND family = $2
        AND family_or_nvt = ANY($3::text[]);"
}

pub(crate) fn scan_config_insert_family_nvt_selector_rows_sql() -> &'static str {
    "INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)
     SELECT $1, $3, 2, oid, $2
       FROM unnest($4::text[]) AS oid;"
}

pub(crate) fn scan_config_recalculate_family_nvt_caches_sql() -> &'static str {
    r#"WITH config_row AS (
            SELECT c.nvt_selector,
                   coalesce(c.families_growing, 0)::integer AS families_growing
              FROM configs c
             WHERE c.id = $1
        ),
        known_families AS (
            SELECT DISTINCT n.family
              FROM nvts n
             WHERE n.family IS NOT NULL
               AND n.family != ''
               AND n.family != 'Credentials'
        ),
        family_state AS (
            SELECT f.family,
                   CASE
                     WHEN c.families_growing <> 0 THEN NOT EXISTS (
                       SELECT 1
                         FROM nvt_selectors ns
                        WHERE ns.name = c.nvt_selector
                          AND ns.type = 1
                          AND ns.family_or_nvt = f.family
                          AND ns.exclude = 1
                     )
                     ELSE EXISTS (
                       SELECT 1
                         FROM nvt_selectors ns
                        WHERE ns.name = c.nvt_selector
                          AND ns.type = 1
                          AND ns.family_or_nvt = f.family
                          AND ns.exclude = 0
                     )
                   END AS growing,
                   CASE
                     WHEN c.families_growing <> 0 AND NOT EXISTS (
                       SELECT 1
                         FROM nvt_selectors ns
                        WHERE ns.name = c.nvt_selector
                          AND ns.type = 1
                          AND ns.family_or_nvt = f.family
                          AND ns.exclude = 1
                     ) THEN (
                       SELECT count(*)::bigint
                         FROM nvts n
                        WHERE n.family = f.family
                     ) - (
                       SELECT count(DISTINCT ns.family_or_nvt)::bigint
                         FROM nvt_selectors ns
                         JOIN nvts n
                           ON n.oid = ns.family_or_nvt
                          AND n.family = f.family
                        WHERE ns.name = c.nvt_selector
                          AND ns.type = 2
                          AND ns.exclude = 1
                     )
                     WHEN c.families_growing = 0 AND EXISTS (
                       SELECT 1
                         FROM nvt_selectors ns
                        WHERE ns.name = c.nvt_selector
                          AND ns.type = 1
                          AND ns.family_or_nvt = f.family
                          AND ns.exclude = 0
                     ) THEN (
                       SELECT count(*)::bigint
                         FROM nvts n
                        WHERE n.family = f.family
                     ) - (
                       SELECT count(DISTINCT ns.family_or_nvt)::bigint
                         FROM nvt_selectors ns
                         JOIN nvts n
                           ON n.oid = ns.family_or_nvt
                          AND n.family = f.family
                        WHERE ns.name = c.nvt_selector
                          AND ns.type = 2
                          AND ns.exclude = 1
                     )
                     ELSE (
                       SELECT count(DISTINCT ns.family_or_nvt)::bigint
                         FROM nvt_selectors ns
                         JOIN nvts n
                           ON n.oid = ns.family_or_nvt
                          AND n.family = f.family
                        WHERE ns.name = c.nvt_selector
                          AND ns.type = 2
                          AND ns.exclude = 0
                     )
                   END AS selected_nvt_count
              FROM config_row c
              CROSS JOIN known_families f
        ),
        cache_values AS (
            SELECT count(*) FILTER (WHERE growing OR selected_nvt_count > 0)::integer
                     AS family_count,
                   coalesce(sum(selected_nvt_count), 0)::integer AS nvt_count,
                   CASE WHEN bool_or(growing) THEN 1 ELSE 0 END::integer AS nvts_growing
              FROM family_state
        )
        UPDATE configs c
           SET family_count = cache_values.family_count,
               nvt_count = cache_values.nvt_count,
               nvts_growing = cache_values.nvts_growing,
               modification_time = m_now()
          FROM cache_values
         WHERE c.id = $1;"#
}

pub(crate) fn scan_config_trash_state_sql() -> &'static str {
    "SELECT id::integer, uuid::text, name, owner::integer, coalesce(scanner_location, 0)::integer
       FROM configs_trash
      WHERE uuid = $1
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn scan_config_unique_name_sql() -> &'static str {
    "SELECT (
        (SELECT count(*) FROM configs WHERE name = $1 AND id != $2)
        + (SELECT count(*) FROM configs_trash WHERE name = $1)
      )::bigint;"
}

pub(crate) fn scan_config_unique_live_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM configs
      WHERE name = $1;"
}

pub(crate) fn scan_config_live_uuid_conflict_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM configs
      WHERE uuid = $1;"
}

pub(crate) fn scan_config_live_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE config = $1
        AND config_location = 0
        AND hidden = 0;"
}

pub(crate) fn scan_config_trash_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE config = $1
        AND config_location = 1;"
}

pub(crate) fn scan_config_trash_insert_sql() -> &'static str {
    "INSERT INTO configs_trash
        (uuid, owner, name, nvt_selector, comment, family_count, nvt_count,
         families_growing, nvts_growing, predefined, creation_time,
         modification_time, scanner_location, usage_type)
     SELECT uuid, owner, name, nvt_selector, comment, family_count, nvt_count,
            families_growing, nvts_growing, predefined, creation_time,
            modification_time, 0, usage_type
       FROM configs
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn scan_config_clone_metadata_sql() -> &'static str {
    "INSERT INTO configs
        (uuid, owner, name, nvt_selector, comment, family_count, nvt_count,
         families_growing, nvts_growing, predefined, creation_time,
         modification_time, usage_type)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('config', name, $2, ' Clone')),
            make_uuid(),
            coalesce($4, comment),
            family_count,
            nvt_count,
            families_growing,
            nvts_growing,
            0,
            m_now(),
            m_now(),
            'scan'
       FROM configs
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn scan_config_create_from_base_metadata_sql() -> &'static str {
    "INSERT INTO configs
        (uuid, owner, name, nvt_selector, comment, family_count, nvt_count,
         families_growing, nvts_growing, predefined, creation_time,
         modification_time, usage_type)
     SELECT make_uuid(),
            $2,
            $3,
            make_uuid(),
            $4,
            family_count,
            nvt_count,
            families_growing,
            nvts_growing,
            0,
            m_now(),
            m_now(),
            'scan'
       FROM configs
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn scan_config_clone_preferences_sql() -> &'static str {
    "INSERT INTO config_preferences
        (config, type, name, value, default_value, pref_nvt, pref_id, pref_type, pref_name)
     SELECT $2, type, name, value, default_value, pref_nvt, pref_id, pref_type, pref_name
       FROM config_preferences
      WHERE config = $1;"
}

pub(crate) fn scan_config_clone_selectors_sql() -> &'static str {
    "INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)
     SELECT (SELECT nvt_selector FROM configs WHERE id = $2), exclude, type, family_or_nvt, family
       FROM nvt_selectors
      WHERE name = (SELECT nvt_selector FROM configs WHERE id = $1);"
}

pub(crate) fn scan_config_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'config'
        AND resource = $1
        AND resource_location = 0;"
}

pub(crate) fn scan_config_preferences_trash_insert_sql() -> &'static str {
    "INSERT INTO config_preferences_trash
        (config, type, name, value, default_value, pref_nvt, pref_id, pref_type, pref_name)
     SELECT $1, type, name, value, default_value, pref_nvt, pref_id, pref_type, pref_name
       FROM config_preferences
      WHERE config = $2;"
}

pub(crate) fn scan_config_task_relink_to_trash_sql() -> &'static str {
    "UPDATE tasks
        SET config = $1,
            config_location = 1
      WHERE config = $2
        AND config_location = 0;"
}

pub(crate) fn scan_config_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'config'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn scan_config_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'config'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn scan_config_delete_preferences_sql() -> &'static str {
    "DELETE FROM config_preferences WHERE config = $1;"
}

pub(crate) fn scan_config_delete_metadata_sql() -> &'static str {
    "DELETE FROM configs WHERE id = $1;"
}

pub(crate) fn scan_config_restore_metadata_sql() -> &'static str {
    "INSERT INTO configs
        (uuid, owner, name, nvt_selector, comment, family_count, nvt_count,
         families_growing, nvts_growing, predefined, creation_time, modification_time, usage_type)
     SELECT uuid, owner, name, nvt_selector, comment, family_count, nvt_count,
            families_growing, nvts_growing, predefined, creation_time, modification_time, usage_type
       FROM configs_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn scan_config_preferences_restore_sql() -> &'static str {
    "INSERT INTO config_preferences
        (config, type, name, value, default_value, pref_nvt, pref_id, pref_type, pref_name)
     SELECT $2, type, name, value, default_value, pref_nvt, pref_id, pref_type, pref_name
       FROM config_preferences_trash
      WHERE config = $1;"
}

pub(crate) fn scan_config_task_relink_to_live_sql() -> &'static str {
    "UPDATE tasks
        SET config = $2,
            config_location = 0
      WHERE config = $1
        AND config_location = 1;"
}

pub(crate) fn scan_config_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'config'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn scan_config_trash_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'config'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn scan_config_delete_trash_preferences_sql() -> &'static str {
    "DELETE FROM config_preferences_trash WHERE config = $1;"
}

pub(crate) fn scan_config_delete_trash_selector_sql() -> &'static str {
    "DELETE FROM nvt_selectors
      WHERE name != '54b45713-d4f4-4435-b20d-304c175ed8c5'
        AND name = (SELECT nvt_selector FROM configs_trash WHERE id = $1);"
}

pub(crate) fn scan_config_trash_tag_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'config'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn scan_config_trash_tag_trash_delete_sql() -> &'static str {
    "DELETE FROM tag_resources_trash
      WHERE resource_type = 'config'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn scan_config_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM configs_trash WHERE id = $1;"
}

pub(crate) fn scan_config_update_metadata_sql() -> &'static str {
    "UPDATE configs
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}
