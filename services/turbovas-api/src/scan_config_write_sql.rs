// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn scan_config_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn scan_config_write_state_sql() -> &'static str {
    "SELECT id::integer, coalesce(predefined, 0)::integer
       FROM configs
      WHERE uuid = $1
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn scan_config_trash_state_sql() -> &'static str {
    "SELECT id::integer, uuid::text, name, coalesce(scanner_location, 0)::integer
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
