// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn report_config_write_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            owner::integer,
            coalesce(report_format_id, '')::text
       FROM report_configs
      WHERE uuid = $1;"
}

pub(crate) fn report_config_trash_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            coalesce(name, '')::text,
            owner::integer
       FROM report_configs_trash
      WHERE uuid = $1;"
}

pub(crate) fn report_config_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn report_config_unique_live_owner_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM report_configs
      WHERE name = $1
        AND owner = $2;"
}

pub(crate) fn report_config_live_uuid_conflict_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM report_configs
      WHERE uuid = $1;"
}

pub(crate) fn report_config_unique_live_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM report_configs
      WHERE name = $1
        AND ($2::integer IS NULL OR id != $2);"
}

pub(crate) fn report_config_format_state_sql() -> &'static str {
    "SELECT id::integer, uuid::text
       FROM report_formats
      WHERE uuid = $1;"
}

pub(crate) fn report_config_format_params_sql() -> &'static str {
    "SELECT id::integer AS internal_id,
            coalesce(name, '') AS name,
            coalesce(type, 100)::integer AS param_type,
            type_min,
            type_max
       FROM report_format_params
      WHERE report_format = $1
      ORDER BY name ASC, id ASC;"
}

pub(crate) fn report_config_format_param_options_sql() -> &'static str {
    "SELECT report_format_param::integer,
            coalesce(value, '') AS value
       FROM report_format_param_options
      WHERE report_format_param = ANY($1::integer[])
      ORDER BY report_format_param ASC, value ASC;"
}

pub(crate) fn report_config_insert_sql() -> &'static str {
    "INSERT INTO report_configs
        (uuid, name, comment, report_format_id, owner, creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, $3, $4, m_now(), m_now())
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_update_metadata_sql() -> &'static str {
    "UPDATE report_configs
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_touch_sql() -> &'static str {
    "UPDATE report_configs
        SET modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_by_internal_id_sql() -> &'static str {
    "SELECT id::integer, uuid::text
       FROM report_configs
      WHERE id = $1;"
}

pub(crate) fn report_config_delete_params_sql() -> &'static str {
    "DELETE FROM report_config_params WHERE report_config = $1;"
}

pub(crate) fn report_config_delete_metadata_sql() -> &'static str {
    "DELETE FROM report_configs WHERE id = $1;"
}

pub(crate) fn report_config_in_use_by_alerts_sql() -> &'static str {
    "SELECT 0::bigint;"
}

pub(crate) fn report_config_trash_insert_sql() -> &'static str {
    "INSERT INTO report_configs_trash
        (uuid, owner, name, comment, creation_time, modification_time, report_format_id)
     SELECT uuid, owner, name, comment, creation_time, modification_time, report_format_id
       FROM report_configs
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_trash_params_insert_sql() -> &'static str {
    "INSERT INTO report_config_params_trash (report_config, name, value)
     SELECT $1, name, value
       FROM report_config_params
      WHERE report_config = $2;"
}

pub(crate) fn report_config_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'report_config'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn report_config_restore_metadata_sql() -> &'static str {
    "INSERT INTO report_configs
        (uuid, owner, name, comment, creation_time, modification_time, report_format_id)
     SELECT uuid, owner, name, comment, creation_time, modification_time, report_format_id
       FROM report_configs_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_restore_params_sql() -> &'static str {
    "INSERT INTO report_config_params (report_config, name, value)
     SELECT $2, name, value
       FROM report_config_params_trash
      WHERE report_config = $1;"
}

pub(crate) fn report_config_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'report_config'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn report_config_delete_trash_params_sql() -> &'static str {
    "DELETE FROM report_config_params_trash WHERE report_config = $1;"
}

pub(crate) fn report_config_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM report_configs_trash WHERE id = $1;"
}

pub(crate) fn report_config_trash_tag_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'report_config'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn report_config_trash_in_use_by_alerts_sql() -> &'static str {
    "SELECT 0::bigint;"
}

pub(crate) fn report_config_insert_param_sql() -> &'static str {
    "INSERT INTO report_config_params (report_config, name, value)
     VALUES ($1, $2, $3)
     ON CONFLICT (report_config, name) DO UPDATE SET value = EXCLUDED.value;"
}

pub(crate) fn report_config_clone_sql() -> &'static str {
    "INSERT INTO report_configs
        (uuid, owner, name, comment, report_format_id, creation_time, modification_time)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('report_config', name, $2, ' Clone')),
            comment,
            report_format_id,
            m_now(),
            m_now()
       FROM report_configs
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_clone_params_sql() -> &'static str {
    "INSERT INTO report_config_params (report_config, name, value)
     SELECT $2, name, value
       FROM report_config_params
      WHERE report_config = $1;"
}

pub(crate) fn report_config_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'report_config'
        AND resource = $1
        AND resource_location = 0;"
}
