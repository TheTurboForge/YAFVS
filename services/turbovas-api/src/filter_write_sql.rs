// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn filter_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn filter_live_alert_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alerts
      WHERE filter = $1;"
}

pub(crate) fn filter_alert_condition_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alert_condition_data
      WHERE name = 'filter_id'
        AND data = (SELECT uuid FROM filters WHERE id = $1)
        AND (SELECT condition IN (4, 5) FROM alerts WHERE id = alert);"
}

pub(crate) fn filter_trash_alert_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alerts_trash
      WHERE filter = $1
        AND filter_location = 1;"
}

pub(crate) fn filter_trash_alert_condition_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alert_condition_data_trash
      WHERE name = 'filter_id'
        AND data = (SELECT uuid FROM filters_trash WHERE id = $1)
        AND (SELECT condition IN (4, 5) FROM alerts_trash WHERE id = alert);"
}

pub(crate) fn filter_settings_cleanup_sql() -> &'static str {
    "DELETE FROM settings
      WHERE name ILIKE '% Filter'
        AND value = $1;"
}

pub(crate) fn filter_trash_insert_sql() -> &'static str {
    "INSERT INTO filters_trash
        (uuid, owner, name, comment, type, term, creation_time, modification_time)
     SELECT uuid, owner, name, comment, type, term, creation_time, modification_time
       FROM filters
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn filter_trash_alert_relink_sql() -> &'static str {
    "UPDATE alerts_trash
        SET filter = $1,
            filter_location = 1
      WHERE filter = $2
        AND filter_location = 0;"
}

pub(crate) fn filter_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'filter'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn filter_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'filter'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn filter_delete_metadata_sql() -> &'static str {
    "DELETE FROM filters WHERE id = $1;"
}

pub(crate) fn filter_write_state_sql() -> &'static str {
    "SELECT id::integer
       FROM filters
      WHERE uuid = $1;"
}

pub(crate) fn filter_trash_state_sql() -> &'static str {
    "SELECT id::integer, uuid::text, name, owner::integer
       FROM filters_trash
      WHERE uuid = $1;"
}

pub(crate) fn filter_unique_name_sql() -> &'static str {
    "SELECT (
        (SELECT count(*) FROM filters WHERE name = $1 AND id != $2)
        + (SELECT count(*) FROM filters_trash WHERE name = $1)
      )::bigint;"
}

pub(crate) fn filter_update_metadata_sql() -> &'static str {
    "UPDATE filters
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}

pub(crate) fn filter_clone_metadata_sql() -> &'static str {
    "INSERT INTO filters
        (uuid, owner, name, comment, type, term, creation_time, modification_time)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('filter', name, $2, ' Clone')),
            coalesce($4, comment),
            type,
            term,
            m_now(),
            m_now()
       FROM filters
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn filter_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'filter'
        AND resource = $1
        AND resource_location = 0;"
}

pub(crate) fn filter_unique_live_owner_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM filters
      WHERE name = $1
        AND owner = $2;"
}

pub(crate) fn filter_live_uuid_conflict_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM filters
      WHERE uuid = $1;"
}

pub(crate) fn filter_restore_metadata_sql() -> &'static str {
    "INSERT INTO filters
        (uuid, owner, name, comment, type, term, creation_time, modification_time)
     SELECT uuid, owner, name, comment, type, term, creation_time, modification_time
       FROM filters_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn filter_trash_alert_relink_to_live_sql() -> &'static str {
    "UPDATE alerts_trash
        SET filter = $2,
            filter_location = 0
      WHERE filter = $1
        AND filter_location = 1;"
}

pub(crate) fn filter_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'filter'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn filter_trash_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'filter'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn filter_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM filters_trash WHERE id = $1;"
}

pub(crate) fn filter_trash_tag_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'filter'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn filter_trash_tag_trash_delete_sql() -> &'static str {
    "DELETE FROM tag_resources_trash
      WHERE resource_type = 'filter'
        AND resource = $1
        AND resource_location = 1;"
}
