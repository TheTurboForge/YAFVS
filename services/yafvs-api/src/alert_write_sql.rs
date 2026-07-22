// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn alert_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn alert_trash_state_sql() -> &'static str {
    "SELECT id::integer, uuid::text, name, owner::integer, filter_location::integer
       FROM alerts_trash
      WHERE uuid = $1;"
}

pub(crate) fn alert_write_state_sql() -> &'static str {
    "SELECT id::integer, owner::integer
       FROM alerts
      WHERE uuid = $1;"
}

pub(crate) fn alert_unique_live_owner_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alerts
      WHERE name = $1
        AND owner = $2;"
}

pub(crate) fn alert_live_uuid_conflict_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alerts
      WHERE uuid = $1;"
}

pub(crate) fn alert_trash_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM task_alerts
      WHERE alert = $1
        AND alert_location <> 0;"
}

pub(crate) fn alert_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alerts
      WHERE name = $1
        AND id != $2;"
}

pub(crate) fn alert_update_metadata_sql() -> &'static str {
    "UPDATE alerts
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn alert_clone_metadata_sql() -> &'static str {
    "INSERT INTO alerts
        (uuid, owner, name, comment, event, condition, method, filter, active,
         creation_time, modification_time)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('alert', name, $2, ' Clone')),
            coalesce($4, comment),
            event,
            condition,
            method,
            filter,
            active,
            m_now(),
            m_now()
       FROM alerts
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn alert_clone_condition_data_sql() -> &'static str {
    "INSERT INTO alert_condition_data (alert, name, data)
     SELECT $2, name, data
       FROM alert_condition_data
      WHERE alert = $1;"
}

pub(crate) fn alert_clone_event_data_sql() -> &'static str {
    "INSERT INTO alert_event_data (alert, name, data)
     SELECT $2, name, data
       FROM alert_event_data
      WHERE alert = $1;"
}

pub(crate) fn alert_clone_method_data_sql() -> &'static str {
    "INSERT INTO alert_method_data (alert, name, data)
     SELECT $2, name, data
       FROM alert_method_data
      WHERE alert = $1;"
}

pub(crate) fn alert_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'alert'
        AND resource = $1
        AND resource_location = 0;"
}

pub(crate) fn alert_live_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM task_alerts ta
       JOIN tasks t ON t.id = ta.task
      WHERE ta.alert = $1
        AND ta.alert_location = 0
        AND coalesce(t.hidden, 0) < 2;"
}

pub(crate) fn alert_trash_insert_sql() -> &'static str {
    "INSERT INTO alerts_trash
        (uuid, owner, name, comment, event, condition, method, filter,
         filter_location, active, creation_time, modification_time)
     SELECT uuid, owner, name, comment, event, condition, method, filter,
            0, active, creation_time, m_now()
       FROM alerts
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn alert_condition_data_trash_insert_sql() -> &'static str {
    "INSERT INTO alert_condition_data_trash (alert, name, data)
     SELECT $1, name, data
       FROM alert_condition_data
      WHERE alert = $2;"
}

pub(crate) fn alert_event_data_trash_insert_sql() -> &'static str {
    "INSERT INTO alert_event_data_trash (alert, name, data)
     SELECT $1, name, data
       FROM alert_event_data
      WHERE alert = $2;"
}

pub(crate) fn alert_method_data_trash_insert_sql() -> &'static str {
    "INSERT INTO alert_method_data_trash (alert, name, data)
     SELECT $1, name, data
       FROM alert_method_data
      WHERE alert = $2;"
}

pub(crate) fn alert_task_relink_to_trash_sql() -> &'static str {
    "UPDATE task_alerts
        SET alert = $1,
            alert_location = 1
      WHERE alert = $2
        AND alert_location = 0;"
}

pub(crate) fn alert_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'alert'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn alert_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'alert'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn alert_delete_condition_data_sql() -> &'static str {
    "DELETE FROM alert_condition_data WHERE alert = $1;"
}

pub(crate) fn alert_delete_event_data_sql() -> &'static str {
    "DELETE FROM alert_event_data WHERE alert = $1;"
}

pub(crate) fn alert_delete_method_data_sql() -> &'static str {
    "DELETE FROM alert_method_data WHERE alert = $1;"
}

pub(crate) fn alert_delete_metadata_sql() -> &'static str {
    "DELETE FROM alerts WHERE id = $1;"
}

pub(crate) fn alert_restore_metadata_sql() -> &'static str {
    "INSERT INTO alerts
        (uuid, owner, name, comment, event, condition, method, filter, active,
         creation_time, modification_time)
     SELECT uuid, owner, name, comment, event, condition, method, filter, active,
            creation_time, modification_time
       FROM alerts_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn alert_restore_condition_data_sql() -> &'static str {
    "INSERT INTO alert_condition_data (alert, name, data)
     SELECT $2, name, data
       FROM alert_condition_data_trash
      WHERE alert = $1;"
}

pub(crate) fn alert_restore_event_data_sql() -> &'static str {
    "INSERT INTO alert_event_data (alert, name, data)
     SELECT $2, name, data
       FROM alert_event_data_trash
      WHERE alert = $1;"
}

pub(crate) fn alert_restore_method_data_sql() -> &'static str {
    "INSERT INTO alert_method_data (alert, name, data)
     SELECT $2, name, data
       FROM alert_method_data_trash
      WHERE alert = $1;"
}

pub(crate) fn alert_task_relink_to_live_sql() -> &'static str {
    "UPDATE task_alerts
        SET alert = $2,
            alert_location = 0
      WHERE alert = $1
        AND alert_location = 1;"
}

pub(crate) fn alert_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'alert'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn alert_trash_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'alert'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn alert_delete_trash_condition_data_sql() -> &'static str {
    "DELETE FROM alert_condition_data_trash WHERE alert = $1;"
}

pub(crate) fn alert_delete_trash_event_data_sql() -> &'static str {
    "DELETE FROM alert_event_data_trash WHERE alert = $1;"
}

pub(crate) fn alert_delete_trash_method_data_sql() -> &'static str {
    "DELETE FROM alert_method_data_trash WHERE alert = $1;"
}

pub(crate) fn alert_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM alerts_trash WHERE id = $1;"
}

pub(crate) fn alert_trash_tag_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'alert'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn alert_trash_tag_trash_delete_sql() -> &'static str {
    "DELETE FROM tag_resources_trash
      WHERE resource_type = 'alert'
        AND resource = $1
        AND resource_location = 1;"
}
