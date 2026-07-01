// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn schedule_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn schedule_trash_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE schedule = $1
        AND schedule_location = 1;"
}

pub(crate) fn schedule_live_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE schedule = $1
        AND schedule_location = 0
        AND hidden = 0;"
}

pub(crate) fn schedule_trash_insert_sql() -> &'static str {
    "INSERT INTO schedules_trash
        (uuid, owner, name, comment, first_time, period, period_months,
         byday, duration, timezone, creation_time, modification_time, icalendar)
     SELECT uuid, owner, name, comment, first_time, period, period_months,
            byday, duration, timezone, creation_time, modification_time, icalendar
       FROM schedules
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn schedule_task_relink_sql() -> &'static str {
    "UPDATE tasks
        SET schedule = $1,
            schedule_location = 1
      WHERE schedule = $2
        AND schedule_location = 0;"
}

pub(crate) fn schedule_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'schedule'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn schedule_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'schedule'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn schedule_delete_metadata_sql() -> &'static str {
    "DELETE FROM schedules WHERE id = $1;"
}

pub(crate) fn schedule_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM schedules
      WHERE uuid = $1;"
}

pub(crate) fn schedule_trash_state_sql() -> &'static str {
    "SELECT id::integer, uuid::text, name, owner::integer
       FROM schedules_trash
      WHERE uuid = $1;"
}

pub(crate) fn schedule_unique_name_sql() -> &'static str {
    "SELECT (
        (SELECT count(*) FROM schedules WHERE name = $1 AND id != $2)
        + (SELECT count(*) FROM schedules_trash WHERE name = $1)
      )::bigint;"
}

pub(crate) fn schedule_unique_live_owner_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM schedules
      WHERE name = $1
        AND owner = $2;"
}

pub(crate) fn schedule_live_uuid_conflict_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM schedules
      WHERE uuid = $1;"
}

pub(crate) fn schedule_update_metadata_sql() -> &'static str {
    "UPDATE schedules
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}

pub(crate) fn schedule_clone_metadata_sql() -> &'static str {
    "INSERT INTO schedules
        (uuid, owner, name, comment, first_time, period, period_months,
         byday, duration, timezone, creation_time, modification_time, icalendar)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('schedule', name, $2, ' Clone')),
            coalesce($4, comment),
            first_time,
            period,
            period_months,
            byday,
            duration,
            timezone,
            m_now(),
            m_now(),
            icalendar
       FROM schedules
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn schedule_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'schedule'
        AND resource = $1
        AND resource_location = 0;"
}

pub(crate) fn schedule_restore_metadata_sql() -> &'static str {
    "INSERT INTO schedules
        (uuid, owner, name, comment, first_time, period, period_months,
         byday, duration, timezone, creation_time, modification_time, icalendar)
     SELECT uuid, owner, name, comment, first_time, period, period_months,
            byday, duration, timezone, creation_time, modification_time, icalendar
       FROM schedules_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn schedule_task_relink_to_live_sql() -> &'static str {
    "UPDATE tasks
        SET schedule = $2,
            schedule_location = 0
      WHERE schedule = $1
        AND schedule_location = 1;"
}

pub(crate) fn schedule_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'schedule'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn schedule_trash_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'schedule'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn schedule_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM schedules_trash WHERE id = $1;"
}

pub(crate) fn schedule_trash_tag_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'schedule'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn schedule_trash_tag_trash_delete_sql() -> &'static str {
    "DELETE FROM tag_resources_trash
      WHERE resource_type = 'schedule'
        AND resource = $1
        AND resource_location = 1;"
}
