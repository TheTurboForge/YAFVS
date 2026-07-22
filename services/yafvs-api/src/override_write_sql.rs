// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn override_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn override_trash_state_sql() -> &'static str {
    "SELECT id::integer,
            coalesce(owner, 0)::integer,
            coalesce(nvt, '')::text,
            coalesce(task, 0)::integer,
            coalesce(result, 0)::integer,
            uuid::text
       FROM overrides_trash
      WHERE uuid = $1
        FOR UPDATE;"
}

pub(crate) fn override_result_scope_by_internal_id_sql() -> &'static str {
    "SELECT r.id::integer,
            coalesce(r.task, 0)::integer,
            coalesce(t.owner, tt.owner, 0)::integer
       FROM results r
  LEFT JOIN tasks t ON t.id = r.task
  LEFT JOIN tasks_trash tt ON tt.id = r.task
      WHERE r.id = $1
      LIMIT 1;"
}

pub(crate) fn override_live_uuid_conflict_sql() -> &'static str {
    "SELECT EXISTS (SELECT 1 FROM overrides WHERE uuid = $1);"
}

pub(crate) fn override_restore_sql() -> &'static str {
    "INSERT INTO overrides
        (uuid, owner, nvt, creation_time, modification_time, text, hosts,
         port, severity, new_severity, task, result, end_time, result_nvt)
     SELECT uuid, owner, nvt, creation_time, modification_time, text, hosts,
            port, severity, new_severity, task, result, end_time, result_nvt
       FROM overrides_trash
      WHERE id = $1
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn override_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'override'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn override_trash_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'override'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn override_delete_trash_sql() -> &'static str {
    "DELETE FROM overrides_trash WHERE id = $1;"
}

pub(crate) fn override_delete_trash_tags_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'override'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn override_delete_trash_trash_tags_sql() -> &'static str {
    "DELETE FROM tag_resources_trash
      WHERE resource_type = 'override'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn override_nvt_exists_sql() -> &'static str {
    "SELECT EXISTS (
         SELECT 1 FROM nvts WHERE oid = $1
         UNION ALL
         SELECT 1 FROM scap.cves WHERE uuid = $1 AND $1 LIKE 'CVE-%'
     );"
}

pub(crate) fn override_task_scope_sql() -> &'static str {
    "SELECT id::integer, owner::integer
       FROM tasks
      WHERE uuid = $1
     UNION ALL
     SELECT id::integer, owner::integer
       FROM tasks_trash
      WHERE uuid = $1
      LIMIT 1;"
}

pub(crate) fn override_result_scope_sql() -> &'static str {
    "SELECT r.id::integer,
            coalesce(r.task, 0)::integer,
            coalesce(t.owner, tt.owner, 0)::integer
       FROM results r
  LEFT JOIN tasks t ON t.id = r.task
  LEFT JOIN tasks_trash tt ON tt.id = r.task
      WHERE r.uuid = $1
      LIMIT 1;"
}

pub(crate) fn override_insert_sql() -> &'static str {
    "INSERT INTO overrides
        (uuid, owner, nvt, creation_time, modification_time, text, hosts,
         port, severity, new_severity, task, result, end_time, result_nvt)
     VALUES
        (make_uuid(), $1, $2, m_now(), m_now(), $3, $4, $5, $6, $7, $8, $9,
         CASE WHEN $10 = -1 THEN 0
              WHEN $10 = 0 THEN 1
              ELSE m_now() + ($10 * 86400) END,
         (SELECT id FROM result_nvts WHERE nvt = $2 LIMIT 1))
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn override_patch_sql() -> &'static str {
    "UPDATE overrides
        SET nvt = CASE WHEN $2 THEN $3 ELSE nvt END,
            result_nvt = CASE WHEN $2
                              THEN (SELECT id FROM result_nvts WHERE nvt = $3 LIMIT 1)
                              ELSE result_nvt END,
            text = CASE WHEN $4 THEN $5 ELSE text END,
            hosts = CASE WHEN $6 THEN $7 ELSE hosts END,
            port = CASE WHEN $8 THEN $9 ELSE port END,
            severity = CASE WHEN $10 THEN $11 ELSE severity END,
            new_severity = CASE WHEN $12 THEN $13 ELSE new_severity END,
            task = CASE WHEN $14 THEN $15 ELSE task END,
            result = CASE WHEN $16 THEN $17 ELSE result END,
            end_time = CASE WHEN $18
                            THEN CASE WHEN $19 = -1 THEN 0
                                      WHEN $19 = 0 THEN 1
                                      ELSE m_now() + ($19 * 86400) END
                            ELSE end_time END,
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn override_clone_sql() -> &'static str {
    "INSERT INTO overrides
        (uuid, owner, nvt, creation_time, modification_time, text, hosts,
         port, severity, new_severity, task, result, end_time, result_nvt)
     SELECT make_uuid(), $2, nvt, m_now(), m_now(), text, hosts,
            port, severity, new_severity, task, result, end_time, result_nvt
       FROM overrides
      WHERE id = $1
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn override_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources
        (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'override'
        AND resource = $1
        AND resource_location = 0;"
}

pub(crate) fn override_write_state_sql() -> &'static str {
    "SELECT id::integer,
            coalesce(owner, 0)::integer,
            coalesce(nvt, '')::text,
            coalesce(task, 0)::integer,
            coalesce(result, 0)::integer
       FROM overrides
      WHERE uuid = $1
        FOR UPDATE;"
}

pub(crate) fn override_affected_reports_sql() -> &'static str {
    "SELECT DISTINCT report::integer
       FROM results
      WHERE nvt = $1
        AND (($3 <> 0 AND id = $3)
             OR ($3 = 0 AND $2 <> 0 AND task = $2)
             OR ($3 = 0 AND $2 = 0))
      ORDER BY report::integer;"
}

pub(crate) fn override_trash_insert_sql() -> &'static str {
    "INSERT INTO overrides_trash
        (uuid, owner, nvt, creation_time, modification_time, text, hosts,
         port, severity, new_severity, task, result, end_time, result_nvt)
     SELECT uuid, owner, nvt, creation_time, modification_time, text, hosts,
            port, severity, new_severity, task, result, end_time, result_nvt
       FROM overrides
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn override_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'override'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn override_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'override'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn override_delete_live_sql() -> &'static str {
    "DELETE FROM overrides WHERE id = $1;"
}

pub(crate) fn override_clear_overridden_report_counts_sql() -> &'static str {
    "DELETE FROM report_counts
      WHERE override = 1
        AND report = ANY($1::integer[]);"
}
