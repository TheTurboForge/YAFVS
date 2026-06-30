// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn scope_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn scope_write_mutability_sql() -> &'static str {
    "SELECT id::integer, coalesce(predefined, 0)::integer, coalesce(is_global, 0)::integer
       FROM scopes
      WHERE uuid = $1;"
}

pub(crate) fn scope_write_report_history_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM scope_reports
      WHERE scope_uuid = $1;"
}

pub(crate) fn scope_write_visible_targets_sql() -> &'static str {
    "SELECT uuid::text
       FROM targets
      WHERE uuid = ANY($1::text[]);"
}

pub(crate) fn scope_write_visible_hosts_sql() -> &'static str {
    "SELECT uuid::text
       FROM hosts
      WHERE uuid = ANY($1::text[]);"
}

pub(crate) fn scope_by_internal_id_sql() -> &'static str {
    "SELECT id::integer, uuid::text
       FROM scopes
      WHERE id = $1;"
}

pub(crate) fn scope_insert_sql() -> &'static str {
    "INSERT INTO scopes
        (uuid, owner, name, comment, protection_requirement, predefined, is_global,
         creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, $3, $4, 0, 0, m_now(), m_now())
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn scope_update_metadata_sql() -> &'static str {
    "UPDATE scopes
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            protection_requirement = coalesce($4, protection_requirement),
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn scope_delete_targets_sql() -> &'static str {
    "DELETE FROM scope_targets WHERE scope = $1;"
}

pub(crate) fn scope_insert_target_sql() -> &'static str {
    "INSERT INTO scope_targets (scope, target, target_uuid, target_name, added_time)
     SELECT $1, id, uuid, name, m_now()
       FROM targets
      WHERE uuid = $2
     ON CONFLICT (scope, target) DO NOTHING;"
}

pub(crate) fn scope_delete_hosts_sql() -> &'static str {
    "DELETE FROM scope_hosts WHERE scope = $1;"
}

pub(crate) fn scope_insert_host_sql() -> &'static str {
    "INSERT INTO scope_hosts (scope, host, host_uuid, host_name, added_time)
     SELECT $1, id, uuid, name, m_now()
       FROM hosts
      WHERE uuid = $2
     ON CONFLICT (scope, host) DO NOTHING;"
}

pub(crate) fn scope_delete_sql() -> &'static str {
    "DELETE FROM scopes WHERE id = $1;"
}
