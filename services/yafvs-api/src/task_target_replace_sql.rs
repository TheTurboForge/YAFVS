// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn task_target_replace_task_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            target::integer,
            run_status::integer,
            coalesce(target_location, 0)::integer,
            coalesce(hidden, 0)::integer,
            coalesce(usage_type, 'scan')
       FROM tasks
      WHERE uuid = $1;"
}

pub(crate) fn task_target_replace_source_target_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            owner::integer
       FROM targets
      WHERE id = $1;"
}

pub(crate) fn task_target_replace_report_count_sql() -> &'static str {
    "SELECT count(*)::bigint FROM reports WHERE task = $1;"
}

pub(crate) fn task_target_replace_live_task_reference_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE target = $1
        AND coalesce(target_location, 0) = 0
        AND coalesce(hidden, 0) = 0;"
}

pub(crate) fn task_target_replace_scope_reference_count_sql() -> &'static str {
    "SELECT count(*)::bigint FROM scope_targets WHERE target = $1;"
}

pub(crate) fn task_target_replace_clone_metadata_sql() -> &'static str {
    "INSERT INTO targets
        (uuid, owner, name, hosts, exclude_hosts, reverse_lookup_only,
         reverse_lookup_unify, comment, port_list, alive_test, creation_time,
         modification_time, allow_simultaneous_ips)
     SELECT make_uuid(),
            $2,
            uniquify('target', name, $2, ' Clone'),
            $3,
            $4,
            reverse_lookup_only,
            reverse_lookup_unify,
            comment,
            port_list,
            alive_test,
            m_now(),
            m_now(),
            allow_simultaneous_ips
       FROM targets
      WHERE id = $1
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn task_target_replace_task_rebind_sql() -> &'static str {
    "UPDATE tasks
        SET target = $2,
            target_location = 0,
            modification_time = m_now()
      WHERE id = $1
        AND target = $3
        AND coalesce(run_status, $4) = $5
        AND coalesce(target_location, 0) = 0
        AND coalesce(hidden, 0) = 0
        AND coalesce(usage_type, 'scan') = 'scan'
      RETURNING uuid::text;"
}
