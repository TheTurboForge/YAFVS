// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn target_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn target_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM targets
      WHERE uuid = $1;"
}

pub(crate) fn target_trash_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            owner::integer,
            name
       FROM targets_trash
      WHERE uuid = $1;"
}

pub(crate) fn target_source_port_list_is_assignable_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets t
       JOIN port_lists pl ON pl.id = t.port_list
      WHERE t.id = $1
        AND NOT (coalesce(pl.predefined, 0) != 0 OR pl.owner IS NOT NULL);"
}

pub(crate) fn target_source_unassignable_credential_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets_login_data tld
       JOIN credentials c ON c.id = tld.credential
      WHERE tld.target = $1
        AND c.owner IS NULL;"
}

pub(crate) fn target_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets
      WHERE name = $1
        AND id != $2
        AND owner = $3;"
}

pub(crate) fn target_in_use_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE target = $1
        AND target_location = 0
        AND hidden = 0;"
}

pub(crate) fn target_scope_membership_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM scope_targets
      WHERE target = $1;"
}

pub(crate) fn target_trash_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE target = $1
        AND target_location = 1;"
}

pub(crate) fn target_live_uuid_conflict_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets
      WHERE uuid = $1;"
}

pub(crate) fn target_trash_unique_live_owner_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets
      WHERE name = $1
        AND owner = $2;"
}

pub(crate) fn target_trash_blocked_reference_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets_trash tt
      WHERE tt.id = $1
        AND (tt.port_list_location = 1
             OR EXISTS (
                    SELECT 1
                      FROM targets_trash_login_data tld
                     WHERE tld.target = tt.id
                       AND tld.credential_location = 1));"
}

pub(crate) fn target_assignable_port_list_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            coalesce(predefined, 0)::integer
       FROM port_lists
      WHERE uuid = $1;"
}

pub(crate) fn target_assignable_credential_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            type
       FROM credentials
      WHERE uuid = $1;"
}

pub(crate) fn target_current_credential_sql() -> &'static str {
    "SELECT credential::integer
       FROM targets_login_data
      WHERE target = $1
        AND type = $2
      LIMIT 1;"
}

pub(crate) fn target_uuid_by_internal_id_sql() -> &'static str {
    "SELECT uuid::text FROM targets WHERE id = $1;"
}

pub(crate) fn target_update_metadata_sql() -> &'static str {
    "UPDATE targets
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            alive_test = coalesce($4, alive_test),
            allow_simultaneous_ips = coalesce($5, allow_simultaneous_ips),
            reverse_lookup_only = coalesce($6, reverse_lookup_only),
            reverse_lookup_unify = coalesce($7, reverse_lookup_unify),
            port_list = coalesce($8, port_list),
            hosts = coalesce($9, hosts),
            exclude_hosts = coalesce($10, exclude_hosts),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}

pub(crate) fn target_create_metadata_sql() -> &'static str {
    "INSERT INTO targets
        (uuid, owner, name, hosts, exclude_hosts, reverse_lookup_only,
         reverse_lookup_unify, comment, port_list, alive_test, creation_time,
         modification_time, allow_simultaneous_ips)
     VALUES (make_uuid(), $1, $2, $3, $4, $5, $6, coalesce($7, ''), $8, $9,
             m_now(), m_now(), $10)
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn target_clone_metadata_sql() -> &'static str {
    "INSERT INTO targets
        (uuid, owner, name, hosts, exclude_hosts, reverse_lookup_only,
         reverse_lookup_unify, comment, port_list, alive_test, creation_time,
         modification_time, allow_simultaneous_ips)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('target', name, $2, ' Clone')),
            hosts,
            exclude_hosts,
            reverse_lookup_only,
            reverse_lookup_unify,
            coalesce($4, comment),
            port_list,
            alive_test,
            m_now(),
            m_now(),
            allow_simultaneous_ips
       FROM targets
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn target_clone_login_data_sql() -> &'static str {
    "INSERT INTO targets_login_data (target, type, credential, port, host_key_pins)
     SELECT $2, type, credential, port, host_key_pins
       FROM targets_login_data
      WHERE target = $1;"
}

pub(crate) fn target_delete_login_data_by_type_sql() -> &'static str {
    "DELETE FROM targets_login_data
      WHERE target = $1
        AND type = $2;"
}

pub(crate) fn target_insert_login_data_sql() -> &'static str {
    "INSERT INTO targets_login_data (target, type, credential, port, host_key_pins)
     VALUES ($1, $2, $3, $4, $5);"
}

pub(crate) fn target_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'target'
        AND resource = $1
        AND resource_location = 0;"
}

pub(crate) fn target_trash_insert_sql() -> &'static str {
    "INSERT INTO targets_trash
        (uuid, owner, name, hosts, exclude_hosts, comment, port_list,
         port_list_location, reverse_lookup_only, reverse_lookup_unify,
         alive_test, allow_simultaneous_ips, creation_time, modification_time)
     SELECT uuid, owner, name, hosts, exclude_hosts, comment, port_list,
            0, reverse_lookup_only, reverse_lookup_unify, alive_test,
            allow_simultaneous_ips, creation_time, modification_time
       FROM targets
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn target_trash_login_data_insert_sql() -> &'static str {
    "INSERT INTO targets_trash_login_data
        (target, type, credential, port, credential_location, host_key_pins)
     SELECT $1, type, credential, port, 0, host_key_pins
       FROM targets_login_data
      WHERE target = $2;"
}

pub(crate) fn target_trash_task_relink_sql() -> &'static str {
    "UPDATE tasks
        SET target = $1,
            target_location = 1
      WHERE target = $2
        AND target_location = 0;"
}

pub(crate) fn target_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'target'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn target_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'target'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn target_delete_login_data_sql() -> &'static str {
    "DELETE FROM targets_login_data WHERE target = $1;"
}

pub(crate) fn target_delete_metadata_sql() -> &'static str {
    "DELETE FROM targets WHERE id = $1;"
}

pub(crate) fn target_restore_metadata_sql() -> &'static str {
    "INSERT INTO targets
        (uuid, owner, name, hosts, exclude_hosts, comment, port_list,
         reverse_lookup_only, reverse_lookup_unify, alive_test,
         allow_simultaneous_ips, creation_time, modification_time)
     SELECT uuid, owner, name, hosts, exclude_hosts, comment, port_list,
            reverse_lookup_only, reverse_lookup_unify, alive_test,
            allow_simultaneous_ips, creation_time, modification_time
       FROM targets_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn target_restore_login_data_sql() -> &'static str {
    "INSERT INTO targets_login_data (target, type, credential, port, host_key_pins)
     SELECT $2, type, credential, port, host_key_pins
       FROM targets_trash_login_data
      WHERE target = $1;"
}

pub(crate) fn target_restore_task_relink_sql() -> &'static str {
    "UPDATE tasks
        SET target = $2,
            target_location = 0
      WHERE target = $1
        AND target_location = 1;"
}

pub(crate) fn target_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'target'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn target_trash_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'target'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn target_delete_trash_login_data_sql() -> &'static str {
    "DELETE FROM targets_trash_login_data WHERE target = $1;"
}

pub(crate) fn target_trash_tag_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'target'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn target_trash_tag_trash_delete_sql() -> &'static str {
    "DELETE FROM tag_resources_trash
      WHERE resource_type = 'target'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn target_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM targets_trash WHERE id = $1;"
}
