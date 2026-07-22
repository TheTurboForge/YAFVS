// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn target_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH base AS (
             SELECT t.id AS target_pk,
                    t.uuid,
                    t.name,
                    coalesce(t.comment, '') AS comment,
                    u.uuid AS owner_id,
                    coalesce(t.hosts, '') AS hosts,
                    coalesce(t.exclude_hosts, '') AS exclude_hosts,
                    coalesce(t.alive_test, 0)::bigint AS alive_test,
                    coalesce(t.allow_simultaneous_ips, 0)::int AS allow_simultaneous_ips,
                    coalesce(t.reverse_lookup_only, 0)::int AS reverse_lookup_only,
                    coalesce(t.reverse_lookup_unify, 0)::int AS reverse_lookup_unify,
                    pl.uuid AS port_list_id,
                    pl.name AS port_list_name,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_port,
                    (SELECT coalesce(tld.host_key_pins, '[]') FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_host_key_pins,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_port,
                    coalesce(t.creation_time, 0)::bigint AS creation_time,
                    coalesce(t.modification_time, 0)::bigint AS modification_time,
                    CASE WHEN coalesce(t.hosts, '') = '' THEN 0::bigint
                         ELSE cardinality(string_to_array(t.hosts, ','))::bigint END AS host_entry_count,
                    count(task.id)::bigint AS task_count,
                    coalesce(array_agg(task.uuid ORDER BY task.name) FILTER (WHERE task.id IS NOT NULL), ARRAY[]::text[]) AS task_ids,
                    coalesce(array_agg(task.name ORDER BY task.name) FILTER (WHERE task.id IS NOT NULL), ARRAY[]::text[]) AS task_names
               FROM targets t
               LEFT JOIN users u ON u.id = t.owner
               LEFT JOIN port_lists pl ON pl.id = t.port_list
               LEFT JOIN tasks task
                 ON task.target = t.id
                AND coalesce(task.hidden, 0) = 0
                AND coalesce(task.usage_type, 'scan') = 'scan'
              GROUP BY t.id, t.uuid, t.name, t.comment, u.uuid, t.hosts, t.exclude_hosts,
                       t.alive_test, t.allow_simultaneous_ips, t.reverse_lookup_only,
                       t.reverse_lookup_unify, pl.uuid, pl.name,
                       t.creation_time, t.modification_time
         ),
         filtered AS (
             SELECT * FROM base WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total, *
           FROM filtered
          ORDER BY {sort_sql}, name ASC {limit_clause};"#
    )
}

/// Shared with typed target tag selection. UUID matching remains exact while
/// name, comment, port-list name, and hosts use literal case-insensitive search.
pub(crate) fn target_collection_predicate_sql(
    uuid_expression: &str,
    name_expression: &str,
    comment_expression: &str,
    port_list_name_expression: &str,
    hosts_expression: &str,
    search_parameter: &str,
) -> String {
    format!(
        "({search_parameter} = ''\n             OR lower({uuid_expression}) = lower({search_parameter})\n             OR strpos(lower({name_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({comment_expression}), lower({search_parameter})) > 0\n             OR strpos(lower(coalesce({port_list_name_expression}, '')), lower({search_parameter})) > 0\n             OR strpos(lower({hosts_expression}), lower({search_parameter})) > 0)"
    )
}

pub(crate) fn tag_target_selection_sql() -> String {
    format!(
        "SELECT t.id::integer, t.uuid::text, t.owner::integer\n           FROM targets t\n      LEFT JOIN port_lists pl ON pl.id = t.port_list\n          WHERE {}\n          ORDER BY t.id ASC\n          LIMIT $2\n          FOR UPDATE OF t;",
        target_collection_predicate_sql(
            "t.uuid",
            "coalesce(t.name, '')",
            "coalesce(t.comment, '')",
            "pl.name",
            "coalesce(t.hosts, '')",
            "$1",
        )
    )
}
