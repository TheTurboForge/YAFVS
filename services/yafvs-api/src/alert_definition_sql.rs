// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn alert_definition_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn alert_definition_operator_owner_for_update_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1 FOR UPDATE;"
}

pub(crate) fn alert_definition_read_sql() -> &'static str {
    r#"SELECT a.id::integer AS internal_id,
              a.owner::integer AS owner_id,
              a.xmin::text AS revision,
              coalesce(a.name, '')::text AS name,
              coalesce(a.comment, '')::text AS comment,
              coalesce(a.active, 0) <> 0 AS active,
              coalesce(a.event, 0)::integer AS event,
              coalesce(a.condition, 0)::integer AS condition,
              coalesce(a.method, 0)::integer AS method,
              a.filter::integer AS filter_id,
              coalesce((SELECT aed.data
                          FROM alert_event_data aed
                         WHERE aed.alert = a.id
                           AND aed.name = 'status'
                         ORDER BY aed.id
                         LIMIT 1), '')::text AS status,
              (SELECT count(*)::bigint
                 FROM alert_condition_data acd
                WHERE acd.alert = a.id) AS condition_data_count,
              ARRAY(SELECT aed.name::text
                      FROM alert_event_data aed
                     WHERE aed.alert = a.id
                     ORDER BY aed.id)::text[] AS event_names,
              ARRAY(SELECT aed.data::text
                      FROM alert_event_data aed
                     WHERE aed.alert = a.id
                     ORDER BY aed.id)::text[] AS event_values,
              ARRAY(SELECT amd.name::text
                      FROM alert_method_data amd
                     WHERE amd.alert = a.id
                     ORDER BY amd.id)::text[] AS method_names,
              ARRAY(SELECT CASE WHEN amd.name = 'snmp_community'
                                THEN NULL::text
                                ELSE amd.data::text
                           END
                     FROM alert_method_data amd
                     WHERE amd.alert = a.id
                     ORDER BY amd.id)::text[] AS method_values,
              ((SELECT count(*)
                  FROM alert_method_data amd
                 WHERE amd.alert = a.id
                   AND amd.name = 'snmp_community') = 1
               AND (SELECT count(*)
                      FROM alert_method_data amd
                     WHERE amd.alert = a.id
                       AND amd.name = 'snmp_community'
                       AND coalesce(amd.data, '') <> '') = 1) AS snmp_community_configured
         FROM alerts a
        WHERE a.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn alert_definition_state_for_update_sql() -> &'static str {
    r#"SELECT a.id::integer,
              a.owner::integer,
              a.xmin::text,
              coalesce(a.method, 0)::integer,
              (coalesce(a.method, 0) = 9
               AND (SELECT count(*)
                      FROM alert_method_data amd
                     WHERE amd.alert = a.id
                       AND amd.name = 'snmp_community') = 1
               AND (SELECT count(*)
                      FROM alert_method_data amd
                     WHERE amd.alert = a.id
                       AND amd.name = 'snmp_community'
                       AND coalesce(amd.data, '') <> '') = 1) AS snmp_community_configured
         FROM alerts a
        WHERE a.uuid = $1
          FOR UPDATE;"#
}

pub(crate) fn alert_definition_credential_reference_sql() -> &'static str {
    r#"SELECT c.id::integer,
              c.owner::integer,
              coalesce(c.type, '')::text,
              coalesce((SELECT cd.value
                          FROM credentials_data cd
                         WHERE cd.credential = c.id
                           AND cd.type = 'username'
                         ORDER BY cd.id
                         LIMIT 1), '')::text AS username,
              (SELECT count(*)::bigint
                 FROM credentials_data cd
                WHERE cd.credential = c.id
                  AND cd.type = 'username') AS username_count
         FROM credentials c
        WHERE c.uuid = $1
          FOR SHARE;"#
}

pub(crate) fn alert_definition_report_format_reference_sql() -> &'static str {
    "SELECT id::integer FROM report_formats WHERE uuid = $1 FOR SHARE;"
}

pub(crate) fn alert_definition_task_reference_sql() -> &'static str {
    r#"SELECT id::integer, owner::integer
         FROM tasks
        WHERE uuid = $1
          AND coalesce(hidden, 0) = 0
          AND coalesce(usage_type, 'scan') = 'scan'
          FOR SHARE;"#
}

pub(crate) fn alert_definition_update_metadata_sql() -> &'static str {
    r#"UPDATE alerts
          SET name = $2,
              comment = $3,
              active = $4,
              event = 1,
              condition = 1,
              method = $5,
              filter = NULL,
              modification_time = m_now()
        WHERE id = $1
        RETURNING uuid::text;"#
}

pub(crate) fn alert_definition_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alerts
      WHERE name = $1
        AND id != $2;"
}

pub(crate) fn alert_definition_delete_condition_data_sql() -> &'static str {
    "DELETE FROM alert_condition_data WHERE alert = $1;"
}

pub(crate) fn alert_definition_delete_event_data_sql() -> &'static str {
    "DELETE FROM alert_event_data WHERE alert = $1;"
}

pub(crate) fn alert_definition_delete_method_data_sql() -> &'static str {
    "DELETE FROM alert_method_data
      WHERE alert = $1
        AND (NOT $2::boolean OR name <> 'snmp_community');"
}

pub(crate) fn alert_definition_insert_event_data_sql() -> &'static str {
    "INSERT INTO alert_event_data (alert, name, data) VALUES ($1, $2, $3);"
}

pub(crate) fn alert_definition_insert_method_data_sql() -> &'static str {
    "INSERT INTO alert_method_data (alert, name, data) VALUES ($1, $2, $3);"
}
