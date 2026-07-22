// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn host_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN hosts ON hosts.id = tr.resource
        WHERE lower(hosts.uuid) = lower($1)
          AND tr.resource_type = 'host'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn operating_system_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN oss ON oss.id = tr.resource
        WHERE lower(oss.uuid) = lower($1)
          AND tr.resource_type = 'os'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn port_list_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN port_lists pl ON pl.id = tr.resource
        WHERE lower(pl.uuid) = lower($1)
          AND tr.resource_type = 'port_list'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn scan_config_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN configs c ON c.id = tr.resource
        WHERE lower(c.uuid) = lower($1)
          AND tr.resource_type = 'config'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn scanner_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN scanners ON scanners.id = tr.resource
        WHERE lower(scanners.uuid) = lower($1)
          AND tr.resource_type = 'scanner'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn schedule_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN schedules s ON s.id = tr.resource
        WHERE lower(s.uuid) = lower($1)
          AND tr.resource_type = 'schedule'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn target_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN targets ON targets.id = tr.resource
        WHERE lower(targets.uuid) = lower($1)
          AND tr.resource_type = 'target'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn tls_certificate_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN tls_certificates ON tls_certificates.id = tr.resource
        WHERE lower(tls_certificates.uuid) = lower($1)
          AND tr.resource_type = 'tls_certificate'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}
