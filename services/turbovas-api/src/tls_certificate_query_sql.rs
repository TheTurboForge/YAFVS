// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn tls_certificate_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH tls_rows AS (
             SELECT c.uuid AS id,
                    coalesce(nullif(c.subject_dn, ''), c.uuid) AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.subject_dn, '') AS subject_dn,
                    coalesce(c.issuer_dn, '') AS issuer_dn,
                    coalesce(c.serial, '') AS serial,
                    coalesce(c.md5_fingerprint, '') AS md5_fingerprint,
                    coalesce(c.sha256_fingerprint, '') AS sha256_fingerprint,
                    coalesce(c.activation_time, 0)::bigint AS activation_time_unix,
                    coalesce(c.expiration_time, 0)::bigint AS expiration_time_unix,
                    coalesce(max(src.timestamp), 0)::bigint AS last_seen_unix,
                    count(DISTINCT lower(loc.host_ip))::bigint AS source_host_count,
                    count(DISTINCT loc.port)::bigint AS source_port_count,
                    count(DISTINCT src.uuid)::bigint AS source_count,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM tls_certificates c
               LEFT JOIN tls_certificate_sources src ON src.tls_certificate = c.id
               LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
              GROUP BY c.id, c.uuid, c.subject_dn, c.comment, c.issuer_dn,
                       c.serial, c.md5_fingerprint, c.sha256_fingerprint,
                       c.activation_time, c.expiration_time,
                       c.creation_time, c.modification_time
         ),
         filtered AS (
             SELECT * FROM tls_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(subject_dn) LIKE '%' || lower($1) || '%'
                     OR lower(issuer_dn) LIKE '%' || lower($1) || '%'
                     OR lower(serial) LIKE '%' || lower($1) || '%'
                     OR lower(md5_fingerprint) LIKE '%' || lower($1) || '%'
                     OR lower(sha256_fingerprint) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, subject_dn ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn tls_certificate_asset_detail_sql() -> &'static str {
    r#"SELECT c.uuid AS id,
              coalesce(nullif(c.subject_dn, ''), c.uuid) AS name,
              coalesce(c.comment, '') AS comment,
              coalesce(c.subject_dn, '') AS subject_dn,
              coalesce(c.issuer_dn, '') AS issuer_dn,
              coalesce(c.serial, '') AS serial,
              coalesce(c.md5_fingerprint, '') AS md5_fingerprint,
              coalesce(c.sha256_fingerprint, '') AS sha256_fingerprint,
              coalesce(c.activation_time, 0)::bigint AS activation_time_unix,
              coalesce(c.expiration_time, 0)::bigint AS expiration_time_unix,
              CAST (((coalesce(c.expiration_time, 0) >= m_now()
                       OR coalesce(c.expiration_time, 0) = -1)
                      AND (coalesce(c.activation_time, 0) <= m_now()
                           OR coalesce(c.activation_time, 0) = -1)) AS integer) AS valid_int,
              coalesce(c.trust, 0)::integer AS trust_int,
              (CASE WHEN (coalesce(c.activation_time, 0) = -1)
                          OR (coalesce(c.expiration_time, 0) = 1)
                    THEN 'unknown'
                    WHEN (coalesce(c.expiration_time, 0) < m_now()
                          AND coalesce(c.expiration_time, 0) != 0)
                    THEN 'expired'
                    WHEN (coalesce(c.activation_time, 0) > m_now())
                    THEN 'inactive'
                    ELSE 'valid' END) AS time_status,
              coalesce(max(src.timestamp), 0)::bigint AS last_seen_unix,
              count(DISTINCT lower(loc.host_ip))::bigint AS source_host_count,
              count(DISTINCT loc.port)::bigint AS source_port_count,
              count(DISTINCT src.uuid)::bigint AS source_count,
              coalesce(c.creation_time, 0)::bigint AS created_at_unix,
              coalesce(c.modification_time, 0)::bigint AS modified_at_unix
         FROM tls_certificates c
         LEFT JOIN tls_certificate_sources src ON src.tls_certificate = c.id
         LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
        WHERE c.uuid = $1
        GROUP BY c.id, c.uuid, c.subject_dn, c.comment, c.issuer_dn,
                 c.serial, c.md5_fingerprint, c.sha256_fingerprint,
                 c.activation_time, c.expiration_time,
                 c.creation_time, c.modification_time
        LIMIT 1;"#
}

pub(crate) fn tls_certificate_sources_sql() -> &'static str {
    r#"SELECT src.uuid AS id,
              coalesce(src.timestamp, 0)::bigint AS timestamp_unix,
              coalesce(src.tls_versions, '') AS tls_versions,
              loc.uuid AS location_id,
              coalesce(loc.host_ip, '') AS location_host_ip,
              coalesce(loc.port, '') AS location_port,
              host_asset.uuid AS host_asset_id,
              origin.uuid AS origin_uuid,
              coalesce(origin.origin_type, '') AS origin_type,
              coalesce(origin.origin_id, '') AS origin_resource_id,
              coalesce(origin.origin_data, '') AS origin_data
         FROM tls_certificates c
         JOIN tls_certificate_sources src ON src.tls_certificate = c.id
         LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
         LEFT JOIN tls_certificate_origins origin ON origin.id = src.origin
         LEFT JOIN LATERAL (
              SELECT h.uuid
                FROM host_identifiers hi
                JOIN hosts h ON h.id = hi.host
               WHERE hi.name = 'ip'
                 AND hi.value = loc.host_ip
                 AND hi.source_id = origin.origin_id
               ORDER BY hi.modification_time DESC NULLS LAST, hi.id DESC
               LIMIT 1
         ) host_asset ON true
        WHERE c.uuid = $1
        ORDER BY src.timestamp DESC NULLS LAST, src.uuid ASC;"#
}

pub(crate) fn tls_certificate_pem_sql() -> &'static str {
    r#"SELECT c.uuid AS id,
              coalesce(c.certificate, '') AS certificate
         FROM tls_certificates c
        WHERE c.uuid = $1
        LIMIT 1;"#
}
