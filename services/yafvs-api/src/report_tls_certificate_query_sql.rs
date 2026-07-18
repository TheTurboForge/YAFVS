// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn report_tls_certificates_sql(sort_sql: &str) -> String {
    format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_report sr\n\
               JOIN report_hosts rh ON rh.report = sr.id\n\
              WHERE coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
         ),\n\
         tls_rows AS (\n\
             SELECT c.uuid AS id,\n\
                    coalesce(c.sha256_fingerprint, '') AS fingerprint_sha256,\n\
                    coalesce(c.subject_dn, '') AS subject,\n\
                    coalesce(c.issuer_dn, '') AS issuer,\n\
                    coalesce(c.serial, '') AS serial,\n\
                    coalesce(c.activation_time, 0)::bigint AS not_before_unix,\n\
                    coalesce(c.expiration_time, 0)::bigint AS not_after_unix,\n\
                    count(DISTINCT lower(loc.host_ip))::bigint AS host_count,\n\
                    count(DISTINCT loc.port)::bigint AS port_count,\n\
                    count(DISTINCT src.uuid)::bigint AS result_count,\n\
                    array_remove(array_agg(DISTINCT sr.uuid), NULL) AS source_report_ids\n\
               FROM selected_report sr\n\
               JOIN tls_certificate_origins origin\n\
                 ON origin.origin_type = 'Report'\n\
                AND origin.origin_id = sr.uuid\n\
               JOIN tls_certificate_sources src ON src.origin = origin.id\n\
               JOIN tls_certificates c ON c.id = src.tls_certificate\n\
               JOIN tls_certificate_locations loc ON loc.id = src.location\n\
               JOIN selected_hosts sh ON sh.host_key = lower(loc.host_ip)\n\
              GROUP BY c.uuid, c.sha256_fingerprint, c.subject_dn, c.issuer_dn,\n\
                       c.serial, c.activation_time, c.expiration_time\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM tls_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(id) LIKE '%' || lower($2) || '%'\n\
                     OR lower(fingerprint_sha256) LIKE '%' || lower($2) || '%'\n\
                     OR lower(subject) LIKE '%' || lower($2) || '%'\n\
                     OR lower(issuer) LIKE '%' || lower($2) || '%'\n\
                     OR lower(serial) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $3 OFFSET $4;"
    )
}
