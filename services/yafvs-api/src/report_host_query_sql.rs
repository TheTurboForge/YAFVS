// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn report_hosts_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH selected_report AS (
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)
         ),
         host_base AS (
             SELECT rh.id AS report_host_id,
                    lower(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host_key,
                    coalesce(nullif(rh.host, ''), rh.hostname, '') AS host,
                    nullif(rh.hostname, '') AS hostname,
                    coalesce(rh.start_time, 0)::bigint AS start_time_unix,
                    coalesce(rh.end_time, 0)::bigint AS end_time_unix,
                    sr.uuid AS source_report_id
               FROM selected_report sr
               JOIN report_hosts rh ON rh.report = sr.id
              WHERE coalesce(nullif(rh.host, ''), rh.hostname, '') <> ''
         ),
         detail_rows AS (
             SELECT hb.report_host_id,
                    nullif(max(rhd.value) FILTER (WHERE rhd.name = 'best_os_cpe'), '') AS best_os_cpe,
                    nullif(max(rhd.value) FILTER (WHERE rhd.name = 'best_os_txt'), '') AS best_os_txt,
                    count(*) FILTER (WHERE rhd.name = 'App')::bigint AS applications_count,
                    max(CASE WHEN rhd.name = 'distance' AND rhd.value ~ '^[0-9]+$' THEN rhd.value::bigint ELSE NULL END) AS distance,
                    bool_or((lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')
                            AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%success%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%succeeded%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%logged in%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%valid credential%')) AS auth_success,
                    bool_or((lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')
                            AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%fail%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%denied%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%invalid%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%refused%')) AS auth_failure,
                    bool_or(lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                            OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                            OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%') AS has_credential_path
               FROM host_base hb
               LEFT JOIN report_host_details rhd ON rhd.report_host = hb.report_host_id
              GROUP BY hb.report_host_id
         ),
         result_counts AS (
             SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,
                    count(*)::bigint AS result_count,
                    count(DISTINCT nullif(r.nvt, '')) FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,
                    count(DISTINCT nullif(r.port, ''))::bigint AS ports_count,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 9.0)::bigint AS severity_critical,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 7.0 AND coalesce(r.severity, 0) < 9.0)::bigint AS severity_high,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 4.0 AND coalesce(r.severity, 0) < 7.0)::bigint AS severity_medium,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) > 0.0 AND coalesce(r.severity, 0) < 4.0)::bigint AS severity_low,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) = 0.0)::bigint AS severity_log,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) = -1.0)::bigint AS severity_false_positive,
                    coalesce(max(r.severity) FILTER (WHERE coalesce(r.severity, 0) > 0), 0)::double precision AS max_severity
               FROM selected_report sr
               JOIN results r ON r.report = sr.id
              WHERE coalesce(r.severity, 0) != -3.0
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
              GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, ''))
         ),
         rows AS (
             SELECT hb.host, hb.hostname, dr.best_os_cpe, dr.best_os_txt,
                    coalesce(rc.ports_count, 0)::bigint AS ports_count,
                    coalesce(dr.applications_count, 0)::bigint AS applications_count,
                    dr.distance,
                    CASE WHEN coalesce(dr.auth_success, false) THEN 'authenticated'
                         WHEN coalesce(dr.auth_failure, false) THEN 'authentication_failed'
                         WHEN coalesce(dr.has_credential_path, false) THEN 'unknown'
                         ELSE 'no_credential_path' END AS authentication_state,
                    hb.start_time_unix, hb.end_time_unix,
                    coalesce(rc.result_count, 0)::bigint AS result_count,
                    coalesce(rc.vulnerability_count, 0)::bigint AS vulnerability_count,
                    coalesce(rc.severity_critical, 0)::bigint AS severity_critical,
                    coalesce(rc.severity_high, 0)::bigint AS severity_high,
                    coalesce(rc.severity_medium, 0)::bigint AS severity_medium,
                    coalesce(rc.severity_low, 0)::bigint AS severity_low,
                    coalesce(rc.severity_log, 0)::bigint AS severity_log,
                    coalesce(rc.severity_false_positive, 0)::bigint AS severity_false_positive,
                    coalesce(rc.max_severity, 0)::double precision AS max_severity,
                    hb.source_report_id
               FROM host_base hb
               LEFT JOIN detail_rows dr ON dr.report_host_id = hb.report_host_id
               LEFT JOIN result_counts rc ON rc.host_key = hb.host_key
         ),
         filtered AS (
             SELECT * FROM rows
              WHERE ($2 = ''
                     OR lower(host) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(best_os_cpe, '')) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(best_os_txt, '')) LIKE '%' || lower($2) || '%'
                     OR lower(authentication_state) LIKE '%' || lower($2) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, host ASC LIMIT $3 OFFSET $4;"#
    )
}
