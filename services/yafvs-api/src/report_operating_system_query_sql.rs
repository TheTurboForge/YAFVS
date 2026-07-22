// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn report_operating_systems_sql(sort_sql: &str) -> String {
    format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         os_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    sr.uuid AS source_report_id,\n\
                    coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown') AS name,\n\
                    coalesce(os_cpe.value, '') AS cpe\n\
               FROM selected_report sr\n\
               JOIN report_hosts rh ON rh.report = sr.id\n\
               LEFT JOIN report_host_details os_cpe\n\
                 ON os_cpe.report_host = rh.id AND os_cpe.name = 'best_os_cpe'\n\
               LEFT JOIN report_host_details os_txt\n\
                 ON os_txt.report_host = rh.id AND os_txt.name = 'best_os_txt'\n\
              WHERE coalesce(os_txt.value, os_cpe.value, '') <> ''\n\
                AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, sr.uuid,\n\
                       coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown'),\n\
                       coalesce(os_cpe.value, '')\n\
         ),\n\
         operating_system_rows AS (\n\
             SELECT oi.name,\n\
                    oi.cpe,\n\
                    count(DISTINCT oi.host_key)::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    coalesce(max(coalesce(r.severity, 0)), 0)::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT oi.source_report_id), NULL) AS source_report_ids\n\
               FROM os_instances oi\n\
               LEFT JOIN results r\n\
                 ON r.report = oi.source_report\n\
                AND lower(coalesce(nullif(r.host, ''), r.hostname, '')) = oi.host_key\n\
                AND coalesce(r.severity, 0) != -3.0\n\
              GROUP BY oi.name, oi.cpe\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM operating_system_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(name) LIKE '%' || lower($2) || '%'\n\
                     OR lower(cpe) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, name ASC LIMIT $3 OFFSET $4;"
    )
}
