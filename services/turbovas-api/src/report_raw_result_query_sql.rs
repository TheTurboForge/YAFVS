// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn report_raw_results_sql(sort_sql: &str) -> String {
    format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         raw_rows AS (\n\
             SELECT r.uuid AS id,\n\
                    sr.uuid AS source_report_id,\n\
                    t.uuid AS task_id,\n\
                    u.uuid AS owner_id,\n\
                    r.host,\n\
                    r.hostname,\n\
                    r.port,\n\
                    r.nvt AS nvt_oid,\n\
                    r.type AS result_type,\n\
                    r.description,\n\
                    r.nvt_version AS scan_nvt_version,\n\
                    r.severity::double precision AS severity,\n\
                    r.qod::bigint AS qod,\n\
                    r.qod_type,\n\
                    r.date::bigint AS created_at_unix,\n\
                    r.path,\n\
                    r.hash_value\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
          LEFT JOIN tasks t ON t.id = r.task\n\
          LEFT JOIN users u ON u.id = r.owner\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM raw_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(id) LIKE '%' || lower($2) || '%'\n\
                     OR lower(coalesce(host, '')) LIKE '%' || lower($2) || '%'\n\
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($2) || '%'\n\
                     OR lower(coalesce(port, '')) LIKE '%' || lower($2) || '%'\n\
                     OR lower(coalesce(nvt_oid, '')) LIKE '%' || lower($2) || '%'\n\
                     OR lower(coalesce(result_type, '')) LIKE '%' || lower($2) || '%'\n\
                     OR lower(coalesce(description, '')) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $3 OFFSET $4;"
    )
}
