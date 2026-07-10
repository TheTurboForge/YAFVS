// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn report_errors_sql(sort_sql: &str) -> String {
    format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         error_rows AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(r.description, '') AS description,\n\
                    sr.uuid AS source_report_id,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
              WHERE (r.type = 'Error Message' OR coalesce(r.severity, 0) = -3)\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM error_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(id) LIKE '%' || lower($2) || '%'\n\
                     OR lower(host) LIKE '%' || lower($2) || '%'\n\
                     OR lower(port) LIKE '%' || lower($2) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($2) || '%'\n\
                     OR lower(description) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $3 OFFSET $4;"
    )
}
