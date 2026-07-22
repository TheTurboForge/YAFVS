// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn report_ports_sql(sort_sql: &str) -> String {
    format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         port_rows AS (\n\
             SELECT coalesce(r.port, '') AS port,\n\
                    CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                         THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                         ELSE '' END AS protocol,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT sr.uuid), NULL) AS source_report_ids\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                AND coalesce(r.port, '') <> ''\n\
              GROUP BY coalesce(r.port, ''),\n\
                       CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                            THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                            ELSE '' END\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM port_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(port) LIKE '%' || lower($2) || '%'\n\
                     OR lower(protocol) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, port ASC LIMIT $3 OFFSET $4;"
    )
}
