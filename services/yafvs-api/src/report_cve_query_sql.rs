// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn report_cves_sql(sort_sql: &str) -> String {
    format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         cve_rows AS (\n\
             SELECT vr.ref_id AS id,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS affected_system_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT sr.uuid), NULL) AS source_report_ids\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
               JOIN vt_refs vr ON vr.vt_oid = r.nvt AND vr.type = 'cve'\n\
              WHERE coalesce(r.severity, 0) > 0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
              GROUP BY vr.ref_id\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM cve_rows\n\
              WHERE ($2 = '' OR lower(id) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $3 OFFSET $4;"
    )
}
