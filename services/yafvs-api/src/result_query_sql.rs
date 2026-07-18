// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn result_detail_sql() -> &'static str {
    r#"SELECT r.uuid AS id,
              lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,
              h.uuid AS host_asset_id,
              nullif(r.hostname, '') AS hostname,
              coalesce(r.port, '') AS port,
              coalesce(r.nvt, '') AS nvt_oid,
              coalesce(n.name, r.nvt, '') AS name,
              nullif(n.family, '') AS nvt_family,
              n.epss_score::double precision AS epss_score,
              n.epss_percentile::double precision AS epss_percentile,
              n.epss_cve AS epss_cve,
              n.epss_severity::double precision AS epss_severity,
              n.max_epss_score::double precision AS max_epss_score,
              n.max_epss_percentile::double precision AS max_epss_percentile,
              n.max_epss_cve AS max_epss_cve,
              n.max_epss_severity::double precision AS max_epss_severity,
              CASE
                WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                THEN refs.cves
                WHEN coalesce(n.cve, '') <> ''
                THEN regexp_split_to_array(n.cve, '\\s*,\\s*')
                ELSE ARRAY[]::text[]
              END AS cves,
              coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
              coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs,
              nullif(r.description, '') AS description,
              nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,
              nullif(n.summary, '') AS summary,
              nullif(n.insight, '') AS insight,
              nullif(n.affected, '') AS affected,
              nullif(n.impact, '') AS impact,
              nullif(n.detection, '') AS detection,
              nullif(n.solution_type, '') AS solution_type,
              nullif(n.solution, '') AS solution,
              coalesce(r.severity, 0)::double precision AS severity,
              coalesce(r.qod, 0)::bigint AS qod,
              nullif(r.nvt_version, '') AS scan_nvt_version,
              coalesce(r.date, 0)::bigint AS created_at_unix,
              rep.uuid AS source_report_id,
              coalesce(nullif(t.name, ''), rep.uuid) AS source_report_name,
              t.uuid AS task_id,
              t.name AS task_name
         FROM results r
         JOIN reports rep ON rep.id = r.report
         LEFT JOIN tasks t ON t.id = coalesce(r.task, rep.task)
         LEFT JOIN hosts h ON lower(h.name) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))
         LEFT JOIN nvts n ON n.oid = r.nvt
         LEFT JOIN LATERAL (
             SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                      FILTER (WHERE vr.ref_id IS NOT NULL
                              AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                    array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                      FILTER (WHERE vr.ref_id IS NOT NULL
                              AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                    array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                      FILTER (WHERE vr.ref_id IS NOT NULL
                              AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
               FROM vt_refs vr
              WHERE vr.vt_oid = r.nvt
         ) refs ON true
        WHERE lower(r.uuid) = lower($1)
          AND coalesce(r.severity, 0) != -3.0
          AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
          AND (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
        LIMIT 1;"#
}

pub(crate) fn result_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN results r ON r.id = tr.resource
        WHERE lower(r.uuid) = lower($1)
          AND tr.resource_type = 'result'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) fn result_effective_overrides_sql() -> &'static str {
    r#"WITH matched AS (
         SELECT DISTINCT ON (o.id)
                o.uuid AS id,
                coalesce(o.nvt, '') AS nvt_id,
                CASE
                  WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                  ELSE coalesce(n.name, o.nvt, '')
                END AS nvt_name,
                CASE
                  WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                  ELSE 'nvt'
                END AS nvt_type,
                coalesce(o.text, '') AS text,
                coalesce(o.hosts, '') AS hosts,
                coalesce(o.port, '') AS port,
                o.severity::double precision AS severity,
                o.new_severity::double precision AS new_severity,
                coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                coalesce(o.end_time, 0)::bigint AS end_time_unix,
                CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int
           FROM result_overrides ro
           JOIN results r ON r.id = ro.result
           JOIN overrides o ON o.id = ro.override
      LEFT JOIN nvts n ON n.oid = o.nvt
          WHERE lower(r.uuid) = lower($1)
          ORDER BY o.id, coalesce(o.modification_time, o.creation_time, 0) DESC, o.uuid ASC
     )
     SELECT * FROM matched
      ORDER BY modified_at_unix DESC, created_at_unix DESC, id ASC;"#
}
