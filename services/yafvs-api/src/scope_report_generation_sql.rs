// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn scope_report_generation_state_sql() -> &'static str {
    "SELECT id::integer, owner::integer, coalesce(is_global, 0)::integer,
            uuid, name, protection_requirement
       FROM scopes
      WHERE lower(uuid) = lower($1)
      FOR UPDATE;"
}

pub(crate) fn scope_report_generation_insert_sql() -> &'static str {
    "INSERT INTO scope_reports
       (uuid, scope, scope_uuid, scope_name, protection_requirement,
        generated_by, creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, $3, $4, $5, m_now(), m_now())
     RETURNING id::integer, uuid;"
}

pub(crate) fn scope_report_generation_members_sql() -> &'static str {
    "INSERT INTO scope_report_hosts
       (scope_report, host_uuid, host_name, added_time)
     SELECT $3, sh.host_uuid, sh.host_name, m_now()
       FROM scope_hosts sh
      WHERE NOT $2 AND sh.scope = $1;"
}

pub(crate) fn scope_report_generation_sources_sql() -> &'static str {
    "WITH selected_targets AS (
       SELECT t.id AS target
         FROM targets t
        WHERE $2
       UNION ALL
       SELECT st.target
         FROM scope_targets st
        WHERE NOT $2 AND st.scope = $1
     )
     INSERT INTO scope_report_sources
       (scope_report, target, target_uuid, target_name, source_report,
        source_report_uuid, task, task_uuid, task_name, scan_start, scan_end,
        selected_time)
     SELECT $3, t.id, t.uuid, t.name, r.id, r.uuid, task.id, task.uuid,
            task.name, r.start_time, r.end_time, m_now()
       FROM selected_targets selected
       JOIN targets t ON t.id = selected.target
       JOIN LATERAL (
         SELECT reports.*
           FROM reports
           JOIN tasks ON tasks.id = reports.task
          WHERE tasks.target = t.id
            AND coalesce(tasks.usage_type, 'scan') = 'scan'
            AND run_status_name(reports.scan_run_status) = 'Done'
          ORDER BY coalesce(reports.end_time, reports.creation_time) DESC,
                   reports.id DESC
          LIMIT 1
       ) r ON TRUE
       JOIN tasks task ON task.id = r.task;"
}

pub(crate) fn scope_report_generation_counts_sql() -> &'static str {
    r#"WITH source_summary AS (
         SELECT count(*)::integer AS source_report_count,
                count(DISTINCT target_uuid)::integer AS source_target_count
           FROM scope_report_sources
          WHERE scope_report = $1
       ),
       member_summary AS (
         SELECT CASE WHEN $3
                     THEN (SELECT count(*)::integer FROM hosts)
                     ELSE (SELECT count(*)::integer
                             FROM scope_report_hosts
                            WHERE scope_report = $1)
                END AS member_host_count
       ),
       evidence_hosts AS (
         SELECT count(DISTINCT lower(rh.host))::integer AS evidence_host_count
           FROM report_hosts rh
           JOIN scope_report_sources srs ON srs.source_report = rh.report
          WHERE srs.scope_report = $1
            AND coalesce(rh.host, '') <> ''
            AND ($3 OR EXISTS (
                  SELECT 1 FROM scope_report_hosts srh
                   WHERE srh.scope_report = $1
                     AND lower(srh.host_name) = lower(rh.host)))
       ),
       deduped_results AS (
         SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,
                coalesce(r.nvt, '') AS nvt_key,
                coalesce(r.port, '') AS port_key,
                max(coalesce(r.severity, 0))::double precision AS severity
           FROM results r
           JOIN scope_report_sources srs ON srs.source_report = r.report
          WHERE srs.scope_report = $1
            AND coalesce(r.severity, 0) != -3.0
            AND ($3 OR EXISTS (
                  SELECT 1 FROM scope_report_hosts srh
                   WHERE srh.scope_report = $1
                     AND (lower(srh.host_name) = lower(coalesce(nullif(r.host, ''), r.hostname))
                          OR lower(srh.host_name) = lower(coalesce(nullif(r.hostname, ''), r.host)))))
          GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),
                   coalesce(r.nvt, ''), coalesce(r.port, '')
       ),
       result_summary AS (
         SELECT count(*)::integer AS result_count,
                count(*) FILTER (WHERE severity > 0)::integer AS vulnerability_count
           FROM deduped_results
       ),
       report_summary AS (
         SELECT coalesce(max(r.severity), 0)::double precision AS max_severity
           FROM results r
           JOIN scope_report_sources srs ON srs.source_report = r.report
          WHERE srs.scope_report = $1
            AND ($3 OR EXISTS (
                  SELECT 1 FROM scope_report_hosts srh
                   WHERE srh.scope_report = $1
                     AND (lower(srh.host_name) = lower(coalesce(nullif(r.host, ''), r.hostname))
                          OR lower(srh.host_name) = lower(coalesce(nullif(r.hostname, ''), r.host)))))
       ),
       latest_evidence AS (
         SELECT coalesce(max(coalesce(r.end_time, r.creation_time)), 0)::integer AS latest_evidence_time
           FROM reports r
           JOIN scope_report_sources srs ON srs.source_report = r.id
          WHERE srs.scope_report = $1
       ),
       excluded AS (
         SELECT CASE WHEN $3 THEN 0 ELSE count(*)::integer END AS excluded_candidate_host_count
           FROM (
             SELECT DISTINCT lower(rh.host) AS host_key
               FROM report_hosts rh
               JOIN scope_report_sources srs ON srs.source_report = rh.report
              WHERE srs.scope_report = $1 AND coalesce(rh.host, '') <> ''
             EXCEPT
             SELECT lower(srh.host_name)
               FROM scope_report_hosts srh
              WHERE srh.scope_report = $1
           ) excluded_hosts
       )
     UPDATE scope_reports sr
        SET source_report_count = source_summary.source_report_count,
            source_target_count = source_summary.source_target_count,
            member_host_count = member_summary.member_host_count,
            evidence_host_count = evidence_hosts.evidence_host_count,
            missing_host_count = greatest(member_summary.member_host_count - evidence_hosts.evidence_host_count, 0),
            result_count = result_summary.result_count,
            vulnerability_count = result_summary.vulnerability_count,
            max_severity = report_summary.max_severity,
            latest_evidence_time = latest_evidence.latest_evidence_time,
            excluded_candidate_host_count = excluded.excluded_candidate_host_count,
            modification_time = m_now()
       FROM source_summary, member_summary, evidence_hosts, result_summary,
            report_summary, latest_evidence, excluded
      WHERE sr.id = $1;"#
}

pub(crate) fn scope_report_generation_system_metrics_sql() -> &'static str {
    r#"WITH source_reports AS (
         SELECT source_report, target
           FROM scope_report_sources
          WHERE scope_report = $1
       ),
       alive AS (
         SELECT lower(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host_key,
                min(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host,
                count(DISTINCT rh.report)::integer AS source_report_count,
                bool_or(EXISTS (
                  SELECT 1 FROM targets_login_data tld
                   WHERE tld.target = source_reports.target
                     AND coalesce(tld.credential, 0) > 0)) AS has_credential_path,
                bool_or(EXISTS (
                  SELECT 1 FROM report_host_details rhd
                   WHERE rhd.report_host = rh.id
                     AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')
                     AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%success%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%succeeded%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%logged in%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%valid credential%'))) AS auth_success,
                bool_or(EXISTS (
                  SELECT 1 FROM report_host_details rhd
                   WHERE rhd.report_host = rh.id
                     AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')
                     AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%fail%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%denied%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%invalid%'
                          OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%refused%'))) AS auth_failure
           FROM report_hosts rh
           JOIN source_reports ON source_reports.source_report = rh.report
          WHERE coalesce(nullif(rh.host, ''), rh.hostname, '') <> ''
            AND ($3 OR EXISTS (
                  SELECT 1 FROM scope_report_hosts srh
                   WHERE srh.scope_report = $1
                     AND lower(srh.host_name) = lower(coalesce(nullif(rh.host, ''), rh.hostname, ''))))
          GROUP BY lower(coalesce(nullif(rh.host, ''), rh.hostname, ''))
       ),
       vuln_by_system AS (
         SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,
                coalesce(nullif(r.nvt, ''), 'unknown') AS nvt_oid,
                max(coalesce(r.severity, 0))::double precision AS cvss_score
           FROM results r
           JOIN source_reports ON source_reports.source_report = r.report
          WHERE coalesce(r.severity, 0) > 0 AND coalesce(r.severity, 0) != -3.0
            AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
            AND ($3 OR EXISTS (
                  SELECT 1 FROM scope_report_hosts srh
                   WHERE srh.scope_report = $1
                     AND lower(srh.host_name) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))))
          GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),
                   coalesce(nullif(r.nvt, ''), 'unknown')
       ),
       system_load AS (
         SELECT host_key, sum(cvss_score)::double precision AS cvss_load,
                max(cvss_score)::double precision AS max_cvss,
                count(*)::integer AS vulnerability_count
           FROM vuln_by_system GROUP BY host_key
       )
     INSERT INTO scope_report_system_metrics
       (scope_report, host, cvss_load, max_cvss, vulnerability_count,
        authentication_state, source_report_count)
     SELECT $1, alive.host, coalesce(system_load.cvss_load, 0),
            coalesce(system_load.max_cvss, 0),
            coalesce(system_load.vulnerability_count, 0),
            CASE WHEN alive.auth_success THEN 'authenticated'
                 WHEN alive.auth_failure THEN 'authentication_failed'
                 WHEN alive.has_credential_path THEN 'unknown'
                 ELSE 'no_credential_path' END,
            alive.source_report_count
       FROM alive LEFT JOIN system_load USING (host_key);"#
}

pub(crate) fn scope_report_generation_vulnerability_metrics_sql() -> &'static str {
    r#"WITH source_reports AS (
         SELECT source_report
           FROM scope_report_sources
          WHERE scope_report = $1
       ),
       deduped_results AS (
         SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,
                coalesce(nullif(r.nvt, ''), 'unknown') AS nvt_oid,
                max(coalesce(n.name, r.nvt, 'Unknown vulnerability')) AS nvt_name,
                max(coalesce(r.severity, 0))::double precision AS cvss_score,
                r.report AS source_report
           FROM results r
           JOIN source_reports ON source_reports.source_report = r.report
           LEFT JOIN nvts n ON n.oid = r.nvt
          WHERE coalesce(r.severity, 0) > 0 AND coalesce(r.severity, 0) != -3.0
            AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
            AND ($3 OR EXISTS (
                  SELECT 1 FROM scope_report_hosts srh
                   WHERE srh.scope_report = $1
                     AND lower(srh.host_name) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))))
          GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),
                   coalesce(nullif(r.nvt, ''), 'unknown'), r.report
       ),
       vuln_by_system AS (
         SELECT host_key, nvt_oid, max(nvt_name) AS nvt_name,
                max(cvss_score)::double precision AS cvss_score
           FROM deduped_results GROUP BY host_key, nvt_oid
       ),
       vuln_sources AS (
         SELECT nvt_oid, count(DISTINCT source_report)::integer AS source_report_count
           FROM deduped_results GROUP BY nvt_oid
       ),
       alive AS (
         SELECT count(*)::double precision AS alive_count
           FROM scope_report_system_metrics WHERE scope_report = $1
       )
     INSERT INTO scope_report_vulnerability_metrics
       (scope_report, nvt_oid, nvt_name, cvss_score, affected_system_count,
        cvss_load, average_contribution, source_report_count)
     SELECT $1, vuln.nvt_oid, max(vuln.nvt_name), max(vuln.cvss_score),
            count(DISTINCT vuln.host_key)::integer,
            max(vuln.cvss_score) * count(DISTINCT vuln.host_key),
            CASE WHEN alive.alive_count > 0
                 THEN (max(vuln.cvss_score) * count(DISTINCT vuln.host_key)) / alive.alive_count
                 ELSE 0 END,
            coalesce(max(vuln_sources.source_report_count), 0)
       FROM vuln_by_system vuln
       LEFT JOIN vuln_sources ON vuln_sources.nvt_oid = vuln.nvt_oid
       CROSS JOIN alive
      GROUP BY vuln.nvt_oid, alive.alive_count;"#
}

pub(crate) fn scope_report_generation_metric_summary_sql() -> &'static str {
    "UPDATE scope_reports
        SET metric_alive_system_count =
              (SELECT count(*) FROM scope_report_system_metrics WHERE scope_report = $1),
            metric_total_system_cvss_load =
              coalesce((SELECT sum(cvss_load) FROM scope_report_system_metrics WHERE scope_report = $1), 0),
            metric_average_system_cvss_load =
              coalesce((SELECT avg(cvss_load) FROM scope_report_system_metrics WHERE scope_report = $1), 0),
            metric_authenticated_system_count =
              (SELECT count(*) FROM scope_report_system_metrics WHERE scope_report = $1 AND authentication_state = 'authenticated'),
            metric_auth_failed_system_count =
              (SELECT count(*) FROM scope_report_system_metrics WHERE scope_report = $1 AND authentication_state = 'authentication_failed'),
            metric_no_credential_path_system_count =
              (SELECT count(*) FROM scope_report_system_metrics WHERE scope_report = $1 AND authentication_state = 'no_credential_path'),
            metric_unknown_authentication_system_count =
              (SELECT count(*) FROM scope_report_system_metrics WHERE scope_report = $1 AND authentication_state = 'unknown'),
            metric_authenticated_scan_coverage =
              CASE WHEN (SELECT count(*) FROM scope_report_system_metrics WHERE scope_report = $1) > 0
                   THEN 100.0 * (SELECT count(*) FROM scope_report_system_metrics WHERE scope_report = $1 AND authentication_state = 'authenticated')
                        / (SELECT count(*) FROM scope_report_system_metrics WHERE scope_report = $1)
                   ELSE 0 END
      WHERE id = $1;"
}
