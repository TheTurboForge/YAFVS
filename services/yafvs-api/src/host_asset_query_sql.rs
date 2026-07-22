// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn host_asset_identifiers_sql() -> &'static str {
    r#"SELECT hi.uuid AS id,
              coalesce(hi.name, '') AS name,
              coalesce(hi.value, '') AS value,
              coalesce(hi.source_type, '') AS source_type,
              coalesce(hi.source_id, '') AS source_id,
              left(coalesce(hi.source_data, ''), 512) AS source_data,
              (length(coalesce(hi.source_data, '')) > 512) AS source_data_truncated,
              coalesce(hi.creation_time, 0)::bigint AS created_at_unix,
              coalesce(hi.modification_time, 0)::bigint AS modified_at_unix
         FROM hosts h
         JOIN host_identifiers hi ON hi.host = h.id
        WHERE h.uuid = $1
          AND hi.name IN ('ip', 'hostname', 'DNS-via-TargetDefinition', 'MAC', 'OS')
        ORDER BY CASE hi.name
                   WHEN 'ip' THEN 0
                   WHEN 'hostname' THEN 1
                   WHEN 'DNS-via-TargetDefinition' THEN 2
                   WHEN 'MAC' THEN 3
                   WHEN 'OS' THEN 4
                   ELSE 5
                 END,
                 hi.modification_time DESC NULLS LAST,
                 hi.id DESC;"#
}

pub(crate) fn host_asset_operating_systems_sql() -> &'static str {
    r#"SELECT ho.uuid AS id,
              coalesce(ho.name, '') AS name,
              coalesce(ho.comment, '') AS comment,
              oss.uuid AS operating_system_id,
              oss.name AS operating_system_name,
              coalesce(cpe_title(oss.name), '') AS title,
              coalesce(ho.source_type, '') AS source_type,
              coalesce(ho.source_id, '') AS source_id,
              left(coalesce(ho.source_data, ''), 512) AS source_data,
              (length(coalesce(ho.source_data, '')) > 512) AS source_data_truncated,
              coalesce(ho.creation_time, 0)::bigint AS created_at_unix,
              coalesce(ho.modification_time, 0)::bigint AS modified_at_unix
         FROM hosts h
         JOIN host_oss ho ON ho.host = h.id
         JOIN oss ON oss.id = ho.os
        WHERE h.uuid = $1
        ORDER BY ho.modification_time DESC NULLS LAST, ho.id DESC;"#
}

pub(crate) fn host_asset_safe_details_sql() -> &'static str {
    r#"WITH latest_details AS (
         SELECT DISTINCT ON (hd.name)
                coalesce(hd.name, '') AS name,
                left(coalesce(hd.value, ''), 4096) AS value,
                (length(coalesce(hd.value, '')) > 4096) AS value_truncated,
                coalesce(hd.source_type, '') AS source_type,
                coalesce(hd.source_id, '') AS source_id,
                coalesce(hd.detail_source_type, '') AS detail_source_type,
                coalesce(hd.detail_source_name, '') AS detail_source_name,
                left(coalesce(hd.detail_source_description, ''), 1024) AS detail_source_description,
                (length(coalesce(hd.detail_source_description, '')) > 1024) AS detail_source_description_truncated
           FROM hosts h
           JOIN host_details hd ON hd.host = h.id
          WHERE h.uuid = $1
            AND hd.name IN ('best_os_cpe', 'best_os_txt', 'traceroute')
          ORDER BY hd.name, hd.id DESC
     )
     SELECT * FROM latest_details
      ORDER BY CASE name
                 WHEN 'best_os_cpe' THEN 0
                 WHEN 'best_os_txt' THEN 1
                 WHEN 'traceroute' THEN 2
                 ELSE 3
               END;"#
}
