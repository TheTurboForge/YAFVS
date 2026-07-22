// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn user_accounts_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH user_rows AS (
             SELECT u.uuid AS id,
                    coalesce(u.name, '') AS name,
                    coalesce(u.comment, '') AS comment,
                    coalesce(u.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(u.modification_time, 0)::bigint AS modified_at_unix
               FROM users u
         ),
         filtered AS (
             SELECT * FROM user_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn user_account_detail_sql() -> &'static str {
    r#"SELECT u.uuid AS id,
              coalesce(u.name, '') AS name,
              coalesce(u.comment, '') AS comment,
              coalesce(u.creation_time, 0)::bigint AS created_at_unix,
              coalesce(u.modification_time, 0)::bigint AS modified_at_unix
         FROM users u
        WHERE u.uuid = $1
        LIMIT 1;"#
}
