// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

/// Shared by the user-management collection and typed User tag selection.
/// Search is literal, case-insensitive data rather than a SQL wildcard pattern.
pub(crate) fn user_management_search_predicate_sql(
    uuid_expression: &str,
    name_expression: &str,
    comment_expression: &str,
    search_parameter: &str,
) -> String {
    format!(
        "({search_parameter} = ''\n             OR strpos(lower({uuid_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({name_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({comment_expression}), lower({search_parameter})) > 0)"
    )
}

pub(crate) fn tag_user_selection_sql() -> String {
    format!(
        "SELECT u.id::integer, u.uuid::text, NULL::integer\n           FROM users u\n          WHERE {}\n          ORDER BY u.id ASC\n          LIMIT $2\n          FOR UPDATE OF u;",
        user_management_search_predicate_sql(
            "u.uuid::text",
            "coalesce(u.name, '')",
            "coalesce(u.comment, '')",
            "$1",
        )
    )
}
