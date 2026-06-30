// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn tag_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn tag_insert_metadata_sql() -> &'static str {
    "INSERT INTO tags
        (uuid, owner, name, comment, value, resource_type, active, creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, coalesce($3, ''), coalesce($4, ''), $5, $6, m_now(), m_now())
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn tag_clone_metadata_sql() -> &'static str {
    "INSERT INTO tags
        (uuid, owner, name, comment, value, resource_type, active, creation_time, modification_time)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('tag', name, $2, ' Clone')),
            coalesce($4, comment),
            value,
            resource_type,
            active,
            m_now(),
            m_now()
       FROM tags
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn tag_clone_resources_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT $2, resource_type, resource, resource_uuid, resource_location
       FROM tag_resources
      WHERE tag = $1;"
}

pub(crate) fn tag_update_metadata_sql() -> &'static str {
    "UPDATE tags
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            value = coalesce($4, value),
            active = coalesce($5, active),
            modification_time = m_now()
      WHERE uuid = $1
      RETURNING id::integer, uuid::text;"
}

#[cfg(test)]
pub(crate) fn tag_write_unassigned_state_sql() -> &'static str {
    tag_write_state_sql()
}

pub(crate) fn tag_write_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            coalesce(resource_type, '')::text,
            coalesce(tag_resources_count(id, resource_type), 0)::bigint AS resource_count
       FROM tags
      WHERE uuid = $1;"
}

pub(crate) fn tag_resource_insert_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT $1, $2, $3, $4, 0
      WHERE NOT EXISTS (
            SELECT 1 FROM tag_resources
             WHERE tag = $1
               AND resource_type = $2
               AND resource = $3
               AND resource_location = 0
      );"
}

pub(crate) fn tag_resource_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE tag = $1
        AND resource_type = $2
        AND resource = $3
        AND resource_location = 0;"
}

pub(crate) fn tag_touch_metadata_sql() -> &'static str {
    "UPDATE tags SET modification_time = m_now() WHERE id = $1;"
}

pub(crate) fn tag_delete_metadata_sql() -> &'static str {
    "DELETE FROM tags
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn tag_write_detail_sql() -> &'static str {
    "SELECT t.uuid AS id,
            coalesce(t.name, '') AS name,
            coalesce(t.comment, '') AS comment,
            coalesce(u.name, '') AS owner_name,
            coalesce(t.resource_type, '') AS resource_type,
            coalesce(tag_resources_count(t.id, t.resource_type), 0)::bigint AS resource_count,
            coalesce(t.active, 0)::integer AS active_int,
            coalesce(t.value, '') AS value,
            coalesce(t.creation_time, 0)::bigint AS created_at_unix,
            coalesce(t.modification_time, 0)::bigint AS modified_at_unix
       FROM tags t
  LEFT JOIN users u ON u.id = t.owner
      WHERE t.uuid = $1
      LIMIT 1;"
}
