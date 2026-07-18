// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn tls_certificate_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn tls_certificate_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM tls_certificates
      WHERE uuid = $1;"
}

pub(crate) fn tls_certificate_delete_permissions_sql() -> &'static str {
    "DELETE FROM permissions
      WHERE resource_type = 'tls_certificate'
        AND resource_location = 0
        AND resource = $1;"
}

pub(crate) fn tls_certificate_delete_tag_resources_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'tls_certificate'
        AND resource_location = 0
        AND resource = $1;"
}

pub(crate) fn tls_certificate_delete_sources_sql() -> &'static str {
    "DELETE FROM tls_certificate_sources
      WHERE tls_certificate = $1;"
}

pub(crate) fn tls_certificate_delete_orphan_locations_sql() -> &'static str {
    "DELETE FROM tls_certificate_locations
      WHERE NOT EXISTS (
            SELECT 1
              FROM tls_certificate_sources
             WHERE location = tls_certificate_locations.id);"
}

pub(crate) fn tls_certificate_delete_orphan_origins_sql() -> &'static str {
    "DELETE FROM tls_certificate_origins
      WHERE NOT EXISTS (
            SELECT 1
              FROM tls_certificate_sources
             WHERE origin = tls_certificate_origins.id);"
}

pub(crate) fn tls_certificate_delete_certificate_sql() -> &'static str {
    "DELETE FROM tls_certificates WHERE id = $1;"
}
