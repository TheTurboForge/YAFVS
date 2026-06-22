// SPDX-FileCopyrightText: 2026 TurboVAS contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn normalize_tag_resource_type(value: String) -> String {
    value.trim().to_ascii_lowercase()
}

fn strip_wrapping_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        trimmed[1..trimmed.len() - 1].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn tag_resource_name_filter(filter: &str) -> (String, bool) {
    let trimmed = filter.trim();
    let lower = trimmed.to_ascii_lowercase();
    for prefix in ["uuid=", "id="] {
        if lower.starts_with(prefix) {
            return (strip_wrapping_quotes(&trimmed[prefix.len()..]), true);
        }
    }
    (trimmed.to_string(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_resource_name_filter_supports_exact_id_syntax() {
        assert_eq!(
            tag_resource_name_filter("uuid=12345678-1234-1234-1234-123456789abc"),
            ("12345678-1234-1234-1234-123456789abc".to_string(), true)
        );
        assert_eq!(
            tag_resource_name_filter("id='CVE-2026-0001'"),
            ("CVE-2026-0001".to_string(), true)
        );
        assert_eq!(
            tag_resource_name_filter("nightly"),
            ("nightly".to_string(), false)
        );
    }
}
