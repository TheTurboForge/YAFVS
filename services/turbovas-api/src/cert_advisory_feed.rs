// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};

use crate::{
    cert_advisory_payloads::{
        CertBundAdvisoryAdditionalInformation, CertBundAdvisoryRevision,
        CertBundAdvisoryRichDetail, DfnCertAdvisoryRichDetail, DfnCertLink,
    },
    feeds::{feed_metadata_root, read_text_file_bounded},
};

const MAX_CERT_ADVISORY_FEED_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn cert_bund_rich_detail(advisory_name: &str) -> Option<CertBundAdvisoryRichDetail> {
    let path = cert_bund_feed_path(advisory_name)?;
    let xml = read_text_file_bounded(&path, MAX_CERT_ADVISORY_FEED_BYTES)
        .map_err(|error| {
            tracing::debug!(%error, path = %path.display(), "CERT-Bund rich advisory feed read failed");
            error
        })
        .ok()?;
    parse_cert_bund_rich_detail(&xml, advisory_name)
}

pub(crate) fn dfn_cert_rich_detail(advisory_name: &str) -> Option<DfnCertAdvisoryRichDetail> {
    let path = dfn_cert_feed_path(advisory_name)?;
    let xml = read_text_file_bounded(&path, MAX_CERT_ADVISORY_FEED_BYTES)
        .map_err(|error| {
            tracing::debug!(%error, path = %path.display(), "DFN-CERT rich advisory feed read failed");
            error
        })
        .ok()?;
    parse_dfn_cert_rich_detail(&xml, advisory_name)
}

fn cert_bund_feed_path(advisory_name: &str) -> Option<PathBuf> {
    let year = if let Some(rest) = advisory_name.strip_prefix("CB-K") {
        parse_leading_year(rest)?
    } else if let Some(rest) = advisory_name.strip_prefix("WID-SEC-") {
        parse_leading_year(rest)?.checked_sub(2000)?
    } else {
        return None;
    };
    Some(
        feed_metadata_root()
            .join("gvm/cert-data")
            .join(format!("CB-K{year:02}.xml")),
    )
}

fn dfn_cert_feed_path(advisory_name: &str) -> Option<PathBuf> {
    let rest = advisory_name.strip_prefix("DFN-CERT-")?;
    let year = parse_leading_year(rest)?;
    if year < 2000 {
        return None;
    }
    Some(
        feed_metadata_root()
            .join("gvm/cert-data")
            .join(format!("dfn-cert-{year:04}.xml")),
    )
}

fn parse_leading_year(value: &str) -> Option<u32> {
    let digits: String = value.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

fn parse_cert_bund_rich_detail(
    xml: &str,
    advisory_name: &str,
) -> Option<CertBundAdvisoryRichDetail> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_advisory = false;
    let mut current = String::new();
    let mut detail = CertBundAdvisoryRichDetail::default();
    let mut ref_num: Option<String> = None;
    let mut revision: Option<CertBundAdvisoryRevision> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let local = xml_local_name(event.name().as_ref()).to_vec();
                let local_name = String::from_utf8_lossy(&local).into_owned();
                if local.as_slice() == b"Advisory" {
                    in_advisory = true;
                    detail = CertBundAdvisoryRichDetail::default();
                    ref_num = None;
                    revision = None;
                }
                if in_advisory {
                    if local.as_slice() == b"Ref_Num" {
                        detail.version = xml_attr_value(&event, &reader, b"update");
                    } else if local.as_slice() == b"Revision" {
                        revision = Some(CertBundAdvisoryRevision::default());
                    }
                    current = local_name;
                }
            }
            Ok(Event::Empty(event)) if in_advisory => {
                if xml_local_name(event.name().as_ref()) == b"Info" {
                    let issuer = xml_attr_value(&event, &reader, b"Info_Issuer");
                    let url = xml_attr_value(&event, &reader, b"Info_URL");
                    if issuer.is_some() || url.is_some() {
                        detail
                            .additional_information
                            .push(CertBundAdvisoryAdditionalInformation { issuer, url });
                    }
                }
            }
            Ok(Event::Text(event)) if in_advisory => {
                let text = event
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                let text = text.trim();
                if !text.is_empty() {
                    apply_cert_bund_text(&current, text, &mut detail, &mut ref_num, &mut revision);
                }
            }
            Ok(Event::CData(event)) if in_advisory => {
                let text = event
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                let text = text.trim();
                if !text.is_empty() {
                    apply_cert_bund_text(&current, text, &mut detail, &mut ref_num, &mut revision);
                }
            }
            Ok(Event::End(event)) if in_advisory => {
                let local = xml_local_name(event.name().as_ref()).to_vec();
                if local.as_slice() == b"Revision" {
                    if let Some(revision) = revision.take() {
                        detail.revision_history.push(revision);
                    }
                } else if local.as_slice() == b"Advisory" {
                    if ref_num.as_deref() == Some(advisory_name) {
                        return Some(detail);
                    }
                    in_advisory = false;
                    current.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                tracing::warn!(%error, "CERT-Bund rich advisory feed XML parse failed");
                break;
            }
            _ => {}
        }
    }

    None
}

fn apply_cert_bund_text(
    current: &str,
    text: &str,
    detail: &mut CertBundAdvisoryRichDetail,
    ref_num: &mut Option<String>,
    revision: &mut Option<CertBundAdvisoryRevision>,
) {
    if let Some(revision) = revision.as_mut() {
        match current {
            "Date" => revision.date = Some(text.to_string()),
            "Description" => revision.description = Some(text.to_string()),
            "Number" => revision.number = text.parse().ok(),
            _ => {}
        }
        return;
    }

    match current {
        "CategoryTree" => detail.categories.push(text.to_string()),
        "Effect" => detail.effect = Some(text.to_string()),
        "Platform" => detail.platform = Some(text.to_string()),
        "Reference_Source" => detail.reference_source = Some(text.to_string()),
        "Reference_URL" => detail.reference_url = Some(text.to_string()),
        "RemoteAttack" => detail.remote_attack = Some(text.to_string()),
        "Ref_Num" => *ref_num = Some(text.to_string()),
        "Risk" => detail.risk = Some(text.to_string()),
        "Software" => detail.software = Some(text.to_string()),
        "TextBlock" => detail.description.push(text.to_string()),
        "Title" => detail.title = Some(text.to_string()),
        "Version" => detail.version = Some(text.to_string()),
        _ => {}
    }
}

fn parse_dfn_cert_rich_detail(xml: &str, advisory_name: &str) -> Option<DfnCertAdvisoryRichDetail> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_entry = false;
    let mut current = String::new();
    let mut detail = DfnCertAdvisoryRichDetail::default();
    let mut ref_num: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let local = xml_local_name(event.name().as_ref()).to_vec();
                let local_name = String::from_utf8_lossy(&local).into_owned();
                if local.as_slice() == b"entry" {
                    in_entry = true;
                    detail = DfnCertAdvisoryRichDetail::default();
                    ref_num = None;
                }
                if in_entry {
                    if local.as_slice() == b"link" {
                        push_dfn_link(&event, &reader, &mut detail);
                    }
                    current = local_name;
                }
            }
            Ok(Event::Empty(event)) if in_entry => {
                if xml_local_name(event.name().as_ref()) == b"link" {
                    push_dfn_link(&event, &reader, &mut detail);
                }
            }
            Ok(Event::Text(event)) if in_entry => {
                let text = event
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                let text = text.trim();
                if current == "refnum" && !text.is_empty() {
                    ref_num = Some(text.to_string());
                }
            }
            Ok(Event::CData(event)) if in_entry => {
                let text = event
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                let text = text.trim();
                if current == "refnum" && !text.is_empty() {
                    ref_num = Some(text.to_string());
                }
            }
            Ok(Event::End(event)) if in_entry => {
                if xml_local_name(event.name().as_ref()) == b"entry" {
                    if ref_num.as_deref() == Some(advisory_name) {
                        return Some(detail);
                    }
                    in_entry = false;
                    current.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                tracing::warn!(%error, "DFN-CERT rich advisory feed XML parse failed");
                break;
            }
            _ => {}
        }
    }

    None
}

fn push_dfn_link(
    event: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    detail: &mut DfnCertAdvisoryRichDetail,
) {
    let Some(href) = xml_attr_value(event, reader, b"href") else {
        return;
    };
    let rel = xml_attr_value(event, reader, b"rel");
    detail.links.push(DfnCertLink { href, rel });
}

fn xml_attr_value(
    event: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    attribute_name: &[u8],
) -> Option<String> {
    for attribute in event.attributes().flatten() {
        if xml_local_name(attribute.key.as_ref()) != attribute_name {
            continue;
        }
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
            .ok()?;
        let value = value.trim().to_string();
        return (!value.is_empty()).then_some(value);
    }
    None
}

fn xml_local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_fixed_cert_bund_feed_paths_from_advisory_names() {
        assert!(
            cert_bund_feed_path("CB-K14/0001")
                .unwrap()
                .ends_with("gvm/cert-data/CB-K14.xml")
        );
        assert!(
            cert_bund_feed_path("WID-SEC-2026-0001")
                .unwrap()
                .ends_with("gvm/cert-data/CB-K26.xml")
        );
        assert!(cert_bund_feed_path("../CB-K26.xml").is_none());
    }

    #[test]
    fn derives_fixed_dfn_cert_feed_paths_from_advisory_names() {
        assert!(
            dfn_cert_feed_path("DFN-CERT-2026-0001")
                .unwrap()
                .ends_with("gvm/cert-data/dfn-cert-2026.xml")
        );
        assert!(dfn_cert_feed_path("DFN-CERT-99-0001").is_none());
        assert!(dfn_cert_feed_path("../../dfn-cert-2026.xml").is_none());
    }

    #[test]
    fn parses_cert_bund_rich_detail_for_matching_ref_num() {
        let xml = r#"<Advisories><Advisory>
          <Description><Element><TextBlock>First block.</TextBlock></Element><Element><Infos><Info Info_Issuer="Issuer" Info_URL="https://example.test/info" /></Infos></Element></Description>
          <CategoryTree>cpe:/a:vendor:product</CategoryTree>
          <Platform>Linux</Platform>
          <Ref_Num update="2">WID-SEC-2026-0001</Ref_Num>
          <Reference_Source>Source</Reference_Source>
          <Reference_URL>https://example.test/advisory</Reference_URL>
          <RevisionHistory><Revision><Date>2026-01-01</Date><Description>Initial</Description><Number>1</Number></Revision></RevisionHistory>
          <Risk>high</Risk><Software>Example Product</Software><Title>Example advisory</Title>
        </Advisory></Advisories>"#;

        let detail = parse_cert_bund_rich_detail(xml, "WID-SEC-2026-0001").unwrap();

        assert_eq!(detail.description, vec!["First block."]);
        assert_eq!(
            detail.additional_information[0].issuer.as_deref(),
            Some("Issuer")
        );
        assert_eq!(detail.categories, vec!["cpe:/a:vendor:product"]);
        assert_eq!(detail.platform.as_deref(), Some("Linux"));
        assert_eq!(
            detail.reference_url.as_deref(),
            Some("https://example.test/advisory")
        );
        assert_eq!(detail.revision_history[0].number, Some(1));
        assert_eq!(detail.software.as_deref(), Some("Example Product"));
        assert_eq!(detail.version.as_deref(), Some("2"));
    }

    #[test]
    fn parses_dfn_cert_links_for_matching_refnum() {
        let xml = r#"<feed xmlns:dfncert="http://www.dfn-cert.de/dfncert.dtd"><entry>
          <link href="https://example.test/main" rel="alternate"/>
          <link href="https://example.test/related"/>
          <dfncert:refnum>DFN-CERT-2026-0001</dfncert:refnum>
        </entry></feed>"#;

        let detail = parse_dfn_cert_rich_detail(xml, "DFN-CERT-2026-0001").unwrap();

        assert_eq!(detail.links[0].href, "https://example.test/main");
        assert_eq!(detail.links[0].rel.as_deref(), Some("alternate"));
        assert_eq!(detail.links[1].href, "https://example.test/related");
    }
}
