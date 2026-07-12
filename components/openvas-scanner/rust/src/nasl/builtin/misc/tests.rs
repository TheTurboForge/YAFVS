// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.

use chrono::Offset;
use flate2::{
    Compression,
    write::{GzEncoder, ZlibEncoder},
};

use crate::nasl::test_prelude::*;

use std::{io::Write, time::Instant};

use super::{MAX_COMPRESSED_SIZE, MAX_DECOMPRESSED_SIZE, gunzip_bytes};

fn compress_test_data(data: &[u8], gzip: bool) -> Vec<u8> {
    if gzip {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    } else {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }
}

#[test]
fn rand() {
    check_code_result_matches!("rand();", NaslValue::Number(_));
    check_code_result_matches!("rand();", NaslValue::Number(_));
}

#[test]
fn get_byte_order() {
    check_code_result_matches!("get_byte_order();", NaslValue::Boolean(_));
}

#[test]
fn dec2str() {
    check_code_result("dec2str(num: 23);", "23");
}

#[test]
fn nasl_typeof() {
    let mut t = TestBuilder::default();
    t.ok(r#"typeof("AA");"#, "string");
    t.ok(r#"typeof(1);"#, "int");
    t.ok(r#"typeof('AA');"#, "data");
    t.ok(r#"typeof(make_array());"#, "array");
    t.ok(r#"typeof(NULL);"#, "undef");
    t.ok(r#"typeof(a);"#, "undef");
    check_err_matches!(
        t,
        r#"typeof(23,76);"#,
        ArgumentError::TrailingPositionals { .. }
    );
    t.ok("d['test'] = 2;", 2);
    t.ok("typeof(d);", "array");
}

#[test]
fn isnull() {
    check_code_result(r#"isnull(42);"#, false);
    check_code_result(r#"isnull(Null);"#, true);
}

#[test]
fn unixtime() {
    check_code_result_matches!(r#"unixtime();"#, NaslValue::Number(_));
}

#[test]
fn gzip() {
    check_code_result(
        r#"gzip(data: 'z', headformat: "gzip");"#,
        vec![
            31u8, 139, 8, 0, 0, 0, 0, 0, 0, 255, 171, 2, 0, 175, 119, 210, 98, 1, 0, 0, 0,
        ],
    );
    check_code_result(
        r#"gzip(data: 'z');"#,
        vec![120u8, 156, 171, 2, 0, 0, 123, 0, 123],
    );
}

#[test]
fn gunzip() {
    let mut t = TestBuilder::default();
    t.run(r#"z = raw_string (0x78, 0x9c, 0xab, 0x02, 0x00, 0x00, 0x7b, 0x00, 0x7b);"#);
    t.ok(r#"gunzip(data: z);"#, b"z".to_vec());
    t.ok(r#"typeof(gunzip(data: z));"#, "data");
    t.run(r#"gz = gzip(data: 'gz', headformat: "gzip");"#);
    t.ok(r#"gunzip(data: gz);"#, b"gz".to_vec());
    t.run(r#"ngz = gzip(data: "ngz");"#);
    t.ok(r#"gunzip(data: ngz);"#, b"ngz".to_vec());
    t.run(r#"bad = raw_string(0x78, 0x9c, 0x00, 0xff);"#);
    t.ok(r#"gunzip(data: bad);"#, NaslValue::Null);
}

#[test]
fn gunzip_accepts_zlib_gzip_binary_and_high_ratio_data() {
    let binary = [0x00, 0xff, 0x80, 0x41, 0x00, 0x7f];
    for gzip in [false, true] {
        let compressed = compress_test_data(&binary, gzip);
        assert_eq!(gunzip_bytes(&compressed), Some(binary.to_vec()));

        let compressed_empty = compress_test_data(&[], gzip);
        assert_eq!(gunzip_bytes(&compressed_empty), Some(Vec::new()));
    }

    let high_ratio = vec![0; 1024 * 1024];
    let compressed = compress_test_data(&high_ratio, false);
    assert!(compressed.len() < high_ratio.len() / 100);
    assert_eq!(gunzip_bytes(&compressed), Some(high_ratio));
}

#[test]
fn gunzip_enforces_absolute_output_limit() {
    let at_limit = vec![0; MAX_DECOMPRESSED_SIZE];
    for gzip in [false, true] {
        let compressed = compress_test_data(&at_limit, gzip);
        assert_eq!(
            gunzip_bytes(&compressed).as_deref(),
            Some(at_limit.as_slice())
        );
    }

    let over_limit = vec![0; MAX_DECOMPRESSED_SIZE + 1];
    for gzip in [false, true] {
        let compressed = compress_test_data(&over_limit, gzip);
        assert_eq!(gunzip_bytes(&compressed), None);
    }
}

#[test]
fn gunzip_rejects_truncated_malformed_checksum_and_trailing_input() {
    assert_eq!(gunzip_bytes(&[0x78, 0x9c, 0x00, 0xff]), None);

    for gzip in [false, true] {
        let mut truncated = compress_test_data(b"truncated", gzip);
        truncated.pop();
        assert_eq!(gunzip_bytes(&truncated), None);

        let mut checksum_failed = compress_test_data(b"checksum", gzip);
        *checksum_failed.last_mut().unwrap() ^= 0xff;
        assert_eq!(gunzip_bytes(&checksum_failed), None);

        let mut trailing = compress_test_data(b"trailing", gzip);
        trailing.push(0x42);
        assert_eq!(gunzip_bytes(&trailing), None);

        let mut concatenated = compress_test_data(b"first", gzip);
        concatenated.extend_from_slice(&compress_test_data(b"second", gzip));
        assert_eq!(gunzip_bytes(&concatenated), None);
    }
}

#[test]
fn gunzip_rejects_invalid_input() {
    assert_eq!(gunzip_bytes(&[]), None);
    assert_eq!(gunzip_bytes(&[0x1f]), None);
    assert_eq!(gunzip_bytes(b"not compressed"), None);

    let mut oversized = vec![0; MAX_COMPRESSED_SIZE + 1];
    oversized[..2].copy_from_slice(&[0x1f, 0x8b]);
    assert_eq!(gunzip_bytes(&oversized), None);
}

#[test]
fn gunzip_accepts_standard_fixtures_and_rejects_legacy_sync_flush() {
    const ZLIB_FIXTURE: &[u8] = &[120, 156, 171, 2, 0, 0, 123, 0, 123];
    const GZIP_FIXTURE: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 171, 2, 0, 175, 119, 210, 98, 1, 0, 0, 0,
    ];
    const LEGACY_SYNC_FLUSH: &[u8] = &[120, 156, 170, 2, 0, 0, 0, 255, 255];

    assert_eq!(gunzip_bytes(ZLIB_FIXTURE), Some(b"z".to_vec()));
    assert_eq!(gunzip_bytes(GZIP_FIXTURE), Some(b"z".to_vec()));
    assert_eq!(gunzip_bytes(LEGACY_SYNC_FLUSH), None);
}

#[test]
fn localtime() {
    let mut t = TestBuilder::default();
    t.run_all(
        r#"
            a = localtime(1676900372, utc: TRUE);
            b = localtime(1676900372, utc: FALSE);
            c = localtime(utc: TRUE);
            d = localtime(utc: FALSE);
        "#,
    );
    let results = t.results();
    let mut results = results.into_iter();

    let offset = chrono::Local::now().offset().fix().local_minus_utc();
    let date_a = results.next();
    assert!(matches!(date_a, Some(Ok(NaslValue::Dict(_)))));
    match date_a.unwrap().unwrap() {
        NaslValue::Dict(x) => {
            assert_eq!(x["sec"], NaslValue::Number(32));
            assert_eq!(x["min"], NaslValue::Number(39));
            assert_eq!(x["hour"], NaslValue::Number(13));
            assert_eq!(x["mday"], NaslValue::Number(20));
            assert_eq!(x["mon"], NaslValue::Number(2));
            assert_eq!(x["year"], NaslValue::Number(2023));
            assert_eq!(x["wday"], NaslValue::Number(1));
            assert_eq!(x["yday"], NaslValue::Number(51));
            assert_eq!(x["isdst"], NaslValue::Number(0));
        }
        _ => panic!("NO DICT"),
    }

    let date_b = results.next();
    assert!(matches!(date_b, Some(Ok(NaslValue::Dict(_)))));
    match date_b.unwrap().unwrap() {
        NaslValue::Dict(x) => {
            assert_eq!(x["sec"], NaslValue::Number(32));
            assert_eq!(x["min"], NaslValue::Number(39));
            assert_eq!(x["hour"], NaslValue::Number(13 + (offset / 3600) as i64));
            assert_eq!(x["mday"], NaslValue::Number(20));
            assert_eq!(x["mon"], NaslValue::Number(2));
            assert_eq!(x["year"], NaslValue::Number(2023));
            assert_eq!(x["wday"], NaslValue::Number(1));
            assert_eq!(x["yday"], NaslValue::Number(51));
            assert_eq!(x["isdst"], NaslValue::Number(0));
        }
        _ => panic!("NO DICT"),
    }

    let date_c = results.next().unwrap().unwrap();
    let date_d = results.next().unwrap().unwrap();
    let hour_c: i64;
    let hour_d: i64;
    let min_c: i64;
    let min_d: i64;
    match date_c {
        NaslValue::Dict(x) => {
            hour_c = (x["hour"].to_owned()).convert_to_number();
            min_c = (x["min"].to_owned()).convert_to_number();
        }
        _ => panic!("NO DICT"),
    }
    match date_d {
        NaslValue::Dict(x) => {
            hour_d = (x["hour"].to_owned()).convert_to_number();
            min_d = (x["min"].to_owned()).convert_to_number();
        }
        _ => panic!("NO DICT"),
    }
    assert_eq!(
        hour_c * 60 + min_c,
        hour_d * 60 + min_d - (offset / 60) as i64
    );
}

#[test]
fn mktime() {
    let offset = chrono::Local::now().offset().fix().local_minus_utc();
    check_code_result(
        r#"mktime(sec: 01, min: 02, hour: 03, mday: 01, mon: 01, year: 1970);"#,
        10921 - offset,
    );
}

#[test]
fn sleep() {
    let now = Instant::now();
    check_code_result(r#"sleep(1);"#, NaslValue::Null);
    assert!(now.elapsed().as_secs() >= 1);
}

#[test]
fn usleep() {
    let now = Instant::now();
    check_code_result(r#"usleep(1000);"#, NaslValue::Null);
    assert!(now.elapsed().as_micros() >= 1000);
}

#[test]
fn defined_func() {
    let mut t = TestBuilder::default();
    t.ok("function b() { return 2; }", NaslValue::Null);
    t.ok(r#"defined_func("b");"#, true);
    t.ok(r#"defined_func("defined_func");"#, true);
    t.ok("a = 12;", 12i64);
    t.ok(r#"defined_func("a");"#, false);
    t.ok("defined_func(a);", false);
}
