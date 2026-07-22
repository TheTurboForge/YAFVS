// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Compact, key-sorted JSON with Python `ensure_ascii=True` string escaping.

use serde_json::Value;

pub(super) fn to_ascii_compact(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    write_value(value, &mut output)?;
    Ok(output)
}

fn write_value(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(value) => write_string(value, output),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_string(key, output);
                output.push(b':');
                write_value(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn write_string(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{08}' => output.extend_from_slice(b"\\b"),
            '\t' => output.extend_from_slice(b"\\t"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\u{0c}' => output.extend_from_slice(b"\\f"),
            '\r' => output.extend_from_slice(b"\\r"),
            character if character <= '\u{1f}' => write_escape(character as u16, output),
            character if character.is_ascii() => output.push(character as u8),
            character => {
                let mut utf16 = [0_u16; 2];
                for unit in character.encode_utf16(&mut utf16) {
                    write_escape(*unit, output);
                }
            }
        }
    }
    output.push(b'"');
}

fn write_escape(value: u16, output: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.extend_from_slice(b"\\u");
    output.push(HEX[((value >> 12) & 0x0f) as usize]);
    output.push(HEX[((value >> 8) & 0x0f) as usize]);
    output.push(HEX[((value >> 4) & 0x0f) as usize]);
    output.push(HEX[(value & 0x0f) as usize]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_matches_ensure_ascii_compact_strings() {
        let value = json!({
            "z": [true, null, "line\n"],
            "a": {"emoji": "😀", "latin": "ä", "control": "\u{0001}"},
        });
        assert_eq!(
            String::from_utf8(to_ascii_compact(&value).unwrap()).unwrap(),
            r#"{"a":{"control":"\u0001","emoji":"\ud83d\ude00","latin":"\u00e4"},"z":[true,null,"line\n"]}"#
        );
    }
}
