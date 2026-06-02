use crate::techniques::{BuildContext, Technique, TechniqueMeta};
use std::fs;

pub struct Xor;

impl Technique for Xor {
    fn meta(&self) -> &'static TechniqueMeta { &XOR_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let key = loop {
            let k = (ctx.polymorph.random_u64() & 0xFF) as u8;
            if k != 0 { break k; }
        };
        let shellcode = fs::read(ctx.shellcode_path)
            .map_err(|e| anyhow::anyhow!("read shellcode: {e}"))?;
        let encrypted: Vec<u8> = shellcode.iter().map(|b| b ^ key).collect();

        let out_path = ctx.src_dir.join("input.xor");
        fs::write(&out_path, &encrypted)
            .map_err(|e| anyhow::anyhow!("write input.xor: {e}"))?;

        ctx.set_replacement("{{PATH_TO_SHELLCODE}}", "\"input.xor\"".to_string());
        ctx.set_replacement("{{DECRYPTION_FUNCTION}}",
            "fn xor_decode(buf: &[u8], key: u8) -> Vec<u8> { buf.iter().map(|x| x ^ key).collect() }".to_string());
        ctx.set_replacement("{{MAIN}}", format!("vec = xor_decode(&vec, {});", key));
        ctx.set_replacement("{{DEPENDENCIES}}", String::new());
        ctx.set_replacement("{{IMPORTS}}", String::new());
        Ok(())
    }
}

// XOR_META declared in the generated registry.rs (build.rs reads technique.toml).
// We re-export it here so users can `use crate::techniques::encryption::xor::XOR_META;`.
pub use super::super::XOR_META;
