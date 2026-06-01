use crate::techniques::{BuildContext, Technique, TechniqueMeta};
use crate::tools::random_u8;
use std::fs;

pub struct Xor;

impl Technique for Xor {
    fn meta(&self) -> &'static TechniqueMeta { &XOR_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let key = non_zero_random_key();
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

fn non_zero_random_key() -> u8 {
    loop {
        let k = random_u8();
        if k != 0 { return k; }
    }
}

// XOR_META declared in the generated registry.rs (build.rs reads technique.toml).
// We re-export it here so users can `use crate::techniques::encryption::xor::XOR_META;`.
pub use super::super::XOR_META;
