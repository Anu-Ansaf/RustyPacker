use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct AntiDebugUnhandledFilter;

impl Technique for AntiDebugUnhandledFilter {
    fn meta(&self) -> &'static TechniqueMeta { &ANTI_DEBUG_UNHANDLED_FILTER_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let snippet = r#"fn evasion_anti_debug_unhandled_filter() {
    extern "system" fn flt(info: *const winapi::um::winnt::EXCEPTION_POINTERS) -> i32 {
        unsafe {
            let ctx = &mut *(*info).ContextRecord;
            ctx.Rip += 3;
        }
        -1
    }
    unsafe {
        let prev = winapi::um::errhandlingapi::SetUnhandledExceptionFilter(Some(flt));
        let mut is_debugged: u8 = 1;
        std::arch::asm!(
            "int 3",
            "jmp 2f",
            "mov {0}, 0",
            "2:",
            inout(reg_byte) is_debugged,
        );
        winapi::um::errhandlingapi::SetUnhandledExceptionFilter(prev);
        if is_debugged == 1 {
            winapi::um::processthreadsapi::ExitProcess(0);
        }
    }
}
evasion_anti_debug_unhandled_filter();"#;
        ctx.append_replacement("{{SANDBOX}}", snippet.to_string());
        Ok(())
    }
}

pub use super::super::ANTI_DEBUG_UNHANDLED_FILTER_META;
