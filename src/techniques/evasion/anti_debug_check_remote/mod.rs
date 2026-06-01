use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct AntiDebugCheckRemote;

impl Technique for AntiDebugCheckRemote {
    fn meta(&self) -> &'static TechniqueMeta { &ANTI_DEBUG_CHECK_REMOTE_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let snippet = r#"fn evasion_anti_debug_check_remote() {
    unsafe {
        let mut present: i32 = 0;
        let _ = winapi::um::debugapi::CheckRemoteDebuggerPresent(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            &mut present,
        );
        if present != 0 {
            winapi::um::processthreadsapi::ExitProcess(0);
        }
    }
}
evasion_anti_debug_check_remote();"#;
        ctx.append_replacement("{{SANDBOX}}", snippet.to_string());
        Ok(())
    }
}

pub use super::super::ANTI_DEBUG_CHECK_REMOTE_META;
