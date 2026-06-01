use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct AntiDebugProcessDebugPort;

impl Technique for AntiDebugProcessDebugPort {
    fn meta(&self) -> &'static TechniqueMeta { &ANTI_DEBUG_PROCESS_DEBUG_PORT_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let snippet = r#"fn evasion_anti_debug_debug_port() {
    unsafe {
        type NtQueryInfoProc = unsafe extern "system" fn(
            winapi::shared::ntdef::HANDLE,
            u32,
            *mut isize,
            u32,
            *mut u32,
        ) -> i32;
        let h = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if h.is_null() { return; }
        let name = b"NtQueryInformationProcess\0";
        let p = winapi::um::libloaderapi::GetProcAddress(h, name.as_ptr() as *const i8);
        if p.is_null() { return; }
        let f: NtQueryInfoProc = std::mem::transmute(p);
        let mut debug_port: isize = 0;
        let mut ret_len: u32 = 0;
        let status = f(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            7, // ProcessDebugPort
            &mut debug_port,
            core::mem::size_of::<isize>() as u32,
            &mut ret_len,
        );
        if status >= 0 && debug_port == -1 {
            winapi::um::processthreadsapi::ExitProcess(0);
        }
    }
}
evasion_anti_debug_debug_port();"#;
        ctx.append_replacement("{{SANDBOX}}", snippet.to_string());
        Ok(())
    }
}

pub use super::super::ANTI_DEBUG_PROCESS_DEBUG_PORT_META;
