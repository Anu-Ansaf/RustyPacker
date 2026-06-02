use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct AntiDebugCheckRemote;

impl Technique for AntiDebugCheckRemote {
    fn meta(&self) -> &'static TechniqueMeta { &ANTI_DEBUG_CHECK_REMOTE_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let snippet = r#"fn {{FN_EVASION_CHECK_REMOTE}}() {
    static OBF_MOD: &[u8] = &{{STR_KERNEL32}};
    static OBF_PROC: &[u8] = &{{STR_CHECK_REMOTE_DBG}};
    type Fn_ = unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> i32;
    unsafe {
        let f: Fn_ = match {{FN_RESOLVER}}(OBF_MOD, OBF_PROC) {
            Some(f) => f,
            None => return,
        };
        let mut present: i32 = 0;
        let _ = f(-1isize as *mut core::ffi::c_void, &mut present);
        if present != 0 {
            std::process::exit(0);
        }
    }
}
{{FN_EVASION_CHECK_REMOTE}}();"#;
        ctx.append_replacement("{{SANDBOX}}", snippet.to_string());
        Ok(())
    }
}

pub use super::super::ANTI_DEBUG_CHECK_REMOTE_META;
