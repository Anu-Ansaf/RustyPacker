use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct AntiDebugVectoredInt3;

impl Technique for AntiDebugVectoredInt3 {
    fn meta(&self) -> &'static TechniqueMeta { &ANTI_DEBUG_VECTORED_INT3_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        // EXCEPTION_POINTERS layout (x86_64): ContextRecord at p+0x08, Rip at ctx+0xF8.
        // Walked by hand to avoid pulling a Windows-binding crate for one type.
        let snippet = r#"fn {{FN_EVASION_VEC_INT3}}() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static SEEN: AtomicBool = AtomicBool::new(false);
    static OBF_MOD: &[u8] = &{{STR_KERNEL32}};
    static OBF_ADD: &[u8] = &{{STR_ADD_VEH}};
    static OBF_REM: &[u8] = &{{STR_REMOVE_VEH}};

    unsafe extern "system" fn handler(p: *mut core::ffi::c_void) -> i32 {
        SEEN.store(true, core::sync::atomic::Ordering::Relaxed);
        unsafe {
            let ctx_ptr = *((p as *mut u8).add(0x08) as *mut *mut u8);
            let rip = ctx_ptr.add(0xF8) as *mut u64;
            *rip = (*rip).wrapping_add(1);
        }
        -1 // EXCEPTION_CONTINUE_EXECUTION
    }

    type AddVeh = unsafe extern "system" fn(
        u32,
        unsafe extern "system" fn(*mut core::ffi::c_void) -> i32,
    ) -> *mut core::ffi::c_void;
    type RemVeh = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;

    unsafe {
        let add: AddVeh = match {{FN_RESOLVER}}(OBF_MOD, OBF_ADD) {
            Some(f) => f,
            None => return,
        };
        let rem: RemVeh = match {{FN_RESOLVER}}(OBF_MOD, OBF_REM) {
            Some(f) => f,
            None => return,
        };
        let h = add(1, handler);
        if h.is_null() {
            return;
        }
        core::arch::asm!("int 3", options(nomem, nostack));
        let _ = rem(h);
        if !SEEN.load(Ordering::Relaxed) {
            std::process::exit(0);
        }
    }
}
{{FN_EVASION_VEC_INT3}}();"#;
        ctx.append_replacement("{{SANDBOX}}", snippet.to_string());
        Ok(())
    }
}

pub use super::super::ANTI_DEBUG_VECTORED_INT3_META;
