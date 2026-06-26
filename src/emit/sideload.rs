use std::path::PathBuf;

use crate::emit::{EmittedFile, FileBody, Item};
use crate::pe::{self, DllExport};
use crate::spec::{SideloadMode, SideloadSpec};

#[derive(Debug, thiserror::Error)]
pub enum SideloadEmitError {
    #[error("pe parse: {0}")]
    Pe(#[from] crate::pe::PeError),
    #[error("hijack export {0:?} not found in target dll")]
    HijackMissing(String),
}

pub struct SideloadEmission {
    pub items: Vec<Item>,
    pub files: Vec<EmittedFile>,
    pub extra_uses: Vec<String>,
    pub extra_deps: Vec<String>,
    pub needs_build_rs: bool,
}

pub fn emit(
    spec: &SideloadSpec,
    fn_run_name: &str,
) -> Result<SideloadEmission, SideloadEmitError> {
    let exports = pe::parse_exports(&spec.target_dll)?;
    let hijack_present = exports
        .iter()
        .any(|e| e.name.as_deref() == Some(spec.hijack_export.as_str()));
    if !hijack_present {
        return Err(SideloadEmitError::HijackMissing(spec.hijack_export.clone()));
    }
    let target_stem = pe::dll_stem(&spec.target_dll);

    let mut items: Vec<Item> = Vec::new();
    let mut files: Vec<EmittedFile> = Vec::new();
    let mut extra_uses: Vec<String> = Vec::new();
    let mut extra_deps: Vec<String> = Vec::new();
    let mut needs_build_rs = false;

    items.push(Item::Raw(dllmain_block()));

    match spec.mode {
        SideloadMode::Sideload => {
            items.push(Item::Raw(sideload_hijack_block(
                &spec.hijack_export,
                fn_run_name,
            )));
        }
        SideloadMode::Proxy => {
            extra_uses.push("use lazy_static::lazy_static;".into());
            extra_deps.push("lazy_static = \"1.4\"".into());
            items.push(Item::Raw(proxy_block(
                &spec.hijack_export,
                fn_run_name,
                &spec.original_name,
                exports.len(),
            )));

            let forwarder = forward_target(spec, &target_stem);
            let def_body = generate_def(&exports, &spec.hijack_export, &target_stem, &forwarder);
            files.push(EmittedFile {
                rel_path: PathBuf::from("proxy.def"),
                body: FileBody::Bytes(def_body.into_bytes()),
            });
            files.push(EmittedFile {
                rel_path: PathBuf::from("build.rs"),
                body: FileBody::Bytes(PROXY_BUILD_RS.as_bytes().to_vec()),
            });
            needs_build_rs = true;
        }
    }

    items.push(Item::ModRef("forward".into()));
    files.push(EmittedFile {
        rel_path: PathBuf::from("src/forward.rs"),
        body: FileBody::Bytes(generate_forward_rs(&exports, &spec.hijack_export).into_bytes()),
    });

    Ok(SideloadEmission {
        items,
        files,
        extra_uses,
        extra_deps,
        needs_build_rs,
    })
}

const PROXY_BUILD_RS: &str = r##"use std::{env, path::PathBuf};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
        let def = PathBuf::from(manifest).join("proxy.def");
        println!("cargo:rustc-link-arg=/DEF:{}", def.display());
        println!("cargo:rerun-if-changed=proxy.def");
    }
}
"##;

fn dllmain_block() -> String {
    r##"const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[no_mangle]
#[allow(non_snake_case, unused_variables, unreachable_patterns)]
extern "system" fn DllMain(_dll: usize, reason: u32, _r: *mut ()) -> bool {
    match reason {
        DLL_PROCESS_ATTACH => (),
        DLL_PROCESS_DETACH => (),
        _ => ()
    }
    true
}"##
        .to_string()
}

fn sideload_hijack_block(hijack: &str, fn_run: &str) -> String {
    format!(
        r##"#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "system" fn {hijack}(
    _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64, _a6: u64, _a7: u64, _a8: u64,
    _a9: u64, _a10: u64, _a11: u64, _a12: u64, _a13: u64, _a14: u64, _a15: u64, _a16: u64,
    _a17: u64, _a18: u64, _a19: u64, _a20: u64,
) -> u64 {{
    {fn_run}();
    1
}}"##
    )
}

fn proxy_block(hijack: &str, fn_run: &str, original_path: &str, num_exports: usize) -> String {
    let escaped = original_path.replace('\\', "\\\\");
    format!(
        r##"lazy_static! {{
    static ref DLL_NAME: String = "{escaped}".to_string();
}}

static mut RP_CALLBACK_TABLE: [usize; {num_exports}] = [0usize; {num_exports}];
static RP_SYNC_LOCK: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

fn rp_dispatch(
    a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64,
    a9: u64, a10: u64, a11: u64, a12: u64, a13: u64, a14: u64, a15: u64, a16: u64,
    a17: u64, a18: u64, a19: u64, a20: u64,
    export_id: u32,
) -> u64 {{
    {{
        let mut guard = RP_SYNC_LOCK.lock().unwrap();
        if *guard == 0 {{
            *guard = 1;
            drop(guard);
            std::thread::spawn(|| {{ {fn_run}(); }});
        }}
    }}

    unsafe {{
        if RP_CALLBACK_TABLE[export_id as usize] != 0 {{
            let target: extern "system" fn(
                u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
                u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
            ) -> u64 = std::mem::transmute(RP_CALLBACK_TABLE[export_id as usize]);
            return target(
                a1, a2, a3, a4, a5, a6, a7, a8, a9, a10,
                a11, a12, a13, a14, a15, a16, a17, a18, a19, a20,
            );
        }}
    }}

    let proc_name = match export_id {{
        0 => "{hijack}".to_string(),
        _ => String::new(),
    }};
    if proc_name.is_empty() {{
        return 0;
    }}

    let dll_name = DLL_NAME.as_str();
    let module = dyncvoke::dyncvoke_core::load_library_a(dll_name);
    if module == 0 {{
        return 0;
    }}
    let proc_addr = dyncvoke::dyncvoke_core::get_function_address(module, &proc_name);
    if proc_addr == 0 {{
        return 0;
    }}

    unsafe {{
        RP_CALLBACK_TABLE[export_id as usize] = proc_addr;
        let target: extern "system" fn(
            u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
            u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
        ) -> u64 = std::mem::transmute(proc_addr);
        target(
            a1, a2, a3, a4, a5, a6, a7, a8, a9, a10,
            a11, a12, a13, a14, a15, a16, a17, a18, a19, a20,
        )
    }}
}}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "system" fn {hijack}(
    a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64,
    a9: u64, a10: u64, a11: u64, a12: u64, a13: u64, a14: u64, a15: u64, a16: u64,
    a17: u64, a18: u64, a19: u64, a20: u64,
) -> u64 {{
    rp_dispatch(
        a1, a2, a3, a4, a5, a6, a7, a8, a9, a10,
        a11, a12, a13, a14, a15, a16, a17, a18, a19, a20,
        0,
    )
}}"##
    )
}

fn forward_target(spec: &SideloadSpec, target_stem: &str) -> String {
    if spec.use_absolute_path {
        let p = spec.target_dll.with_extension("");
        p.display().to_string()
    } else if !spec.original_name.trim().is_empty() {
        std::path::Path::new(spec.original_name.trim())
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("{target_stem}_orig"))
    } else {
        format!("{target_stem}_orig")
    }
}

fn generate_forward_rs(exports: &[DllExport], hijack: &str) -> String {
    let mut out = String::new();
    out.push_str("#![allow(non_snake_case)]\n\n");
    for e in exports {
        if let Some(name) = &e.name {
            if name != hijack {
                out.push_str(&format!(
                    "#[no_mangle]\npub unsafe extern \"system\" fn {name}() {{}}\n"
                ));
            }
        }
    }
    out
}

fn generate_def(
    exports: &[DllExport],
    hijack: &str,
    target_stem: &str,
    forward_target: &str,
) -> String {
    let mut def = format!("LIBRARY {target_stem}\nEXPORTS\n");
    for e in exports {
        let Some(name) = &e.name else { continue };
        if name == hijack {
            def.push_str(&format!("    {name} @{}\n", e.ordinal));
        } else {
            def.push_str(&format!(
                "    {name}={forward_target}.{name} @{}\n",
                e.ordinal
            ));
        }
    }
    def
}
