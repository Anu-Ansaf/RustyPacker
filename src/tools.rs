use crate::order::Order;
use path_clean::PathClean;
use rand::distr::Alphanumeric;
use rand::RngExt;
use std::env;
use std::fs::{self, File};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct EncryptionOutput {
    pub decryption_function: String,
    pub main: String,
    pub dependencies: Option<String>,
    pub imports: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SandboxOutput {
    pub sandbox_function: String,
    pub sandbox_import: String,
}

pub fn absolute_path(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    }.clean();
    Ok(absolute_path)
}

pub fn write_to_file(content: &[u8], path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    file.write_all(content)?;
    Ok(())
}

pub fn random_u8() -> u8 { rand::random() }
pub fn random_aes_key() -> [u8; 32] { rand::random::<[u8; 32]>() }
pub fn random_aes_iv()  -> [u8; 16] { rand::random::<[u8; 16]>() }

pub fn get_source_binary_filename(order: &Order, output_folder: &Path) -> PathBuf {
    let template_name = template_name_for_injection(&order.injection_id);
    let binary_name = format!("{}.{}", template_name, order.format.extension());
    let candidates = [
        "target/x86_64-pc-windows-msvc/release",
        "target/x86_64-pc-windows-gnu/release",
    ];
    for dir in candidates {
        let path = output_folder.join(dir).join(&binary_name);
        if path.exists() {
            return path;
        }
    }
    output_folder.join(format!("target/x86_64-pc-windows-gnu/release/{}", binary_name))
}

fn template_name_for_injection(injection_id: &str) -> &'static str {
    // The compiled binary inherits its name from the template folder.
    match injection_id {
        "syscrt"                 => "sysCRT",
        "wincrt"                 => "winCRT",
        "sysfiber"               => "sysFIBER",
        "earlycascade"           => "ntEarlyCascade",
        "enum_calendar_info"     => "callbackExec",
        "enum_desktops"          => "callbackExec",
        "enum_system_geo_id"     => "callbackExec",
        "enum_window_stations"   => "callbackExec",
        "cdef_folder_menu"       => "callbackExec",
        "rtl_user_fiber_start"   => "callbackExec",
        other => panic!("unknown injection id: {other}"),
    }
}

pub fn process_output(order: &Order, output_folder_path: &Path) -> io::Result<()> {
    let output_path = match &order.output { Some(p) => p, None => return Ok(()) };
    if let Some(parent) = output_path.parent() {
        if !parent.exists() { fs::create_dir_all(parent)?; }
    }
    let source_binary = get_source_binary_filename(order, output_folder_path);
    if !source_binary.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Source file does not exist: {:?}", source_binary)));
    }
    fs::copy(&source_binary, output_path)?;
    crate::blog!("[+] Your binary has been written here: {:?}", output_path);
    Ok(())
}

pub fn generate_random_filename(order: &Order) -> String {
    let mut rng = rand::rng();
    let random_string: String = (0..8).map(|_| rng.sample(Alphanumeric) as char).collect();
    format!("{}.{}", random_string, order.format.extension())
}

pub fn rename_source_binary(order: &Order, output_folder_path: &Path) -> io::Result<()> {
    let source_binary = get_source_binary_filename(order, output_folder_path);
    if !source_binary.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Source file does not exist: {:?}", source_binary)));
    }
    let random_filename = generate_random_filename(order);
    let release_dir = source_binary.parent().expect("Source binary has no parent directory");
    let new_path = release_dir.join(random_filename);
    fs::rename(&source_binary, &new_path)?;
    crate::blog!("[+] Source binary has been renamed to: {:?}", new_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order::{Order, OutputFormat};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn fixture_order(format: OutputFormat) -> Order {
        Order {
            shellcode_path: PathBuf::from("/tmp/test.bin"),
            format,
            encryption_id: "xor".to_string(),
            injection_id: "syscrt".to_string(),
            evasions: Vec::new(),
            params: HashMap::new(),
            output: None,
            sideload: None,
        }
    }

    #[test]
    fn write_to_file_roundtrip() {
        let dir = std::env::temp_dir().join("rustpacker_test_tools_write");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_output.bin");
        let content: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE];
        write_to_file(&content, &path).unwrap();
        let read_back = fs::read(&path).unwrap();
        assert_eq!(read_back, content);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn absolute_path_already_absolute() {
        let path: &Path = if cfg!(windows) { Path::new("C:\\tmp\\test") } else { Path::new("/tmp/test") };
        let result = absolute_path(path).unwrap();
        assert!(result.is_absolute());
        assert_eq!(result, path);
    }

    #[test]
    fn random_aes_key_length() { assert_eq!(random_aes_key().len(), 32); }

    #[test]
    fn random_aes_iv_length() { assert_eq!(random_aes_iv().len(), 16); }

    #[test]
    fn generate_random_filename_format() {
        let order = fixture_order(OutputFormat::Exe);
        let filename = generate_random_filename(&order);
        assert!(filename.ends_with(".exe"));
        assert_eq!(filename.len(), 12);
    }

    #[test]
    fn get_source_binary_filename_uses_template_name() {
        let order = fixture_order(OutputFormat::Dll);
        let path = get_source_binary_filename(&order, Path::new("/output"));
        assert!(path.to_string_lossy().contains("sysCRT.dll"));
    }
}
