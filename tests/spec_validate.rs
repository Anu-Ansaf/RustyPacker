use std::collections::BTreeMap;
use std::path::PathBuf;

use rustypacker::app::state::UiState;
use rustypacker::spec::{CheckId, EncryptionKind, LoaderKindSel, OutputFormSel, BuildSpecError};
#[allow(unused_imports)]
use rustypacker::spec::OutputFormSel as _;

fn touch(tmp: &std::path::Path, name: &str) -> PathBuf {
    let p = tmp.join(name);
    std::fs::write(&p, b"\x90\x90\x90\x90").unwrap();
    p
}

fn workdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rustypacker_test_recipe_{tag}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn fresh_state() -> UiState {
    UiState {
        target_exe: "Notepad.exe".into(),
        ..UiState::default()
    }
}

#[test]
fn no_shellcode_path() {
    let s = fresh_state();
    match s.to_spec() {
        Err(BuildSpecError::NoShellcode) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn shellcode_missing_file() {
    let mut s = fresh_state();
    s.shellcode_path = Some(PathBuf::from("does/not/exist.bin"));
    s.delivery_path = Some(PathBuf::from("out.exe"));
    match s.to_spec() {
        Err(BuildSpecError::ShellcodeMissing(_)) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn no_delivery_path() {
    let dir = workdir("no_delivery");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    match s.to_spec() {
        Err(BuildSpecError::NoDelivery) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn dll_export_empty() {
    let dir = workdir("dll_empty");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    s.delivery_path = Some(dir.join("out.dll"));
    s.loader = LoaderKindSel::SelfInject;
    s.output = OutputFormSel::Dll;
    s.dll_export = "  ".into();
    match s.to_spec() {
        Err(BuildSpecError::DllExportEmpty) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn dll_export_invalid() {
    let dir = workdir("dll_invalid");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    s.delivery_path = Some(dir.join("out.dll"));
    s.loader = LoaderKindSel::SelfInject;
    s.output = OutputFormSel::Dll;
    s.dll_export = "9bad-name".into();
    match s.to_spec() {
        Err(BuildSpecError::DllExportInvalid(_)) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn dll_export_valid() {
    let dir = workdir("dll_ok");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    s.delivery_path = Some(dir.join("out.dll"));
    s.loader = LoaderKindSel::SelfInject;
    s.output = OutputFormSel::Dll;
    s.dll_export = "Fn_Hzv4_Run".into();
    assert!(s.to_spec().is_ok());
}

#[test]
fn earlycascade_target_required() {
    let dir = workdir("ec_empty");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    s.delivery_path = Some(dir.join("out.exe"));
    s.loader = LoaderKindSel::Remote;
    s.target_exe = "   ".into();
    match s.to_spec() {
        Err(BuildSpecError::TargetExeEmpty) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn delay_ms_must_parse() {
    let dir = workdir("delay_bad");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    s.delivery_path = Some(dir.join("out.exe"));
    let mut on = BTreeMap::new();
    on.insert(CheckId::NtDelay, true);
    s.checks_on = on;
    s.check_params.insert("nt_nap.ms".into(), "abc".into());
    match s.to_spec() {
        Err(BuildSpecError::DelayMsInvalid(_)) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn gpu_storage_blocks_earlycascade() {
    let dir = workdir("gpu_ec");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    s.delivery_path = Some(dir.join("out.exe"));
    s.loader = LoaderKindSel::Remote;
    s.target_exe = "Notepad.exe".into();
    s.gpu_storage = true;
    match s.to_spec() {
        Err(BuildSpecError::GpuStorageWrongLoader) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn gpu_storage_ok_with_fiber() {
    let dir = workdir("gpu_fiber_ok");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    s.delivery_path = Some(dir.join("out.exe"));
    s.gpu_storage = true;
    assert!(s.to_spec().is_ok());
}

#[test]
fn happy_fiber_exe_no_checks() {
    let dir = workdir("happy_exe");
    let mut s = fresh_state();
    s.shellcode_path = Some(touch(&dir, "raw.bin"));
    s.delivery_path = Some(dir.join("out.exe"));
    s.encryption = EncryptionKind::Xor8;
    let r = s.to_spec().expect("recipe");
    assert!(matches!(r.loader, rustypacker::spec::LoaderKind::SelfInject { .. }));
}
