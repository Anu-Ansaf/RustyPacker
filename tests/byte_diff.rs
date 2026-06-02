use std::collections::HashMap;
use std::path::PathBuf;

use rustpacker::order::{Order, OutputFormat};
use rustpacker::polymorph::BuildSeed;
use rustpacker::puzzle;

fn write_noop_shellcode() -> PathBuf {
    let scratch = PathBuf::from("target").join("byte_diff_noop.bin");
    std::fs::create_dir_all(scratch.parent().unwrap()).expect("mkdir target");
    std::fs::write(&scratch, [0xC3u8]).expect("write noop shellcode");
    scratch
}

fn assemble_with_seed(seed: u64) -> PathBuf {
    let shellcode = write_noop_shellcode();
    let order = Order {
        shellcode_path: shellcode,
        format: OutputFormat::Exe,
        encryption_id: "xor".to_string(),
        injection_id: "syscrt".to_string(),
        evasions: vec![
            "anti_debug_check_remote".to_string(),
            "anti_debug_process_debug_port".to_string(),
            "anti_debug_vectored_int3".to_string(),
        ],
        params: HashMap::new(),
        output: None,
        sideload: None,
        seed: BuildSeed(seed),
    };
    puzzle::assemble(order)
}

fn read_main(folder: &PathBuf) -> String {
    std::fs::read_to_string(folder.join("src").join("main.rs")).expect("read main.rs")
}

#[test]
fn same_seed_produces_identical_main_rs() {
    let a = assemble_with_seed(0xDEAD_BEEF_DEAD_BEEF);
    let b = assemble_with_seed(0xDEAD_BEEF_DEAD_BEEF);
    let main_a = read_main(&a);
    let main_b = read_main(&b);
    assert_eq!(main_a, main_b,
        "same seed produced different main.rs; polymorph reproducibility broken");
}

#[test]
fn different_seeds_produce_different_main_rs() {
    let a = assemble_with_seed(0x1111_1111_1111_1111);
    let b = assemble_with_seed(0x2222_2222_2222_2222);
    let main_a = read_main(&a);
    let main_b = read_main(&b);
    assert_ne!(main_a, main_b,
        "different seeds produced identical main.rs; polymorph layer not engaged");

    let diff_lines: usize = main_a.lines()
        .zip(main_b.lines())
        .filter(|(x, y)| x != y)
        .count();
    assert!(diff_lines >= 20,
        "expected at least 20 differing lines between distinct-seed builds, got {diff_lines}");
}

#[test]
fn forbidden_plaintext_not_in_main_rs() {
    const FORBIDDEN: &[&str] = &[
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "GetComputerNameExW",
        "AddVectoredExceptionHandler",
        "RemoveVectoredExceptionHandler",
        "SetUnhandledExceptionFilter",
        "boxboxbox",
        "evasion_anti_debug_check_remote",
        "evasion_anti_debug_debug_port",
        "evasion_anti_debug_teb",
        "evasion_anti_debug_vectored_int3",
        "evasion_domain_pin",
    ];
    let folder = assemble_with_seed(0x4242_4242_4242_4242);
    let body = read_main(&folder);
    let mut leaks = Vec::new();
    for needle in FORBIDDEN {
        if body.contains(needle) {
            leaks.push(*needle);
        }
    }
    assert!(leaks.is_empty(),
        "forbidden plaintext strings present in generated main.rs: {leaks:?}");
}
