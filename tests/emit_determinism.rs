use std::path::PathBuf;

use rustypacker::emit;
use rustypacker::spec::{
    BuildSeed, CheckChoice, CheckId, EncryptionKind, LoaderKind, OutputForm, BuildSpec,
};

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rustypacker_test_emit_{tag}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn write_shellcode(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("raw.bin");
    let bytes: Vec<u8> = (0..64u8).collect();
    std::fs::write(&p, bytes).unwrap();
    p
}

fn fiber_exe_recipe(dir: &std::path::Path, seed: u64) -> BuildSpec {
    BuildSpec {
        shellcode_path: write_shellcode(dir),
        delivery_path:  dir.join("out.exe"),
        loader:         LoaderKind::SelfInject {
            method: rustypacker::spec::SelfInjectMethod::Fiber,
            format: OutputForm::Exe,
        },
        encryption:     EncryptionKind::Xor8,
        checks:         vec![CheckChoice {
            id: CheckId::TebFlag,
            params: Default::default(),
        }],
        gpu_storage:    false,
        seed:           BuildSeed(seed),
    }
}

#[test]
fn same_seed_yields_identical_program() {
    let dir = tmpdir("det_fiber");
    let r1 = fiber_exe_recipe(&dir, 0x0123_4567_89ab_cdef);
    let r2 = fiber_exe_recipe(&dir, 0x0123_4567_89ab_cdef);

    let p1 = emit::build(&r1).unwrap();
    let p2 = emit::build(&r2).unwrap();

    assert_eq!(p1.crate_meta.crate_name, p2.crate_meta.crate_name);
    assert_eq!(p1.files.len(), p2.files.len());
    for (a, b) in p1.files.iter().zip(p2.files.iter()) {
        assert_eq!(a.rel_path, b.rel_path);
        match (&a.body, &b.body) {
            (emit::FileBody::Bytes(x), emit::FileBody::Bytes(y)) => assert_eq!(x, y),
            (emit::FileBody::Source(x), emit::FileBody::Source(y)) => {
                let xs = serde_repr(x);
                let ys = serde_repr(y);
                assert_eq!(xs, ys);
            }
            _ => panic!("file body kind mismatch"),
        }
    }
}

#[test]
fn different_seed_yields_different_crate_name() {
    let dir = tmpdir("det_diff");
    let r1 = fiber_exe_recipe(&dir, 0x1111_2222_3333_4444);
    let r2 = fiber_exe_recipe(&dir, 0xaaaa_bbbb_cccc_dddd);
    let p1 = emit::build(&r1).unwrap();
    let p2 = emit::build(&r2).unwrap();
    assert_ne!(p1.crate_meta.crate_name, p2.crate_meta.crate_name);
}

fn serde_repr(sections: &[emit::Section]) -> String {
    let mut out = String::new();
    for s in sections {
        match s {
            emit::Section::InnerAttrs(a) => {
                out.push_str("ATTRS|");
                for x in a {
                    out.push_str(x);
                    out.push('\n');
                }
            }
            emit::Section::Uses(u) => {
                out.push_str("USES|");
                for x in u {
                    out.push_str(x);
                    out.push('\n');
                }
            }
            emit::Section::Items(items) => {
                out.push_str("ITEMS|");
                for it in items {
                    match it {
                        emit::Item::Const { name, ty, value } => {
                            out.push_str(&format!("C:{name}:{ty}:{value}\n"));
                        }
                        emit::Item::Fn { sig, body } => {
                            out.push_str(&format!("F:{sig}\n{body}\n"));
                        }
                        emit::Item::Raw(s) => {
                            out.push_str(&format!("R:{s}\n"));
                        }
                        emit::Item::ModRef(m) => {
                            out.push_str(&format!("M:{m}\n"));
                        }
                    }
                }
            }
        }
    }
    out
}
