use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

/// Spawn `cmd` with stdout+stderr piped, stream every line into the
/// `build_log` sink as it arrives, and return the final ExitStatus.
fn stream_command(cmd: &mut Command) -> std::io::Result<ExitStatus> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let t_out = stdout.map(|out| {
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                crate::build_log::write(&line);
            }
        })
    });
    let t_err = stderr.map(|err| {
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                crate::build_log::write(&line);
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

fn build_target() -> &'static str {
    if cfg!(target_os = "windows") {
        "x86_64-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-gnu"
    }
}

fn compile_locally(path_to_cargo_folder: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let target = build_target();
    let manifest = path_to_cargo_folder.join("Cargo.toml");
    let mut cmd = Command::new("cargo");

    if cfg!(not(target_os = "windows")) {
        cmd.env("CFLAGS", "-lrt");
        cmd.env("LDFLAGS", "-lrt");
    }

    cmd.env("RUSTFLAGS", "-C target-feature=+crt-static")
        .args(["build", "--release", "--manifest-path"])
        .arg(&manifest)
        .args(["--target", target]);

    let status = stream_command(&mut cmd)?;

    if !status.success() {
        return Err(format!("Compilation failed: {}", status).into());
    }
    Ok(())
}

pub fn compile(path_to_cargo_folder: &Path) {
    crate::blog!("[+] Starting to compile your payload..");
    compile_locally(path_to_cargo_folder).unwrap_or_else(|err| {
        panic!("Compilation failed: {:?}", err);
    });
    crate::blog!("[+] Successfully compiled! Rust code and compiled binary are in the 'shared' folder");
}

fn clean_locally(path_to_cargo_folder: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = path_to_cargo_folder.join("Cargo.toml");
    let mut cmd = Command::new("cargo");
    cmd.args(["clean", "--manifest-path"]).arg(&manifest);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("cargo clean failed: {}", status).into());
    }
    Ok(())
}

/// Removes the `target/` directory under the generated output folder.
/// Source files (`Cargo.toml`, `src/`, encrypted blob) are preserved.
/// Only call this after the final binary has been copied to the user's
/// destination, otherwise the only built artifact gets nuked along with
/// the intermediates.
pub fn clean(path_to_cargo_folder: &Path) {
    crate::blog!("[*] Removing build artifacts to save disk space..");
    match clean_locally(path_to_cargo_folder) {
        Ok(()) => crate::blog!("[+] Cleaned: {}/target", path_to_cargo_folder.display()),
        Err(e) => crate::blog!("[!] cargo clean skipped: {}", e),
    }
}
