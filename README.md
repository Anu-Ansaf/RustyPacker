<div align="center">
  <br>
  <img width="520px" src="./assets/logos/logo.jpg" alt="RustyPacker Logo" />
  <h1>RustyPacker</h1>
  <p><b>A native Rust shellcode packer with a GUI. RustyPacker assembles a Rust project from templates, compiles it in an format of EXE or Proxy & sideloadable DLLs.</b></p>
  <img src="https://img.shields.io/badge/Language-Rust-orange" alt="Language: Rust" />
  <img src="https://img.shields.io/badge/OS-Windows-blue" alt="OS: Windows" />
  <img src="https://img.shields.io/badge/Maintained-Yes-green" alt="Maintained: Yes" />
  <img src="https://img.shields.io/badge/Version-v0.1.1-purple" alt="Version: v0.1.1" />
</div>

<br>

RustyPacker comes in two themes:


<div align="center">
  <img src="./assets/imgs/main-1.png" width="49%" alt="RustyPacker main view" />
  <img src="./assets/imgs/main-2.png" width="49%" alt="RustyPacker secondary view" />
</div>

<br>

> Note: Rustypacker is in early stage of development. If you are facing bugs, please create an issue, Rustypacker grows along with the community. If you want to help by adding your own techniques or to fix a bug, please refer [Contribution](#contribution) section.

## What it does

You give it raw shellcode. You pick:

- An encryption method (AES-256-CBC, XOR, UUID-encoded).
- An injection technique. `SELF` or `REMOTE`.
- Zero or more anti-debug checks.
- Zero or more evasion checks (sleep, domain pinning).
- An output format. EXE, DLL, or DLL Sideload with optional Proxy mode and a `.def` for unhandled exports.

RustyPacker writes a fresh Rust project under `shared/output_<timestamp>/`, performs every placeholder substitution the chosen techniques request, and runs `cargo build --release --target x86_64-pc-windows-{msvc|gnu}` to produce the final binary alongside the generated source.


## Features

| Category   | Built-in techniques                                                                                              |
|------------|------------------------------------------------------------------------------------------------------------------|
| Encryption | AES-256-CBC, XOR, UUID                                                                                            |
| Injection (remote) | sysCRT, winCRT, EarlyCascade                                                                              |
| Injection (self)   | sysFIBER, EnumCalendarInfoA, EnumDesktopsW, EnumWindowStationsW, EnumSystemGeoID, CDefFolderMenu_Create2, RtlUserFiberStart |
| Anti-debug | CheckRemoteDebuggerPresent, NtQueryInformationProcess (ProcessDebugPort), TEB BeingDebugged, Vectored INT3 |
| Evasion    | NtDelayExecution sleep, domain pinning                                                                            |
| Output     | EXE, DLL, DLL Sideload (Sideload or Proxy with absolute or relative path)                                         |

Other extras:

- Live FlowCase tab. Shows the execution path of the payload you are configuring.
- Inline DLL exports preview when picking a sideload target.
- Streaming Console. Streams `cargo` output line by line.
- Cyberpunk default theme. Switch to Tactical via the `◆` button in the top-left.

---

## Polymorphism

Every build picks a fresh random seed from the OS and drives every variable surface in the payload from it. Two builds with the same shellcode and the same options still produce different payloads.

What varies each build:

- Anti debug API calls resolve at runtime via `GetModuleHandleA` and `GetProcAddress` with XOR'd name strings. `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `GetComputerNameExW`, `AddVectoredExceptionHandler`, and `RemoveVectoredExceptionHandler` do not appear in the payload IAT or `.rdata`.
- The EarlyCascade stub is encrypted with XOR at packer time and decoded at runtime. The plaintext Outflank bytes (`55 56 57 65 48 8B 14 25 60 00 00 00 ...`) do not appear in the payload binary. The placeholder slot is filled with random bytes before encryption so the ciphertext carries no signature at a fixed offset either.
- Function names like `boxboxbox`, `enhance`, `pause`, and every `evasion_anti_debug_*` are renamed each build. The pause cadence between injection steps is jittered around the base values. The shellcode XOR key and the obfuscated API name keys are random per build.

---

## Build and Run

Prerequisites:

- Rust toolchain. `rustup` is enough. RustyPacker runs via `cargo run`.
- Windows host with MSVC, or any host with the MinGW-w64 toolchain plus `rustup target add x86_64-pc-windows-gnu`.

```pwsh
git clone https://github.com/Whitecat18/RustyPacker.git
cd RustPacker
cargo r -r
```

## Using the GUI

The window has three tabs.

### Configure

- Shellcode. Pick the `.bin` or `.raw` file.
- Output. `EXE`, `DLL`, or `SIDELOAD`. Set the save path.
- DLL Sideload (when SIDELOAD is the format). Target DLL, hijack export, and mode (`SIDELOAD` for pure replacement, `PROXY` to forward unhandled exports to the original via a generated `.def`).
- Encryption. Pick a method. Configure any parameters it exposes.
- Injection. Toggle `SELF` or `REMOTE`, then pick a technique. The template dropdown filters to the matching mode. Per-technique params (e.g. target process name for remote) appear below.
- Anti-debug. Empty by default. `+ ADD CHECK` opens a popup. Pick one to add it as a row. Each row has a `× Remove`.
- Evasion. Same row builder pattern. Each evasion row exposes its own parameter form (delay ms, placement, expected domain, etc.).

Validation errors (missing shellcode, missing sideload target, etc.) appear as a banner at the bottom.

### FlowCase

A live, ordered preview of what the generated payload does. Steps run from `Loader starts` through anti-debug, sleep evasion, decryption, allocation, injection, and `Shellcode runs · C2 callback`. Updates as you change Configure. No prose, only the ordered steps and an accent pill per step.

### Console

The build log. Streams `cargo build` stdout and stderr line-by-line, classified by `[*]`, `[+]`, `[!]`, `[-]` prefixes.

---

## Output

A successful build writes:

```
shared/output_<unix-timestamp>/
├── Cargo.toml              # rendered from the chosen template
├── src/
│   ├── main.rs (or lib.rs) # rendered, with shellcode embedded
│   └── input.aes / .xor    # encrypted shellcode blob
└── target/
    └── x86_64-pc-windows-{msvc|gnu}/release/
        ├── <name>.exe
        └── <name>.dll
```

The full Rust project stays on disk for you to inspect, tweak, or rebuild manually.

---

## Running the payload

### EXE

Run it directly. No special invocation needed.

```pwsh
.\payload.exe
```

### DLL

DllMain is a NO-OP. The payload body lives in four exported functions, so the loader must call one of them. Pick whichever fits the host.

```pwsh
rundll32.exe payload.dll,Run
regsvr32.exe payload.dll                          # calls DllRegisterServer
regsvr32.exe /u payload.dll                       # calls DllUnregisterServer
rundll32.exe payload.dll,DllRegisterServer
```

Exported entrypoints: `Run`, `DllRegisterServer`, `DllGetClassObject`, `DllUnregisterServer`. COM hijacks ride `DllGetClassObject`. Keeping DllMain empty avoids loader-lock deadlocks and cuts EDR signal during DLL load.

### DLL Sideload (Sideload or Proxy)

The hijacked export from the target DLL becomes the entrypoint. Drop your DLL next to the host EXE and let the host load it. The payload fires when the host calls the hijacked export. Proxy mode forwards every other export to the original DLL via a generated `.def`, so the host keeps working without crashing.

For the full sideloading workflow, picking a target, and proxy generation, see [LazyDLLSideload](https://github.com/Whitecat18/LazyDLLSideload).

---

## For developers

Adding your own encryption, injection, anti-debug, or evasion technique is a three-file change (`technique.toml` plus `mod.rs` plus an optional template folder). `build.rs` discovers techniques by walking `src/techniques/`, so there is no registration boilerplate to edit.

Full guide lives in [development.md](./development.md). It covers architecture, manifest format, `BuildContext` API, placeholder catalogue, three worked examples, GUI integration notes, and common pitfalls.

---

## Project layout

```
src/
├── bin/gui.rs              # entry point
├── compiler.rs             # invokes cargo for the assembled project
├── puzzle.rs               # assembles the project from techniques + templates
├── order.rs                # the build order DTO
├── techniques/             # technique plugins (auto-discovered by build.rs)
│   ├── encryption/{aes,xor,uuid}/
│   ├── injection/{syscrt,sysfiber,wincrt,earlycascade,callback-based self-inject}/
│   └── evasion/{nt_delay,domain_pin,anti_debug_*}/
├── gui/
│   ├── mod.rs              # App, validation, top-level dispatch
│   ├── state.rs            # AppState, persisted via eframe::set_value
│   ├── theme.rs            # Tactical + Cyberpunk palettes
│   ├── widgets.rs          # ground-truth widget primitives
│   ├── tab_configure.rs    # Configure tab
│   ├── tab_flowcase.rs     # FlowCase tab
│   └── tab_console.rs      # Console tab
├── sideload.rs, pe_parser.rs, shellcode_reader.rs, tools.rs, build_log.rs
└── lib.rs
templates/                  # technique templates (Cargo + main.rs with placeholders)
build.rs                    # walks techniques/, emits registry.rs into OUT_DIR
```


## Contribution

RustyPacker grows with community help. The repo runs on two branches.

- `main`: stable version. Reviewed `dev` work lands here. Maintainers add extra techniques and hardening during the merge.
- `dev`: where new work lands first. All contributor PRs target this branch.

To contribute:

1. Fork the repo and clone your fork.
2. Switch to the `dev` branch on your fork. Branch off `dev`, not `main`.
3. Read [development.md](./development.md). The mental model, technique system, and three worked examples cover most of what you need.
4. Pick an open issue, or open one to discuss your idea first.
5. Code, run `cargo run --release` to smoke-test, then open a pull request targeting `dev`.
6. Wait for review. Maintainers might request changes before merging to `dev`. Your contribution rides into `main` later, with the next `dev` merge.

Recognition:

Every accepted contribution puts your handle in the Credits section and the release notes. Your name stays in the contributor list.

> Motivation: Bring your shellcode, your ideas for evading systems, and your patches.

## Credits

- [Dyncvoke](https://github.com/Whitecat18/Dyncvoke) 
- [Rust-for-Malware-Development](https://codeberg.org/smukx/Rust-for-Malware-Development.git)
- [LazyDLLSideload](https://github.com/Whitecat18/LazyDLLSideload)
- [EarlyCascade](https://github.com/Whitecat18/earlycascade-injection.git) 

> Note: Original credits have been mentioned in the main repository. I respect each and every one's hard work and their will to help the community.

## Disclaimer

This tool is for authorised offensive security work, CTFs, malware research, and detection engineering only.