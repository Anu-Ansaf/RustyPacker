<div align="center">
  <br>
  <img width="520px" src="assets/logo/logo.jpg" alt="rustypacker Logo" />
  <h1>Rustypacker</h1>
  <p><b>A native Rust shellcode packer with a GUI.</b></p>
  <img src="https://img.shields.io/badge/Language-Rust-orange" alt="Language: Rust" />
  <img src="https://img.shields.io/badge/OS-Windows-blue" alt="OS: Windows" />
  <img src="https://img.shields.io/badge/Maintained-Bug--Fixes--only-yellow" alt="Maintained: Bug Fixes" />
  <img src="https://img.shields.io/badge/Version-v0.1.5-purple" alt="Version: v0.1.5" />
</div>

<br>

> Note: 0.1.5 is a fresh rewrite with 3 times faster.. Rustypacker is in early stages. This is the last update for Rustypacker...

## Features

| Category    | Options                                                                              |
| ----------- | ------------------------------------------------------------------------------------ |
| Encryption  | xor8, aes-ctr, rc4, khufu, ecies, camellia                                           |
| Self-inject | FIBER SWITCH, EnumCalendarInfoA, EnumDesktopsW, EnumWindowStationsW, EnumSystemGeoID |
| Remote      | EarlyCascade, NtCreateThreadEx                                                       |
| Anti-debug  | ProcessDebugObjectHandle, ProcessDebugPort, PEB BeingDebugged, Vectored INT3         |
| Evasion     | NtDelayExecution nap (at_start / between / before_exec)                              |
| Storage     | host Vec, optional NVIDIA GPU VRAM via CUDA driver API                               |
| Output      | EXE, DLL                                                                             |
| DLL         | chosen export name, Sideload (pure replace), Sideload Proxy (forwards via .def)      |
| Syscalls    | NtAllocate/Write/Protect/Delay/QueryInformationProcess                               |
| Themes      | Tactical (warm amber), Cyberpunk (mint neon, mono-only, scanlines)                   |
| Tabs        | Configure, FlowCase, Console                                                         |
| Polymorph   | per-build identifier + key rotation, deterministic when `RUSTYPACKER_SEED` is set    |

## Encryption

| Algorithm | Key                  | Block    | Crate deps in loader |
| --------- | -------------------- | -------- | -------------------- |
| xor8      | 32 bytes             | stream   | none                 |
| aes-ctr   | AES-256, zero IV     | stream   | aes, ctr             |
| rc4       | 32 bytes (KSA+PRGA)  | stream   | none                 |
| khufu     | 64 bytes permuted    | 8 bytes  | none                 |
| ecies     | secp256k1 + sha2 KDF | stream   | k256, sha2           |
| camellia  | two u64 subkeys      | 16 bytes | none                 |

## Anti-analysis

| Check        | Mechanism                                           | Routed via |
| ------------ | --------------------------------------------------- | ---------- |
| check-remote | NtQueryInformationProcess(ProcessDebugObjectHandle) | syscall    |
| debug-port   | NtQueryInformationProcess(ProcessDebugPort)         | syscall    |
| peb-flag     | inline asm read of gs:[0x60]+0x02                   | no API     |
| vec-int3     | AddVectoredExceptionHandler + int 3 + handler latch | Win32      |
| nt-nap       | NtDelayExecution at chosen placement                | syscall    |

## Loaders

| Loader              | Category    | Calls                                               |
| ------------------- | ----------- | --------------------------------------------------- |
| FIBER SWITCH        | self-inject | Nt syscall                                          |
| EnumCalendarInfoA   | self-inject | Nt syscall + callback hijack                        |
| EnumDesktopsW       | self-inject | Nt syscall + callback hijack                        |
| EnumWindowStationsW | self-inject | Nt syscall + callback hijack                        |
| EnumSystemGeoID     | self-inject | Nt syscall + callback hijack                        |
| EarlyCascade        | remote      | Win32 + ntdll pattern scan                          |
| NtCreateThreadEx    | remote      | NtAllocate / NtWrite / NtProtect / NtCreateThreadEx |

## Build and Run

```pwsh
git clone https://git.smukx.site/smukx/Rustypacker.git
cd Rustypacker
cargo build --release
target\release\rustypacker.exe
```

## Output layout

```
workdir/<seed_hex>/
├── Cargo.toml
├── src/
│   ├── main.rs or lib.rs
│   └── embed/blob.bin
└── target/x86_64-pc-windows-msvc/release/<crate>.exe or .dll
```

Final artifact copied to the path you picked. Clean button wipes `workdir/`.

## Reproducing a build

| Env var                | Effect                                               |
| ---------------------- | ---------------------------------------------------- |
| `RUSTYPACKER_SEED=...` | 16 hex chars, pins identifiers + key bytes per build |
| (not set)              | seed drawn from `getrandom`                          |

ECIES draws its long-term and ephemeral scalars from `OsRng`, so its output stays non-deterministic.

## Project layout

```
src/
├── main.rs / lib.rs
├── app/        GUI (theme, widgets, shell, form, flow, console)
├── spec/       typed build order + validation
├── emit/       in-memory loader source builder
│   ├── loaders/  selfinject, earlycascade, syscrt
│   ├── checks/
│   ├── gpu.rs
│   ├── sideload.rs
│   └── rng / namebook / keygen
├── crypt/      six algorithms (encrypt + matching loader decoder)
├── compose/    orchestrator (spec → emit → cargo build → place artifact)
├── pe.rs       hand-rolled PE export parser for sideload
└── logbus.rs   GUI console log channel
assets/
├── fonts/      Inter + JetBrains Mono (regular + bold)
└── stubs/      earlycascade APC stub asm + assembled bytes
tests/
workdir/        gitignored, emit writes per-build crates here
```

## Tests

| Command                   | Coverage                                |
| ------------------------- | --------------------------------------- |
| `cargo test`              | 11 spec validation + 2 emit determinism |
| `cargo test -- --ignored` | 17 end-to-end cargo-build smoke runs    |

## Credits / Resources

- Fiber Execution [Resource 1](https://github.com/Kara-4search/Fiber_ShellcodeExecution) [Resource 2](https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber)
- [GPU Abuse, VX Underground paper](https://github.com/vxunderground/VXUG-Papers/blob/main/GpuMemoryAbuse.cpp)
- [Sandbox Evasion](https://0xpat.github.io/Malware_development_part_2)
- [DLL Sideloading & Proxy templates](https://git.smukx.site/smukx/LazyDLLSideload)
- [EarlyCascade Template](https://git.smukx.site/smukx/Earlycascade-Injection.git)
- [Self Injection Methods](https://git.smukx.site/smukx/Rust-for-Malware-Development/src/branch/main/Process)
- [AntiDebugging Methods](https://git.smukx.site/smukx/Rust-for-Malware-Development/src/branch/main/AntiDebugging)
- [Encryption Methods](https://git.smukx.site/smukx/Rust-for-Malware-Development#encryption-techniques)
- [Remote NtCreateUserProcess Injection](https://git.smukx.site/smukx/Rust-for-Malware-Development/src/branch/main/NtCreateUserProcess)
- [Call Stack & Syscall Wrapper](https://git.smukx.site/smukx/Dyncvoke)

## License

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.

## Disclaimer

For authorised offensive security work, CTFs, malware research, and detection engineering only. 
