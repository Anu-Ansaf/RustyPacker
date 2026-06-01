# Development notes

Everything you need to extend RustyPacker, add techniques, write a new
template, plug into the GUI, ship a feature.

If you're new to the codebase, read [Mental model](#mental-model) first, then
jump to whichever worked example matches what you want to build.

---

## Table of contents

- [Development notes](#development-notes)
  - [Table of contents](#table-of-contents)
  - [Mental model](#mental-model)
  - [Project layout](#project-layout)
  - [The technique system](#the-technique-system)
    - [How the registry is generated](#how-the-registry-is-generated)
    - [`technique.toml` manifest format](#techniquetoml-manifest-format)
    - [The `Technique` trait](#the-technique-trait)
    - [`BuildContext` API reference](#buildcontext-api-reference)
  - [Placeholders](#placeholders)
    - [Standard placeholder catalogue](#standard-placeholder-catalogue)
    - [Single-writer vs multi-writer](#single-writer-vs-multi-writer)
    - [Adding a new placeholder](#adding-a-new-placeholder)
  - [Worked examples](#worked-examples)
    - [A. Add an evasion / anti-debug check](#a-add-an-evasion--anti-debug-check)
    - [B. Add a self-injection technique that reuses `callbackExec`](#b-add-a-self-injection-technique-that-reuses-callbackexec)
    - [C. Add an injection technique with its own template](#c-add-an-injection-technique-with-its-own-template)
  - [GUI integration](#gui-integration)
    - [How a new technique surfaces](#how-a-new-technique-surfaces)
    - [The row-builder pattern](#the-row-builder-pattern)
    - [Adding a brand-new section to Configure](#adding-a-brand-new-section-to-configure)
    - [FlowCase reflections](#flowcase-reflections)
  - [State \& persistence](#state--persistence)
  - [Build pipeline at runtime](#build-pipeline-at-runtime)
  - [DLL Sideload mechanism](#dll-sideload-mechanism)
  - [Theme system](#theme-system)
  - [Testing \& debugging tips](#testing--debugging-tips)
  - [Common pitfalls](#common-pitfalls)

---

## Mental model

Three layers:

```
 ┌────────────────────────────────────┐
 │   GUI (egui, src/gui/*)            │   ← user picks techniques & params
 └────────────────────────────────────┘
                  │  AppState  →  Order
                  ▼
 ┌────────────────────────────────────┐
 │   Puzzle (src/puzzle.rs)           │   ← walks techniques, copies template,
 │   + Techniques (src/techniques/)   │     fills placeholders, writes Cargo.toml
 └────────────────────────────────────┘
                  │
                  ▼
 ┌────────────────────────────────────┐
 │   Compiler (src/compiler.rs)       │   ← runs `cargo build --release`
 └────────────────────────────────────┘
                  │
                  ▼
                payload
```

The middle layer is the interesting one. A "technique" is a plugin discovered
at compile time. Each technique decides which template directory to copy and
what string substitutions to make. The GUI just lists what's in the registry
and lets the user pick + parameterise; the puzzle layer turns those picks
into a Rust project on disk; the compiler runs `cargo` on it.

**Most new work happens inside `src/techniques/<category>/<id>/`** with
optional changes to a `templates/<TemplateDir>/`. You rarely touch the GUI
unless you're adding a brand-new section.

---

## Project layout

```
src/
├── bin/gui.rs                # binary entry point, just constructs the App
├── lib.rs                    # crate root, re-exports modules
├── build_log.rs              # thread-safe log sink the compiler streams into
├── compiler.rs               # spawns `cargo build`, streams stdout/stderr
├── order.rs                  # Order DTO (what the GUI hands off to puzzle.rs)
├── puzzle.rs                 # the assembler, orchestrates techniques + template
├── sideload.rs               # DLL Sideload (.def gen, proxy rewiring)
├── pe_parser.rs              # parse exports from target DLLs for sideload preview
├── shellcode_reader.rs       # raw-shellcode helpers
├── tools.rs                  # random keys/IVs, path helpers
├── techniques/
│   ├── mod.rs                # registry glue (REGISTRY included from OUT_DIR)
│   ├── types.rs              # TechniqueMeta, ParamSpec, Category, Requirement
│   ├── build_context.rs      # BuildContext struct + helpers
│   ├── encryption/{aes,xor,uuid}/
│   ├── injection/{syscrt,sysfiber,wincrt,earlycascade,enum_*,rtl_user_fiber_start,cdef_folder_menu}/
│   └── evasion/{nt_delay,domain_pin,anti_debug_*}/
└── gui/
    ├── mod.rs                # App impl, validation, top-level draw dispatch
    ├── state.rs              # AppState (persisted via eframe::set_value)
    ├── theme.rs              # Tactical + Cyberpunk palettes
    ├── widgets.rs            # all custom drawing primitives
    ├── tab_configure.rs      # the Configure tab + the row_builder helper
    ├── tab_flowcase.rs       # FlowCase tab
    └── tab_console.rs        # Console tab
templates/                    # one folder per injection template
build.rs                      # at compile time: walks techniques/, emits registry.rs
```

Generated, never in git:

```
shared/output_<unix-ts>/      # one directory per build
target/                       # cargo's
```

---

## The technique system

### How the registry is generated

`build.rs` runs at compile time (Cargo build script). It:

1. Walks `src/techniques/{encryption,injection,evasion}/*/technique.toml`.
2. Parses each manifest. Panics if `id` is invalid, `category` doesn't match
   the folder, or two techniques claim the same `id`.
3. Emits `$OUT_DIR/registry.rs` containing:
   - A `pub static <ID>_META: TechniqueMeta = …` for every technique.
   - A `pub mod <category> { #[path = "…/mod.rs"] pub mod <id>; }` tree.
   - A `static REGISTRY: &[&'static dyn Technique]` array.

`src/techniques/mod.rs` includes that file via `include!`. From the rest of
the codebase you only ever call `techniques::all()`, `techniques::find(id)`,
or `techniques::by_category(cat)`.

The "discover by filesystem walk" model means **you never edit a registry
list to add a technique**, you just create the folder.

### `technique.toml` manifest format

```toml
id = "my_thing"                # snake_case, ^[a-z][a-z0-9_]*$, globally unique
display_name = "My Thing"      # what the user sees in dropdowns / rows
description = "One-liner."     # short blurb shown under the picker
category = "evasion"           # "encryption" | "injection" | "evasion"

tags = ["anti_debug"]          # free-form. UI uses these for grouping:
                               #   - "anti_debug" → goes in the Anti-Debug section
                               #   - "self_injection" / "remote_injection" → drives Injection SELF/REMOTE switch
                               #   - "syscall" → shown as a tag pill

requires = ["self_injection"]  # validation hints, parsed by build.rs.
                               # Allowed: "target_process", "self_injection",
                               #          "format:exe", "format:dll"

incompatible_with = []         # reserved; not enforced yet

template_dir = "MyTemplate"    # injection only. Folder under templates/.
                               # Multiple techniques may share one folder.

# Repeatable. One [[params]] block per user-configurable knob.
[[params]]
name = "delay_ms"              # snake_case
kind = "text"                  # "text" | "bool" | "choice"
label = "Delay (ms)"           # label shown next to the input
default = "3000"               # default value (string for text, bool for bool)

[[params]]
name = "placement"
kind = "choice"
label = "Placement"
options = ["Between every step", "Before execution only", "At start"]
```

### The `Technique` trait

```rust
pub trait Technique: Send + Sync {
    fn meta(&self) -> &'static TechniqueMeta;
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()>;
}
```

You implement this on a unit struct named in PascalCase of the manifest `id`
(`my_thing` → `MyThing`). `build.rs` references `crate::techniques::<cat>::<id>::<Pascal>`
when emitting the registry array, so the names must line up.

`apply` runs once per build, only if the user has selected this technique
(or, for evasion/anti-debug, included it in their list). Inside `apply` you
either choose the template (injection), write source files (encryption), or
set / append placeholder replacements.

### `BuildContext` API reference

Defined in `src/techniques/build_context.rs`.

```rust
pub struct BuildContext<'a> {
    pub shellcode_path: &'a Path,          // raw shellcode path from the user
    pub output_folder: PathBuf,            // shared/output_<ts>/
    pub src_dir: PathBuf,                  // shared/output_<ts>/src/
    pub replacements: HashMap<&'static str, String>,
    pub template_choice: Option<&'static str>,
    pub params: &'a HashMap<String, String>, // keys are "<id>.<param_name>"
}
```

Methods:

| Method                            | When to use                                                               |
| --------------------------------- | ------------------------------------------------------------------------- |
| `set_template(folder_name)`       | Injection only. Picks the template directory under `templates/`.          |
| `set_replacement(key, val)`       | Overwrite a `{{KEY}}`. Last writer wins.                                  |
| `append_replacement(key, val)`    | Append `val` after the existing value (newline-joined). For multi-writer. |
| `param(technique_id, param_name)` | Read a user-set param value. Returns `Option<&str>`.                      |

Direct field access:

- `ctx.shellcode_path`, for encryption techniques that read the raw bytes.
- `ctx.src_dir`, to write your own files (e.g. `input.aes` for AES).
- `ctx.output_folder`, for anything that needs the full project root.

---

## Placeholders

### Standard placeholder catalogue

| Placeholder                                                                                                                                                                                                                                                  | Owner / lifetime                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| `{{PATH_TO_SHELLCODE}}`                                                                                                                                                                                                                                      | Encryption, quoted path of encrypted blob.                                       |
| `{{DECRYPTION_FUNCTION}}`                                                                                                                                                                                                                                    | Encryption, top-level decryption fn.                                             |
| `{{MAIN}}`                                                                                                                                                                                                                                                   | Encryption, code that turns `vec` into plain shellcode.                          |
| `{{IMPORTS}}`                                                                                                                                                                                                                                                | Encryption, `use` lines for the decryption crate.                                |
| `{{DEPENDENCIES}}`                                                                                                                                                                                                                                           | Encryption (+ sideload), extra `[dependencies]` lines for Cargo.toml.            |
| `{{API_KEY}}`                                                                                                                                                                                                                                                | Always, random non-zero u8 used to XOR-obfuscate NTAPI names.                    |
| `{{OBF_NT_OPEN_PROCESS}}`, `{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}}`, `{{OBF_NT_WRITE_VIRTUAL_MEMORY}}`, `{{OBF_NT_PROTECT_VIRTUAL_MEMORY}}`, `{{OBF_NT_CREATE_THREAD_EX}}`, `{{OBF_NT_QUEUE_APC_THREAD}}`, `{{OBF_NT_TEST_ALERT}}`, `{{OBF_NT_DELAY_EXECUTION}}` | Always, byte arrays of XOR-obfuscated NTAPI names.                               |
| `{{TARGET_PROCESS}}`                                                                                                                                                                                                                                         | Remote injection, process name from param.                                       |
| `{{SANDBOX}}`                                                                                                                                                                                                                                                | **Multi-writer.** Each evasion + anti-debug appends a `fn …() {}` + call.         |
| `{{SANDBOX_IMPORTS}}`                                                                                                                                                                                                                                        | **Multi-writer.** Same as above for `use` lines.                                  |
| `{{NT_DELAY_AT_START}}`, `{{NT_DELAY_STEP}}`, `{{NT_DELAY_FINAL}}`                                                                                                                                                                                           | nt_delay evasion, only one is set per build based on `placement`.                |
| `{{CALLBACK_INVOKE}}`                                                                                                                                                                                                                                        | Injection (callbackExec), full unsafe body that allocs + invokes a callback API. |
| `{{INJECTION_HELPERS}}`                                                                                                                                                                                                                                      | Injection (callbackExec), module-level helpers (thread fns, get_teb…).           |
| `{{DLL_MAIN}}`                                                                                                                                                                                                                                               | Output-format step, DllMain + exported stubs (DLL / DllSideload only).           |
| `{{DLL_FORMAT}}`                                                                                                                                                                                                                                             | Output-format step, `[lib] crate-type` lines for Cargo.toml.                     |

All placeholders default to empty (set in `default_replacements` in
`puzzle.rs`) so an unset key never leaks through as literal text. If you
introduce a new placeholder, add it there.

### Single-writer vs multi-writer

The default semantics are **single-writer**: `set_replacement` overwrites,
last writer wins. Fine for placeholders that exactly one technique owns
(`{{TARGET_PROCESS}}`, `{{MAIN}}`, `{{CALLBACK_INVOKE}}`).

For placeholders that several techniques can contribute to, `{{SANDBOX}}`
is the canonical example, every anti-debug check + domain_pin all write into
it, use `append_replacement`. The order of appends matches the order the
techniques appear in `Order.evasions`, which in turn matches Anti-Debug
first, then Evasion (set in `AppState::to_order`).

Convention for code that goes into a multi-writer placeholder:

- Wrap your snippet in a uniquely-named function: `fn evasion_<id>() {}`.
- Call it at the bottom of the snippet (`evasion_<id>();`).
- Use fully-qualified paths in the function body
  (`winapi::um::processthreadsapi::ExitProcess(0)`) instead of `use` lines,
  so two contributors can't import the same symbol twice.

### Adding a new placeholder

1. Insert it into the template file(s) where you want it substituted.
2. Add an entry to `default_replacements` in `src/puzzle.rs` with an empty
   default.
3. Set / append it from the relevant `Technique::apply`.

---

## Worked examples

### A. Add an evasion / anti-debug check

Goal: a new anti-debug check that calls `IsDebuggerPresent` and exits.

**Folder:**

```
src/techniques/evasion/anti_debug_is_debugger/
├── technique.toml
└── mod.rs
```

**`technique.toml`:**

```toml
id = "anti_debug_is_debugger"
display_name = "IsDebuggerPresent"
description = "Cheapest user-mode debugger check."
category = "evasion"
tags = ["anti_debug"]
requires = []
incompatible_with = []
```

The `anti_debug` tag is what makes the GUI sort this into the Anti-Debug
section instead of the regular Evasion section.

**`mod.rs`:**

```rust
use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct AntiDebugIsDebugger;

impl Technique for AntiDebugIsDebugger {
    fn meta(&self) -> &'static TechniqueMeta { &ANTI_DEBUG_IS_DEBUGGER_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let snippet = r#"fn evasion_anti_debug_is_debugger() {
    unsafe {
        if winapi::um::debugapi::IsDebuggerPresent() != 0 {
            winapi::um::processthreadsapi::ExitProcess(0);
        }
    }
}
evasion_anti_debug_is_debugger();"#;
        ctx.append_replacement("{{SANDBOX}}", snippet.to_string());
        Ok(())
    }
}

pub use super::super::ANTI_DEBUG_IS_DEBUGGER_META;
```

That's it. `cargo run`, open the GUI → Anti-Debug section → `+ ADD CHECK`,
and the new entry is there.

The features you use (`debugapi`, `processthreadsapi`) need to be enabled in
every injection template's `Cargo.toml`. Most already are, see
`templates/*/Cargo.toml`. Add any missing ones if your snippet imports
something exotic.

### B. Add a self-injection technique that reuses `callbackExec`

`callbackExec` is a shared template for "alloc + copy + invoke a callback
API" self-injection. Adding a new one means writing only a manifest + a
small `mod.rs` that sets `{{CALLBACK_INVOKE}}`.

Example, `EnumProcessModules`-style execution (made up for illustration):

**Folder:**

```
src/techniques/injection/enum_modules/
├── technique.toml
└── mod.rs
```

**`technique.toml`:**

```toml
id = "enum_modules"
display_name = "EnumModules"
description = "Execute via a fictional EnumModules callback."
category = "injection"
tags = ["self_injection"]
requires = ["self_injection"]
incompatible_with = []
template_dir = "callbackExec"
```

**`mod.rs`:**

```rust
use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct EnumModules;

impl Technique for EnumModules {
    fn meta(&self) -> &'static TechniqueMeta { &ENUM_MODULES_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");
        let body = r#"
        let addr = VirtualAlloc(
            null_mut(),
            vec.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if addr.is_null() { return; }
        std::ptr::copy_nonoverlapping(vec.as_ptr(), addr as *mut u8, vec.len());
        // Replace with the real API call:
        // winapi::um::psapi::EnumProcessModules(
        //     winapi::um::processthreadsapi::GetCurrentProcess(),
        //     std::mem::transmute(addr),
        //     0,
        //     std::ptr::null_mut(),
        // );
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::ENUM_MODULES_META;
```

If the API takes a thread-able invocation (e.g. `CreateThread` wrapping a
callback), define your `extern "system" fn` in `{{INJECTION_HELPERS}}`,
that placeholder lives at module scope, above `main()`. See
`cdef_folder_menu/mod.rs` for a worked example.

If your snippet needs a new winapi feature, add it to
`templates/callbackExec/Cargo.toml`.

### C. Add an injection technique with its own template

Use this when the technique doesn't fit the alloc-and-callback model, e.g.
APC queues, syscalls, anything that pivots execution differently from the
existing templates.

**Folders:**

```
src/techniques/injection/my_thing/
├── technique.toml
└── mod.rs
templates/MyThing/
├── Cargo.toml
└── src/main.rs
```

**`technique.toml`:**

```toml
id = "my_thing"
display_name = "My Thing"
description = "One-liner."
category = "injection"
tags = ["self_injection"]      # or ["remote_injection"] + add a target_process param
requires = ["self_injection"]
incompatible_with = []
template_dir = "MyThing"
```

**`mod.rs`:**

```rust
use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct MyThing;

impl Technique for MyThing {
    fn meta(&self) -> &'static TechniqueMeta { &MY_THING_META }
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("MyThing");
        Ok(())
    }
}

pub use super::super::MY_THING_META;
```

**`templates/MyThing/Cargo.toml`:**

```toml
[package]
name = "MyThing"
version = "0.1.0"
edition = "2021"

{{DLL_FORMAT}}

[dependencies]
winapi = { version = "0.3", features = ["ntdef", "ntstatus", "impl-default", "libloaderapi", "processthreadsapi", "debugapi", "errhandlingapi", "winnt", "sysinfoapi"] }
{{DEPENDENCIES}}

[profile.release]
strip = true
opt-level = "z"
codegen-units = 1
panic = "abort"
lto = true
```

The winapi feature set above is the baseline used across all templates,
copy it so anti-debug / domain_pin snippets keep compiling regardless of
which injection a user picks.

**`templates/MyThing/src/main.rs`:** copy `templates/ntFIBER/src/main.rs`
as a starting point and adapt, it has all the standard placeholders wired
in already (`{{IMPORTS}}`, `{{SANDBOX}}`, `{{NT_DELAY_*}}`, decryption,
the dynamic NTAPI resolver `g()`, `pause()`, `check_environment()`).

A `cargo run` regenerates the registry. Test by selecting your technique in
the GUI and watching the Console tab for the build log.

---

## GUI integration

### How a new technique surfaces

Once your `technique.toml` parses cleanly:

| Category                   | UI surface                                                                                                           |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Encryption                 | Appears in the Encryption combobox in Configure.                                                                     |
| Injection                  | Appears in the Injection Template combobox, filtered by the `self_injection` / `remote_injection` tag → SELF/REMOTE. |
| Evasion (untagged)         | Appears in the Evasion `+ ADD EVASION` popup.                                                                        |
| Evasion (tag `anti_debug`) | Appears in the Anti-Debug `+ ADD CHECK` popup.                                                                       |

No GUI code changes needed for any of these.

If your technique declares `[[params]]`, the params automatically render in
the row (for evasion / anti-debug) or below the picker (for encryption /
injection) via `draw_params_into`. Supported `kind` values: `text`, `bool`,
`choice`.

### The row-builder pattern

`row_builder` (in `src/gui/tab_configure.rs`) renders a vertical list of
selected techniques + a `+ ADD …` button that opens a popup. It's reused
by both the Evasion and Anti-Debug sections, parameterised by:

```rust
fn row_builder(
    ui: &mut egui::Ui,
    selected: &mut Vec<String>,                                  // mutable selection
    params: &mut HashMap<String, String>,                        // shared with AppState
    available: &[&'static dyn crate::techniques::Technique],     // filtered candidates
    add_label: &str,                                             // "ADD CHECK" / "ADD EVASION"
    popup_id: &str,                                              // unique popup persistent id
    empty_hint: &str,                                            // shown when selected is empty
)
```

If you add a new multi-pick section, you can reuse this verbatim.

### Adding a brand-new section to Configure

1. Add a `Vec<String>` field to `AppState` (with `#[serde(default)]` for
   backward-compat).
2. Initialise it in `AppState::default()`.
3. Extend `AppState::to_order()` to fold it into `Order.evasions` (or
   wherever the runtime should process it) in the order you want.
4. Write a `draw_<section>` function in `tab_configure.rs` that:
   - filters the registry to your section's techniques,
   - calls `section_header(...)`,
   - wraps a `row_builder(...)` call in a `card(...)`.
5. Wire `draw_<section>` into the `draw(ui, state)` dispatcher near the top
   of `tab_configure.rs`.
6. Extend `validate_state` in `gui/mod.rs` to validate the new IDs.
7. Mirror it into `compute_steps` in `tab_flowcase.rs` so the FlowCase tab
   shows the new steps.

### FlowCase reflections

`tab_flowcase.rs::compute_steps` is the single source of truth for what the
FlowCase preview shows. It reads `AppState` directly. When you add a new
state field or new technique category, push a `Step { title, pill, accent }`
into the vec at the appropriate place in the execution order:

```
Loader starts → anti-debug → evasion → decrypt → (open target if remote)
   → alloc/write/protect → inject → detonate
```

Accent options: `Normal` (orange-ish), `Warn` (yellow), `Danger` (red).
Pill text is shouted upper-case; use `pill_for_injection(id)` style mapping
if your raw id is too long to read in caps.

---

## State & persistence

`AppState` (in `src/gui/state.rs`) is serialised to disk by `eframe` via
`set_value("app_state", &self.state)` in `App::save`. It loads at startup
through `eframe::get_value("app_state")`.

Rules of thumb:

- **Always** put `#[serde(default)]` on new fields so old saved state still
  loads.
- Don't put runtime-only data here (channels, flags). Keep it for user
  selections + params.
- Path types use `Option<PathBuf>`; the GUI treats `None` as "unset".

The `params: HashMap<String, String>` field stores every `[[params]]` value
the user has touched, keyed `"<technique_id>.<param_name>"`. Untouched params
fall back to their manifest defaults.

---

## Build pipeline at runtime

When the user hits **BUILD** (top-right of the title bar, handled in
`gui/mod.rs::App::start_build`):

1. `validate_state(&state)` runs synchronously. Bails with a banner on error.
2. `state.to_order()` produces an `Order` DTO.
3. A worker thread is spawned. It calls:
   ```rust
   let folder = puzzle::assemble(order);
   compiler::compile(&folder);
   ```
4. `puzzle::assemble`:
   - Creates `shared/output_<ts>/`.
   - Seeds `BuildContext.replacements` from `default_replacements`.
   - Runs the **injection** technique's `apply` (it picks the template).
   - Copies the chosen template into the output folder.
   - Runs the **encryption** technique's `apply` (writes encrypted blob,
     sets `{{MAIN}}` etc.).
   - Iterates `order.evasions`, calling each evasion's `apply`. Anti-debug
     entries come first because `to_order()` puts them first.
   - Applies output-format adjustments (DLL renames `main.rs` → `lib.rs` and
     fills `{{DLL_MAIN}}` + `{{DLL_FORMAT}}`; DllSideload also invokes
     `sideload::apply`).
   - Walks both `Cargo.toml` and the target source file and replaces every
     `{{KEY}}` with the accumulated `replacements` map.
5. `compiler::compile` runs `cargo build --release --target …` in that
   folder. Stdout/stderr are streamed line-by-line into `build_log`, which
   is mirrored into the Console tab.

If `cargo` fails, the panic propagates and the GUI surfaces the error.
The generated folder is **always left in place** for debugging.

---

## DLL Sideload mechanism

`src/sideload.rs` is invoked only when the user picks output format
`DLL Sideload`. Two modes:

- **Sideload (pure)**, generate a replacement DLL where the hijacked export
  carries the payload, and all other exports become no-op stubs. The user
  drops it alongside a vulnerable host app that loads it.
- **Proxy**, generate a `.def` file that forwards every non-hijacked
  export to the original DLL (renamed or via absolute path), so the host app
  keeps working while our hijacked export still detonates.

Proxy mode adds these to `{{DEPENDENCIES}}`:

```toml
lazy_static = "1.4"
dyncvoke = { git = "https://github.com/Whitecat18/Dyncvoke" }
```

`pe_parser::parse_exports` is what populates the `.def`; it also feeds the
inline exports preview in the Configure tab.

DllSideload requires a **self-injection** technique; the validator enforces
this.

---

## Theme system

`src/gui/theme.rs` ships two themes:

- **Tactical** (orange-on-black, the original look).
- **Cyberpunk** (current default, magenta accents, mono-only typography,
  a faint scanline overlay painted on the foreground layer in `widgets.rs`).

The current theme is held in `AppState.active_theme` (persisted) and a
process-wide `AtomicU8`. Widgets read colours through `palette::*`
accessors that branch on the atomic. Switch via the `◆` button in the
title bar.

To add a third theme:

1. Add a variant to the `Theme` enum and `Theme::ALL`.
2. Implement a `Palette` static (copy `TACTICAL_PAL` / `CYBERPUNK_PAL`).
3. Wire it in `Theme::palette()`, `Theme::label()`, `Theme::mono_only()`.

---

## Testing & debugging tips

- **No headless tests for the GUI**, `cargo run` and click around. Speed
  this up with `cargo build` once, then `target/release/RustPacker`.
- **Inspect a generated build**: `shared/output_<ts>/` is left untouched on
  every build. Open `src/main.rs` to see exactly what your `apply` calls
  produced. Any unresolved `{{PLACEHOLDER}}` text is a clue you forgot a
  default in `puzzle.rs::default_replacements`.
- **Cargo errors from the generated project**: re-run `cargo build` in the
  output folder by hand to see them without the GUI's line-buffering.
- **Append ordering**: if multiple anti-debug checks need to run in a
  specific order, the order in `Order.evasions` is the iteration order, and
  that order is "anti-debug first (in selection order), then evasions (in
  selection order)" per `AppState::to_order()`.
- **Validation gotcha**: `validate_state` runs at frame time *and* on build
  start. Any `Err` from it blocks the build button.
- **Title bar version**: comes from `env!("CARGO_PKG_VERSION")`, bump
  `Cargo.toml` and rebuild.

---

## Common pitfalls

- **Forgetting `default_replacements`**: if your new template uses
  `{{MY_THING}}` and you forget to seed it with `String::new()`, an unset
  build leaks `{{MY_THING}}` into the source as literal text, and `cargo
  build` errors with a syntax error.
- **Two techniques setting the same single-writer placeholder**: only the
  last one wins. If you want stacking semantics, use `append_replacement`
  and uniquify your function names.
- **Duplicate `use` lines from multi-writer imports**: prefer
  fully-qualified paths inside multi-writer snippets, so two techniques
  importing the same symbol don't collide at compile time.
- **`tags` typos**: the Anti-Debug filter is a literal string match on
  `"anti_debug"`. Misspell it and your check ends up in the regular Evasion
  list.
- **Manifest `id` mismatch**: `id` in the manifest, the folder name, and
  the PascalCase struct in `mod.rs` must all line up. `build.rs` will panic
  with a useful message when they don't.
- **Adding a `[[params]]` without restarting the GUI**: persisted state
  doesn't carry the new param's default until the user touches it. If
  you're testing defaults, clear your state via `eframe`'s data dir
  (`%APPDATA%/RustPacker/` on Windows).
- **Generated source uses a winapi feature your template doesn't enable**:
  add the feature to `templates/<dir>/Cargo.toml`. The baseline feature set
  (debugapi, errhandlingapi, processthreadsapi, winnt, sysinfoapi, ntdef,
  libloaderapi) is required across all templates so anti-debug + domain_pin
  always compile.
