use crate::gui::theme::Theme;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Tab { Configure, FlowCase, Console }

impl Default for Tab { fn default() -> Self { Self::Configure } }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SideloadMode { Sideload, Proxy }

impl Default for SideloadMode { fn default() -> Self { Self::Sideload } }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SideloadConfig {
    pub target_dll: Option<PathBuf>,
    pub hijack_export: String,
    pub mode: SideloadMode,
    pub renamed: String,            // proxy/relative mode — e.g. "Shaping.dll"
    pub use_absolute_path: bool,    // proxy/absolute mode
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppState {
    pub current_tab: Tab,

    pub shellcode_path: Option<PathBuf>,
    pub format: Format,
    pub output_path: Option<PathBuf>,

    pub encryption_id: String, // e.g. "aes"
    pub injection_id: String,  // e.g. "syscrt"
    pub enabled_evasions: Vec<String>,
    #[serde(default)]
    pub enabled_anti_debug: Vec<String>,

    /// Flat key/value, scoped by "<technique_id>.<param_name>".
    pub params: HashMap<String, String>,

    pub sideload: SideloadConfig,

    pub console_log: String,

    /// Active visual theme — persisted across runs.
    pub active_theme: Theme,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Format { Exe, Dll, DllSideload }

impl Default for Format { fn default() -> Self { Self::Exe } }

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Exe => "EXE",
            Format::Dll => "DLL",
            Format::DllSideload => "DLL SIDELOAD",
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            current_tab: Tab::Configure,
            shellcode_path: None,
            format: Format::Exe,
            output_path: None,
            encryption_id: "aes".to_string(),
            injection_id: "syscrt".to_string(),
            enabled_evasions: Vec::new(),
            enabled_anti_debug: Vec::new(),
            params: HashMap::new(),
            sideload: SideloadConfig::default(),
            console_log: String::new(),
            active_theme: Theme::default(),
        }
    }
}

impl AppState {
    pub fn to_order(&self) -> Option<crate::order::Order> {
        use crate::order::{
            Order, OutputFormat, SideloadConfig as OrderSideload, SideloadMode as OrderMode,
        };

        let sideload = match self.format {
            Format::DllSideload => {
                let target = self.sideload.target_dll.clone()?;
                Some(OrderSideload {
                    target_dll: target,
                    hijack_export: self.sideload.hijack_export.clone(),
                    mode: match self.sideload.mode {
                        SideloadMode::Sideload => OrderMode::Sideload,
                        SideloadMode::Proxy => OrderMode::Proxy,
                    },
                    renamed: self.sideload.renamed.clone(),
                    use_absolute_path: self.sideload.use_absolute_path,
                })
            }
            _ => None,
        };

        Some(Order {
            shellcode_path: self.shellcode_path.clone()?,
            format: match self.format {
                Format::Exe         => OutputFormat::Exe,
                Format::Dll         => OutputFormat::Dll,
                Format::DllSideload => OutputFormat::DllSideload,
            },
            encryption_id: self.encryption_id.clone(),
            injection_id: self.injection_id.clone(),
            evasions: {
                // Anti-debug checks run first (bail out before sandbox/sleep evasions).
                let mut combined = self.enabled_anti_debug.clone();
                combined.extend(self.enabled_evasions.iter().cloned());
                combined
            },
            params: self.params.clone(),
            output: self.output_path.clone(),
            sideload,
        })
    }
}
