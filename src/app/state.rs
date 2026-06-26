use crate::spec::{CheckId, EncryptionKind, LoaderKindSel, OutputFormSel, RemoteMethod, SelfInjectMethod, SideloadConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Tab {
    #[default]
    Build,
    Flow,
    Console,
}

pub use super::theme::Theme;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UiState {
    pub shellcode_path: Option<PathBuf>,
    pub delivery_path:  Option<PathBuf>,

    pub loader: LoaderKindSel,
    pub selfinject_method: SelfInjectMethod,
    pub remote_method: RemoteMethod,
    pub output: OutputFormSel,
    pub dll_export: String,
    pub target_exe: String,

    pub encryption: EncryptionKind,
    pub checks_on:  BTreeMap<CheckId, bool>,
    pub check_params: BTreeMap<String, String>,

    pub gpu_storage: bool,

    pub sideload: SideloadConfig,

    pub tab: Tab,
    pub theme: Theme,
}
