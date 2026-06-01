//! Static metadata types for techniques. Every technique provides a
//! `&'static TechniqueMeta` describing itself to the GUI and CLI.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Encryption,
    Injection,
    Evasion,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Encryption => "encryption",
            Category::Injection => "injection",
            Category::Evasion => "evasion",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Format {
    Exe,
    Dll,
    DllSideload,
}

#[derive(Debug, Clone, Copy)]
pub enum Requirement {
    /// Technique needs a target process name (remote injection).
    TargetProcess,
    /// Technique only works with the given output format.
    Format(Format),
    /// Technique injects into the current process (no remote target).
    SelfInjection,
}

#[derive(Debug, Clone, Copy)]
pub enum ParamSpec {
    Text   { name: &'static str, label: &'static str, default: &'static str },
    Bool   { name: &'static str, label: &'static str, default: bool },
    Choice { name: &'static str, label: &'static str, options: &'static [&'static str] },
}

#[derive(Debug)]
pub struct TechniqueMeta {
    pub id: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub category: Category,
    pub tags: &'static [&'static str],
    pub requires: &'static [Requirement],
    pub incompatible_with: &'static [&'static str],
    pub params: &'static [ParamSpec],
}

include!("types_tests.rs");
