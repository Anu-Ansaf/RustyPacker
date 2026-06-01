use crate::techniques::{BuildContext, Technique, TechniqueMeta};
pub struct Syscrt;
impl Technique for Syscrt {
    fn meta(&self) -> &'static TechniqueMeta { &SYSCRT_META }
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("sysCRT");
        let tgt = ctx.param("syscrt", "target_process").unwrap_or("dllhost.exe");
        ctx.set_replacement("{{TARGET_PROCESS}}", tgt.to_string());
        Ok(())
    }
}
pub use super::super::SYSCRT_META;
