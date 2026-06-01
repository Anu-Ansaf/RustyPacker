use crate::techniques::{BuildContext, Technique, TechniqueMeta};
pub struct Wincrt;
impl Technique for Wincrt {
    fn meta(&self) -> &'static TechniqueMeta { &WINCRT_META }
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("winCRT");
        let tgt = ctx.param("wincrt", "target_process").unwrap_or("dllhost.exe");
        ctx.set_replacement("{{TARGET_PROCESS}}", tgt.to_string());
        Ok(())
    }
}
pub use super::super::WINCRT_META;
