use crate::techniques::{BuildContext, Technique, TechniqueMeta};
pub struct Earlycascade;
impl Technique for Earlycascade {
    fn meta(&self) -> &'static TechniqueMeta { &EARLYCASCADE_META }
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("ntEarlyCascade");
        let tgt = ctx.param("earlycascade", "target_process").unwrap_or("dllhost.exe");
        ctx.set_replacement("{{TARGET_PROCESS}}", tgt.to_string());
        Ok(())
    }
}
pub use super::super::EARLYCASCADE_META;
