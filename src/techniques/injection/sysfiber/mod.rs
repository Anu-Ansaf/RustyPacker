use crate::techniques::{BuildContext, Technique, TechniqueMeta};
pub struct Sysfiber;
impl Technique for Sysfiber {
    fn meta(&self) -> &'static TechniqueMeta { &SYSFIBER_META }
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("sysFIBER");
        Ok(())
    }
}
pub use super::super::SYSFIBER_META;
