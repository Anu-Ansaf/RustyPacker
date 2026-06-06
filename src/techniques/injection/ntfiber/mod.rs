use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct Ntfiber;

impl Technique for Ntfiber {
    fn meta(&self) -> &'static TechniqueMeta { &NTFIBER_META }
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("ntFIBER");
        ctx.apply_exec_mode("ntfiber");
        Ok(())
    }
}

pub use super::super::NTFIBER_META;
