use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct Ntapc;

impl Technique for Ntapc {
    fn meta(&self) -> &'static TechniqueMeta { &NTAPC_META }
    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        ctx.set_template("ntAPC");
        ctx.apply_exec_mode("ntapc");
        Ok(())
    }
}

pub use super::super::NTAPC_META;
