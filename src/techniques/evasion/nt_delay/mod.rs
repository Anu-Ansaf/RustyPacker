//! NtDelayExecution-based sleep evasion.
//!
//! Emits a single `pause(N);` call into ONE of three template placeholders
//! based on the user's `placement` choice. The `pause` function already
//! exists in every injection template (each one wraps either NtDelayExecution
//! via dynamic resolution / indirect syscall, or std::thread::sleep).

use crate::techniques::{BuildContext, Technique, TechniqueMeta};

pub struct NtDelay;

impl Technique for NtDelay {
    fn meta(&self) -> &'static TechniqueMeta { &NT_DELAY_META }

    fn apply(&self, ctx: &mut BuildContext) -> anyhow::Result<()> {
        let raw_ms = ctx.param("nt_delay", "delay_ms").unwrap_or("3000");
        let ms: u64 = raw_ms.trim().parse().unwrap_or(3000);
        if ms == 0 {
            return Ok(()); // no-op when user clears the field
        }

        let placement = ctx
            .param("nt_delay", "placement")
            .unwrap_or("Between every step");

        let call = format!("{{{{FN_PAUSE}}}}({});", ms);

        match placement {
            "At start" => {
                ctx.set_replacement("{{NT_DELAY_AT_START}}", call);
            }
            "Before execution only" => {
                ctx.set_replacement("{{NT_DELAY_FINAL}}", call);
            }
            _ => {
                // Default: between every step.
                ctx.set_replacement("{{NT_DELAY_STEP}}", call);
            }
        }
        Ok(())
    }
}

pub use super::super::NT_DELAY_META;
