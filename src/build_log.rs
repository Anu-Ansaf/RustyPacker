//! Process-wide sink for build-pipeline output.
//!
//! The GUI installs a shared `Arc<Mutex<String>>` before kicking off a build;
//! every `blog!()` call from `puzzle`, `compiler`, `tools`, etc. appends a line
//! to that buffer so it can be rendered live in the Console tab. With no sink
//! installed the writes are silently dropped (the GUI binary has no stdout when
//! launched with `windows_subsystem = "windows"`).

use std::sync::{Arc, Mutex, OnceLock};

type SinkHandle = Arc<Mutex<String>>;

static SLOT: OnceLock<Mutex<Option<SinkHandle>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<SinkHandle>> {
    SLOT.get_or_init(|| Mutex::new(None))
}

pub fn set_sink(sink: SinkHandle) {
    *slot().lock().unwrap() = Some(sink);
}

pub fn clear_sink() {
    *slot().lock().unwrap() = None;
}

pub fn write(line: &str) {
    let sink_opt = slot().lock().unwrap().clone();
    if let Some(sink) = sink_opt {
        let mut buf = sink.lock().unwrap();
        buf.push_str(line);
        if !line.ends_with('\n') {
            buf.push('\n');
        }
    }
}

#[macro_export]
macro_rules! blog {
    ($($arg:tt)*) => {
        $crate::build_log::write(&format!($($arg)*))
    };
}
