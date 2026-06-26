use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Sink {
    buf: Arc<Mutex<String>>,
}

impl Sink {
    pub fn new(buf: Arc<Mutex<String>>) -> Self {
        Self { buf }
    }

    pub fn write(&self, line: &str) {
        if let Ok(mut g) = self.buf.lock() {
            g.push_str(line);
            g.push('\n');
        }
    }
}
