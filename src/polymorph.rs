use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use std::collections::HashSet;

#[derive(Copy, Clone, Debug)]
pub struct BuildSeed(pub u64);

impl BuildSeed {
    pub fn from_os() -> Self {
        BuildSeed(rand::random::<u64>())
    }
}

impl Default for BuildSeed {
    fn default() -> Self {
        Self::from_os()
    }
}

pub struct Polymorph {
    rng: SmallRng,
    issued_idents: HashSet<String>,
    api_key: u8,
}

const RESERVED: &[&str] = &[
    "fn", "let", "mut", "pub", "use", "mod", "as", "if", "in", "for", "while", "loop",
    "match", "ref", "self", "Self", "super", "type", "trait", "impl", "struct", "enum",
    "where", "true", "false", "static", "const", "extern", "unsafe", "move", "box", "do",
    "yield", "crate", "async", "await", "dyn", "return", "break", "continue", "else",
    "main", "new", "drop", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "usize",
    "isize", "bool", "char", "str", "String",
];

impl Polymorph {
    pub fn from_seed(seed: BuildSeed) -> Self {
        let mut rng = SmallRng::seed_from_u64(seed.0);
        let api_key = loop {
            let k: u8 = rng.random();
            if k != 0 {
                break k;
            }
        };
        Self {
            rng,
            issued_idents: HashSet::new(),
            api_key,
        }
    }

    pub fn api_key(&self) -> u8 {
        self.api_key
    }

    pub fn random_ident(&mut self, _hint: &str) -> String {
        for _ in 0..32 {
            let len = self.rng.random_range(7..11);
            let mut s = String::with_capacity(len);
            s.push((b'a' + self.rng.random_range(0..26u8)) as char);
            for _ in 1..len {
                let pool = b"abcdefghijklmnopqrstuvwxyz0123456789_";
                let i = self.rng.random_range(0..pool.len());
                s.push(pool[i] as char);
            }
            if RESERVED.contains(&s.as_str()) {
                continue;
            }
            if self.issued_idents.insert(s.clone()) {
                return s;
            }
        }
        panic!("polymorph: failed to produce a unique identifier in 32 attempts");
    }

    pub fn jitter(&mut self, base: u32, pct: u32) -> u32 {
        let delta = base * pct / 100;
        let lo = base.saturating_sub(delta);
        let hi = base + delta;
        let v = self.rng.random_range(lo..=hi);
        (v / 25) * 25
    }

    pub fn xor_bytes_literal(&self, plain: &[u8], key: u8) -> String {
        let parts: Vec<String> = plain
            .iter()
            .map(|b| format!("0x{:02x}", b ^ key))
            .collect();
        format!("[{}]", parts.join(", "))
    }

    pub fn pick<T: Copy>(&mut self, choices: &[T]) -> T {
        let i = self.rng.random_range(0..choices.len());
        choices[i]
    }

    pub fn random_u64(&mut self) -> u64 {
        self.rng.random()
    }

    pub fn random_odd_u64(&mut self) -> u64 {
        let v: u64 = self.rng.random();
        v | 1
    }
}
