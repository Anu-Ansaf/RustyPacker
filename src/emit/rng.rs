pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn from_seed(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn token(&mut self, len: usize) -> String {
        let letters: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
        let mixed:   &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
        let mut s = String::with_capacity(len.max(1));
        let first = (self.next_u64() as usize) % letters.len();
        s.push(letters[first] as char);
        for _ in 1..len.max(1) {
            let v = (self.next_u64() as usize) % mixed.len();
            s.push(mixed[v] as char);
        }
        s
    }

    pub fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        let mut i = 0;
        while i < n {
            let v = self.next_u64().to_le_bytes();
            let take = (n - i).min(8);
            out[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
        out
    }
}

pub fn os_seed_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("getrandom");
    v
}
