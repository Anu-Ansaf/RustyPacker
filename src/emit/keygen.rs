use super::rng::Rng;

pub fn key_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut r = Rng::from_seed(seed.wrapping_mul(0xa537_24c1_fbd7_9e85).wrapping_add(0x1));
    r.next_bytes(len)
}
