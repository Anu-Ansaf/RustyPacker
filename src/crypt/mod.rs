use aes::cipher::{KeyIvInit, StreamCipher};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Field;
use k256::{EncodedPoint, ProjectivePoint, Scalar};
use rand_core::OsRng;
use sha2::Digest;

use crate::emit::{Item, Namebook};
use crate::spec::EncryptionKind;

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

/// Aux const that needs to ride along the encrypted blob into the loader source.
#[derive(Debug, Clone)]
pub struct AuxConst {
    /// `'r'` for the secp256k1 R point. Single letter so loader naming stays compact.
    pub tag:   char,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EncryptOut {
    pub blob: Vec<u8>,
    pub key:  Vec<u8>,
    pub aux:  Vec<AuxConst>,
}

pub fn encrypt(kind: EncryptionKind, plain: &[u8], seed: u64) -> EncryptOut {
    match kind {
        EncryptionKind::Xor8        => enc_xor8(plain, seed),
        EncryptionKind::AesCtr      => enc_aes_ctr(plain, seed),
        EncryptionKind::Rc4         => enc_rc4(plain, seed),
        EncryptionKind::Khufu       => enc_khufu(plain, seed),
        EncryptionKind::CamelliaToy => enc_camellia_toy(plain, seed),
        EncryptionKind::Ecies       => enc_ecies(plain),
    }
}

pub fn extra_emit_deps(kind: EncryptionKind) -> Vec<&'static str> {
    match kind {
        EncryptionKind::AesCtr      => vec!["aes = \"0.8\"", "ctr = \"0.9\""],
        EncryptionKind::Ecies       => vec![
            "k256 = { version = \"0.13\", default-features = false, features = [\"arithmetic\"] }",
            "sha2 = { version = \"0.10\", default-features = false }",
        ],
        _ => vec![],
    }
}

pub fn loader_decoder_items(kind: EncryptionKind, n: &Namebook) -> Vec<Item> {
    match kind {
        EncryptionKind::Xor8 => vec![Item::Fn {
            sig: format!("fn {}(src: &[u8], k: &[u8]) -> Vec<u8>", n.fn_decode),
            body: "    src.iter().enumerate().map(|(i, b)| b ^ k[i % k.len()]).collect()".into(),
        }],
        EncryptionKind::AesCtr => vec![Item::Raw(format!(
            r#"fn {dec}(src: &[u8], k: &[u8]) -> Vec<u8> {{
    use aes::cipher::{{KeyIvInit, StreamCipher}};
    type C = ctr::Ctr64BE<aes::Aes256>;
    let mut key = [0u8; 32];
    key.copy_from_slice(&k[..32]);
    let iv = [0u8; 16];
    let mut buf = src.to_vec();
    let mut c = C::new(&key.into(), &iv.into());
    c.apply_keystream(&mut buf);
    buf
}}"#,
            dec = n.fn_decode
        ))],
        EncryptionKind::Rc4 => vec![Item::Raw(format!(
            r#"fn {dec}(src: &[u8], k: &[u8]) -> Vec<u8> {{
    let mut s = [0u8; 256];
    for i in 0..256 {{ s[i] = i as u8; }}
    let mut j = 0usize;
    for i in 0..256 {{
        j = (j + s[i] as usize + k[i % k.len()] as usize) % 256;
        s.swap(i, j);
    }}
    let mut out = Vec::with_capacity(src.len());
    let (mut x, mut y) = (0usize, 0usize);
    for &b in src {{
        x = (x + 1) % 256;
        y = (y + s[x] as usize) % 256;
        s.swap(x, y);
        let t = (s[x] as usize + s[y] as usize) % 256;
        out.push(b ^ s[t]);
    }}
    out
}}"#,
            dec = n.fn_decode
        ))],
        EncryptionKind::Khufu => vec![Item::Raw(format!(
            r#"fn {dec}(src: &[u8], k: &[u8]) -> Vec<u8> {{
    const ROUNDS: usize = 16;
    const BLOCK: usize = 8;
    const KEY_SIZE: usize = 64;
    fn sbox(key: &[u8], round: usize) -> [u32; 256] {{
        let mut s = [0u32; 256];
        for i in 0..256 {{
            s[i] = ((key[(round * 8 + i) % KEY_SIZE] as u32) << 24)
                | ((key[(round * 8 + i + 1) % KEY_SIZE] as u32) << 16)
                | ((key[(round * 8 + i + 2) % KEY_SIZE] as u32) << 8)
                | (key[(round * 8 + i + 3) % KEY_SIZE] as u32);
        }}
        s
    }}
    fn dec_block(block: &mut [u8; BLOCK], key: &[u8]) {{
        let mut left  = u32::from_be_bytes(block[0..4].try_into().unwrap());
        let mut right = u32::from_be_bytes(block[4..8].try_into().unwrap());
        left  ^= u32::from_be_bytes(key[8..12].try_into().unwrap());
        right ^= u32::from_be_bytes(key[12..16].try_into().unwrap());
        for round in (0..ROUNDS).rev() {{
            let s = sbox(key, round);
            let temp = right;
            right = left ^ s[(right & 0xFF) as usize];
            left = temp.rotate_left(8);
            core::mem::swap(&mut left, &mut right);
        }}
        left  ^= u32::from_be_bytes(key[0..4].try_into().unwrap());
        right ^= u32::from_be_bytes(key[4..8].try_into().unwrap());
        block[..4].copy_from_slice(&left.to_be_bytes());
        block[4..].copy_from_slice(&right.to_be_bytes());
    }}
    let mut buf = src.to_vec();
    let pad = (BLOCK - buf.len() % BLOCK) % BLOCK;
    buf.extend(core::iter::repeat(0u8).take(pad));
    for chunk in buf.chunks_exact_mut(BLOCK) {{
        let mut blk: [u8; BLOCK] = chunk.try_into().unwrap();
        dec_block(&mut blk, k);
        chunk.copy_from_slice(&blk);
    }}
    buf.truncate(src.len());
    buf
}}"#,
            dec = n.fn_decode
        ))],
        EncryptionKind::CamelliaToy => vec![Item::Raw(format!(
            r#"fn {dec}(src: &[u8], k: &[u8]) -> Vec<u8> {{
    const BLOCK: usize = 16;
    static SBOX: [u8; 256] = [
         60,242, 25,216, 58, 27, 73, 52,207,254,213, 69, 21, 90, 66,193,
         39,162, 33,153,235,  1, 57, 28,205, 23,128,149, 74,146,141,246,
        117,252, 80, 53,229,184,192,136,113,111,181,133,253,164,188,250,
         82,110, 35,233,220,125,215,208,206,203, 18,138,196,104,140,226,
        101,160,156, 78, 30,137, 17,152, 62,170, 56,230,225,249,157, 63,
        166,143,202, 32, 44, 98,144,198,108,183, 92,147,214,190,174,243,
        211,179,175, 10, 42, 59,139,100, 49, 13,131,102, 50, 76,109, 68,
        103, 34,118, 47,151,  4,199,248, 46, 16,123, 81,234, 70,223,201,
        155,  2, 64,  0,107,239, 12,218, 40,142, 19,221, 29,  3,178, 88,
        126,119, 11,209,121,150,238, 97,231,182,245, 77,177, 94,161, 26,
         89, 54,244,180,176,232, 22, 48, 91,173, 24,227,112, 87,169,  5,
        185,135, 71,224,210,191, 79,129,145,251,200,130,167,186, 75,115,
        163, 72,105,217,116, 15,236,195, 61, 31,241,  7,114,197, 45,159,
        237,222, 51,168,132,165,171,219,127,  6,124,204, 95,122,247,187,
        106,189,158, 38, 14, 37, 20,228, 86, 93,  9, 67, 43,255,148, 55,
        154,240, 65, 84, 85,  8,172, 99, 41,194,212,120, 96, 36,134, 83,
    ];
    fn round_f(input: u64, key: u64) -> u64 {{
        let input = input ^ key;
        let mut y = [0u8; 8];
        for i in 0..8 {{
            y[i] = SBOX[((input >> (56 - i * 8)) & 0xFF) as usize];
        }}
        y.iter().enumerate().fold(0u64, |acc, (i, &val)| acc | ((val as u64) << (56 - i * 8)))
    }}
    let k1 = u64::from_be_bytes(k[0..8].try_into().unwrap());
    let k2 = u64::from_be_bytes(k[8..16].try_into().unwrap());
    let mut buf = src.to_vec();
    let pad = (BLOCK - buf.len() % BLOCK) % BLOCK;
    buf.extend(core::iter::repeat(0u8).take(pad));
    for chunk in buf.chunks_exact_mut(BLOCK) {{
        let mut left  = u64::from_be_bytes(chunk[0..8].try_into().unwrap());
        let mut right = u64::from_be_bytes(chunk[8..16].try_into().unwrap());
        core::mem::swap(&mut left, &mut right);
        for _ in 0..8 {{
            left  ^= round_f(right, k2);
            right ^= round_f(left,  k1);
        }}
        chunk[..8].copy_from_slice(&left.to_be_bytes());
        chunk[8..].copy_from_slice(&right.to_be_bytes());
    }}
    buf.truncate(src.len());
    buf
}}"#,
            dec = n.fn_decode
        ))],
        EncryptionKind::Ecies => vec![Item::Raw(format!(
            r#"fn {dec}(src: &[u8], k: &[u8], r_bytes: &[u8]) -> Vec<u8> {{
    use k256::{{EncodedPoint, ProjectivePoint, Scalar}};
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::elliptic_curve::PrimeField;
    use sha2::Digest;

    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&k[..32]);
    let private = Scalar::from_repr(sk_bytes.into()).unwrap();

    let r_enc = EncodedPoint::from_bytes(r_bytes).expect("r point");
    let r = ProjectivePoint::from_encoded_point(&r_enc).unwrap();
    let shared = (r * private).to_affine();
    let shared_bytes = shared.to_bytes();

    let mut h = sha2::Sha256::new();
    h.update(shared_bytes);
    let key_stream = h.finalize();

    src.iter()
        .zip(key_stream.iter().cycle())
        .map(|(&b, &k)| b ^ k)
        .collect()
}}"#,
            dec = n.fn_decode
        ))],
    }
}

pub fn loader_decode_call(kind: EncryptionKind, n: &Namebook) -> String {
    match kind {
        EncryptionKind::Ecies => format!(
            "{}({}, &{}, &{})",
            n.fn_decode, n.const_blob, n.const_key, n.const_rpoint
        ),
        _ => format!("{}({}, &{})", n.fn_decode, n.const_blob, n.const_key),
    }
}

// ---------------------------------------------------------------------- algorithms

fn enc_xor8(plain: &[u8], seed: u64) -> EncryptOut {
    let key = crate::emit::keygen::key_bytes(seed, 32);
    let blob = plain
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    EncryptOut { blob, key, aux: vec![] }
}

fn enc_aes_ctr(plain: &[u8], seed: u64) -> EncryptOut {
    let key = crate::emit::keygen::key_bytes(seed, 32);
    let mut k = [0u8; 32];
    k.copy_from_slice(&key);
    let iv = [0u8; 16];
    let mut buf = plain.to_vec();
    let mut c = Aes256Ctr::new(&k.into(), &iv.into());
    c.apply_keystream(&mut buf);
    EncryptOut { blob: buf, key, aux: vec![] }
}

fn enc_rc4(plain: &[u8], seed: u64) -> EncryptOut {
    let key = crate::emit::keygen::key_bytes(seed, 32);
    let mut s = [0u8; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut out = Vec::with_capacity(plain.len());
    let (mut x, mut y) = (0usize, 0usize);
    for &b in plain {
        x = (x + 1) % 256;
        y = (y + s[x] as usize) % 256;
        s.swap(x, y);
        let t = (s[x] as usize + s[y] as usize) % 256;
        out.push(b ^ s[t]);
    }
    EncryptOut { blob: out, key, aux: vec![] }
}

fn enc_khufu(plain: &[u8], seed: u64) -> EncryptOut {
    let key = khufu_key_from_seed(seed);
    const ROUNDS: usize = 16;
    const BLOCK: usize = 8;
    const KEY_SIZE: usize = 64;

    fn sbox(key: &[u8], round: usize) -> [u32; 256] {
        let mut s = [0u32; 256];
        for i in 0..256 {
            s[i] = ((key[(round * 8 + i) % KEY_SIZE] as u32) << 24)
                | ((key[(round * 8 + i + 1) % KEY_SIZE] as u32) << 16)
                | ((key[(round * 8 + i + 2) % KEY_SIZE] as u32) << 8)
                | (key[(round * 8 + i + 3) % KEY_SIZE] as u32);
        }
        s
    }

    fn enc_block(block: &mut [u8; BLOCK], key: &[u8]) {
        let mut left = u32::from_be_bytes(block[0..4].try_into().unwrap());
        let mut right = u32::from_be_bytes(block[4..8].try_into().unwrap());
        left ^= u32::from_be_bytes(key[0..4].try_into().unwrap());
        right ^= u32::from_be_bytes(key[4..8].try_into().unwrap());
        for round in 0..ROUNDS {
            let s = sbox(key, round);
            let temp = left;
            left = right ^ s[(left & 0xFF) as usize];
            right = temp.rotate_right(8);
            std::mem::swap(&mut left, &mut right);
        }
        left ^= u32::from_be_bytes(key[8..12].try_into().unwrap());
        right ^= u32::from_be_bytes(key[12..16].try_into().unwrap());
        block[..4].copy_from_slice(&left.to_be_bytes());
        block[4..].copy_from_slice(&right.to_be_bytes());
    }

    let mut buf = plain.to_vec();
    let pad = (BLOCK - buf.len() % BLOCK) % BLOCK;
    buf.resize(buf.len() + pad, 0u8);
    for chunk in buf.chunks_exact_mut(BLOCK) {
        let mut blk: [u8; BLOCK] = chunk.try_into().unwrap();
        enc_block(&mut blk, &key);
        chunk.copy_from_slice(&blk);
    }

    EncryptOut {
        blob: buf,
        key,
        aux: vec![],
    }
}

fn khufu_key_from_seed(seed: u64) -> Vec<u8> {
    let mut k: Vec<u8> = (0u8..64).collect();
    let mut rng = crate::emit::rng::Rng::from_seed(seed.wrapping_mul(0x3779_b9cf_4a7c_15a5).wrapping_add(7));
    for i in (1..k.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        k.swap(i, j);
    }
    k
}

fn enc_camellia_toy(plain: &[u8], seed: u64) -> EncryptOut {
    let key = crate::emit::keygen::key_bytes(seed, 16);
    let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
    let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());

    const BLOCK: usize = 16;
    static SBOX: [u8; 256] = [
         60,242, 25,216, 58, 27, 73, 52,207,254,213, 69, 21, 90, 66,193,
         39,162, 33,153,235,  1, 57, 28,205, 23,128,149, 74,146,141,246,
        117,252, 80, 53,229,184,192,136,113,111,181,133,253,164,188,250,
         82,110, 35,233,220,125,215,208,206,203, 18,138,196,104,140,226,
        101,160,156, 78, 30,137, 17,152, 62,170, 56,230,225,249,157, 63,
        166,143,202, 32, 44, 98,144,198,108,183, 92,147,214,190,174,243,
        211,179,175, 10, 42, 59,139,100, 49, 13,131,102, 50, 76,109, 68,
        103, 34,118, 47,151,  4,199,248, 46, 16,123, 81,234, 70,223,201,
        155,  2, 64,  0,107,239, 12,218, 40,142, 19,221, 29,  3,178, 88,
        126,119, 11,209,121,150,238, 97,231,182,245, 77,177, 94,161, 26,
         89, 54,244,180,176,232, 22, 48, 91,173, 24,227,112, 87,169,  5,
        185,135, 71,224,210,191, 79,129,145,251,200,130,167,186, 75,115,
        163, 72,105,217,116, 15,236,195, 61, 31,241,  7,114,197, 45,159,
        237,222, 51,168,132,165,171,219,127,  6,124,204, 95,122,247,187,
        106,189,158, 38, 14, 37, 20,228, 86, 93,  9, 67, 43,255,148, 55,
        154,240, 65, 84, 85,  8,172, 99, 41,194,212,120, 96, 36,134, 83,
    ];

    fn round_f(input: u64, key: u64) -> u64 {
        let input = input ^ key;
        let mut y = [0u8; 8];
        for i in 0..8 {
            y[i] = SBOX[((input >> (56 - i * 8)) & 0xFF) as usize];
        }
        y.iter()
            .enumerate()
            .fold(0u64, |acc, (i, &val)| acc | ((val as u64) << (56 - i * 8)))
    }

    let mut buf = plain.to_vec();
    let pad = (BLOCK - buf.len() % BLOCK) % BLOCK;
    buf.resize(buf.len() + pad, 0u8);
    for chunk in buf.chunks_exact_mut(BLOCK) {
        let mut left = u64::from_be_bytes(chunk[0..8].try_into().unwrap());
        let mut right = u64::from_be_bytes(chunk[8..16].try_into().unwrap());
        for _ in 0..8 {
            right ^= round_f(left, k1);
            left ^= round_f(right, k2);
        }
        std::mem::swap(&mut left, &mut right);
        chunk[..8].copy_from_slice(&left.to_be_bytes());
        chunk[8..].copy_from_slice(&right.to_be_bytes());
    }

    EncryptOut {
        blob: buf,
        key,
        aux: vec![],
    }
}

fn enc_ecies(plain: &[u8]) -> EncryptOut {
    let mut rng = OsRng;
    let private = Scalar::random(&mut rng);
    let public = (ProjectivePoint::GENERATOR * private).to_affine();
    let k = Scalar::random(&mut rng);
    let r = (ProjectivePoint::GENERATOR * k).to_affine();
    let shared = (ProjectivePoint::from(public) * k).to_affine();
    let shared_bytes = shared.to_bytes();

    let mut h = sha2::Sha256::new();
    h.update(shared_bytes);
    let stream_key = h.finalize();

    let blob: Vec<u8> = plain
        .iter()
        .zip(stream_key.iter().cycle())
        .map(|(&b, &k)| b ^ k)
        .collect();

    let private_bytes: [u8; 32] = private.to_bytes().into();
    let r_enc: EncodedPoint = r.to_encoded_point(false);
    let r_bytes = r_enc.as_bytes().to_vec();

    EncryptOut {
        blob,
        key: private_bytes.to_vec(),
        aux: vec![AuxConst { tag: 'r', bytes: r_bytes }],
    }
}
