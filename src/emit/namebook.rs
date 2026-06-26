use super::rng::Rng;

#[derive(Debug, Clone)]
pub struct Namebook {
    pub crate_name: String,
    pub fn_run:      String,
    pub fn_nap:      String,
    pub fn_decode:   String,
    pub fn_timing:   String,
    pub const_key:   String,
    pub const_blob:  String,

    pub mod_scan: String,
    pub mod_blob: String,
    pub fn_find_dll:  String,
    pub fn_find_shim: String,
    pub fn_encode_ptr: String,
    pub fn_find_pat:   String,

    pub const_rpoint:   String,
    pub mod_gpu:        String,
    pub fn_gpu_present: String,
    pub fn_gpu_stash:   String,
    pub fn_gpu_pull:    String,
    pub fn_gpu_free:    String,
}

impl Namebook {
    pub fn from_seed(seed: u64) -> Self {
        let mut r = Rng::from_seed(seed);
        let crate_name = format!("{}_{}", r.token(5), r.token(4));
        Self {
            crate_name,
            fn_run:        format!("{}_run", r.token(2)),
            fn_nap:        format!("{}_nap", r.token(2)),
            fn_decode:     format!("{}_dec", r.token(2)),
            fn_timing:     format!("{}_ts",  r.token(2)),
            const_key:     format!("K_{}",   r.token(4).to_uppercase()),
            const_blob:    format!("B_{}",   r.token(4).to_uppercase()),
            mod_scan:      format!("{}_scan", r.token(2)),
            mod_blob:      format!("{}_blob", r.token(2)),
            fn_find_dll:   format!("{}_fd",  r.token(2)),
            fn_find_shim:  format!("{}_fs",  r.token(2)),
            fn_encode_ptr: format!("{}_ep",  r.token(2)),
            fn_find_pat:   format!("{}_fp",  r.token(2)),
            const_rpoint:    format!("R_{}", r.token(4).to_uppercase()),
            mod_gpu:         format!("{}_gpu", r.token(2)),
            fn_gpu_present:  format!("{}_gpchk", r.token(2)),
            fn_gpu_stash:    format!("{}_gpput", r.token(2)),
            fn_gpu_pull:     format!("{}_gpget", r.token(2)),
            fn_gpu_free:     format!("{}_gpfree", r.token(2)),
        }
    }
}
