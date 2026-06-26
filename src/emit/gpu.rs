use super::{Item, Namebook};

pub fn extra_uses() -> Vec<String> {
    vec![
        "use windows_sys::Win32::Foundation::HMODULE;".into(),
        "use windows_sys::Win32::Graphics::Gdi::{DISPLAY_DEVICEW, EnumDisplayDevicesW};".into(),
        "use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, GetProcAddress};".into(),
    ]
}

pub fn extra_features() -> Vec<&'static str> {
    vec![
        "Win32_Foundation",
        "Win32_Graphics_Gdi",
        "Win32_System_LibraryLoader",
    ]
}

pub fn items(n: &Namebook) -> Vec<Item> {
    let fn_init = init_fn_name(n);
    let body = format!(
        r#"#[allow(non_camel_case_types)]
type CuInit            = unsafe extern "system" fn(u32) -> i32;
#[allow(non_camel_case_types)]
type CuDeviceGetCount  = unsafe extern "system" fn(*mut i32) -> i32;
#[allow(non_camel_case_types)]
type CuDeviceGet       = unsafe extern "system" fn(*mut i32, i32) -> i32;
#[allow(non_camel_case_types)]
type CuCtxCreate       = unsafe extern "system" fn(*mut *mut core::ffi::c_void, u32, i32) -> i32;
#[allow(non_camel_case_types)]
type CuMemAlloc        = unsafe extern "system" fn(*mut u64, usize) -> i32;
#[allow(non_camel_case_types)]
type CuMemcpyHtoD      = unsafe extern "system" fn(u64, *const core::ffi::c_void, usize) -> i32;
#[allow(non_camel_case_types)]
type CuMemcpyDtoH      = unsafe extern "system" fn(*mut core::ffi::c_void, u64, usize) -> i32;
#[allow(non_camel_case_types)]
type CuMemFree         = unsafe extern "system" fn(u64) -> i32;
#[allow(non_camel_case_types)]
type CuCtxDestroy      = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;

pub struct GpuCtx {{
    pub ctx:   *mut core::ffi::c_void,
    pub alloc: CuMemAlloc,
    pub h2d:   CuMemcpyHtoD,
    pub d2h:   CuMemcpyDtoH,
    pub free:  CuMemFree,
    pub destroy: CuCtxDestroy,
}}

pub fn {fn_present}() -> bool {{
    unsafe {{
        let mut idx = 0u32;
        let mut dd: DISPLAY_DEVICEW = core::mem::zeroed();
        dd.cb = core::mem::size_of::<DISPLAY_DEVICEW>() as u32;
        while EnumDisplayDevicesW(core::ptr::null(), idx, &mut dd, 0) != 0 {{
            let s = &dd.DeviceString;
            let len = s.iter().position(|&c| c == 0).unwrap_or(s.len());
            let name = String::from_utf16_lossy(&s[..len]);
            if name.to_uppercase().contains("NVIDIA") {{
                return true;
            }}
            idx += 1;
            dd = core::mem::zeroed();
            dd.cb = core::mem::size_of::<DISPLAY_DEVICEW>() as u32;
        }}
        false
    }}
}}

pub fn {fn_init}() -> Option<GpuCtx> {{
    unsafe {{
        let mut name: Vec<u16> = "nvcuda.dll".encode_utf16().collect();
        name.push(0);
        let lib: HMODULE = LoadLibraryW(name.as_ptr());
        if lib.is_null() {{ return None; }}

        let init_fp        = GetProcAddress(lib, b"cuInit\0".as_ptr())?;
        let dev_count_fp   = GetProcAddress(lib, b"cuDeviceGetCount\0".as_ptr())?;
        let dev_get_fp     = GetProcAddress(lib, b"cuDeviceGet\0".as_ptr())?;
        let ctx_create_fp  = GetProcAddress(lib, b"cuCtxCreate_v2\0".as_ptr())?;
        let alloc_fp       = GetProcAddress(lib, b"cuMemAlloc_v2\0".as_ptr())?;
        let h2d_fp         = GetProcAddress(lib, b"cuMemcpyHtoD_v2\0".as_ptr())?;
        let d2h_fp         = GetProcAddress(lib, b"cuMemcpyDtoH_v2\0".as_ptr())?;
        let free_fp        = GetProcAddress(lib, b"cuMemFree_v2\0".as_ptr())?;
        let destroy_fp     = GetProcAddress(lib, b"cuCtxDestroy\0".as_ptr())?;

        let init:       CuInit            = core::mem::transmute(init_fp);
        let dev_count:  CuDeviceGetCount  = core::mem::transmute(dev_count_fp);
        let dev_get:    CuDeviceGet       = core::mem::transmute(dev_get_fp);
        let ctx_create: CuCtxCreate       = core::mem::transmute(ctx_create_fp);
        let alloc:      CuMemAlloc        = core::mem::transmute(alloc_fp);
        let h2d:        CuMemcpyHtoD      = core::mem::transmute(h2d_fp);
        let d2h:        CuMemcpyDtoH      = core::mem::transmute(d2h_fp);
        let free:       CuMemFree         = core::mem::transmute(free_fp);
        let destroy:    CuCtxDestroy      = core::mem::transmute(destroy_fp);

        if init(0) != 0 {{ return None; }}
        let mut count = 0i32;
        if dev_count(&mut count) != 0 || count == 0 {{ return None; }}
        let mut dev = 0i32;
        if dev_get(&mut dev, 0) != 0 {{ return None; }}
        let mut ctx: *mut core::ffi::c_void = core::ptr::null_mut();
        if ctx_create(&mut ctx, 0, dev) != 0 {{ return None; }}

        Some(GpuCtx {{ ctx, alloc, h2d, d2h, free, destroy }})
    }}
}}

pub fn {fn_stash}(g: &GpuCtx, host: &[u8]) -> u64 {{
    unsafe {{
        let mut dev: u64 = 0;
        if (g.alloc)(&mut dev, host.len()) != 0 {{ return 0; }}
        if (g.h2d)(dev, host.as_ptr() as *const _, host.len()) != 0 {{
            let _ = (g.free)(dev);
            return 0;
        }}
        dev
    }}
}}

pub fn {fn_pull}(g: &GpuCtx, dev: u64, len: usize) -> Vec<u8> {{
    let mut out = vec![0u8; len];
    unsafe {{
        let _ = (g.d2h)(out.as_mut_ptr() as *mut _, dev, len);
    }}
    out
}}

pub fn {fn_free}(g: &GpuCtx, dev: u64) {{
    unsafe {{
        if dev != 0 {{ let _ = (g.free)(dev); }}
        let _ = (g.destroy)(g.ctx);
    }}
}}"#,
        fn_present = n.fn_gpu_present,
        fn_init    = fn_init,
        fn_stash   = n.fn_gpu_stash,
        fn_pull    = n.fn_gpu_pull,
        fn_free    = n.fn_gpu_free,
    );

    vec![Item::Raw(body)]
}

pub fn init_fn_name(n: &Namebook) -> String {
    format!("{}_init", n.fn_gpu_present)
}
