use crate::emit::{Item, Namebook};
use crate::spec::{CheckChoice, CheckId, BuildSpec};

pub fn items_for(recipe: &BuildSpec, names: &Namebook) -> Vec<Item> {
    let mut out: Vec<Item> = Vec::new();
    for c in &recipe.checks {
        match c.id {
            CheckId::CheckRemote => out.push(check_remote_fn(names)),
            CheckId::DebugPort => out.push(debug_port_fn(names)),
            CheckId::TebFlag => out.push(teb_flag_fn(names)),
            CheckId::VecInt3 => out.push(vec_int3_fn(names)),
            CheckId::NtDelay => out.push(nt_nap_fn(names, c)),
        }
    }
    out
}

pub fn callable_for(id: CheckId, names: &Namebook) -> String {
    match id {
        CheckId::CheckRemote => fname(names, "ck_rd"),
        CheckId::DebugPort   => fname(names, "ck_dp"),
        CheckId::TebFlag     => fname(names, "ck_teb"),
        CheckId::VecInt3     => fname(names, "ck_vi3"),
        CheckId::NtDelay     => fname(names, "ck_nd"),
    }
}

fn fname(n: &Namebook, suffix: &str) -> String {
    format!("{}_{}", n.fn_run, suffix)
}

fn check_remote_fn(n: &Namebook) -> Item {
    let name = fname(n, "ck_rd");
    Item::Fn {
        sig: format!("fn {name}()"),
        body: r#"    let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut len: u32 = 0;
    let _ = syscall!(
        "NtQueryInformationProcess",
        -1isize as *mut core::ffi::c_void,
        30u32,
        &mut handle as *mut *mut core::ffi::c_void,
        core::mem::size_of::<*mut core::ffi::c_void>() as u32,
        &mut len as *mut u32
    );
    if !handle.is_null() { std::process::exit(0); }"#
            .into(),
    }
}

fn debug_port_fn(n: &Namebook) -> Item {
    let name = fname(n, "ck_dp");
    Item::Fn {
        sig: format!("fn {name}()"),
        body: r#"    let mut port: isize = 0;
    let mut len: u32 = 0;
    let _ = syscall!(
        "NtQueryInformationProcess",
        -1isize as *mut core::ffi::c_void,
        7u32,
        &mut port as *mut isize,
        core::mem::size_of::<isize>() as u32,
        &mut len as *mut u32
    );
    if port != 0 { std::process::exit(0); }"#
            .into(),
    }
}

fn teb_flag_fn(n: &Namebook) -> Item {
    let name = fname(n, "ck_teb");
    Item::Fn {
        sig: format!("fn {name}()"),
        body: r#"    let being_debugged: u32;
    unsafe {
        std::arch::asm!(
            "mov {peb}, gs:[0x60]",
            "movzx {bd:e}, byte ptr [{peb} + 0x02]",
            peb = out(reg) _,
            bd  = out(reg) being_debugged,
            options(nostack, preserves_flags),
        );
    }
    if being_debugged != 0 { std::process::exit(0); }"#
            .into(),
    }
}

fn vec_int3_fn(n: &Namebook) -> Item {
    let name = fname(n, "ck_vi3");
    Item::Fn {
        sig: format!("fn {name}()"),
        body: r#"    use core::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::System::Diagnostics::Debug::{AddVectoredExceptionHandler, EXCEPTION_POINTERS, RemoveVectoredExceptionHandler};
    static SEEN: AtomicBool = AtomicBool::new(false);
    unsafe extern "system" fn h(p: *mut EXCEPTION_POINTERS) -> i32 {
        SEEN.store(true, Ordering::Relaxed);
        unsafe {
            let bp = p as *mut u8;
            let ctx_ptr = *(bp.add(0x08) as *mut *mut u8);
            let rip = ctx_ptr.add(0xF8) as *mut u64;
            *rip = (*rip).wrapping_add(1);
        }
        -1
    }
    unsafe {
        let veh = AddVectoredExceptionHandler(1, Some(h));
        if veh.is_null() { return; }
        core::arch::asm!("int 3", options(nomem, nostack));
        let _ = RemoveVectoredExceptionHandler(veh);
        if !SEEN.load(Ordering::Relaxed) { std::process::exit(0); }
    }"#
            .into(),
    }
}

fn nt_nap_fn(n: &Namebook, c: &CheckChoice) -> Item {
    let name = fname(n, "ck_nd");
    let ms: u64 = c
        .params
        .get("ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000);
    Item::Fn {
        sig: format!("fn {name}()"),
        body: format!(
            "    let t: i64 = -({ms} * 10_000) as i64;\n    let _ = syscall!(\"NtDelayExecution\", 0u32, &t as *const i64);"
        ),
    }
}
