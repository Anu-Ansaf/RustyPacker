use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DllExport {
    pub name: Option<String>,
    pub ordinal: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a valid PE: {0}")]
    Bad(String),
    #[error("rva out of range: {0:#x}")]
    Rva(u32),
}

fn u16le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn u32le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn rva_to_off(secs: &[(u32, u32, u32)], rva: u32) -> Option<usize> {
    for &(vaddr, vsize, raw_off) in secs {
        if rva >= vaddr && rva < vaddr.saturating_add(vsize) {
            return Some((rva - vaddr + raw_off) as usize);
        }
    }
    None
}

fn read_cstr(data: &[u8], off: usize) -> Option<String> {
    let end = data[off..].iter().position(|&b| b == 0)?;
    String::from_utf8(data[off..off + end].to_vec()).ok()
}

fn parse_sections(data: &[u8], pe_off: usize, num_secs: u16) -> Vec<(u32, u32, u32)> {
    let opt_size = u16le(data, pe_off + 20) as usize;
    let start = pe_off + 24 + opt_size;
    (0..num_secs as usize)
        .map(|i| {
            let base = start + i * 40;
            let vaddr = u32le(data, base + 12);
            let vsize = u32le(data, base + 8);
            let raw = u32le(data, base + 20);
            (vaddr, vsize, raw)
        })
        .collect()
}

pub fn parse_exports(dll_path: &Path) -> Result<Vec<DllExport>, PeError> {
    let data = fs::read(dll_path)?;
    if data.len() < 64 || u16le(&data, 0) != 0x5A4D {
        return Err(PeError::Bad("MZ signature".into()));
    }
    let pe_off = u32le(&data, 0x3C) as usize;
    if data.len() < pe_off + 4 || u32le(&data, pe_off) != 0x0000_4550 {
        return Err(PeError::Bad("PE signature".into()));
    }

    let magic = u16le(&data, pe_off + 24);
    let export_dir_loc = match magic {
        0x10b => pe_off + 24 + 96,  // PE32
        0x20b => pe_off + 24 + 112, // PE32+
        _ => return Err(PeError::Bad(format!("optional header magic 0x{magic:04x}"))),
    };

    let num_secs = u16le(&data, pe_off + 6);
    let secs = parse_sections(&data, pe_off, num_secs);

    let export_rva = u32le(&data, export_dir_loc);
    let export_size = u32le(&data, export_dir_loc + 4);
    if export_rva == 0 || export_size == 0 {
        return Ok(vec![]);
    }
    let edt_off = rva_to_off(&secs, export_rva).ok_or(PeError::Rva(export_rva))?;

    let num_funcs = u32le(&data, edt_off + 20) as usize;
    let num_names = u32le(&data, edt_off + 24) as usize;
    let ordinal_base = u32le(&data, edt_off + 16) as u16;

    let addr_table_rva = u32le(&data, edt_off + 28);
    let name_ptr_rva = u32le(&data, edt_off + 32);
    let ordinal_table_rva = u32le(&data, edt_off + 36);

    let addr_off = rva_to_off(&secs, addr_table_rva).ok_or(PeError::Rva(addr_table_rva))?;
    let nameptr_off = rva_to_off(&secs, name_ptr_rva).ok_or(PeError::Rva(name_ptr_rva))?;
    let ord_off = rva_to_off(&secs, ordinal_table_rva).ok_or(PeError::Rva(ordinal_table_rva))?;

    let mut names_by_idx: Vec<Option<String>> = vec![None; num_funcs];
    for i in 0..num_names {
        let nrva = u32le(&data, nameptr_off + i * 4);
        let oidx = u16le(&data, ord_off + i * 2) as usize;
        if let Some(off) = rva_to_off(&secs, nrva) {
            if let Some(n) = read_cstr(&data, off) {
                if oidx < num_funcs {
                    names_by_idx[oidx] = Some(n);
                }
            }
        }
    }

    let export_end = export_rva + export_size;
    let mut out = Vec::new();
    for i in 0..num_funcs {
        let frva = u32le(&data, addr_off + i * 4);
        if frva == 0 {
            continue;
        }
        let is_forwarder = frva >= export_rva && frva < export_end;
        if is_forwarder {
            continue;
        }
        out.push(DllExport {
            name: names_by_idx[i].clone(),
            ordinal: ordinal_base + i as u16,
        });
    }
    Ok(out)
}

pub fn dll_stem(dll_path: &Path) -> String {
    let s = dll_path.to_str().unwrap_or("original");
    let fname = s.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(s);
    fname
        .strip_suffix(".dll")
        .or_else(|| fname.strip_suffix(".DLL"))
        .unwrap_or(fname)
        .to_string()
}
