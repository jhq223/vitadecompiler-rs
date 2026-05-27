use crate::yaml_db::YamlDb;
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub sym_type: u32,
    pub n_args: u32,
    pub args_stats: [u32; 11],
}

impl Symbol {
    pub fn is_subroutine(&self) -> bool {
        self.sym_type & SYMBOL_SUBROUTINE != 0
    }
    pub fn is_label(&self) -> bool {
        self.sym_type & SYMBOL_LABEL != 0
    }
    pub fn is_import(&self) -> bool {
        self.sym_type & SYMBOL_IMPORT != 0
    }
    pub fn is_export(&self) -> bool {
        self.sym_type & SYMBOL_EXPORT != 0
    }
}

pub const SYMBOL_SUBROUTINE: u32 = 0x1;
pub const SYMBOL_LABEL: u32 = 0x2;
pub const SYMBOL_STRING: u32 = 0x4;
pub const SYMBOL_EXPORT: u32 = 0x8;
pub const SYMBOL_IMPORT: u32 = 0x10;

#[derive(Debug, Copy, Clone)]
struct SceModuleInfo {
    _attr: u16,
    _ver: u16,
    name: [u8; 27],
    _type: u8,
    _gp: u32,
    exp_top: u32,
    exp_btm: u32,
    imp_top: u32,
    imp_btm: u32,
    nid: u32,
    _unk: [u32; 3],
    _start: u32,
    _stop: u32,
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]))
}
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn read_sce_module_info(data: &[u8], offset: usize) -> SceModuleInfo {
    let mut name = [0u8; 27];
    name.copy_from_slice(&data[offset + 4..offset + 4 + 27]);
    SceModuleInfo {
        _attr: read_u16(data, offset),
        _ver: read_u16(data, offset + 2),
        name,
        _type: data[offset + 31],
        _gp: read_u32(data, offset + 32),
        exp_top: read_u32(data, offset + 36),
        exp_btm: read_u32(data, offset + 40),
        imp_top: read_u32(data, offset + 44),
        imp_btm: read_u32(data, offset + 48),
        nid: read_u32(data, offset + 52),
        _unk: [
            read_u32(data, offset + 56),
            read_u32(data, offset + 60),
            read_u32(data, offset + 64),
        ],
        _start: read_u32(data, offset + 68),
        _stop: read_u32(data, offset + 72),
    }
}

fn find_entry_point(text_seg: &[u8], text_addr: u32, initial_entry: u32) -> u32 {
    let offset = (initial_entry - text_addr) as usize;
    if offset + 27 > text_seg.len() {
        return find_by_magic(text_seg, text_addr);
    }

    let name_bytes = &text_seg[offset + 4..offset + 4 + 27];
    if is_ascii_name(name_bytes) {
        return initial_entry;
    }

    println!("Invalid entrypoint, attempting to find...");
    find_by_magic(text_seg, text_addr)
}

fn is_ascii_name(bytes: &[u8]) -> bool {
    if let Some(&first) = bytes.first()
        && (first == 0 || !(0x20..=0x7E).contains(&first)) {
            return false;
        }
    bytes.iter().all(|&b| b == 0 || (0x20..=0x7E).contains(&b))
}

fn find_by_magic(text_seg: &[u8], text_addr: u32) -> u32 {
    let check: [u8; 16] = [
        0xE0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0xA0, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let mut ep = text_seg.len();
    while ep > check.len() {
        ep -= 1;
        if text_seg[ep..].len() >= check.len() && text_seg[ep..ep + check.len()] == check {
            let result = (ep + check.len() - 2) as u32;
            println!("ELF has stripped module name, resolved via magic pattern at offset 0x{:X}", ep);
            return text_addr + result;
        }
    }
    text_addr // fallback
}

pub struct ModuleAnalysis {
    pub symbols: HashMap<u32, Symbol>,
    pub mod_info_offset: u32,
    #[allow(dead_code)]
    pub module_name: String,
    #[allow(dead_code)]
    pub module_nid: u32,
    #[allow(dead_code)]
    pub opt_ver: String,
}

pub fn analyze_module(
    text_seg: &[u8],
    text_addr: u32,
    text_size: u32,
    initial_entry: u32,
    db: &YamlDb,
    path: &str,
    opt_ver: &str,
) -> Result<ModuleAnalysis> {
    let entry = find_entry_point(text_seg, text_addr, initial_entry);
    let mod_info_offset = entry - text_addr;
    let mod_info = read_sce_module_info(text_seg, mod_info_offset as usize);

    let module_name = String::from_utf8_lossy(&mod_info.name)
        .trim_end_matches('\0')
        .to_string();
    println!("Module name: {}", module_name);

    let mut symbols: HashMap<u32, Symbol> = HashMap::new();

    // --- Exports ---
    let mut nids_out = String::new();
    nids_out.push_str("//EXPORTS:\n");

    let mut yml_out = format!(
        "version: 0x2\n\
         firmware: {}\n\
         modules:\n\
         \x20 {module}:\n\
         \x20\x20\x20\x20 nid: 0x{nid:08X}\n\
         \x20\x20\x20\x20 libraries:\n",
        opt_ver,
        module = module_name,
        nid = mod_info.nid
    );

    let mut x: u32 = 0;
    let mut i = mod_info.exp_top as usize;

    // SceExportsTable layout:
    //   0: size(u16)  2: lib_version(u16)  4: attribute(u16)  6: num_functions(u16)
    //   8: num_vars(u32)  12: num_tls_vars(u32)  16: module_nid(u32)
    //   20: lib_name(u32)  24: nid_table(u32)  28: entry_table(u32)
    while i < mod_info.exp_btm as usize && i < text_seg.len() {
        let size = read_u16(text_seg, i) as usize;
        if size == 0 || i + size > text_seg.len() {
            break;
        }

        let attribute = read_u16(text_seg, i + 4);
        let num_functions = read_u16(text_seg, i + 6) as usize;
        let num_vars = read_u32(text_seg, i + 8) as usize;
        let module_nid = read_u32(text_seg, i + 16);
        let lib_name_vaddr = read_u32(text_seg, i + 20);
        let nid_table_vaddr = read_u32(text_seg, i + 24);
        let entry_table_vaddr = read_u32(text_seg, i + 28);

        let has_lib = lib_name_vaddr >= text_addr && lib_name_vaddr < text_addr + text_size;
        let lib_name_str = if has_lib {
            let lib_name = read_str_at(text_seg, text_addr, lib_name_vaddr);
            String::from_utf8_lossy(&lib_name)
                .trim_end_matches('\0')
                .to_string()
        } else {
            String::new()
        };

        if has_lib {
            nids_out.push_str(&format!("\n//{}:{:08X}\n", lib_name_str, module_nid));

            yml_out.push_str(&format!("      {}:\n", lib_name_str));
            yml_out.push_str(&format!("        nid: 0x{:08X}\n", module_nid));
            yml_out.push_str(if attribute & 0x4000 != 0 {
                "        kernel: false\n"
            } else {
                "        kernel: true\n"
            });
            yml_out.push_str("        functions:\n");
        }

        for j in 0..(num_functions + num_vars) {
            let nid = read_u32(text_seg, (nid_table_vaddr - text_addr) as usize + j * 4);
            let addr = read_u32(text_seg, (entry_table_vaddr - text_addr) as usize + j * 4);

            let name = if has_lib {
                let func_name = db.lookup(&lib_name_str, nid).unwrap_or("unknown");
                if func_name == "unknown" {
                    nids_out.push_str(&format!(
                        "//{}: {}_{}_{:08X} {:08X} @OFF: {:08X} VADDR: {:08X}\n",
                        x,
                        lib_name_str,
                        lib_name_str,
                        nid,
                        nid,
                        addr - text_addr,
                        addr
                    ));
                    format!("{}_{:08X}", lib_name_str, nid)
                } else {
                    nids_out.push_str(&format!(
                        "//{}: {} {:08X} @OFF: {:08X} VADDR: {:08X}\n",
                        x,
                        func_name,
                        nid,
                        addr - text_addr,
                        addr
                    ));
                    func_name.to_string()
                }
            } else {
                // Syslib exports (no lib_name)
                let syslib_name = match nid {
                    0x70FBA1E7 => "module_process_param",
                    0x6C2224BA => "module_info",
                    0x935CD196 => "module_start",
                    0x79F8E492 => "module_stop",
                    0x913482A9 => "module_exit",
                    _ => "unknown",
                };
                nids_out.push_str(&format!(
                    "//{}: {} {:08X} @OFF: {:08X} VADDR: {:08X}\n",
                    x,
                    syslib_name,
                    nid,
                    addr - text_addr,
                    addr
                ));
                syslib_name.to_string()
            };

            if has_lib {
                yml_out.push_str(&format!(
                    "          {}_{:08X}: 0x{:08X}\n",
                    lib_name_str, nid, nid
                ));
            }

            if addr < text_addr {
                nids_out.push_str(&format!("///Something is wrong with NID {}\n", name));
            }

            let sym_addr = addr & !0x1;
            symbols.entry(sym_addr).or_insert(Symbol {
                name,
                sym_type: SYMBOL_SUBROUTINE | SYMBOL_EXPORT,
                n_args: 0,
                args_stats: [0; 11],
            });
            x += 1;
        }

        i += size;
    }

    // --- Imports ---
    nids_out.push_str("//IMPORTS:\n");
    x = 0;
    i = mod_info.imp_top as usize;

    while i < mod_info.imp_btm as usize && i < text_seg.len() {
        let size = read_u16(text_seg, i) as usize;
        if size == 0 || i + size > text_seg.len() {
            break;
        }

        // SceImportsTable2xx (size=0x34):
        //   0: size(u16)  2: lib_version(u16)  4: attribute(u16)  6: num_functions(u16)
        //   8: num_vars(u16)  10: num_tls_vars(u16)  12: reserved1(u32)
        //   16: module_nid(u32)  20: lib_name(u32)  24: reserved2(u32)
        //   28: func_nid_table(u32)  32: func_entry_table(u32)
        // SceImportsTable3xx (size=0x24):
        //   0: size(u16)  2: lib_version(u16)  4: attribute(u16)  6: num_functions(u16)
        //   8: num_vars(u16)  10: unknown1(u16)  12: module_nid(u32)
        //   16: lib_name(u32)  20: func_nid_table(u32)  24: func_entry_table(u32)
        let (lib_name_vaddr, func_nid_table, func_entry_table, num_functions, module_nid) =
            if size == 0x34 {
                // 2xx format
                let lib_name_vaddr = read_u32(text_seg, i + 20);
                let func_nid_table = read_u32(text_seg, i + 28);
                let func_entry_table = read_u32(text_seg, i + 32);
                let num_functions = read_u16(text_seg, i + 6) as usize;
                let module_nid = read_u32(text_seg, i + 16);
                (
                    lib_name_vaddr,
                    func_nid_table,
                    func_entry_table,
                    num_functions,
                    module_nid,
                )
            } else {
                // 3xx format (size=0x24)
                let lib_name_vaddr = read_u32(text_seg, i + 16);
                let func_nid_table = read_u32(text_seg, i + 20);
                let func_entry_table = read_u32(text_seg, i + 24);
                let num_functions = read_u16(text_seg, i + 6) as usize;
                let module_nid = read_u32(text_seg, i + 12);
                (
                    lib_name_vaddr,
                    func_nid_table,
                    func_entry_table,
                    num_functions,
                    module_nid,
                )
            };

        if lib_name_vaddr >= text_addr && lib_name_vaddr < text_addr + text_size {
            let lib_name = read_str_at(text_seg, text_addr, lib_name_vaddr);
            let lib_name_str = String::from_utf8_lossy(&lib_name)
                .trim_end_matches('\0')
                .to_string();

            nids_out.push_str(&format!("\n//{}:{:08X}\n", lib_name_str, module_nid));

            for j in 0..num_functions {
                let nid = read_u32(text_seg, (func_nid_table - text_addr) as usize + j * 4);
                let addr = read_u32(text_seg, (func_entry_table - text_addr) as usize + j * 4);

                let func_name = db.lookup(&lib_name_str, nid);
                let name = if let Some(fn_name) = func_name {
                    nids_out.push_str(&format!(
                        "//{}: {} {:08X} @OFF: {:08X} VADDR: {:08X}\n",
                        x,
                        fn_name,
                        nid,
                        addr - text_addr,
                        addr
                    ));
                    fn_name.to_string()
                } else {
                    let gen_name = format!("{}_{:08X}", lib_name_str, nid);
                    nids_out.push_str(&format!(
                        "//{}: {} {:08X} @OFF: {:08X} VADDR: {:08X}\n",
                        x,
                        gen_name,
                        nid,
                        addr - text_addr,
                        addr
                    ));
                    gen_name
                };

                symbols.entry(addr).or_insert(Symbol {
                    name,
                    sym_type: SYMBOL_SUBROUTINE | SYMBOL_IMPORT,
                    n_args: 0,
                    args_stats: [0; 11],
                });
                x += 1;
            }
        }

        i += size;
    }

    // Write output files
    std::fs::write(format!("{}.nids.txt", path), &nids_out)?;
    // Write YML alongside the input binary using module name
    let yml_path = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(format!("{}.yml", module_name))
        .to_string_lossy()
        .to_string();
    std::fs::write(&yml_path, &yml_out)?;
    println!("Exported NIDS file to: {}.nids.txt", path);
    println!("Exported db_lookup file to: {}", yml_path);

    Ok(ModuleAnalysis {
        symbols,
        mod_info_offset,
        module_name,
        module_nid: mod_info.nid,
        opt_ver: opt_ver.to_string(),
    })
}

fn read_str_at(seg: &[u8], text_addr: u32, addr: u32) -> Vec<u8> {
    let offset = (addr - text_addr) as usize;
    let mut result = Vec::new();
    let mut p = offset;
    while p < seg.len() {
        if seg[p] == 0 {
            break;
        }
        result.push(seg[p]);
        p += 1;
    }
    result
}
