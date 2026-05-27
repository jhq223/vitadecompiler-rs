use crate::analyze::{Context, RegisterAssignment, get_cond_info, get_reg_name};
use crate::instructions;
use crate::vita::Symbol;
use capstone::prelude::*;
use std::io::Write;

const INDENT: &str = "\t";

fn to_u32(r: RegId) -> u32 {
    r.0 as u32
}

pub fn decompile(ctx: &mut Context, out_path: &str) -> Result<(), anyhow::Error> {
    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()?;

    let code_data = &ctx.text_seg[..ctx.mod_info_offset as usize];
    let insns = cs.disasm_all(code_data, ctx.text_addr as u64)?;

    let mut fout = std::fs::File::create(format!("{}.c", out_path))?;
    let mut fheader = std::fs::File::create(format!("{}.h", out_path))?;

    println!("Exporting source file to: {}.c", out_path);
    println!("Exporting header file to: {}.h", out_path);

    let mut first_import = true;
    let mut first = true;
    let mut i = 0;

    while i < insns.len() {
        let insn = &insns[i];
        let addr = insn.address() as u32;

        if ctx.symbols.contains_key(&addr) {
            ctx.free_reg_assign_map();
            ctx.use_flags = false;
        }

        // Import stubs
        if let Some(sym) = ctx.symbols.get(&addr)
            && sym.is_import()
        {
            if first_import {
                writeln!(fout, "}}\n")?;
                first_import = false;
            }
            let args = get_args_decl(sym);
            writeln!(fout, "int {}({});", sym.name, args)?;
            writeln!(fheader, "int {}({});", sym.name, args)?;
            i += 4;
            continue;
        }

        // Subroutine/label header
        if let Some(sym) = ctx.symbols.get(&addr) {
            if sym.is_subroutine() {
                if first {
                    first = false;
                } else {
                    writeln!(fout, "}}\n")?;
                }
                writeln!(
                    fout,
                    "//VADDR: {:08X} OFF: {:08X}",
                    addr,
                    addr - ctx.text_addr
                )?;
                if sym.is_import() {
                    writeln!(fout, "// Imported")?;
                } else if sym.is_export() {
                    writeln!(fout, "// Exported")?;
                }
                let args = get_args_decl(sym);
                writeln!(fheader, "int {}({});", sym.name, args)?;
                writeln!(fout, "int {}({})", sym.name, args)?;
                writeln!(fout, "{{")?;
            } else if sym.is_label() {
                writeln!(fout)?;
                writeln!(fout, "{}:", sym.name)?;
                writeln!(
                    fout,
                    "//VADDR: {:08X} OFF: {:08X}",
                    addr,
                    addr - ctx.text_addr
                )?;
            }
        }

        pseudo_code(insn, ctx, &cs, &mut fout)?;
        i += 1;
    }

    if !first {
        writeln!(fout, "}}")?;
    }
    Ok(())
}

fn pseudo_code(
    insn: &capstone::Insn,
    ctx: &mut Context,
    cs: &Capstone,
    fout: &mut impl Write,
) -> Result<(), anyhow::Error> {
    let mnemonic_raw = insn.mnemonic().unwrap_or("");
    let mnemonic = mnemonic_raw.trim_end_matches(".w");
    let addr = insn.address() as u32;

    let detail = match cs.insn_detail(insn) {
        Ok(d) => d,
        Err(_) => {
            return handle_unknown(insn, fout);
        }
    };
    let arch_detail = detail.arch_detail();
    let arm = match arch_detail.arm() {
        Some(a) => a,
        None => {
            return handle_unknown(insn, fout);
        }
    };

    let cc = arm.cc();
    let update_flags = arm.update_flags();
    let is_cond = cc != arch::arm::ArmCC::ARM_CC_AL;

    if is_cond {
        ctx.use_flags = true;
    }
    if update_flags {
        ctx.use_flags = false;
        ctx.condition_reg_1.clear();
        ctx.condition_reg_2.clear();
    }

    let (mut_base, cond_info) = get_cond_info(cc, mnemonic);

    // Strip 's' suffix when update_flags is set (like original trimMnemonic)
    let base = if update_flags
        && mut_base.len() > 1
        && mut_base.ends_with('s')
        && mut_base != "cmp"
        && mut_base != "cmn"
        && mut_base != "tst"
    {
        &mut_base[..mut_base.len() - 1]
    } else {
        mut_base
    };

    let code = match instructions::get_instruction_code(base, arm.operands().len() as u8) {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return handle_unknown(insn, fout),
    };

    let translated = translate_instruction(insn, arm, ctx, base, addr, &code);

    // Output condition header
    let mut indent = INDENT.to_string();
    if let Some((cond_flags, _)) = cond_info
        && !cond_flags.is_empty()
    {
        writeln!(fout, "{}{}", indent, cond_flags)?;
        indent = format!("{}\t", INDENT);
    }

    let translated = translated.replace("\\", &format!("\n{}", indent));
    let translated = translated.replace("()n", "\\n");

    if ctx.ignore_map.get(&addr).copied().unwrap_or(false) {
        return Ok(());
    }

    write!(fout, "{}", indent)?;
    writeln!(fout, "{}", translated)?;

    Ok(())
}

fn handle_unknown(insn: &capstone::Insn, fout: &mut impl Write) -> Result<(), anyhow::Error> {
    let mnemonic_raw = insn.mnemonic().unwrap_or("");
    let mnemonic = mnemonic_raw.trim_end_matches(".w");
    let op_str = insn.op_str().unwrap_or("");

    if mnemonic == "bx" && op_str == "lr" {
        writeln!(fout, "{}return a1;", INDENT)?;
    } else if mnemonic == "pop" {
        writeln!(fout, "{}return a1; // {} {}", INDENT, mnemonic_raw, op_str)?;
    } else if mnemonic == "push" {
        writeln!(fout, "{}// {} {}", INDENT, mnemonic_raw, op_str)?;
    } else if mnemonic.starts_with("stm") || mnemonic.starts_with("ldm") {
        let renamed = rename_regs_in_str(op_str);
        writeln!(fout, "{}// {} {}", INDENT, mnemonic_raw, renamed)?;
    } else if mnemonic == "nop" || mnemonic.starts_with("it") {
    } else if mnemonic.starts_with('v') {
        writeln!(fout, "{}// vfp: {} {}", INDENT, mnemonic_raw, op_str)?;
    } else {
        writeln!(fout, "{}asm(\"{} {}\\n\");", INDENT, mnemonic_raw, op_str)?;
    }
    Ok(())
}

fn rename_regs_in_str(s: &str) -> String {
    let mut result = s.to_string();
    let regs = [
        ("r12", "ip"),
        ("r11", "fp"),
        ("r10", "sl"),
        ("r9", "sb"),
        ("r8", "v5"),
        ("r7", "v4"),
        ("r6", "v3"),
        ("r5", "v2"),
        ("r4", "v1"),
        ("r3", "a4"),
        ("r2", "a3"),
        ("r1", "a2"),
        ("r0", "a1"),
    ];
    for (from, to) in &regs {
        result = result.replace(from, to);
    }
    result
}

fn translate_instruction(
    insn: &capstone::Insn,
    arm: &arch::arm::ArmInsnDetail,
    ctx: &mut Context,
    base: &str,
    addr: u32,
    code: &str,
) -> String {
    let mut code = code.to_string();
    let ops: Vec<_> = arm.operands().collect();
    let is_cmp = base == "cmp";

    // Phase 1: Parse operands
    for i in 0..ops.len() {
        let op_name = format!("op{}", i);
        let is_last = i == ops.len() - 1;
        match &ops[i].op_type {
            arch::arm::ArmOperandType::Reg(reg) => {
                let reg_id = to_u32(*reg);
                let mut reg_str = get_reg_name(reg_id);
                if !code.contains(&format!("{} = ", op_name)) {
                    compose_reg(ctx, &mut reg_str, reg_id, false);
                }
                if is_last {
                    reg_str = instructions::handle_shift(&reg_str, &ops[i].shift, get_reg_name);
                }
                if is_cmp {
                    if i == 0 {
                        ctx.condition_reg_1 = reg_str.clone();
                    } else if i == 1 {
                        ctx.condition_reg_2 = reg_str.clone();
                    }
                }
                code = code.replace(&op_name, &reg_str);
            }
            arch::arm::ArmOperandType::Imm(imm) => {
                code = code.replace(&op_name, &get_imm_string(*imm as u32, false));
            }
            arch::arm::ArmOperandType::Mem(mem) => {
                let base_reg = to_u32(mem.base());
                let mut reg = get_reg_name(base_reg);
                if !code.contains(&format!("{} = ", op_name)) {
                    compose_reg(ctx, &mut reg, base_reg, false);
                }
                let str_val = if mem.index().0 != 0 {
                    let reg2 = get_reg_name(to_u32(mem.index()));
                    format!("{} + {}", reg, reg2)
                } else {
                    let disp = mem.disp();
                    let mut s = format!("{} + {}", reg, get_imm_string(disp as u32, true));
                    if s.ends_with(" + 0") {
                        s = s[..s.len() - 4].to_string();
                    }
                    s
                };
                code = code.replace(&op_name, &str_val);
            }
            _ => {}
        }
    }

    // Phase 2: Register assignment tracking
    if code.len() > 3 && &code[3..4] == "=" && !code.contains(" = symbol") {
        let cc = arm.cc();
        let is_cond = cc != arch::arm::ArmCC::ARM_CC_AL;

        if is_cond {
            if let arch::arm::ArmOperandType::Reg(reg) = ops[0].op_type {
                ctx.reg_assign_map.remove(&to_u32(reg));
            }
        } else if let Some(eq_pos) = code.find(" = ") {
            let start = eq_pos + 3;
            let semi = code[start..].find(';').unwrap_or(code.len() - start);
            let assign = code[start..start + semi].to_string();

            // Handle movt composition
            if base == "movt"
                && let arch::arm::ArmOperandType::Reg(reg) = ops[0].op_type
            {
                let reg_id = to_u32(reg);
                if let Some(Some(entry)) = ctx.reg_assign_map.get(&reg_id)
                    && is_hex_or_dec(&entry.assign)
                {
                    let composed = compose_movt_value(ctx, reg_id, &assign);
                    let entry_ref = ctx.reg_assign_map.entry(reg_id).or_insert_with(|| {
                        Some(RegisterAssignment {
                            assign: String::new(),
                            addr: 0,
                            update_flags: false,
                        })
                    });
                    if let Some(e) = entry_ref {
                        e.assign = composed.clone();
                        e.addr = addr;
                        e.update_flags = arm.update_flags();
                    }
                    return format!("{} = {};", get_reg_name(reg_id), composed);
                }
            }

            // Normal assignment
            if let arch::arm::ArmOperandType::Reg(reg) = ops[0].op_type {
                let reg_id = to_u32(reg);
                let entry_ref = ctx.reg_assign_map.entry(reg_id).or_insert_with(|| {
                    Some(RegisterAssignment {
                        assign: String::new(),
                        addr: 0,
                        update_flags: false,
                    })
                });
                if let Some(e) = entry_ref {
                    e.assign = assign;
                    e.addr = addr;
                    e.update_flags = arm.update_flags();
                }
            }
        }
    }

    // Phase 3: Replace symbols
    for (i, op) in ops.iter().enumerate().take(2) {
        if let arch::arm::ArmOperandType::Imm(imm) = op.op_type {
            let target = imm as u32;
            if let Some(sym) = ctx.symbols.get(&target).cloned() {
                if sym.is_subroutine() || sym.is_label() {
                    code = code.replace("symbol", &sym.name);
                    if sym.is_subroutine() {
                        let n_args = sym.n_args;
                        let args_str = get_args_use_n(n_args, ctx);
                        code = code.replace("...", &args_str);
                    }
                }
            } else if i == 1 {
                code = code.replace("symbol", insn.op_str().unwrap_or(""));
            }
        }
    }

    if base == "bl" || base == "blx" {
        ctx.clear_regs_after_branch();
        ctx.use_flags = false;
    }

    code
}

fn compose_reg(ctx: &mut Context, reg_str: &mut String, reg: u32, analyse: bool) {
    if reg == crate::analyze::ARM_REG_SP {
        return;
    }
    if let Some(Some(entry)) = ctx.reg_assign_map.get(&reg)
        && entry.assign.len() < 128
    {
        let assign = entry.assign.clone();
        let is_string = assign.starts_with('"') && assign.ends_with('"');
        let is_atom = !assign.contains(' ');
        if !is_string && !is_atom {
            *reg_str = format!("({})", assign);
        } else {
            *reg_str = assign;
        }
        if analyse {
            ctx.ignore_addr(reg);
        }
    }
}

fn compose_movt_value(ctx: &mut Context, reg_id: u32, assign: &str) -> String {
    let movt_part = assign.split_whitespace().next().unwrap_or("");
    if let Some(Some(prev)) = ctx.reg_assign_map.get(&reg_id)
        && is_hex_or_dec(&prev.assign)
        && let Ok(movt_val) = u32::from_str_radix(movt_part.trim_start_matches("0x"), 16)
    {
        let movw_val = if prev.assign.starts_with("0x") {
            u32::from_str_radix(prev.assign.trim_start_matches("0x"), 16).unwrap_or(0)
        } else {
            prev.assign.parse::<i32>().unwrap_or(0) as u32
        };
        let value = movt_val | movw_val;

        if value >= ctx.text_addr && value < ctx.text_addr + ctx.text_size {
            let off = (value - ctx.text_addr) as usize;
            if off + 4 <= ctx.text_seg.len() {
                let bytes = &ctx.text_seg[off..off + 4];
                if bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    let s = read_cstr(&ctx.text_seg, off);
                    return format!("/*s_text_{:08X}*/ \"{}\"", value, s.replace('\n', "\\n"));
                }
            }
            let final_val = check_dword_chain(ctx, value);
            if final_val != value
                && let Some(sym) = ctx.symbols.get(&(final_val & !0x1))
                && sym.is_subroutine()
            {
                return sym.name.clone();
            }
            return format!("/*text_{:08X}*/ 0x{:08X}", value, final_val);
        }

        if value >= ctx.data_addr && value < ctx.data_addr + ctx.data_size {
            let off = (value - ctx.data_addr) as usize;
            if off + 4 <= ctx.data_seg.len() {
                let bytes = &ctx.data_seg[off..off + 4];
                if bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    let s = read_cstr(&ctx.data_seg, off);
                    return format!("/*s_data_{:08X}*/ \"{}\"", value, s.replace('\n', "\\n"));
                }
            }
            let final_val = check_dword_chain_data(ctx, value);
            return format!("/*data_{:08X}*/ 0x{:08X}", value, final_val);
        }

        return format!("/*data_{:08X}*/", value);
    }
    assign.to_string()
}

fn check_dword_chain(ctx: &Context, mut addr: u32) -> u32 {
    while addr > ctx.text_addr && addr < ctx.text_addr + ctx.text_size {
        let off = (addr - ctx.text_addr) as usize;
        if off + 4 > ctx.text_seg.len() {
            break;
        }
        addr = u32::from_le_bytes(ctx.text_seg[off..off + 4].try_into().unwrap_or([0; 4]));
    }
    addr
}

fn check_dword_chain_data(ctx: &Context, mut addr: u32) -> u32 {
    while addr > ctx.data_addr && addr < ctx.data_addr + ctx.data_size {
        let off = (addr - ctx.data_addr) as usize;
        if off + 4 > ctx.data_seg.len() {
            break;
        }
        addr = u32::from_le_bytes(ctx.data_seg[off..off + 4].try_into().unwrap_or([0; 4]));
    }
    addr
}

fn read_cstr(data: &[u8], offset: usize) -> String {
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - offset);
    String::from_utf8_lossy(&data[offset..offset + end]).to_string()
}

pub(crate) fn get_imm_string(imm: u32, is_mem: bool) -> String {
    let s = imm as i32;
    if (-9..0).contains(&s) || (0..=9).contains(&s) || (is_mem && (imm & 0x80000000 != 0)) {
        format!("{}", s)
    } else {
        format!("0x{:X}", imm)
    }
}

fn is_hex_or_dec(s: &str) -> bool {
    if s.len() > 2 && &s[0..2] == "0x" && s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    !s.is_empty() && s.chars().all(|c| c == '-' || c.is_ascii_digit())
}

fn get_args_decl(sym: &Symbol) -> String {
    let n = (sym.n_args as usize).min(11);
    (1..=n)
        .map(|i| format!("int arg{}", i))
        .collect::<Vec<_>>()
        .join(", ")
}

fn get_args_use_n(n_args: u32, ctx: &mut Context) -> String {
    let n = (n_args as usize).min(11);
    let mut parts = Vec::new();
    let regs = [
        crate::analyze::ARM_REG_R0,
        crate::analyze::ARM_REG_R1,
        crate::analyze::ARM_REG_R2,
        crate::analyze::ARM_REG_R3,
    ];
    for (i, reg) in regs.iter().enumerate().take(n) {
        if let Some(Some(entry)) = ctx.reg_assign_map.get(reg) {
            parts.push(entry.assign.clone());
        } else {
            parts.push(format!("a{}", i + 1));
        }
    }
    for i in 4..n {
        parts.push(format!("*(sp+{})", (i - 4) * 4));
    }
    parts.join(", ")
}
