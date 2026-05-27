use crate::instructions::{self, CONDITIONS};
use crate::translate::get_imm_string;
use crate::vita::{SYMBOL_LABEL, SYMBOL_STRING, SYMBOL_SUBROUTINE, Symbol};
use capstone::prelude::*;
use std::collections::HashMap;

const MAX_ARGS: usize = 11;

#[derive(Clone)]
pub struct RegisterAssignment {
    pub assign: String,
    pub addr: u32,
    pub update_flags: bool,
}

pub struct Context {
    pub symbols: HashMap<u32, Symbol>,
    pub movw_map: HashMap<u32, u32>,
    pub ignore_map: HashMap<u32, bool>,
    pub reg_assign_map: HashMap<u32, Option<RegisterAssignment>>,
    pub use_flags: bool,
    pub condition_reg_1: String,
    pub condition_reg_2: String,
    pub text_seg: Vec<u8>,
    pub data_seg: Vec<u8>,
    pub text_addr: u32,
    pub text_size: u32,
    pub data_addr: u32,
    pub data_size: u32,
    pub mod_info_offset: u32,
}

fn to_u32(r: RegId) -> u32 {
    r.0 as u32
}

impl Context {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        text_seg: Vec<u8>,
        data_seg: Vec<u8>,
        text_addr: u32,
        text_size: u32,
        data_addr: u32,
        data_size: u32,
        mod_info_offset: u32,
        symbols: HashMap<u32, Symbol>,
    ) -> Self {
        Context {
            symbols,
            movw_map: HashMap::new(),
            ignore_map: HashMap::new(),
            reg_assign_map: HashMap::new(),
            use_flags: false,
            condition_reg_1: String::new(),
            condition_reg_2: String::new(),
            text_seg,
            data_seg,
            text_addr,
            text_size,
            data_addr,
            data_size,
            mod_info_offset,
        }
    }

    pub fn add_symbol(&mut self, addr: u32, name: String, sym_type: u32) {
        self.symbols.entry(addr).or_insert(Symbol {
            name,
            sym_type,
            n_args: 0,
            args_stats: [0; 11],
        });
    }

    pub(crate) fn free_reg_assign_map(&mut self) {
        self.reg_assign_map.clear();
    }

    pub(crate) fn clear_regs_after_branch(&mut self) {
        self.reg_assign_map.remove(&ARM_REG_R0);
        self.reg_assign_map.remove(&ARM_REG_R1);
        self.reg_assign_map.remove(&ARM_REG_R2);
        self.reg_assign_map.remove(&ARM_REG_R3);
    }

    pub(crate) fn ignore_addr(&mut self, reg: u32) {
        if let Some(Some(entry)) = self.reg_assign_map.get(&reg) {
            if entry.update_flags && self.use_flags {
                return;
            }
            self.ignore_map.insert(entry.addr, true);
        }
    }
}

// capstone v5 ARM register IDs
pub const ARM_REG_LR: u32 = 10;
pub const ARM_REG_PC: u32 = 11;
pub const ARM_REG_SP: u32 = 12;
pub const ARM_REG_R0: u32 = 66;
pub const ARM_REG_R1: u32 = 67;
pub const ARM_REG_R2: u32 = 68;
pub const ARM_REG_R3: u32 = 69;
pub const ARM_REG_R4: u32 = 70;
pub const ARM_REG_R5: u32 = 71;
pub const ARM_REG_R6: u32 = 72;
pub const ARM_REG_R7: u32 = 73;
pub const ARM_REG_R8: u32 = 74;
pub const ARM_REG_R9: u32 = 75;
pub const ARM_REG_R10: u32 = 76;
pub const ARM_REG_R11: u32 = 77;
pub const ARM_REG_R12: u32 = 78;

pub fn get_reg_name(reg_id: u32) -> String {
    match reg_id {
        ARM_REG_R0 => "a1",
        ARM_REG_R1 => "a2",
        ARM_REG_R2 => "a3",
        ARM_REG_R3 => "a4",
        ARM_REG_R4 => "v1",
        ARM_REG_R5 => "v2",
        ARM_REG_R6 => "v3",
        ARM_REG_R7 => "v4",
        ARM_REG_R8 => "v5",
        ARM_REG_R9 => "sb",
        ARM_REG_R10 => "sl",
        ARM_REG_R11 => "fp",
        ARM_REG_R12 => "ip",
        ARM_REG_SP => "sp",
        ARM_REG_LR => "lr",
        ARM_REG_PC => "pc",
        _ => "unk",
    }
    .into()
}

fn read_cstr(data: &[u8], offset: usize) -> String {
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - offset);
    String::from_utf8_lossy(&data[offset..offset + end]).to_string()
}

fn is_hex_or_dec(s: &str) -> bool {
    if s.len() > 2 && &s[0..2] == "0x" && s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    !s.is_empty() && s.chars().all(|c| c == '-' || c.is_ascii_digit())
}

// ========== Pass 1: Discover symbols from branches ==========

pub fn analyze_symbols_pass1(ctx: &mut Context) -> Result<(), anyhow::Error> {
    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()?;

    let code = &ctx.text_seg[..ctx.mod_info_offset as usize];
    let insns = cs.disasm_all(code, ctx.text_addr as u64)?;

    for insn in insns.iter() {
        let detail = match cs.insn_detail(insn) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let arch_detail = detail.arch_detail();
        let arm = match arch_detail.arm() {
            Some(a) => a,
            None => continue,
        };

        let mnemonic_raw = insn.mnemonic().unwrap_or("");
        let mnemonic = mnemonic_raw.trim_end_matches(".w");
        // Strip condition suffix (like original trimMnemonic)
        let (base_mnemonic, _) = get_cond_info(arm.cc(), mnemonic);
        let ops: Vec<_> = arm.operands().collect();

        let is_branch = base_mnemonic == "b";
        if (is_branch || base_mnemonic == "bl" || base_mnemonic == "blx")
            && let Some(op) = ops.first()
            && let arch::arm::ArmOperandType::Imm(imm) = op.op_type
        {
            let target = imm as u32;
            if target >= ctx.text_addr
                && target < ctx.text_addr + ctx.text_size
                && !ctx.symbols.contains_key(&target)
            {
                let name = if is_branch {
                    format!("loc_{:08X}", target)
                } else {
                    format!("sub_{:08X}", target)
                };
                let st = if is_branch {
                    SYMBOL_LABEL
                } else {
                    SYMBOL_SUBROUTINE
                };
                ctx.add_symbol(target, name, st);
            }
        }

        if (base_mnemonic == "cbz" || base_mnemonic == "cbnz")
            && ops.len() >= 2
            && let arch::arm::ArmOperandType::Imm(imm) = ops[1].op_type
        {
            let target = imm as u32;
            if target >= ctx.text_addr
                && target < ctx.text_addr + ctx.text_size
                && !ctx.symbols.contains_key(&target)
            {
                ctx.add_symbol(target, format!("loc_{:08X}", target), SYMBOL_LABEL);
            }
        }

        if (base_mnemonic == "mov" || base_mnemonic == "movw")
            && ops.len() >= 2
            && let (arch::arm::ArmOperandType::Reg(reg), arch::arm::ArmOperandType::Imm(imm)) =
                (&ops[0].op_type, &ops[1].op_type)
        {
            ctx.movw_map.insert(to_u32(*reg), *imm as u32);
        }

        if base_mnemonic == "movt" && ops.len() >= 2
            && let (arch::arm::ArmOperandType::Reg(reg), arch::arm::ArmOperandType::Imm(imm)) =
                (&ops[0].op_type, &ops[1].op_type)
            {
                let reg_id = to_u32(*reg);
                if let Some(&movw_val) = ctx.movw_map.get(&reg_id) {
                    let value = (*imm as u32) << 16 | movw_val;
                    if value >= ctx.text_addr && value < ctx.text_addr + ctx.text_size {
                        let off = (value - ctx.text_addr) as usize;
                        if off + 4 <= ctx.text_seg.len() {
                            let bytes = &ctx.text_seg[off..off + 4];
                            if value > ctx.text_addr + ctx.mod_info_offset
                                && bytes.iter().all(|&b| (0x20..=0x7E).contains(&b))
                            {
                                let s = read_cstr(&ctx.text_seg, off);
                                ctx.add_symbol(value, s, SYMBOL_STRING);
                            } else {
                                let a = value & !0x1;
                                ctx.add_symbol(a, format!("sub_{:08X}", a), SYMBOL_SUBROUTINE);
                            }
                        }
                    }
                }
            }
    }
    Ok(())
}

// ========== Pass 2: Discover functions at pop/bx boundaries ==========

pub fn analyze_symbols_pass2(ctx: &mut Context) -> Result<(), anyhow::Error> {
    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()?;

    let code = &ctx.text_seg[..ctx.mod_info_offset as usize];
    let insns = cs.disasm_all(code, ctx.text_addr as u64)?;

    for i in 0..insns.len() {
        let insn = &insns[i];
        let mnemonic = insn.mnemonic().unwrap_or("").trim_end_matches(".w");

        if mnemonic == "pop" || mnemonic == "bx" {
            let addr = if i + 1 < insns.len()
                && insns[i + 1].mnemonic().unwrap_or("").trim_end_matches(".w") == "nop"
            {
                insns[i + 1].address() as u32
            } else {
                insn.address() as u32
            };
            if !ctx.symbols.contains_key(&addr) {
                ctx.add_symbol(addr, format!("sub_{:08X}", addr), SYMBOL_SUBROUTINE);
            }
        }
    }

    if !ctx.symbols.contains_key(&ctx.text_addr) {
        ctx.add_symbol(
            ctx.text_addr,
            format!("sub_{:08X}", ctx.text_addr),
            SYMBOL_SUBROUTINE,
        );
    }

    Ok(())
}

// ========== Pass 3: Analyze argument counts ==========

pub fn analyze_arguments(ctx: &mut Context) -> Result<(), anyhow::Error> {
    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()?;

    let code = &ctx.text_seg[..ctx.mod_info_offset as usize];
    let insns = cs.disasm_all(code, ctx.text_addr as u64)?;
    let mut n_args: usize = 0;

    for insn in insns.iter() {
        let addr = insn.address() as u32;
        if ctx.symbols.contains_key(&addr) {
            n_args = 0;
        }

        let detail = match cs.insn_detail(insn) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let arch_detail = detail.arch_detail();
        let arm = match arch_detail.arm() {
            Some(a) => a,
            None => continue,
        };
        let mnemonic_raw = insn.mnemonic().unwrap_or("");
        let mnemonic = mnemonic_raw.trim_end_matches(".w");
        let (base, _) = get_cond_info(arm.cc(), mnemonic);
        let ops: Vec<_> = arm.operands().collect();

        // str/strd to sp → stack args
        if (base == "str" && ops.len() >= 2) || (base == "strd" && ops.len() >= 3) {
            let mem_idx = if base == "strd" { 2 } else { 1 };
            if let arch::arm::ArmOperandType::Mem(mem) = &ops[mem_idx].op_type
                && to_u32(mem.base()) == ARM_REG_SP
                && mem.disp() >= 0
                && mem.disp() < 0xC
            {
                let n_stack = (mem.disp() as usize >> 2) + 1;
                if n_args <= 4 + n_stack {
                    n_args = 4 + n_stack;
                }
            }
        }

        // Register usage for args
        if let Some(code) = instructions::get_instruction_code(base, ops.len() as u8)
            && code.contains("op0 = ")
            && !ops.is_empty()
        {
            if let arch::arm::ArmOperandType::Reg(reg) = ops[0].op_type {
                let r = to_u32(reg);
                if (ARM_REG_R0..=ARM_REG_R3).contains(&r) {
                    if r == ARM_REG_R0 && n_args == 0 {
                        n_args = 1;
                    } else if r == ARM_REG_R1 && n_args <= 1 {
                        n_args = 2;
                    } else if r == ARM_REG_R2 && n_args <= 2 {
                        n_args = 3;
                    } else if r == ARM_REG_R3 && n_args <= 3 {
                        n_args = 4;
                    }
                }
            }
            // ldrd: also check second destination register
            if base == "ldrd"
                && ops.len() >= 2
                && let arch::arm::ArmOperandType::Reg(reg) = ops[1].op_type
            {
                let r = to_u32(reg);
                if (ARM_REG_R0..=ARM_REG_R3).contains(&r) {
                    if r == ARM_REG_R0 && n_args == 0 {
                        n_args = 1;
                    } else if r == ARM_REG_R1 && n_args <= 1 {
                        n_args = 2;
                    } else if r == ARM_REG_R2 && n_args <= 2 {
                        n_args = 3;
                    } else if r == ARM_REG_R3 && n_args <= 3 {
                        n_args = 4;
                    }
                }
            }
        }

        // Call → record stats
        if base == "bl" || base == "blx" {
            if let Some(op) = ops.first()
                && let arch::arm::ArmOperandType::Imm(imm) = op.op_type
            {
                let target = imm as u32;
                if target >= ctx.text_addr
                    && target < ctx.text_addr + ctx.text_size
                    && let Some(sym) = ctx.symbols.get_mut(&target)
                    && n_args < MAX_ARGS
                {
                    sym.args_stats[n_args] += 1;
                }
            }
            n_args = 0;
        }
    }

    for sym in ctx.symbols.values_mut() {
        if sym.is_subroutine() {
            let mut best = 0u32;
            let mut max = 0u32;
            for i in 0..MAX_ARGS {
                if sym.args_stats[i] > max {
                    max = sym.args_stats[i];
                    best = i as u32;
                }
            }
            sym.n_args = best;
        }
    }

    Ok(())
}

// ========== Pass 4: Analyze register assignments ==========

pub fn analyze_code(ctx: &mut Context) -> Result<(), anyhow::Error> {
    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()?;

    let code = &ctx.text_seg[..ctx.mod_info_offset as usize];
    let insns = cs.disasm_all(code, ctx.text_addr as u64)?;

    for insn in insns.iter() {
        let addr = insn.address() as u32;
        if ctx.symbols.contains_key(&addr) {
            ctx.free_reg_assign_map();
            ctx.use_flags = false;
        }

        let detail = match cs.insn_detail(insn) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let arch_detail = detail.arch_detail();
        let arm = match arch_detail.arm() {
            Some(a) => a,
            None => continue,
        };
        let mnemonic_raw = insn.mnemonic().unwrap_or("");
        let mnemonic = mnemonic_raw.trim_end_matches(".w");
        let update_flags = arm.update_flags();

        let is_cond = arm.cc() != arch::arm::ArmCC::ARM_CC_AL;
        if is_cond {
            ctx.use_flags = true;
        }
        if update_flags {
            ctx.use_flags = false;
            ctx.condition_reg_1.clear();
            ctx.condition_reg_2.clear();
        }

        let (mut_base, _) = get_cond_info(arm.cc(), mnemonic);

        // Strip 's' suffix when update_flags is set
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

        let code_str = match instructions::get_instruction_code(base, arm.operands().len() as u8) {
            Some(c) => c.to_string(),
            None => continue,
        };

        let ops: Vec<_> = arm.operands().collect();
        let is_cmp = base == "cmp";

        // Phase 1: replace operands in template (like parseOperations)
        let mut mod_code = code_str.clone();
        let orig_code = code_str.clone(); // for "op_i = " destination check

        for i in 0..ops.len() {
            let op_name = format!("op{}", i);
            let is_last = i == ops.len() - 1;
            match &ops[i].op_type {
                arch::arm::ArmOperandType::Reg(reg) => {
                    let reg_id = to_u32(*reg);
                    let mut reg_str = get_reg_name(reg_id);
                    let is_dest = orig_code.contains(&format!("{} = ", op_name));
                    if !is_dest {
                        compose_register(ctx, &mut reg_str, reg_id, true);
                    }
                    if is_last {
                        reg_str = instructions::handle_shift(&reg_str, &ops[i].shift, |id| {
                            get_reg_name(id)
                        });
                    }
                    if is_cmp {
                        if i == 0 {
                            ctx.condition_reg_1 = reg_str.clone();
                        } else if i == 1 {
                            ctx.condition_reg_2 = reg_str.clone();
                        }
                    }
                    mod_code = mod_code.replace(&op_name, &reg_str);
                }
                arch::arm::ArmOperandType::Imm(imm) => {
                    mod_code = mod_code.replace(&op_name, &get_imm_string(*imm as u32, false));
                }
                arch::arm::ArmOperandType::Mem(mem) => {
                    let base_reg = to_u32(mem.base());
                    let mut reg = get_reg_name(base_reg);
                    let is_dest = orig_code.contains(&format!("{} = ", op_name));
                    if !is_dest {
                        compose_register(ctx, &mut reg, base_reg, true);
                    }
                    let str_val = if mem.index().0 != 0 {
                        let reg2 = get_reg_name(to_u32(mem.index()));
                        format!("{} + {}", reg, reg2)
                    } else {
                        let mut s =
                            format!("{} + {}", reg, get_imm_string(mem.disp() as u32, true));
                        if s.ends_with(" + 0") {
                            s = s[..s.len() - 4].to_string();
                        }
                        s
                    };
                    mod_code = mod_code.replace(&op_name, &str_val);
                }
                _ => {}
            }
        }

        // Phase 2: track assignments on the modified code (like assignRegister)
        if mod_code.len() > 3
            && &mod_code[3..4] == "="
            && !mod_code.contains(" = symbol")
            && let arch::arm::ArmOperandType::Reg(reg) = ops[0].op_type
        {
            let reg_id = to_u32(reg);
            if !is_cond {
                if let Some(eq_pos) = mod_code.find(" = ") {
                    let start = eq_pos + 3;
                    let semi = mod_code[start..]
                        .find(';')
                        .unwrap_or(mod_code.len() - start);
                    let assign = mod_code[start..start + semi].to_string();

                    // movt: compose with previous movw and ignore the movw
                    if base == "movt"
                        && let Some(Some(prev)) = ctx.reg_assign_map.get(&reg_id)
                        && is_hex_or_dec(&prev.assign)
                        && let Some(movt_part) = assign.split_whitespace().next()
                        && let Ok(movt_val) =
                            u32::from_str_radix(movt_part.trim_start_matches("0x"), 16)
                    {
                        let movw_val = if prev.assign.starts_with("0x") {
                            u32::from_str_radix(prev.assign.trim_start_matches("0x"), 16)
                                .unwrap_or(0)
                        } else {
                            prev.assign.parse::<i32>().unwrap_or(0) as u32
                        };
                        let value = movt_val | movw_val;
                        ctx.ignore_addr(reg_id);
                        let entry = ctx.reg_assign_map.entry(reg_id).or_insert_with(|| {
                            Some(RegisterAssignment {
                                assign: String::new(),
                                addr: 0,
                                update_flags: false,
                            })
                        });
                        if let Some(e) = entry {
                            e.assign = format!("0x{:08X}", value);
                            e.addr = addr;
                            e.update_flags = update_flags;
                        }
                        continue; // skip normal assignment below
                    }

                    let entry = ctx.reg_assign_map.entry(reg_id).or_insert_with(|| {
                        Some(RegisterAssignment {
                            assign: String::new(),
                            addr: 0,
                            update_flags: false,
                        })
                    });
                    if let Some(e) = entry {
                        e.assign = assign;
                        e.addr = addr;
                        e.update_flags = update_flags;
                    }
                }
            } else {
                ctx.reg_assign_map.remove(&reg_id);
            }
        }

        // Phase 3: symbol & argument composition (like original translateCode Phase 3)
        // For bl/blx, compose argument registers and call ignore_addr
        if base == "bl" || base == "blx" {
            for op in ops.iter().take(2) {
                if let arch::arm::ArmOperandType::Imm(imm) = op.op_type {
                    let target = imm as u32;
                    if let Some(sym) = ctx.symbols.get(&target)
                        && sym.is_subroutine()
                    {
                        let n = (sym.n_args as usize).min(11);
                        let regs = [ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3];
                        for &r in &regs[..n.min(4)] {
                            ctx.ignore_addr(r);
                        }
                    }
                }
            }
            ctx.clear_regs_after_branch();
            ctx.use_flags = false;
        }
    }

    Ok(())
}

pub fn get_cond_info(
    cc: arch::arm::ArmCC,
    mnemonic: &str,
) -> (&str, Option<(&'static str, &'static str)>) {
    if cc == arch::arm::ArmCC::ARM_CC_AL || mnemonic.len() < 2 {
        return (mnemonic, None);
    }
    let (base, suffix) = mnemonic.split_at(mnemonic.len() - 2);

    let cc_name = match cc {
        arch::arm::ArmCC::ARM_CC_EQ => "eq",
        arch::arm::ArmCC::ARM_CC_NE => "ne",
        arch::arm::ArmCC::ARM_CC_HS => "hs",
        arch::arm::ArmCC::ARM_CC_LO => "lo",
        arch::arm::ArmCC::ARM_CC_HI => "hi",
        arch::arm::ArmCC::ARM_CC_LS => "ls",
        arch::arm::ArmCC::ARM_CC_GE => "ge",
        arch::arm::ArmCC::ARM_CC_LT => "lt",
        arch::arm::ArmCC::ARM_CC_GT => "gt",
        arch::arm::ArmCC::ARM_CC_LE => "le",
        arch::arm::ArmCC::ARM_CC_MI => "mi",
        arch::arm::ArmCC::ARM_CC_PL => "pl",
        arch::arm::ArmCC::ARM_CC_VS => "vs",
        arch::arm::ArmCC::ARM_CC_VC => "vc",
        _ => return (mnemonic, None),
    };

    if suffix == cc_name
        && let Some(cond) = CONDITIONS.get(cc_name)
    {
        let cf = if cond.cond_flags.is_empty() {
            None
        } else {
            Some(cond.cond_flags)
        };
        let cr = if cond.cond_regs.is_empty() {
            None
        } else {
            Some(cond.cond_regs)
        };
        return (base, Some((cf.unwrap_or(""), cr.unwrap_or(""))));
    }
    (mnemonic, None)
}

fn compose_register(ctx: &mut Context, reg_str: &mut String, reg: u32, analyse: bool) {
    if reg == ARM_REG_SP {
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
