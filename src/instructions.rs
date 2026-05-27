use std::collections::HashMap;
use std::sync::LazyLock;

pub struct Condition {
    pub cond_flags: &'static str,
    pub cond_regs: &'static str,
}

pub static CONDITIONS: LazyLock<HashMap<&'static str, Condition>> = LazyLock::new(|| {
    HashMap::from([
        (
            "eq",
            Condition {
                cond_flags: "if (Z == 1) // ==",
                cond_regs: "if (COND_X == COND_Y)",
            },
        ),
        (
            "ne",
            Condition {
                cond_flags: "if (Z == 0) // !=",
                cond_regs: "if (COND_X != COND_Y)",
            },
        ),
        (
            "hs",
            Condition {
                cond_flags: "if (C == 1) // unsigned >=",
                cond_regs: "if ((unsigned)(COND_X) >= (unsigned)(COND_Y))",
            },
        ),
        (
            "lo",
            Condition {
                cond_flags: "if (C == 0) // unsigned <",
                cond_regs: "if ((unsigned)(COND_X) < (unsigned)(COND_Y))",
            },
        ),
        (
            "hi",
            Condition {
                cond_flags: "if (C == 1 && Z == 0) // unsigned >",
                cond_regs: "if ((unsigned)(COND_X) > (unsigned)(COND_Y))",
            },
        ),
        (
            "ls",
            Condition {
                cond_flags: "if (C == 0 || Z == 1) // unsigned <=",
                cond_regs: "if ((unsigned)(COND_X) <= (unsigned)(COND_Y))",
            },
        ),
        (
            "ge",
            Condition {
                cond_flags: "if (N == V) // signed >=",
                cond_regs: "if ((signed)(COND_X) >= (signed)(COND_Y))",
            },
        ),
        (
            "lt",
            Condition {
                cond_flags: "if (N != V) // signed <",
                cond_regs: "if ((signed)(COND_X) < (signed)(COND_Y))",
            },
        ),
        (
            "gt",
            Condition {
                cond_flags: "if (Z == 0 && N == V) // signed >",
                cond_regs: "if ((signed)(COND_X) > (signed)(COND_Y))",
            },
        ),
        (
            "le",
            Condition {
                cond_flags: "if (Z == 1 || N != V) // signed <=",
                cond_regs: "if ((signed)(COND_X) <= (signed)(COND_Y))",
            },
        ),
        (
            "mi",
            Condition {
                cond_flags: "if (N == 1) // signed < 0",
                cond_regs: "",
            },
        ),
        (
            "pl",
            Condition {
                cond_flags: "if (N == 0) // signed > 0",
                cond_regs: "",
            },
        ),
        (
            "vs",
            Condition {
                cond_flags: "if (V == 1) // Signed overflow",
                cond_regs: "",
            },
        ),
        (
            "vc",
            Condition {
                cond_flags: "if (V == 0) // No signed overflow",
                cond_regs: "",
            },
        ),
        (
            "al",
            Condition {
                cond_flags: "if (1) // Always",
                cond_regs: "",
            },
        ),
    ])
});

#[allow(dead_code)]
pub static SHIFTS: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("asr", ">>"),
        ("lsl", "<<"),
        ("lsr", ">>"),
        ("ror", "__builtin_ror"),
        ("rrx", "__builtin_rrx"),
    ])
});

#[allow(dead_code)]
pub fn get_shift_op(shift_name: &str) -> Option<&'static str> {
    SHIFTS.get(shift_name).copied()
}

pub fn handle_shift(
    reg_str: &str,
    shift: &capstone::arch::arm::ArmShift,
    reg_namer: impl Fn(u32) -> String,
) -> String {
    use capstone::arch::arm::ArmShift;
    match shift {
        ArmShift::Invalid
        | ArmShift::Lsl(0)
        | ArmShift::Asr(0)
        | ArmShift::Lsr(0)
        | ArmShift::Ror(0)
        | ArmShift::Rrx(_) => reg_str.to_string(),
        ArmShift::Asr(n) => format!("({} >> {})", reg_str, n),
        ArmShift::Lsl(n) => format!("({} << {})", reg_str, n),
        ArmShift::Lsr(n) => format!("((unsigned){} >> {})", reg_str, n),
        ArmShift::Ror(n) => format!("__builtin_ror({}, {})", reg_str, n),
        ArmShift::AsrReg(reg) => format!("({} >> {})", reg_str, reg_namer(reg.0 as u32)),
        ArmShift::LslReg(reg) => format!("({} << {})", reg_str, reg_namer(reg.0 as u32)),
        ArmShift::LsrReg(reg) => format!("((unsigned){} >> {})", reg_str, reg_namer(reg.0 as u32)),
        ArmShift::RorReg(reg) => format!("__builtin_ror({}, {})", reg_str, reg_namer(reg.0 as u32)),
        ArmShift::RrxReg(_) => format!("__builtin_rrx({})", reg_str),
    }
}

pub fn get_instruction_code(mnemonic: &str, op_count: u8) -> Option<&'static str> {
    if let Some(&code) = INSTRUCTIONS_3OP.get(mnemonic) {
        if op_count == 2
            && let Some(&code2) = INSTRUCTIONS_2OP.get(mnemonic) {
                return Some(code2);
            }
        return Some(code);
    }
    None
}

pub static INSTRUCTIONS_3OP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("cmp", "FLAGS = op0 - op1;"),
        ("cmn", "FLAGS = op0 + op1;"),
        ("tst", "FLAGS = op0 & op1;"),
        ("cbz", "if (op0 == 0)\\\tgoto symbol;"),
        ("cbnz", "if (op0 != 0)\\\tgoto symbol;"),
        ("b", "goto symbol;"),
        ("bl", "a1 = symbol(...);"),
        ("blx", "a1 = symbol(...);"),
        ("add", "op0 = op1 + op2;"),
        ("addw", "op0 = op1 + op2;"),
        ("adc", "op0 = op1 + op2;"),
        ("sub", "op0 = op1 - op2;"),
        ("subw", "op0 = op1 - op2;"),
        ("rsb", "op0 = op2 - op1;"),
        ("sbc", "op0 = op1 - op2;"),
        ("asr", "op0 = op1 >> op2;"),
        ("asl", "op0 = op1 << op2;"),
        ("mul", "op0 = op1 * op2;"),
        ("mla", "op0 = op1 * op2 + op3;"),
        ("mls", "op0 = op1 * op2 - op3;"),
        (
            "umull",
            "op0 = (op2 * op3) << 32;\\op1 = (op2 * op3) & 0xFFFFFFFF;",
        ),
        ("and", "op0 = op1 & op2;"),
        ("bic", "op0 = op1 & ~op2;"),
        ("eor", "op0 = op1 ^ op2;"),
        ("orr", "op0 = op1 | op2;"),
        ("lsr", "op0 = op1 >> op2;"),
        ("lsl", "op0 = op1 << op2;"),
        ("ubfx", "op0 = (op1 >> op2) & ((1 << op3) - 1);"),
        ("rev", "op0 = __builtin_bswap32(op1);"),
        ("rev16", "op0 = __builtin_bswap16(op1);"),
        ("mov", "op0 = op1;"),
        ("mvn", "op0 = ~op1;"),
        ("movt", "op0 = op10000 | op0;"),
        ("movw", "op0 = op1;"),
        ("uxtb", "op0 = (uint8_t)op1;"),
        ("uxth", "op0 = (uint16_t)op1;"),
        ("sxtb", "op0 = (int8_t)op1;"),
        ("sxth", "op0 = (int16_t)op1;"),
        ("ldr", "op0 = *(uint32_t *)(op1);"),
        ("ldrb", "op0 = *(uint8_t *)(op1);"),
        ("ldrsb", "op0 = *(int8_t *)(op1);"),
        ("ldrh", "op0 = *(uint16_t *)(op1);"),
        ("ldrsh", "op0 = *(int16_t *)(op1);"),
        (
            "ldrd",
            "op0 = *(uint32_t *)(op2);\\op1 = *(uint32_t *)(op2 + 0x4);",
        ),
        ("str", "*(uint32_t *)(op1) = op0;"),
        ("strb", "*(uint8_t *)(op1) = op0;"),
        ("strsb", "*(int8_t *)(op1) = op0;"),
        ("strh", "*(uint16_t *)(op1) = op0;"),
        ("strsh", "*(int16_t *)(op1) = op0;"),
        (
            "strd",
            "*(uint32_t *)(op2) = op0;\\*(uint32_t *)(op2 + 0x4) = op1;",
        ),
    ])
});

pub static INSTRUCTIONS_2OP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("add", "op0 = op0 + op1;"),
        ("sub", "op0 = op0 - op1;"),
        ("mul", "op0 = op0 * op1;"),
        ("asr", "op0 = op0 >> op1;"),
        ("asl", "op0 = op0 << op1;"),
        ("and", "op0 = op0 & op1;"),
        ("bic", "op0 = op0 & ~op1;"),
        ("eor", "op0 = op0 ^ op1;"),
        ("orr", "op0 = op0 | op1;"),
        ("lsr", "op0 = op0 >> op1;"),
        ("lsl", "op0 = op0 << op1;"),
    ])
});
