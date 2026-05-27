use crate::elf::ElfPhdr;

pub fn relocate(reloc_data: &[u8], phdrs: &[ElfPhdr], text_seg: &mut [u8], data_seg: &mut [u8]) {
    let mut pos = 0usize;

    while pos + 8 <= reloc_data.len() {
        let r_type = read_u32_le(reloc_data, pos);

        let (r_offset, r_addend, entry_size) = if is_short(r_type) {
            let r_opt1 = r_type;
            let r_opt2 = read_u32_le(reloc_data, pos + 4);
            let offset = (r_opt1 >> 20) | ((r_opt2 & 0x3FF) << 12) ;
            let addend = r_opt2 >> 10 ;
            (offset, addend, 8usize)
        } else {
            if pos + 12 > reloc_data.len() {
                break;
            }
            let r_addend = read_u32_le(reloc_data, pos + 4);
            let r_offset = read_u32_le(reloc_data, pos + 8);
            (r_offset, r_addend, 12usize)
        };

        let r_code = (r_type >> 8) & 0xFF;
        let r_symseg = (r_type >> 4) & 0xF;
        let r_datseg = (r_type >> 16) & 0xF;

        let symval = if r_symseg == 15 {
            0u32
        } else {
            phdrs.get(r_symseg as usize).map(|p| p.p_vaddr).unwrap_or(0)
        };

        let loc = phdrs.get(r_datseg as usize).map(|p| p.p_vaddr).unwrap_or(0) + r_offset;
        let segment_data = if r_datseg != 0 {
            &mut *data_seg
        } else {
            &mut *text_seg
        };
        let seg_base = phdrs.get(r_datseg as usize).map(|p| p.p_vaddr).unwrap_or(0);

        if r_offset as usize > segment_data.len() {
            pos += entry_size;
            continue;
        }

        let seg_offset = (loc - seg_base) as usize;

        let value = match r_code {
            0 => {
                pos += entry_size;
                continue;
            } // R_ARM_NONE

            2 | 38 => {
                // R_ARM_ABS32 | R_ARM_TARGET1
                r_addend.wrapping_add(symval)
            }

            3 | 41 => {
                // R_ARM_REL32 | R_ARM_TARGET2
                r_addend.wrapping_add(symval).wrapping_sub(loc)
            }

            10 => {
                // R_ARM_THM_CALL
                if seg_offset + 4 > segment_data.len() {
                    pos += entry_size;
                    continue;
                }
                let upper = u16::from_le_bytes(
                    segment_data[seg_offset..seg_offset + 2].try_into().unwrap(),
                ) as u32;
                let lower = u16::from_le_bytes(
                    segment_data[seg_offset + 2..seg_offset + 4]
                        .try_into()
                        .unwrap(),
                ) as u32;

                let offset = (r_addend.wrapping_add(symval).wrapping_sub(loc)) as i32;
                let sign = ((offset as u32) >> 24) & 1;
                let j1 = sign ^ ((!((offset as u32) >> 23)) & 1);
                let j2 = sign ^ ((!((offset as u32) >> 22)) & 1);

                let upper = (upper & 0xf800) | (sign << 10) | (((offset as u32) >> 12) & 0x03ff);
                let lower =
                    (lower & 0xd000) | (j1 << 13) | (j2 << 11) | (((offset as u32) >> 1) & 0x07ff);

                (lower << 16) | upper
            }

            28 | 29 => {
                // R_ARM_CALL | R_ARM_JUMP24
                if seg_offset + 4 > segment_data.len() {
                    pos += entry_size;
                    continue;
                }
                let offset = (r_addend.wrapping_add(symval).wrapping_sub(loc)) as i32;
                let offset = ((offset as u32) >> 2) & 0x00ffffff;
                let inst = read_u32_le(segment_data, seg_offset);
                (inst & 0xff000000) | offset
            }

            40 => {
                // R_ARM_V4BX
                if seg_offset + 4 > segment_data.len() {
                    pos += entry_size;
                    continue;
                }
                let inst = read_u32_le(segment_data, seg_offset);
                (inst & 0xf000000f) | 0x01a0f000
            }

            42 => {
                // R_ARM_PREL31
                let offset = r_addend.wrapping_add(symval).wrapping_sub(loc);
                offset & 0x7fffffff
            }

            43 | 44 => {
                // R_ARM_MOVW_ABS_NC | R_ARM_MOVT_ABS
                if seg_offset + 4 > segment_data.len() {
                    pos += entry_size;
                    continue;
                }
                let mut offset = symval.wrapping_add(r_addend);
                if r_code == 44 {
                    offset >>= 16;
                }
                let inst = read_u32_le(segment_data, seg_offset);
                let value = inst & 0xfff0f000;
                value | ((offset & 0xf000) << 4) | (offset & 0x0fff)
            }

            47 | 48 => {
                // R_ARM_THM_MOVW_ABS_NC | R_ARM_THM_MOVT_ABS
                if seg_offset + 4 > segment_data.len() {
                    pos += entry_size;
                    continue;
                }
                let upper = u16::from_le_bytes(
                    segment_data[seg_offset..seg_offset + 2].try_into().unwrap(),
                ) as u32;
                let lower = u16::from_le_bytes(
                    segment_data[seg_offset + 2..seg_offset + 4]
                        .try_into()
                        .unwrap(),
                ) as u32;

                let mut offset = symval.wrapping_add(r_addend);
                if r_code == 48 {
                    offset >>= 16;
                }

                let upper = (upper & 0xfbf0) | ((offset & 0xf000) >> 12) | ((offset & 0x0800) >> 1);
                let lower = (lower & 0x8f00) | ((offset & 0x0700) << 4) | (offset & 0x00ff);

                (lower << 16) | upper
            }

            _ => {
                eprintln!("Unknown relocation code {} at pos {}", r_code, pos);
                pos += entry_size;
                continue;
            }
        };

        if seg_offset + 4 <= segment_data.len() {
            segment_data[seg_offset..seg_offset + 4].copy_from_slice(&value.to_le_bytes());
        } else {
            eprintln!("Relocation overflows segment at offset {}", seg_offset);
        }

        pos += entry_size;
    }
}

fn is_short(r_type: u32) -> bool {
    (r_type & 0xF) != 0
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
}
