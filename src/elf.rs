use anyhow::{Context, Result};
use flate2::Decompress;
use std::io::Read;

const SELF_MAGIC: u32 = 0x454353;
const HEADER_LEN: usize = 0x1000;

pub struct LoadedBinary {
    pub text_seg: Vec<u8>,
    pub data_seg: Vec<u8>,
    pub text_addr: u32,
    pub data_addr: u32,
    pub entry_point: u32,
    pub phdrs: Vec<ElfPhdr>,
    pub segment_infos: Vec<(u64, u64, u64)>,
    pub buf: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ElfPhdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
}

pub fn load_binary(path: &str) -> Result<LoadedBinary> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("Failed to open: {}", path))?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let buf_len = buf.len();

    let (elf_offset, phdr_offset, section_info_offset) = if is_self(&buf) {
        let self_hdr = parse_self_header(&buf)?;
        (
            self_hdr.elf_offset as usize,
            self_hdr.phdr_offset as usize,
            self_hdr.section_info_offset as usize,
        )
    } else if is_elf(&buf) {
        (0, 0, 0)
    } else {
        anyhow::bail!("File is not ELF or SELF");
    };

    let elf_bytes = &buf[elf_offset..];
    let elf = goblin::elf::Elf::parse(elf_bytes)?;

    let phdr_start = if is_self(&buf) {
        phdr_offset - elf_offset
    } else {
        elf.header.e_phoff as usize
    };

    if !is_self(&buf) && (phdr_start == 0 || elf.header.e_phnum == 0) {
        anyhow::bail!("No program headers found");
    }

    let mut phdrs: Vec<ElfPhdr> = Vec::new();
    let mut segment_infos: Vec<(u64, u64, u64)> = Vec::new();

    for i in 0..elf.header.e_phnum as usize {
        let phdr_bytes = &elf_bytes[phdr_start + i * elf.header.e_phentsize as usize..];
        let p_type = u32::from_le_bytes(phdr_bytes[0..4].try_into().unwrap());
        let p_offset = u32::from_le_bytes(phdr_bytes[4..8].try_into().unwrap());
        let p_vaddr = u32::from_le_bytes(phdr_bytes[8..12].try_into().unwrap());
        let _p_paddr = u32::from_le_bytes(phdr_bytes[12..16].try_into().unwrap());
        let p_filesz = u32::from_le_bytes(phdr_bytes[16..20].try_into().unwrap());
        let p_memsz = u32::from_le_bytes(phdr_bytes[20..24].try_into().unwrap());

        if is_self(&buf) && section_info_offset > 0 {
            let si_off = section_info_offset + i * 24;
            if si_off + 24 <= buf_len {
                let si_offset = u64::from_le_bytes(buf[si_off..si_off + 8].try_into().unwrap());
                let si_length =
                    u64::from_le_bytes(buf[si_off + 8..si_off + 16].try_into().unwrap());
                let si_compression =
                    u64::from_le_bytes(buf[si_off + 16..si_off + 24].try_into().unwrap());
                segment_infos.push((si_offset, si_length, si_compression));
            } else {
                segment_infos.push((p_offset as u64, p_filesz as u64, 1));
            }
        } else {
            segment_infos.push((p_offset as u64, p_filesz as u64, 1));
        }

        phdrs.push(ElfPhdr {
            p_type,
            p_offset,
            p_vaddr,
            p_filesz,
            p_memsz,
        });
    }

    if phdrs.len() < 2 {
        anyhow::bail!(
            "Need at least 2 segments (text + data), got {}",
            phdrs.len()
        );
    }

    let text_seg = load_segment(&buf, &phdrs[0], segment_infos.first())?;
    let data_seg = load_segment(&buf, &phdrs[1], segment_infos.get(1))?;

    println!(
        "Text segment: vaddr=0x{:08X} size=0x{:X}",
        phdrs[0].p_vaddr,
        text_seg.len()
    );
    println!(
        "Data segment: vaddr=0x{:08X} size=0x{:X}",
        phdrs[1].p_vaddr,
        data_seg.len()
    );

    Ok(LoadedBinary {
        text_seg,
        data_seg,
        text_addr: phdrs[0].p_vaddr,
        data_addr: phdrs[1].p_vaddr,
        entry_point: elf.header.e_entry as u32,
        phdrs,
        segment_infos,
        buf,
    })
}

impl LoadedBinary {
    #[allow(dead_code)]
    pub fn load_segment_by_index(&self, idx: usize) -> Result<Vec<u8>> {
        if idx >= self.phdrs.len() {
            anyhow::bail!("Segment index {} out of range", idx);
        }
        load_segment(&self.buf, &self.phdrs[idx], self.segment_infos.get(idx))
    }

    pub fn load_segment_raw(&self, idx: usize) -> Result<Vec<u8>> {
        if idx >= self.phdrs.len() {
            anyhow::bail!("Segment index {} out of range", idx);
        }
        let phdr = &self.phdrs[idx];
        let (file_offset, file_size) = if let Some(&(off, len, _)) = self.segment_infos.get(idx) {
            (off as usize, len as usize)
        } else {
            (phdr.p_offset as usize, phdr.p_filesz as usize)
        };
        let sz = std::cmp::max(phdr.p_memsz as usize, phdr.p_filesz as usize);
        let copy_size = std::cmp::min(
            file_size,
            sz.min(self.buf.len().saturating_sub(file_offset)),
        );
        let mut output = vec![0u8; sz];
        if file_offset + copy_size <= self.buf.len() {
            output[..copy_size].copy_from_slice(&self.buf[file_offset..file_offset + copy_size]);
        }
        Ok(output)
    }
}

fn is_self(buf: &[u8]) -> bool {
    buf.len() >= 4 && u32::from_le_bytes(buf[0..4].try_into().unwrap()) == SELF_MAGIC
}

fn is_elf(buf: &[u8]) -> bool {
    buf.len() >= 8 && &buf[0..4] == b"\x7fELF"
}

struct SelfHeader {
    elf_offset: u64,
    phdr_offset: u64,
    section_info_offset: u64,
}

fn parse_self_header(buf: &[u8]) -> Result<SelfHeader> {
    if buf.len() < HEADER_LEN {
        anyhow::bail!("SELF file too small");
    }
    Ok(SelfHeader {
        elf_offset: u64::from_le_bytes(buf[0x40..0x48].try_into().unwrap()),
        phdr_offset: u64::from_le_bytes(buf[0x48..0x50].try_into().unwrap()),
        section_info_offset: u64::from_le_bytes(buf[0x58..0x60].try_into().unwrap()),
    })
}

fn load_segment(buf: &[u8], phdr: &ElfPhdr, seg_info: Option<&(u64, u64, u64)>) -> Result<Vec<u8>> {
    let sz = std::cmp::max(phdr.p_memsz as usize, phdr.p_filesz as usize);
    let mut output = vec![0u8; sz];

    let (file_offset, file_size, compression) = if let Some(&(off, len, comp)) = seg_info {
        (off as usize, len as usize, comp)
    } else {
        (phdr.p_offset as usize, phdr.p_filesz as usize, 1)
    };

    let copy_size = std::cmp::min(file_size, sz);
    if file_offset + copy_size <= buf.len() {
        output[..copy_size].copy_from_slice(&buf[file_offset..file_offset + copy_size]);
    }

    if compression == 2 {
        let mut decompress = Decompress::new(true);
        let mut decompressed = vec![0u8; sz];
        let status = decompress.decompress(
            &output[..copy_size],
            &mut decompressed,
            flate2::FlushDecompress::Finish,
        )?;
        if status != flate2::Status::StreamEnd {
            println!("Warning: segment decompression incomplete: {:?}", status);
        }
        Ok(decompressed)
    } else {
        Ok(output)
    }
}
