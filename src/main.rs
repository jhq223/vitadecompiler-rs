mod analyze;
mod elf;
mod instructions;
mod relocate;
mod translate;
mod vita;
mod yaml_db;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "vitadecompiler")]
#[command(about = "PS Vita ARM Thumb binary decompiler (Rust rewrite)")]
struct Cli {
    /// Input binary (ELF or SELF)
    binary: String,

    /// YAML database file (NID -> function name mappings)
    db: String,

    /// Perform SCE relocations
    #[arg(short = 'r', long)]
    relocs: bool,

    /// Output YAML db_lookup only (skip decompilation)
    #[arg(short = 'y', long)]
    yaml_only: bool,

    /// Firmware version string
    #[arg(short = 'v', long, default_value = "3.60")]
    version: String,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    let db = yaml_db::YamlDb::load(&args.db)?;

    let mut loaded = elf::load_binary(&args.binary)?;

    if args.relocs {
        for (i, phdr) in loaded.phdrs.iter().enumerate() {
            if phdr.p_type == 0x60000000 {
                println!("Performing relocations using segment {}", i);
                let reloc_data = loaded.load_segment_raw(i)?;
                relocate::relocate(
                    &reloc_data,
                    &loaded.phdrs,
                    &mut loaded.text_seg,
                    &mut loaded.data_seg,
                );
            }
        }
    }

    let text_size = loaded.text_seg.len() as u32;
    let module_analysis = vita::analyze_module(
        &loaded.text_seg,
        loaded.text_addr,
        text_size,
        loaded.entry_point,
        &db,
        &args.binary,
        &args.version,
    )?;

    if args.yaml_only {
        return Ok(());
    }

    let data_size = loaded.data_seg.len() as u32;
    let mut ctx = analyze::Context::new(
        loaded.text_seg,
        loaded.data_seg,
        loaded.text_addr,
        text_size,
        loaded.data_addr,
        data_size,
        module_analysis.mod_info_offset,
        module_analysis.symbols,
    );

    println!("Analyzing symbols (pass 1)...");
    analyze::analyze_symbols_pass1(&mut ctx)?;

    println!("Analyzing symbols (pass 2)...");
    analyze::analyze_symbols_pass2(&mut ctx)?;

    println!("Analyzing arguments...");
    analyze::analyze_arguments(&mut ctx)?;

    println!("Analyzing code...");
    analyze::analyze_code(&mut ctx)?;

    println!("Decompiling...");
    translate::decompile(&mut ctx, &args.binary)?;

    println!("Finished.");
    Ok(())
}
