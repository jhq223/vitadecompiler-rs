# VitaDecompiler RS

PS Vita ARM Thumb binary decompiler written in Rust.

## Build

```bash
# Requires Rust toolchain + CMake (for capstone C sources)
cargo build --release
```

## Usage

```bash
# Basic decompilation
vitadecompiler eboot.bin db.yml

# Specify firmware version
vitadecompiler -v 3.65 eboot.bin db.yml

# Export YAML database only (no decompilation)
vitadecompiler -y eboot.bin db.yml

# Apply SCE relocations
vitadecompiler -r eboot.bin db.yml
```

## Output

| File | Description |
|------|-------------|
| `<binary>.c` | Pseudo-C decompiled output |
| `<binary>.h` | Function declaration header |
| `<binary>.nids.txt` | NID table (export/import function list) |
| `<module>.yml` | db_lookup file (NID to function name mapping) |

## NID Database

A YAML-format NID database (from vitasdk) is required. Merge individual module YAMLs from `vitasdk/share/vita-headers/db/` into a single file:

```bash
cd vitasdk/share/vita-headers/db/360
python -c "
import yaml, glob
result = {'version': '0x2', 'firmware': '3.60', 'modules': {}}
for f in sorted(glob.glob('*.yml')):
    data = yaml.safe_load(open(f))
    if data and 'modules' in data:
        result['modules'].update(data['modules'])
print(yaml.dump(result))
" > db_360_merged.yml
```

## License

GPLv3 — Inspired by [PSVita-RE-tools](https://github.com/TeamFAPS/PSVita-RE-tools).
