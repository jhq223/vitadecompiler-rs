# VitaDecompiler RS

用 Rust 编写的 PS Vita ARM Thumb 二进制反编译器。

## 构建

```bash
# 需要 Rust 工具链 + CMake（capstone 的 C 源码需要 CMake 编译）
cargo build --release
```

## 用法

```bash
# 基本反编译
vitadecompiler eboot.bin db.yml

# 指定固件版本
vitadecompiler -v 3.65 eboot.bin db.yml

# 仅导出 YAML 数据库（不反编译）
vitadecompiler -y eboot.bin db.yml

# 执行 SCE 重定位
vitadecompiler -r eboot.bin db.yml
```

## 输出文件

| 文件 | 说明 |
|------|------|
| `<binary>.c` | 伪 C 反编译输出 |
| `<binary>.h` | 函数声明头文件 |
| `<binary>.nids.txt` | NID 表（导出/导入函数清单） |
| `<module>.yml` | db_lookup 文件（NID 到函数名映射） |

## NID 数据库

需要 YAML 格式的 NID 数据库（来自 vitasdk）。将 `vitasdk/share/vita-headers/db/` 下的各模块 YAML 合并为单个文件：

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

## 许可

GPLv3 — 本项目参考了 [PSVita-RE-tools](https://github.com/TeamFAPS/PSVita-RE-tools) 的实现，使用 Rust 重写。
