#!/usr/bin/env python3
# 部署新编译的 LyScript.dp64 到 x64dbg 插件目录，并验证 PE 导入表依赖
# 用途：解决旧 DLL 依赖 MSVCR120/MSVCP120 缺失导致插件不加载的问题
import struct
import shutil
import os
import sys

SRC = r'F:\00\LyScript_mcp\build\LyScript.dp64'
DST = r'C:\x64dbg\x64\plugins\LyScript.dp64'
BAK = DST + '.bak2'


def rva_to_offset(rva, sections):
    """RVA 转文件偏移：遍历节区，找到包含该 RVA 的节"""
    for vaddr, vsize, raw_ptr in sections:
        if vaddr <= rva < vaddr + vsize:
            return rva - vaddr + raw_ptr
    return rva


def parse_imports(path):
    """解析 PE 导入表，返回依赖 DLL 名称列表"""
    with open(path, 'rb') as fp:
        data = fp.read()

    # DOS header: e_lfanew at 0x3C 指向 PE header
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    # Optional header 紧跟 PE signature(4) + COFF header(20)
    opt_off = pe_off + 24
    magic = struct.unpack_from('<H', data, opt_off)[0]
    # PE32+ (64位) 数据目录偏移 = opt+112; PE32 (32位) = opt+96
    data_dir_off = opt_off + 112 if magic == 0x20b else opt_off + 96
    # 导入表是第 2 个数据目录项 (index 1)，偏移 +8
    import_rva = struct.unpack_from('<I', data, data_dir_off + 8)[0]

    # 节区表紧跟 Optional header；节区数量在 COFF header 的 +6
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_size

    # 读取所有节区：每节 40 字节，VirtualAddress@+12, VirtualSize@+8, PointerToRawData@+20
    sections = []
    for i in range(num_sections):
        vsize = struct.unpack_from('<I', data, sec_off + i * 40 + 8)[0]
        vaddr = struct.unpack_from('<I', data, sec_off + i * 40 + 12)[0]
        raw_ptr = struct.unpack_from('<I', data, sec_off + i * 40 + 20)[0]
        sections.append((vaddr, vsize, raw_ptr))

    # 遍历导入目录表，每项 20 字节，直到全 0 项
    deps = []
    imp_off = rva_to_offset(import_rva, sections)
    while True:
        ilt_rva = struct.unpack_from('<I', data, imp_off)[0]
        name_rva = struct.unpack_from('<I', data, imp_off + 12)[0]
        if ilt_rva == 0 and name_rva == 0:
            break
        if name_rva != 0:
            name_off = rva_to_offset(name_rva, sections)
            end = data.index(b'\x00', name_off)
            deps.append(data[name_off:end].decode('ascii', errors='ignore'))
        imp_off += 20
    return deps


def main():
    if not os.path.exists(SRC):
        print(f'[ERR] new DLL not found: {SRC}')
        sys.exit(1)

    print('=== New DLL deps (build/LyScript.dp64) ===')
    deps = parse_imports(SRC)
    for d in deps:
        print(f'  - {d}')

    bad = [d for d in deps if d.upper().startswith(('MSVCR', 'MSVCP', 'VCRUNTIME'))]
    if bad:
        print(f'\n[WARN] new DLL still depends on VC runtime: {bad}')
    else:
        print('\n[OK] no MSVCR/MSVCP/VCRUNTIME - /MT static link successful')

    # 备份旧 DLL
    if os.path.exists(DST):
        if not os.path.exists(BAK):
            shutil.copy2(DST, BAK)
            print(f'\n[OK] old DLL backed up to: {BAK}')
        else:
            print(f'\n[INFO] backup already exists: {BAK}')

    # 复制新 DLL
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    shutil.copy2(SRC, DST)
    print(f'[OK] new DLL copied to: {DST}')
    print(f'new size: {os.path.getsize(DST)} bytes')

    # 验证部署后的文件
    print('\n=== Verify deployed DLL deps ===')
    deps2 = parse_imports(DST)
    for d in deps2:
        print(f'  - {d}')


if __name__ == '__main__':
    main()
