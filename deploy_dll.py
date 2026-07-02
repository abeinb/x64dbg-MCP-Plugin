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

# x86 版本（毒舌批评要求双架构支持，用于调试 32 位卡密程序）
SRC_X86 = r'F:\00\LyScript_mcp\build\LyScript.dp32'
DST_X86 = r'C:\x64dbg\x32\plugins\LyScript.dp32'
BAK_X86 = DST_X86 + '.bak'


def rva_to_offset(rva, sections):
    """RVA 转文件偏移：遍历节区，找到包含该 RVA 的节
    毒舌批评修复：找不到节区时抛异常而非返回 rva（rva 不是文件偏移）
    """
    for vaddr, vsize, raw_ptr in sections:
        if vaddr <= rva < vaddr + vsize:
            return rva - vaddr + raw_ptr
    raise ValueError(f'RVA 0x{rva:x} not in any section')


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

    # 毒舌批评修复：无导入表时返回空列表，避免从文件头解析
    if import_rva == 0:
        return []

    # 遍历导入目录表，每项 20 字节，直到全 0 项
    deps = []
    try:
        imp_off = rva_to_offset(import_rva, sections)
    except ValueError:
        return []
    while True:
        # 毒舌批评修复：越界保护
        if imp_off + 20 > len(data):
            break
        ilt_rva = struct.unpack_from('<I', data, imp_off)[0]
        name_rva = struct.unpack_from('<I', data, imp_off + 12)[0]
        if ilt_rva == 0 and name_rva == 0:
            break
        if name_rva != 0:
            try:
                name_off = rva_to_offset(name_rva, sections)
                if name_off < len(data):
                    end = data.find(b'\x00', name_off, name_off + 256)
                    if end > 0:
                        deps.append(data[name_off:end].decode('ascii', errors='ignore'))
            except ValueError:
                pass
        imp_off += 20
    return deps


def deploy_one(src, dst, bak, arch_name):
    """部署单个 DLL：备份旧版 + 复制新版 + 验证依赖"""
    if not os.path.exists(src):
        print(f'[ERR] {arch_name} DLL not found: {src}')
        return False

    print(f'\n=== {arch_name} deps ({os.path.basename(src)}) ===')
    deps = parse_imports(src)
    for d in deps:
        print(f'  - {d}')

    bad = [d for d in deps if d.upper().startswith(('MSVCR', 'MSVCP', 'VCRUNTIME'))]
    if bad:
        print(f'[WARN] {arch_name} still depends on VC runtime: {bad}')
    else:
        print(f'[OK] {arch_name} no MSVCR/MSVCP/VCRUNTIME - /MT static link successful')

    # 毒舌批评修复：用时间戳备份，避免多次运行只保留第一次的备份
    import time
    if os.path.exists(dst):
        ts = time.strftime('%Y%m%d_%H%M%S')
        bak_ts = f'{dst}.bak.{ts}'
        shutil.copy2(dst, bak_ts)
        print(f'[OK] old {arch_name} backed up to: {bak_ts}')
        # 保留最新 .bak.latest
        latest = f'{dst}.bak.latest'
        shutil.copy2(dst, latest)

    # 复制新 DLL
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    print(f'[OK] {arch_name} copied to: {dst}')
    print(f'new size: {os.path.getsize(dst)} bytes')

    # 验证部署后的文件
    print(f'=== Verify deployed {arch_name} deps ===')
    deps2 = parse_imports(dst)
    for d in deps2:
        print(f'  - {d}')
    return True


def main():
    # 部署 x64
    ok64 = deploy_one(SRC, DST, BAK, 'x64')
    # 部署 x86
    ok32 = deploy_one(SRC_X86, DST_X86, BAK_X86, 'x86')
    if not (ok64 and ok32):
        sys.exit(1)


if __name__ == '__main__':
    main()
