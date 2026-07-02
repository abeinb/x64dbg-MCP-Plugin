#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LyScript.dp64 / LyScript.dp32 编译脚本
用 vswhere 定位 VS 安装路径，避免硬编码
用 /MT 静态链接 CRT，避免依赖 MSVCR120/MSVCP120
"""
import subprocess
import os
import sys
from pathlib import Path

PROJ_DIR = Path(r'F:\00\LyScript_mcp')
SDK_DIR = Path(r'F:\00\tools\x64dbg\release\pluginsdk')
DEPS_DIR = PROJ_DIR / 'deps'
BUILD_DIR = PROJ_DIR / 'build'
BUILD_DIR.mkdir(parents=True, exist_ok=True)


def find_vs_install():
    """用 vswhere 定位最新带 VC++ 工具的 VS 安装路径"""
    candidates = [
        os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
        os.environ.get('ProgramFiles', r'C:\Program Files'),
    ]
    for base in candidates:
        vswhere = Path(base) / 'Microsoft Visual Studio' / 'Installer' / 'vswhere.exe'
        if vswhere.exists():
            # 调用 vswhere 查找带 x86/x64 VC 工具的最新 VS
            result = subprocess.run(
                [str(vswhere), '-latest', '-products', '*',
                 '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
                 '-property', 'installationPath'],
                capture_output=True, text=True, timeout=30
            )
            path = result.stdout.strip()
            if path:
                return path
    return None


def setup_msvc_env(vs_install, arch):
    """
    调用 vcvars64.bat / vcvars32.bat 并继承环境变量
    arch: 'x64' or 'x86'
    返回 env dict
    """
    if arch == 'x64':
        vcvars = Path(vs_install) / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat'
    else:
        vcvars = Path(vs_install) / 'VC' / 'Auxiliary' / 'Build' / 'vcvars32.bat'

    if not vcvars.exists():
        print(f'[ERROR] vcvars not found: {vcvars}')
        sys.exit(1)

    # 用临时 bat 文件调用 vcvars 并导出环境变量到文件
    # 避免 cmd 引号转义问题
    import tempfile
    env_file = Path(tempfile.gettempdir()) / f'lyscript_env_{arch}.txt'
    # bat 文件必须用 GBK 编码（中文 Windows 默认代码页）
    bat_content = f'@echo off\r\ncall "{vcvars}" >nul 2>&1\r\nset > "{env_file}"\r\n'
    bat_file = Path(tempfile.gettempdir()) / f'lyscript_setup_{arch}.bat'
    bat_file.write_bytes(bat_content.encode('gbk'))

    result = subprocess.run(
        ['cmd', '/c', str(bat_file)],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0 or not env_file.exists():
        print(f'[ERROR] vcvars setup failed:\n{result.stderr}')
        sys.exit(1)

    env = dict(os.environ)
    # 从导出的环境变量文件读取（用 latin-1 避免编码异常）
    with open(env_file, 'r', encoding='latin-1', errors='replace') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if '=' in line:
                k, _, v = line.partition('=')
                env[k] = v
    # 清理临时文件
    try:
        env_file.unlink()
        bat_file.unlink()
    except OSError:
        pass
    return env


def build(arch):
    """编译指定架构"""
    vs_install = find_vs_install()
    if not vs_install:
        print('[ERROR] No Visual Studio with VC++ tools found')
        sys.exit(1)
    print(f'[OK] VS found: {vs_install}')

    print(f'\n=== Building LyScript.dp{"64" if arch=="x64" else "32"} ({arch}) ===')
    env = setup_msvc_env(vs_install, arch)

    # 公共编译参数
    # /O2 速度优化
    # /MT 静态链接 CRT（关键：避免 MSVCR120/MSVCP120 依赖）
    # /LD 编译为 DLL
    # /EHsc C++ 异常模型（毒舌批评要求）
    # /utf-8 源文件编码（毒舌批评要求）
    common_flags = '/O2 /MT /LD /EHsc /utf-8 /D_USRDLL /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS'.split()

    if arch == 'x64':
        arch_flags = ['/D_WIN64']
        out_file = BUILD_DIR / 'LyScript.dp64'
        link_libs = [str(SDK_DIR / 'x64dbg.lib'), str(SDK_DIR / 'x64bridge.lib')]
    else:
        arch_flags = ['/D_WIN32']
        out_file = BUILD_DIR / 'LyScript.dp32'
        link_libs = [str(SDK_DIR / 'x32dbg.lib'), str(SDK_DIR / 'x32bridge.lib')]

    cl_cmd = [
        'cl',
        *common_flags,
        *arch_flags,
        f'/I{SDK_DIR}',
        f'/I{DEPS_DIR}',
        f'/I{PROJ_DIR}',
        f'/Fo{BUILD_DIR}\\',
        f'/Fe{out_file}',
        str(PROJ_DIR / 'pluginmain.cpp'),
        str(DEPS_DIR / 'mongoose.c'),
        str(DEPS_DIR / 'cJSON.c'),
        '/link',
        *link_libs,
        'ws2_32.lib', 'wininet.lib', 'user32.lib', 'advapi32.lib',
    ]

    print(f'cmd: {" ".join(cl_cmd)}\n')
    # 用 shell=True 让 cmd 负责在 PATH 中查找 cl.exe
    # 同时把环境变量传给子进程
    result = subprocess.run(
        ' '.join(f'"{c}"' if ' ' in c else c for c in cl_cmd),
        env=env, shell=True, capture_output=True, text=True
    )
    # cl 输出在 stdout
    if result.stdout:
        print(result.stdout[-3000:])  # 只打印最后 3KB
    if result.stderr:
        print('STDERR:', result.stderr[-2000:])

    if result.returncode != 0:
        print(f'[ERROR] {arch} build failed (exit={result.returncode})')
        sys.exit(1)

    if out_file.exists():
        size = out_file.stat().st_size
        print(f'[OK] {out_file.name} built ({size} bytes)')
        return out_file
    else:
        print(f'[ERROR] {out_file.name} not generated')
        sys.exit(1)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if target not in ('all', 'x64', 'x86'):
        print(f'Usage: {sys.argv[0]} [all|x64|x86]')
        sys.exit(1)

    if target in ('all', 'x64'):
        build('x64')
    if target in ('all', 'x86'):
        build('x86')

    print('\n=== BUILD COMPLETE ===')
    for f in BUILD_DIR.glob('LyScript.dp*'):
        print(f'  {f.name}: {f.stat().st_size} bytes')


if __name__ == '__main__':
    main()
