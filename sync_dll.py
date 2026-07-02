#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""同步 LyScript.dp64/dp32 到 deploy 目录和 Trae CN 配置目录"""
import shutil
from pathlib import Path

BUILD = Path(r'F:\00\LyScript_mcp\build')
DEPLOY = Path(r'F:\00\LyScript_mcp\deploy')
TRAE_DIRS = [
    Path(r'C:\Users\Administrator\AppData\Roaming\TRAE SOLO CN\User\lyscript_mcp'),
    Path(r'C:\Users\Administrator\AppData\Roaming\Trae CN\User\lyscript_mcp'),
]

FILES = ['LyScript.dp64', 'LyScript.dp32']

# 同步到 deploy
for f in FILES:
    src = BUILD / f
    dst = DEPLOY / f
    if src.exists():
        shutil.copy2(src, dst)
        print(f'[OK] {f} -> deploy/ ({src.stat().st_size} bytes)')

# 同步到 Trae CN 目录
for d in TRAE_DIRS:
    if d.exists():
        for f in FILES:
            src = BUILD / f
            dst = d / f
            if src.exists():
                shutil.copy2(src, dst)
                print(f'[OK] {f} -> {d}')
    else:
        print(f'[SKIP] not exist: {d}')

# 列出 deploy 目录
print('\ndeploy dir contents:')
for f in sorted(DEPLOY.glob('LyScript.dp*')):
    print(f'  {f.name}: {f.stat().st_size} bytes')
