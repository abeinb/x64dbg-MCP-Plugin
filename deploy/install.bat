@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo  LyScript MCP Server Installer (x32 + x64)
echo ============================================================
echo.

echo [1/4] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo   [ERROR] Python not installed or not in PATH.
    echo   Install Python 3.11+ from https://www.python.org/downloads/
    goto :error_end
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo   [OK] Python %PYVER% found.

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if errorlevel 1 (
    echo   [ERROR] Python 3.11+ required, got %PYVER%
    goto :error_end
)
echo   [OK] Python version meets 3.11+ requirement.

echo.
echo [2/4] Installing MCP package...
python -c "import mcp" >nul 2>&1
if !errorlevel! == 0 (
    echo   [OK] mcp already installed.
    goto :step3
)
echo   Installing mcp[cli] via python -m pip ...
python -m pip install "mcp[cli]" --no-warn-script-location --timeout 120
if !errorlevel! == 0 (
    echo   [OK] mcp[cli] installed.
    goto :step3
)
echo   [WARN] Default PyPI failed, trying Tsinghua mirror...
python -m pip install "mcp[cli]" -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn --no-warn-script-location --timeout 120
if !errorlevel! == 0 (
    echo   [OK] mcp[cli] installed from mirror.
    goto :step3
)
echo   [ERROR] Failed to install mcp[cli].
echo   Try manually: python -m pip install "mcp[cli]"
goto :error_end

:step3
echo.
echo [3/4] Locating x64dbg plugins directory...
set "X64DBG_PLUGINS="
set "X32DBG_PLUGINS="
for %%d in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist "%%d:\x64dbg\x64\plugins\" set "X64DBG_PLUGINS=%%d:\x64dbg\x64\plugins"
    if exist "%%d:\x64dbg\x32\plugins\" set "X32DBG_PLUGINS=%%d:\x64dbg\x32\plugins"
)

if "!X64DBG_PLUGINS!"=="" (
    if "!X32DBG_PLUGINS!"=="" (
        echo   Could not auto-detect x64dbg installation.
        set /p X64DBG_PLUGINS="  Enter x64dbg plugins path (e.g. C:\x64dbg\x64\plugins): "
    )
)

echo.
echo [4/4] Copying files...
if not "!X64DBG_PLUGINS!"=="" (
    if exist "!X64DBG_PLUGINS!\" (
        echo   Copying LyScript.dp64 to !X64DBG_PLUGINS!...
        copy /Y "LyScript.dp64" "!X64DBG_PLUGINS!\LyScript.dp64" >nul 2>&1
        if !errorlevel! neq 0 (
            echo   [ERROR] Failed to copy LyScript.dp64
            echo   Make sure x64dbg is closed.
        ) else (
            echo   [OK] LyScript.dp64 installed.
        )
    )
)

if not "!X32DBG_PLUGINS!"=="" (
    if exist "!X32DBG_PLUGINS!\" (
        echo   Copying LyScript.dp32 to !X32DBG_PLUGINS!...
        copy /Y "LyScript.dp32" "!X32DBG_PLUGINS!\LyScript.dp32" >nul 2>&1
        if !errorlevel! neq 0 (
            echo   [ERROR] Failed to copy LyScript.dp32
            echo   Make sure x32dbg is closed.
        ) else (
            echo   [OK] LyScript.dp32 installed.
        )
    )
)

set "X64DBG_ROOT="
if not "!X64DBG_PLUGINS!"=="" (
    for %%i in ("!X64DBG_PLUGINS!\..\..") do set "X64DBG_ROOT=%%~fi"
) else if not "!X32DBG_PLUGINS!"=="" (
    for %%i in ("!X32DBG_PLUGINS!\..\..") do set "X64DBG_ROOT=%%~fi"
)
if "!X64DBG_ROOT!"=="" set "X64DBG_ROOT=C:\x64dbg"

set "MCP_DIR=!X64DBG_ROOT!\LyScript_mcp"
if not exist "!MCP_DIR!\" mkdir "!MCP_DIR!"
echo   Copying MCP server files to !MCP_DIR!...
copy /Y "main.py"        "!MCP_DIR!\main.py"        >nul 2>&1
copy /Y "core.py"        "!MCP_DIR!\core.py"        >nul 2>&1
copy /Y "fusion.py"      "!MCP_DIR!\fusion.py"      >nul 2>&1
copy /Y "fusion2.py"     "!MCP_DIR!\fusion2.py"     >nul 2>&1
copy /Y "fusion3.py"     "!MCP_DIR!\fusion3.py"     >nul 2>&1
copy /Y "start_mcp.bat"  "!MCP_DIR!\start_mcp.bat"  >nul 2>&1
echo   [OK] MCP server files copied.

echo.
echo ============================================================
echo  Installation Complete!
echo ============================================================
echo.
if not "!X64DBG_PLUGINS!"=="" echo   x64 Plugin: !X64DBG_PLUGINS!\LyScript.dp64
if not "!X32DBG_PLUGINS!"=="" echo   x32 Plugin: !X32DBG_PLUGINS!\LyScript.dp32
echo   MCP Server: !MCP_DIR!
echo.
echo  Next steps:
echo   1. Start x64dbg or x32dbg (plugin auto-starts HTTP on port 8000)
echo   2. Run start_mcp.bat in !MCP_DIR!
echo.
goto :success_end

:error_end
echo.
echo ============================================================
echo  Installation FAILED.
echo ============================================================
echo.
pause
exit /b 1

:success_end
pause
exit /b 0