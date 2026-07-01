@echo off
REM ============================================================
REM  LyScript MCP Server Installer for x64dbg
REM  Run this script on the machine where x64dbg is installed
REM ============================================================
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo  LyScript MCP Server Installer
echo ============================================================
echo.

REM --- Step 1: Check Python ---
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo   [ERROR] Python is not installed or not in PATH.
    echo   Please install Python 3.11 or later from https://www.python.org/downloads/
    echo   Make sure to check "Add Python to PATH" during installation.
    goto :error_end
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo   [OK] Python %PYVER% found.

REM --- Step 2: Install mcp package ---
echo.
echo [2/4] Installing MCP Python package...

REM 修复闪退Bug: 用 python -m pip 替代裸 pip（pip 可能不在 PATH）
REM 先检查 mcp 是否已安装
python -c "import mcp" >nul 2>&1
if !errorlevel! == 0 (
    echo   [OK] mcp package already installed.
    goto :step3
)

echo   Installing mcp package via python -m pip ...
REM 第一次尝试：默认 PyPI 源，超时 120 秒
python -m pip install mcp --no-warn-script-location --timeout 120
if !errorlevel! == 0 (
    echo   [OK] mcp package installed from default PyPI.
    goto :step3
)

echo   [WARN] Default PyPI failed, trying Tsinghua mirror...
REM 第二次尝试：清华镜像源（国内加速）
python -m pip install mcp -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn --no-warn-script-location --timeout 120
if !errorlevel! == 0 (
    echo   [OK] mcp package installed from Tsinghua mirror.
    goto :step3
)

echo   [ERROR] Failed to install mcp package from both sources.
echo   Please check network connection and try manually:
echo     python -m pip install mcp
goto :error_end

:step3
REM --- Step 3: Locate x64dbg plugins directory ---
echo.
echo [3/4] Locating x64dbg plugins directory...

REM Default common paths
set "X64DBG_PLUGINS="
if exist "C:\x64dbg\x64\plugins\" set "X64DBG_PLUGINS=C:\x64dbg\x64\plugins"
if exist "D:\x64dbg\x64\plugins\" set "X64DBG_PLUGINS=D:\x64dbg\x64\plugins"
if exist "E:\x64dbg\x64\plugins\" set "X64DBG_PLUGINS=E:\x64dbg\x64\plugins"

if "!X64DBG_PLUGINS!"=="" (
    echo   Could not auto-detect x64dbg plugins directory.
    set /p X64DBG_PLUGINS="  Please enter x64dbg plugins path (e.g. C:\x64dbg\x64\plugins): "
)

if not exist "!X64DBG_PLUGINS!\" (
    echo   [ERROR] Directory does not exist: !X64DBG_PLUGINS!
    goto :error_end
)
echo   [OK] x64dbg plugins: !X64DBG_PLUGINS!

REM --- Step 4: Copy files ---
echo.
echo [4/4] Copying files...

REM Copy plugin to x64dbg
echo   Copying LyScript.dp64 to x64dbg plugins...
copy /Y "LyScript.dp64" "!X64DBG_PLUGINS!\LyScript.dp64" >nul 2>&1
if !errorlevel! neq 0 (
    echo   [ERROR] Failed to copy LyScript.dp64
    echo   Make sure x64dbg is closed ^(file may be locked^).
    goto :error_end
)
echo   [OK] Plugin installed.

REM Create MCP server working directory
set "MCP_DIR=!X64DBG_PLUGINS!\..\..\LyScript_mcp"
if not exist "!MCP_DIR!\" mkdir "!MCP_DIR!"

echo   Copying MCP server files...
copy /Y "main.py" "!MCP_DIR!\main.py" >nul 2>&1
if !errorlevel! neq 0 (
    echo   [ERROR] Failed to copy main.py
    goto :error_end
)
copy /Y "core.py" "!MCP_DIR!\core.py" >nul 2>&1
if !errorlevel! neq 0 (
    echo   [ERROR] Failed to copy core.py
    goto :error_end
)
copy /Y "start_mcp.bat" "!MCP_DIR!\start_mcp.bat" >nul 2>&1
if !errorlevel! neq 0 (
    echo   [ERROR] Failed to copy start_mcp.bat
    goto :error_end
)
echo   [OK] MCP server files copied to: !MCP_DIR!

REM --- Done ---
echo.
echo ============================================================
echo  Installation Complete!
echo ============================================================
echo.
echo  Plugin location:  !X64DBG_PLUGINS!\LyScript.dp64
echo  MCP server dir:   !MCP_DIR!
echo.
echo  Next steps:
echo   1. Start x64dbg (the plugin auto-starts HTTP server on port 8000)
echo   2. Run start_mcp.bat to start the MCP server
echo   3. Configure your MCP client to connect to this machine
echo.
goto :success_end

:error_end
echo.
echo ============================================================
echo  Installation FAILED. See errors above.
echo ============================================================
echo.

:success_end
REM 修复闪退Bug: 无条件 pause，确保用户能看到结果
pause
exit /b 0
