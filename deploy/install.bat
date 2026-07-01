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
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo   [OK] Python %PYVER% found.

REM --- Step 2: Install mcp package ---
echo.
echo [2/4] Installing MCP Python package...
python -c "import mcp" >nul 2>&1
if errorlevel 1 (
    echo   Installing mcp package...
    echo   [*] Using Tsinghua mirror to speed up download...
    REM 修复闪退Bug: pip 在 Windows 上是 pip.bat，bat 脚本里调用必须加 call
    REM 否则控制权转移给 pip.bat 后不返回，当前脚本直接退出（这就是闪退根因）
    REM 同时使用国内清华镜像加速，避免虚拟机访问 PyPI 超时
    call pip install mcp -i https://pypi.tuna.tsinghua.edu.cn/simple
    if errorlevel 1 (
        echo.
        echo   [ERROR] Failed to install mcp package.
        echo   Try manually: pip install mcp -i https://pypi.tuna.tsinghua.edu.cn/simple
        echo.
        pause
        exit /b 1
    )
    echo   [OK] mcp package installed.
) else (
    echo   [OK] mcp package already installed.
)

REM --- Step 3: Locate x64dbg plugins directory ---
echo.
echo [3/4] Locating x64dbg plugins directory...

REM Default common paths
set "X64DBG_PLUGINS="
if exist "C:\x64dbg\x64\plugins\" set "X64DBG_PLUGINS=C:\x64dbg\x64\plugins"
if exist "D:\x64dbg\x64\plugins\" set "X64DBG_PLUGINS=D:\x64dbg\x64\plugins"

if "%X64DBG_PLUGINS%"=="" (
    echo   Could not auto-detect x64dbg plugins directory.
    set /p X64DBG_PLUGINS="  Please enter x64dbg plugins path (e.g. C:\x64dbg\x64\plugins): "
)

if not exist "%X64DBG_PLUGINS%\" (
    echo   [ERROR] Directory does not exist: %X64DBG_PLUGINS%
    pause
    exit /b 1
)
echo   [OK] x64dbg plugins: %X64DBG_PLUGINS%

REM --- Step 4: Copy files ---
echo.
echo [4/4] Copying files...

REM Copy plugin to x64dbg
echo   Copying LyScript.dp64 to x64dbg plugins...
copy /Y "LyScript.dp64" "%X64DBG_PLUGINS%\LyScript.dp64" >nul 2>&1
if errorlevel 1 (
    echo   [ERROR] Failed to copy LyScript.dp64
    echo   Make sure x64dbg is closed (file may be locked).
    pause
    exit /b 1
)
echo   [OK] Plugin installed.

REM Create MCP server working directory
set "MCP_DIR=%X64DBG_PLUGINS%\..\..\LyScript_mcp"
if not exist "%MCP_DIR%\" mkdir "%MCP_DIR%"

echo   Copying MCP server files...
copy /Y "main.py" "%MCP_DIR%\main.py" >nul 2>&1
copy /Y "core.py" "%MCP_DIR%\core.py" >nul 2>&1
copy /Y "start_mcp.bat" "%MCP_DIR%\start_mcp.bat" >nul 2>&1
if errorlevel 1 (
    echo   [ERROR] Failed to copy MCP server files.
    pause
    exit /b 1
)
echo   [OK] MCP server files copied to: %MCP_DIR%

REM --- Done ---
echo.
echo ============================================================
echo  Installation Complete!
echo ============================================================
echo.
echo  Plugin location:  %X64DBG_PLUGINS%\LyScript.dp64
echo  MCP server dir:   %MCP_DIR%
echo.
echo  Next steps:
echo   1. Start x64dbg (the plugin auto-starts HTTP server on port 8000)
echo   2. Run start_mcp.bat to start the MCP server (port 8001)
echo   3. Configure your MCP client to connect to this machine port 8001
echo.
pause
exit /b 0
