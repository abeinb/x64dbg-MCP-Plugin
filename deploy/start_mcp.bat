@echo off
REM ============================================================
REM  LyScript MCP Server Launcher
REM  Starts the MCP server (port 8001) which connects to
REM  the x64dbg LyScript plugin (port 8000)
REM ============================================================
REM 修复闪退Bug: 需要 enabledelayedexpansion 才能用 !errorlevel!
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo  LyScript MCP Server Launcher
echo ============================================================
echo.

REM Change to script directory
cd /d "%~dp0"

REM Verify files exist
if not exist "main.py" (
    echo [ERROR] main.py not found in current directory.
    echo Expected location: %CD%
    pause
    exit /b 1
)
if not exist "core.py" (
    echo [ERROR] core.py not found in current directory.
    pause
    exit /b 1
)

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH.
    pause
    exit /b 1
)

REM Check if mcp package is installed
python -c "import mcp" >nul 2>&1
if !errorlevel! neq 0 (
    echo [WARN] mcp package not found. Installing...
    REM 修复闪退Bug: 用 python -m pip 替代裸 pip，加清华镜像 fallback
    python -m pip install mcp --no-warn-script-location --timeout 120
    if !errorlevel! neq 0 (
        echo [WARN] Default PyPI failed, trying Tsinghua mirror...
        python -m pip install mcp -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn --no-warn-script-location --timeout 120
    )
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to install mcp package.
        echo Please run manually: python -m pip install mcp
        pause
        exit /b 1
    )
)

REM Configuration (defaults work for same-machine deployment)
REM MCP server listens on 0.0.0.0:8001 (accessible from other machines)
REM LyScript plugin should be on 127.0.0.1:8000 (same machine)
REM Override with environment variables if needed:
REM   set LYSCRIPT_MCP_HOST=0.0.0.0
REM   set LYSCRIPT_MCP_PORT=8001
REM   set LYSCRIPT_DBG_HOST=127.0.0.1
REM   set LYSCRIPT_DBG_PORT=8000

echo [*] Starting LyScript MCP Server...
echo [*] MCP server:    0.0.0.0:8001 (accessible from network)
echo [*] x64dbg plugin: 127.0.0.1:8000 (local x64dbg)
echo [*] Press Ctrl+C to stop.
echo.

python main.py

echo.
echo [*] MCP Server stopped.
pause
exit /b 0
