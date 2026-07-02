@echo off
setlocal enabledelayedexpansion

REM Force UTF-8 to avoid encoding issues with Chinese paths/output
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
chcp 65001 >nul 2>&1

echo.
echo ============================================================
echo  LyScript MCP Server Launcher
echo ============================================================
echo.

REM pushd replaces cd /d to support UNC paths
pushd "%~dp0"

set "MISSING=0"
if not exist "main.py"    ( echo [ERROR] main.py not found    & set "MISSING=1" )
if not exist "core.py"    ( echo [ERROR] core.py not found    & set "MISSING=1" )
if not exist "fusion.py"  ( echo [ERROR] fusion.py not found  & set "MISSING=1" )
if not exist "fusion2.py" ( echo [ERROR] fusion2.py not found & set "MISSING=1" )
if not exist "fusion3.py" ( echo [ERROR] fusion3.py not found & set "MISSING=1" )
if "!MISSING!"=="1" (
    echo.
    echo [ERROR] Required files missing in %CD%
    pause
    exit /b 1
)

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not in PATH
    pause
    exit /b 1
)

python -c "import mcp" >nul 2>&1
if !errorlevel! neq 0 (
    echo [WARN] mcp not found. Installing mcp[cli]...
    python -m pip install "mcp[cli]" --no-warn-script-location --timeout 120
    if !errorlevel! neq 0 (
        echo [WARN] Default PyPI failed, trying Tsinghua mirror...
        python -m pip install "mcp[cli]" -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn --no-warn-script-location --timeout 120
    )
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to install mcp[cli]
        echo Run manually: python -m pip install "mcp[cli]"
        pause
        exit /b 1
    )
)

echo [*] Starting LyScript MCP Server...
echo [*] Make sure x64dbg/x32dbg is running (plugin listens on port 8000).
echo [*] Press Ctrl+C to stop.
echo.

python main.py
set EXITCODE=%errorlevel%
echo.
if %EXITCODE% == 0 (
    echo [*] MCP Server stopped normally.
) else (
    echo [ERROR] MCP Server crashed with exit code %EXITCODE%.
    echo Check log above for details.
)
popd
pause
exit /b %EXITCODE%