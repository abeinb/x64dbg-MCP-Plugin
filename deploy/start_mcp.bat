@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo  LyScript MCP Server Launcher
echo ============================================================
echo.

cd /d "%~dp0"

if not exist "main.py" (
    echo [ERROR] main.py not found in %CD%
    pause
    exit /b 1
)
if not exist "core.py" (
    echo [ERROR] core.py not found in %CD%
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
echo [*] Press Ctrl+C to stop.
echo.

python main.py

echo.
echo [*] MCP Server stopped.
pause
exit /b 0