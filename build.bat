@echo off
REM Build LyScript.dp64 with VS2022 MSVC 14.50 and /MT static CRT
REM This avoids VS2013 runtime dependency (MSVCR120/MSVCP120)

call "E:\vis\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to setup MSVC environment
    exit /b 1
)
echo [OK] MSVC environment ready

echo.
echo === Starting compilation ===
cl /O2 /MT /LD /D_WIN64 /D_USRDLL /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"F:\00\tools\x64dbg\release\pluginsdk" /I"F:\00\LyScript_mcp\deps" /I"F:\00\LyScript_mcp" /Fo"F:\00\LyScript_mcp\build\\" /Fe"F:\00\LyScript_mcp\build\LyScript.dp64" "F:\00\LyScript_mcp\pluginmain.cpp" "F:\00\LyScript_mcp\deps\mongoose.c" "F:\00\LyScript_mcp\deps\cJSON.c" /link "F:\00\tools\x64dbg\release\pluginsdk\x64dbg.lib" "F:\00\tools\x64dbg\release\pluginsdk\x64bridge.lib" ws2_32.lib wininet.lib user32.lib advapi32.lib

if exist "F:\00\LyScript_mcp\build\LyScript.dp64" (
    echo.
    echo === BUILD SUCCESS ===
    dir "F:\00\LyScript_mcp\build\LyScript.dp64"
    exit /b 0
) else (
    echo.
    echo === BUILD FAILED ===
    exit /b 1
)