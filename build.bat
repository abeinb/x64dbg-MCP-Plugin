@echo off
REM Build LyScript.dp64 and LyScript.dp32 with VS2022 MSVC and /MT static CRT
REM This avoids VS2013 runtime dependency (MSVCR120/MSVCP120)
REM
REM Usage:
REM   build.bat            - build both x64 and x86
REM   build.bat x64        - build x64 only
REM   build.bat x86        - build x86 only
REM
REM 修复毒舌批评:
REM   1. 用 vswhere 动态定位 VS 安装路径，不再硬编码 E:\vis
REM   2. 添加 /EHsc (C++异常模型) 与 /utf-8 (源文件编码)
REM   3. 支持双架构 x64/x86 编译

setlocal enabledelayedexpansion

REM === 参数解析 ===
set TARGET=%1
if "%TARGET%"=="" set TARGET=all

REM === 定位 Visual Studio 安装路径 (用 vswhere，兼容任意安装位置) ===
set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" set VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found, please install Visual Studio Installer
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSINSTALL=%%i
if "%VSINSTALL%"=="" (
    echo [ERROR] No Visual Studio with VC++ tools found
    exit /b 1
)
echo [OK] VS found: %VSINSTALL%

set SDK_DIR=F:\00\tools\x64dbg\release\pluginsdk
set PROJ_DIR=F:\00\LyScript_mcp
set DEPS_DIR=%PROJ_DIR%\deps
set BUILD_DIR=%PROJ_DIR%\build

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM === 编译函数 ===
goto :main

:build_x64
echo.
echo === Building LyScript.dp64 (x64) ===
call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to setup x64 MSVC environment
    exit /b 1
)
cl /O2 /MT /LD /EHsc /utf-8 /D_WIN64 /D_USRDLL /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%SDK_DIR%" /I"%DEPS_DIR%" /I"%PROJ_DIR%" /Fo"%BUILD_DIR%\\" /Fe"%BUILD_DIR%\LyScript.dp64" "%PROJ_DIR%\pluginmain.cpp" "%DEPS_DIR%\mongoose.c" "%DEPS_DIR%\cJSON.c" /link "%SDK_DIR%\x64dbg.lib" "%SDK_DIR%\x64bridge.lib" ws2_32.lib wininet.lib user32.lib advapi32.lib
if errorlevel 1 (
    echo [ERROR] x64 build failed
    exit /b 1
)
if exist "%BUILD_DIR%\LyScript.dp64" (
    echo [OK] LyScript.dp64 built (%~z1 bytes)
) else (
    echo [ERROR] LyScript.dp64 not generated
    exit /b 1
)
exit /b 0

:build_x86
echo.
echo === Building LyScript.dp32 (x86) ===
call "%VSINSTALL%\VC\Auxiliary\Build\vcvars32.bat" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to setup x86 MSVC environment
    exit /b 1
)
cl /O2 /MT /LD /EHsc /utf-8 /D_WIN32 /D_USRDLL /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%SDK_DIR%" /I"%DEPS_DIR%" /I"%PROJ_DIR%" /Fo"%BUILD_DIR%\\" /Fe"%BUILD_DIR%\LyScript.dp32" "%PROJ_DIR%\pluginmain.cpp" "%DEPS_DIR%\mongoose.c" "%DEPS_DIR%\cJSON.c" /link "%SDK_DIR%\x32dbg.lib" "%SDK_DIR%\x32bridge.lib" ws2_32.lib wininet.lib user32.lib advapi32.lib
if errorlevel 1 (
    echo [ERROR] x86 build failed
    exit /b 1
)
if exist "%BUILD_DIR%\LyScript.dp32" (
    echo [OK] LyScript.dp32 built
) else (
    echo [ERROR] LyScript.dp32 not generated
    exit /b 1
)
exit /b 0

:main
if /i "%TARGET%"=="x64" (
    call :build_x64
    if errorlevel 1 exit /b 1
) else if /i "%TARGET%"=="x86" (
    call :build_x86
    if errorlevel 1 exit /b 1
) else (
    call :build_x64
    if errorlevel 1 exit /b 1
    call :build_x86
    if errorlevel 1 exit /b 1
)

echo.
echo === BUILD COMPLETE ===
dir "%BUILD_DIR%\LyScript.dp*"
exit /b 0
