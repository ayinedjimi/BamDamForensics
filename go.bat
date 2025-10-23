@echo off
REM Compilation script for BamDamForensics
REM WinToolsSuite Serie 3 - Forensics Tool #23

echo ========================================
echo Building BamDamForensics
echo ========================================

cl.exe /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE ^
    /Fe:BamDamForensics.exe ^
    BamDamForensics.cpp ^
    /link ^
    comctl32.lib shlwapi.lib advapi32.lib user32.lib gdi32.lib shell32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build successful!
    echo Executable: BamDamForensics.exe
    echo ========================================
    if exist BamDamForensics.obj del BamDamForensics.obj
) else (
    echo.
    echo ========================================
    echo Build FAILED!
    echo ========================================
    exit /b 1
)
