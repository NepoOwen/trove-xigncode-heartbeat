@echo off
setlocal

REM Test every challenge in ..\challenges.txt using the AutoHotkey port
REM and write the detailed results to results.txt in this folder.

set "AHKDIR=%~dp0"
set "CHFILE=%AHKDIR%..\challenges.txt"
set "OUTFILE=%AHKDIR%results.txt"

REM Locate the AutoHotkey v1.1 interpreter (Unicode 64-bit preferred).
set "AHK="
for %%P in (
    "C:\Program Files\AutoHotkey\AutoHotkeyU64.exe"
    "C:\Program Files\AutoHotkey\AutoHotkey.exe"
    "C:\Program Files (x86)\AutoHotkey\AutoHotkeyU64.exe"
    "C:\Program Files (x86)\AutoHotkey\AutoHotkey.exe"
) do (
    if not defined AHK if exist %%P set "AHK=%%~P"
)
if not defined AHK (
    where AutoHotkeyU64.exe >nul 2>nul && set "AHK=AutoHotkeyU64.exe"
)
if not defined AHK (
    where AutoHotkey.exe >nul 2>nul && set "AHK=AutoHotkey.exe"
)

if not defined AHK (
    echo ERROR: AutoHotkey v1.1 interpreter not found.
    exit /b 1
)

if not exist "%CHFILE%" (
    echo ERROR: challenges.txt not found at "%CHFILE%"
    exit /b 1
)

echo Running AHK challenge tests with %AHK%...
"%AHK%" "%AHKDIR%run_tests.ahk"

if %ERRORLEVEL% neq 0 (
    echo ERROR: tests failed. See "%OUTFILE%" for details.
) else (
    echo Done. Results written to "%OUTFILE%"
)

endlocal
