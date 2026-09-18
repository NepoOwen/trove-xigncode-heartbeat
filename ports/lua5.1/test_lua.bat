@echo off
setlocal

REM Test every challenge in ..\challenges.txt using the Lua port
REM and write the detailed results to results.txt in this folder.

set "LUADIR=%~dp0"
set "CHFILE=%LUADIR%..\challenges.txt"
set "OUTFILE=%LUADIR%results.txt"

REM Prefer the bundled luajit.exe in this folder for speed; otherwise fall back
REM to lua53.exe / lua.exe on PATH. The port is pure-Lua and runs on 5.1..5.4.
set "LUA=%LUADIR%luajit.exe"
if not exist "%LUA%" (
    where lua53.exe >nul 2>nul
    if not errorlevel 1 (
        set "LUA=lua53.exe"
    ) else (
        set "LUA=lua.exe"
    )
)

if not exist "%CHFILE%" (
    echo ERROR: challenges.txt not found at "%CHFILE%"
    exit /b 1
)

echo Running Lua challenge tests with %LUA%...
"%LUA%" "%LUADIR%run_tests.lua" > "%OUTFILE%" 2>&1

if %ERRORLEVEL% neq 0 (
    echo ERROR: tests failed. See "%OUTFILE%" for details.
) else (
    echo Done. Results written to "%OUTFILE%"
)

endlocal
