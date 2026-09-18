@echo off
setlocal

REM Test every A2 challenge in ..\challenges.txt using the Python port
REM and write the detailed results to results.txt in this folder.

set "PYDIR=%~dp0"
set "CHFILE=%PYDIR%..\challenges.txt"
set "OUTFILE=%PYDIR%results.txt"

if not exist "%CHFILE%" (
    echo ERROR: challenges.txt not found at "%CHFILE%"
    exit /b 1
)

echo Running Python challenge tests...
python "%PYDIR%run_tests.py" > "%OUTFILE%" 2>&1

if %ERRORLEVEL% neq 0 (
    echo ERROR: tests failed. See "%OUTFILE%" for details.
) else (
    echo Done. Results written to "%OUTFILE%"
)

endlocal
