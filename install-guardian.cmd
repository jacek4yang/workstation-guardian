@echo off
REM Double-click this file, then accept the UAC prompt.
REM
REM It installs the Workstation Guardian service and starts it. Everything it does is visible in
REM the output, and it stops on the first failure rather than leaving a half-installed service.

cd /d "%~dp0"

echo.
echo Workstation Guardian - installation
echo ==================================
echo.

if not exist "target\release\guardianctl.exe" (
    echo ERROR: target\release\guardianctl.exe not found.
    echo Build first with:  cargo build --workspace --release
    echo.
    pause
    exit /b 1
)

echo Requesting administrator rights...
powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/k','cd /d \"%~dp0\" && target\release\guardianctl.exe install && echo. && echo === Verification === && target\release\guardianctl.exe doctor' -Verb RunAs"

exit /b 0
