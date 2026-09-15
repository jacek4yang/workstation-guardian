@echo off
REM Build a redistributable archive of Workstation Guardian.
REM
REM Produces dist\workstation-guardian-<version>-x64.zip containing the three service-side
REM binaries, the tray UI, and the documentation. The archive is what gets attached to a GitHub
REM release; nothing in it is machine-specific.

setlocal enabledelayedexpansion

cd /d "%~dp0.."

for /f "tokens=2 delims== " %%v in ('findstr /r "^version" Cargo.toml') do (
    set VERSION=%%~v
    goto :version_found
)
:version_found
set VERSION=%VERSION:"=%
if "%VERSION%"=="" set VERSION=0.1.0

echo Building Workstation Guardian %VERSION% ...
cargo build --workspace --release || exit /b 1

set DIST=dist\workstation-guardian-%VERSION%-x64
if exist dist rmdir /s /q dist
mkdir "%DIST%" || exit /b 1

REM Binaries
copy /y target\release\guardian-service.exe "%DIST%\" >nul || exit /b 1
copy /y target\release\guardian-session.exe "%DIST%\" >nul || exit /b 1
copy /y target\release\guardian-ui.exe      "%DIST%\" >nul || exit /b 1
copy /y target\release\guardianctl.exe      "%DIST%\" >nul || exit /b 1

REM Documentation
copy /y README.md "%DIST%\" >nul
mkdir "%DIST%\docs" 2>nul
xcopy /y /q docs\*.md "%DIST%\docs\" >nul

REM A short install note beside the binaries, because someone extracting a zip should not have to
REM find the README first.
> "%DIST%\INSTALL.txt" echo Workstation Guardian %VERSION%
>>"%DIST%\INSTALL.txt" echo.
>>"%DIST%\INSTALL.txt" echo Install, from an ELEVATED prompt in this folder:
>>"%DIST%\INSTALL.txt" echo.
>>"%DIST%\INSTALL.txt" echo     guardianctl install
>>"%DIST%\INSTALL.txt" echo.
>>"%DIST%\INSTALL.txt" echo Verify:
>>"%DIST%\INSTALL.txt" echo.
>>"%DIST%\INSTALL.txt" echo     guardianctl doctor
>>"%DIST%\INSTALL.txt" echo.
>>"%DIST%\INSTALL.txt" echo Optional: copy guardian-session.exe to your Startup folder so the
>>"%DIST%\INSTALL.txt" echo shutdown blocker runs in your interactive session.
>>"%DIST%\INSTALL.txt" echo.
>>"%DIST%\INSTALL.txt" echo Uninstall:
>>"%DIST%\INSTALL.txt" echo.
>>"%DIST%\INSTALL.txt" echo     guardianctl uninstall
>>"%DIST%\INSTALL.txt" echo.
>>"%DIST%\INSTALL.txt" echo Uninstall restores only the update policy values Guardian itself set.
>>"%DIST%\INSTALL.txt" echo It never reboots the machine.

REM Archive
powershell -NoProfile -Command "Compress-Archive -Path '%DIST%' -DestinationPath 'dist\workstation-guardian-%VERSION%-x64.zip' -Force" || exit /b 1

echo.
echo Built dist\workstation-guardian-%VERSION%-x64.zip
dir /b dist\*.zip
endlocal
