@echo off
REM Build a redistributable archive of Workstation Guardian.
REM
REM Produces dist\workstation-guardian-<version>-x64.zip containing the tray application, the
REM diagnostic CLI, the session helper and the documentation. The archive is what gets attached
REM to a GitHub release; nothing in it is machine-specific.

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

REM Binaries. guardian-ui.exe is the program; the rest are helpers an operator may want.
copy /y target\release\guardian-ui.exe      "%DIST%\" >nul || exit /b 1
copy /y target\release\guardianctl.exe      "%DIST%\" >nul || exit /b 1
copy /y target\release\guardian-session.exe "%DIST%\" >nul || exit /b 1

REM The console harness is included because it is genuinely useful for observing the runtime
REM without a GUI, and because it is a few hundred kilobytes.
copy /y target\release\guardian-service.exe "%DIST%\" >nul || exit /b 1

REM Documentation
copy /y README.md "%DIST%\" >nul
mkdir "%DIST%\docs" 2>nul
xcopy /y /q docs\*.md "%DIST%\docs\" >nul

REM A short note beside the binaries, because someone extracting a zip should not have to find the
REM README first.
> "%DIST%\README-FIRST.txt" echo Workstation Guardian %VERSION%
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo There is nothing to install. Guardian is a tray application:
>>"%DIST%\README-FIRST.txt" echo it registers no Windows service and creates no scheduled task.
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo To run it, double-click guardian-ui.exe and accept the UAC
>>"%DIST%\README-FIRST.txt" echo prompt. Administrator rights are needed to apply the Windows
>>"%DIST%\README-FIRST.txt" echo Update policy.
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo The tray icon stays until you close it. Closing the window hides
>>"%DIST%\README-FIRST.txt" echo it to the tray; only "Exit Guardian" stops protection.
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo To verify:
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo     guardianctl doctor
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo Optional: copy a shortcut to guardian-session.exe into your
>>"%DIST%\README-FIRST.txt" echo Startup folder (shell:startup) so the shutdown blocker runs in
>>"%DIST%\README-FIRST.txt" echo your interactive session.
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo To remove Guardian:
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo     1. Exit Guardian from the tray menu.
>>"%DIST%\README-FIRST.txt" echo     2. guardianctl restore-policy    (from an elevated prompt)
>>"%DIST%\README-FIRST.txt" echo     3. Delete this folder.
>>"%DIST%\README-FIRST.txt" echo.
>>"%DIST%\README-FIRST.txt" echo restore-policy restores only the policy values Guardian itself
>>"%DIST%\README-FIRST.txt" echo set. It never reboots the machine.

REM Archive
powershell -NoProfile -Command "Compress-Archive -Path '%DIST%' -DestinationPath 'dist\workstation-guardian-%VERSION%-x64.zip' -Force" || exit /b 1

echo.
echo Built dist\workstation-guardian-%VERSION%-x64.zip
dir /b dist\*.zip
endlocal
