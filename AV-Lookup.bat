@echo off
title AV-Lookup v2.0
REM Launcher: runs AV-Lookup.ps1 from the same folder. Extra args (e.g. -Json) are passed through.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0AV-Lookup.ps1" -NoPause %*
echo.
pause
