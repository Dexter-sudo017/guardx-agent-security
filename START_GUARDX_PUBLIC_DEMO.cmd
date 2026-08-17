@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start_public_demo.ps1" -Port 8023
if errorlevel 1 pause
endlocal
