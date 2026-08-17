@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start_reviewer_demo.ps1" -Port 8021
if errorlevel 1 pause
endlocal
