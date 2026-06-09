@echo off
REM Launch the Windows Driver policy manager elevated.
set "PS1=%~dp0manage.ps1"
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','\"%PS1%\"'"
