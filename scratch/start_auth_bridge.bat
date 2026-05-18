@echo off
title Active Directory Auth Bridge
echo Starting Active Directory Auth Bridge on port 8888...
powershell -Command "Start-Process python -ArgumentList 'c:\APPS\KeepassViewer\scratch\auth_helper.py' -WindowStyle Hidden"
echo Auth Bridge initiated in hidden background mode!
pause
