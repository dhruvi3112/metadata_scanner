@echo off
cd /d C:\metadata_scanner_web

call venv\Scripts\activate

start cmd /k python run.py

timeout /t 3 >nul

start chrome http://127.0.0.1:5000
