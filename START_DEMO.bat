@echo off
REM ============================================================
REM  API Security Lab — One-Click Demo Launcher
REM  Starts the app in VULNERABLE mode then runs all attacks
REM ============================================================
echo.
echo  ==========================================
echo   API Security Testing Lab — DEMO START
echo  ==========================================
echo.

cd /d "%~dp0"

echo [1/3] Starting server in VULNERABLE mode...
set APP_MODE=vulnerable
start "API Security Lab Server" cmd /k "cd /d %~dp0 && set APP_MODE=vulnerable && python -m uvicorn demo.demo_app:app --port 8000 --reload"

echo [2/3] Waiting 4 seconds for server to start...
timeout /t 4 /nobreak >nul

echo [3/3] Running attack demonstrations...
echo.
python demo/run_attacks.py --url http://localhost:8000

echo.
echo  ==========================================
echo   To see attacks BLOCKED, run:
echo   START_DEMO_SECURED.bat
echo  ==========================================
pause
