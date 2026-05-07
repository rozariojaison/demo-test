@echo off
REM ============================================================
REM  API Security Lab — One-Click Secured Mode Demo
REM  Shows all 5 attacks BLOCKED by the hardened API
REM ============================================================
echo.
echo  ==========================================
echo   API Security Testing Lab — SECURED MODE
echo  ==========================================
echo.

cd /d "%~dp0"

echo [1/3] Starting server in SECURED mode...
set APP_MODE=secured
start "API Security Lab Server (Secured)" cmd /k "cd /d %~dp0 && set APP_MODE=secured && python -m uvicorn demo.demo_app:app --port 8000 --reload"

echo [2/3] Waiting 4 seconds for server to start...
timeout /t 4 /nobreak >nul

echo [3/3] Running attack demonstrations (all should be BLOCKED)...
echo.
python demo/run_attacks.py --url http://localhost:8000

echo.
echo  ==========================================
echo   All attacks should show GREEN (blocked).
echo  ==========================================
pause
