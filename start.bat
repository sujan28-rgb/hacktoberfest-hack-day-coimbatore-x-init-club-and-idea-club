@echo off
setlocal enabledelayedexpansion
title Sentinel Evidence - Running

echo ============================================
echo   Sentinel Evidence - Starting
echo ============================================
echo.

:: Check setup was done
if not exist ".venv" (
    echo [ERROR] Virtual environment not found. Run setup.bat first.
    pause & exit /b 1
)
if not exist "web\node_modules" (
    echo [ERROR] Frontend dependencies not found. Run setup.bat first.
    pause & exit /b 1
)

:: Check ports
netstat -ano | findstr ":8000 " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [WARNING] Port 8000 is already in use.
    echo          Run stop.bat first, or check for conflicting services.
    pause & exit /b 1
)
netstat -ano | findstr ":5173 " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [WARNING] Port 5173 is already in use.
    echo          Run stop.bat first, or check for conflicting services.
    pause & exit /b 1
)

:: Create .sentinel dir if missing
if not exist ".sentinel" mkdir .sentinel

:: Start Backend
echo [1/3] Starting FastAPI backend on http://localhost:8000 ...
call .venv\Scripts\activate.bat
start /b "SentinelBackend" cmd /c ".venv\Scripts\python.exe -m uvicorn sentinel_evidence.api.app:app --host 127.0.0.1 --port 8000 --log-level info > .sentinel\backend.log 2>&1"

:: Wait for backend to be ready
echo        Waiting for backend...
set RETRIES=0
:wait_backend
timeout /t 1 /nobreak >nul
set /a RETRIES+=1
curl -s http://127.0.0.1:8000/health >nul 2>&1
if not errorlevel 1 goto backend_ready
if %RETRIES% lss 15 goto wait_backend
echo [WARNING] Backend may not have started. Check .sentinel\backend.log
goto start_frontend

:backend_ready
echo        Backend is running.

:start_frontend
:: Start Frontend
echo [2/3] Starting React frontend on http://localhost:5173 ...
pushd web
start /b "SentinelFrontend" cmd /c "npm run dev > ..\.sentinel\frontend.log 2>&1"
popd

:: Wait for frontend
set RETRIES=0
:wait_frontend
timeout /t 1 /nobreak >nul
set /a RETRIES+=1
netstat -ano | findstr ":5173 " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 goto frontend_ready
if %RETRIES% lss 15 goto wait_frontend
echo [WARNING] Frontend may not have started. Check .sentinel\frontend.log

:frontend_ready
echo        Frontend is running.

:: Ollama status
echo.
echo --- Ollama Status ---
where ollama >nul 2>&1
if errorlevel 1 (
    echo [INFO] Ollama not available. Running in deterministic-only mode.
) else (
    ollama list 2>nul | findstr /i "gemma" >nul
    if errorlevel 1 (
        echo [INFO] No Gemma model found. AI explanations unavailable.
    ) else (
        echo [OK]   Ollama + Gemma available for AI explanations.
    )
)

:: Open browser
echo.
echo [3/3] Opening application in browser...
timeout /t 2 /nobreak >nul
start "" http://localhost:5173

echo.
echo ============================================
echo   Sentinel Evidence is running!
echo.
echo   Frontend:  http://localhost:5173
echo   Backend:   http://localhost:8000
echo   API Docs:  http://localhost:8000/docs
echo   Health:    http://localhost:8000/health
echo.
echo   Logs: .sentinel\backend.log
echo         .sentinel\frontend.log
echo.
echo   To stop: run stop.bat
echo ============================================
echo.
echo Press any key to keep this window open...
pause >nul
