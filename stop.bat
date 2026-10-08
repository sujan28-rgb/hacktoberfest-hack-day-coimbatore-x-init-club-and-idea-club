@echo off
title Sentinel Evidence - Stopping

echo ============================================
echo   Sentinel Evidence - Stopping Servers
echo ============================================
echo.

:: Kill uvicorn (backend)
echo [1/2] Stopping backend (uvicorn)...
for /f "tokens=2" %%p in ('netstat -ano ^| findstr ":8000 " ^| findstr "LISTENING"') do (
    taskkill /PID %%p /F >nul 2>&1
)
echo        Backend stopped.

:: Kill vite (frontend)
echo [2/2] Stopping frontend (vite on port 5173)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":5173 " ^| findstr "LISTENING"') do (
    taskkill /PID %%p /F >nul 2>&1
)
echo        Frontend stopped.

echo.
echo ============================================
echo   All Sentinel Evidence servers stopped.
echo ============================================
pause
