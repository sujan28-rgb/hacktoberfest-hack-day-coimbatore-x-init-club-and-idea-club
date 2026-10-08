@echo off
setlocal enabledelayedexpansion
title Sentinel Evidence - Setup

echo ============================================
echo   Sentinel Evidence - First-Time Setup
echo ============================================
echo.

:: Check Python
echo [1/6] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ and add to PATH.
    pause & exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo        Found Python %PYVER%

:: Check Node.js
echo [2/6] Checking Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. Install Node.js 18+ and add to PATH.
    pause & exit /b 1
)
for /f %%v in ('node --version') do set NODEVER=%%v
echo        Found Node.js %NODEVER%

:: Check npm
npm --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm not found. Install npm and add to PATH.
    pause & exit /b 1
)
for /f %%v in ('npm --version') do set NPMVER=%%v
echo        Found npm %NPMVER%

:: Create Python virtual environment
echo [3/6] Setting up Python virtual environment...
if not exist ".venv" (
    python -m venv .venv
    echo        Created .venv
) else (
    echo        .venv already exists, reusing.
)

:: Install Python dependencies
echo [4/6] Installing Python dependencies...
call .venv\Scripts\activate.bat
pip install -e ".[test]" --quiet 2>nul
if errorlevel 1 (
    echo [WARNING] pip install had issues, trying again...
    pip install -e ".[test]"
)
echo        Python dependencies installed.

:: Install frontend dependencies
echo [5/6] Installing frontend dependencies...
pushd web
if not exist "node_modules" (
    call npm install --silent 2>nul
    echo        Frontend dependencies installed.
) else (
    echo        node_modules exists, reusing.
)
popd

:: Create .sentinel directory and copy .env
echo [6/6] Preparing local config...
if not exist ".sentinel" mkdir .sentinel
if not exist ".env" (
    copy .env.example .env >nul 2>&1
    echo        Created .env from .env.example
) else (
    echo        .env already exists, keeping.
)

:: Check Ollama availability
echo.
echo --- Ollama Status ---
where ollama >nul 2>&1
if errorlevel 1 (
    echo [INFO] Ollama not found on PATH. AI explanations will be unavailable.
    echo        Install Ollama from https://ollama.com if needed.
) else (
    echo [OK]   Ollama is installed.
    ollama list 2>nul | findstr /i "gemma" >nul
    if errorlevel 1 (
        echo [INFO] No Gemma model found locally. Run: ollama pull gemma3
        echo        AI explanations require a local model.
    ) else (
        echo [OK]   Gemma model available.
    )
)

echo.
echo ============================================
echo   Setup complete!
echo.
echo   Start the application: start.bat
echo   Stop the application:  stop.bat
echo ============================================
pause
