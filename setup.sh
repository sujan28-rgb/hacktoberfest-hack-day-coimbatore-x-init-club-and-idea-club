#!/usr/bin/env bash
set -e
echo "============================================"
echo "  Sentinel Evidence - First-Time Setup"
echo "============================================"
echo ""

# Check Python
echo "[1/6] Checking Python..."
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 not found. Install Python 3.10+ first."; exit 1
fi
echo "       Found $(python3 --version)"

# Check Node.js
echo "[2/6] Checking Node.js..."
if ! command -v node &>/dev/null; then
    echo "[ERROR] Node.js not found. Install Node.js 18+ first."; exit 1
fi
echo "       Found Node.js $(node --version)"

# Check npm
if ! command -v npm &>/dev/null; then
    echo "[ERROR] npm not found."; exit 1
fi
echo "       Found npm $(npm --version)"

# Create Python virtual environment
echo "[3/6] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "       Created .venv"
else
    echo "       .venv already exists, reusing."
fi

# Install Python dependencies
echo "[4/6] Installing Python dependencies..."
source .venv/bin/activate
pip install -e ".[test]" --quiet 2>/dev/null || pip install -e ".[test]"
echo "       Python dependencies installed."

# Install frontend dependencies
echo "[5/6] Installing frontend dependencies..."
cd web
if [ ! -d "node_modules" ]; then
    npm install --silent 2>/dev/null
    echo "       Frontend dependencies installed."
else
    echo "       node_modules exists, reusing."
fi
cd ..

# Create config
echo "[6/6] Preparing local config..."
mkdir -p .sentinel
if [ ! -f ".env" ]; then
    cp .env.example .env 2>/dev/null || true
    echo "       Created .env from .env.example"
else
    echo "       .env already exists, keeping."
fi

# Check Ollama
echo ""
echo "--- Ollama Status ---"
if ! command -v ollama &>/dev/null; then
    echo "[INFO] Ollama not found. AI explanations will be unavailable."
else
    echo "[OK]   Ollama is installed."
    if ollama list 2>/dev/null | grep -iq "gemma"; then
        echo "[OK]   Gemma model available."
    else
        echo "[INFO] No Gemma model found. Run: ollama pull gemma3"
    fi
fi

echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  Start: ./start.sh"
echo "  Stop:  ./stop.sh"
echo "============================================"
