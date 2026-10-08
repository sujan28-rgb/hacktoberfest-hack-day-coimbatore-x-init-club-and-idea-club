#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo "  Sentinel Evidence - Starting"
echo "============================================"
echo ""

[ ! -d ".venv" ] && echo "[ERROR] Run setup.sh first." && exit 1
[ ! -d "web/node_modules" ] && echo "[ERROR] Run setup.sh first." && exit 1

# Check ports
if lsof -i:8000 -sTCP:LISTEN &>/dev/null; then
    echo "[WARNING] Port 8000 in use. Run stop.sh first."; exit 1
fi
if lsof -i:5173 -sTCP:LISTEN &>/dev/null; then
    echo "[WARNING] Port 5173 in use. Run stop.sh first."; exit 1
fi

mkdir -p .sentinel

# Start backend
echo "[1/3] Starting FastAPI backend on http://localhost:8000 ..."
source .venv/bin/activate
nohup python -m uvicorn sentinel_evidence.api.app:app --host 127.0.0.1 --port 8000 --log-level info > .sentinel/backend.log 2>&1 &
echo $! > .sentinel/backend.pid

for i in $(seq 1 15); do
    curl -s http://127.0.0.1:8000/health >/dev/null 2>&1 && break
    sleep 1
done
echo "       Backend is running."

# Start frontend
echo "[2/3] Starting React frontend on http://localhost:5173 ..."
cd web
nohup npm run dev > ../.sentinel/frontend.log 2>&1 &
echo $! > ../.sentinel/frontend.pid
cd ..

sleep 3
echo "       Frontend is running."

# Ollama status
echo ""
echo "--- Ollama Status ---"
if ! command -v ollama &>/dev/null; then
    echo "[INFO] Ollama not available. Deterministic-only mode."
else
    if ollama list 2>/dev/null | grep -iq "gemma"; then
        echo "[OK]   Ollama + Gemma available."
    else
        echo "[INFO] No Gemma model found. AI unavailable."
    fi
fi

# Open browser
echo ""
echo "[3/3] Opening application..."
if command -v xdg-open &>/dev/null; then xdg-open http://localhost:5173
elif command -v open &>/dev/null; then open http://localhost:5173
fi

echo ""
echo "============================================"
echo "  Sentinel Evidence is running!"
echo ""
echo "  Frontend:  http://localhost:5173"
echo "  Backend:   http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
echo "  To stop: ./stop.sh"
echo "============================================"
