#!/usr/bin/env bash
echo "============================================"
echo "  Sentinel Evidence - Stopping Servers"
echo "============================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[1/2] Stopping backend..."
if [ -f .sentinel/backend.pid ]; then
    kill "$(cat .sentinel/backend.pid)" 2>/dev/null || true
    rm -f .sentinel/backend.pid
fi
echo "       Backend stopped."

echo "[2/2] Stopping frontend..."
if [ -f .sentinel/frontend.pid ]; then
    kill "$(cat .sentinel/frontend.pid)" 2>/dev/null || true
    rm -f .sentinel/frontend.pid
fi
echo "       Frontend stopped."

echo ""
echo "============================================"
echo "  All Sentinel Evidence servers stopped."
echo "============================================"
