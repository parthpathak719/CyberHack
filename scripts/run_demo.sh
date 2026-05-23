#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# ARP Guardian — Full Demo Script
#
# Starts all components for a local simulation demo:
#   1. Switch simulator (background)
#   2. ARP Guardian monitor in simulation mode
#   3. Dashboard server (background)
#
# Usage:
#   chmod +x scripts/run_demo.sh
#   ./scripts/run_demo.sh
# ──────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           🛡️  ARP Guardian — Demo Launcher               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Cleanup existing ports to prevent "Address already in use"
# or serving an old dashboard from a previous project.
echo "🧹 Cleaning up old processes..."
lsof -ti:8080 -ti:8081 -ti:5000 -ti:5050 | xargs kill -9 2>/dev/null || true

# Ensure data directory exists
mkdir -p data

# Install dependencies if needed
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "📦 Installing Python dependencies..."
    # We use --break-system-packages to bypass the error on system-wide python,
    # or you could run this in a venv.
    pip3 install -r requirements.txt --break-system-packages || true
fi

# 1. Start switch simulator in background
#    We use port 5050 because port 5000 is often taken by macOS AirPlay.
echo "🔌 Starting switch simulator on port 5050..."
FLASK_RUN_PORT=5050 python3 -c "
import sys; sys.path.insert(0, '.')
from switch_simulator.app import app
app.run(host='0.0.0.0', port=5050)
" &
SWITCH_PID=$!
sleep 2

# 2. Start dashboard server in background
echo "🌐 Starting dashboard server on port 8080..."
if command -v node >/dev/null 2>&1; then
    node dashboard/server.js &
    DASH_PID=$!
else
    echo "⚠️  Node.js not found. Using Python-based dashboard server fallback..."
    python3 dashboard/server.py &
    DASH_PID=$!
fi
sleep 1

# 3. Start ARP Guardian in simulation mode (foreground)
echo ""
echo "🛡️  Starting ARP Guardian in simulation mode..."
echo "   Dashboard: http://localhost:8080"
echo "   API:       http://localhost:8081"
echo ""
echo "   Press Ctrl+C to stop all components."
echo ""

# Cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping all components..."
    kill $SWITCH_PID 2>/dev/null || true
    kill $DASH_PID 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT

# Run monitor in foreground pointing to switch port 5050
python3 -m src.arp_guardian --simulate --switch-url http://localhost:5050
