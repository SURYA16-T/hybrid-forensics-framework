#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
echo "ERROR: Python 3 is required."
exit 1
fi

if [ ! -d "venv" ]; then
echo "[1/4] Creating virtual environment..."
python3 -m venv venv
fi

echo "[2/4] Activating virtual environment..."
source venv/bin/activate

echo "[3/4] Installing requirements..."
python -m pip install -r requirements.txt

echo "[4/4] Running tests..."
python -m pytest -q

echo
echo "Starting macOS live process/virtual-memory scanner..."
echo

python -m src.main --scan-live
