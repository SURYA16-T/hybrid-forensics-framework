#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Create and activate virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Run tests
pytest -q tests/

# Launch the live scanner
python3 -m src.main --scan-live
