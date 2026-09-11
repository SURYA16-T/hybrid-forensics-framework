#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
python -m src.main --help
