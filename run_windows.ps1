$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
python -m src.main --help
Write-Host "For live scanning, open an Administrator PowerShell and run:"
Write-Host "python -m src.main --scan-live"
Write-Host "For a saved live triage snapshot:"
Write-Host "python -m src.main --capture-live output\live_snapshot.json"
