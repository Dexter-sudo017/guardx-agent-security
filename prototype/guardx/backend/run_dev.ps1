$ErrorActionPreference = "Stop"
param(
    [int]$Port = 8014
)

Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    python -m venv .venv
}

& ".\.venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip
pip install -r requirements.txt

uvicorn app.main:app --reload --port $Port
