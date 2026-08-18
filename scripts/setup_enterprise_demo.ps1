param(
    [string]$RuntimeRoot = "E:\GuardX\runtime",
    [string]$ModelRoot = "E:\GuardX\models"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $repositoryRoot "prototype\guardx\backend"
$mainEnvironment = Join-Path $RuntimeRoot "guardx-venv"
$rerankerEnvironment = Join-Path $RuntimeRoot "bge-reranker-venv"

New-Item -ItemType Directory -Path $RuntimeRoot, $ModelRoot -Force | Out-Null

if (-not (Test-Path -LiteralPath (Join-Path $mainEnvironment "Scripts\python.exe"))) {
    python -m venv $mainEnvironment
}
& (Join-Path $mainEnvironment "Scripts\python.exe") -m pip install --upgrade pip
& (Join-Path $mainEnvironment "Scripts\python.exe") -m pip install -r (Join-Path $backendRoot "requirements-enterprise-demo.txt")

if (-not (Test-Path -LiteralPath (Join-Path $rerankerEnvironment "Scripts\python.exe"))) {
    python -m venv $rerankerEnvironment
}
& (Join-Path $rerankerEnvironment "Scripts\python.exe") -m pip install --upgrade pip
& (Join-Path $rerankerEnvironment "Scripts\python.exe") -m pip install -r (Join-Path $backendRoot "requirements-reranker-worker.txt")

Write-Output "GuardX enterprise demo runtimes are ready."
Write-Output "Main runtime: $mainEnvironment"
Write-Output "Reranker runtime: $rerankerEnvironment"
