param(
    [int]$Port = 8021,
    [string]$WebToken = "",
    [switch]$PublicDemo
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $repositoryRoot "prototype\guardx\backend"
$enterprisePython = "E:\GuardX\runtime\guardx-venv\Scripts\python.exe"
$pythonPath = if (Test-Path -LiteralPath $enterprisePython) { $enterprisePython } else { (Get-Command python).Source }
$env:HF_HOME = "E:\GuardX\models\huggingface"
$env:GUARDX_RUNTIME_TEMP = "E:\GuardX\runtime\tmp"
$env:GUARDX_RAG_RERANKER_PATH = "E:\GuardX\models\bge-reranker-v2-m3"
$env:GUARDX_AGENT_TICKET_ROOT = "E:\GuardX\runtime\agent-tickets"
$env:PYTHONUTF8 = "1"
if (-not $env:GUARDX_CONTEXTUAL_JUDGE_MODEL) {
    $env:GUARDX_CONTEXTUAL_JUDGE_MODEL = "qwen2.5:3b"
}

foreach ($variableName in @("DEEPSEEK_API_KEY", "MOONSHOT_API_KEY", "ZHIPU_API_KEY", "DASHSCOPE_API_KEY")) {
    $userValue = [Environment]::GetEnvironmentVariable($variableName, "User")
    if ($userValue) {
        Set-Item -LiteralPath "Env:$variableName" -Value $userValue
    }
}

if ($WebToken) {
    $env:GUARDX_WEB_TOKEN = $WebToken
}
if ($PublicDemo) {
    Remove-Item Env:GUARDX_WEB_TOKEN -ErrorAction SilentlyContinue
    $env:GUARDX_WEB_ALLOW_UNAUTHENTICATED_PUBLIC_DEMO = "1"
}

$arguments = @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", [string]$Port)
$process = Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory $backendRoot -WindowStyle Hidden -PassThru
Write-Output "GuardX reviewer server started: PID=$($process.Id) PORT=$Port"
