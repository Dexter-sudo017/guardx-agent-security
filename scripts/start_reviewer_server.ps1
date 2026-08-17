param(
    [int]$Port = 8021,
    [string]$WebToken = "",
    [switch]$PublicDemo
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $repositoryRoot "prototype\guardx\backend"
$pythonPath = (Get-Command python).Source

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
