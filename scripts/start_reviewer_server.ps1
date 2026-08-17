param(
    [int]$Port = 8021
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

$arguments = @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", [string]$Port)
$process = Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory $backendRoot -WindowStyle Hidden -PassThru
Write-Output "GuardX reviewer server started: PID=$($process.Id) PORT=$Port"
