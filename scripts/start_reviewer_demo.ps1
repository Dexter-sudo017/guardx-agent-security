param(
    [int]$Port = 8021
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$serverScript = Join-Path $PSScriptRoot "start_reviewer_server.ps1"
$reviewerUrl = "http://127.0.0.1:$Port/final/"

function Test-GuardXReviewer {
    param([string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 2 -UseBasicParsing
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

Set-Location -LiteralPath $repositoryRoot

if (-not (Test-GuardXReviewer -Url $reviewerUrl)) {
    & $serverScript -Port $Port | Write-Output

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        Start-Sleep -Milliseconds 500
        if (Test-GuardXReviewer -Url $reviewerUrl) {
            $ready = $true
            break
        }
    }

    if (-not $ready) {
        throw "GuardX reviewer server did not become ready within 30 seconds."
    }
}

Start-Process $reviewerUrl
Write-Output "GuardX reviewer console is ready: $reviewerUrl"
