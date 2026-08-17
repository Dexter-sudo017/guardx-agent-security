param(
    [int]$Port = 8023,
    [string]$CloudflaredPath = "E:\GuardX\tools\cloudflared.exe"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$serverScript = Join-Path $PSScriptRoot "start_reviewer_server.ps1"
$localUrl = "http://127.0.0.1:$Port/final/"
$originUrl = "http://127.0.0.1:$Port"
$runtimeRoot = "E:\GuardX\runtime\public-demo"

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

function Stop-GuardXTrackedProcess {
    param(
        [string]$PidPath,
        [ValidateSet("server", "tunnel")]
        [string]$Kind
    )
    if (-not (Test-Path -LiteralPath $PidPath)) {
        return
    }
    $trackedPid = 0
    [void][int]::TryParse((Get-Content -LiteralPath $PidPath -Raw).Trim(), [ref]$trackedPid)
    if ($trackedPid -gt 0) {
        $trackedProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $trackedPid" -ErrorAction SilentlyContinue
        $isExpected = $false
        if ($trackedProcess -and $Kind -eq "tunnel") {
            $isExpected = $trackedProcess.Name -eq "cloudflared.exe"
        }
        elseif ($trackedProcess -and $Kind -eq "server") {
            $commandLine = [string]$trackedProcess.CommandLine
            $isExpected = $commandLine.Contains("uvicorn app.main:app") -and $commandLine.Contains("--port $Port")
        }
        if ($isExpected) {
            Stop-Process -Id $trackedPid -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path -LiteralPath $CloudflaredPath)) {
    $command = Get-Command cloudflared -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "cloudflared was not found. Place cloudflared.exe at E:\GuardX\tools\cloudflared.exe or add it to PATH."
    }
    $CloudflaredPath = $command.Source
}

New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
$serverPidPath = Join-Path $runtimeRoot "guardx-server.pid"
$tunnelPidPath = Join-Path $runtimeRoot "cloudflared.pid"

Stop-GuardXTrackedProcess -PidPath $tunnelPidPath -Kind tunnel
Stop-GuardXTrackedProcess -PidPath $serverPidPath -Kind server

if (Test-GuardXReviewer -Url $localUrl) {
    throw "Port $Port is already serving an untracked GuardX process. Choose another port for the public demo."
}

& $serverScript -Port $Port -PublicDemo | Write-Output

for ($attempt = 0; $attempt -lt 60 -and -not (Test-GuardXReviewer -Url $localUrl); $attempt++) {
    Start-Sleep -Milliseconds 500
}
if (-not (Test-GuardXReviewer -Url $localUrl)) {
    throw "GuardX reviewer server did not become ready within 30 seconds."
}

$serverConnection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $serverConnection) {
    throw "GuardX reviewer server is ready but its process id could not be resolved."
}
Set-Content -LiteralPath $serverPidPath -Value $serverConnection.OwningProcess -Encoding ascii

$stdoutPath = Join-Path $runtimeRoot "cloudflared.stdout.log"
$stderrPath = Join-Path $runtimeRoot "cloudflared.stderr.log"
Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue

$tunnel = Start-Process -FilePath $CloudflaredPath -ArgumentList @("tunnel", "--url", $originUrl, "--protocol", "http2", "--no-autoupdate") -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
$publicUrl = $null
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    Start-Sleep -Milliseconds 500
    if ($tunnel.HasExited) {
        $detail = (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue)
        throw "Cloudflare tunnel exited before becoming ready. $detail"
    }
    $logText = ((Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue) + "`n" + (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue))
    $match = [regex]::Match($logText, 'https://[a-z0-9-]+\.trycloudflare\.com')
    if ($match.Success) {
        $publicUrl = "$($match.Value)/final/"
        break
    }
}

if (-not $publicUrl) {
    Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue
    throw "Cloudflare tunnel did not publish a URL within 30 seconds."
}

$urlPath = Join-Path $runtimeRoot "public-url.txt"
$oldAccessPath = Join-Path $runtimeRoot "access-code.txt"
Set-Content -LiteralPath $tunnelPidPath -Value $tunnel.Id -Encoding ascii
Set-Content -LiteralPath $urlPath -Value $publicUrl -Encoding utf8
Remove-Item -LiteralPath $oldAccessPath -Force -ErrorAction SilentlyContinue

$publicReady = $false
$publicHost = ([uri]$publicUrl).DnsSafeHost
for ($attempt = 0; $attempt -lt 45; $attempt++) {
    try {
        $dnsRecords = Resolve-DnsName -Name $publicHost -Server 8.8.8.8 -Type A -ErrorAction Stop
        if (@($dnsRecords | Where-Object { $_.IPAddress }).Count -gt 0) {
            ipconfig /flushdns | Out-Null
            $publicReady = $true
            break
        }
    }
    catch {
        # Quick Tunnel DNS can take a few seconds to propagate after registration.
    }
    Start-Sleep -Seconds 1
}

Start-Process $publicUrl
Write-Output "GuardX temporary public demo is ready: $publicUrl"
Write-Output "Reviewers can open this URL directly; no login or access code is required."
Write-Output "The URL is also saved in E:\GuardX\runtime\public-demo\public-url.txt."
if (-not $publicReady) {
    Write-Output "The tunnel is registered; if the page is not visible yet, wait briefly for DNS propagation and refresh."
}
Write-Output "The temporary URL remains available while the GuardX server and tunnel are running."
