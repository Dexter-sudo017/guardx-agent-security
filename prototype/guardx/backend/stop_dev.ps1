$ErrorActionPreference = "Continue"

$ports = @(8011, 8012, 8013, 8014)
$stopped = @()

foreach ($port in $ports) {
    $connections = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        try {
            Stop-Process -Id $conn.OwningProcess -Force
            $stopped += [PSCustomObject]@{
                Port = $port
                Pid = $conn.OwningProcess
                Status = "stopped"
            }
        } catch {
            $stopped += [PSCustomObject]@{
                Port = $port
                Pid = $conn.OwningProcess
                Status = "failed"
            }
        }
    }
}

if (-not $stopped) {
    Write-Host "No GuardX dev server found on ports 8011 or 8012."
} else {
    $stopped | Format-Table -AutoSize
}
