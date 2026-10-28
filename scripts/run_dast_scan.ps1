<#
.SYNOPSIS
    Script tự động chạy kiểm thử DAST bằng OWASP ZAP Baseline qua Docker Network.
.DESCRIPTION
    1. Kiểm tra ứng dụng Flask đang chạy và healthy.
    2. Xác định Docker network nội bộ của container web.
    3. Chạy container OWASP ZAP gắn vào cùng network.
    4. Xuất báo cáo HTML và JSON vào evidence/dast/.
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  OWASP ZAP DAST BASELINE SCAN (DOCKER NETWORK ISOLATED) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$outputDir = "evidence/dast"
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
}

# 1. Kiểm tra trạng thái container web
Write-Host "`n[1/3] Kiểm tra trạng thái ứng dụng web..." -ForegroundColor Yellow
$containerId = docker compose ps -q web
if (!$containerId) {
    Write-Host "Container web chưa chạy. Đang khởi động..." -ForegroundColor Yellow
    docker compose up -d --build
    Start-Sleep -Seconds 5
    $containerId = docker compose ps -q web
}

$healthStatus = docker inspect --format='{{json .State.Health.Status}}' $containerId
Write-Host "Trạng thái container: $healthStatus" -ForegroundColor Green

# 2. Xác định Docker network
Write-Host "`n[2/3] Xác định Docker network nội bộ..." -ForegroundColor Yellow
$networkName = docker inspect --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' $containerId
if (!$networkName) {
    $networkName = "devsecops_web_security_default"
}
Write-Host "Docker Network: $networkName" -ForegroundColor Green

# 3. Chạy OWASP ZAP Baseline Scan
Write-Host "`n[3/3] Thực thi OWASP ZAP Baseline Scan đối với http://web:5000 ..." -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()

docker run --rm `
    --network $networkName `
    -v "${PWD}/evidence/dast:/zap/wrk/:rw" `
    -v "${PWD}/security/zap:/zap/config/:ro" `
    zaproxy/zap-stable:latest `
    zap-baseline.py `
    -t http://web:5000 `
    -c /zap/config/zap-baseline.conf `
    -r zap-report.html `
    -J zap-report.json `
    -I `
    -m 2

$zapExit = $LASTEXITCODE

$sw.Stop()

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  ZAP SCAN FINISHED in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s (Exit Code: $zapExit)" -ForegroundColor Green
if ($zapExit -eq 3) {
    Write-Host "  [ERROR] ZAP failed with code 3 (target unreachable or config error)." -ForegroundColor Red
    exit 3
} elseif ($zapExit -gt 3) {
    Write-Host "  [ERROR] Docker execution failed with code $zapExit." -ForegroundColor Red
    exit $zapExit
} else {
    Write-Host "  [AUDIT MODE] Scan completed successfully. Findings saved for review." -ForegroundColor Green
}
Write-Host "  Reports saved: $outputDir/zap-report.html" -ForegroundColor Cyan
Write-Host "                 $outputDir/zap-report.json" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
