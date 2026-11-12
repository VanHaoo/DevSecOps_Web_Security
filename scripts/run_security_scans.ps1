<#
.SYNOPSIS
    Script tự động thực thi các công cụ kiểm tra an toàn thông tin (DevSecOps) và xuất SBOM.
.DESCRIPTION
    Hỗ trợ thực thi linh hoạt các công cụ bảo mật thông qua container Docker:
    - Static (mặc định):
        1. Semgrep (SAST)
        2. Trivy Filesystem (SCA)
        3. Trivy Docker Image (Container Vulnerability Scanning)
        4. Gitleaks (Secret Scanning)
        5. Trivy SBOM (CycloneDX 1.6 JSON)
    - DAST:
        Kiểm tra trạng thái ứng dụng, kết nối Docker network nội bộ và chạy OWASP ZAP Baseline Scan.
    - All:
        Thực thi toàn bộ kiểm thử tĩnh (Static) kết hợp kiểm thử động (DAST).
.PARAMETER Type
    Chế độ quét: 'static' (mặc định), 'dast', 'all', 'sast', 'sca', 'image', 'secrets', 'sbom'.
#>

param(
    [ValidateSet("all", "static", "dast", "sast", "sca", "image", "secrets", "sbom")]
    [string]$Type = "static"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  DEVSECOPS LAB - AUTOMATED SECURITY TOOLING EXECUTION   " -ForegroundColor Cyan
Write-Host "  Chế độ thực thi: $Type.ToUpper()                        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$outputDir = "evidence/security-tooling"
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
}

function Verify-JsonReport {
    param(
        [string]$Path,
        [string]$ToolName
    )
    if (!(Test-Path $Path)) {
        Write-Error "[$ToolName] Thất bại: Không tìm thấy file báo cáo tại $Path"
        exit 1
    }
    try {
        $content = Get-Content -Raw $Path | ConvertFrom-Json
        if ($null -eq $content) {
            throw "File rỗng hoặc không đúng định dạng JSON"
        }
        Write-Host "  [OK] Báo cáo hợp lệ: $Path" -ForegroundColor DarkGreen
    } catch {
        Write-Error "[$ToolName] Thất bại: Báo cáo không phải JSON hợp lệ. Chi tiết: $_"
        exit 1
    }
}

# -------------------------------------------------------------
# 1. Semgrep (SAST)
# -------------------------------------------------------------
function Run-Semgrep {
    Write-Host "`n[*] Running Semgrep SAST..." -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    docker run --rm -v "${PWD}:/src" semgrep/semgrep:1.109.0 `
        semgrep scan `
        --config /src/security/semgrep/semgrep-rules.yaml `
        --config "p/flask" `
        --config "p/owasp-top-ten" `
        --json `
        --output "/src/$outputDir/semgrep-report.json" `
        /src/app /src/wsgi.py
    $sw.Stop()
    Verify-JsonReport -Path "$outputDir/semgrep-report.json" -ToolName "Semgrep"
    Write-Host "  -> Semgrep finished in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s" -ForegroundColor Green
}

# -------------------------------------------------------------
# 2. Trivy Filesystem (SCA)
# -------------------------------------------------------------
function Run-TrivyFs {
    Write-Host "`n[*] Running Trivy Filesystem (SCA)..." -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    docker run --rm -v "${PWD}:/src" aquasec/trivy:0.59.1 `
        fs --scanners vuln `
        --skip-dirs venv --skip-dirs .git `
        --format json `
        --output "/src/$outputDir/trivy-fs-report.json" `
        /src
    $sw.Stop()
    Verify-JsonReport -Path "$outputDir/trivy-fs-report.json" -ToolName "Trivy FS"
    Write-Host "  -> Trivy FS finished in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s" -ForegroundColor Green
}

# -------------------------------------------------------------
# 3. Trivy Docker Image
# -------------------------------------------------------------
function Run-TrivyImage {
    Write-Host "`n[*] Running Trivy Docker Image Scan..." -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/src" aquasec/trivy:0.59.1 `
        image --format json `
        --output "/src/$outputDir/trivy-image-report.json" `
        devsecops_web_security-web:latest
    $sw.Stop()
    Verify-JsonReport -Path "$outputDir/trivy-image-report.json" -ToolName "Trivy Image"
    Write-Host "  -> Trivy Image scan finished in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s" -ForegroundColor Green
}

# -------------------------------------------------------------
# 4. Gitleaks (Secret Scanning)
# -------------------------------------------------------------
function Run-Gitleaks {
    Write-Host "`n[*] Running Gitleaks Secret Scan..." -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    docker run --rm -v "${PWD}:/src" zricethezav/gitleaks:v8.24.0 `
        detect --source /src `
        --config /src/security/gitleaks/gitleaks.toml `
        --report-path "/src/$outputDir/gitleaks-report.json" `
        --report-format json
    $sw.Stop()
    Verify-JsonReport -Path "$outputDir/gitleaks-report.json" -ToolName "Gitleaks"
    Write-Host "  -> Gitleaks finished in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s" -ForegroundColor Green
}

# -------------------------------------------------------------
# 5. Trivy SBOM Generation (CycloneDX)
# -------------------------------------------------------------
function Run-SBOM {
    Write-Host "`n[*] Generating SBOM (CycloneDX JSON)..." -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/src" aquasec/trivy:0.59.1 `
        image --format cyclonedx `
        --output "/src/$outputDir/sbom-image-cyclonedx.json" `
        devsecops_web_security-web:latest

    docker run --rm -v "${PWD}:/src" aquasec/trivy:0.59.1 `
        fs --skip-dirs venv --skip-dirs .git --format cyclonedx `
        --output "/src/$outputDir/sbom-fs-cyclonedx.json" `
        /src
    $sw.Stop()
    Verify-JsonReport -Path "$outputDir/sbom-image-cyclonedx.json" -ToolName "Trivy SBOM Image"
    Verify-JsonReport -Path "$outputDir/sbom-fs-cyclonedx.json" -ToolName "Trivy SBOM FS"
    Write-Host "  -> SBOM generation finished in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s" -ForegroundColor Green
}

# -------------------------------------------------------------
# 6. OWASP ZAP (DAST)
# -------------------------------------------------------------
function Run-DAST {
    Write-Host "`n[*] Running OWASP ZAP DAST Baseline Scan..." -ForegroundColor Yellow
    $dastDir = "evidence/dast"
    if (!(Test-Path $dastDir)) {
        New-Item -ItemType Directory -Force -Path $dastDir | Out-Null
    }

    # 6.1. Kiểm tra trạng thái container web
    Write-Host "  [1/3] Kiểm tra trạng thái ứng dụng web..." -ForegroundColor Cyan
    $containerId = docker compose ps -q web
    if (!$containerId) {
        Write-Host "  Container web chưa chạy. Đang khởi động..." -ForegroundColor Yellow
        docker compose up -d --build
        Start-Sleep -Seconds 5
        $containerId = docker compose ps -q web
    }

    $healthStatus = docker inspect --format='{{json .State.Health.Status}}' $containerId
    Write-Host "  Trạng thái container: $healthStatus" -ForegroundColor Green

    # 6.2. Xác định Docker network
    Write-Host "  [2/3] Xác định Docker network nội bộ..." -ForegroundColor Cyan
    $networkName = docker inspect --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' $containerId
    if (!$networkName) {
        $networkName = "devsecops_web_security_default"
    }
    Write-Host "  Docker Network: $networkName" -ForegroundColor Green

    # 6.3. Chạy OWASP ZAP Baseline Scan
    Write-Host "  [3/3] Thực thi OWASP ZAP Baseline Scan đối với http://web:5000 ..." -ForegroundColor Cyan
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

    Write-Host "`n  ZAP SCAN FINISHED in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s (Exit Code: $zapExit)" -ForegroundColor Green
    if ($zapExit -eq 3) {
        Write-Error "  [ERROR] ZAP failed with code 3 (target unreachable or config error)."
        exit 3
    } elseif ($zapExit -gt 3) {
        Write-Error "  [ERROR] Docker execution failed with code $zapExit."
        exit $zapExit
    }
    Verify-JsonReport -Path "$dastDir/zap-report.json" -ToolName "OWASP ZAP DAST"
}

# -------------------------------------------------------------
# Dispatch execution based on -Type
# -------------------------------------------------------------
switch ($Type.ToLower()) {
    "sast"    { Run-Semgrep }
    "sca"     { Run-TrivyFs }
    "image"   { Run-TrivyImage }
    "secrets" { Run-Gitleaks }
    "sbom"    { Run-SBOM }
    "dast"    { Run-DAST }
    "all"     {
        Run-Semgrep
        Run-TrivyFs
        Run-TrivyImage
        Run-Gitleaks
        Run-SBOM
        Run-DAST
    }
    "static"  {
        Run-Semgrep
        Run-TrivyFs
        Run-TrivyImage
        Run-Gitleaks
        Run-SBOM
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  SECURITY SCAN COMPLETED SUCCESSFULLY!                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
