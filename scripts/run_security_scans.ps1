<#
.SYNOPSIS
    Script tự động thực thi toàn bộ công cụ kiểm tra bảo mật và xuất SBOM (Giai đoạn 2).
.DESCRIPTION
    Thực thi độc lập bằng Docker:
    1. Semgrep (SAST)
    2. Trivy Filesystem (SCA)
    3. Trivy Docker Image (Container Vulnerability Scanning)
    4. Gitleaks (Secret Scanning)
    5. Trivy SBOM (CycloneDX 1.6 JSON)
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  DEVSECOPS LAB - AUTOMATED SECURITY TOOLING EXECUTION   " -ForegroundColor Cyan
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

# 1. Semgrep (SAST)
Write-Host "`n[1/5] Running Semgrep SAST..." -ForegroundColor Yellow
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

# 2. Trivy Filesystem (SCA)
Write-Host "`n[2/5] Running Trivy Filesystem (SCA)..." -ForegroundColor Yellow
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

# 3. Trivy Docker Image
Write-Host "`n[3/5] Running Trivy Docker Image Scan..." -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/src" aquasec/trivy:0.59.1 `
    image --format json `
    --output "/src/$outputDir/trivy-image-report.json" `
    devsecops_web_security-web:latest
$sw.Stop()
Verify-JsonReport -Path "$outputDir/trivy-image-report.json" -ToolName "Trivy Image"
Write-Host "  -> Trivy Image scan finished in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s" -ForegroundColor Green

# 4. Gitleaks (Secret Scanning)
Write-Host "`n[4/5] Running Gitleaks Secret Scan..." -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()
docker run --rm -v "${PWD}:/src" zricethezav/gitleaks:v8.24.0 `
    detect --source /src `
    --config /src/security/gitleaks/gitleaks.toml `
    --report-path "/src/$outputDir/gitleaks-report.json" `
    --report-format json
$sw.Stop()
Verify-JsonReport -Path "$outputDir/gitleaks-report.json" -ToolName "Gitleaks"
Write-Host "  -> Gitleaks finished in $([Math]::Round($sw.Elapsed.TotalSeconds, 2))s" -ForegroundColor Green

# 5. Trivy SBOM Generation (CycloneDX)
Write-Host "`n[5/5] Generating SBOM (CycloneDX JSON)..." -ForegroundColor Yellow
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

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  ALL SECURITY SCANS & SBOM GENERATION COMPLETED!        " -ForegroundColor Cyan
Write-Host "  Reports saved in: $outputDir/                           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
