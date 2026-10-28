#!/usr/bin/env bash
# ==============================================================================
# Linux Bash Runner for DevSecOps Security Scans & SBOM Generation (Phase 2 & 3)
# ==============================================================================
set -euo pipefail

OUTPUT_DIR="evidence/security-tooling"
mkdir -p "$OUTPUT_DIR"

echo "=========================================================="
echo "  DEVSECOPS LAB - SECURITY TOOLING EXECUTION (LINUX/BASH) "
echo "=========================================================="

# 1. Semgrep (SAST)
echo -e "\n[1/5] Running Semgrep SAST..."
docker run --rm -v "${PWD}:/src" semgrep/semgrep:1.109.0 \
    semgrep scan \
    --config /src/security/semgrep/semgrep-rules.yaml \
    --config "p/flask" \
    --config "p/owasp-top-ten" \
    --json \
    --output "/src/$OUTPUT_DIR/semgrep-report.json" \
    /src/app /src/wsgi.py

# 2. Trivy Filesystem (SCA)
echo -e "\n[2/5] Running Trivy Filesystem (SCA)..."
docker run --rm -v "${PWD}:/src" aquasec/trivy:0.59.1 \
    fs --scanners vuln \
    --skip-dirs venv --skip-dirs .git \
    --format json \
    --output "/src/$OUTPUT_DIR/trivy-fs-report.json" \
    /src

# 3. Trivy Docker Image
echo -e "\n[3/5] Running Trivy Docker Image Scan..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/src" aquasec/trivy:0.59.1 \
    image --format json \
    --output "/src/$OUTPUT_DIR/trivy-image-report.json" \
    devsecops_web_security-web:latest

# 4. Gitleaks (Secret Scanning)
echo -e "\n[4/5] Running Gitleaks Secret Scan..."
docker run --rm -v "${PWD}:/src" zricethezav/gitleaks:v8.24.0 \
    detect --source /src \
    --config /src/security/gitleaks/gitleaks.toml \
    --report-path "/src/$OUTPUT_DIR/gitleaks-report.json" \
    --report-format json

# 5. Trivy SBOM Generation (CycloneDX)
echo -e "\n[5/5] Generating SBOM (CycloneDX JSON)..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/src" aquasec/trivy:0.59.1 \
    image --format cyclonedx \
    --output "/src/$OUTPUT_DIR/sbom-image-cyclonedx.json" \
    devsecops_web_security-web:latest

docker run --rm -v "${PWD}:/src" aquasec/trivy:0.59.1 \
    fs --skip-dirs venv --skip-dirs .git --format cyclonedx \
    --output "/src/$OUTPUT_DIR/sbom-fs-cyclonedx.json" \
    /src

echo -e "\n=========================================================="
echo "  ALL SECURITY SCANS & SBOM GENERATION COMPLETED!        "
echo "  Reports saved in: $OUTPUT_DIR/                           "
echo "=========================================================="
