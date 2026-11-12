#!/usr/bin/env bash
# ==============================================================================
# Linux Bash Runner for DevSecOps Security Scans & SBOM Generation
# ==============================================================================
set -euo pipefail

SCAN_TYPE="${1:-static}"
OUTPUT_DIR="evidence/security-tooling"
mkdir -p "$OUTPUT_DIR"

echo "=========================================================="
echo "  DEVSECOPS LAB - SECURITY TOOLING EXECUTION (LINUX/BASH) "
echo "  Scan Type: $SCAN_TYPE                                   "
echo "=========================================================="

run_semgrep() {
    echo -e "\n[*] Running Semgrep SAST..."
    docker run --rm -v "${PWD}:/src" semgrep/semgrep:1.109.0 \
        semgrep scan \
        --config /src/security/semgrep/semgrep-rules.yaml \
        --config "p/flask" \
        --config "p/owasp-top-ten" \
        --json \
        --output "/src/$OUTPUT_DIR/semgrep-report.json" \
        /src/app /src/wsgi.py
}

run_trivy_fs() {
    echo -e "\n[*] Running Trivy Filesystem (SCA)..."
    docker run --rm -v "${PWD}:/src" aquasec/trivy:0.59.1 \
        fs --scanners vuln \
        --skip-dirs venv --skip-dirs .git \
        --format json \
        --output "/src/$OUTPUT_DIR/trivy-fs-report.json" \
        /src
}

run_trivy_image() {
    echo -e "\n[*] Running Trivy Docker Image Scan..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/src" aquasec/trivy:0.59.1 \
        image --format json \
        --output "/src/$OUTPUT_DIR/trivy-image-report.json" \
        devsecops_web_security-web:latest
}

run_gitleaks() {
    echo -e "\n[*] Running Gitleaks Secret Scan..."
    docker run --rm -v "${PWD}:/src" zricethezav/gitleaks:v8.24.0 \
        detect --source /src \
        --config /src/security/gitleaks/gitleaks.toml \
        --report-path "/src/$OUTPUT_DIR/gitleaks-report.json" \
        --report-format json
}

run_sbom() {
    echo -e "\n[*] Generating SBOM (CycloneDX JSON)..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/src" aquasec/trivy:0.59.1 \
        image --format cyclonedx \
        --output "/src/$OUTPUT_DIR/sbom-image-cyclonedx.json" \
        devsecops_web_security-web:latest

    docker run --rm -v "${PWD}:/src" aquasec/trivy:0.59.1 \
        fs --skip-dirs venv --skip-dirs .git --format cyclonedx \
        --output "/src/$OUTPUT_DIR/sbom-fs-cyclonedx.json" \
        /src
}

run_dast() {
    echo -e "\n[*] Running OWASP ZAP DAST..."
    mkdir -p evidence/dast
    WEB_CID=$(docker compose ps -q web || true)
    if [ -z "$WEB_CID" ]; then
        docker compose up -d --build
        sleep 5
        WEB_CID=$(docker compose ps -q web)
    fi
    NETWORK_NAME=$(docker inspect --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$WEB_CID")
    docker run --rm \
        --network "${NETWORK_NAME:-devsecops_web_security_default}" \
        -v "${PWD}/evidence/dast:/zap/wrk/:rw" \
        -v "${PWD}/security/zap:/zap/config/:ro" \
        zaproxy/zap-stable:latest \
        zap-baseline.py \
        -t http://web:5000 \
        -c /zap/config/zap-baseline.conf \
        -r zap-report.html \
        -J zap-report.json \
        -I \
        -m 2
}

case "$SCAN_TYPE" in
    sast)    run_semgrep ;;
    sca)     run_trivy_fs ;;
    image)   run_trivy_image ;;
    secrets) run_gitleaks ;;
    sbom)    run_sbom ;;
    dast)    run_dast ;;
    all)
        run_semgrep
        run_trivy_fs
        run_trivy_image
        run_gitleaks
        run_sbom
        run_dast
        ;;
    static|*)
        run_semgrep
        run_trivy_fs
        run_trivy_image
        run_gitleaks
        run_sbom
        ;;
esac

echo -e "\nSecurity scans completed. Reports saved in evidence/"
