#!/usr/bin/env python3
"""
Security Quality Gate - Test Suite
TC-GATE-01 to TC-GATE-08

Ghi chú: Tất cả test cases sử dụng dữ liệu giả lập (synthetic) để kiểm thử logic
của Security Gate Engine. Không thay thế cho thực nghiệm bảo mật thật với dữ liệu quét thực tế.
"""
import os
import sys
import json
import tempfile
import shutil
import subprocess
from datetime import date, timedelta

# Path to security_gate.py
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_SCRIPT = os.path.join(BASE_DIR, "scripts", "security_gate.py")

PASSED = []
FAILED = []


def make_semgrep_report(findings=None):
    """Create a synthetic Semgrep report."""
    return {"results": findings or [], "errors": []}


def make_trivy_fs_report(vulns=None):
    """Create a synthetic Trivy FS report."""
    results = []
    if vulns:
        results.append({"Target": "requirements.txt", "Class": "lang-pkgs",
                        "Type": "pip", "Vulnerabilities": vulns})
    return {"SchemaVersion": 2, "Results": results}


def make_trivy_image_report(os_vulns=None, app_vulns=None):
    """Create a synthetic Trivy Image report."""
    results = []
    if os_vulns:
        results.append({"Target": "debian:13", "Class": "os-pkgs",
                        "Type": "debian", "Vulnerabilities": os_vulns})
    if app_vulns:
        results.append({"Target": "Python", "Class": "lang-pkgs",
                        "Type": "pip", "Vulnerabilities": app_vulns})
    return {"SchemaVersion": 2, "Results": results}


def make_gitleaks_report(leaks=None):
    """Create a synthetic Gitleaks report."""
    return leaks or []


def make_zap_report(alerts=None):
    """Create a synthetic ZAP report."""
    return {"site": [{"name": "http://localhost", "alerts": alerts or []}]}


def make_policy(mode="enforce"):
    return {
        "version": "1.0",
        "mode": mode,
        "thresholds": {
            "gitleaks": {"max_leaks": 0},
            "semgrep": {"blocked_severities": ["ERROR", "WARNING"]},
            "trivy_fs": {"blocked_severities": ["CRITICAL", "HIGH", "MEDIUM"]},
            "trivy_image": {"blocked_os_severities": ["CRITICAL", "HIGH"],
                           "blocked_app_severities": ["CRITICAL", "HIGH", "MEDIUM"]}
        }
    }


def make_exceptions(exceptions_list=None):
    return {"version": "1.0", "exceptions": exceptions_list or []}


def run_gate(tmpdir, mode=None, extra_args=None, test_exit_code=0):
    """Run security_gate.py in a temp directory with given reports."""
    args = [sys.executable, GATE_SCRIPT]
    args += ["--policy", os.path.join(tmpdir, "policy.json")]
    args += ["--exceptions", os.path.join(tmpdir, "exceptions.json")]
    args += ["--semgrep-report", os.path.join(tmpdir, "semgrep.json")]
    args += ["--trivy-fs-report", os.path.join(tmpdir, "trivy-fs.json")]
    args += ["--trivy-image-report", os.path.join(tmpdir, "trivy-image.json")]
    args += ["--gitleaks-report", os.path.join(tmpdir, "gitleaks.json")]
    args += ["--zap-report", os.path.join(tmpdir, "zap.json")]
    args += ["--output-json", os.path.join(tmpdir, "result.json")]
    args += ["--output-md", os.path.join(tmpdir, "result.md")]
    args += ["--test-exit-code", str(test_exit_code)]
    if mode:
        args += ["--mode", mode]
    if extra_args:
        args += extra_args
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8")
    # Load result json if available
    result_json = None
    rpath = os.path.join(tmpdir, "result.json")
    if os.path.isfile(rpath):
        with open(rpath, "r", encoding="utf-8") as f:
            result_json = json.load(f)
    return result.returncode, result_json, result.stdout, result.stderr


def write_fixtures(tmpdir, policy, exceptions, semgrep, trivy_fs, trivy_image, gitleaks, zap):
    """Write all fixture files."""
    def w(fname, obj):
        with open(os.path.join(tmpdir, fname), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
    w("policy.json", policy)
    w("exceptions.json", exceptions)
    w("semgrep.json", semgrep)
    w("trivy-fs.json", trivy_fs)
    w("trivy-image.json", trivy_image)
    w("gitleaks.json", gitleaks)
    w("zap.json", zap)


def run_test(tc_id, description, setup_fn, assert_fn):
    """Execute a single test case."""
    tmpdir = tempfile.mkdtemp(prefix=f"{tc_id}_")
    print(f"\n{'='*60}")
    print(f"[{tc_id}] {description}")
    print(f"{'='*60}")
    try:
        ctx = setup_fn(tmpdir)
        returncode, result_json, stdout, stderr = ctx
        ok, msg = assert_fn(returncode, result_json)
        status_symbol = "PASS" if ok else "FAIL"
        print(f"  Return code: {returncode}")
        if result_json:
            print(f"  Gate status: {result_json.get('overall_status')}")
            print(f"  Violations: {len(result_json.get('violations', []))}")
            print(f"  Exceptions used: {result_json.get('summary', {}).get('active_exceptions_used', 0)}")
        print(f"  Assert: {msg}")
        print(f"  --> [{status_symbol}]")
        if ok:
            PASSED.append(tc_id)
        else:
            FAILED.append(tc_id)
        if stderr.strip():
            print(f"  STDERR: {stderr.strip()[:300]}")
    except Exception as e:
        print(f"  EXCEPTION during test: {e}")
        FAILED.append(tc_id)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────
# TC-GATE-01: No violations → PASS
# ─────────────────────────────────────────────────────────────
def tc01_setup(tmpdir):
    write_fixtures(tmpdir,
        policy=make_policy("enforce"),
        exceptions=make_exceptions([]),
        semgrep=make_semgrep_report([]),
        trivy_fs=make_trivy_fs_report([]),
        trivy_image=make_trivy_image_report([], []),
        gitleaks=make_gitleaks_report([]),
        zap=make_zap_report([])
    )
    return run_gate(tmpdir, mode="enforce")


def tc01_assert(rc, rj):
    if rc != 0:
        return False, f"Expected exit code 0, got {rc}"
    if rj["overall_status"] != "PASS":
        return False, f"Expected PASS, got {rj['overall_status']}"
    return True, "No violations, gate correctly returned PASS"


# ─────────────────────────────────────────────────────────────
# TC-GATE-02: Unexempted HIGH OS CVE → FAIL
# ─────────────────────────────────────────────────────────────
def tc02_setup(tmpdir):
    os_vuln = [{
        "VulnerabilityID": "CVE-2099-99999", "PkgName": "libc6",
        "InstalledVersion": "1.0", "FixedVersion": None,
        "Severity": "HIGH", "Title": "Test critical OS CVE"
    }]
    write_fixtures(tmpdir,
        policy=make_policy("enforce"),
        exceptions=make_exceptions([]),
        semgrep=make_semgrep_report([]),
        trivy_fs=make_trivy_fs_report([]),
        trivy_image=make_trivy_image_report(os_vulns=os_vuln, app_vulns=[]),
        gitleaks=make_gitleaks_report([]),
        zap=make_zap_report([])
    )
    return run_gate(tmpdir, mode="enforce")


def tc02_assert(rc, rj):
    if rc != 1:
        return False, f"Expected exit code 1, got {rc}"
    if rj["overall_status"] != "FAIL":
        return False, f"Expected FAIL, got {rj['overall_status']}"
    violations = rj.get("violations", [])
    if not any(v.get("cve_id") == "CVE-2099-99999" for v in violations):
        return False, "Expected CVE-2099-99999 in violations"
    return True, f"Correctly detected unexempted HIGH CVE → FAIL (violations={len(violations)})"


# ─────────────────────────────────────────────────────────────
# TC-GATE-03: Secret/credential leak → FAIL
# ─────────────────────────────────────────────────────────────
def tc03_setup(tmpdir):
    leak = [{
        "RuleID": "aws-access-token",
        "File": "config/settings.py",
        "StartLine": 42,
        "Description": "AWS Access Key found"
    }]
    write_fixtures(tmpdir,
        policy=make_policy("enforce"),
        exceptions=make_exceptions([]),
        semgrep=make_semgrep_report([]),
        trivy_fs=make_trivy_fs_report([]),
        trivy_image=make_trivy_image_report([], []),
        gitleaks=make_gitleaks_report(leak),
        zap=make_zap_report([])
    )
    return run_gate(tmpdir, mode="enforce")


def tc03_assert(rc, rj):
    if rc != 1:
        return False, f"Expected exit code 1, got {rc}"
    if rj["overall_status"] != "FAIL":
        return False, f"Expected FAIL, got {rj['overall_status']}"
    violations = rj.get("violations", [])
    gitleaks_violations = [v for v in violations if v.get("tool") == "gitleaks"]
    if not gitleaks_violations:
        return False, "Expected gitleaks violation"
    return True, f"Secret leak correctly blocked pipeline → FAIL (gitleaks violations={len(gitleaks_violations)})"


# ─────────────────────────────────────────────────────────────
# TC-GATE-04: Valid approved exception → CVE exempted
# ─────────────────────────────────────────────────────────────
def tc04_setup(tmpdir):
    future_date = (date.today() + timedelta(days=180)).isoformat()
    os_vuln = [{
        "VulnerabilityID": "CVE-2099-11111", "PkgName": "libtest1",
        "InstalledVersion": "1.0", "FixedVersion": None,
        "Severity": "HIGH", "Title": "Test exempted OS CVE"
    }]
    exc = [{
        "id": "EXC-TEST-001", "cve_id": "CVE-2099-11111",
        "package_name": "libtest1", "status": "APPROVED",
        "expires_at": future_date,
        "rationale": "No fix available. Non-exploitable in container (no mount/nsenter).",
        "compensating_controls": ["non-root runtime", "seccomp profile"]
    }]
    write_fixtures(tmpdir,
        policy=make_policy("enforce"),
        exceptions=make_exceptions(exc),
        semgrep=make_semgrep_report([]),
        trivy_fs=make_trivy_fs_report([]),
        trivy_image=make_trivy_image_report(os_vulns=os_vuln, app_vulns=[]),
        gitleaks=make_gitleaks_report([]),
        zap=make_zap_report([])
    )
    return run_gate(tmpdir, mode="enforce")


def tc04_assert(rc, rj):
    if rc != 0:
        return False, f"Expected exit code 0 (exception should cover CVE), got {rc}"
    if rj["overall_status"] != "PASS":
        return False, f"Expected PASS, got {rj['overall_status']}"
    exc_used = rj.get("summary", {}).get("active_exceptions_used", 0)
    if exc_used == 0:
        return False, "Expected at least 1 exception used"
    return True, f"Valid approved exception correctly exempted CVE → PASS (exceptions_used={exc_used})"


# ─────────────────────────────────────────────────────────────
# TC-GATE-05: Expired exception → FAIL
# ─────────────────────────────────────────────────────────────
def tc05_setup(tmpdir):
    past_date = (date.today() - timedelta(days=1)).isoformat()
    os_vuln = [{
        "VulnerabilityID": "CVE-2099-22222", "PkgName": "libtest2",
        "InstalledVersion": "1.0", "FixedVersion": None,
        "Severity": "HIGH", "Title": "Test expired exception CVE"
    }]
    exc = [{
        "id": "EXC-TEST-002", "cve_id": "CVE-2099-22222",
        "package_name": "libtest2", "status": "APPROVED",
        "expires_at": past_date,
        "rationale": "EXPIRED test exception"
    }]
    write_fixtures(tmpdir,
        policy=make_policy("enforce"),
        exceptions=make_exceptions(exc),
        semgrep=make_semgrep_report([]),
        trivy_fs=make_trivy_fs_report([]),
        trivy_image=make_trivy_image_report(os_vulns=os_vuln, app_vulns=[]),
        gitleaks=make_gitleaks_report([]),
        zap=make_zap_report([])
    )
    return run_gate(tmpdir, mode="enforce")


def tc05_assert(rc, rj):
    if rc != 1:
        return False, f"Expected exit code 1 (expired exception), got {rc}"
    if rj["overall_status"] != "FAIL":
        return False, f"Expected FAIL, got {rj['overall_status']}"
    violations = rj.get("violations", [])
    expired = [v for v in violations if "EXPIRED" in v.get("message", "")]
    if not expired:
        return False, "Expected EXPIRED message in violations"
    return True, f"Expired exception correctly triggers FAIL (expired_violations={len(expired)})"


# ─────────────────────────────────────────────────────────────
# TC-GATE-06: Malformed JSON report → exit code 2
# ─────────────────────────────────────────────────────────────
def tc06_setup(tmpdir):
    write_fixtures(tmpdir,
        policy=make_policy("enforce"),
        exceptions=make_exceptions([]),
        semgrep=make_semgrep_report([]),
        trivy_fs=make_trivy_fs_report([]),
        trivy_image=make_trivy_image_report([], []),
        gitleaks=make_gitleaks_report([]),
        zap=make_zap_report([])
    )
    # Overwrite gitleaks with invalid JSON
    bad_path = os.path.join(tmpdir, "gitleaks.json")
    with open(bad_path, "w") as f:
        f.write("{THIS IS NOT VALID JSON{{{{")
    return run_gate(tmpdir, mode="enforce")


def tc06_assert(rc, rj):
    if rc != 2:
        return False, f"Expected exit code 2 (malformed JSON), got {rc}"
    return True, f"Malformed JSON correctly returned exit code 2 (system error)"


# ─────────────────────────────────────────────────────────────
# TC-GATE-07: Mandatory report file missing → exit code 2
# ─────────────────────────────────────────────────────────────
def tc07_setup(tmpdir):
    write_fixtures(tmpdir,
        policy=make_policy("enforce"),
        exceptions=make_exceptions([]),
        semgrep=make_semgrep_report([]),
        trivy_fs=make_trivy_fs_report([]),
        trivy_image=make_trivy_image_report([], []),
        gitleaks=make_gitleaks_report([]),
        zap=make_zap_report([])
    )
    # Remove mandatory gitleaks report
    os.remove(os.path.join(tmpdir, "gitleaks.json"))
    return run_gate(tmpdir, mode="enforce")


def tc07_assert(rc, rj):
    if rc != 2:
        return False, f"Expected exit code 2 (missing file), got {rc}"
    return True, "Missing mandatory report correctly returned exit code 2"


# ─────────────────────────────────────────────────────────────
# TC-GATE-08: Audit mode with violations → AUDIT_WARNING, exit 0
# ─────────────────────────────────────────────────────────────
def tc08_setup(tmpdir):
    os_vuln = [{
        "VulnerabilityID": "CVE-2099-33333", "PkgName": "libtest3",
        "InstalledVersion": "1.0", "FixedVersion": None,
        "Severity": "HIGH", "Title": "Test audit-mode CVE"
    }]
    write_fixtures(tmpdir,
        policy=make_policy("audit"),
        exceptions=make_exceptions([]),
        semgrep=make_semgrep_report([]),
        trivy_fs=make_trivy_fs_report([]),
        trivy_image=make_trivy_image_report(os_vulns=os_vuln, app_vulns=[]),
        gitleaks=make_gitleaks_report([]),
        zap=make_zap_report([])
    )
    return run_gate(tmpdir, mode="audit")


def tc08_assert(rc, rj):
    if rc != 0:
        return False, f"Expected exit code 0 (audit mode does not block), got {rc}"
    if rj["overall_status"] != "AUDIT_WARNING":
        return False, f"Expected AUDIT_WARNING, got {rj['overall_status']}"
    violations = rj.get("violations", [])
    if len(violations) == 0:
        return False, "Expected violations to be reported (but not blocking)"
    return True, f"Audit mode correctly returns AUDIT_WARNING with exit 0 (violations tracked: {len(violations)})"


# ─────────────────────────────────────────────────────────────
# Pytest test discovery wrappers
# ─────────────────────────────────────────────────────────────
def test_tc_gate_01_no_violations():
    tmpdir = tempfile.mkdtemp(prefix="tc01_")
    try:
        rc, rj, so, se = tc01_setup(tmpdir)
        ok, msg = tc01_assert(rc, rj)
        assert ok, msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_tc_gate_02_unexempted_high_cve():
    tmpdir = tempfile.mkdtemp(prefix="tc02_")
    try:
        rc, rj, so, se = tc02_setup(tmpdir)
        ok, msg = tc02_assert(rc, rj)
        assert ok, msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_tc_gate_03_secret_leak():
    tmpdir = tempfile.mkdtemp(prefix="tc03_")
    try:
        rc, rj, so, se = tc03_setup(tmpdir)
        ok, msg = tc03_assert(rc, rj)
        assert ok, msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_tc_gate_04_valid_approved_exception():
    tmpdir = tempfile.mkdtemp(prefix="tc04_")
    try:
        rc, rj, so, se = tc04_setup(tmpdir)
        ok, msg = tc04_assert(rc, rj)
        assert ok, msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_tc_gate_05_expired_exception():
    tmpdir = tempfile.mkdtemp(prefix="tc05_")
    try:
        rc, rj, so, se = tc05_setup(tmpdir)
        ok, msg = tc05_assert(rc, rj)
        assert ok, msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_tc_gate_06_malformed_json():
    tmpdir = tempfile.mkdtemp(prefix="tc06_")
    try:
        rc, rj, so, se = tc06_setup(tmpdir)
        ok, msg = tc06_assert(rc, rj)
        assert ok, msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_tc_gate_07_missing_mandatory_report():
    tmpdir = tempfile.mkdtemp(prefix="tc07_")
    try:
        rc, rj, so, se = tc07_setup(tmpdir)
        ok, msg = tc07_assert(rc, rj)
        assert ok, msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_tc_gate_08_audit_mode_warning():
    tmpdir = tempfile.mkdtemp(prefix="tc08_")
    try:
        rc, rj, so, se = tc08_setup(tmpdir)
        ok, msg = tc08_assert(rc, rj)
        assert ok, msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────
def main():
    print("\n" + "="*60)
    print("SECURITY QUALITY GATE — TEST SUITE")
    print("Dữ liệu: SYNTHETIC (giả lập logic)")
    print("Không thay thế thực nghiệm bảo mật thật")
    print("="*60)

    run_test("TC-GATE-01", "Không có vi phạm → PASS", tc01_setup, tc01_assert)
    run_test("TC-GATE-02", "CVE High OS chưa có exception → FAIL", tc02_setup, tc02_assert)
    run_test("TC-GATE-03", "Secret leak → FAIL", tc03_setup, tc03_assert)
    run_test("TC-GATE-04", "Exception hợp lệ được phê duyệt → PASS", tc04_setup, tc04_assert)
    run_test("TC-GATE-05", "Exception hết hạn → FAIL", tc05_setup, tc05_assert)
    run_test("TC-GATE-06", "JSON không hợp lệ → exit code 2", tc06_setup, tc06_assert)
    run_test("TC-GATE-07", "File báo cáo bắt buộc thiếu → exit code 2", tc07_setup, tc07_assert)
    run_test("TC-GATE-08", "Audit Mode có vi phạm → AUDIT_WARNING, exit 0", tc08_setup, tc08_assert)

    print("\n" + "="*60)
    print(f"TỔNG KẾT: {len(PASSED)}/{len(PASSED)+len(FAILED)} PASSED")
    if PASSED:
        print(f"  PASS: {', '.join(PASSED)}")
    if FAILED:
        print(f"  FAIL: {', '.join(FAILED)}")
    print("="*60)

    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
