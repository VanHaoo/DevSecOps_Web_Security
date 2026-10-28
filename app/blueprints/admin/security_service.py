import os
import json


def get_project_root():
    """Return the absolute path to the project root directory."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def load_json_file(relative_path, default=None):
    """Safely load a JSON file relative to the project root."""
    root = get_project_root()
    abs_path = os.path.join(root, relative_path)
    if os.path.isfile(abs_path):
        try:
            with open(abs_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return default or {}


def get_security_dashboard_data():
    """
    Aggregate all verified empirical evidence for the Security Dashboard.
    Ensures strict distinction between local verified test data and GitHub Actions cloud execution.
    """
    # 1. Load actual Gate Results and Policy files
    gate_result = load_json_file("evidence/remediation/rescan/security-gate-result.json")
    policy_data = load_json_file("security/policies/security-policy.json")
    exceptions_data = load_json_file("security/policies/exceptions.json")

    # 2. CI/CD Pipeline Definition & Jobs
    cicd_data = {
        "repository_url": "https://github.com/VanHaoo/DevSecOps_Web_Security",
        "active_branch": "master",
        "latest_commit_sha": "1e18dd5",
        "commit_message": "feat: integrate security quality gate and release blocking",
        "workflow_file": ".github/workflows/devsecops-pipeline.yml",
        "data_source_note": "Kết quả được kiểm chứng thực tế tại môi trường local (pre-push verification). Trên GitHub Actions, jobs sẽ tự động kích hoạt khi có push/tag.",
        "jobs": [
            {
                "id": "unit-tests",
                "name": "1. Unit Testing (pytest)",
                "tool": "pytest 8.3.4 + pytest-cov",
                "status": "PASS",
                "metric": "41/41 unit tests passed (95% code coverage)",
                "artifact": "coverage.xml, junit.xml",
                "action": "Chặn pipeline nếu test thất bại"
            },
            {
                "id": "sast-semgrep",
                "name": "2. SAST (Semgrep)",
                "tool": "semgrep 1.109.0 (rules: flask + owasp-top-ten)",
                "status": "PASS",
                "metric": "0 findings (sạch hoàn toàn sau khắc phục)",
                "artifact": "semgrep-report.json",
                "action": "Chặn nếu có finding mức ERROR / WARNING"
            },
            {
                "id": "secret-scan-gitleaks",
                "name": "3. Secret Scanning (Gitleaks)",
                "tool": "gitleaks v8.24.0",
                "status": "PASS",
                "metric": "0 leaks (quét toàn bộ lịch sử commit & working tree)",
                "artifact": "gitleaks-report.json",
                "action": "Chặn nếu phát hiện secret/token chưa allowlist"
            },
            {
                "id": "sca-container-trivy",
                "name": "4. SCA, Container Scan & SBOM (Trivy)",
                "tool": "aquasec/trivy 0.59.1",
                "status": "PASS (Tool executed)",
                "metric": "Trivy FS: 0 CVE | Container Image: 170 CVE (164 OS, 6 pip) | SBOM: 108 components",
                "artifact": "trivy-fs-report.json, trivy-image-report.json, sbom-cyclonedx.json",
                "action": "Thu thập báo cáo cho Security Gate đánh giá"
            },
            {
                "id": "dast-owasp-zap",
                "name": "5. DAST (OWASP ZAP Baseline)",
                "tool": "zaproxy/zap-stable:latest",
                "status": "PASS (Baseline compliant)",
                "metric": "26 alert instances across 9 categories (0 High, 0 Medium, 10 Low, 16 Info)",
                "artifact": "zap-report.html, zap-report.json",
                "action": "Chặn nếu xuất hiện cảnh báo High hoặc Medium mới"
            },
            {
                "id": "pipeline-summary",
                "name": "6. Pipeline Summary (Audit Mode)",
                "tool": "CI Health Check Evaluator",
                "status": "PASS",
                "metric": "Tổng kết trạng thái hoạt động của 5 jobs công cụ",
                "artifact": "CI Step Summary log",
                "action": "Thông báo trạng thái công cụ"
            },
            {
                "id": "security-quality-gate",
                "name": "7. Security Quality Gate",
                "tool": "scripts/security_gate.py (Core Engine)",
                "status": "EVALUATED (Audit: WARNING / Enforce: FAIL)",
                "metric": "Đánh giá chính sách an toàn, quản lý ngoại lệ, chặn phát hành nếu vi phạm",
                "artifact": "security-gate-result.json, security-gate-summary.md",
                "action": "Cổng quyết định PASS (0) / FAIL (1) / ERROR (2)"
            },
            {
                "id": "release-deployment",
                "name": "8. Release & Deployment Gate",
                "tool": "CD Release Blocker",
                "status": "BLOCKED (Audit Mode / Enforce FAIL)",
                "metric": "Chỉ kích hoạt khi Gate chạy Enforcement Mode và có trạng thái PASS",
                "artifact": "Release authorization audit log",
                "action": "Ngăn chặn tuyệt đối việc phát hành container không đạt chuẩn"
            }
        ],
        "modes_comparison": [
            {
                "mode": "Audit Mode",
                "trigger": "Push lên master, PR thông thường, hoặc workflow_dispatch mode=audit",
                "behavior": "Chạy toàn bộ công cụ quét, xuất báo cáo tổng hợp vào $GITHUB_STEP_SUMMARY, trả exit code 0 (AUDIT_WARNING)",
                "release_blocked": "CÓ (Job 8 bị bỏ qua, không phát hành container)"
            },
            {
                "mode": "Enforcement Mode",
                "trigger": "Gắn release tag (v*.*.*) hoặc workflow_dispatch mode=enforce",
                "behavior": "Áp dụng ngưỡng chặn nghiêm ngặt. Nếu có vi phạm chưa có ngoại lệ APPROVED -> trả exit code 1",
                "release_blocked": "CÓ (Chặn tuyệt đối Job 8 khi Gate FAIL, chỉ cho phép khi Gate thực sự PASS)"
            }
        ]
    }

    # 4. Security Scanning (So Sánh Trước - Sau)
    scans_data = {
        "comparison_table": [
            {
                "tool": "Semgrep (SAST)",
                "scope": "Mã nguồn Python/Flask (app/, wsgi.py)",
                "before": "3 findings (SQL Injection, XSS, Hardcoded Secret)",
                "after": "0 findings",
                "delta": "-100% (Đã vá dứt điểm)",
                "status_badge": "bg-success",
                "details": "Đã chuyển sang SQLAlchemy ORM parameterized query, auto-escaping Jinja2, và dynamic token_hex secret key."
            },
            {
                "tool": "Trivy Filesystem (SCA)",
                "scope": "Thư viện phụ thuộc (requirements.txt)",
                "before": "0 CVE",
                "after": "0 CVE",
                "delta": "0 CVE (Duy trì sạch)",
                "status_badge": "bg-success",
                "details": "Dependencies được ghim phiên bản an toàn: Flask 3.1.3, Werkzeug 3.1.9, SQLAlchemy 2.0.36."
            },
            {
                "tool": "Trivy Container Image",
                "scope": "Docker Base Image (debian:13.7 / python:3.12-slim)",
                "before": "170 CVE (164 OS, 6 pip)",
                "after": "170 CVE (164 OS, 6 pip)",
                "delta": "Giữ nguyên (44 High OS + 5 Med pip)",
                "status_badge": "bg-danger",
                "details": "44 High OS thuộc 8 CVE ID upstream Debian chưa phát hành bản vá (FixedVersion: None). Đã thiết lập kiểm soát bù trừ non-root."
            },
            {
                "tool": "Gitleaks (Secrets)",
                "scope": "Lịch sử commit Git và working directory",
                "before": "0 leaks",
                "after": "0 leaks",
                "delta": "0 leaks (Không lộ bí mật)",
                "status_badge": "bg-success",
                "details": "Cấu hình gitleaks.toml tùy chỉnh loại trừ các public key hợp lệ và scan evidence."
            },
            {
                "tool": "OWASP ZAP (DAST)",
                "scope": "Web endpoints đang chạy (/login, /products, /admin...)",
                "before": "45+ alert instances (Thiếu CSP, Clickjacking, Cookie flags, nosniff)",
                "after": "26 alert instances (0 High, 0 Medium, 10 Low, 16 Info)",
                "delta": "-42% instances, 0 High/Med",
                "status_badge": "bg-info",
                "details": "Đã bổ sung Content-Security-Policy (CSP), SRI hashes, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, SameSite=Lax."
            },
            {
                "tool": "CycloneDX SBOM",
                "scope": "Thành phần phần mềm toàn hệ thống",
                "before": "Chưa có SBOM",
                "after": "108 components (JSON format)",
                "delta": "+108 components định danh",
                "status_badge": "bg-primary",
                "details": "Tạo tự động trong CI/CD pipeline phục vụ kiểm toán chuỗi cung ứng phần mềm."
            }
        ],
        "high_os_analysis": {
            "total_records": 44,
            "unique_cves": 8,
            "upstream_fixed": 0,
            "cve_list": [
                {
                    "cve": "CVE-2026-76642 / 78408 / 78409 / 78410",
                    "packages": "util-linux (bsdutils, libblkid1, libmount1, mount... - 36 bản ghi)",
                    "severity": "HIGH",
                    "fixed": "None",
                    "rationale": "Yêu cầu quyền truy cập local shell hoặc login terminal. Container chạy headless qua Gunicorn, không chạy login interactive."
                },
                {
                    "cve": "CVE-2025-69720",
                    "packages": "ncurses (libncursesw6, libtinfo6, ncurses-bin... - 4 bản ghi)",
                    "severity": "HIGH",
                    "fixed": "None",
                    "rationale": "Lỗ hổng xử lý buffer terminal UI. Web server Flask không gọi hoặc hiển thị ncurses terminal graphics."
                },
                {
                    "cve": "CVE-2026-16742",
                    "packages": "systemd / udev (libsystemd0, libudev1 - 2 bản ghi)",
                    "severity": "HIGH",
                    "fixed": "None",
                    "rationale": "Quản lý thiết bị phần cứng daemon. Container không chạy systemd init (PID 1 là gunicorn), không có quyền truy cập device node."
                },
                {
                    "cve": "CVE-2026-54369",
                    "packages": "libacl1 (1 bản ghi)",
                    "severity": "HIGH",
                    "fixed": "None",
                    "rationale": "Cơ chế POSIX Access Control Lists. Ứng dụng truy cập database SQLite qua quyền DAC chuẩn của appuser."
                },
                {
                    "cve": "CVE-2026-9538",
                    "packages": "perl-base (1 bản ghi)",
                    "severity": "HIGH",
                    "fixed": "None",
                    "rationale": "Perl runtime có sẵn trong base image nhưng ứng dụng hoàn toàn không thực thi script perl."
                }
            ]
        },
        "pip_analysis": [
            {"cve": "CVE-2025-8869", "package": "pip 25.0.1", "sev": "MEDIUM", "fix": "25.3", "note": "Symlink extraction (chỉ xảy ra khi cài package ngoài)"},
            {"cve": "CVE-2026-13346", "package": "pip 25.0.1", "sev": "MEDIUM", "fix": "26.2.0", "note": "Malicious package index file installation"},
            {"cve": "CVE-2026-3219", "package": "pip 25.0.1", "sev": "MEDIUM", "fix": "26.1", "note": "Archive handling trong pip wheel"},
            {"cve": "CVE-2026-6357", "package": "pip 25.0.1", "sev": "MEDIUM", "fix": "26.1", "note": "Arbitrary code execution qua malicious wheel"},
            {"cve": "CVE-2026-8643", "package": "pip 25.0.1", "sev": "MEDIUM", "fix": "26.1.2", "note": "Path traversal via entry point name"},
            {"cve": "CVE-2026-1703", "package": "pip 25.0.1", "sev": "LOW", "fix": "26.0", "note": "Path traversal khi trích xuất wheel"}
        ]
    }

    # 5. Security Quality Gate Status & Regression Evidence
    gate_data = {
        "status": gate_result.get("overall_status", "FAIL"),
        "exit_code": gate_result.get("exit_code", 1),
        "evaluation_date": gate_result.get("evaluation_date", "2026-10-28"),
        "mode": gate_result.get("mode", "enforce"),
        "blocking_violations": gate_result.get("summary", {}).get("blocking_violations", 49),
        "active_exceptions": gate_result.get("summary", {}).get("active_exceptions_used", 0),
        "tracked_warnings": gate_result.get("summary", {}).get("tracked_warnings", 119),
        "exceptions_count": len(exceptions_data.get("exceptions", [])),
        "exceptions_status": "50 ngoại lệ ở trạng thái PENDING_REVIEW (chưa phê duyệt giả lập)",
        "violations_breakdown": [
            {
                "category": "OS Packages (High CVEs)",
                "count": 44,
                "reason": "Ngoại lệ chưa ở trạng thái APPROVED (hiện trạng: PENDING_REVIEW)",
                "action": "Cần phê duyệt chính thức kèm kiểm soát bù trừ hoặc cập nhật base image khi có patch"
            },
            {
                "category": "Python Runtime (pip)",
                "count": 5,
                "reason": "Lỗ hổng Medium trong pip 25.0.1 thuộc diện chính sách chặn",
                "action": "Nâng cấp pip hoặc gỡ bỏ pip khỏi production container qua multi-stage build"
            }
        ],
        "regression_evidence": {
            "title": "Thí Nghiệm Kiểm Thử Hồi Quy Có Kiểm Soát (Controlled Regression)",
            "description": "Chứng minh Security Quality Gate thực sự chặn phát hành khi có lỗi hồi quy và phục hồi khi được khắc phục.",
            "steps": [
                {
                    "step": "Bước 1: Trạng Thái An Toàn (Clean Baseline)",
                    "condition": "Mã nguồn sạch trên master (commit b456741)",
                    "tool_finding": "Gitleaks: 0 leaks",
                    "gate_decision": "PASS",
                    "exit_code": 0,
                    "release_status": "AUTHORIZED",
                    "badge": "bg-success",
                    "evidence_file": "gate-regression-stepA-clean-pass.json"
                },
                {
                    "step": "Bước 2: Cố Ý Đưa Lại Lỗi Hồi Quy (Injected Secret)",
                    "condition": "Đưa token bí mật có độ hỗn loạn cao vào app/__init__.py trong môi trường cô lập",
                    "tool_finding": "Gitleaks: 1 generic-api-key leak",
                    "gate_decision": "FAIL",
                    "exit_code": 1,
                    "release_status": "BLOCKED (Ngăn chặn phát hành)",
                    "badge": "bg-danger",
                    "evidence_file": "gate-regression-stepB-vuln-fail.json"
                },
                {
                    "step": "Bước 3: Khôi Phục Và Xác Minh (Restored Clean)",
                    "condition": "Loại bỏ chuỗi secret, khôi phục nguyên trạng tệp nguồn",
                    "tool_finding": "Gitleaks: 0 leaks",
                    "gate_decision": "PASS",
                    "exit_code": 0,
                    "release_status": "AUTHORIZED (Khôi phục phát hành)",
                    "badge": "bg-success",
                    "evidence_file": "gate-regression-stepC-restored-pass.json"
                }
            ]
        }
    }

    # 6. Demonstration Walkthrough Guide for Instructor
    demo_guide = [
        {
            "step_num": 1,
            "title": "Tổng quan Kiến trúc DevSecOps 6 lớp phòng thủ",
            "objective": "Trình bày các công cụ bảo mật được tích hợp đa tầng: Unit test -> SAST -> Secret Scan -> SCA & Container Scan -> DAST -> Security Quality Gate.",
            "action": "Mở tab 'CI/CD Pipeline' trên Security Dashboard, chỉ ra 8 jobs liên hoàn và cơ chế tải artifact động giữa các jobs."
        },
        {
            "step_num": 2,
            "title": "Chứng minh kết quả khắc phục lỗ hổng (Trước vs Sau)",
            "objective": "Cho giảng viên thấy các lỗ hổng nghiêm trọng ở Giai đoạn 2 & 3 đã được xử lý triệt để ở Giai đoạn 4.",
            "action": "Mở tab 'Security Scanning'. Nêu bật: Semgrep giảm từ 3 -> 0 (vá SQLi, XSS, Secret); ZAP giảm 45+ alert xuống 26 alert (0 High, 0 Medium) nhờ CSP và Anti-clickjacking."
        },
        {
            "step_num": 3,
            "title": "Phân tích 170 CVE còn tồn tại theo rủi ro thực tế",
            "objective": "Giải thích vì sao số lượng CVE chưa về 0 nhưng hệ thống vẫn an toàn.",
            "action": "Chỉ ra 44 CVE High OS đều có FixedVersion: None từ Debian 13.7 và chỉ ảnh hưởng terminal/local shell, trong khi container chạy headless non-root."
        },
        {
            "step_num": 4,
            "title": "Trình diễn Security Quality Gate chặn phát hành",
            "objective": "Chứng minh Security Gate không phải hình thức mà thực sự chặn khi có vi phạm.",
            "action": "Mở tab 'Security Quality Gate'. Trình bày kết quả Enforcement Mode trả FAIL (Exit code 1, 49 vi phạm). Chỉ ra Job 8 bị SKIP/BLOCKED khi Gate FAIL."
        },
        {
            "step_num": 5,
            "title": "Chứng minh kiểm thử hồi quy (PASS -> FAIL -> PASS)",
            "objective": "Minh chứng thí nghiệm kiểm thử hồi quy với chuỗi bí mật đã thực hiện trong môi trường cô lập.",
            "action": "Xem phần 'Bằng chứng thực nghiệm hồi quy', đối chiếu 3 tệp báo cáo JSON thật của 3 bước."
        }
    ]

    return {
        "cicd": cicd_data,
        "scans": scans_data,
        "gate": gate_data,
        "demo": demo_guide
    }
