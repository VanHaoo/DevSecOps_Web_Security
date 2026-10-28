# 🛡️ Báo Cáo Đánh Giá Security Quality Gate
**Trạng thái quyết định**: 🔴 **FAIL** | **Chế độ thực thi**: `ENFORCE` | **Ngày đánh giá**: `2026-10-28`

## 1. Tóm Tắt Kết Quả Kiểm Tra
- **Tổng số công cụ kiểm tra**: 6
- **Công cụ đạt chuẩn (PASS)**: 5
- **Công cụ vi phạm chính sách (FAIL)**: 1
- **Số lượng vi phạm chặn phát hành**: 49
- **Ngoại lệ hợp lệ được áp dụng**: 0
- **Cảnh báo theo dõi (Low/Info)**: 119

## 2. Chi Tiết Theo Từng Công Cụ
| Công cụ kiểm tra | Loại kiểm thử | Trạng thái | Chi tiết phát hiện |
| :--- | :--- | :---: | :--- |
| **unit_tests** | pytest functional and regression test suite | PASS | All unit tests passed successfully. |
| **gitleaks** | Secret and credential scanning | PASS | 0 leaks |
| **semgrep** | Static Application Security Testing | PASS | 0 SAST findings |
| **trivy_fs** | Software Composition Analysis (Filesystem) | PASS | 0 SCA CVEs |
| **trivy_image** | Container image vulnerability scanning | **FAIL** | 170 Image CVEs (0 exempted High) |
| **zap_dast** | Dynamic Application Security Testing | PASS | 9 DAST groups (26 instances) |

## 3. Danh Sách Vi Phạm Chặn Phát Hành
| STT | Công cụ | Mức độ | Mã phát hiện / Quy tắc | Chi tiết vi phạm |
| :---: | :--- | :---: | :--- | :--- |
| 1 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-013 not in APPROVED status (current: PENDING_REVIEW) |
| 2 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-022 not in APPROVED status (current: PENDING_REVIEW) |
| 3 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-031 not in APPROVED status (current: PENDING_REVIEW) |
| 4 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-040 not in APPROVED status (current: PENDING_REVIEW) |
| 5 | `trivy_image` | **HIGH** | `CVE-2026-54369` | Exception EXC-2026-011 not in APPROVED status (current: PENDING_REVIEW) |
| 6 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-014 not in APPROVED status (current: PENDING_REVIEW) |
| 7 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-023 not in APPROVED status (current: PENDING_REVIEW) |
| 8 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-032 not in APPROVED status (current: PENDING_REVIEW) |
| 9 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-041 not in APPROVED status (current: PENDING_REVIEW) |
| 10 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-015 not in APPROVED status (current: PENDING_REVIEW) |
| 11 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-024 not in APPROVED status (current: PENDING_REVIEW) |
| 12 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-033 not in APPROVED status (current: PENDING_REVIEW) |
| 13 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-042 not in APPROVED status (current: PENDING_REVIEW) |
| 14 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-016 not in APPROVED status (current: PENDING_REVIEW) |
| 15 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-025 not in APPROVED status (current: PENDING_REVIEW) |
| 16 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-034 not in APPROVED status (current: PENDING_REVIEW) |
| 17 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-043 not in APPROVED status (current: PENDING_REVIEW) |
| 18 | `trivy_image` | **HIGH** | `CVE-2025-69720` | Exception EXC-2026-001 not in APPROVED status (current: PENDING_REVIEW) |
| 19 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-017 not in APPROVED status (current: PENDING_REVIEW) |
| 20 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-026 not in APPROVED status (current: PENDING_REVIEW) |
| 21 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-035 not in APPROVED status (current: PENDING_REVIEW) |
| 22 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-044 not in APPROVED status (current: PENDING_REVIEW) |
| 23 | `trivy_image` | **HIGH** | `CVE-2026-16742` | Exception EXC-2026-007 not in APPROVED status (current: PENDING_REVIEW) |
| 24 | `trivy_image` | **HIGH** | `CVE-2025-69720` | Exception EXC-2026-002 not in APPROVED status (current: PENDING_REVIEW) |
| 25 | `trivy_image` | **HIGH** | `CVE-2026-16742` | Exception EXC-2026-008 not in APPROVED status (current: PENDING_REVIEW) |
| 26 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-018 not in APPROVED status (current: PENDING_REVIEW) |
| 27 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-027 not in APPROVED status (current: PENDING_REVIEW) |
| 28 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-036 not in APPROVED status (current: PENDING_REVIEW) |
| 29 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-045 not in APPROVED status (current: PENDING_REVIEW) |
| 30 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-019 not in APPROVED status (current: PENDING_REVIEW) |
| 31 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-028 not in APPROVED status (current: PENDING_REVIEW) |
| 32 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-037 not in APPROVED status (current: PENDING_REVIEW) |
| 33 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-046 not in APPROVED status (current: PENDING_REVIEW) |
| 34 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-020 not in APPROVED status (current: PENDING_REVIEW) |
| 35 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-029 not in APPROVED status (current: PENDING_REVIEW) |
| 36 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-038 not in APPROVED status (current: PENDING_REVIEW) |
| 37 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-047 not in APPROVED status (current: PENDING_REVIEW) |
| 38 | `trivy_image` | **HIGH** | `CVE-2025-69720` | Exception EXC-2026-003 not in APPROVED status (current: PENDING_REVIEW) |
| 39 | `trivy_image` | **HIGH** | `CVE-2025-69720` | Exception EXC-2026-004 not in APPROVED status (current: PENDING_REVIEW) |
| 40 | `trivy_image` | **HIGH** | `CVE-2026-9538` | Exception EXC-2026-050 not in APPROVED status (current: PENDING_REVIEW) |
| 41 | `trivy_image` | **HIGH** | `CVE-2026-76642` | Exception EXC-2026-021 not in APPROVED status (current: PENDING_REVIEW) |
| 42 | `trivy_image` | **HIGH** | `CVE-2026-78408` | Exception EXC-2026-030 not in APPROVED status (current: PENDING_REVIEW) |
| 43 | `trivy_image` | **HIGH** | `CVE-2026-78409` | Exception EXC-2026-039 not in APPROVED status (current: PENDING_REVIEW) |
| 44 | `trivy_image` | **HIGH** | `CVE-2026-78410` | Exception EXC-2026-048 not in APPROVED status (current: PENDING_REVIEW) |
| 45 | `trivy_image` | **MEDIUM** | `CVE-2025-8869` | Unfixed application vulnerability: pip: pip missing checks on symbolic link extraction |
| 46 | `trivy_image` | **MEDIUM** | `CVE-2026-13346` | Unfixed application vulnerability: pip: pip: Arbitrary file installation via malicious package indexes |
| 47 | `trivy_image` | **MEDIUM** | `CVE-2026-3219` | Unfixed application vulnerability: pip: pip: Incorrect file installation due to improper archive handling |
| 48 | `trivy_image` | **MEDIUM** | `CVE-2026-6357` | Unfixed application vulnerability: pip: pip: Arbitrary code execution or information disclosure via malicious wheel package installation |
| 49 | `trivy_image` | **MEDIUM** | `CVE-2026-8643` | Unfixed application vulnerability: python-pip: Path traversal via malicious entry point name in pip wheel installation allows arbitrary file overwrite |

*Exit code trả về cho CI/CD pipeline: `1`*