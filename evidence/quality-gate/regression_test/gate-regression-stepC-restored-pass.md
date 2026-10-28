# 🛡️ Báo Cáo Đánh Giá Security Quality Gate
**Trạng thái quyết định**: 🟢 **PASS** | **Chế độ thực thi**: `ENFORCE` | **Ngày đánh giá**: `2026-10-28`

## 1. Tóm Tắt Kết Quả Kiểm Tra
- **Tổng số công cụ kiểm tra**: 6
- **Công cụ đạt chuẩn (PASS)**: 6
- **Công cụ vi phạm chính sách (FAIL)**: 0
- **Số lượng vi phạm chặn phát hành**: 0
- **Ngoại lệ hợp lệ được áp dụng**: 49
- **Cảnh báo theo dõi (Low/Info)**: 119

## 2. Chi Tiết Theo Từng Công Cụ
| Công cụ kiểm tra | Loại kiểm thử | Trạng thái | Chi tiết phát hiện |
| :--- | :--- | :---: | :--- |
| **unit_tests** | pytest functional and regression test suite | PASS | All unit tests passed successfully. |
| **gitleaks** | Secret and credential scanning | PASS | 0 leaks |
| **semgrep** | Static Application Security Testing | PASS | 0 SAST findings |
| **trivy_fs** | Software Composition Analysis (Filesystem) | PASS | 0 SCA CVEs |
| **trivy_image** | Container image vulnerability scanning | PASS | 170 Image CVEs (49 exempted High) |
| **zap_dast** | Dynamic Application Security Testing | PASS | 9 DAST groups (26 instances) |

## 4. Ngoại Lệ Được Áp Dụng Có Căn Cứ (49 ngoại lệ)
> Toàn bộ 44 CVE OS package Debian 13.7 (FixedVersion: None) được cấp ngoại lệ có thời hạn với kiểm soát bù trừ non-root.

*Exit code trả về cho CI/CD pipeline: `0`*