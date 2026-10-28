# Báo cáo Tổng hợp Kết quả Kiểm tra Bảo mật (Giai đoạn 2)

**Dự án:** DevSecOps_Web_Security  
**Nhánh:** `feature/security-tooling`  
**Ngày thực hiện:** 28/10/2026  
**Môi trường thực thi:** Docker Isolated Containers trên Windows 11  

---

## 1. Thông tin công cụ và thời gian thực thi

| Công cụ | Phân loại | Phiên bản | Container Image | Thời gian chạy | Kết quả chính |
|---|---|---|---|---|---|
| **Semgrep** | SAST (Static Analysis) | `1.109.0` | `semgrep/semgrep:1.109.0` | ~31.31s | 2 cảnh báo (0 lỗi nghiêm trọng) |
| **Trivy (FS)** | SCA (Dependency Scan) | `0.59.1` | `aquasec/trivy:0.59.1` | ~41.52s | 0 lỗ hổng trong `requirements.txt` |
| **Trivy (Image)** | Container Vuln Scan | `0.59.1` | `aquasec/trivy:0.59.1` | ~17.74s | 12 CVEs (Python) + 164 CVEs (Debian OS) |
| **Gitleaks** | Secret Scanning | `8.24.0` | `zricethezav/gitleaks:v8.24.0` | ~4.72s | 0 rò rỉ bí mật trong lịch sử Git |
| **Trivy (SBOM)** | SBOM Generator | `0.59.1` | `aquasec/trivy:0.59.1` | ~4.19s | CycloneDX 1.6 (113 components) |

---

## 2. Chi tiết kết quả từng công cụ

### 2.1. Semgrep – Static Application Security Testing (SAST)
- **Cấu hình luật:** Bộ quy tắc tùy chỉnh [security/semgrep/semgrep-rules.yaml](../../security/semgrep/semgrep-rules.yaml) kết hợp ruleset tiêu chuẩn `p/flask` và `p/owasp-top-ten`.
- **Số tệp quét:** 24 tệp mã nguồn Python/HTML.
- **Số phát hiện:** 2 cảnh báo (`WARNING`).

#### Bảng chi tiết phát hiện:
1. **Rule ID:** `security.semgrep.hardcoded-secret-key`
   - **Vị trí:** `app/__init__.py:33`
   - **Mã phát hiện:** `app.config['SECRET_KEY'] = 'test-secret-key'`
   - **CWE:** CWE-798 (Use of Hard-coded Credentials) | Mức độ: `WARNING`
   - **Đánh giá:** **False Positive (Dương tính giả) / Benign Finding**. Đây là cấu hình giả lập dành riêng cho môi trường unit test in-memory (`if config_name == 'testing'`). Trong môi trường production, ứng dụng nạp secret key từ biến môi trường qua `os.environ.get('SECRET_KEY')`.
2. **Rule ID:** `python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host`
   - **Vị trí:** `wsgi.py:7`
   - **Mã phát hiện:** `app.run(host='0.0.0.0', port=5000)`
   - **CWE:** CWE-668 (Exposure of Resource to Wrong Sphere) | Mức độ: `WARNING`
   - **Đánh giá:** **Cảnh báo cần lưu ý (Informational/Warning)**. Khối code này chỉ chạy khi chạy trực tiếp file `wsgi.py`. Trong môi trường container, ứng dụng chạy thông qua server chuẩn Gunicorn, và cổng mạng được giới hạn tại `127.0.0.1:5000` thông qua Docker Compose.

#### Giới hạn của Semgrep:
Semgrep phân tích cây cú pháp trừu tượng tĩnh (AST) nên **không thể** phát hiện:
- Lỗ hổng runtime/logic nghiệp vụ phức tạp (như bypass kiểm tra số dư, logic workflow bị đảo lộn).
- Lỗ hổng phụ thuộc vào trạng thái động của cơ sở dữ liệu hoặc phiên làm việc người dùng.
- Tấn công mạng thực tế (Network/TLS configuration, DNS rebinding, DDoS).
- Lỗ hổng bên trong các thư viện nhị phân đã biên dịch (compiled binaries).

---

### 2.2. Trivy – SCA và Quét Lỗ hổng Container

#### A. Quét mã nguồn & dependencies cục bộ (Trivy Filesystem):
- **Đối tượng:** `requirements.txt`
- **Kết quả:** **0 lỗ hổng**. Tất cả các thư viện chính được khai báo đều là các bản phát hành ổn định tại thời điểm ghim phiên bản.

#### B. Quét Docker Image (`devsecops_web_security-web:latest`):
Trivy phân tách rõ ràng 2 tầng lỗ hổng:

1. **Tầng thư viện Python (`lang-pkgs`):** Phát hiện **12 lỗ hổng**
   - **Werkzeug 3.1.3** (4 CVEs - Medium): `CVE-2025-66221`, `CVE-2026-102598`, `CVE-2026-21860`, `CVE-2026-27199` liên quan đến `safe_join()` và xử lý tên thiết bị trên Windows. Bản vá: nâng cấp lên `3.1.4+` hoặc `3.1.9`.
   - **Flask 3.1.1** (1 CVE - Low): `CVE-2026-27205` lộ thông tin qua cơ chế cache. Bản vá: `3.1.3`.
   - **pip 25.0.1** (6 CVEs - Medium/Low): `CVE-2025-8869`, `CVE-2026-13346`, `CVE-2026-3219`, `CVE-2026-6357`, `CVE-2026-8643`, `CVE-2026-1703` có sẵn trong base image Python của Docker.
   - **pytest 8.3.4** (1 CVE - Medium): `CVE-2025-71176`. Bản vá: `9.0.3`.

2. **Tầng Hệ điều hành Container (`debian 13.7`):** Phát hiện **164 lỗ hổng**
   - Phân bố: 44 HIGH, 58 MEDIUM, 61 LOW, 1 UNKNOWN.
   - Nguyên nhân: Các gói nhị phân của bản phân phối Debian (chẳng hạn `glibc`, `openssl`, `tar`, `perl`) thuộc base image `python:3.12-slim`.
   - **Đánh giá kiến trúc:** Đây là sự khác biệt cơ bản giữa SCA tầng mã nguồn ứng dụng và Container Scanning. Để giảm thiểu, trong các giai đoạn sau có thể áp dụng base image tối giản hơn (distroless hoặc alpine) hoặc áp dụng quy trình `apt-get upgrade` định kỳ.

---

### 2.3. Gitleaks – Secret Scanning
- **Đối tượng quét:** Toàn bộ lịch sử commit Git và thư mục làm việc của dự án.
- **Kết quả trên Git chính thức:** **0 rò rỉ bí mật (`no leaks found`)**.
- **Thực nghiệm khả năng phát hiện:** Tạo tệp tạm thời ngoài Git chứa token giả lập AWS (`AKIA[MOCK_AWS_TOKEN]`), Gitleaks đã phát hiện chính xác sau **77.2ms** với Rule ID `aws-access-token` và mức độ tin cậy cao. Tệp tạm đã được dọn dẹp ngay sau khi thực nghiệm.
- **Phân biệt quét thư mục hiện tại vs quét lịch sử Git:**
  - *Quét thư mục (Working Directory / `gitleaks dir`):* Chỉ kiểm tra trạng thái snapshot hiện tại của các file trên đĩa. Nếu nhà phát triển vô tình commit secret ở một commit cũ rồi sau đó xóa file ở commit mới, quét thư mục sẽ **bỏ sót hoàn toàn**.
  - *Quét lịch sử Git (`gitleaks detect`):* Duyệt qua toàn bộ cây commit (Git commits, blobs, diffs). Bất kỳ bí mật nào từng xuất hiện trong quá khứ dù đã bị xóa ở commit sau vẫn bị phát hiện và cảnh báo.

---

### 2.4. Trivy – Tạo Software Bill of Materials (SBOM)
- **Định dạng:** CycloneDX version 1.6 (JSON tiêu chuẩn quốc tế).
- **SBOM Docker Image ([sbom-image-cyclonedx.json](sbom-image-cyclonedx.json)):** Liệt kê chi tiết **113 components**, bao gồm cả 87 Debian packages tầng OS và 26 Python packages tầng runtime, đi kèm Package URL (`purl`) chuẩn hóa.
- **SBOM Filesystem ([sbom-fs-cyclonedx.json](sbom-fs-cyclonedx.json)):** Liệt kê 11 thư viện dependencies trực tiếp.

#### Ứng dụng của SBOM khi phát sinh CVE mới:
Khi một lỗ hổng Zero-day hoặc CVE mới được công bố (ví dụ: một thư viện con như `urllib3` hay `jinja2` bị lỗi nghiêm trọng):
1. **Tra cứu tức thì (Zero-Scan Query):** Thay vì phải build và chạy lại toàn bộ quy trình scan nặng nề, đội bảo mật chỉ cần đối chiếu SBOM JSON (sử dụng công cụ như Dependency-Track, Trivy hoặc jq) với mã CVE.
2. **Xác định chính xác phạm vi ảnh hưởng (Blast Radius):** SBOM cho biết ngay phiên bản bị ảnh hưởng có mặt trong container image cụ thể nào, digest bao nhiêu, đang triển khai ở đâu.
3. **Truy xuất nguồn gốc chuỗi cung ứng (Software Supply Chain):** SBOM CycloneDX cung cấp hàm băm (hashes), giấy phép (licenses) và định danh PURL giúp ngăn ngừa tấn công giả mạo gói mã độc (Dependency Confusion, Typosquatting).

---

## 3. Danh mục tệp báo cáo JSON đã xuất

Tất cả báo cáo được lưu trữ tập trung tại `evidence/security-tooling/`:
- `semgrep-report.json`: Kết quả phân tích SAST chi tiết.
- `trivy-fs-report.json`: Kết quả quét SCA tầng dependencies.
- `trivy-image-report.json`: Kết quả quét lỗ hổng Docker image và phân loại CVE.
- `gitleaks-report.json`: Kết quả quét secret scanning trên Git repository.
- `sbom-image-cyclonedx.json`: SBOM đầy đủ của container image (CycloneDX 1.6).
- `sbom-fs-cyclonedx.json`: SBOM tầng mã nguồn.
- `tool-versions.json`: Metadata thông tin công cụ, tag image và thời gian chạy.
- `run_security_scans.ps1` (trong `scripts/`): Script PowerShell thực thi tự động toàn bộ quy trình.
