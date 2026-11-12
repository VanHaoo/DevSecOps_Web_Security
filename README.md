# DevSecOps Web Security

**Đề tài môn An toàn thông tin:** Tích hợp kiểm soát an toàn vào vòng đời phát triển ứng dụng Web.

Dự án xây dựng một **ứng dụng Web quản lý sản phẩm bằng Flask** làm đối tượng kiểm thử, đồng thời tích hợp các bước kiểm tra an toàn vào **GitHub Actions CI/CD**. Trọng tâm là phát hiện vấn đề sớm, lưu minh chứng trước–sau khắc phục và sử dụng **Security Quality Gate** để đánh giá điều kiện phát hành.

> **Phạm vi:** Đây là môi trường thực nghiệm phục vụ môn học, **không phải hệ thống đã được xác nhận an toàn để triển khai công khai lên Internet**. Mã nguồn và kết quả quét có thể chứa các cảnh báo chưa được xử lý.

## 1. Chức năng và công nghệ

**Ứng dụng Web**

- Đăng ký, đăng nhập, **đăng xuất bảo mật (POST + CSRF)** và quản lý hồ sơ người dùng.
- Xem, tìm kiếm, lọc theo danh mục và xem chi tiết sản phẩm.
- Quản trị sản phẩm (thêm, sửa, xóa), theo dõi số lượng tồn kho và xem danh sách người dùng.
- Phân quyền theo vai trò **Admin/User**; kiểm tra đầu vào, CSRF token, password hashing và các HTTP security headers.
- **Open Redirect protection:** tham số `next` được xác thực — chỉ chấp nhận đường dẫn nội bộ.

**Công nghệ chính**

| Nhóm | Công nghệ |
| --- | --- |
| Backend | Python 3.12, Flask 3.1.3, Gunicorn 23.0.0 |
| Cơ sở dữ liệu | SQLite, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.0.36 |
| Xác thực & biểu mẫu | Flask-Login 0.6.3, Flask-WTF 1.2.2, WTForms 3.3.1, Werkzeug 3.1.9 |
| Giao diện | Jinja2, Bootstrap 5.3.3, Bootstrap Icons 1.11.3 |
| Đóng gói | Docker, Docker Compose; ứng dụng chạy dưới tài khoản không đặc quyền `appuser` |
| Kiểm thử | pytest 8.3.4, pytest-cov 6.0.0 |
| Quét bảo mật | Semgrep, Gitleaks, Trivy, OWASP ZAP |
| SBOM | CycloneDX, tạo bằng Trivy |
| CI/CD | GitHub Actions, Security Quality Gate |

## 2. Cấu trúc repository đầy đủ

Dưới đây là **toàn bộ file đang được Git theo dõi** trên nhánh hiện tại. Cây đã mở rộng đến tên file cụ thể.

```text
DevSecOps_Web_Security/
├── .github/  # GitHub Actions
│   └── workflows/
│       └── devsecops-pipeline.yml
├── app/  # Ứng dụng Flask
│   ├── blueprints/  # Các nhóm chức năng Flask (flat module, không dùng sub-package)
│   │   ├── __init__.py  # Xuất tất cả 4 blueprints
│   │   ├── admin.py     # Quản trị viên (Dashboard, CRUD sản phẩm, User list)
│   │   ├── auth.py      # Xác thực (Đăng ký, Đăng nhập, Đăng xuất POST, Profile, is_safe_url)
│   │   ├── main.py      # Trang chủ và Health check endpoint
│   │   └── products.py  # Danh mục và chi tiết sản phẩm
│   ├── static/  # Tài nguyên tĩnh
│   │   └── css/
│   │       └── style.css
│   ├── templates/  # Giao diện HTML/Jinja2
│   │   ├── admin/
│   │   │   ├── dashboard.html
│   │   │   ├── product_form.html
│   │   │   └── users.html
│   │   ├── auth/
│   │   │   ├── login.html
│   │   │   ├── profile.html
│   │   │   └── register.html
│   │   ├── main/
│   │   │   └── index.html
│   │   ├── products/
│   │   │   ├── detail.html
│   │   │   └── list.html
│   │   └── base.html  # Layout chung, nút đăng xuất dùng POST form + CSRF token
│   ├── __init__.py  # Application Factory, security headers, 3-mode SECRET_KEY config
│   ├── forms.py     # Kiểm tra dữ liệu nhập, CSRF; InputRequired cho price/stock
│   └── models.py    # Mô hình User và Product
├── docs/  # Tài liệu kiến trúc
│   └── architecture.md
├── evidence/  # Minh chứng thực nghiệm (được lưu trong Git)
│   ├── quality-gate/  # Minh chứng đánh giá Gate
│   │   └── regression_test/  # Dữ liệu kiểm thử hồi quy PASS/FAIL/PASS
│   │       ├── gate-partA-secure.json
│   │       ├── gate-partA-secure.md
│   │       ├── gate-partB-regression-fail.json
│   │       ├── gate-partB-regression-fail.md
│   │       ├── gate-partC-restored-result.json
│   │       ├── gate-partC-restored-summary.md
│   │       ├── gate-regression-stepA-clean-pass.json
│   │       ├── gate-regression-stepB-vuln-fail.json
│   │       ├── gate-regression-stepB-vuln-fail.md
│   │       ├── gate-regression-stepC-restored-pass.json
│   │       ├── gitleaks-step1-clean.json
│   │       ├── gitleaks-step3-vuln.json
│   │       └── gitleaks-step5-restored.json
│   └── remediation/  # Minh chứng trước và sau khắc phục
│       ├── baseline_immutable/  # Bản gốc trước khắc phục — không chỉnh sửa
│       │   ├── gitleaks-report.json
│       │   ├── sbom-fs-cyclonedx.json
│       │   ├── sbom-image-cyclonedx.json
│       │   ├── security-summary.md
│       │   ├── semgrep-report.json
│       │   ├── tool-versions.json
│       │   ├── trivy-fs-report.json
│       │   ├── trivy-image-report.json
│       │   ├── zap-report.html
│       │   ├── zap-report.json
│       │   └── zap.yaml
│       └── rescan/  # Báo cáo quét lại sau khắc phục
│           ├── gitleaks-after.json
│           ├── sbom-cyclonedx-after.json
│           ├── security-gate-result.json
│           ├── security-gate-summary.md
│           ├── semgrep-after.json
│           ├── trivy-fs-after.json
│           ├── trivy-image-after.json
│           ├── zap-report-after.html
│           ├── zap-report-after.json
│           └── zap.yaml
├── scripts/  # Các script chạy công cụ và Security Gate
│   ├── run_security_scans.ps1  # Chạy Semgrep/Gitleaks/Trivy/ZAP trên Windows (-Type static|dast|all)
│   ├── run_security_scans.sh   # Chạy Semgrep/Gitleaks/Trivy/ZAP trên Linux (-t static|dast|all)
│   ├── security_gate.py        # Security Quality Gate
│   └── seed_db.py              # Tạo tài khoản và sản phẩm mẫu
├── security/  # Cấu hình bảo mật và chính sách
│   ├── gitleaks/
│   │   └── gitleaks.toml   # Quy tắc quét secret
│   ├── policies/
│   │   ├── exceptions-approved.json  # Dữ liệu kịch bản kiểm thử, không phải phê duyệt thực tế
│   │   ├── exceptions-empty.json
│   │   ├── exceptions.json           # Ngoại lệ chính thức — chưa phê duyệt
│   │   └── security-policy.json      # Ngưỡng đánh giá Gate
│   ├── semgrep/
│   │   └── semgrep-rules.yaml  # Quy tắc Semgrep
│   └── zap/
│       └── zap-baseline.conf   # Cấu hình ZAP baseline
├── tests/  # Kiểm thử tự động
│   ├── __init__.py
│   ├── conftest.py                  # Shared fixtures (app, db, client, users, products)
│   ├── test_app.py                  # Kiểm thử chức năng + bảo mật + CSRF
│   ├── test_remediation_security.py # Kiểm thử headers, session, SECRET_KEY, SRI
│   └── test_security_gate.py        # Kiểm thử Security Quality Gate logic
├── .env.example       # Mẫu biến môi trường (có hướng dẫn tiếng Việt đầy đủ)
├── .gitignore
├── .gitleaksignore
├── compose.yaml       # Chạy container web và volume SQLite
├── Dockerfile         # Build image ứng dụng Flask (không chứa SECRET_KEY hardcode)
├── pyproject.toml     # Cấu hình pytest
├── README.md          # Hướng dẫn dự án
├── requirements-dev.txt  # Thư viện phát triển/pytest
├── requirements.txt      # Thư viện production
└── wsgi.py            # Entry point Gunicorn/Flask
```

**Lưu ý về thư mục tự sinh:** `evidence/security-tooling/`, `evidence/dast/`, `evidence/ci-run/`, `evidence/test-reports/`, `instance/`, `.venv/` và các thư mục cache có thể xuất hiện trên máy khi chạy ứng dụng hoặc các công cụ. Các đường dẫn này được Git bỏ qua; chúng **không phải phần thiếu của repository**.

## 3. Cài đặt và chạy bằng Docker (khuyến nghị)

**Yêu cầu:** Git, Docker Desktop (hoặc Docker Engine có Docker Compose), Internet khi tải image/thư viện lần đầu.

### Bước 1 — Clone dự án

```powershell
git clone https://github.com/VanHaoo/DevSecOps_Web_Security.git
cd DevSecOps_Web_Security
```

### Bước 2 — Thiết lập biến môi trường

Sao chép tệp mẫu và điền `SECRET_KEY` bằng khóa ngẫu nhiên **của riêng bạn**:

```powershell
Copy-Item .env.example .env
# Sinh khóa ngẫu nhiên (PowerShell, không cần Python):
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[Convert]::ToBase64String($bytes)
```

Lấy chuỗi vừa in ra, mở `.env` và gán vào `SECRET_KEY`. Xem `.env.example` để biết tất cả biến được hỗ trợ.

> **Production:** `SECRET_KEY` bắt buộc phải có và không được là các giá trị mặc định (`change-this-in-production`, `secret`, v.v.). Ứng dụng sẽ từ chối khởi động nếu thiếu hoặc dùng key không an toàn.
>
> **Lab/localhost HTTP:** Thêm `SESSION_COOKIE_SECURE=False` vào `.env` để cookie hoạt động qua HTTP (mặc định `True` trong production).

### Bước 3 — Build và khởi động

```powershell
docker compose up -d --build
```

Docker build ứng dụng với Python 3.12-slim, tạo container `web` chạy dưới user `appuser` (non-root) và volume `sqlite_data`.

### Bước 4 — Nạp dữ liệu mẫu

```powershell
docker compose exec web python scripts/seed_db.py
```

Script tạo **3 tài khoản và 8 sản phẩm mẫu** khi cơ sở dữ liệu chưa có người dùng. Nếu dữ liệu đã tồn tại, script bỏ qua để tránh tạo trùng.

| Vai trò | Tên đăng nhập | Mật khẩu mẫu |
| --- | --- | --- |
| Admin | `admin` | `Admin@123456` |
| User | `user1` | `User@123456` |

> Các tài khoản này chỉ dùng để thực nghiệm. Mật khẩu admin có thể đặt qua biến `ADMIN_INITIAL_PASSWORD` trong môi trường production.

### Bước 5 — Truy cập và kiểm tra

- Website: <http://127.0.0.1:5000>
- Healthcheck: <http://127.0.0.1:5000/health>

```powershell
docker compose ps
docker compose logs --tail=100 web
```

Dừng ứng dụng bằng `docker compose down`. Volume `sqlite_data` vẫn được giữ lại; **`docker compose down -v` sẽ xóa volume**.

## 4. Chạy trực tiếp trên Windows (phát triển/kiểm thử)

Yêu cầu Python 3.12 và Git:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# Thiết lập cho phiên PowerShell hiện tại
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:FLASK_ENV = "development"
$env:SESSION_COOKIE_SECURE = "False"   # localhost HTTP

python scripts/seed_db.py
python -m flask --app wsgi run --host=127.0.0.1 --port=5000
```

> `SESSION_COOKIE_SECURE=False` cần thiết khi chạy HTTP localhost để cookie đăng nhập hoạt động đúng. Trong production (HTTPS), giữ giá trị mặc định `True`.

## 5. Kiểm thử tự động

Dự án có **62 test cases** được tổ chức theo nhóm:

| Nhóm | File | Số test |
| --- | --- | --- |
| Chức năng ứng dụng + bảo mật + CSRF | `test_app.py` | 42 |
| Security headers, session, SECRET_KEY, SRI | `test_remediation_security.py` | 12 |
| Security Quality Gate | `test_security_gate.py` | 8 |

```powershell
# Chạy toàn bộ test
.\venv\Scripts\pytest -v

# Kèm coverage report
.\venv\Scripts\pytest --cov=app --cov-report=term-missing
```

**Kết quả hiện tại (nhánh `master`):** 62/62 tests passed — Coverage: **93%**.

> Coverage thấp hơn một chút do các nhánh production trong `app/__init__.py` và `auth.py` không được kích hoạt trong môi trường testing (đây là hành vi đúng — code path đó chỉ chạy khi `FLASK_ENV=production`).

## 6. Script kiểm thử bảo mật

Tất cả công cụ bảo mật được tích hợp trong **một script duy nhất** với tham số `-Type`:

```powershell
# Chạy SAST (Semgrep + Gitleaks + Trivy)
.\scripts\run_security_scans.ps1 -Type static

# Chạy DAST (khởi động app → ZAP → dừng app)
.\scripts\run_security_scans.ps1 -Type dast

# Chạy tất cả
.\scripts\run_security_scans.ps1 -Type all
```

Trên Linux/macOS:

```bash
bash scripts/run_security_scans.sh -t static
bash scripts/run_security_scans.sh -t dast
bash scripts/run_security_scans.sh -t all
```

## 7. GitHub Actions: Quy trình kiểm tra bảo mật

Workflow: [`.github/workflows/devsecops-pipeline.yml`](.github/workflows/devsecops-pipeline.yml). Workflow chạy khi push lên `master` hoặc `feature/**`, tạo Pull Request hướng vào `master`, push tag `v*`, hoặc chạy thủ công bằng **Run workflow**.

| Job | Mục đích |
| --- | --- |
| 1. Unit Testing | Chạy pytest, đo coverage và xuất JUnit XML |
| 2. SAST — Semgrep | Kiểm tra mã nguồn tĩnh bằng quy tắc bảo mật |
| 3. Secret Scanning — Gitleaks | Tìm khóa bí mật/token trong lịch sử mã nguồn |
| 4. SCA, Container Scan & SBOM — Trivy | Quét dependencies, Docker image và tạo CycloneDX SBOM |
| 5. DAST — OWASP ZAP Baseline | Khởi động ứng dụng trong Docker, quét động và lưu báo cáo |
| 6. Pipeline Summary | Kiểm tra các job công cụ đã chạy thành công hay chưa |
| 7. Security Quality Gate | Đối chiếu kết quả quét với chính sách và ngoại lệ |
| 8. Release & Deployment Gate | Xác nhận quyền phát hành **chỉ khi** Enforce Mode đạt `PASS` |

Các job có quan hệ phụ thuộc; Job 4 và 5 phụ thuộc Unit Testing. **Job 8 hiện chỉ kiểm tra điều kiện cho phép phát hành, chưa có thao tác triển khai lên máy chủ/cloud.**

### Chế độ của Security Quality Gate

Chính sách tại [`security/policies/security-policy.json`](security/policies/security-policy.json), ngoại lệ chính thức tại [`security/policies/exceptions.json`](security/policies/exceptions.json).

| Chế độ | Hành vi |
| --- | --- |
| `audit` | Thu thập và báo cáo vấn đề. Vi phạm → `AUDIT_WARNING` nhưng job kết thúc `exit 0`. **Không cho phép phát hành.** |
| `enforce` | Vi phạm chưa xử lý → Gate trả `FAIL` (`exit 1`) và chặn nhánh phát hành. |

Các lần push thông thường chạy ở `audit`. Để kiểm tra `enforce`, vào **Actions → Run workflow → gate_mode: enforce**.

**Quan trọng:** Workflow hiển thị màu xanh ở Audit Mode chỉ chứng minh các bước đã thực thi thành công, **không có nghĩa ứng dụng đã qua Security Quality Gate để phát hành**.

## 8. Kết quả thực nghiệm đã lưu

Các số liệu sau lấy từ các bản báo cáo lưu trong `evidence/remediation/`:

| Chỉ số | Baseline | Sau khắc phục |
| --- | ---: | ---: |
| Semgrep — số finding | 2 | 0 |
| Trivy filesystem — số bản ghi CVE | 6 | 0 |
| Trivy Docker image — số bản ghi CVE | 176 | 170 |
| OWASP ZAP — số instance được ghi nhận | 68 | 26 |
| CycloneDX SBOM (image) — số thành phần | 113 | 108 |
| Gitleaks — số secret phát hiện | 0 | 0 |

**Cách hiểu số liệu:**

- Semgrep ban đầu ghi nhận vấn đề `SECRET_KEY` hardcoded và cấu hình chạy ứng dụng; không có cơ sở kết luận đã sửa được SQL Injection hoặc XSS chỉ từ hai finding này.
- Kết quả ZAP trước–sau có **phạm vi URL được quét khác nhau**, nên mức giảm số instance không thể quy hoàn toàn cho hoạt động khắc phục.
- Image sau khắc phục vẫn còn nhiều lỗ hổng từ gói hệ điều hành; chạy container dưới quyền non-root là biện pháp giảm thiểu rủi ro, không tương đương vá CVE.

Ở lần chạy CI/CD thành công ngày **28/10/2026** ([run #40726692235](https://github.com/VanHaoo/DevSecOps_Web_Security/actions/runs/40726692235)), Security Quality Gate ghi nhận **`AUDIT_WARNING`, 49 vi phạm chính sách và 170 bản ghi CVE trong image**.

Các minh chứng được tổ chức tại:

- [`evidence/remediation/baseline_immutable/`](evidence/remediation/baseline_immutable/) — báo cáo gốc trước khắc phục.
- [`evidence/remediation/rescan/`](evidence/remediation/rescan/) — báo cáo sau khắc phục, kết quả Gate và SBOM.
- [`evidence/quality-gate/regression_test/`](evidence/quality-gate/regression_test/) — minh chứng kiểm thử hồi quy PASS/FAIL/PASS.

## 9. Xem và tải báo cáo GitHub Actions

1. Mở [GitHub Actions của dự án](https://github.com/VanHaoo/DevSecOps_Web_Security/actions).
2. Chọn workflow **DevSecOps CI/CD & Security Pipeline** và mở một lần chạy.
3. Chọn từng job để xem log; xem **Security Quality Gate** và phần **Summary**.
4. Cuộn đến **Artifacts** để tải báo cáo (nếu artifact chưa hết hạn).

| Artifact | Nội dung |
| --- | --- |
| `unit-test-results` | JUnit XML, Coverage XML |
| `semgrep-report` | Báo cáo SAST dạng JSON |
| `gitleaks-report` | Báo cáo quét secret |
| `trivy-and-sbom-reports` | Trivy FS, Trivy image, SBOM CycloneDX |
| `dast-zap-reports` | OWASP ZAP HTML và JSON |
| `security-quality-gate-results` | Kết quả Gate JSON và bản tóm tắt Markdown |

Artifact thông thường được giữ **14 ngày**; artifact Security Quality Gate được giữ **30 ngày**.

## 10. Lưu ý an toàn và giới hạn

- Chỉ chạy OWASP ZAP đối với ứng dụng thí nghiệm thuộc quyền kiểm soát của nhóm.
- Không commit `.env`, secret thật, dữ liệu cá nhân hoặc cơ sở dữ liệu chứa thông tin nhạy cảm.
- Không công khai cổng ứng dụng ra Internet; cấu hình hiện tại phục vụ **localhost và HTTP**.
- Việc đánh giá CVE phụ thuộc phiên bản image và cơ sở dữ liệu lỗ hổng tại thời điểm quét.
- Hệ thống chưa triển khai CD lên môi trường production; cần hoàn thiện quản lý secret, HTTPS, chính sách ngoại lệ trước khi cân nhắc triển khai thực tế.

## 11. Tài liệu tham khảo trong repository

- [Thiết kế kiến trúc — `docs/architecture.md`](docs/architecture.md)
- [Pipeline — `devsecops-pipeline.yml`](.github/workflows/devsecops-pipeline.yml)
- [Security Policy — `security-policy.json`](security/policies/security-policy.json)
- [Security Gate Engine — `scripts/security_gate.py`](scripts/security_gate.py)

---

*Dự án học tập môn An toàn thông tin — Tích hợp kiểm soát an toàn vào vòng đời phát triển ứng dụng Web.*
