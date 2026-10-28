# DevSecOps Web Security - Hệ thống quản lý sản phẩm

Dự án đồ án môn An toàn thông tin: **Tích hợp kiểm soát an toàn vào vòng đời phát triển ứng dụng Web (DevSecOps Pipeline)**.

---

## 1. Giới thiệu dự án

Dự án phát triển ứng dụng Web quản lý sản phẩm hoàn chỉnh, bảo mật làm nền tảng (baseline), đồng thời tích hợp toàn diện quy trình kiểm thử và tự động hoá an ninh DevSecOps (SAST, SCA, Secret Scanning, SBOM, DAST, Security Quality Gate và Release Gate) thông qua GitHub Actions CI/CD Pipeline 8 Jobs.

### Công nghệ sử dụng
- **Ngôn ngữ & Runtime**: Python 3.12 (Dockerfile) / Python 3.12+
- **Backend Framework**: Flask (3.1.3)
- **Database & ORM**: SQLite & SQLAlchemy (2.0.36) / Flask-SQLAlchemy (3.1.1)
- **Authentication**: Flask-Login (0.6.3), Werkzeug Security (3.1.9)
- **Form & Validation**: Flask-WTF (1.2.2), WTForms (3.3.1), email-validator (2.2.0)
- **Frontend**: Bootstrap 5.3.3 (SRI verified), Bootstrap Icons 1.11.3
- **WSGI Production Server**: Gunicorn (23.0.0)
- **Containerization**: Docker (Single-stage production image, non-root user `appuser`) & Docker Compose
- **Testing**: pytest (8.3.4), pytest-cov (6.0.0) — **49/49 tests passed**
- **Security Tooling**: Semgrep (SAST), Gitleaks (Secret Scanning), Trivy (SCA, Container Scanning, CycloneDX SBOM), OWASP ZAP (DAST)

---

## 2. Cấu trúc thư mục thực tế

```text
DevSecOps_Web_Security/
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml # CI/CD Pipeline 8 Jobs tích hợp Quality Gate
├── app/
│   ├── blueprints/                # Các module nghiệp vụ
│   │   ├── admin/                 # Bảng điều khiển admin, CRUD sản phẩm, quản lý users
│   │   ├── auth/                  # Đăng ký, đăng nhập, đăng xuất, hồ sơ
│   │   ├── main/                  # Trang chủ, endpoint giám sát /health
│   │   └── products/              # Danh sách, tìm kiếm, chi tiết sản phẩm
│   ├── static/                    # CSS & Static assets
│   ├── templates/                 # Giao diện Jinja2 Templates (Bootstrap 5.3)
│   │   ├── admin/                 # dashboard.html, product_form.html, users.html
│   │   ├── auth/                  # login.html, profile.html, register.html
│   │   ├── main/                  # index.html
│   │   ├── products/              # list.html, detail.html
│   │   └── base.html              # Layout gốc với điều hướng phân quyền (RBAC)
│   ├── __init__.py                # Application Factory & Security Headers Middleware
│   ├── forms.py                   # Form validation & CSRF protection
│   └── models.py                  # SQLAlchemy Models (User, Product)
├── docker/                        # Cấu hình phụ trợ container
├── docs/
│   └── architecture.md            # Tài liệu thiết kế kiến trúc hệ thống
├── evidence/                      # Thư mục lưu trữ bằng chứng thực nghiệm & baseline
│   ├── quality-gate/
│   │   └── regression_test/       # Dữ liệu kiểm thử hồi quy Gate (PASS -> FAIL -> PASS)
│   └── remediation/
│       ├── baseline_immutable/    # Báo cáo quét gốc trước khắc phục (bất biến)
│       └── rescan/                # Báo cáo quét sau khắc phục và đối soát
├── scripts/
│   ├── run_dast_scan.ps1          # Script chạy OWASP ZAP DAST scan
│   ├── run_security_scans.ps1     # Script quét an toàn tự động (PowerShell)
│   ├── run_security_scans.sh      # Script quét an toàn tự động (Bash)
│   ├── security_gate.py           # Security Quality Gate Engine
│   └── seed_db.py                 # Script nạp dữ liệu mẫu ban đầu
├── security/
│   ├── gitleaks/                  # Cấu hình gitleaks.toml
│   ├── policies/                  # security-policy.json, exceptions.json
│   ├── semgrep/                   # Quy tắc semgrep.yml
│   ├── trivy/                     # trivy.yaml
│   └── zap/                       # zap.yaml
├── tests/
│   ├── conftest.py                # Fixtures cho pytest (in-memory SQLite)
│   ├── test_app.py                # 32 unit & integration test cases
│   ├── test_remediation_security.py # 9 security control tests (CSP, SRI, Cookie,...)
│   └── test_security_gate.py      # 8 test cases kiểm thử logic Quality Gate
├── .env.example                   # Mẫu cấu hình biến môi trường
├── .gitignore                     # Bỏ qua file nhạy cảm & báo cáo quét tự sinh
├── .gitleaksignore                # Cấu hình bỏ qua false positive cho Gitleaks
├── compose.yaml                   # Docker Compose cấu hình service Web
├── Dockerfile                     # Dockerfile production image (Python 3.12, non-root)
├── pyproject.toml                 # Cấu hình pytest & coverage
├── requirements.txt               # Thư viện phụ thuộc production
├── requirements-dev.txt           # Thư viện phụ thuộc môi trường phát triển & CI
└── wsgi.py                        # Entry point khởi chạy ứng dụng WSGI
```

---

## 3. Hướng dẫn Clone và Khởi chạy

### 3.1. Clone mã nguồn
```powershell
git clone https://github.com/VanHaoo/DevSecOps_Web_Security.git
cd DevSecOps_Web_Security
```

### 3.2. Chạy nhanh bằng Docker & Docker Compose (Khuyến nghị)

Ứng dụng được đóng gói sẵn với **Gunicorn WSGI Server**, người dùng không đặc quyền `appuser` (non-root), health check tích hợp và bind nội bộ tại `127.0.0.1:5000`.

1. **Khởi động container**:
   ```powershell
   docker compose up -d --build
   ```

2. **Khởi tạo dữ liệu mẫu (Seed Database)**:
   ```powershell
   docker compose exec web python scripts/seed_db.py
   ```
   *Tài khoản thử nghiệm sẵn có:*
   - **Tài khoản Quản trị (Admin)**: `admin` / `Admin@123456`
   - **Tài khoản Người dùng (User)**: `user1` / `User@123456`

3. **Kiểm tra trạng thái & nhật ký**:
   ```powershell
   docker compose ps
   docker compose logs -f
   ```

4. **Truy cập ứng dụng**:
   - Website: `http://127.0.0.1:5000`
   - Endpoint kiểm tra sức khỏe: `http://127.0.0.1:5000/health`

5. **Dừng hệ thống**:
   ```powershell
   docker compose down
   ```

---

### 3.3. Chạy trực tiếp trên máy cục bộ (Môi trường phát triển)

1. **Tạo môi trường ảo và cài đặt thư viện**:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements-dev.txt
   ```

2. **Cấu hình biến môi trường và nạp database**:
   ```powershell
   Copy-Item .env.example .env
   $env:PYTHONPATH="."
   python scripts/seed_db.py
   ```

3. **Khởi chạy máy chủ phát triển Flask**:
   ```powershell
   $env:FLASK_APP="wsgi.py"
   python -m flask run --host=127.0.0.1 --port=5000
   ```

---

## 4. Chạy kiểm thử tự động (pytest)

Dự án có tổng cộng **49 bài kiểm thử** bao phủ toàn bộ chức năng, cơ chế bảo mật và quy tắc Quality Gate:
- 32 test cases chức năng ứng dụng, xác thực, phân quyền RBAC và xử lý lỗi (`tests/test_app.py`).
- 9 test cases kiểm soát an toàn kỹ thuật: CSP, Anti-clickjacking, Nosniff, Secure Cookie, Dynamic Test Secret Key, Subresource Integrity (`tests/test_remediation_security.py`).
- 8 test cases kiểm thử logic Security Quality Gate: pass/fail conditions, expired exceptions, missing mandatory reports, audit vs enforce mode (`tests/test_security_gate.py`).

Chạy toàn bộ 49 test cases:
```powershell
python -m pytest tests/ -v
```

Kiểm tra độ bao phủ mã nguồn (Code Coverage >= 90%):
```powershell
python -m pytest --cov=app --cov-report=term-missing tests/
```

---

## 5. Quy trình CI/CD Pipeline & Xem báo cáo trên GitHub Actions

Quy trình DevSecOps Pipeline được định nghĩa tại `.github/workflows/devsecops-pipeline.yml`, bao gồm **8 Jobs tuần tự và song song**:

1. **Job 1: Unit Testing (pytest)**: Chạy 49 tests, đo đạc coverage và xuất `coverage.xml`.
2. **Job 2: SAST (Semgrep)**: Quét mã nguồn tĩnh phát hiện lỗ hổng ứng dụng.
3. **Job 3: Secret Scanning (Gitleaks)**: Quét phát hiện khóa bí mật, token vô tình lọt vào commit.
4. **Job 4: SCA, Container Scan & SBOM (Trivy)**: Quét phụ thuộc thư viện, lỗ hổng base image và xuất SBOM định dạng CycloneDX.
5. **Job 5: DAST (OWASP ZAP)**: Khởi chạy container tạm thời, cấu hình quyền ghi báo cáo (`chown 1000:1000`) và thực hiện quét động baseline API/Web.
6. **Job 6: Pipeline Summary (Audit Mode)**: Tổng hợp kết quả quét toàn diện phục vụ kiểm toán.
7. **Job 7: Security Quality Gate**: Đánh giá dựa trên chính sách `security-policy.json` và danh sách ngoại lệ `exceptions.json`. Hỗ trợ 2 chế độ:
   - `audit`: Cảnh báo vi phạm nhưng không chặn pipeline (exit 0).
   - `enforce`: Chặn pipeline khi có vi phạm chưa được phê duyệt hợp lệ (exit 1).
8. **Job 8: Release & Deployment Gate**: Chỉ kích hoạt khi Job 7 chạy ở chế độ `enforce` và đạt trạng thái **PASS**.

### Cách xem báo cáo quét trên GitHub Actions
1. Truy cập tab **Actions** trên repository GitHub: `https://github.com/VanHaoo/DevSecOps_Web_Security/actions`.
2. Nhấn vào workflow run mới nhất.
3. **Xem tóm tắt trực quan**: Xem phần **Summary** ở cuối trang run để xem bảng kết quả Security Quality Gate.
4. **Tải Artifacts**: Tại mục **Artifacts** ở cuối trang, tải về các tệp báo cáo chi tiết:
   - `unit-test-results`: Báo cáo kiểm thử JUnit và Coverage XML.
   - `semgrep-report`: Kết quả phân tích tĩnh SAST (JSON/SARIF).
   - `gitleaks-report`: Kết quả rà soát khóa bí mật.
   - `trivy-and-sbom-reports`: Báo cáo SCA, lỗ hổng Image và CycloneDX SBOM (JSON).
   - `dast-zap-reports`: Báo cáo quét động OWASP ZAP (HTML & JSON).
   - `security-quality-gate-results`: Kết quả và tóm tắt đánh giá Gate.
