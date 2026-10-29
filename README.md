# DevSecOps Web Security

**Đề tài môn An toàn thông tin:** Tích hợp kiểm soát an toàn vào vòng đời phát triển ứng dụng Web.

Dự án xây dựng một **ứng dụng Web quản lý sản phẩm bằng Flask** làm đối tượng kiểm thử, đồng thời tích hợp các bước kiểm tra an toàn vào **GitHub Actions CI/CD**. Trọng tâm là phát hiện vấn đề sớm, lưu minh chứng trước–sau khắc phục và sử dụng **Security Quality Gate** để đánh giá điều kiện phát hành.

> **Phạm vi:** Đây là môi trường thực nghiệm phục vụ môn học, **không phải hệ thống đã được xác nhận an toàn để triển khai công khai lên Internet**. Mã nguồn và kết quả quét có thể chứa các cảnh báo chưa được xử lý.

## 1. Chức năng và công nghệ

**Ứng dụng Web**

- Đăng ký, đăng nhập, đăng xuất và quản lý hồ sơ người dùng.
- Xem, tìm kiếm, lọc theo danh mục và xem chi tiết sản phẩm.
- Quản trị sản phẩm (thêm, sửa, xóa), theo dõi số lượng tồn kho và xem danh sách người dùng.
- Phân quyền theo vai trò **Admin/User**; kiểm tra đầu vào, CSRF token, password hashing và các HTTP security headers.

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

## 2. Cấu trúc repository

```text
DevSecOps_Web_Security/
├── .github/workflows/
│   └── devsecops-pipeline.yml      # Pipeline GitHub Actions (8 jobs)
├── app/
│   ├── blueprints/
│   │   ├── admin/                 # Quản trị sản phẩm và người dùng
│   │   ├── auth/                  # Đăng ký, đăng nhập, hồ sơ
│   │   ├── main/                  # Trang chủ và /health
│   │   └── products/              # Danh sách, tìm kiếm, chi tiết
│   ├── static/                    # CSS
│   ├── templates/                 # Giao diện Jinja2
│   ├── __init__.py                # Application Factory, security headers
│   ├── forms.py                   # Form validation, CSRF
│   └── models.py                  # User, Product
├── docs/
│   └── architecture.md            # Mô tả kiến trúc
├── evidence/
│   ├── remediation/
│   │   ├── baseline_immutable/    # Báo cáo trước khắc phục
│   │   └── rescan/                # Báo cáo quét lại sau khắc phục
│   └── quality-gate/
│       └── regression_test/       # Minh chứng kiểm thử hồi quy Gate
├── scripts/
│   ├── run_dast_scan.ps1
│   ├── run_security_scans.ps1
│   ├── run_security_scans.sh
│   ├── security_gate.py
│   └── seed_db.py
├── security/
│   ├── gitleaks/gitleaks.toml
│   ├── policies/
│   │   ├── security-policy.json
│   │   ├── exceptions.json
│   │   ├── exceptions-empty.json
│   │   └── exceptions-approved.json
│   ├── semgrep/semgrep-rules.yaml
│   └── zap/zap-baseline.conf
├── tests/
│   ├── conftest.py
│   ├── test_app.py
│   ├── test_remediation_security.py
│   └── test_security_gate.py
├── .env.example
├── .gitignore
├── .gitleaksignore
├── Dockerfile                     # Đặt ở thư mục gốc
├── compose.yaml                   # Đặt ở thư mục gốc
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── wsgi.py
└── README.md
```

Các thư mục `evidence/security-tooling/`, `evidence/dast/`, `evidence/ci-run/` và `evidence/test-reports/` là **đầu ra tự sinh** khi chạy công cụ hoặc CI; chúng được loại khỏi Git theo `.gitignore` và có thể chưa tồn tại sau khi clone. Hai file `Dockerfile` và `compose.yaml` được giữ ở **thư mục gốc** để Docker Compose build theo đường dẫn hiện tại.

## 3. Cài đặt và chạy bằng Docker (khuyến nghị)

**Yêu cầu:** Git, Docker Desktop (hoặc Docker Engine có Docker Compose), Internet khi tải image/thư viện lần đầu. Không cần cài Python và Flask trực tiếp trên máy nếu chỉ chạy website bằng Docker.

### Bước 1 — Clone dự án

```powershell
git clone https://github.com/VanHaoo/DevSecOps_Web_Security.git
cd DevSecOps_Web_Security
```

### Bước 2 — Thiết lập khóa phiên cho môi trường chạy

Sao chép tệp mẫu và thay giá trị `SECRET_KEY` bằng khóa ngẫu nhiên **của riêng máy bạn** (không commit `.env`):

```powershell
Copy-Item .env.example .env
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[Convert]::ToBase64String($bytes)
```

Lấy chuỗi ngẫu nhiên vừa in ra, mở `.env` và thay giá trị `SECRET_KEY`. Các lệnh trên dùng PowerShell, **không cần cài Python** trên máy chạy Docker. Cấu hình Docker Compose có giá trị fallback dùng cho lab; **không sử dụng fallback đó cho môi trường công khai**.

### Bước 3 — Build và khởi động

```powershell
docker compose up -d --build web
```

Docker sẽ build ứng dụng với Python và các thư viện trong `requirements.txt`, tạo container `web` và volume `sqlite_data` để lưu cơ sở dữ liệu SQLite.

### Bước 4 — Nạp dữ liệu mẫu

```powershell
docker compose exec web python scripts/seed_db.py
```

Script tạo **3 tài khoản và 8 sản phẩm mẫu** khi cơ sở dữ liệu chưa có người dùng. Nếu dữ liệu người dùng đã tồn tại, script sẽ bỏ qua để tránh tạo trùng.

| Vai trò | Tên đăng nhập | Mật khẩu mẫu |
| --- | --- | --- |
| Admin | `admin` | `Admin@123456` |
| User | `user1` | `User@123456` |

> Các tài khoản và mật khẩu này chỉ dùng để thực nghiệm. Không tái sử dụng khi triển khai hệ thống thật.

### Bước 5 — Truy cập và kiểm tra

- Website: <http://127.0.0.1:5000>
- Healthcheck: <http://127.0.0.1:5000/health>

```powershell
docker compose ps
docker compose logs --tail=100 web
```

Dừng ứng dụng bằng `docker compose down`. Volume `sqlite_data` vẫn được giữ lại; **`docker compose down -v` sẽ xóa volume và có thể làm mất dữ liệu**.

## 4. Chạy trực tiếp trên Windows (phát triển/kiểm thử)

Yêu cầu Python 3.12 và Git. Chạy các lệnh sau trong PowerShell tại thư mục dự án:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt

# Thiết lập cho phiên PowerShell hiện tại
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:DATABASE_URL = "sqlite:///app.db"

python scripts/seed_db.py
python -m flask --app wsgi run --host=127.0.0.1 --port=5000
```

Lưu ý: `.env.example` là **tệp mẫu**, không tự động bảo đảm các biến môi trường được nạp khi chạy Python trực tiếp. Ví dụ trên đặt biến môi trường cho phiên PowerShell hiện tại. Máy chủ Flask ở bước này dành cho phát triển, không phải cách triển khai công khai.

## 5. Kiểm thử tự động

Dự án có **49 test cases**: 32 bài kiểm thử chức năng ứng dụng, 9 bài kiểm thử cơ chế bảo mật và 8 bài kiểm thử Security Quality Gate.

```powershell
python -m pytest tests/ -q
python -m pytest tests/ --cov=app --cov-report=term-missing
```

Kết quả GitHub Actions ở commit `6405012b` ngày 28/10/2026: **49/49 tests passed**, **95% coverage**. Đây là kết quả của lần chạy được ghi nhận, không phải cam kết mọi lần chạy trong tương lai đều đạt.

## 6. GitHub Actions: Quy trình kiểm tra bảo mật

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

Các job có quan hệ phụ thuộc nên một số bước có thể chạy song song; Job 4 và 5 phụ thuộc Unit Testing. **Job 8 hiện chỉ kiểm tra điều kiện cho phép phát hành, chưa có thao tác triển khai ứng dụng lên máy chủ/cloud.**

### Chế độ của Security Quality Gate

Chính sách được khai báo tại [`security/policies/security-policy.json`](security/policies/security-policy.json), danh sách ngoại lệ chính thức tại [`security/policies/exceptions.json`](security/policies/exceptions.json).

| Chế độ | Hành vi |
| --- | --- |
| `audit` | Thu thập và báo cáo vấn đề. Nếu có vi phạm chính sách, kết quả là `AUDIT_WARNING` nhưng job có thể kết thúc thành công (`exit 0`). **Không cho phép phát hành.** |
| `enforce` | Nếu vi phạm chưa được xử lý hoặc không có ngoại lệ hợp lệ, Gate trả `FAIL` (`exit 1`) và chặn nhánh phát hành. |

Các lần push thông thường chạy ở `audit`. Để kiểm tra `enforce`, vào **Actions → DevSecOps CI/CD & Security Pipeline → Run workflow → gate_mode: enforce**. Việc push tag phát hành `v*` cũng sử dụng `enforce` theo workflow hiện tại.

**Quan trọng:** Workflow hiển thị màu xanh ở Audit Mode chỉ chứng minh các bước đã thực thi thành công, **không có nghĩa ứng dụng đã qua Security Quality Gate để phát hành**. File `exceptions-approved.json` phục vụ **bộ dữ liệu kiểm thử**; các ngoại lệ đang ở trạng thái `PENDING_REVIEW` trong `exceptions.json` không được tính là đã phê duyệt.

## 7. Kết quả thực nghiệm đã lưu

Các số liệu sau lấy từ các bản báo cáo lưu trong `evidence/remediation/` và **không phải số liệu trực tiếp của mọi lần chạy CI/CD**:

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
- Image sau khắc phục vẫn còn nhiều lỗ hổng từ gói hệ điều hành và thư viện; việc chạy container dưới quyền non-root chỉ là một biện pháp giảm thiểu rủi ro, không tương đương với vá CVE.

Ở lần chạy CI/CD thành công ngày **28/10/2026** ([run #40726692235](https://github.com/VanHaoo/DevSecOps_Web_Security/actions/runs/40726692235)), Security Quality Gate ghi nhận **`AUDIT_WARNING`, 49 vi phạm chính sách và 170 bản ghi CVE trong image**; ZAP ở lần chạy đó có **31 instances**. Đây là **lần quét khác** với báo cáo rescan 26 instances phía trên.

Các minh chứng được tổ chức tại:

- [`evidence/remediation/baseline_immutable/`](evidence/remediation/baseline_immutable/) — báo cáo gốc trước khắc phục.
- [`evidence/remediation/rescan/`](evidence/remediation/rescan/) — báo cáo sau khắc phục, kết quả Gate và SBOM.
- [`evidence/quality-gate/regression_test/`](evidence/quality-gate/regression_test/) — minh chứng kiểm thử hồi quy, bao gồm các tình huống PASS/FAIL/PASS trong điều kiện thử nghiệm được kiểm soát.

## 8. Xem và tải báo cáo GitHub Actions

1. Mở [GitHub Actions của dự án](https://github.com/VanHaoo/DevSecOps_Web_Security/actions).
2. Chọn workflow **DevSecOps CI/CD & Security Pipeline** và mở một lần chạy.
3. Chọn từng job để xem log; xem **Security Quality Gate** và phần **Summary** để biết trạng thái đánh giá.
4. Cuộn đến **Artifacts** để tải báo cáo (nếu artifact chưa hết hạn).

| Artifact | Nội dung |
| --- | --- |
| `unit-test-results` | JUnit XML, Coverage XML |
| `semgrep-report` | Báo cáo SAST dạng JSON |
| `gitleaks-report` | Báo cáo quét secret |
| `trivy-and-sbom-reports` | Trivy FS, Trivy image, SBOM CycloneDX |
| `dast-zap-reports` | OWASP ZAP HTML và JSON |
| `security-quality-gate-results` | Kết quả Gate JSON và bản tóm tắt Markdown |

Artifact thông thường được giữ **14 ngày** theo workflow; artifact Security Quality Gate được giữ **30 ngày**. Các minh chứng quan trọng đã được lưu riêng trong `evidence/remediation/` và `evidence/quality-gate/regression_test/`.

## 9. Lưu ý an toàn và giới hạn

- Chỉ chạy OWASP ZAP đối với ứng dụng thí nghiệm thuộc quyền kiểm soát của nhóm.
- Không commit `.env`, secret thật, dữ liệu cá nhân hoặc cơ sở dữ liệu chứa thông tin nhạy cảm.
- Không công khai cổng ứng dụng ra Internet chỉ vì container chạy bằng Gunicorn; cấu hình hiện tại phục vụ **localhost và HTTP**.
- Việc đánh giá CVE phụ thuộc phiên bản image và cơ sở dữ liệu lỗ hổng tại thời điểm quét. Các lần chạy sau có thể cho kết quả khác.
- Hệ thống chưa triển khai CD lên môi trường production; cần hoàn thiện quản lý secret, HTTPS, chính sách ngoại lệ và xử lý rủi ro còn tồn tại trước khi cân nhắc triển khai thực tế.

## 10. Tài liệu tham khảo trong repository

- [Thiết kế kiến trúc — `docs/architecture.md`](docs/architecture.md)
- [Pipeline — `devsecops-pipeline.yml`](.github/workflows/devsecops-pipeline.yml)
- [Security Policy — `security-policy.json`](security/policies/security-policy.json)
- [Security Gate Engine — `scripts/security_gate.py`](scripts/security_gate.py)

---

*Dự án học tập môn An toàn thông tin — Tích hợp kiểm soát an toàn vào vòng đời phát triển ứng dụng Web.*
