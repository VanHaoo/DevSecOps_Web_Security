# DevSecOps Web Security Lab

Dự án đồ án môn An toàn thông tin: **Tích hợp kiểm soát an toàn vào vòng đời phát triển ứng dụng Web**.

---

## 1. Giới thiệu dự án

Dự án mô phỏng ứng dụng Web quản lý sản phẩm hoàn chỉnh và an toàn ở **Giai đoạn 1**, làm nền tảng (baseline) để tích hợp các quy trình kiểm thử và tự động hoá an ninh DevSecOps (SAST, SCA, Secret Scanning, SBOM, DAST, Quality Gate) trong các giai đoạn tiếp theo.

### Công nghệ sử dụng
- **Backend Framework**: Python (Flask 3.1.1)
- **Database & ORM**: SQLite & SQLAlchemy (2.0.36) / Flask-SQLAlchemy (3.1.1)
- **Authentication**: Flask-Login (0.6.3), Werkzeug Security (băm mật khẩu an toàn)
- **Form & Validation**: Flask-WTF (1.2.2), WTForms (CSRF protection)
- **Frontend**: Bootstrap 5.3, Bootstrap Icons, Custom CSS
- **WSGI Production Server**: Gunicorn (23.0.0)
- **Containerization**: Docker (Multi-stage/Best practices, Non-root user) & Docker Compose
- **Testing**: pytest (8.3.4), pytest-cov (6.0.0)

---

## 2. Cấu trúc thư mục

```text
DevSecOps_Web_Security/
├── .github/
│   └── workflows/          # Cấu hình GitHub Actions CI/CD (các giai đoạn sau)
├── app/
│   ├── blueprints/         # Phân chia module chức năng
│   │   ├── admin/          # Quản trị viên (CRUD sản phẩm, quản lý user)
│   │   ├── auth/           # Đăng ký, đăng nhập, đăng xuất, hồ sơ
│   │   ├── main/           # Trang chủ, endpoint /health
│   │   └── products/       # Xem danh sách, tìm kiếm, chi tiết sản phẩm
│   ├── static/             # CSS & Static assets
│   ├── templates/          # 10 Jinja2 Templates (Bootstrap 5.3)
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
│   │   └── base.html       # Layout gốc điều hướng theo vai trò (RBAC)
│   ├── __init__.py         # Application Factory & khởi tạo extensions
│   ├── forms.py            # Form validation & CSRF protection
│   └── models.py           # SQLAlchemy Data Models (User, Product)
├── docker/                 # Cấu hình mở rộng cho container
├── docs/                   # Tài liệu kỹ thuật dự án
│   └── architecture.md     # Tài liệu thiết kế kiến trúc
├── evidence/               # Thư mục lưu kết quả kiểm thử và bằng chứng an toàn
├── scripts/
│   └── seed_db.py          # Script nạp dữ liệu mẫu giả lập
├── tests/
│   ├── conftest.py         # Fixtures cho pytest (SQLite in-memory)
│   └── test_app.py         # Test suite kiểm thử toàn diện (32 test cases)
├── .env.example            # Mẫu biến môi trường
├── .gitignore              # Loại trừ file nhạy cảm, db runtime, venv
├── compose.yaml            # Docker Compose chạy dịch vụ
├── Dockerfile              # Dockerfile chạy ứng dụng với Gunicorn & non-root user
├── pyproject.toml          # Cấu hình pytest
├── requirements.txt        # Danh sách thư viện phụ thuộc
├── wsgi.py                 # Entry point cho WSGI server
└── README.md               # Tài liệu hướng dẫn sử dụng
```

---

## 3. Hướng dẫn cài đặt và chạy trên Windows (PowerShell)

### 3.1. Yêu cầu môi trường
- Python 3.12+ (đã hỗ trợ và kiểm thử trên Python 3.15.1)
- Git
- PowerShell

### 3.2. Cài đặt Virtual Environment & Dependencies
```powershell
# Chuyển vào thư mục dự án
cd "DevSecOps_Web_Security"

# Tạo môi trường ảo
python -m venv venv

# Kích hoạt môi trường ảo
.\venv\Scripts\Activate.ps1

# Cài đặt thư viện
pip install -r requirements.txt
```

### 3.3. Khởi tạo Database và Dữ liệu mẫu
```powershell
$env:PYTHONPATH="."
python scripts/seed_db.py
```
*Tài khoản thử nghiệm mặc định:*
- **Admin**: `admin` / `Admin@123456`
- **User**: `user1` / `User@123456`

### 3.4. Khởi chạy ứng dụng trực tiếp (Development)
```powershell
$env:PYTHONPATH="."
$env:FLASK_APP="wsgi.py"
python -m flask run --host=127.0.0.1 --port=5000
```
Truy cập tại: `http://127.0.0.1:5000`

---

## 4. Hướng dẫn chạy bằng Docker & Docker Compose

Dự án đã cấu hình chạy với **Gunicorn WSGI Server** (chuẩn production), user `appuser` (non-root), health check tự động và chỉ mở port nội bộ `127.0.0.1:5000`.

### 4.1. Khởi động container
```powershell
# Build và chạy ứng dụng nền
docker compose up -d --build
```

### 4.2. Khởi tạo dữ liệu mẫu trong container
```powershell
docker compose exec web python scripts/seed_db.py
```

### 4.3. Kiểm tra trạng thái và logs
```powershell
# Kiểm tra container và health status
docker compose ps

# Xem nhật ký hoạt động
docker compose logs -f
```

### 4.4. Dừng container
```powershell
docker compose down
```

---

## 5. Hướng dẫn chạy kiểm thử (pytest)

Toàn bộ test suite chạy trên database SQLite `:memory:` biệt lập, không ảnh hưởng đến dữ liệu thực nghiệm:

```powershell
.\venv\Scripts\python -m pytest tests/ -v
```

Kiểm tra độ bao phủ (coverage):
```powershell
.\venv\Scripts\python -m pytest --cov=app tests/
```

---

## 6. Kiểm tra Endpoint Giám sát `/health`

Endpoint: `GET /health`

Phản hồi mẫu:
```json
{
  "service": "DevSecOps Web Security Lab",
  "status": "healthy"
}
```

Kiểm tra nhanh bằng PowerShell:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/health"
```
