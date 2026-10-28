# Tài liệu kiến trúc hệ thống

## 1. Tổng quan

Hệ thống quản lý sản phẩm là ứng dụng Web được xây dựng bằng Python (Flask), phục vụ làm ứng dụng mục tiêu cho đồ án tích hợp kiểm soát an toàn vào vòng đời phát triển phần mềm (DevSecOps).

Hệ thống cung cấp đầy đủ các chức năng nghiệp vụ thực tế:
- Quản lý danh mục sản phẩm (CRUD sản phẩm, phân loại, tìm kiếm, kiểm soát tồn kho).
- Xác thực và phân quyền người dùng (Role-Based Access Control: Admin và User).
- Quản trị người dùng và giám sát trạng thái hệ thống.

---

## 2. Mô hình kiến trúc runtime

```text
Client (Web Browser)
       │
       │ HTTP (Port 5000)
       ▼
┌────────────────────────────────────────────────────────┐
│                   Docker Container                     │
│  ┌──────────────────────────────────────────────────┐  │
│  │   Gunicorn WSGI Server (2 Workers, Non-root)     │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │                          │
│  ┌──────────────────────────▼───────────────────────┐  │
│  │                 Flask Application                │  │
│  │  - Blueprints (main, auth, products, admin)       │  │
│  │  - Security Middleware (CSP, Anti-clickjacking)  │  │
│  │  - CSRF Protection (Flask-WTF)                   │  │
│  │  - Authentication (Flask-Login + Werkzeug)       │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │                          │
│  ┌──────────────────────────▼───────────────────────┐  │
│  │             SQLAlchemy ORM (2.0.36)              │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │                          │
│  ┌──────────────────────────▼───────────────────────┐  │
│  │              SQLite Database (app.db)            │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

---

## 3. Công nghệ và Thư viện chính

| Thành phần | Công nghệ / Thư viện | Phiên bản | Vai trò kỹ thuật |
|---|---|---|---|
| **Ngôn ngữ nền tảng** | Python | 3.12 (Dockerfile) / 3.12+ | Môi trường runtime chính |
| **Web Framework** | Flask | 3.1.3 | Routing, MVC controller, application factory |
| **ORM** | SQLAlchemy / Flask-SQLAlchemy | 2.0.36 / 3.1.1 | Data abstraction, chống SQL Injection |
| **Authentication** | Flask-Login | 0.6.3 | Quản lý session và trạng thái người dùng |
| **Password Hashing** | Werkzeug | 3.1.9 | Băm mật khẩu chuẩn bảo mật an toàn |
| **Form & CSRF** | Flask-WTF / WTForms | 1.2.2 / 3.3.1 | Validation input và phòng chống tấn công CSRF |
| **Email Validation** | email-validator | 2.2.0 | Chuẩn hóa và kiểm tra định dạng email |
| **Database** | SQLite | 3 (file-based) | Lưu trữ dữ liệu ứng dụng |
| **WSGI Server** | Gunicorn | 23.0.0 | Production WSGI application server |
| **Container** | Docker & Docker Compose | Docker 24+ | Đóng gói môi trường thực thi chuẩn hóa |
| **Testing Framework** | pytest, pytest-cov | 8.3.4 / 6.0.0 | Kiểm thử tự động (49 test cases đạt 100%) |

---

## 4. Cấu trúc Module (Flask Blueprints)

Ứng dụng được tổ chức theo mẫu Application Factory (`create_app`):

- **`main` (`/`)**:
  - Trang chủ (`/`), hiển thị danh mục và giới thiệu hệ thống.
  - Endpoint giám sát trạng thái sức khỏe (`/health`).
- **`auth` (`/auth`)**:
  - Đăng ký tài khoản (`/auth/register`).
  - Đăng nhập (`/auth/login`), Đăng xuất (`/auth/logout`).
  - Xem và cập nhật hồ sơ cá nhân (`/auth/profile`).
- **`products` (`/products`)**:
  - Xem danh sách sản phẩm và phân trang (`/products/`).
  - Tìm kiếm sản phẩm theo tên, danh mục (`/products/?q=...`).
  - Xem chi tiết sản phẩm (`/products/<int:id>`).
- **`admin` (`/admin`)**:
  - Bảng điều khiển quản trị (`/admin/`).
  - Thêm, sửa, xóa sản phẩm (`/admin/products/...`).
  - Quản lý danh sách người dùng hệ thống (`/admin/users`).
  - Được bảo vệ bởi decorator phân quyền `@admin_required`.

---

## 5. Các biện pháp an toàn thông tin cốt lõi

1. **Phòng chống SQL Injection (CWE-89)**:
   - Toàn bộ truy vấn cơ sở dữ liệu được tham số hóa thông qua SQLAlchemy ORM.
2. **Phòng chống Cross-Site Scripting (XSS - CWE-79)**:
   - Jinja2 tự động escape HTML khi render dữ liệu động.
   - Header `Content-Security-Policy` (CSP) giới hạn nghiêm ngặt nguồn script, style và chặn inline execution trái phép.
3. **Phòng chống Cross-Site Request Forgery (CSRF - CWE-352)**:
   - Flask-WTF kích hoạt CSRF token trên mọi phương thức gửi dữ liệu POST/PUT/DELETE.
4. **Phòng chống Clickjacking (CWE-1021)**:
   - Header `X-Frame-Options: DENY` và directive CSP `frame-ancestors 'none'`.
5. **Bảo vệ Cookie & Session (CWE-614, CWE-1004)**:
   - Cấu hình `SESSION_COOKIE_HTTPONLY=True` ngăn chặn truy cập cookie từ JavaScript.
   - Cấu hình `SESSION_COOKIE_SAMESITE='Lax'` ngăn ngừa rò rỉ cookie trong các yêu cầu cross-site.
6. **Bảo vệ MIME-Sniffing (CWE-695)**:
   - Header `X-Content-Type-Options: nosniff`.
7. **Subresource Integrity (SRI - CWE-345)**:
   - Mọi tài nguyên nạp từ CDN bên ngoài (Bootstrap CSS/JS) đều có hash toàn vẹn `integrity="sha384-..."`.
8. **Bảo mật Container runtime**:
   - Docker container chạy bằng non-root user (`appuser`).
   - Cổng 5000 chỉ lắng nghe nội bộ trên `127.0.0.1`.
