# Tài liệu kiến trúc hệ thống

## Tổng quan

Ứng dụng quản lý sản phẩm được xây dựng bằng Flask, phục vụ thực nghiệm DevSecOps.

## Kiến trúc

```
Client (Browser) → Flask App (Gunicorn) → SQLAlchemy ORM → SQLite Database
```

## Công nghệ

| Thành phần | Công nghệ | Phiên bản |
|---|---|---|
| Web Framework | Flask | 3.1.1 |
| ORM | SQLAlchemy | 2.0.36 |
| Authentication | Flask-Login | 0.6.3 |
| Form Validation | Flask-WTF | 1.2.2 |
| Database | SQLite | Built-in |
| WSGI Server | Gunicorn | 23.0.0 |
| Testing | pytest | 8.3.4 |
| Container | Docker | - |

## Cấu trúc Blueprint

- **main**: Trang chủ, health check
- **auth**: Đăng ký, đăng nhập, đăng xuất, hồ sơ
- **products**: Danh sách, tìm kiếm, chi tiết sản phẩm
- **admin**: Dashboard, CRUD sản phẩm, quản lý người dùng

## Bảo mật cơ bản

- Mật khẩu được băm bằng Werkzeug (pbkdf2:sha256)
- CSRF protection qua Flask-WTF
- Input validation trên tất cả form
- SQL Injection prevention qua SQLAlchemy ORM
- Role-based access control (admin/user)
