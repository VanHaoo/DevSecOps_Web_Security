"""Tests for health endpoint, authentication, authorization, products, and input validation."""
import json
from tests.conftest import login, logout


# ============================================================
# 1. Health Check Endpoint
# ============================================================

class TestHealthEndpoint:
    """Test /health endpoint."""

    def test_health_returns_200(self, client):
        """TC-01: Health endpoint returns 200 with correct JSON."""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'service' in data


# ============================================================
# 2. User Registration
# ============================================================

class TestRegistration:
    """Test user registration."""

    def test_register_success(self, client):
        """TC-02: Successful registration redirects to login."""
        response = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'new@test.com',
            'password': 'NewUser@123',
            'confirm_password': 'NewUser@123'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Đăng ký thành công' in response.data.decode('utf-8')

    def test_register_duplicate_username(self, client, regular_user):
        """TC-03: Registration fails with duplicate username."""
        response = client.post('/auth/register', data={
            'username': 'testuser',  # same as regular_user
            'email': 'other@test.com',
            'password': 'Other@123456',
            'confirm_password': 'Other@123456'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Tên đăng nhập đã tồn tại' in response.data.decode('utf-8')

    def test_register_password_mismatch(self, client):
        """TC-04: Registration fails when passwords don't match."""
        response = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'new@test.com',
            'password': 'Password@1',
            'confirm_password': 'Password@2'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Mật khẩu xác nhận không khớp' in response.data.decode('utf-8')


# ============================================================
# 3. Login & Logout
# ============================================================

class TestLogin:
    """Test login and logout functionality."""

    def test_login_valid(self, client, regular_user):
        """TC-05: Valid login succeeds."""
        response = login(client, 'testuser', 'Test@123456')
        assert response.status_code == 200
        assert 'Đăng nhập thành công' in response.data.decode('utf-8')

    def test_login_invalid_password(self, client, regular_user):
        """TC-06: Login fails with wrong password."""
        response = login(client, 'testuser', 'WrongPassword')
        assert response.status_code == 200
        assert 'Tên đăng nhập hoặc mật khẩu không đúng' in response.data.decode('utf-8')

    def test_login_nonexistent_user(self, client):
        """TC-07: Login fails for non-existent user."""
        response = login(client, 'ghost', 'SomePassword@1')
        assert response.status_code == 200
        assert 'Tên đăng nhập hoặc mật khẩu không đúng' in response.data.decode('utf-8')

    def test_logout(self, client, regular_user):
        """TC-08: Logout works correctly."""
        login(client, 'testuser', 'Test@123456')
        response = logout(client)
        assert response.status_code == 200
        assert 'Đã đăng xuất' in response.data.decode('utf-8')


# ============================================================
# 4. Authentication Required
# ============================================================

class TestAuthRequired:
    """Test that protected routes require authentication."""

    def test_profile_requires_login(self, client):
        """TC-09: Profile page redirects unauthenticated user."""
        response = client.get('/auth/profile')
        assert response.status_code == 302  # redirect to login

    def test_admin_requires_login(self, client):
        """TC-10: Admin dashboard redirects unauthenticated user."""
        response = client.get('/admin/')
        assert response.status_code == 302


# ============================================================
# 5. Authorization (Role-Based)
# ============================================================

class TestAuthorization:
    """Test role-based access control."""

    def test_regular_user_cannot_access_admin(self, client, regular_user):
        """TC-11: Regular user gets 403 on admin routes."""
        login(client, 'testuser', 'Test@123456')
        response = client.get('/admin/')
        assert response.status_code == 403

    def test_admin_can_access_admin(self, client, admin_user):
        """TC-12: Admin user can access admin dashboard."""
        login(client, 'admin', 'Admin@123456')
        response = client.get('/admin/')
        assert response.status_code == 200

    def test_regular_user_cannot_add_product(self, client, regular_user):
        """TC-13: Regular user gets 403 on add product."""
        login(client, 'testuser', 'Test@123456')
        response = client.get('/admin/products/add')
        assert response.status_code == 403

    def test_regular_user_cannot_delete_product(self, client, regular_user, sample_product):
        """TC-14: Regular user gets 403 on delete product."""
        login(client, 'testuser', 'Test@123456')
        response = client.post(f'/admin/products/{sample_product.id}/delete')
        assert response.status_code == 403


# ============================================================
# 6. Product Viewing & Search
# ============================================================

class TestProducts:
    """Test product viewing and search."""

    def test_product_list(self, client, sample_product):
        """TC-15: Product list page loads successfully."""
        response = client.get('/products/')
        assert response.status_code == 200
        assert 'Test Product' in response.data.decode('utf-8')

    def test_product_detail(self, client, sample_product):
        """TC-16: Product detail page loads successfully."""
        response = client.get(f'/products/{sample_product.id}')
        assert response.status_code == 200
        assert 'Test Product' in response.data.decode('utf-8')

    def test_product_search(self, client, sample_product):
        """TC-17: Search returns matching products."""
        response = client.get('/products/?q=Test')
        assert response.status_code == 200
        assert 'Test Product' in response.data.decode('utf-8')

    def test_product_search_no_results(self, client, sample_product):
        """TC-18: Search with no matches shows empty state."""
        response = client.get('/products/?q=NonExistentXYZ')
        assert response.status_code == 200
        assert 'Test Product' not in response.data.decode('utf-8')

    def test_product_not_found(self, client):
        """TC-19: Non-existent product returns 404."""
        response = client.get('/products/99999')
        assert response.status_code == 404


# ============================================================
# 7. Admin Product CRUD
# ============================================================

class TestAdminProductCRUD:
    """Test admin product management."""

    def test_add_product(self, client, admin_user):
        """TC-20: Admin can add a product."""
        login(client, 'admin', 'Admin@123456')
        response = client.post('/admin/products/add', data={
            'name': 'New Product',
            'description': 'A brand new product',
            'price': 50000,
            'category': 'New',
            'stock': 5,
            'image_url': ''
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Thêm sản phẩm thành công' in response.data.decode('utf-8')

    def test_edit_product(self, client, admin_user, sample_product):
        """TC-21: Admin can edit a product."""
        login(client, 'admin', 'Admin@123456')
        response = client.post(f'/admin/products/{sample_product.id}/edit', data={
            'name': 'Updated Product',
            'description': 'Updated description',
            'price': 200000,
            'category': 'Updated',
            'stock': 20,
            'image_url': ''
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Cập nhật sản phẩm thành công' in response.data.decode('utf-8')

    def test_delete_product(self, client, admin_user, sample_product):
        """TC-22: Admin can delete a product."""
        login(client, 'admin', 'Admin@123456')
        response = client.post(
            f'/admin/products/{sample_product.id}/delete',
            follow_redirects=True
        )
        assert response.status_code == 200
        assert 'Xóa sản phẩm thành công' in response.data.decode('utf-8')


# ============================================================
# 8. Input Validation
# ============================================================

class TestInputValidation:
    """Test input validation."""

    def test_register_short_password(self, client):
        """TC-23: Registration fails with short password."""
        response = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'new@test.com',
            'password': 'short',
            'confirm_password': 'short'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'ít nhất 8 ký tự' in response.data.decode('utf-8')

    def test_register_invalid_email(self, client):
        """TC-24: Registration fails with invalid email."""
        response = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'not-an-email',
            'password': 'Valid@123456',
            'confirm_password': 'Valid@123456'
        }, follow_redirects=True)
        assert response.status_code == 200
        # The form should not succeed - page stays on register
        assert 'Đăng ký' in response.data.decode('utf-8')

    def test_add_product_missing_name(self, client, admin_user):
        """TC-25: Adding product without name fails validation."""
        login(client, 'admin', 'Admin@123456')
        response = client.post('/admin/products/add', data={
            'name': '',
            'description': 'No name',
            'price': 50000,
            'category': '',
            'stock': 5,
            'image_url': ''
        }, follow_redirects=True)
        assert response.status_code == 200
        # Should stay on the form page (not redirect to dashboard)
        assert 'Thêm sản phẩm thành công' not in response.data.decode('utf-8')

    def test_add_product_negative_price(self, client, admin_user):
        """TC-26: Adding product with negative price fails validation."""
        login(client, 'admin', 'Admin@123456')
        response = client.post('/admin/products/add', data={
            'name': 'Bad Product',
            'description': 'Negative price',
            'price': -100,
            'category': '',
            'stock': 5,
            'image_url': ''
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Thêm sản phẩm thành công' not in response.data.decode('utf-8')


# ============================================================
# 9. Error Cases
# ============================================================

class TestErrorCases:
    """Test error handling."""

    def test_404_page(self, client):
        """TC-27: Non-existent route returns 404."""
        response = client.get('/nonexistent-page')
        assert response.status_code == 404

    def test_home_page_loads(self, client):
        """TC-28: Home page loads successfully."""
        response = client.get('/')
        assert response.status_code == 200
        assert 'Hệ thống quản lý sản phẩm' in response.data.decode('utf-8')

    def test_admin_user_list(self, client, admin_user, regular_user):
        """TC-29: Admin can view user list."""
        login(client, 'admin', 'Admin@123456')
        response = client.get('/admin/users')
        assert response.status_code == 200
        assert 'testuser' in response.data.decode('utf-8')

    def test_profile_update(self, client, regular_user):
        """TC-30: User can update profile email."""
        login(client, 'testuser', 'Test@123456')
        response = client.post('/auth/profile', data={
            'email': 'newemail@test.com'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Cập nhật thông tin thành công' in response.data.decode('utf-8')


# ============================================================
# 10. Security Controls Verification
# ============================================================

class TestSecurityControls:
    """Test security-specific controls."""

    def test_csrf_protection_blocks_post_without_token(self, app):
        """TC-31: When CSRF is enabled, POST without token is rejected with 400."""
        app.config['WTF_CSRF_ENABLED'] = True
        client = app.test_client()
        response = client.post('/auth/login', data={
            'username': 'admin',
            'password': 'password'
        })
        assert response.status_code == 400
        app.config['WTF_CSRF_ENABLED'] = False

    def test_password_hashing_security(self, regular_user):
        """TC-32: Passwords are not plaintext and use secure hashing algorithm."""
        assert regular_user.password_hash != 'Test@123456'
        assert regular_user.password_hash.startswith(('scrypt:', 'pbkdf2:'))
        assert regular_user.check_password('Test@123456') is True
        assert regular_user.check_password('WrongPassword') is False
