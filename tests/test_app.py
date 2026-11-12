"""Tests for health endpoint, authentication, authorization, products, and input validation."""
import json
import re
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
        """TC-08: Logout works correctly via POST."""
        login(client, 'testuser', 'Test@123456')
        response = logout(client)
        assert response.status_code == 200
        assert 'Đã đăng xuất' in response.data.decode('utf-8')

    def test_get_logout_rejected_and_state_preserved(self, client, regular_user):
        """TC-08b: GET logout must be rejected with 405 Method Not Allowed and preserve authentication."""
        login(client, 'testuser', 'Test@123456')
        # Attempt logout via GET
        response = client.get('/auth/logout')
        assert response.status_code == 405

        # Verify user is still authenticated
        profile_resp = client.get('/auth/profile')
        assert profile_resp.status_code == 200
        assert 'testuser' in profile_resp.data.decode('utf-8')

    def test_open_redirect_safe_internal_targets(self, client, regular_user):
        """TC-08c: Safe internal relative paths are permitted on login redirect."""
        # First login: redirect to /auth/profile
        resp = client.post('/auth/login?next=/auth/profile', data={
            'username': 'testuser',
            'password': 'Test@123456'
        })
        assert resp.status_code == 302, f'Expected 302, got {resp.status_code}'
        assert resp.headers['Location'] == '/auth/profile', (
            f"Expected '/auth/profile', got {resp.headers.get('Location')}"
        )

        # Logout so the second login is not short-circuited by is_authenticated guard
        client.post('/auth/logout')

        # Second login: redirect to /products
        resp2 = client.post('/auth/login?next=/products', data={
            'username': 'testuser',
            'password': 'Test@123456'
        })
        assert resp2.status_code == 302, f'Expected 302, got {resp2.status_code}'
        assert resp2.headers['Location'] == '/products', (
            f"Expected '/products', got {resp2.headers.get('Location')}"
        )

    def test_open_redirect_malicious_targets_blocked(self, client, regular_user):
        """TC-08d: Open redirect attempts are rejected and fallback to home page."""
        malicious_urls = [
            'https://evil.com',
            'http://evil.com',
            '//evil.com',
            '//evil.com/path',
            '/\\evil.com',
            '\\evil.com',
            'javascript:alert(1)',
            'data:text/html;base64,PHNjcmlwdD4=',
            'http://attacker.com/steal?token=123',
            'https://google.com@attacker.com',
            r'/products\evil.com',
            '/\x00evil.com',
        ]
        for bad_url in malicious_urls:
            resp = client.post(f'/auth/login?next={bad_url}', data={
                'username': 'testuser',
                'password': 'Test@123456'
            })
            assert resp.status_code == 302
            # Location must fallback to home page '/' or main.index
            assert resp.headers['Location'] in ('/', 'http://localhost/')


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

    def test_add_product_zero_price_and_stock_is_valid(self, client, admin_user):
        """TC-26b: Product with price=0 (e.g. giveaway) and stock=0 (out-of-stock) is valid."""
        login(client, 'admin', 'Admin@123456')
        response = client.post('/admin/products/add', data={
            'name': 'Free Out Of Stock Sample',
            'description': 'Valid zero price and zero stock item',
            'price': 0,
            'category': 'Freebie',
            'stock': 0,
            'image_url': ''
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Thêm sản phẩm thành công' in response.data.decode('utf-8')

    def test_add_product_negative_stock_fails(self, client, admin_user):
        """TC-26c: Product with negative stock fails validation."""
        login(client, 'admin', 'Admin@123456')
        response = client.post('/admin/products/add', data={
            'name': 'Negative Stock Product',
            'description': 'Invalid stock',
            'price': 10000,
            'category': '',
            'stock': -1,
            'image_url': ''
        }, follow_redirects=True)
        assert response.status_code == 200
        assert 'Thêm sản phẩm thành công' not in response.data.decode('utf-8')

    def test_add_product_missing_price_or_stock_fails(self, client, admin_user):
        """TC-26d: Product with missing price or stock is rejected."""
        login(client, 'admin', 'Admin@123456')
        # Missing price
        resp1 = client.post('/admin/products/add', data={
            'name': 'No Price',
            'price': '',
            'stock': 10
        }, follow_redirects=True)
        assert 'Thêm sản phẩm thành công' not in resp1.data.decode('utf-8')

        # Missing stock
        resp2 = client.post('/admin/products/add', data={
            'name': 'No Stock',
            'price': 10000,
            'stock': ''
        }, follow_redirects=True)
        assert 'Thêm sản phẩm thành công' not in resp2.data.decode('utf-8')

    def test_add_product_invalid_data_types_fails(self, client, admin_user):
        """TC-26e: Non-numeric price or stock values fail type conversion validation."""
        login(client, 'admin', 'Admin@123456')
        resp = client.post('/admin/products/add', data={
            'name': 'String Price Product',
            'price': 'one-hundred',
            'stock': 'fifty'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert 'Thêm sản phẩm thành công' not in resp.data.decode('utf-8')


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


# ============================================================
# 11. Comprehensive CSRF Protection Verification
# ============================================================

class TestCSRFProtection:
    """Rigorous verification of CSRF protection across sensitive state-changing endpoints."""

    def _extract_token(self, html):
        """Helper to extract CSRF token from HTML."""
        match = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html)
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']', html)
        return match.group(1) if match else None

    def test_csrf_blocks_post_without_token_on_all_critical_routes(self, app, regular_user, admin_user, sample_product):
        """TC-33: POST without CSRF token is blocked with HTTP 400 on critical routes."""
        app.config['WTF_CSRF_ENABLED'] = True
        client = app.test_client()

        # 1. Login
        resp_login = client.post('/auth/login', data={'username': 'testuser', 'password': 'Test@123456'})
        assert resp_login.status_code == 400

        # 2. Registration
        resp_reg = client.post('/auth/register', data={
            'username': 'attacker',
            'email': 'attacker@test.com',
            'password': 'Password@123',
            'confirm_password': 'Password@123'
        })
        assert resp_reg.status_code == 400

        # 3. Logout
        resp_logout = client.post('/auth/logout')
        assert resp_logout.status_code == 400

        # 4. Add product
        resp_add = client.post('/admin/products/add', data={
            'name': 'Hacked Product',
            'price': 100,
            'stock': 1
        })
        assert resp_add.status_code == 400

        # 5. Delete product
        resp_del = client.post(f'/admin/products/{sample_product.id}/delete')
        assert resp_del.status_code == 400

        app.config['WTF_CSRF_ENABLED'] = False

    def test_csrf_blocks_post_with_invalid_token(self, app):
        """TC-34: POST with forged or tampered CSRF token is rejected with HTTP 400."""
        app.config['WTF_CSRF_ENABLED'] = True
        client = app.test_client()

        # Initial GET to establish session cookie
        client.get('/auth/login')

        response = client.post('/auth/login', data={
            'username': 'testuser',
            'password': 'Test@123456',
            'csrf_token': 'forged_or_expired_token_12345'
        })
        assert response.status_code == 400
        app.config['WTF_CSRF_ENABLED'] = False

    def test_csrf_allows_post_with_valid_token_for_login_and_logout(self, app, regular_user):
        """TC-35: Legitimate POST containing valid CSRF token succeeds for login and logout."""
        app.config['WTF_CSRF_ENABLED'] = True
        client = app.test_client()

        # 1. GET login page to obtain valid CSRF token
        get_resp = client.get('/auth/login')
        token = self._extract_token(get_resp.data.decode('utf-8'))
        assert token is not None

        # 2. POST login with valid token
        post_resp = client.post('/auth/login', data={
            'username': 'testuser',
            'password': 'Test@123456',
            'csrf_token': token
        }, follow_redirects=True)
        assert post_resp.status_code == 200
        assert 'Đăng nhập thành công' in post_resp.data.decode('utf-8')

        # 3. GET profile/page to obtain fresh CSRF token from navbar logout form
        base_resp = client.get('/')
        logout_token = self._extract_token(base_resp.data.decode('utf-8'))
        assert logout_token is not None

        # 4. POST logout with valid token
        logout_resp = client.post('/auth/logout', data={
            'csrf_token': logout_token
        }, follow_redirects=True)
        assert logout_resp.status_code == 200
        assert 'Đã đăng xuất' in logout_resp.data.decode('utf-8')

        app.config['WTF_CSRF_ENABLED'] = False

    def test_csrf_allows_valid_token_on_register(self, app):
        """TC-36: Legitimate POST containing valid CSRF token succeeds for registration."""
        app.config['WTF_CSRF_ENABLED'] = True
        client = app.test_client()

        get_resp = client.get('/auth/register')
        token = self._extract_token(get_resp.data.decode('utf-8'))
        assert token is not None

        post_resp = client.post('/auth/register', data={
            'username': 'legit_user',
            'email': 'legit@test.com',
            'password': 'LegitPassword@123',
            'confirm_password': 'LegitPassword@123',
            'csrf_token': token
        }, follow_redirects=True)
        assert post_resp.status_code == 200
        assert 'Đăng ký thành công' in post_resp.data.decode('utf-8')

        app.config['WTF_CSRF_ENABLED'] = False
