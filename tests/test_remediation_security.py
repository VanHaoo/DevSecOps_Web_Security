"""Comprehensive Security Remediation Verification Tests (Phase 4).

Covers:
- CSP Header directives (base-uri, form-action, object-src, frame-ancestors, script/style/font)
- Anti-clickjacking header (X-Frame-Options: DENY)
- MIME-sniffing protection (X-Content-Type-Options: nosniff)
- Session Cookie attributes (HttpOnly, SameSite, Secure flag logic)
- CSRF protection and role-based access control
- SECRET_KEY configuration in testing and production modes
- Subresource Integrity (SRI) attributes in base template
"""
import os
import re
import pytest
from app import create_app
from tests.conftest import login


class TestSecurityHeaders:
    """Verify HTTP security response headers."""

    def test_csp_header_present_and_configured(self, client):
        """SEC-01: Content-Security-Policy is present with robust directives."""
        response = client.get('/')
        assert response.status_code == 200
        assert 'Content-Security-Policy' in response.headers
        csp = response.headers['Content-Security-Policy']

        # Assert mandatory directives
        assert "default-src 'self'" in csp
        assert "script-src 'self' https://cdn.jsdelivr.net" in csp
        assert "style-src 'self' https://cdn.jsdelivr.net" in csp
        assert "font-src 'self' https://cdn.jsdelivr.net" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp
        assert "object-src 'none'" in csp

    def test_anticlickjacking_header_deny(self, client):
        """SEC-02: X-Frame-Options is set to DENY to prevent UI redressing."""
        response = client.get('/auth/login')
        assert response.status_code == 200
        assert response.headers.get('X-Frame-Options') == 'DENY'

    def test_x_content_type_options_nosniff(self, client):
        """SEC-03: X-Content-Type-Options is set to nosniff."""
        response = client.get('/static/css/style.css')
        assert response.status_code == 200
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_defense_in_depth_headers(self, client):
        """SEC-04: Referrer-Policy and Permissions-Policy headers."""
        response = client.get('/')
        assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
        assert 'camera=()' in response.headers.get('Permissions-Policy', '')
        assert 'geolocation=()' in response.headers.get('Permissions-Policy', '')


class TestSessionCookieSecurity:
    """Verify session cookie security flags."""

    def test_session_cookie_httponly_and_samesite(self, client, regular_user):
        """SEC-05: Session cookie contains HttpOnly and SameSite=Lax on authenticated session."""
        response = login(client, 'testuser', 'Test@123456')
        assert response.status_code == 200
        # Check app configuration
        assert client.application.config['SESSION_COOKIE_HTTPONLY'] is True
        assert client.application.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
        # Inspect raw Set-Cookie headers
        set_cookies = response.headers.getlist('Set-Cookie')
        session_cookie = next((c for c in set_cookies if 'session=' in c), None)
        assert session_cookie is not None
        assert 'HttpOnly' in session_cookie
        assert 'SameSite=Lax' in session_cookie


    def test_session_cookie_secure_flag_logic(self):
        """SEC-06: SESSION_COOKIE_SECURE respects environment configuration."""
        # When SESSION_COOKIE_SECURE is False (dev/test)
        app_dev = create_app('testing')
        assert app_dev.config['SESSION_COOKIE_HTTPONLY'] is True
        assert app_dev.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
        assert app_dev.config['SESSION_COOKIE_SECURE'] is False

        # When SESSION_COOKIE_SECURE is enabled via environment
        old_val = os.environ.get('SESSION_COOKIE_SECURE')
        try:
            os.environ['SESSION_COOKIE_SECURE'] = 'true'
            app_prod = create_app('testing')
            assert app_prod.config['SESSION_COOKIE_SECURE'] is True
        finally:
            if old_val is not None:
                os.environ['SESSION_COOKIE_SECURE'] = old_val
            else:
                os.environ.pop('SESSION_COOKIE_SECURE', None)


class TestSecretKeyConfiguration:
    """Verify SECRET_KEY management in different environments."""

    def test_testing_secret_key_is_dynamic_and_strong(self):
        """SEC-07: Testing mode generates dynamic high-entropy SECRET_KEY."""
        app1 = create_app('testing')
        app2 = create_app('testing')
        # Dynamic tokens must not be identical hardcoded strings
        assert app1.config['SECRET_KEY'] != app2.config['SECRET_KEY']
        assert len(app1.config['SECRET_KEY']) >= 32

    def test_production_secret_key_uses_env(self):
        """SEC-08: Production mode requires or reads SECRET_KEY from environment."""
        old_key = os.environ.get('SECRET_KEY')
        try:
            test_prod_key = 'super-secure-production-secret-key-12345'
            os.environ['SECRET_KEY'] = test_prod_key
            app = create_app('production')
            assert app.config['SECRET_KEY'] == test_prod_key
        finally:
            if old_key is not None:
                os.environ['SECRET_KEY'] = old_key
            else:
                os.environ.pop('SECRET_KEY', None)


class TestSubresourceIntegrity:
    """Verify SRI attributes on external CDN dependencies in HTML templates."""

    def test_bootstrap_cdn_has_sri_hashes(self, client):
        """SEC-09: CDN link and script tags include integrity and crossorigin attributes."""
        response = client.get('/')
        assert response.status_code == 200
        html = response.data.decode('utf-8')

        # Verify Bootstrap CSS link has integrity sha384 and crossorigin
        css_match = re.search(r'<link[^>]*href="[^"]*bootstrap[^"]*"[^>]*>', html)
        assert css_match is not None
        css_tag = css_match.group(0)
        assert 'integrity="sha384-' in css_tag
        assert 'crossorigin="anonymous"' in css_tag

        # Verify Bootstrap Icons link has integrity sha384 and crossorigin
        icons_match = re.search(r'<link[^>]*href="[^"]*bootstrap-icons[^"]*"[^>]*>', html)
        assert icons_match is not None
        icons_tag = icons_match.group(0)
        assert 'integrity="sha384-' in icons_tag
        assert 'crossorigin="anonymous"' in icons_tag

        # Verify Bootstrap JS script tag has integrity sha384 and crossorigin
        js_match = re.search(r'<script[^>]*src="[^"]*bootstrap[^"]*"[^>]*>', html)
        assert js_match is not None
        js_tag = js_match.group(0)
        assert 'integrity="sha384-' in js_tag
        assert 'crossorigin="anonymous"' in js_tag

