"""Tests for Security Dashboard (Giai đoạn 6)."""
from tests.conftest import login, logout


class TestSecurityDashboardAccess:
    """Test access control for /admin/security-dashboard."""

    def test_unauthenticated_user_redirected(self, client):
        """Unauthenticated user is redirected to login page."""
        response = client.get('/admin/security-dashboard')
        assert response.status_code == 302
        assert '/auth/login' in response.headers.get('Location', '')

    def test_regular_user_forbidden(self, client, regular_user):
        """Regular user cannot access security dashboard (403 Forbidden)."""
        login(client, 'testuser', 'Test@123456')
        response = client.get('/admin/security-dashboard')
        assert response.status_code == 403

    def test_admin_user_can_access(self, client, admin_user):
        """Admin user can successfully access security dashboard (200 OK)."""
        login(client, 'admin', 'Admin@123456')
        response = client.get('/admin/security-dashboard')
        assert response.status_code == 200
        html = response.data.decode('utf-8')
        assert 'Security &amp; DevSecOps Dashboard' in html or 'Security & DevSecOps Dashboard' in html


class TestSecurityDashboardContent:
    """Test that all required sections and empirical data are present."""

    def test_three_main_tabs_present(self, client, admin_user):
        """Dashboard must contain the 3 primary interactive tabs + demo guide."""
        login(client, 'admin', 'Admin@123456')
        response = client.get('/admin/security-dashboard')
        assert response.status_code == 200
        html = response.data.decode('utf-8')

        # Tab 1: CI/CD Pipeline
        assert '1. CI/CD Pipeline' in html
        assert 'devsecops-pipeline.yml' in html
        assert 'Unit Testing (pytest)' in html
        assert 'SAST (Semgrep)' in html
        assert 'Secret Scanning (Gitleaks)' in html
        assert 'Release &amp; Deployment Gate' in html or 'Release & Deployment Gate' in html

        # Tab 2: Security Scanning
        assert '2. Security Scanning' in html
        assert 'Semgrep (SAST)' in html
        assert 'Trivy Filesystem (SCA)' in html
        assert 'Trivy Container Image' in html
        assert 'OWASP ZAP (DAST)' in html
        assert 'CycloneDX SBOM' in html

        # Tab 3: Security Quality Gate
        assert '3. Security Quality Gate' in html
        assert 'Thí Nghiệm Kiểm Thử Hồi Quy' in html
        assert 'gate-regression-stepA-clean-pass.json' in html
        assert 'gate-regression-stepB-vuln-fail.json' in html
        assert 'gate-regression-stepC-restored-pass.json' in html

        # Tab 4: Instructor Demo Guide
        assert 'Kịch Bản Demo Giảng Viên' in html

    def test_empirical_metrics_integrity(self, client, admin_user):
        """Verify empirical metrics match verified project artifacts."""
        login(client, 'admin', 'Admin@123456')
        response = client.get('/admin/security-dashboard')
        html = response.data.decode('utf-8')

        # Check repository and commit info
        assert 'VanHaoo/DevSecOps_Web_Security' in html
        assert '1e18dd5' in html

        # Check Gate status and violation counts
        assert 'FAIL' in html
        assert '49' in html  # 49 blocking violations (44 OS + 5 pip)
        assert 'PENDING_REVIEW' in html
