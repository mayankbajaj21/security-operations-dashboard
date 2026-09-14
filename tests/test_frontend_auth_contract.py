"""
Frontend Authentication Contract & Static Verification Tests
Milestone 1-3 Extension: Authentication Contract Verification

Validates that:
1. LandingPage.jsx imports and calls loginUser(email, password) on sign in.
2. LandingPage.jsx no longer calls getDemoUsers() for authentication.
3. LandingPage.jsx no longer performs client-side password matching (u.password === password).
4. api.js exports loginUser and calls POST /v1/auth/login with { email, password }.
5. api.js configures Authorization Bearer token header interceptor.
6. Backend main.py registers the authentication router matching the frontend endpoint.
"""

import unittest
from pathlib import Path


class TestFrontendAuthContract(unittest.TestCase):
    """Verifies that frontend authentication strictly conforms to backend API contract."""

    @classmethod
    def setUpClass(cls):
        cls.base_dir = Path(__file__).resolve().parent.parent
        cls.landing_page_path = cls.base_dir / "frontend" / "src" / "pages" / "LandingPage.jsx"
        cls.api_service_path = cls.base_dir / "frontend" / "src" / "services" / "api.js"
        cls.app_path = cls.base_dir / "frontend" / "src" / "App.jsx"
        cls.main_py_path = cls.base_dir / "backend" / "app" / "main.py"

        with open(cls.landing_page_path, "r", encoding="utf-8") as f:
            cls.landing_page_content = f.read()

        with open(cls.api_service_path, "r", encoding="utf-8") as f:
            cls.api_service_content = f.read()

        with open(cls.app_path, "r", encoding="utf-8") as f:
            cls.app_content = f.read()

        with open(cls.main_py_path, "r", encoding="utf-8") as f:
            cls.main_py_content = f.read()

    def test_01_landing_page_imports_and_calls_login_user(self):
        """1. LandingPage.jsx must import and invoke loginUser."""
        self.assertIn(
            "loginUser",
            self.landing_page_content,
            "LandingPage.jsx must reference loginUser API service function."
        )
        self.assertIn(
            "await loginUser(",
            self.landing_page_content,
            "LandingPage.jsx must await loginUser in its submit handler."
        )

    def test_02_no_demo_users_mock_in_landing_page(self):
        """2. LandingPage.jsx must not contain getDemoUsers() or soc_demo_users."""
        self.assertNotIn(
            "getDemoUsers",
            self.landing_page_content,
            "LandingPage.jsx must NOT contain mock getDemoUsers function."
        )
        self.assertNotIn(
            "soc_demo_users",
            self.landing_page_content,
            "LandingPage.jsx must NOT use localStorage soc_demo_users."
        )

    def test_03_no_client_side_password_comparison(self):
        """3. LandingPage.jsx must never compare passwords client-side."""
        self.assertNotIn(
            "u.password === password",
            self.landing_page_content,
            "LandingPage.jsx must NOT perform client-side password equality checks."
        )

    def test_04_api_service_exports_login_user(self):
        """4. api.js must export loginUser and dispatch POST to /v1/auth/login."""
        self.assertIn(
            "export const loginUser",
            self.api_service_content,
            "frontend/src/services/api.js must export loginUser."
        )
        self.assertIn(
            "/v1/auth/login",
            self.api_service_content,
            "api.js loginUser must target /v1/auth/login."
        )

    def test_05_api_service_attaches_bearer_token(self):
        """5. api.js must attach Bearer token via Axios interceptor."""
        self.assertIn(
            "apiClient.interceptors.request.use",
            self.api_service_content,
            "api.js must register request interceptor for Authorization header."
        )
        self.assertIn(
            "Bearer",
            self.api_service_content,
            "api.js interceptor must include Bearer token format."
        )

    def test_06_backend_main_registers_auth_router(self):
        """6. backend/app/main.py must import and register auth_router."""
        self.assertIn(
            "auth_router",
            self.main_py_content,
            "main.py must register auth_router."
        )
        self.assertIn(
            'app.include_router(auth_router, prefix="/v1")',
            self.main_py_content,
            "main.py must include auth_router under /v1 for Vite proxy compatibility."
        )


if __name__ == "__main__":
    unittest.main()
