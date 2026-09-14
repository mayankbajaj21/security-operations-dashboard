"""
Unit and Integration Tests for Backend Authentication & Identity Layer
Milestone 1-3 Extension: Authentication Test Suite

Validates:
1. Login endpoint registration and presence
2. Successful authentication with valid credentials
3. Proper HTTP 401 rejection on incorrect password
4. Proper HTTP 401 rejection on unknown email
5. Request schema validation on empty/missing email (HTTP 422)
6. Request schema validation on empty/missing password (HTTP 422)
7. Case-insensitive email normalization
8. TokenResponse schema contract (access_token, token_type, user payload)
9. Strict omission of sensitive fields (password, hashed_password)
10. Duplicate user creation prevention (email uniqueness)
11. Bcrypt hash format and non-plaintext storage
12. Cryptographic JWT decoding and claim validation
"""

import unittest
import os
import jwt
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.auth_service import AuthService, get_auth_service, JWT_SECRET_KEY, JWT_ALGORITHM


class TestAuthAPI(unittest.TestCase):
    """Test suite covering authentication API endpoints and services."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.auth_service = get_auth_service()
        # Seed test user dedicated for testing
        cls.test_email = "test_analyst_auth@soc.internal"
        cls.test_password = "TestPassword123!"
        cls.test_name = "Auth Test Analyst"
        cls.test_role = "Senior SOC Analyst"

        # Ensure test account exists
        existing = cls.auth_service.get_user_by_email(cls.test_email)
        if not existing:
            cls.auth_service.create_user(
                email=cls.test_email,
                password=cls.test_password,
                full_name=cls.test_name,
                role=cls.test_role
            )

    @classmethod
    def tearDownClass(cls):
        try:
            cls.auth_service.users_collection.delete_one({"email": cls.test_email})
        except Exception:
            pass

    def test_01_login_endpoint_exists(self):
        """1. Verify login endpoint exists at /api/v1/auth/login and /v1/auth/login."""
        res_v1 = self.client.post("/api/v1/auth/login", json={})
        self.assertNotEqual(res_v1.status_code, 404, "Endpoint /api/v1/auth/login must exist.")

        res_root_v1 = self.client.post("/v1/auth/login", json={})
        self.assertNotEqual(res_root_v1.status_code, 404, "Endpoint /v1/auth/login must exist.")

    def test_02_valid_credentials_succeed(self):
        """2. Verify valid credentials return HTTP 200."""
        payload = {
            "email": self.test_email,
            "password": self.test_password
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data.get("token_type"), "bearer")
        self.assertEqual(data.get("user", {}).get("email"), self.test_email)

    def test_03_wrong_password_fails(self):
        """3. Verify incorrect password returns HTTP 401 with safe message."""
        payload = {
            "email": self.test_email,
            "password": "IncorrectPassword999!"
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        self.assertEqual(res.status_code, 401)
        data = res.json()
        self.assertEqual(data.get("detail"), "Invalid email or password.")

    def test_04_unknown_email_fails(self):
        """4. Verify unknown email returns HTTP 401 with the same safe message."""
        payload = {
            "email": "nonexistent_analyst@nowhere.internal",
            "password": "AnyPassword123!"
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        self.assertEqual(res.status_code, 401)
        data = res.json()
        self.assertEqual(data.get("detail"), "Invalid email or password.")

    def test_05_empty_email_fails_validation(self):
        """5. Verify empty email triggers HTTP 422 Unprocessable Entity."""
        payload = {
            "email": "",
            "password": "Password123!"
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        self.assertEqual(res.status_code, 422)

    def test_06_empty_password_fails_validation(self):
        """6. Verify empty password triggers HTTP 422 Unprocessable Entity."""
        payload = {
            "email": self.test_email,
            "password": ""
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        self.assertEqual(res.status_code, 422)

    def test_07_email_normalization_works(self):
        """7. Verify mixed-case and padded email normalizes to the same user."""
        mixed_case_email = f"  {self.test_email.upper()}  "
        payload = {
            "email": mixed_case_email,
            "password": self.test_password
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("user", {}).get("email"), self.test_email)

    def test_08_successful_response_contains_expected_fields(self):
        """8. Verify response contains access_token, token_type, and safe user fields."""
        payload = {
            "email": self.test_email,
            "password": self.test_password
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data.get("access_token"), str)
        self.assertGreater(len(data.get("access_token")), 20)
        self.assertEqual(data.get("token_type"), "bearer")

        user = data.get("user", {})
        self.assertEqual(user.get("email"), self.test_email)
        self.assertEqual(user.get("full_name"), self.test_name)
        self.assertEqual(user.get("role"), self.test_role)

    def test_09_successful_response_does_not_contain_password_or_hash(self):
        """9. Verify response strict exclusion of password and hashed_password."""
        payload = {
            "email": self.test_email,
            "password": self.test_password
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        data = res.json()
        self.assertNotIn("password", data)
        self.assertNotIn("hashed_password", data)

        user = data.get("user", {})
        self.assertNotIn("password", user)
        self.assertNotIn("hashed_password", user)

    def test_10_duplicate_user_creation_prevented(self):
        """10. Verify creating a duplicate user raises an error."""
        with self.assertRaises(ValueError):
            self.auth_service.create_user(
                email=self.test_email,
                password="AnotherPassword123!",
                full_name="Duplicate Test",
                role="Analyst"
            )

    def test_11_password_hash_format(self):
        """11. Verify stored password is not plaintext and uses standard bcrypt format."""
        user = self.auth_service.get_user_by_email(self.test_email)
        self.assertIsNotNone(user)
        self.assertNotIn("password", user, "Plaintext password must NEVER exist in DB.")
        hashed = user.get("hashed_password")
        self.assertIsNotNone(hashed)
        self.assertTrue(
            hashed.startswith("$2b$") or hashed.startswith("$2a$"),
            f"Stored credential must use bcrypt hashing format. Got: {hashed[:4]}"
        )
        self.assertNotEqual(hashed, self.test_password, "Hash must not equal plaintext password.")

    def test_12_token_validation_with_secret(self):
        """12. Verify issued access token can be decoded with configured secret key."""
        payload = {
            "email": self.test_email,
            "password": self.test_password
        }
        res = self.client.post("/api/v1/auth/login", json=payload)
        token = res.json()["access_token"]

        decoded = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer="soc-operations-auth"
        )
        self.assertEqual(decoded["sub"], self.test_email)
        self.assertEqual(decoded["name"], self.test_name)
        self.assertEqual(decoded["role"], self.test_role)


if __name__ == "__main__":
    unittest.main()
