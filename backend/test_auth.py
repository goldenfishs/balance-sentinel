"""Authentication regression tests; run with python -m unittest backend.test_auth."""

import hashlib
import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import main


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(main, "DB_PATH", Path(self.temp.name) / "test.db")
        self.db_patch.start()
        self.env_patch = patch.dict(os.environ, {"ADMIN_USERNAME": "", "ADMIN_PASSWORD": "", "CORS_ORIGINS": ""})
        self.env_patch.start()
        self.secure_patch = patch.object(main, "COOKIE_SECURE", False)
        self.secure_patch.start()
        main._login_failures.clear()
        self.client = TestClient(main.app)
        self.client.__enter__()
        self.payload = {"username": "测试管理员", "password": "test-only-password-123"}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.secure_patch.stop()
        self.env_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()
        main._login_failures.clear()

    def setup_admin(self):
        response = self.client.post("/api/auth/setup", json=self.payload)
        self.assertEqual(response.status_code, 201)
        return response

    def test_default_guard_covers_all_private_api_paths(self):
        for method, path in [
            ("GET", "/api/accounts"), ("POST", "/api/accounts"),
            ("PATCH", "/api/accounts/example"), ("DELETE", "/api/accounts/example"),
            ("GET", "/api/accounts/example/history"), ("POST", "/api/accounts/example/check"),
            ("POST", "/api/accounts/check-all"), ("GET", "/api/auth/me"),
            ("POST", "/api/auth/logout"), ("GET", "/api/future-private-route"),
        ]:
            with self.subTest(path=path, method=method):
                self.assertEqual(self.client.request(method, path).status_code, 401)
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/api/auth/status").json(), {
            "setup_required": True, "authenticated": False, "username": None,
        })

    def test_setup_creates_only_one_admin_and_secure_hashed_session(self):
        response = self.setup_admin()
        self.assertEqual(response.json(), {"username": self.payload["username"]})
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertIn("max-age=86400", cookie)
        raw_token = self.client.cookies.get(main.SESSION_COOKIE)
        with main.conn() as c:
            admin = c.execute("SELECT * FROM administrators").fetchone()
            session = c.execute("SELECT * FROM admin_sessions").fetchone()
        self.assertNotIn(self.payload["password"], str(dict(admin)))
        self.assertTrue(admin["password_hash"].startswith("scrypt$"))
        self.assertNotIn(raw_token, str(dict(session)))
        self.assertEqual(session["token_hash"], hashlib.sha256(raw_token.encode()).hexdigest())
        self.assertEqual(self.client.get("/api/auth/me").json(), {"username": self.payload["username"]})
        self.assertEqual(self.client.get("/api/auth/status").json(), {
            "setup_required": False, "authenticated": True, "username": self.payload["username"],
        })
        self.assertEqual(self.client.get("/api/accounts").headers["cache-control"], "no-store")
        other = {"username": "other", "password": "a-different-long-password"}
        self.assertEqual(self.client.post("/api/auth/setup", json=other).status_code, 409)

    def test_concurrent_setup_cannot_replace_first_admin(self):
        def attempt(username):
            with TestClient(main.app) as client:
                return client.post("/api/auth/setup", json={**self.payload, "username": username}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(attempt, ["first", "second"]))
        self.assertEqual(sorted(statuses), [201, 409])
        with main.conn() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM administrators").fetchone()[0], 1)

    def test_setup_validation_does_not_echo_password(self):
        for password in ["too-short", "x" * 257]:
            response = self.client.post("/api/auth/setup", json={**self.payload, "password": password})
            self.assertEqual(response.status_code, 422)
            self.assertNotIn(password, response.text)
        for username in ["   ", "x" * 65]:
            self.assertEqual(self.client.post("/api/auth/setup", json={**self.payload, "username": username}).status_code, 422)
        self.payload["username"] = "  admin  "
        self.assertEqual(self.setup_admin().json(), {"username": "admin"})

    def test_wrong_password_and_username_fail_without_credential_leaks(self):
        self.setup_admin()
        self.client.post("/api/auth/logout")
        for payload in [{**self.payload, "password": "wrong-password"}, {**self.payload, "username": "other"}]:
            response = self.client.post("/api/auth/login", json=payload)
            self.assertEqual(response.status_code, 401)
            self.assertNotIn(payload["password"], response.text)
            self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.client.get("/api/auth/status").json()["username"], None)
        self.assertEqual(self.client.post("/api/auth/login", json=self.payload).status_code, 200)

    def test_sessions_expire_on_server_and_logout_revokes_token(self):
        self.setup_admin()
        revoked_token = self.client.cookies.get(main.SESSION_COOKIE)
        self.assertEqual(self.client.post("/api/auth/logout").json(), {"ok": True})
        self.client.cookies.set(main.SESSION_COOKIE, revoked_token)
        self.assertEqual(self.client.get("/api/accounts").status_code, 401)
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/api/auth/login", json=self.payload).status_code, 200)
        with main.conn() as c:
            c.execute("UPDATE admin_sessions SET expires_at='2000-01-01T00:00:00+00:00'")
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        with main.conn() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM admin_sessions").fetchone()[0], 0)

    def test_session_survives_app_lifespan_restart(self):
        self.setup_admin()
        token = self.client.cookies.get(main.SESSION_COOKIE)
        with TestClient(main.app) as restarted:
            restarted.cookies.set(main.SESSION_COOKIE, token)
            self.assertEqual(restarted.get("/api/auth/me").json(), {"username": self.payload["username"]})

    def test_bad_origin_cannot_setup_login_or_mutate_authenticated_state(self):
        bad_headers = {"Origin": "https://untrusted.example"}
        self.assertEqual(self.client.post("/api/auth/setup", json=self.payload, headers=bad_headers).status_code, 403)
        self.setup_admin()
        for path in ["/api/auth/login", "/api/auth/logout", "/api/accounts/check-all"]:
            self.assertEqual(self.client.post(path, json=self.payload, headers=bad_headers).status_code, 403)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)
        self.assertEqual(self.client.post("/api/auth/logout", headers={"Origin": "http://testserver"}).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/login", json=self.payload, headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)

    def test_login_rate_limit_cleans_expired_buckets(self):
        self.setup_admin()
        self.client.post("/api/auth/logout")
        wrong = {**self.payload, "password": "wrong-password"}
        for _ in range(main.LOGIN_FAILURE_LIMIT):
            self.assertEqual(self.client.post("/api/auth/login", json=wrong).status_code, 401)
        response = self.client.post("/api/auth/login", json=self.payload)
        self.assertEqual(response.status_code, 429)
        self.assertIn("retry-after", response.headers)
        for key in list(main._login_failures):
            main._login_failures[key] = (5, time.monotonic() - 1)
        self.assertEqual(self.client.post("/api/auth/login", json=self.payload).status_code, 200)
        self.assertEqual(len(main._login_failures), 0)

    def test_bootstrap_requires_explicit_credentials_and_never_replaces_admin(self):
        with patch.dict(os.environ, {"ADMIN_USERNAME": "bootstrap", "ADMIN_PASSWORD": ""}):
            main.bootstrap_admin()
            self.assertIsNone(main._admin_row())
        with patch.dict(os.environ, {"ADMIN_USERNAME": "bootstrap", "ADMIN_PASSWORD": "bootstrap-password-123"}):
            main.bootstrap_admin()
        self.assertEqual(main._admin_row()["username"], "bootstrap")
        with patch.dict(os.environ, {"ADMIN_USERNAME": "replacement", "ADMIN_PASSWORD": "replacement-password-123"}):
            main.bootstrap_admin()
        self.assertEqual(main._admin_row()["username"], "bootstrap")

    def test_secure_cookie_on_https(self):
        self.client.base_url = "https://testserver"
        self.assertIn("secure", self.setup_admin().headers["set-cookie"].lower())

    def test_static_traversal_and_api_docs_are_blocked(self):
        for path in ["/%2e%2e/backend/main.py", "/../backend/main.py", "/%2e%2e/data/balance-monitor.db", "/docs", "/redoc", "/openapi.json"]:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/app.js").status_code, 200)

    def test_authenticated_account_crud_masks_secrets_and_deletes(self):
        self.setup_admin()
        payload = {"name": "test", "provider": "sub2api", "base_url": "https://example.test", "api_key": "not-a-real-api-key-123456", "enabled": False}
        response = self.client.post("/api/accounts", json=payload)
        self.assertEqual(response.status_code, 201)
        self.assertNotIn(payload["api_key"], response.text)
        account_id = response.json()["id"]
        self.assertEqual(self.client.patch(f"/api/accounts/{account_id}", json={"name": "updated"}).status_code, 200)
        self.assertEqual(self.client.get(f"/api/accounts/{account_id}/history").json(), [])
        self.assertEqual(self.client.post("/api/accounts/check-all").json(), {"checked": 0, "results": []})
        self.assertEqual(self.client.delete(f"/api/accounts/{account_id}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/accounts/{account_id}").status_code, 404)
        self.assertEqual(self.client.get("/api/accounts").json(), [])


if __name__ == "__main__":
    unittest.main()
