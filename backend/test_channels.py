"""Small integration coverage for the channel/model probe API.

Run from the repository root with ``python -m unittest backend.test_channels``.
The test uses a local HTTP server, so it never calls a real provider.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx

from . import main


class _Provider(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        payload = {"data": [{"id": "demo-model"}, {"id": "second-model"}]} if self.path == "/v1/models" else {}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = b'{"choices":[{"message":{"content":"ok"}}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class ChannelApiTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = HTTPServer(("127.0.0.1", 0), _Provider)
        threading.Thread(target=cls.provider.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.provider.shutdown()

    def setUp(self):
        self.db_file = pathlib.Path(tempfile.mktemp(suffix=".db"))
        main.DB_PATH = self.db_file
        main.init_db()
        main._login_failures.clear()

    async def test_models_probe_and_schedule(self):
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/auth/setup", json={"username": "admin", "password": "supersecure123"})
            self.assertEqual(response.status_code, 201)
            provider_url = f"http://127.0.0.1:{self.provider.server_port}"
            response = await client.post("/api/channels", json={"name": "local", "provider": "sub2api", "base_url": provider_url, "api_key": "test-key"})
            self.assertEqual(response.status_code, 201)
            channel_id = response.json()["id"]

            response = await client.post(f"/api/channels/{channel_id}/models")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["models"], ["demo-model", "second-model"])

            response = await client.post(f"/api/channels/{channel_id}/probe", json={"model": "demo-model"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["status"], "ok")
            self.assertEqual(response.json()["http_status"], 200)

            response = await client.put(f"/api/channels/{channel_id}/schedule", json={"enabled": True, "interval_seconds": 30})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["probe_enabled"])
            response = await client.get(f"/api/channels/{channel_id}/probes")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.json()), 1)


if __name__ == "__main__":
    unittest.main()
