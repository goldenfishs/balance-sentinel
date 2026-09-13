from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
import uuid
import secrets
import base64
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, HttpUrl, field_validator


DB_PATH = Path(os.getenv("DATABASE_PATH", "/data/balance-monitor.db"))
POLL_SECONDS = max(30, int(os.getenv("MONITOR_INTERVAL_SECONDS", "300")))
SESSION_COOKIE = "balance_sentinel_session"
SESSION_TTL_SECONDS = 86400
COOKIE_SECURE = os.getenv("AUTH_COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
PUBLIC_API_PATHS = {"/api/auth/status", "/api/auth/setup", "/api/auth/login", "/api/health"}
_login_failures: dict[str, tuple[int, float]] = {}
_login_limit_lock = threading.Lock()
LOGIN_FAILURE_LIMIT = 5
LOGIN_WINDOW_SECONDS = 300
LOGIN_BUCKET_LIMIT = 4096


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              provider TEXT NOT NULL CHECK(provider IN ('sub2api','newapi')),
              base_url TEXT NOT NULL,
              credential_kind TEXT NOT NULL DEFAULT 'api_key',
              api_key TEXT,
              access_token TEXT,
              user_id TEXT,
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              last_checked_at TEXT,
              last_status TEXT NOT NULL DEFAULT 'unknown',
              last_error TEXT,
              last_result TEXT,
              threshold REAL NOT NULL DEFAULT 5,
              notes TEXT
            );
            CREATE TABLE IF NOT EXISTS balance_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              account_id TEXT NOT NULL,
              checked_at TEXT NOT NULL,
              status TEXT NOT NULL,
              remaining REAL,
              used REAL,
              total REAL,
              unit TEXT,
              raw TEXT,
              error TEXT,
              FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_account ON balance_snapshots(account_id, checked_at DESC);
            CREATE TABLE IF NOT EXISTS administrators (
              id INTEGER PRIMARY KEY CHECK(id = 1), username TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
              token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions(expires_at);
            """
        )


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$16384$8$1$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def _password_verify(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = encoded.split("$", 5)
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _admin_row() -> sqlite3.Row | None:
    with conn() as c:
        try:
            return c.execute("SELECT * FROM administrators WHERE id=1").fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
    init_db()
    with conn() as c:
        return c.execute("SELECT * FROM administrators WHERE id=1").fetchone()


def bootstrap_admin() -> None:
    username, password = os.getenv("ADMIN_USERNAME"), os.getenv("ADMIN_PASSWORD")
    if _admin_row() or not username or not password:
        return
    username = username.strip()
    if not 1 <= len(username) <= 64 or not 12 <= len(password) <= 256:
        raise RuntimeError("ADMIN_USERNAME must be 1–64 characters and ADMIN_PASSWORD 12–256 characters")
    with conn() as c:
        c.execute("INSERT OR IGNORE INTO administrators(id,username,password_hash,created_at) VALUES(1,?,?,?)", (username, _password_hash(password), utc_now()))


def _session_user(request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 256:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = utc_now()
    with conn() as c:
        try:
            c.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (now,))
            row = c.execute("SELECT username FROM admin_sessions WHERE token_hash=? AND expires_at > ?", (token_hash, now)).fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
            init_db()
            with conn() as retry:
                row = retry.execute("SELECT username FROM admin_sessions WHERE token_hash=? AND expires_at > ?", (token_hash, now)).fetchone()
    return row["username"] if row else None


def _origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return request.headers.get("sec-fetch-site") != "cross-site"
    trusted = [x.strip().rstrip("/") for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip() and x.strip() != "*"]
    # The app is normally behind Nginx. Uvicorn sees the internal Docker
    # connection, so compare against the externally visible forwarded origin.
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",", 1)[0].strip()
    forwarded_host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc)).split(",", 1)[0].strip()
    request_origin = f"{forwarded_proto}://{forwarded_host}"
    return origin.rstrip("/") == request_origin.rstrip("/") or origin.rstrip("/") in trusted


def _login_attempt(request: Request) -> str:
    # Do not trust caller-supplied X-Forwarded-For headers here.
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _login_limit_lock:
        for key, (_, expires) in list(_login_failures.items()):
            if expires <= now:
                del _login_failures[key]
        count, expiry = _login_failures.get(client_ip, (0, now + LOGIN_WINDOW_SECONDS))
        if count >= LOGIN_FAILURE_LIMIT:
            raise HTTPException(429, "尝试次数过多，请 5 分钟后再试", headers={"Retry-After": str(max(1, int(expiry - now)))})
        if len(_login_failures) >= LOGIN_BUCKET_LIMIT and client_ip not in _login_failures:
            # Fail closed while all rate-limit slots are occupied.
            raise HTTPException(429, "登录请求过多，请稍后再试", headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)})
        _login_failures[client_ip] = (count + 1, expiry)
    return client_ip


def _new_session(username: str, request: Request, response: Response) -> None:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    old_token = request.cookies.get(SESSION_COOKIE)
    with conn() as c:
        c.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (now.isoformat(),))
        if old_token:
            c.execute("DELETE FROM admin_sessions WHERE token_hash=?", (hashlib.sha256(old_token.encode()).hexdigest(),))
        c.execute("INSERT INTO admin_sessions(token_hash,username,created_at,expires_at) VALUES(?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), username, now.isoformat(), (now + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()))
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_TTL_SECONDS, secure=COOKIE_SECURE or request.url.scheme == "https", path="/")


class AccountCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    provider: Literal["sub2api", "newapi"]
    base_url: HttpUrl
    credential_kind: Literal["api_key", "account"] = "api_key"
    api_key: str | None = None
    access_token: str | None = None
    user_id: str | None = None
    enabled: bool = True
    threshold: float = Field(default=5, ge=0)
    notes: str | None = Field(default=None, max_length=200)


class AccountUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    base_url: HttpUrl | None = None
    credential_kind: Literal["api_key", "account"] | None = None
    api_key: str | None = None
    access_token: str | None = None
    user_id: str | None = None
    enabled: bool | None = None
    threshold: float | None = Field(default=None, ge=0)
    notes: str | None = Field(default=None, max_length=200)


def mask(value: str | None) -> str | None:
    if not value:
        return None
    return value[:4] + "••••" + value[-4:] if len(value) > 10 else "••••••••"


def account_view(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result.pop("api_key", None)
    result.pop("access_token", None)
    if result.get("credential_kind") == "account":
        result["credential"] = mask(row["access_token"])
    else:
        result["credential"] = mask(row["api_key"])
    result["enabled"] = bool(result["enabled"])
    if result.get("last_result"):
        import json
        result["balance"] = json.loads(result["last_result"])
    result.pop("last_result", None)
    return result


def normalize_url(url: str) -> str:
    return url.rstrip("/")


async def fetch_balance(row: sqlite3.Row) -> dict[str, Any]:
    base = normalize_url(row["base_url"])
    provider = row["provider"]
    headers: dict[str, str] = {"Accept": "application/json"}
    if row["credential_kind"] == "account" and row["access_token"]:
        headers["Authorization"] = f"Bearer {row['access_token']}"
        if row["user_id"]:
            headers["New-Api-User"] = row["user_id"]
    elif row["api_key"]:
        headers["Authorization"] = f"Bearer {row['api_key']}"
    else:
        raise ValueError("missing credential")

    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
        if provider == "sub2api":
            response = await client.get(f"{base}/v1/usage", headers=headers)
            response.raise_for_status()
            raw = response.json()
            quota = raw.get("quota") or {}
            remaining = raw.get("remaining", quota.get("remaining", raw.get("balance")))
            used = quota.get("used")
            total = quota.get("limit")
            if total is None and remaining is not None and used is not None:
                total = remaining + used
            return {"remaining": remaining, "used": used, "total": total, "unit": raw.get("unit", quota.get("unit", "USD")), "mode": raw.get("mode"), "is_valid": raw.get("isValid", True), "raw": raw}

        if row["credential_kind"] == "account":
            response = await client.get(f"{base}/api/user/self", headers=headers)
            response.raise_for_status()
            raw = response.json()
            data = raw.get("data", raw)
            # New API quota is an internal unit; status exposes the instance conversion.
            multiplier = 500000
            try:
                status = await client.get(f"{base}/api/status")
                if status.is_success:
                    multiplier = float(status.json().get("data", {}).get("quota_per_unit") or multiplier)
            except Exception:
                pass
            remaining = float(data.get("quota", 0)) / multiplier
            used = float(data.get("used_quota", 0)) / multiplier
            return {"remaining": remaining, "used": used, "total": remaining + used, "unit": "USD", "mode": "account", "is_valid": True, "raw": raw, "quota_per_unit": multiplier}

        response = await client.get(f"{base}/api/usage/token/", headers=headers)
        response.raise_for_status()
        raw = response.json()
        data = raw.get("data", raw)
        multiplier = 500000
        try:
            status = await client.get(f"{base}/api/status")
            if status.is_success:
                multiplier = float(status.json().get("data", {}).get("quota_per_unit") or multiplier)
        except Exception:
            pass
        unlimited = bool(data.get("unlimited_quota", False))
        remaining = None if unlimited else float(data.get("total_available", 0)) / multiplier
        used = float(data.get("total_used", 0)) / multiplier
        total = None if unlimited else float(data.get("total_granted", 0)) / multiplier
        return {"remaining": remaining, "used": used, "total": total, "unit": "USD", "mode": "api_key", "is_valid": bool(raw.get("code", True)), "raw": raw, "quota_per_unit": multiplier, "unlimited": unlimited, "expires_at": data.get("expires_at")}


async def check_account(account_id: str) -> dict[str, Any]:
    with conn() as c:
        row = c.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not row:
        raise HTTPException(404, "account not found")
    checked_at = utc_now()
    import json
    try:
        result = await fetch_balance(row)
        status, error = ("ok", None)
    except Exception as exc:
        result, status, error = ({"is_valid": False}, "error", str(exc)[:500])
    with conn() as c:
        c.execute("UPDATE accounts SET last_checked_at=?,last_status=?,last_error=?,last_result=?,updated_at=? WHERE id=?", (checked_at, status, error, json.dumps(result, ensure_ascii=False), checked_at, account_id))
        c.execute("INSERT INTO balance_snapshots(account_id,checked_at,status,remaining,used,total,unit,raw,error) VALUES(?,?,?,?,?,?,?,?,?)", (account_id, checked_at, status, result.get("remaining"), result.get("used"), result.get("total"), result.get("unit"), json.dumps(result.get("raw"), ensure_ascii=False), error))
    result.update({"status": status, "checked_at": checked_at, "error": error})
    return result


async def monitor_loop() -> None:
    while True:
        try:
            with conn() as c:
                ids = [r["id"] for r in c.execute("SELECT id FROM accounts WHERE enabled=1")]
            if ids:
                await asyncio.gather(*(check_account(i) for i in ids), return_exceptions=True)
        except Exception:
            pass
        await asyncio.sleep(POLL_SECONDS)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    bootstrap_admin()
    task = asyncio.create_task(monitor_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Balance Monitor API", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
_cors_origins = [x.strip().rstrip("/") for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip() and x.strip() != "*"]
if _cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type"])


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/api/auth/"):
        # Pydantic's default error includes the rejected input, which can be a password.
        return JSONResponse({"detail": "用户名须为 1–64 个字符；设置密码须为 12–256 个字符"}, status_code=422)
    return await request_validation_exception_handler(request, exc)

@app.middleware("http")
async def admin_session_guard(request: Request, call_next):
    path = request.url.path
    if path == "/api" or path.startswith("/api/"):
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not _origin_allowed(request):
            return JSONResponse({"detail": "不允许跨站请求"}, status_code=403)
        request.state.admin_username = _session_user(request)
        if path not in PUBLIC_API_PATHS and request.method != "OPTIONS" and not request.state.admin_username:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
    response = await call_next(request)
    if path == "/api" or path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username", mode="before")
    @classmethod
    def trim_username(cls, value):
        return value.strip() if isinstance(value, str) else value


class SetupPayload(LoginPayload):
    password: str = Field(min_length=12, max_length=256)


@app.get("/api/auth/status")
def auth_status(request: Request):
    username = request.state.admin_username
    return {"setup_required": _admin_row() is None, "authenticated": bool(username), "username": username}


@app.post("/api/auth/setup", status_code=201)
def setup_admin(payload: SetupPayload, request: Request, response: Response):
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        if c.execute("SELECT 1 FROM administrators WHERE id=1").fetchone():
            raise HTTPException(409, "管理员已设置，请登录")
        c.execute("INSERT INTO administrators(id,username,password_hash,created_at) VALUES(1,?,?,?)", (payload.username, _password_hash(payload.password), utc_now()))
    _new_session(payload.username, request, response)
    return {"username": payload.username}


@app.post("/api/auth/login")
def login(payload: LoginPayload, request: Request, response: Response):
    client_ip = _login_attempt(request)
    admin = _admin_row()
    if not admin:
        raise HTTPException(409, "请先设置管理员账号")
    password_matches = _password_verify(payload.password, admin["password_hash"])
    if not hmac.compare_digest(payload.username.encode(), admin["username"].encode()) or not password_matches:
        raise HTTPException(401, "用户名或密码错误")
    with _login_limit_lock:
        _login_failures.pop(client_ip, None)
    _new_session(admin["username"], request, response)
    return {"username": admin["username"]}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with conn() as c:
            c.execute("DELETE FROM admin_sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict", secure=COOKIE_SECURE or request.url.scheme == "https")
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request):
    return {"username": request.state.admin_username}


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "time": utc_now()}


@app.get("/api/accounts")
def list_accounts() -> list[dict[str, Any]]:
    with conn() as c:
        return [account_view(r) for r in c.execute("SELECT * FROM accounts ORDER BY created_at DESC")]


@app.post("/api/accounts", status_code=201)
def create_account(payload: AccountCreate) -> dict[str, Any]:
    if payload.provider == "newapi" and payload.credential_kind == "account" and not payload.access_token:
        raise HTTPException(400, "access_token is required for account mode")
    if payload.credential_kind == "api_key" and not payload.api_key:
        raise HTTPException(400, "api_key is required")
    now, account_id = utc_now(), str(uuid.uuid4())
    with conn() as c:
        c.execute("INSERT INTO accounts(id,name,provider,base_url,credential_kind,api_key,access_token,user_id,enabled,threshold,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (account_id, payload.name, payload.provider, str(payload.base_url).rstrip("/"), payload.credential_kind, payload.api_key, payload.access_token, payload.user_id, int(payload.enabled), payload.threshold, payload.notes, now, now))
        row = c.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    return account_view(row)


@app.patch("/api/accounts/{account_id}")
def update_account(account_id: str, payload: AccountUpdate) -> dict[str, Any]:
    values = payload.model_dump(exclude_unset=True)
    if "base_url" in values:
        values["base_url"] = str(values["base_url"]).rstrip("/")
    if "enabled" in values:
        values["enabled"] = int(values["enabled"])
    if not values:
        raise HTTPException(400, "no fields to update")
    with conn() as c:
        if not c.execute("SELECT 1 FROM accounts WHERE id=?", (account_id,)).fetchone():
            raise HTTPException(404, "account not found")
        values["updated_at"] = utc_now()
        clause = ",".join(f"{k}=?" for k in values)
        c.execute(f"UPDATE accounts SET {clause} WHERE id=?", (*values.values(), account_id))
        row = c.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    return account_view(row)


@app.delete("/api/accounts/{account_id}", status_code=200)
def delete_account(account_id: str) -> None:
    with conn() as c:
        deleted = c.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        if deleted.rowcount == 0:
            raise HTTPException(404, "account not found")


@app.post("/api/accounts/{account_id}/check")
async def check(account_id: str) -> dict[str, Any]:
    return await check_account(account_id)


@app.get("/api/accounts/{account_id}/history")
def history(account_id: str, limit: int = 30) -> list[dict[str, Any]]:
    import json
    limit = min(max(limit, 1), 200)
    with conn() as c:
        if not c.execute("SELECT 1 FROM accounts WHERE id=?", (account_id,)).fetchone():
            raise HTTPException(404, "account not found")
        rows = c.execute("SELECT id,checked_at,status,remaining,used,total,unit,raw,error FROM balance_snapshots WHERE account_id=? ORDER BY checked_at DESC LIMIT ?", (account_id, limit)).fetchall()
    return [{**dict(r), "raw": json.loads(r["raw"]) if r["raw"] else None} for r in rows]


@app.post("/api/accounts/check-all")
async def check_all() -> dict[str, Any]:
    with conn() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM accounts WHERE enabled=1")]
    results = await asyncio.gather(*(check_account(i) for i in ids), return_exceptions=True)
    return {"checked": len(ids), "results": [r if isinstance(r, dict) else {"error": str(r)} for r in results]}



@app.get("/{path:path}")
def frontend(path: str):
    # Keep SPA fallback while refusing requests that resemble filesystem traversal
    # or internal source/data paths after URL normalization by the ASGI server.
    segments = {part for part in path.split("/") if part}
    if (path in {"docs", "redoc", "openapi.json"} or path == "api" or path.startswith("api/")
            or "backend" in segments or "data" in segments or path.endswith((".py", ".db", ".sqlite"))):
        raise HTTPException(404, "not found")
    public_dir = Path(__file__).resolve().parent / "public"
    if not public_dir.exists(): public_dir = Path(__file__).resolve().parent.parent / "public"
    public_dir = public_dir.resolve()
    file = (public_dir / path).resolve()
    if not file.is_relative_to(public_dir):
        raise HTTPException(404, "not found")
    if path and file.is_file(): return FileResponse(file)
    return FileResponse(public_dir / "index.html")
