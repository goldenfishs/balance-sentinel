from __future__ import annotations

import asyncio
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, HttpUrl


DB_PATH = Path(os.getenv("DATABASE_PATH", "/data/balance-monitor.db"))
POLL_SECONDS = max(30, int(os.getenv("MONITOR_INTERVAL_SECONDS", "300")))


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
            """
        )


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
    task = asyncio.create_task(monitor_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Balance Monitor API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in os.getenv("CORS_ORIGINS", "*").split(",")], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


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
        c.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        if c.rowcount == 0:
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
    public_dir = Path(__file__).resolve().parent / "public"
    if not public_dir.exists(): public_dir = Path(__file__).resolve().parent.parent / "public"
    file = public_dir / path
    if path and file.is_file(): return FileResponse(file)
    return FileResponse(public_dir / "index.html")
