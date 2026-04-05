import base64
import collections
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import tarfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import paramiko
import routeros_api
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from routes_auth_users import register_auth_user_routes
from routes_devices import register_device_routes
from routes_system import register_system_routes
from routes_terminal_backups import register_terminal_backup_routes

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "devices.db"
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
SYSTEM_BACKUP_DIR = DATA_DIR / "system-backups"
SYSTEM_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
SECRET = os.environ.get("MIM_SECRET", "")
DEFAULT_ADMIN_PASSWORD = os.environ.get("MIM_ADMIN_PASSWORD", "admin")
TOKEN_TTL_SECONDS = int(os.environ.get("MIM_TOKEN_TTL_SECONDS", "28800"))
SSH_IDLE_TTL_SECONDS = int(os.environ.get("MIM_SSH_IDLE_TTL_SECONDS", "120"))
SSH_CONNECT_TIMEOUT = int(os.environ.get("MIM_SSH_CONNECT_TIMEOUT", "10"))
SSH_COMMAND_TIMEOUT = int(os.environ.get("MIM_SSH_COMMAND_TIMEOUT", "25"))
SSH_KEEPALIVE_SECONDS = int(os.environ.get("MIM_SSH_KEEPALIVE_SECONDS", "20"))
SSH_RETRY_ATTEMPTS = int(os.environ.get("MIM_SSH_RETRY_ATTEMPTS", "2"))
SSH_RETRY_BASE_MS = int(os.environ.get("MIM_SSH_RETRY_BASE_MS", "220"))
BROADCAST_CONFIRM_TTL_SECONDS = int(os.environ.get("MIM_BROADCAST_CONFIRM_TTL_SECONDS", "90"))
ROS_VERSION_RECHECK_SECONDS = int(os.environ.get("MIM_ROS_VERSION_RECHECK_SECONDS", "1800"))
GLOBAL_SSH_LIMIT_DEFAULT = int(os.environ.get("MIM_GLOBAL_SSH_LIMIT", "4"))
ROS_API_TIMEOUT = int(os.environ.get("MIM_ROS_API_TIMEOUT", "8"))
HEALTH_STALE_SECONDS = int(os.environ.get("MIM_HEALTH_STALE_SECONDS", "120"))
HEALTH_HIGH_QUEUE_DEPTH = int(os.environ.get("MIM_HEALTH_HIGH_QUEUE_DEPTH", "3"))
HEALTH_WORKER_ENABLED = str(os.environ.get("MIM_HEALTH_WORKER_ENABLED", "1")).strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
HEALTH_WORKER_INTERVAL_SECONDS = int(os.environ.get("MIM_HEALTH_WORKER_INTERVAL_SECONDS", "45"))
HEALTH_WORKER_COMMAND = os.environ.get("MIM_HEALTH_WORKER_COMMAND", "/system identity print without-paging").strip() or "/system identity print without-paging"
ALERT_COOLDOWN_SECONDS = int(os.environ.get("MIM_ALERT_COOLDOWN_SECONDS", "300"))
ALERT_WEBHOOK_URL = os.environ.get("MIM_ALERT_WEBHOOK_URL", "").strip()
ALERT_REPEAT_WHILE_DOWN = str(os.environ.get("MIM_ALERT_REPEAT_WHILE_DOWN", "0")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ALERT_HISTORY_MAX = int(os.environ.get("MIM_ALERT_HISTORY_MAX", "500"))

ROLE_LEVEL = {"viewer": 1, "operator": 2, "admin": 3}
SSH_POOL_LOCK = threading.Lock()
SSH_POOL: dict[str, dict] = {}
DEVICE_QUEUES_LOCK = threading.Lock()
DEVICE_QUEUES: dict[str, dict] = {}
SSH_DIAG_LOCK = threading.Lock()
SSH_DIAG: dict[str, dict] = {}
DEVICE_PROFILE_LOCK = threading.Lock()
DEVICE_PROFILE: dict[str, dict] = {}
GLOBAL_SSH_COND = threading.Condition()
GLOBAL_SSH_ACTIVE = 0
GLOBAL_SSH_WAITING = 0
GLOBAL_SSH_LIMIT = max(1, GLOBAL_SSH_LIMIT_DEFAULT)
HEALTH_WORKER_STOP = threading.Event()
HEALTH_WORKER_THREAD: threading.Thread | None = None
HEALTH_WORKER_STATE_LOCK = threading.Lock()
HEALTH_WORKER_STATE: dict[int, dict] = {}
ALERTS_LOCK = threading.Lock()
ALERT_HISTORY = collections.deque(maxlen=max(50, ALERT_HISTORY_MAX))
ALERT_LAST_SENT: dict[str, float] = {}
ALERT_SEQ = 0
HEALTH_WORKER_RUNTIME_LOCK = threading.Lock()
HEALTH_WORKER_RUNTIME = {
    "last_cycle_at": None,
    "last_cycle_duration_ms": None,
    "last_cycle_devices": 0,
    "last_cycle_failures": 0,
}


def _derive_auth_secret(secret: str) -> str:
    return hashlib.sha256(f"mim-auth:{secret}".encode()).hexdigest()


def _parse_cors_origins(raw: str) -> list[str]:
    items = [item.strip() for item in (raw or "").split(",") if item.strip()]
    if not items:
        return []
    if "*" in items:
        return ["*"]
    return items


if not SECRET:
    raise RuntimeError("MIM_SECRET is required")

AUTH_SECRET = os.environ.get("MIM_AUTH_SECRET", "").strip() or _derive_auth_secret(SECRET)
CORS_ORIGINS = _parse_cors_origins(os.environ.get("MIM_CORS_ORIGINS", ""))

if not AUTH_SECRET:
    raise RuntimeError("MIM_AUTH_SECRET or MIM_SECRET is required")

fernet = Fernet(SECRET.encode())

app = FastAPI(title="Mikro Interface Manager")
if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials="*" not in CORS_ORIGINS,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
app.mount("/static", StaticFiles(directory="static"), name="static")


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=255)


class DeviceUpdateIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=80)
    password: str | None = Field(default=None, min_length=1, max_length=255)


class InterfaceToggle(BaseModel):
    disabled: bool


class InterfaceEdit(BaseModel):
    new_name: str | None = Field(default=None, max_length=80)
    mtu: int | None = Field(default=None, ge=68, le=65535)
    comment: str | None = Field(default=None, max_length=300)


class BackupUpload(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=2_000_000)


class TerminalCommand(BaseModel):
    command: str = Field(min_length=1, max_length=500)


class BroadcastExecuteIn(BaseModel):
    command: str = Field(min_length=1, max_length=500)
    confirm_token: str = Field(min_length=16, max_length=4096)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=255)


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=6, max_length=255)
    role: str = Field(min_length=5, max_length=10)


class ChangePasswordIn(BaseModel):
    new_password: str = Field(min_length=6, max_length=255)


class DeviceBulkImportIn(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    update_existing: bool = False
    content: str | None = Field(default=None, max_length=2_000_000)
    server_path: str | None = Field(default=None, max_length=500)


class SSHConcurrencyIn(BaseModel):
    limit: int = Field(ge=1, le=32)


class HealthWorkerToggleIn(BaseModel):
    enabled: bool


def init_db() -> None:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                role TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                owner_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                device_id INTEGER,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "password_hash" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        if "password" in user_cols:
            rows = conn.execute("SELECT id, password, password_hash FROM users").fetchall()
            for row in rows:
                if (not row[2]) and row[1]:
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(str(row[1])), row[0]))

        device_cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "owner_id" not in device_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN owner_id INTEGER")
        if "ros_version" not in device_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN ros_version TEXT")
        if "ros_version_checked_at" not in device_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN ros_version_checked_at TEXT")

        conn.commit()

    ensure_default_users()

    with closing(db_conn()) as conn:
        admin = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if admin:
            conn.execute("UPDATE devices SET owner_id = ? WHERE owner_id IS NULL", (int(admin["id"]),))
            conn.commit()


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def get_setting(key: str, default: str | None = None) -> str | None:
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    return str(row["value"])


def set_setting(key: str, value: str) -> None:
    with closing(db_conn()) as conn:
        conn.execute(
            "INSERT INTO app_settings(key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
            (key, str(value)),
        )
        conn.commit()


def set_global_ssh_limit(limit: int) -> int:
    global GLOBAL_SSH_LIMIT
    safe = max(1, int(limit))
    with GLOBAL_SSH_COND:
        GLOBAL_SSH_LIMIT = safe
        GLOBAL_SSH_COND.notify_all()
    return safe


def _is_enabled_value(value: str | None, default: bool = True) -> bool:
    if value is None:
        return bool(default)
    v = str(value).strip().lower()
    if v in {"1", "true", "yes", "on"}:
        return True
    if v in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def get_global_ssh_runtime() -> dict:
    with GLOBAL_SSH_COND:
        return {
            "limit": int(GLOBAL_SSH_LIMIT),
            "active": int(GLOBAL_SSH_ACTIVE),
            "waiting": int(GLOBAL_SSH_WAITING),
        }


def set_health_worker_enabled(enabled: bool) -> bool:
    global HEALTH_WORKER_ENABLED
    HEALTH_WORKER_ENABLED = bool(enabled)
    if HEALTH_WORKER_ENABLED:
        start_health_worker()
    else:
        stop_health_worker()
    return HEALTH_WORKER_ENABLED


def _acquire_global_ssh_slot() -> None:
    global GLOBAL_SSH_ACTIVE, GLOBAL_SSH_WAITING
    with GLOBAL_SSH_COND:
        GLOBAL_SSH_WAITING += 1
        try:
            while GLOBAL_SSH_ACTIVE >= GLOBAL_SSH_LIMIT:
                GLOBAL_SSH_COND.wait()
            GLOBAL_SSH_ACTIVE += 1
        finally:
            GLOBAL_SSH_WAITING = max(0, GLOBAL_SSH_WAITING - 1)


def _release_global_ssh_slot() -> None:
    global GLOBAL_SSH_ACTIVE
    with GLOBAL_SSH_COND:
        GLOBAL_SSH_ACTIVE = max(0, GLOBAL_SSH_ACTIVE - 1)
        GLOBAL_SSH_COND.notify_all()


def load_runtime_settings() -> None:
    raw = get_setting("global_ssh_limit", str(GLOBAL_SSH_LIMIT_DEFAULT))
    try:
        limit = max(1, int(raw or GLOBAL_SSH_LIMIT_DEFAULT))
    except Exception:
        limit = max(1, GLOBAL_SSH_LIMIT_DEFAULT)
    set_global_ssh_limit(limit)

    worker_default = "1" if HEALTH_WORKER_ENABLED else "0"
    worker_raw = get_setting("health_worker_enabled", worker_default)
    set_health_worker_enabled(_is_enabled_value(worker_raw, default=HEALTH_WORKER_ENABLED))


def hash_password(password: str, salt_hex: str | None = None) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, saved_hash: str) -> bool:
    try:
        salt_hex, digest_hex = saved_hash.split(":", 1)
    except ValueError:
        return False
    check = hash_password(password, salt_hex)
    return hmac.compare_digest(check, f"{salt_hex}:{digest_hex}")


def ensure_default_users() -> None:
    with closing(db_conn()) as conn:
        admin = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if not admin:
            conn.execute(
                "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hash_password(DEFAULT_ADMIN_PASSWORD), "admin"),
            )
        operator = conn.execute("SELECT id FROM users WHERE username = 'operator'").fetchone()
        if not operator:
            conn.execute(
                "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                ("operator", hash_password("operator"), "operator"),
            )
        conn.commit()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def make_token(username: str, role: str) -> str:
    payload = {
        "u": username,
        "r": role,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    encoded = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(AUTH_SECRET.encode(), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{_b64u(sig)}"


def parse_token(token: str) -> dict:
    try:
        encoded, signature = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")

    expected_sig = _b64u(hmac.new(AUTH_SECRET.encode(), encoded.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected_sig):
        raise HTTPException(status_code=401, detail="Invalid token signature")

    try:
        payload = json.loads(_b64u_decode(encoded).decode())
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token payload: {e}")

    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=401, detail="Token expired")

    return payload


def current_user(request: Request) -> sqlite3.Row:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    payload = parse_token(token)
    username = payload.get("u", "")
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return row


def require_role(request: Request, min_role: str) -> sqlite3.Row:
    user = current_user(request)
    user_level = ROLE_LEVEL.get(user["role"], 0)
    required = ROLE_LEVEL.get(min_role, 0)
    if user_level < required:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return user


def log_audit(username: str, role: str, action: str, device_id: int | None = None, details: str = "") -> None:
    with closing(db_conn()) as conn:
        conn.execute(
            "INSERT INTO audit_logs(username, role, action, device_id, details) VALUES (?, ?, ?, ?, ?)",
            (username, role, action, device_id, details[:1000]),
        )
        conn.commit()


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _record_alert(
    event: str,
    severity: str,
    device_id: int | None,
    device_name: str,
    message: str,
    details: str = "",
    webhook_status: int | None = None,
    webhook_error: str | None = None,
) -> dict:
    global ALERT_SEQ
    entry = {
        "id": 0,
        "created_at": _utc_now_iso(),
        "event": event,
        "severity": severity,
        "device_id": device_id,
        "device_name": device_name,
        "message": message,
        "details": details,
        "webhook_enabled": bool(ALERT_WEBHOOK_URL),
        "webhook_status": webhook_status,
        "webhook_error": webhook_error,
    }
    with ALERTS_LOCK:
        ALERT_SEQ += 1
        entry["id"] = ALERT_SEQ
        ALERT_HISTORY.append(entry)
    return entry


def list_alert_history(limit: int = 200) -> list[dict]:
    safe = max(1, min(2000, int(limit)))
    with ALERTS_LOCK:
        items = list(ALERT_HISTORY)
    if not items:
        return []
    items = items[-safe:]
    items.reverse()
    return [dict(x) for x in items]


def list_active_health_issues() -> list[dict]:
    with HEALTH_WORKER_STATE_LOCK:
        out = [dict(v) for v in HEALTH_WORKER_STATE.values() if v.get("is_down")]
    out.sort(key=lambda x: x.get("last_change_at") or "", reverse=True)
    return out


def get_health_worker_runtime() -> dict:
    with HEALTH_WORKER_RUNTIME_LOCK:
        runtime = dict(HEALTH_WORKER_RUNTIME)
    with HEALTH_WORKER_STATE_LOCK:
        tracked = len(HEALTH_WORKER_STATE)
        active_alerts = sum(1 for x in HEALTH_WORKER_STATE.values() if x.get("is_down"))
    return {
        "enabled": bool(HEALTH_WORKER_ENABLED),
        "running": bool(HEALTH_WORKER_THREAD and HEALTH_WORKER_THREAD.is_alive()),
        "interval_seconds": int(max(10, HEALTH_WORKER_INTERVAL_SECONDS)),
        "command": HEALTH_WORKER_COMMAND,
        "alert_cooldown_seconds": int(max(30, ALERT_COOLDOWN_SECONDS)),
        "tracked_devices": int(tracked),
        "active_alerts": int(active_alerts),
        **runtime,
    }


def _emit_health_alert(event: str, severity: str, row: sqlite3.Row, message: str, details: str = "") -> None:
    device_id = int(row["id"]) if row and row["id"] is not None else None
    device_name = row["name"] if row and row["name"] else "unknown"
    dedupe_key = f"{event}:{device_id or 0}"
    now = time.time()
    cooldown = max(30, int(ALERT_COOLDOWN_SECONDS))

    with ALERTS_LOCK:
        last_sent = float(ALERT_LAST_SENT.get(dedupe_key, 0) or 0)
        if (now - last_sent) < cooldown:
            return
        ALERT_LAST_SENT[dedupe_key] = now

    webhook_status = None
    webhook_error = None
    payload = {
        "created_at": _utc_now_iso(),
        "event": event,
        "severity": severity,
        "device": {
            "id": device_id,
            "name": device_name,
            "host": row["host"],
            "port": int(row["port"]),
        },
        "message": message,
        "details": details,
    }

    if ALERT_WEBHOOK_URL:
        req = urllib.request.Request(
            ALERT_WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                webhook_status = int(getattr(resp, "status", resp.getcode()))
        except urllib.error.HTTPError as e:
            webhook_status = int(getattr(e, "code", 0) or 0)
            webhook_error = str(e)
        except Exception as e:
            webhook_error = str(e)

    _record_alert(
        event=event,
        severity=severity,
        device_id=device_id,
        device_name=device_name,
        message=message,
        details=details,
        webhook_status=webhook_status,
        webhook_error=webhook_error,
    )
    try:
        log_audit("system", "admin", "health_alert", device_id, f"{event}: {message}")
    except Exception:
        pass


def _set_health_worker_state(row: sqlite3.Row, is_down: bool, last_error: str | None) -> tuple[bool, bool]:
    device_id = int(row["id"])
    now_iso = _utc_now_iso()
    with HEALTH_WORKER_STATE_LOCK:
        prev = HEALTH_WORKER_STATE.get(device_id)
        prev_down = bool(prev and prev.get("is_down"))
        changed = (prev is None) or (prev_down != bool(is_down))
        HEALTH_WORKER_STATE[device_id] = {
            "device_id": device_id,
            "name": row["name"],
            "host": row["host"],
            "port": int(row["port"]),
            "is_down": bool(is_down),
            "last_error": (last_error or "")[:300] if last_error else None,
            "last_checked_at": now_iso,
            "last_change_at": now_iso if changed else (prev.get("last_change_at") if prev else now_iso),
        }
    return prev_down, changed


def _health_worker_devices() -> list[sqlite3.Row]:
    with closing(db_conn()) as conn:
        rows = conn.execute(
            "SELECT id, name, host, port, username, password_enc FROM devices ORDER BY id"
        ).fetchall()
    return rows


def _health_worker_cycle() -> tuple[int, int]:
    rows = _health_worker_devices()
    failures = 0
    seen_ids = set()
    for row in rows:
        if HEALTH_WORKER_STOP.is_set():
            break
        seen_ids.add(int(row["id"]))
        dkey = _device_key(row["host"], int(row["port"]))
        try:
            password = fernet.decrypt(row["password_enc"].encode()).decode()
            safe_ssh_exec(row["host"], int(row["port"]), row["username"], password, HEALTH_WORKER_COMMAND)
            _diag_mark_event(dkey, "health_probe_ok")
            was_down, changed = _set_health_worker_state(row, is_down=False, last_error=None)
            if was_down and changed:
                _emit_health_alert("device_recovered", "info", row, "Device recovered and is reachable")
        except HTTPException as e:
            failures += 1
            detail = str(e.detail)
            _diag_mark_event(dkey, "health_probe_failed")
            was_down, changed = _set_health_worker_state(row, is_down=True, last_error=detail)
            if (not was_down and changed) or ALERT_REPEAT_WHILE_DOWN:
                _emit_health_alert("device_down", "critical", row, "Device is unreachable", detail)
        except Exception as e:
            failures += 1
            detail = str(e)
            _diag_mark_event(dkey, "health_probe_failed")
            was_down, changed = _set_health_worker_state(row, is_down=True, last_error=detail)
            if (not was_down and changed) or ALERT_REPEAT_WHILE_DOWN:
                _emit_health_alert("device_down", "critical", row, "Device is unreachable", detail)

    with HEALTH_WORKER_STATE_LOCK:
        for device_id in list(HEALTH_WORKER_STATE.keys()):
            if device_id not in seen_ids:
                HEALTH_WORKER_STATE.pop(device_id, None)

    return len(rows), failures


def _health_worker_main() -> None:
    interval = max(10, int(HEALTH_WORKER_INTERVAL_SECONDS))
    while not HEALTH_WORKER_STOP.is_set():
        started = time.time()
        devices = 0
        failures = 0
        try:
            devices, failures = _health_worker_cycle()
        except Exception as e:
            _record_alert(
                event="health_worker_error",
                severity="warning",
                device_id=None,
                device_name="worker",
                message="Health worker cycle failed",
                details=str(e),
            )
        duration_ms = int((time.time() - started) * 1000)
        with HEALTH_WORKER_RUNTIME_LOCK:
            HEALTH_WORKER_RUNTIME["last_cycle_at"] = _utc_now_iso()
            HEALTH_WORKER_RUNTIME["last_cycle_duration_ms"] = duration_ms
            HEALTH_WORKER_RUNTIME["last_cycle_devices"] = int(devices)
            HEALTH_WORKER_RUNTIME["last_cycle_failures"] = int(failures)

        wait_for = max(1, interval - int(time.time() - started))
        if HEALTH_WORKER_STOP.wait(wait_for):
            break


def start_health_worker() -> None:
    global HEALTH_WORKER_THREAD
    if not HEALTH_WORKER_ENABLED:
        return
    if HEALTH_WORKER_THREAD and HEALTH_WORKER_THREAD.is_alive():
        return
    HEALTH_WORKER_STOP.clear()
    HEALTH_WORKER_THREAD = threading.Thread(target=_health_worker_main, name="mim-health-worker", daemon=True)
    HEALTH_WORKER_THREAD.start()


def stop_health_worker() -> None:
    global HEALTH_WORKER_THREAD
    HEALTH_WORKER_STOP.set()
    t = HEALTH_WORKER_THREAD
    if t and t.is_alive():
        t.join(timeout=8)
    HEALTH_WORKER_THREAD = None


def _ssh_pool_key(host: str, port: int, username: str, password: str) -> str:
    pw_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
    return f"{host}|{port}|{username}|{pw_hash}"


def _device_key(host: str, port: int) -> str:
    return f"{host}|{port}"


def _diag_get(device_key: str) -> dict:
    with SSH_DIAG_LOCK:
        entry = SSH_DIAG.get(device_key)
        if entry:
            entry.setdefault("last_rtt_ms", None)
            entry.setdefault("last_error", None)
            entry.setdefault("reconnect_count", 0)
            entry.setdefault("last_connected_at", None)
            entry.setdefault("last_success_at", None)
            entry.setdefault("last_attempt_at", None)
            entry.setdefault("last_health_check_at", None)
            entry.setdefault("last_event", None)
            return entry
        entry = {
            "last_rtt_ms": None,
            "last_error": None,
            "reconnect_count": 0,
            "last_connected_at": None,
            "last_success_at": None,
            "last_attempt_at": None,
            "last_health_check_at": None,
            "last_event": None,
        }
        SSH_DIAG[device_key] = entry
        return entry


def _diag_mark_attempt(device_key: str) -> None:
    diag = _diag_get(device_key)
    ts = datetime.utcnow().isoformat() + "Z"
    diag["last_attempt_at"] = ts
    diag["last_health_check_at"] = ts


def _diag_mark_connect(device_key: str, reconnect: bool) -> None:
    diag = _diag_get(device_key)
    had_connected_before = bool(diag.get("last_connected_at"))
    diag["last_connected_at"] = datetime.utcnow().isoformat() + "Z"
    diag["last_event"] = "connected"
    if reconnect and had_connected_before:
        diag["reconnect_count"] += 1


def _diag_mark_success(device_key: str, rtt_ms: int) -> None:
    diag = _diag_get(device_key)
    ts = datetime.utcnow().isoformat() + "Z"
    diag["last_rtt_ms"] = rtt_ms
    diag["last_error"] = None
    diag["last_success_at"] = ts
    diag["last_health_check_at"] = ts
    diag["last_event"] = "command_success"


def _diag_mark_error(device_key: str, err: str) -> None:
    diag = _diag_get(device_key)
    diag["last_health_check_at"] = datetime.utcnow().isoformat() + "Z"
    diag["last_error"] = (err or "unknown")[:300]
    diag["last_event"] = "error"


def _diag_mark_event(device_key: str, event_name: str) -> None:
    diag = _diag_get(device_key)
    diag["last_event"] = (event_name or "event")[:80]


def _make_broadcast_confirm_token(command: str, username: str, device_ids: list[int]) -> str:
    payload = {
        "cmd": command,
        "u": username,
        "ids": device_ids,
        "exp": int(time.time()) + BROADCAST_CONFIRM_TTL_SECONDS,
    }
    encoded = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(AUTH_SECRET.encode(), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{_b64u(sig)}"


def _verify_broadcast_confirm_token(token: str, command: str, username: str) -> dict:
    payload = parse_token(token)
    if payload.get("u") != username:
        raise HTTPException(status_code=403, detail="Broadcast confirm token is bound to another user")
    if payload.get("cmd") != command:
        raise HTTPException(status_code=400, detail="Broadcast command does not match confirmation token")
    ids = payload.get("ids")
    if not isinstance(ids, list):
        raise HTTPException(status_code=400, detail="Invalid broadcast confirmation token payload")
    return payload


def _get_device_queue(key: str) -> dict:
    with DEVICE_QUEUES_LOCK:
        queue = DEVICE_QUEUES.get(key)
        if queue:
            return queue
        queue = {
            "cond": threading.Condition(),
            "tokens": collections.deque(),
            "last_used": time.time(),
        }
        DEVICE_QUEUES[key] = queue
        return queue


def _run_device_queued(key: str, func):
    queue = _get_device_queue(key)
    token = object()

    with queue["cond"]:
        queue["tokens"].append(token)
        while queue["tokens"][0] is not token:
            queue["cond"].wait()

    try:
        queue["last_used"] = time.time()
        _acquire_global_ssh_slot()
        try:
            return func()
        finally:
            _release_global_ssh_slot()
    finally:
        with queue["cond"]:
            if queue["tokens"] and queue["tokens"][0] is token:
                queue["tokens"].popleft()
            else:
                try:
                    queue["tokens"].remove(token)
                except ValueError:
                    pass
            queue["cond"].notify_all()


def _is_pool_entry_active(entry: dict) -> bool:
    try:
        transport = entry["client"].get_transport()
        return bool(transport and transport.is_active())
    except Exception:
        return False


def _close_client_safely(client: paramiko.SSHClient) -> None:
    try:
        client.close()
    except Exception:
        pass


def _cleanup_ssh_pool() -> None:
    now = time.time()
    to_remove = []
    with SSH_POOL_LOCK:
        for key, entry in SSH_POOL.items():
            idle_too_long = (now - entry.get("last_used", 0)) > SSH_IDLE_TTL_SECONDS
            if idle_too_long or not _is_pool_entry_active(entry):
                to_remove.append(key)

        for key in to_remove:
            entry = SSH_POOL.pop(key, None)
            if entry:
                _close_client_safely(entry["client"])

    queue_cleanup = []
    with DEVICE_QUEUES_LOCK:
        for key, queue in DEVICE_QUEUES.items():
            if queue["tokens"]:
                continue
            if (now - queue.get("last_used", 0)) > (SSH_IDLE_TTL_SECONDS * 2):
                queue_cleanup.append(key)
        for key in queue_cleanup:
            DEVICE_QUEUES.pop(key, None)


def _drop_pooled_client(key: str) -> None:
    with SSH_POOL_LOCK:
        entry = SSH_POOL.pop(key, None)
    if entry:
        _close_client_safely(entry["client"])


def _create_pool_entry(host: str, port: int, username: str, password: str) -> dict:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=SSH_CONNECT_TIMEOUT,
        banner_timeout=SSH_CONNECT_TIMEOUT,
        auth_timeout=SSH_CONNECT_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(SSH_KEEPALIVE_SECONDS)
    return {"client": client, "last_used": time.time(), "lock": threading.Lock()}


def _get_or_create_pool_entry(host: str, port: int, username: str, password: str) -> tuple[str, dict]:
    _cleanup_ssh_pool()
    key = _ssh_pool_key(host, port, username, password)
    dkey = _device_key(host, port)

    with SSH_POOL_LOCK:
        existing = SSH_POOL.get(key)
        if existing and _is_pool_entry_active(existing):
            existing["last_used"] = time.time()
            return key, existing

    new_entry = _create_pool_entry(host, port, username, password)
    _diag_mark_connect(dkey, reconnect=True)
    with SSH_POOL_LOCK:
        existing = SSH_POOL.get(key)
        if existing and _is_pool_entry_active(existing):
            _close_client_safely(new_entry["client"])
            existing["last_used"] = time.time()
            return key, existing
        SSH_POOL[key] = new_entry
        return key, new_entry


def _ssh_exec_once(host: str, port: int, username: str, password: str, command: str) -> str:
    dkey = _device_key(host, port)
    _diag_mark_attempt(dkey)
    key, entry = _get_or_create_pool_entry(host, port, username, password)
    started = time.perf_counter()
    try:
        with entry["lock"]:
            if not _is_pool_entry_active(entry):
                _drop_pooled_client(key)
                key, entry = _get_or_create_pool_entry(host, port, username, password)

            _, stdout, stderr = entry["client"].exec_command(command, timeout=SSH_COMMAND_TIMEOUT)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")

            with SSH_POOL_LOCK:
                if key in SSH_POOL:
                    SSH_POOL[key]["last_used"] = time.time()

            rtt_ms = int((time.perf_counter() - started) * 1000)
            _diag_mark_success(dkey, rtt_ms)
            return (out + "\n" + err).strip()
    except Exception:
        _diag_mark_error(dkey, "command execution failed")
        _drop_pooled_client(key)
        raise


def ssh_exec(host: str, port: int, username: str, password: str, command: str) -> str:
    def _run():
        attempts_total = max(1, SSH_RETRY_ATTEMPTS + 1)
        last_exc = None
        for attempt in range(1, attempts_total + 1):
            try:
                return _ssh_exec_once(host, port, username, password, command)
            except (TimeoutError, socket.timeout, paramiko.SSHException, OSError) as exc:
                last_exc = exc
                _diag_mark_error(_device_key(host, port), str(exc))
                if attempt >= attempts_total:
                    break
                backoff_sec = (SSH_RETRY_BASE_MS / 1000.0) * (2 ** (attempt - 1))
                time.sleep(backoff_sec)
        raise last_exc if last_exc else RuntimeError("SSH command failed")

    return _run_device_queued(_device_key(host, port), _run)


def safe_ssh_exec(host: str, port: int, username: str, password: str, command: str) -> str:
    try:
        return ssh_exec(host, port, username, password, command)
    except TimeoutError:
        _diag_mark_error(_device_key(host, port), "timeout")
        raise HTTPException(
            status_code=400,
            detail=f"SSH timeout: cannot reach {host}:{port}. Check route, firewall, and SSH service on MikroTik.",
        )
    except socket.timeout:
        _diag_mark_error(_device_key(host, port), "socket timeout")
        raise HTTPException(
            status_code=400,
            detail=f"SSH timeout: cannot reach {host}:{port}. Check route, firewall, and SSH service on MikroTik.",
        )
    except paramiko.AuthenticationException:
        _diag_mark_error(_device_key(host, port), "authentication failed")
        raise HTTPException(status_code=400, detail="SSH authentication failed. Check username/password.")
    except paramiko.SSHException as e:
        _diag_mark_error(_device_key(host, port), str(e))
        raise HTTPException(status_code=400, detail=f"SSH protocol error: {e}")
    except OSError as e:
        _diag_mark_error(_device_key(host, port), str(e))
        raise HTTPException(status_code=400, detail=f"Network error while connecting to {host}:{port}: {e}")


def test_routeros_api(host: str, username: str, password: str, api_port: int = 8728, use_ssl: bool = False) -> dict:
    pool = None
    try:
        pool = routeros_api.RouterOsApiPool(
            host,
            username=username,
            password=password,
            port=int(api_port),
            use_ssl=bool(use_ssl),
            ssl_verify=False,
            ssl_verify_hostname=False,
            plaintext_login=True,
            socket_timeout=ROS_API_TIMEOUT,
        )
        api = pool.get_api()
        identity_res = api.get_resource("/system/identity")
        rows = identity_res.get()
        name = rows[0].get("name") if rows else None
        ros_version = None
        try:
            res = api.get_resource("/system/resource")
            rrows = res.get()
            if rrows:
                ros_version = rrows[0].get("version")
        except Exception:
            ros_version = None
        return {
            "ok": True,
            "identity": name or "unknown",
            "ros_version": ros_version,
            "api_port": int(api_port),
            "api_ssl": bool(use_ssl),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"RouterOS API connection failed on {host}:{api_port}: {e}")
    finally:
        if pool is not None:
            try:
                pool.disconnect()
            except Exception:
                pass


def _is_compat_error_detail(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return False
    return any(
        x in t
        for x in [
            "expected end of command",
            "syntax error",
            "input does not match any value",
            "bad command name",
            "no such command",
            "unknown command",
        ]
    )


def _looks_like_command_error_output(text: str) -> bool:
    if not text:
        return False
    lines = [ln.strip().lower() for ln in str(text).splitlines() if ln.strip()]
    if not lines:
        return False
    first = lines[0]
    return (
        first.startswith("failure:")
        or "expected end of command" in first
        or "input does not match any value" in first
        or "bad command name" in first
        or "unknown command" in first
        or first.startswith("syntax error")
    )


def _is_transport_error_detail(text: str) -> bool:
    t = (text or "").lower()
    return any(
        x in t
        for x in [
            "ssh timeout",
            "authentication failed",
            "network error",
            "ssh protocol error",
            "cannot reach",
        ]
    )


def _extract_ros_version(text: str) -> str | None:
    content = text or ""
    m = re.search(r"version\s*[:=]\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", content, flags=re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b", content)
    if m:
        return m.group(1)
    return None


def _ros_major(version: str | None) -> int | None:
    if not version:
        return None
    try:
        return int(str(version).split(".", 1)[0])
    except Exception:
        return None


def set_device_ros_version(device_id: int, version: str | None) -> None:
    ts = datetime.utcnow().isoformat() + "Z"
    with closing(db_conn()) as conn:
        conn.execute(
            "UPDATE devices SET ros_version = ?, ros_version_checked_at = ? WHERE id = ?",
            (version, ts, device_id),
        )
        conn.commit()


def get_device_ros_version(device_id: int) -> str | None:
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT ros_version FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not row:
        return None
    return row["ros_version"]


def remember_device_profile_version(host: str, port: int, version: str | None) -> None:
    dkey = _device_key(host, port)
    with DEVICE_PROFILE_LOCK:
        p = DEVICE_PROFILE.get(dkey, {"version": None, "major": None, "commands": {}, "version_checked_ts": 0})
        p.setdefault("commands", {})
        p["version"] = version
        p["major"] = _ros_major(version)
        p["version_checked_ts"] = time.time()
        DEVICE_PROFILE[dkey] = p


def reset_device_profile(host: str, port: int) -> None:
    dkey = _device_key(host, port)
    with DEVICE_PROFILE_LOCK:
        DEVICE_PROFILE.pop(dkey, None)


def detect_ros_version(host: str, port: int, username: str, password: str) -> str | None:
    candidates = [
        "/system resource get version",
        ":put [/system resource get version]",
        "/system package update get installed-version",
        "/system resource print without-paging",
        "/system resource print",
    ]
    for cmd in candidates:
        try:
            out = safe_ssh_exec(host, port, username, password, cmd)
        except HTTPException as e:
            detail = str(e.detail)
            # Connection/auth failures should fail fast; retrying other version
            # commands only adds long delays for unreachable devices.
            if _is_transport_error_detail(detail):
                raise
            continue
        except Exception:
            continue
        ver = _extract_ros_version(out)
        if ver:
            return ver
    return None


def _feature_command_candidates(feature: str, major: int | None) -> list[str]:
    if feature == "backup_export":
        if major and major >= 7:
            return [
                "/export show-sensitive terse",
                "/export terse show-sensitive",
                "/export terse",
                "/export compact",
            ]
        return [
            "/export terse show-sensitive",
            "/export show-sensitive terse",
            "/export terse",
            "/export compact",
        ]
    if feature == "interfaces_list":
        return [
            "/interface print detail terse without-paging",
            "/interface print terse without-paging",
            "/interface print without-paging",
        ]
    if feature == "logs_read":
        return [
            "/log print without-paging",
            "/log print",
        ]
    if feature == "resource_print":
        return [
            "/system resource print without-paging",
            "/system resource print",
        ]
    if feature == "identity_print":
        return [
            "/system identity print without-paging",
            "/system identity print",
        ]
    return []


def exec_feature_command(
    host: str,
    port: int,
    username: str,
    password: str,
    feature: str,
    device_id: int | None = None,
) -> dict:
    dkey = _device_key(host, port)
    with DEVICE_PROFILE_LOCK:
        profile = DEVICE_PROFILE.get(dkey, {"version": None, "major": None, "commands": {}, "version_checked_ts": 0})

    version = profile.get("version")
    major = profile.get("major")
    checked_ts = float(profile.get("version_checked_ts") or 0)
    should_recheck_version = (time.time() - checked_ts) > ROS_VERSION_RECHECK_SECONDS

    # Reuse persisted version from DB if profile cache was lost (e.g., restart).
    if version is None and device_id:
        db_ver = get_device_ros_version(int(device_id))
        if db_ver:
            version = db_ver
            major = _ros_major(version)
            checked_ts = time.time()
            remember_device_profile_version(host, port, version)

    # Avoid heavy version probing on every connect/test/log call.
    # Only probe lazily for backup feature and with cooldown.
    if feature == "backup_export" and (version is None) and should_recheck_version:
        try:
            version = detect_ros_version(host, port, username, password)
            major = _ros_major(version)
        except HTTPException:
            # Continue with fallback commands; transport/auth errors will be raised
            # by actual command execution below.
            pass
        finally:
            with DEVICE_PROFILE_LOCK:
                p = DEVICE_PROFILE.get(dkey, {"version": None, "major": None, "commands": {}, "version_checked_ts": 0})
                p.setdefault("commands", {})
                p["version"] = version
                p["major"] = major
                p["version_checked_ts"] = time.time()
                DEVICE_PROFILE[dkey] = p
            if device_id and version:
                set_device_ros_version(device_id, version)

    candidates = _feature_command_candidates(feature, major)
    preferred = profile.get("commands", {}).get(feature)
    if preferred and preferred in candidates:
        candidates = [preferred] + [x for x in candidates if x != preferred]

    last_error = None
    for cmd in candidates:
        try:
            out = safe_ssh_exec(host, port, username, password, cmd)
        except HTTPException as e:
            detail = str(e.detail)
            last_error = detail
            if _is_compat_error_detail(detail):
                continue
            raise
        except Exception as e:
            last_error = str(e)
            continue

        # Router logs are free-form text and can legitimately contain words like "failure".
        # Treat non-empty output for logs_read as successful execution.
        if feature == "logs_read" and (out or "").strip():
            pass
        elif _looks_like_command_error_output(out):
            last_error = out[:400]
            continue

        with DEVICE_PROFILE_LOCK:
            p = DEVICE_PROFILE.get(dkey, {"version": version, "major": major, "commands": {}, "version_checked_ts": checked_ts})
            p.setdefault("commands", {})
            p["commands"][feature] = cmd
            p["version"] = version
            p["major"] = major
            if checked_ts:
                p["version_checked_ts"] = checked_ts
            DEVICE_PROFILE[dkey] = p

        if device_id:
            set_device_ros_version(device_id, version)

        return {"ok": True, "command": cmd, "output": out, "version": version}

    raise HTTPException(
        status_code=400,
        detail=f"Feature '{feature}' is not supported on this RouterOS version/device. Last error: {last_error or 'unknown'}",
    )


def load_device(device_id: int, actor: sqlite3.Row | None = None) -> sqlite3.Row:
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    if actor and ROLE_LEVEL.get(actor["role"], 0) < ROLE_LEVEL["admin"]:
        if row["owner_id"] is None or int(row["owner_id"]) != int(actor["id"]):
            raise HTTPException(status_code=404, detail="Device not found")
    return row


def load_backup(device_id: int, backup_id: int) -> sqlite3.Row:
    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT * FROM backups WHERE id = ? AND device_id = ?",
            (backup_id, device_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Backup not found")
    return row


def validate_terminal_command(command: str) -> str:
    blocked_patterns = [
        r"(^|\s):foreach\b",
        r"(^|\s)/system\s+reset-configuration\b",
        r"(^|\s)/system\s+reboot\b",
        r"(^|\s)/file\s+remove\b",
        r"(^|\s)/user\s+remove\b",
        r"(^|\s)/interface\s+remove\b",
    ]
    clean = command.strip()
    if not clean:
        raise HTTPException(status_code=400, detail="Empty command")
    for pattern in blocked_patterns:
        if re.search(pattern, clean, re.IGNORECASE):
            raise HTTPException(status_code=400, detail="Dangerous command is blocked")
    return clean


def parse_interfaces(raw: str) -> list[dict]:
    result = []
    for line in raw.splitlines():
        text = line.strip()
        if not text:
            continue
        if not re.search(r"name=", text):
            continue

        flags = ""
        m = re.match(r"^\d+\s+([A-Z]+)\s+", text)
        if m:
            flags = m.group(1)

        kv = {}
        for m in re.finditer(r"([\w-]+)=(\"[^\"]*\"|[^\s]+)", text):
            key = m.group(1)
            val = m.group(2)
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            kv[key] = val
        name = kv.get("name")
        if not name:
            continue

        disabled = kv.get("disabled", "no") in {"yes", "true"} or "X" in flags
        running = kv.get("running", "false") in {"yes", "true"} or "R" in flags
        iface_type = kv.get("type", "")
        mtu = kv.get("mtu", "")
        port = kv.get("default-name", "")
        comment = kv.get("comment", "")

        result.append(
            {
                "name": name,
                "port": port,
                "disabled": disabled,
                "running": running,
                "type": iface_type,
                "mtu": mtu,
                "comment": comment,
            }
        )
    return sorted(result, key=lambda x: x["name"])


def save_backup(device_id: int, base_name: str, content: str) -> dict:
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", base_name).strip("._") or "backup"
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_name}_{timestamp}.rsc"
    device_dir = BACKUP_DIR / str(device_id)
    device_dir.mkdir(parents=True, exist_ok=True)
    full_path = device_dir / filename
    full_path.write_text(content, encoding="utf-8")

    with closing(db_conn()) as conn:
        cur = conn.execute(
            "INSERT INTO backups(device_id, name, file_path) VALUES (?, ?, ?)",
            (device_id, filename, str(full_path)),
        )
        conn.commit()
        backup_id = cur.lastrowid

    return {"id": backup_id, "name": filename, "path": str(full_path)}


def parse_device_import_lines(content: str) -> tuple[list[dict], list[str]]:
    devices: list[dict] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    for idx, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^\d+\)\s*", "", line)
        parts = [p.strip() for p in re.split(r"[\t,;]+", line) if p.strip()]
        if len(parts) < 1:
            continue
        host = parts[0]
        name = parts[1] if len(parts) > 1 else host
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                errors.append(f"line {idx}: invalid host '{host}'")
                continue
        key = (host.lower(), name)
        if key in seen:
            continue
        seen.add(key)
        devices.append({"host": host, "name": name})
    return devices, errors


def _cleanup_deleted_device_runtime(host: str, port: int, username: str, password_enc: str) -> None:
    dkey = _device_key(host, port)
    with DEVICE_QUEUES_LOCK:
        DEVICE_QUEUES.pop(dkey, None)
    with SSH_DIAG_LOCK:
        SSH_DIAG.pop(dkey, None)
    with DEVICE_PROFILE_LOCK:
        DEVICE_PROFILE.pop(dkey, None)

    keys_to_drop = []
    try:
        password = fernet.decrypt(password_enc.encode()).decode()
        keys_to_drop.append(_ssh_pool_key(host, port, username, password))
    except Exception:
        pass

    prefix = f"{host}|{port}|{username}|"
    with SSH_POOL_LOCK:
        for key in list(SSH_POOL.keys()):
            if key in keys_to_drop or key.startswith(prefix):
                entry = SSH_POOL.pop(key, None)
                if entry:
                    _close_client_safely(entry["client"])


def create_system_backup_archive() -> Path:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out = SYSTEM_BACKUP_DIR / f"mim-system-backup-{ts}.tar.gz"
    with tarfile.open(out, "w:gz") as tar:
        if DB_PATH.exists():
            tar.add(DB_PATH, arcname="data/devices.db")
        if BACKUP_DIR.exists():
            tar.add(BACKUP_DIR, arcname="data/backups")
    return out


def restore_system_backup_archive(name: str) -> dict:
    src = resolve_system_backup_path(name)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    db_tmp = DATA_DIR / f"devices.restore.{ts}.tmp"
    backups_tmp = DATA_DIR / f"backups.restore.{ts}.tmp"
    db_snapshot = DATA_DIR / f"devices.pre-restore.{ts}.db"
    backups_snapshot = DATA_DIR / f"backups.pre-restore.{ts}"

    db_bytes: bytes | None = None
    backup_files: list[tuple[str, bytes]] = []

    with tarfile.open(src, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            member_name = member.name.replace("\\", "/")
            if member_name == "data/devices.db":
                f = tar.extractfile(member)
                if f is not None:
                    db_bytes = f.read()
            elif member_name.startswith("data/backups/"):
                rel = member_name[len("data/backups/") :]
                if not rel or rel.startswith("/") or ".." in rel.split("/"):
                    continue
                f = tar.extractfile(member)
                if f is not None:
                    backup_files.append((rel, f.read()))

    if not db_bytes:
        raise HTTPException(status_code=400, detail="System backup is missing data/devices.db")

    if DB_PATH.exists():
        shutil.copy2(DB_PATH, db_snapshot)
    if BACKUP_DIR.exists():
        shutil.copytree(BACKUP_DIR, backups_snapshot)

    db_tmp.write_bytes(db_bytes)
    with closing(sqlite3.connect(db_tmp)) as conn:
        conn.execute("PRAGMA integrity_check").fetchone()

    if backups_tmp.exists():
        shutil.rmtree(backups_tmp)
    backups_tmp.mkdir(parents=True, exist_ok=True)
    for rel, content in backup_files:
        out = backups_tmp / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(content)

    os.replace(db_tmp, DB_PATH)
    if BACKUP_DIR.exists():
        shutil.rmtree(BACKUP_DIR)
    os.replace(backups_tmp, BACKUP_DIR)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    # Re-run migrations/default users after DB replacement.
    init_db()

    return {
        "ok": True,
        "restored_from": src.name,
        "db_snapshot": db_snapshot.name if db_snapshot.exists() else None,
        "backups_snapshot": backups_snapshot.name if backups_snapshot.exists() else None,
        "restored_backup_files": len(backup_files),
    }


def list_system_backups() -> list[dict]:
    items = []
    for path in sorted(SYSTEM_BACKUP_DIR.glob("mim-system-backup-*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True):
        stat = path.stat()
        items.append(
            {
                "name": path.name,
                "size_bytes": int(stat.st_size),
                "created_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
            }
        )
    return items


def resolve_system_backup_path(name: str) -> Path:
    if not re.fullmatch(r"mim-system-backup-\d{8}_\d{6}\.tar\.gz", name):
        raise HTTPException(status_code=400, detail="Invalid backup name")

    path = (SYSTEM_BACKUP_DIR / name).resolve()
    root = SYSTEM_BACKUP_DIR.resolve()
    if not str(path).startswith(str(root) + os.sep):
        raise HTTPException(status_code=400, detail="Invalid backup path")
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="System backup not found")
    return path


def ssh_import_script(host: str, port: int, username: str, password: str, script_content: str) -> str:
    remote_name = f"mim-restore-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.rsc"
    def _run_restore() -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=SSH_CONNECT_TIMEOUT,
                banner_timeout=SSH_CONNECT_TIMEOUT,
                auth_timeout=SSH_CONNECT_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(SSH_KEEPALIVE_SECONDS)

            sftp = client.open_sftp()
            try:
                with sftp.open(remote_name, "w") as remote_file:
                    remote_file.write(script_content)
            finally:
                sftp.close()

            _, stdout, stderr = client.exec_command(f"/import file-name={remote_name}", timeout=120)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            client.exec_command(f"/file remove [find where name={remote_name}]", timeout=30)
            return (out + "\n" + err).strip() or "Import completed"
        except TimeoutError:
            raise HTTPException(status_code=400, detail="Restore timeout while applying backup script")
        except socket.timeout:
            raise HTTPException(status_code=400, detail="Restore timeout while applying backup script")
        except paramiko.AuthenticationException:
            raise HTTPException(status_code=400, detail="SSH authentication failed during restore")
        except paramiko.SSHException as e:
            raise HTTPException(status_code=400, detail=f"SSH restore error: {e}")
        except OSError as e:
            raise HTTPException(status_code=400, detail=f"Network restore error: {e}")
        finally:
            client.close()

    return _run_device_queued(_device_key(host, port), _run_restore)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    load_runtime_settings()


@app.on_event("shutdown")
def on_shutdown() -> None:
    stop_health_worker()
    with SSH_POOL_LOCK:
        entries = list(SSH_POOL.values())
        SSH_POOL.clear()
    for entry in entries:
        _close_client_safely(entry["client"])

_route_ctx = SimpleNamespace(**globals())
register_auth_user_routes(app, _route_ctx)
register_device_routes(app, _route_ctx)
register_terminal_backup_routes(app, _route_ctx)
register_system_routes(app, _route_ctx)
