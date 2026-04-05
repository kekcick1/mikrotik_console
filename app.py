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
import ssl
import sqlite3
import tarfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta, timezone
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
from routes_fleet_policy import register_fleet_policy_routes
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
HEALTH_API_PROBE_ENABLED = str(os.environ.get("MIM_HEALTH_API_PROBE_ENABLED", "0")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
HEALTH_PACKETLOSS_TARGET = os.environ.get("MIM_HEALTH_PACKETLOSS_TARGET", "1.1.1.1").strip() or "1.1.1.1"
HEALTH_PACKETLOSS_COUNT = max(1, int(os.environ.get("MIM_HEALTH_PACKETLOSS_COUNT", "3")))
HEALTH_BACKUP_FRESHNESS_HOURS_DEFAULT = max(1, int(os.environ.get("MIM_HEALTH_BACKUP_FRESHNESS_HOURS_DEFAULT", "48")))
DRIFT_RECHECK_SECONDS = max(300, int(os.environ.get("MIM_DRIFT_RECHECK_SECONDS", "3600")))
CHANGE_CONFIRM_TTL_SECONDS = max(60, int(os.environ.get("MIM_CHANGE_CONFIRM_TTL_SECONDS", "300")))

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
HEALTH_SLO_LOCK = threading.Lock()
HEALTH_SLO_STATE: dict[int, dict] = {}


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


class DeviceProfileAssignIn(BaseModel):
    profile_key: str = Field(min_length=2, max_length=64)


class ChangePreviewIn(BaseModel):
    command: str = Field(min_length=1, max_length=500)
    device_ids: list[int] = Field(min_length=1, max_length=500)


class ChangeApproveIn(BaseModel):
    confirm_token: str | None = Field(default=None, max_length=4096)


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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_profiles (
                key TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                max_batch_changes INTEGER NOT NULL,
                require_manual_approval INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS change_previews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_by TEXT NOT NULL,
                created_role TEXT NOT NULL,
                command TEXT NOT NULL,
                device_ids_json TEXT NOT NULL,
                diff_json TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                requires_approval INTEGER NOT NULL,
                status TEXT NOT NULL,
                confirm_token TEXT,
                approved_by TEXT,
                approved_at TEXT,
                executed_at TEXT,
                execution_result_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_baselines (
                device_id INTEGER PRIMARY KEY,
                config_hash TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_slo_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                ssh_reachable INTEGER NOT NULL,
                api_reachable INTEGER,
                cpu_load REAL,
                ram_used_pct REAL,
                packet_loss_pct REAL,
                rtt_ms REAL,
                backup_age_seconds INTEGER,
                config_drift INTEGER,
                slo_state TEXT,
                metrics_json TEXT,
                collected_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
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
        if "profile_key" not in device_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN profile_key TEXT DEFAULT 'branch-small'")

        conn.commit()

    ensure_default_profiles()
    ensure_default_users()

    with closing(db_conn()) as conn:
        admin = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if admin:
            conn.execute("UPDATE devices SET owner_id = ? WHERE owner_id IS NULL", (int(admin["id"]),))
            conn.execute("UPDATE devices SET profile_key = 'branch-small' WHERE profile_key IS NULL OR profile_key = ''")
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


def ensure_default_profiles() -> None:
    defaults = [
        {
            "key": "branch-small",
            "name": "Branch Small",
            "description": "Small branch office routers with conservative rollout limits.",
            "max_batch_changes": 10,
            "require_manual_approval": 0,
            "policy": {
                "slo": {
                    "max_cpu_load_pct": 85,
                    "max_ram_used_pct": 90,
                    "max_packet_loss_pct": 5,
                    "max_backup_age_hours": 48,
                }
            },
        },
        {
            "key": "hq",
            "name": "HQ",
            "description": "Headquarters routers with stricter health requirements.",
            "max_batch_changes": 5,
            "require_manual_approval": 1,
            "policy": {
                "slo": {
                    "max_cpu_load_pct": 75,
                    "max_ram_used_pct": 85,
                    "max_packet_loss_pct": 2,
                    "max_backup_age_hours": 24,
                }
            },
        },
        {
            "key": "dc-edge",
            "name": "DC Edge",
            "description": "Datacenter edge routers, lowest tolerance and smallest rollout batches.",
            "max_batch_changes": 3,
            "require_manual_approval": 1,
            "policy": {
                "slo": {
                    "max_cpu_load_pct": 70,
                    "max_ram_used_pct": 80,
                    "max_packet_loss_pct": 1,
                    "max_backup_age_hours": 12,
                }
            },
        },
    ]
    with closing(db_conn()) as conn:
        for row in defaults:
            conn.execute(
                """
                INSERT INTO device_profiles(key, name, description, max_batch_changes, require_manual_approval, policy_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    max_batch_changes = excluded.max_batch_changes,
                    require_manual_approval = excluded.require_manual_approval,
                    policy_json = excluded.policy_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    row["key"],
                    row["name"],
                    row["description"],
                    int(row["max_batch_changes"]),
                    int(row["require_manual_approval"]),
                    json.dumps(row["policy"], separators=(",", ":")),
                ),
            )
        conn.commit()


def _safe_json_loads(raw: str | None, default):
    try:
        if not raw:
            return default
        return json.loads(raw)
    except Exception:
        return default


def list_device_profiles() -> list[dict]:
    with closing(db_conn()) as conn:
        rows = conn.execute(
            "SELECT key, name, description, max_batch_changes, require_manual_approval, policy_json, updated_at FROM device_profiles ORDER BY key"
        ).fetchall()
    out = []
    for row in rows:
        out.append(
            {
                "key": row["key"],
                "name": row["name"],
                "description": row["description"],
                "max_batch_changes": int(row["max_batch_changes"]),
                "require_manual_approval": bool(row["require_manual_approval"]),
                "policy": _safe_json_loads(row["policy_json"], {}),
                "updated_at": row["updated_at"],
            }
        )
    return out


def get_device_profile(profile_key: str | None) -> dict:
    key = (profile_key or "branch-small").strip().lower() or "branch-small"
    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT key, name, description, max_batch_changes, require_manual_approval, policy_json FROM device_profiles WHERE key = ?",
            (key,),
        ).fetchone()
    if not row and key != "branch-small":
        return get_device_profile("branch-small")
    if not row:
        raise HTTPException(status_code=500, detail="Default device profile is missing")
    return {
        "key": row["key"],
        "name": row["name"],
        "description": row["description"],
        "max_batch_changes": int(row["max_batch_changes"]),
        "require_manual_approval": bool(row["require_manual_approval"]),
        "policy": _safe_json_loads(row["policy_json"], {}),
    }


def assign_device_profile(device_id: int, profile_key: str, actor: sqlite3.Row) -> dict:
    profile = get_device_profile(profile_key)
    row = load_device(device_id, actor)
    with closing(db_conn()) as conn:
        conn.execute("UPDATE devices SET profile_key = ? WHERE id = ?", (profile["key"], int(device_id)))
        conn.commit()
    log_audit(
        actor["username"],
        actor["role"],
        "device_profile_set",
        int(device_id),
        f"{row['name']} -> {profile['key']}",
    )
    return profile


def list_visible_devices(actor: sqlite3.Row, device_ids: list[int] | None = None) -> list[sqlite3.Row]:
    ids = sorted({int(x) for x in (device_ids or []) if int(x) > 0})
    with closing(db_conn()) as conn:
        params: list = []
        if ROLE_LEVEL.get(actor["role"], 0) >= ROLE_LEVEL["admin"]:
            query = "SELECT * FROM devices"
            if ids:
                placeholders = ",".join("?" for _ in ids)
                query += f" WHERE id IN ({placeholders})"
                params.extend(ids)
            query += " ORDER BY name"
            rows = conn.execute(query, tuple(params)).fetchall()
        else:
            query = "SELECT * FROM devices WHERE owner_id = ?"
            params.append(int(actor["id"]))
            if ids:
                placeholders = ",".join("?" for _ in ids)
                query += f" AND id IN ({placeholders})"
                params.extend(ids)
            query += " ORDER BY name"
            rows = conn.execute(query, tuple(params)).fetchall()
    return rows


def _risk_level(score: int) -> str:
    s = int(score)
    if s >= 80:
        return "critical"
    if s >= 55:
        return "high"
    if s >= 25:
        return "medium"
    return "low"


def _command_risk(command: str) -> tuple[int, list[str]]:
    score = 10
    flags = []
    checks = [
        (r"\b(remove|delete)\b", 30, "destructive_keywords"),
        (r"\b(set|add)\b", 12, "config_mutation"),
        (r"/ip\s+firewall", 18, "firewall_change"),
        (r"/routing\b", 20, "routing_change"),
        (r"/system\b", 15, "system_scope"),
        (r"show-sensitive", 12, "sensitive_export"),
    ]
    for pattern, points, label in checks:
        if re.search(pattern, command, flags=re.IGNORECASE):
            score += points
            flags.append(label)
    return score, flags


def _make_change_confirm_token(preview_id: int, username: str) -> str:
    payload = {
        "preview_id": int(preview_id),
        "u": username,
        "exp": int(time.time()) + CHANGE_CONFIRM_TTL_SECONDS,
    }
    encoded = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(AUTH_SECRET.encode(), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{_b64u(sig)}"


def _verify_change_confirm_token(token: str, preview_id: int, username: str) -> None:
    payload = parse_token(token)
    if int(payload.get("preview_id", 0)) != int(preview_id):
        raise HTTPException(status_code=400, detail="Confirmation token is for another preview")
    if payload.get("u") != username:
        raise HTTPException(status_code=403, detail="Confirmation token is bound to another user")


def create_change_preview(actor: sqlite3.Row, command: str, device_ids: list[int]) -> dict:
    clean = validate_terminal_command(command)
    ids = sorted({int(x) for x in device_ids if int(x) > 0})
    if not ids:
        raise HTTPException(status_code=400, detail="No target devices selected")
    rows = list_visible_devices(actor, ids)
    if len(rows) != len(ids):
        raise HTTPException(status_code=404, detail="Some target devices are missing or not accessible")

    score, flags = _command_risk(clean)
    diff_items = []
    max_batch_limit = 0
    approval_required_by_profile = False
    profiles_map = {}
    for row in rows:
        profile = get_device_profile(row["profile_key"])
        profiles_map[str(row["id"])] = profile["key"]
        max_batch_limit = max(max_batch_limit, int(profile["max_batch_changes"]))
        approval_required_by_profile = approval_required_by_profile or bool(profile["require_manual_approval"])
        diff_items.append(
            {
                "device_id": int(row["id"]),
                "device_name": row["name"],
                "profile_key": profile["key"],
                "diff": [
                    f"- running-config (current): unchanged snapshot",
                    f"+ pending-change: {clean}",
                ],
            }
        )

    if len(rows) > max(1, max_batch_limit):
        score += 30
        flags.append("batch_limit_exceeded")
    if len(rows) >= 10:
        score += 15
        flags.append("mass_change")
    elif len(rows) >= 5:
        score += 8
        flags.append("multi_device_change")

    risk_level = _risk_level(score)
    requires_approval = approval_required_by_profile or risk_level in {"high", "critical"} or len(rows) > max(1, max_batch_limit)
    record = {
        "created_by": actor["username"],
        "created_role": actor["role"],
        "command": clean,
        "device_ids_json": json.dumps([int(r["id"]) for r in rows], separators=(",", ":")),
        "diff_json": json.dumps(
            {
                "flags": flags,
                "profiles": profiles_map,
                "items": diff_items,
            },
            separators=(",", ":"),
        ),
        "risk_score": int(score),
        "risk_level": risk_level,
        "requires_approval": int(bool(requires_approval)),
        "status": "previewed",
    }
    with closing(db_conn()) as conn:
        cur = conn.execute(
            """
            INSERT INTO change_previews(
                created_by, created_role, command, device_ids_json, diff_json,
                risk_score, risk_level, requires_approval, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["created_by"],
                record["created_role"],
                record["command"],
                record["device_ids_json"],
                record["diff_json"],
                record["risk_score"],
                record["risk_level"],
                record["requires_approval"],
                record["status"],
            ),
        )
        preview_id = int(cur.lastrowid)
        confirm_token = _make_change_confirm_token(preview_id, actor["username"]) if requires_approval else None
        conn.execute("UPDATE change_previews SET confirm_token = ? WHERE id = ?", (confirm_token, preview_id))
        conn.commit()
    log_audit(actor["username"], actor["role"], "change_preview_create", None, f"preview_id={preview_id}, devices={len(rows)}")
    return {
        "id": preview_id,
        "status": "previewed",
        "command": clean,
        "targets": [{"id": int(r["id"]), "name": r["name"], "profile_key": profiles_map[str(r["id"])]} for r in rows],
        "risk_score": int(score),
        "risk_level": risk_level,
        "requires_approval": bool(requires_approval),
        "confirm_token": confirm_token,
        "confirm_ttl_seconds": CHANGE_CONFIRM_TTL_SECONDS if confirm_token else None,
        "diff": _safe_json_loads(record["diff_json"], {}),
    }


def _load_change_preview(preview_id: int) -> sqlite3.Row:
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT * FROM change_previews WHERE id = ?", (int(preview_id),)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Change preview not found")
    return row


def approve_change_preview(preview_id: int, actor: sqlite3.Row, confirm_token: str | None = None) -> dict:
    row = _load_change_preview(preview_id)
    if row["status"] != "previewed":
        raise HTTPException(status_code=400, detail=f"Preview status is '{row['status']}', expected 'previewed'")
    requires_approval = bool(row["requires_approval"])
    risk_level = str(row["risk_level"])
    if requires_approval:
        if not confirm_token:
            raise HTTPException(status_code=400, detail="Confirmation token is required for this preview")
        _verify_change_confirm_token(confirm_token, int(preview_id), actor["username"])
    if risk_level in {"high", "critical"} and ROLE_LEVEL.get(actor["role"], 0) < ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role is required to approve high-risk changes")
    with closing(db_conn()) as conn:
        conn.execute(
            "UPDATE change_previews SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ?",
            (actor["username"], int(preview_id)),
        )
        conn.commit()
    log_audit(actor["username"], actor["role"], "change_preview_approve", None, f"preview_id={preview_id}")
    return {"ok": True, "id": int(preview_id), "status": "approved"}


def execute_change_preview(preview_id: int, actor: sqlite3.Row) -> dict:
    row = _load_change_preview(preview_id)
    if row["status"] != "approved":
        raise HTTPException(status_code=400, detail=f"Preview status is '{row['status']}', expected 'approved'")
    device_ids = _safe_json_loads(row["device_ids_json"], [])
    if not isinstance(device_ids, list):
        raise HTTPException(status_code=400, detail="Invalid preview device list")
    rows = list_visible_devices(actor, [int(x) for x in device_ids])
    if len(rows) != len(device_ids):
        raise HTTPException(status_code=403, detail="Some target devices are no longer accessible")

    command = str(row["command"])
    results = []
    for drow in rows:
        try:
            password = fernet.decrypt(drow["password_enc"].encode()).decode()
            output = safe_ssh_exec(drow["host"], int(drow["port"]), drow["username"], password, command)
            results.append({"device_id": int(drow["id"]), "name": drow["name"], "ok": True, "output": output})
        except HTTPException as e:
            results.append({"device_id": int(drow["id"]), "name": drow["name"], "ok": False, "error": str(e.detail)})
        except Exception as e:
            results.append({"device_id": int(drow["id"]), "name": drow["name"], "ok": False, "error": str(e)})

    failed = sum(1 for x in results if not x.get("ok"))
    status = "executed" if failed == 0 else "executed_with_errors"
    with closing(db_conn()) as conn:
        conn.execute(
            "UPDATE change_previews SET status = ?, executed_at = CURRENT_TIMESTAMP, execution_result_json = ? WHERE id = ?",
            (status, json.dumps({"results": results}, separators=(",", ":")), int(preview_id)),
        )
        conn.commit()
    log_audit(
        actor["username"],
        actor["role"],
        "change_preview_execute",
        None,
        f"preview_id={preview_id}, failed={failed}, total={len(results)}",
    )
    return {
        "ok": failed == 0,
        "id": int(preview_id),
        "status": status,
        "failed": int(failed),
        "total": len(results),
        "results": results,
    }


def get_change_preview(preview_id: int) -> dict:
    row = _load_change_preview(preview_id)
    return {
        "id": int(row["id"]),
        "created_by": row["created_by"],
        "created_role": row["created_role"],
        "command": row["command"],
        "risk_score": int(row["risk_score"]),
        "risk_level": row["risk_level"],
        "requires_approval": bool(row["requires_approval"]),
        "status": row["status"],
        "approved_by": row["approved_by"],
        "approved_at": row["approved_at"],
        "executed_at": row["executed_at"],
        "diff": _safe_json_loads(row["diff_json"], {}),
        "execution": _safe_json_loads(row["execution_result_json"], None),
        "created_at": row["created_at"],
    }


def _to_float_or_none(value) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _parse_datetime_to_epoch(value: str | None) -> float | None:
    text = (value or "").strip()
    if not text:
        return None
    candidates = [text]
    if " " in text and "T" not in text:
        candidates.append(text.replace(" ", "T"))
    if text.endswith("Z"):
        candidates.append(text[:-1] + "+00:00")
    for item in candidates:
        try:
            dt = datetime.fromisoformat(item)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return float(dt.timestamp())
        except Exception:
            continue
    return None


def _parse_routeros_resource_metrics(raw: str) -> dict:
    text = raw or ""
    out = {
        "cpu_load_pct": None,
        "ram_used_pct": None,
    }
    m_cpu = re.search(r"cpu-load:\s*(\d+(?:\.\d+)?)", text, flags=re.IGNORECASE)
    if m_cpu:
        out["cpu_load_pct"] = _to_float_or_none(m_cpu.group(1))
    m_total = re.search(r"total-memory:\s*(\d+)", text, flags=re.IGNORECASE)
    m_free = re.search(r"free-memory:\s*(\d+)", text, flags=re.IGNORECASE)
    if m_total and m_free:
        total = _to_float_or_none(m_total.group(1))
        free = _to_float_or_none(m_free.group(1))
        if total and total > 0 and free is not None:
            used_pct = max(0.0, min(100.0, ((total - free) / total) * 100.0))
            out["ram_used_pct"] = round(used_pct, 2)
    return out


def _parse_packet_loss_pct(raw: str) -> float | None:
    text = raw or ""
    m = re.search(r"packet-loss(?:=|:\s*)(\d+(?:\.\d+)?)\s*%", text, flags=re.IGNORECASE)
    if not m:
        m = re.search(r"(\d+(?:\.\d+)?)\s*%\s*packet\s*loss", text, flags=re.IGNORECASE)
    if m:
        return _to_float_or_none(m.group(1))
    return None


def _latest_backup_age_seconds(device_id: int) -> int | None:
    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT created_at FROM backups WHERE device_id = ? ORDER BY id DESC LIMIT 1",
            (int(device_id),),
        ).fetchone()
    if not row or not row["created_at"]:
        return None
    ts = _parse_datetime_to_epoch(str(row["created_at"]))
    if ts is None:
        return None
    return int(max(0, time.time() - ts))


def set_device_baseline_hash(device_id: int, config_hash: str) -> None:
    with closing(db_conn()) as conn:
        conn.execute(
            """
            INSERT INTO device_baselines(device_id, config_hash, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(device_id) DO UPDATE SET
                config_hash = excluded.config_hash,
                updated_at = CURRENT_TIMESTAMP
            """,
            (int(device_id), str(config_hash)),
        )
        conn.commit()


def get_device_baseline_hash(device_id: int) -> str | None:
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT config_hash FROM device_baselines WHERE device_id = ?", (int(device_id),)).fetchone()
    if not row:
        return None
    return row["config_hash"]


def capture_device_config_baseline(device_id: int, actor: sqlite3.Row) -> dict:
    row = load_device(device_id, actor)
    password = fernet.decrypt(row["password_enc"].encode()).decode()
    out = exec_feature_command(row["host"], int(row["port"]), row["username"], password, "backup_export", int(row["id"]))
    output = out.get("output", "")
    config_hash = hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest()
    set_device_baseline_hash(int(row["id"]), config_hash)
    log_audit(actor["username"], actor["role"], "slo_baseline_capture", int(row["id"]), f"hash={config_hash[:12]}")
    return {
        "device_id": int(row["id"]),
        "device_name": row["name"],
        "profile_key": row["profile_key"] or "branch-small",
        "config_hash": config_hash,
        "captured_at": _utc_now_iso(),
    }


def _evaluate_slo_state(profile_key: str, metric: dict) -> tuple[str, list[str]]:
    profile = get_device_profile(profile_key)
    slo = profile.get("policy", {}).get("slo", {})
    violations = []
    ssh_reachable = bool(metric.get("ssh_reachable"))
    if not ssh_reachable:
        return "offline", ["ssh_unreachable"]
    cpu = _to_float_or_none(metric.get("cpu_load_pct"))
    ram = _to_float_or_none(metric.get("ram_used_pct"))
    loss = _to_float_or_none(metric.get("packet_loss_pct"))
    backup_age_seconds = metric.get("backup_age_seconds")
    drift = metric.get("config_drift")
    if cpu is not None and cpu > float(slo.get("max_cpu_load_pct", 85)):
        violations.append("cpu")
    if ram is not None and ram > float(slo.get("max_ram_used_pct", 90)):
        violations.append("ram")
    if loss is not None and loss > float(slo.get("max_packet_loss_pct", 5)):
        violations.append("packet_loss")
    if backup_age_seconds is not None:
        max_backup_hours = float(slo.get("max_backup_age_hours", HEALTH_BACKUP_FRESHNESS_HOURS_DEFAULT))
        if backup_age_seconds > int(max_backup_hours * 3600):
            violations.append("backup_freshness")
    if drift is True:
        violations.append("config_drift")
    if violations:
        return "degraded", violations
    return "healthy", []


def record_device_slo_metric(device_id: int, metric: dict) -> dict:
    device_id = int(device_id)
    profile_key = metric.get("profile_key") or "branch-small"
    slo_state, violations = _evaluate_slo_state(profile_key, metric)
    payload = {
        "device_id": device_id,
        "ssh_reachable": bool(metric.get("ssh_reachable")),
        "api_reachable": metric.get("api_reachable"),
        "cpu_load_pct": _to_float_or_none(metric.get("cpu_load_pct")),
        "ram_used_pct": _to_float_or_none(metric.get("ram_used_pct")),
        "packet_loss_pct": _to_float_or_none(metric.get("packet_loss_pct")),
        "rtt_ms": _to_float_or_none(metric.get("rtt_ms")),
        "backup_age_seconds": metric.get("backup_age_seconds"),
        "config_drift": metric.get("config_drift"),
        "slo_state": slo_state,
        "violations": violations,
        "collected_at": _utc_now_iso(),
    }
    with closing(db_conn()) as conn:
        conn.execute(
            """
            INSERT INTO device_slo_metrics(
                device_id, ssh_reachable, api_reachable, cpu_load, ram_used_pct, packet_loss_pct,
                rtt_ms, backup_age_seconds, config_drift, slo_state, metrics_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["device_id"],
                int(payload["ssh_reachable"]),
                None if payload["api_reachable"] is None else int(bool(payload["api_reachable"])),
                payload["cpu_load_pct"],
                payload["ram_used_pct"],
                payload["packet_loss_pct"],
                payload["rtt_ms"],
                payload["backup_age_seconds"],
                None if payload["config_drift"] is None else int(bool(payload["config_drift"])),
                payload["slo_state"],
                json.dumps(payload, separators=(",", ":")),
            ),
        )
        conn.commit()
    with HEALTH_SLO_LOCK:
        HEALTH_SLO_STATE[device_id] = payload
    return payload


def get_device_slo_snapshot(device_id: int) -> dict | None:
    did = int(device_id)
    with HEALTH_SLO_LOCK:
        cached = HEALTH_SLO_STATE.get(did)
        if cached:
            return dict(cached)
    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT metrics_json FROM device_slo_metrics WHERE device_id = ? ORDER BY id DESC LIMIT 1",
            (did,),
        ).fetchone()
    if not row:
        return None
    parsed = _safe_json_loads(row["metrics_json"], None)
    if isinstance(parsed, dict):
        return parsed
    return None


def list_fleet_slo(actor: sqlite3.Row) -> list[dict]:
    rows = list_visible_devices(actor)
    out = []
    for row in rows:
        snap = get_device_slo_snapshot(int(row["id"])) or {}
        out.append(
            {
                "device_id": int(row["id"]),
                "name": row["name"],
                "host": row["host"],
                "profile_key": row["profile_key"] or "branch-small",
                **snap,
            }
        )
    return out


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

    try:
        exp = int(payload.get("exp", 0))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token expiry")
    if exp < int(time.time()):
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
            "SELECT id, name, host, port, username, password_enc, profile_key FROM devices ORDER BY id"
        ).fetchall()
    return rows


def _collect_config_drift(row: sqlite3.Row, password: str) -> bool | None:
    baseline_hash = get_device_baseline_hash(int(row["id"]))
    if not baseline_hash:
        return None
    device_id = int(row["id"])
    now = time.time()
    with HEALTH_SLO_LOCK:
        cached = HEALTH_SLO_STATE.get(device_id) or {}
        checked_ts = float(cached.get("drift_checked_ts") or 0)
        if (now - checked_ts) < DRIFT_RECHECK_SECONDS and ("config_drift" in cached):
            return bool(cached.get("config_drift"))
    try:
        out = exec_feature_command(row["host"], int(row["port"]), row["username"], password, "backup_export", int(row["id"]))
        current_hash = hashlib.sha256(out.get("output", "").encode("utf-8", errors="replace")).hexdigest()
        drift = current_hash != baseline_hash
    except Exception:
        return None
    with HEALTH_SLO_LOCK:
        cached = HEALTH_SLO_STATE.get(device_id) or {}
        cached["drift_checked_ts"] = now
        cached["config_drift"] = drift
        HEALTH_SLO_STATE[device_id] = cached
    return drift


def _collect_device_slo_metric(row: sqlite3.Row, password: str | None, ssh_reachable: bool, error_text: str | None = None) -> None:
    device_id = int(row["id"])
    dkey = _device_key(row["host"], int(row["port"]))
    diag = _diag_get(dkey).copy()
    metric = {
        "profile_key": row["profile_key"] or "branch-small",
        "ssh_reachable": bool(ssh_reachable),
        "api_reachable": None,
        "cpu_load_pct": None,
        "ram_used_pct": None,
        "packet_loss_pct": None,
        "rtt_ms": diag.get("last_rtt_ms"),
        "backup_age_seconds": _latest_backup_age_seconds(device_id),
        "config_drift": None,
    }
    if ssh_reachable and password:
        try:
            resource = exec_feature_command(
                row["host"],
                int(row["port"]),
                row["username"],
                password,
                "resource_print",
                int(row["id"]),
            )
            parsed_resource = _parse_routeros_resource_metrics(resource.get("output", ""))
            metric["cpu_load_pct"] = parsed_resource.get("cpu_load_pct")
            metric["ram_used_pct"] = parsed_resource.get("ram_used_pct")
        except Exception:
            pass
        try:
            ping_raw = safe_ssh_exec(
                row["host"],
                int(row["port"]),
                row["username"],
                password,
                f"/ping {HEALTH_PACKETLOSS_TARGET} count={HEALTH_PACKETLOSS_COUNT}",
            )
            metric["packet_loss_pct"] = _parse_packet_loss_pct(ping_raw)
        except Exception:
            pass
        if HEALTH_API_PROBE_ENABLED:
            try:
                api_out = test_routeros_api(row["host"], row["username"], password, api_port=8728, use_ssl=False)
                metric["api_reachable"] = bool(api_out.get("ok"))
            except Exception:
                metric["api_reachable"] = False
        metric["config_drift"] = _collect_config_drift(row, password)
    if error_text:
        metric["error"] = str(error_text)[:300]
    record_device_slo_metric(device_id, metric)


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
            _collect_device_slo_metric(row, password=password, ssh_reachable=True, error_text=None)
            if was_down and changed:
                _emit_health_alert("device_recovered", "info", row, "Device recovered and is reachable")
        except HTTPException as e:
            failures += 1
            detail = str(e.detail)
            _diag_mark_event(dkey, "health_probe_failed")
            was_down, changed = _set_health_worker_state(row, is_down=True, last_error=detail)
            _collect_device_slo_metric(row, password=None, ssh_reachable=False, error_text=detail)
            if (not was_down and changed) or ALERT_REPEAT_WHILE_DOWN:
                _emit_health_alert("device_down", "critical", row, "Device is unreachable", detail)
        except Exception as e:
            failures += 1
            detail = str(e)
            _diag_mark_event(dkey, "health_probe_failed")
            was_down, changed = _set_health_worker_state(row, is_down=True, last_error=detail)
            _collect_device_slo_metric(row, password=None, ssh_reachable=False, error_text=detail)
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
    def _connect_once(use_ssl_value: bool) -> dict:
        pool = None
        base_kwargs = {
            "username": username,
            "password": password,
            "port": int(api_port),
            "use_ssl": bool(use_ssl_value),
            "ssl_verify": False,
            "ssl_verify_hostname": False,
            "plaintext_login": True,
        }
        try:
            # routeros-api versions differ in supported init kwargs.
            # Prefer timeout when available, but gracefully fallback for older versions.
            try:
                pool = routeros_api.RouterOsApiPool(
                    host,
                    socket_timeout=ROS_API_TIMEOUT,
                    **base_kwargs,
                )
            except TypeError as e:
                if "unexpected keyword argument 'socket_timeout'" not in str(e):
                    raise
                pool = routeros_api.RouterOsApiPool(host, **base_kwargs)
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
                "api_ssl": bool(use_ssl_value),
            }
        finally:
            if pool is not None:
                try:
                    pool.disconnect()
                except Exception:
                    pass

    try:
        return _connect_once(bool(use_ssl))
    except ssl.SSLError as e:
        # Common case: SSL enabled against plain API port 8728.
        if bool(use_ssl):
            try:
                out = _connect_once(False)
                out["warning"] = (
                    "SSL handshake failed; plaintext API succeeded. "
                    "Use api_ssl=false on port 8728, or enable api-ssl and use port 8729."
                )
                return out
            except Exception:
                pass
        hint = "Try api_ssl=false on port 8728, or api_ssl=true on port 8729."
        raise HTTPException(status_code=400, detail=f"RouterOS API SSL error on {host}:{api_port}: {e}. {hint}")
    except Exception as e:
        try:
            if bool(use_ssl) and int(api_port) == 8728:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"RouterOS API connection failed on {host}:{api_port}: {e}. "
                        "Likely SSL is enabled on plain API port. Use api_ssl=false on 8728, "
                        "or use api_ssl=true with 8729."
                    ),
                )
        except HTTPException:
            raise
        raise HTTPException(status_code=400, detail=f"RouterOS API connection failed on {host}:{api_port}: {e}")


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


def _resolve_device_ros_version(
    host: str,
    port: int,
    username: str,
    password: str,
    device_id: int | None,
    profile: dict,
    force_recheck: bool = False,
) -> tuple[str | None, int | None, float]:
    version = profile.get("version")
    major = profile.get("major")
    checked_ts = float(profile.get("version_checked_ts") or 0)
    should_recheck_version = force_recheck or (not checked_ts) or ((time.time() - checked_ts) > ROS_VERSION_RECHECK_SECONDS)

    # Reuse persisted DB version when in-memory cache is empty.
    if version is None and device_id:
        db_ver = get_device_ros_version(int(device_id))
        if db_ver:
            version = db_ver
            major = _ros_major(version)
            checked_ts = time.time()

    if (version is None) or should_recheck_version:
        try:
            detected = detect_ros_version(host, port, username, password)
            if detected:
                version = detected
                major = _ros_major(version)
                checked_ts = time.time()
        except HTTPException:
            # If transport/auth fails, downstream call will fail with concrete error.
            pass

    with DEVICE_PROFILE_LOCK:
        p = DEVICE_PROFILE.get(_device_key(host, port), {"version": None, "major": None, "commands": {}, "version_checked_ts": 0})
        p.setdefault("commands", {})
        p["version"] = version
        p["major"] = major
        if checked_ts:
            p["version_checked_ts"] = checked_ts
        DEVICE_PROFILE[_device_key(host, port)] = p
    if device_id and version:
        set_device_ros_version(int(device_id), version)
    return version, major, checked_ts


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
        if major and major >= 7:
            return [
                "/interface print detail terse without-paging",
                "/interface print terse without-paging",
                "/interface print without-paging",
                "/interface print detail terse",
                "/interface print terse",
                "/interface print",
            ]
        return [
            "/interface print detail terse",
            "/interface print terse",
            "/interface print detail terse without-paging",
            "/interface print terse without-paging",
            "/interface print without-paging",
            "/interface print",
        ]
    if feature == "logs_read":
        if major and major >= 7:
            return [
                "/log print without-paging",
                "/log print",
                "/system logging action print without-paging",
            ]
        return [
            "/log print",
            "/log print without-paging",
            "/system logging action print",
        ]
    if feature == "resource_print":
        if major and major >= 7:
            return [
                "/system resource print without-paging",
                "/system resource print",
            ]
        return [
            "/system resource print",
            "/system resource print without-paging",
        ]
    if feature == "identity_print":
        if major and major >= 7:
            return [
                "/system identity print without-paging",
                "/system identity print",
            ]
        return [
            "/system identity print",
            "/system identity print without-paging",
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

    # Always resolve RouterOS version before selecting command set.
    # Uses cache + DB + cooldown recheck to avoid excess probes.
    version, major, checked_ts = _resolve_device_ros_version(
        host=host,
        port=port,
        username=username,
        password=password,
        device_id=device_id,
        profile=profile,
    )

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
register_fleet_policy_routes(app, _route_ctx)
