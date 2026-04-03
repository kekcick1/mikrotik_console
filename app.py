import base64
import collections
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import tarfile
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import paramiko
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
AUTH_SECRET = os.environ.get("MIM_AUTH_SECRET", SECRET)
DEFAULT_ADMIN_PASSWORD = os.environ.get("MIM_ADMIN_PASSWORD", "admin")
TOKEN_TTL_SECONDS = int(os.environ.get("MIM_TOKEN_TTL_SECONDS", "28800"))
SSH_IDLE_TTL_SECONDS = int(os.environ.get("MIM_SSH_IDLE_TTL_SECONDS", "120"))
SSH_CONNECT_TIMEOUT = int(os.environ.get("MIM_SSH_CONNECT_TIMEOUT", "10"))
SSH_COMMAND_TIMEOUT = int(os.environ.get("MIM_SSH_COMMAND_TIMEOUT", "25"))
SSH_KEEPALIVE_SECONDS = int(os.environ.get("MIM_SSH_KEEPALIVE_SECONDS", "20"))
SSH_RETRY_ATTEMPTS = int(os.environ.get("MIM_SSH_RETRY_ATTEMPTS", "2"))
SSH_RETRY_BASE_MS = int(os.environ.get("MIM_SSH_RETRY_BASE_MS", "220"))
BROADCAST_CONFIRM_TTL_SECONDS = int(os.environ.get("MIM_BROADCAST_CONFIRM_TTL_SECONDS", "90"))

ROLE_LEVEL = {"viewer": 1, "operator": 2, "admin": 3}
SSH_POOL_LOCK = threading.Lock()
SSH_POOL: dict[str, dict] = {}
DEVICE_QUEUES_LOCK = threading.Lock()
DEVICE_QUEUES: dict[str, dict] = {}
SSH_DIAG_LOCK = threading.Lock()
SSH_DIAG: dict[str, dict] = {}

if not SECRET:
    raise RuntimeError("MIM_SECRET is required")

if not AUTH_SECRET:
    raise RuntimeError("MIM_AUTH_SECRET or MIM_SECRET is required")

fernet = Fernet(SECRET.encode())

app = FastAPI(title="Mikro Interface Manager")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=255)


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


def _ssh_pool_key(host: str, port: int, username: str, password: str) -> str:
    pw_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
    return f"{host}|{port}|{username}|{pw_hash}"


def _device_key(host: str, port: int) -> str:
    return f"{host}|{port}"


def _diag_get(device_key: str) -> dict:
    with SSH_DIAG_LOCK:
        entry = SSH_DIAG.get(device_key)
        if entry:
            return entry
        entry = {
            "last_rtt_ms": None,
            "last_error": None,
            "reconnect_count": 0,
            "last_connected_at": None,
            "last_success_at": None,
            "last_attempt_at": None,
        }
        SSH_DIAG[device_key] = entry
        return entry


def _diag_mark_attempt(device_key: str) -> None:
    diag = _diag_get(device_key)
    diag["last_attempt_at"] = datetime.utcnow().isoformat() + "Z"


def _diag_mark_connect(device_key: str, reconnect: bool) -> None:
    diag = _diag_get(device_key)
    diag["last_connected_at"] = datetime.utcnow().isoformat() + "Z"
    if reconnect:
        diag["reconnect_count"] += 1


def _diag_mark_success(device_key: str, rtt_ms: int) -> None:
    diag = _diag_get(device_key)
    diag["last_rtt_ms"] = rtt_ms
    diag["last_error"] = None
    diag["last_success_at"] = datetime.utcnow().isoformat() + "Z"


def _diag_mark_error(device_key: str, err: str) -> None:
    diag = _diag_get(device_key)
    diag["last_error"] = (err or "unknown")[:300]


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
        return func()
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

        kv = dict(re.findall(r"([\w-]+)=([^\s]+)", text))
        name = kv.get("name")
        if not name:
            continue

        disabled = kv.get("disabled", "no") in {"yes", "true"} or "X" in flags
        running = kv.get("running", "false") in {"yes", "true"} or "R" in flags
        iface_type = kv.get("type", "")
        mtu = kv.get("mtu", "")

        result.append(
            {
                "name": name,
                "disabled": disabled,
                "running": running,
                "type": iface_type,
                "mtu": mtu,
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


@app.on_event("shutdown")
def on_shutdown() -> None:
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
