import base64
import collections
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path

import paramiko
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "devices.db"
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
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


class BackupUpload(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1)


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


def init_db() -> None:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
        conn.commit()
    ensure_default_admin()


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


def ensure_default_admin() -> None:
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if row:
            return
        conn.execute(
            "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", hash_password(DEFAULT_ADMIN_PASSWORD), "admin"),
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


def load_device(device_id: int) -> sqlite3.Row:
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not row:
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


@app.get("/")
def index() -> FileResponse:
    return FileResponse("static/index.html")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}


@app.post("/api/auth/login")
def auth_login(payload: LoginIn) -> dict:
    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT id, username, role, password_hash FROM users WHERE username = ?",
            (payload.username.strip(),),
        ).fetchone()
    if not row or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = make_token(row["username"], row["role"])
    return {"token": token, "user": {"id": row["id"], "username": row["username"], "role": row["role"]}}


@app.get("/api/auth/me")
def auth_me(request: Request) -> dict:
    user = require_role(request, "viewer")
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


@app.get("/api/users")
def list_users(request: Request) -> list[dict]:
    require_role(request, "admin")
    with closing(db_conn()) as conn:
        rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY username").fetchall()
    return [dict(r) for r in rows]


@app.post("/api/users")
def create_user(request: Request, payload: UserIn) -> dict:
    actor = require_role(request, "admin")
    role = payload.role.strip().lower()
    if role not in ROLE_LEVEL:
        raise HTTPException(status_code=400, detail="Invalid role")
    username = payload.username.strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{3,80}", username):
        raise HTTPException(status_code=400, detail="Invalid username format")

    with closing(db_conn()) as conn:
        exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            raise HTTPException(status_code=400, detail="User already exists")
        cur = conn.execute(
            "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(payload.password), role),
        )
        conn.commit()

    log_audit(actor["username"], actor["role"], "user_create", None, f"created={username}, role={role}")
    return {"id": cur.lastrowid, "username": username, "role": role}


@app.delete("/api/users/{user_id}")
def delete_user(request: Request, user_id: int) -> dict:
    actor = require_role(request, "admin")
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        if row["username"] == actor["username"]:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")
        if row["role"] == "admin":
            admins = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()["c"]
            if admins <= 1:
                raise HTTPException(status_code=400, detail="Cannot delete last admin")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

    log_audit(actor["username"], actor["role"], "user_delete", None, f"deleted={row['username']}")
    return {"ok": True}


@app.get("/api/devices")
def list_devices(request: Request) -> list[dict]:
    require_role(request, "viewer")
    with closing(db_conn()) as conn:
        rows = conn.execute(
            "SELECT id, name, host, port, username, created_at FROM devices ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/devices")
def create_device(request: Request, payload: DeviceIn) -> dict:
    actor = require_role(request, "admin")
    password_enc = fernet.encrypt(payload.password.encode()).decode()
    with closing(db_conn()) as conn:
        cur = conn.execute(
            "INSERT INTO devices(name, host, port, username, password_enc) VALUES (?, ?, ?, ?, ?)",
            (payload.name.strip(), payload.host.strip(), payload.port, payload.username.strip(), password_enc),
        )
        conn.commit()
        device_id = cur.lastrowid
    log_audit(actor["username"], actor["role"], "device_create", device_id, payload.name.strip())
    return {"id": device_id}


@app.delete("/api/devices/{device_id}")
def delete_device(device_id: int, request: Request) -> dict:
    actor = require_role(request, "admin")
    with closing(db_conn()) as conn:
        cur = conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Device not found")
    log_audit(actor["username"], actor["role"], "device_delete", device_id, "")
    return {"ok": True}


@app.post("/api/devices/{device_id}/test")
def test_device(device_id: int, request: Request) -> dict:
    require_role(request, "viewer")
    row = load_device(device_id)
    password = fernet.decrypt(row["password_enc"].encode()).decode()
    output = safe_ssh_exec(row["host"], row["port"], row["username"], password, "/system identity print")
    return {"ok": True, "output": output}


@app.get("/api/devices/{device_id}/ssh-status")
def device_ssh_status(device_id: int, request: Request) -> dict:
    require_role(request, "viewer")
    row = load_device(device_id)
    password = fernet.decrypt(row["password_enc"].encode()).decode()
    key = _ssh_pool_key(row["host"], row["port"], row["username"], password)
    dkey = _device_key(row["host"], row["port"])

    active = False
    idle_seconds = None
    queued = 0

    with SSH_POOL_LOCK:
        entry = SSH_POOL.get(key)
        if entry and _is_pool_entry_active(entry):
            active = True
            idle_seconds = int(max(0, time.time() - entry.get("last_used", time.time())))

    with DEVICE_QUEUES_LOCK:
        queue = DEVICE_QUEUES.get(dkey)
        if queue:
            queued = len(queue.get("tokens", []))

    return {
        "status": "active" if active else "reconnect",
        "idle_seconds": idle_seconds,
        "queue_depth": queued,
    }


@app.post("/api/devices/{device_id}/disconnect")
def device_disconnect(device_id: int, request: Request) -> dict:
    actor = require_role(request, "operator")
    row = load_device(device_id)
    password = fernet.decrypt(row["password_enc"].encode()).decode()

    key = _ssh_pool_key(row["host"], row["port"], row["username"], password)
    dkey = _device_key(row["host"], row["port"])
    _drop_pooled_client(key)
    _diag_mark_error(dkey, "manual disconnect")

    log_audit(actor["username"], actor["role"], "device_disconnect", device_id, row["name"])
    return {"ok": True, "status": "disconnected"}


@app.get("/api/devices/{device_id}/ssh-diagnostics")
def device_ssh_diagnostics(device_id: int, request: Request) -> dict:
    require_role(request, "viewer")
    row = load_device(device_id)
    dkey = _device_key(row["host"], row["port"])
    diag = _diag_get(dkey).copy()
    status = device_ssh_status(device_id, request)

    return {
        "device_id": device_id,
        "status": status["status"],
        "queue_depth": status["queue_depth"],
        "idle_seconds": status["idle_seconds"],
        "rtt_ms": diag.get("last_rtt_ms"),
        "last_error": diag.get("last_error"),
        "reconnect_count": diag.get("reconnect_count", 0),
        "last_connected_at": diag.get("last_connected_at"),
        "last_success_at": diag.get("last_success_at"),
        "last_attempt_at": diag.get("last_attempt_at"),
    }


@app.get("/api/devices/{device_id}/interfaces")
def list_interfaces(device_id: int, request: Request) -> list[dict]:
    require_role(request, "viewer")
    row = load_device(device_id)
    password = fernet.decrypt(row["password_enc"].encode()).decode()
    raw = safe_ssh_exec(
        row["host"],
        row["port"],
        row["username"],
        password,
        "/interface print terse without-paging",
    )
    interfaces = parse_interfaces(raw)
    return interfaces


@app.post("/api/devices/{device_id}/interfaces/{interface_name}")
def toggle_interface(device_id: int, interface_name: str, payload: InterfaceToggle, request: Request) -> dict:
    actor = require_role(request, "operator")
    row = load_device(device_id)
    password = fernet.decrypt(row["password_enc"].encode()).decode()

    if not re.fullmatch(r"[\w\-.@:+/]+", interface_name):
        raise HTTPException(status_code=400, detail="Invalid interface name")

    escaped_name = interface_name.replace('"', '')
    action = "disable" if payload.disabled else "enable"
    command = f'/interface {action} [find where name="{escaped_name}"]'
    output = safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
    log_audit(actor["username"], actor["role"], "interface_toggle", device_id, f"{interface_name}:{action}")

    return {"ok": True, "action": action, "output": output}


@app.post("/api/devices/{device_id}/terminal")
def terminal_exec(device_id: int, payload: TerminalCommand, request: Request) -> dict:
    actor = require_role(request, "operator")
    row = load_device(device_id)
    password = fernet.decrypt(row["password_enc"].encode()).decode()
    command = validate_terminal_command(payload.command)
    output = safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
    log_audit(actor["username"], actor["role"], "terminal_exec", device_id, command)
    return {"ok": True, "command": command, "output": output}


@app.post("/api/terminal/broadcast")
def terminal_broadcast(payload: TerminalCommand, request: Request) -> dict:
    actor = require_role(request, "operator")
    command = validate_terminal_command(payload.command)

    with closing(db_conn()) as conn:
        devices = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()

    results = []
    for row in devices:
        try:
            password = fernet.decrypt(row["password_enc"].encode()).decode()
            output = safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
            results.append({"device_id": row["id"], "name": row["name"], "ok": True, "output": output})
        except HTTPException as e:
            results.append({"device_id": row["id"], "name": row["name"], "ok": False, "error": str(e.detail)})
        except Exception as e:
            results.append({"device_id": row["id"], "name": row["name"], "ok": False, "error": str(e)})

    log_audit(actor["username"], actor["role"], "terminal_broadcast", None, command)
    return {"ok": True, "command": command, "results": results}


@app.post("/api/terminal/broadcast/preview")
def terminal_broadcast_preview(payload: TerminalCommand, request: Request) -> dict:
    actor = require_role(request, "operator")
    command = validate_terminal_command(payload.command)

    with closing(db_conn()) as conn:
        devices = conn.execute("SELECT id, name, host, port FROM devices ORDER BY name").fetchall()

    targets = []
    ids = []
    for d in devices:
        ids.append(d["id"])
        dkey = _device_key(d["host"], d["port"])
        with DEVICE_QUEUES_LOCK:
            queue = DEVICE_QUEUES.get(dkey)
            qdepth = len(queue.get("tokens", [])) if queue else 0
        targets.append({"id": d["id"], "name": d["name"], "queue_depth": qdepth})

    token = _make_broadcast_confirm_token(command, actor["username"], ids)
    return {
        "ok": True,
        "dry_run": True,
        "command": command,
        "targets": targets,
        "confirm_token": token,
        "confirm_ttl_seconds": BROADCAST_CONFIRM_TTL_SECONDS,
    }


@app.post("/api/terminal/broadcast/execute")
def terminal_broadcast_execute(payload: BroadcastExecuteIn, request: Request) -> dict:
    actor = require_role(request, "operator")
    command = validate_terminal_command(payload.command)
    token_payload = _verify_broadcast_confirm_token(payload.confirm_token, command, actor["username"])
    allowed_ids = token_payload.get("ids", [])

    with closing(db_conn()) as conn:
        if allowed_ids:
            placeholders = ",".join("?" for _ in allowed_ids)
            devices = conn.execute(
                f"SELECT * FROM devices WHERE id IN ({placeholders}) ORDER BY name",
                tuple(int(x) for x in allowed_ids),
            ).fetchall()
        else:
            devices = []

    results = []
    for row in devices:
        try:
            password = fernet.decrypt(row["password_enc"].encode()).decode()
            output = safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
            results.append({"device_id": row["id"], "name": row["name"], "ok": True, "output": output})
        except HTTPException as e:
            results.append({"device_id": row["id"], "name": row["name"], "ok": False, "error": str(e.detail)})
        except Exception as e:
            results.append({"device_id": row["id"], "name": row["name"], "ok": False, "error": str(e)})

    log_audit(actor["username"], actor["role"], "terminal_broadcast_safe", None, command)
    return {"ok": True, "command": command, "results": results}


@app.get("/api/devices/{device_id}/backups")
def list_backups(device_id: int, request: Request) -> list[dict]:
    require_role(request, "viewer")
    load_device(device_id)
    with closing(db_conn()) as conn:
        rows = conn.execute(
            "SELECT id, name, created_at FROM backups WHERE device_id = ? ORDER BY id DESC",
            (device_id,),
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/devices/{device_id}/backups/capture")
def capture_backup(device_id: int, request: Request) -> dict:
    actor = require_role(request, "operator")
    row = load_device(device_id)
    password = fernet.decrypt(row["password_enc"].encode()).decode()
    content = safe_ssh_exec(
        row["host"],
        row["port"],
        row["username"],
        password,
        "/export terse show-sensitive",
    )
    if re.search(r"expected end of command|syntax error|input does not match any value", content, re.IGNORECASE):
        raise HTTPException(status_code=400, detail=f"Backup export failed: {content[:300]}")
    backup = save_backup(device_id, f"{row['name']}_export", content)
    log_audit(actor["username"], actor["role"], "backup_capture", device_id, backup["name"])
    return {"ok": True, "backup": {"id": backup["id"], "name": backup["name"]}}


@app.post("/api/devices/{device_id}/backups/upload")
def upload_backup(device_id: int, payload: BackupUpload, request: Request) -> dict:
    actor = require_role(request, "operator")
    load_device(device_id)
    backup = save_backup(device_id, payload.name, payload.content)
    log_audit(actor["username"], actor["role"], "backup_upload", device_id, backup["name"])
    return {"ok": True, "backup": {"id": backup["id"], "name": backup["name"]}}


@app.get("/api/devices/{device_id}/backups/{backup_id}/download")
def download_backup(device_id: int, backup_id: int, request: Request) -> PlainTextResponse:
    require_role(request, "viewer")
    backup = load_backup(device_id, backup_id)
    path = Path(backup["file_path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup file missing")
    content = path.read_text(encoding="utf-8", errors="replace")
    headers = {"Content-Disposition": f'attachment; filename="{backup["name"]}"'}
    return PlainTextResponse(content=content, headers=headers)


@app.delete("/api/devices/{device_id}/backups/{backup_id}")
def delete_backup(device_id: int, backup_id: int, request: Request) -> dict:
    actor = require_role(request, "operator")
    backup = load_backup(device_id, backup_id)
    path = Path(backup["file_path"])

    with closing(db_conn()) as conn:
        conn.execute("DELETE FROM backups WHERE id = ? AND device_id = ?", (backup_id, device_id))
        conn.commit()

    if path.exists():
        path.unlink()

    log_audit(actor["username"], actor["role"], "backup_delete", device_id, backup["name"])
    return {"ok": True}


@app.post("/api/devices/{device_id}/backups/{backup_id}/restore")
def restore_backup(device_id: int, backup_id: int, request: Request) -> dict:
    actor = require_role(request, "operator")
    row = load_device(device_id)
    backup = load_backup(device_id, backup_id)
    path = Path(backup["file_path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup file missing")

    password = fernet.decrypt(row["password_enc"].encode()).decode()
    content = path.read_text(encoding="utf-8", errors="replace")
    output = ssh_import_script(row["host"], row["port"], row["username"], password, content)
    log_audit(actor["username"], actor["role"], "backup_restore", device_id, backup["name"])

    return {"ok": True, "backup": backup["name"], "output": output}


@app.get("/api/audit")
def list_audit(request: Request, limit: int = 200) -> list[dict]:
    require_role(request, "operator")
    limit = max(1, min(1000, int(limit)))
    with closing(db_conn()) as conn:
        rows = conn.execute(
            """
            SELECT a.id, a.username, a.role, a.action, a.device_id, d.name AS device_name, a.details, a.created_at
            FROM audit_logs a
            LEFT JOIN devices d ON d.id = a.device_id
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
