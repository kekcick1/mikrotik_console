import re
from contextlib import closing
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import PlainTextResponse


def register_terminal_backup_routes(app, ctx) -> None:
    @app.post("/api/devices/{device_id}/terminal")
    def terminal_exec(device_id: int, payload: ctx.TerminalCommand, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        command = ctx.validate_terminal_command(payload.command)
        output = ctx.safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
        ctx.log_audit(actor["username"], actor["role"], "terminal_exec", device_id, command)
        return {"ok": True, "command": command, "output": output}

    @app.post("/api/terminal/broadcast")
    def terminal_broadcast(payload: ctx.TerminalCommand, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        command = ctx.validate_terminal_command(payload.command)
        with closing(ctx.db_conn()) as conn:
            if ctx.ROLE_LEVEL.get(actor["role"], 0) >= ctx.ROLE_LEVEL["admin"]:
                devices = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
            else:
                devices = conn.execute(
                    "SELECT * FROM devices WHERE owner_id = ? ORDER BY name", (actor["id"],)
                ).fetchall()

        results = []
        for row in devices:
            try:
                password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
                output = ctx.safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
                results.append({"device_id": row["id"], "name": row["name"], "ok": True, "output": output})
            except HTTPException as e:
                results.append({"device_id": row["id"], "name": row["name"], "ok": False, "error": str(e.detail)})
            except Exception as e:
                results.append({"device_id": row["id"], "name": row["name"], "ok": False, "error": str(e)})

        ctx.log_audit(actor["username"], actor["role"], "terminal_broadcast", None, command)
        return {"ok": True, "command": command, "results": results}

    @app.post("/api/terminal/broadcast/preview")
    def terminal_broadcast_preview(payload: ctx.TerminalCommand, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        command = ctx.validate_terminal_command(payload.command)

        with closing(ctx.db_conn()) as conn:
            if ctx.ROLE_LEVEL.get(actor["role"], 0) >= ctx.ROLE_LEVEL["admin"]:
                devices = conn.execute("SELECT id, name, host, port FROM devices ORDER BY name").fetchall()
            else:
                devices = conn.execute(
                    "SELECT id, name, host, port FROM devices WHERE owner_id = ? ORDER BY name", (actor["id"],)
                ).fetchall()

        targets = []
        ids = []
        for device in devices:
            ids.append(device["id"])
            dkey = ctx._device_key(device["host"], device["port"])
            with ctx.DEVICE_QUEUES_LOCK:
                queue = ctx.DEVICE_QUEUES.get(dkey)
                qdepth = len(queue.get("tokens", [])) if queue else 0
            targets.append({"id": device["id"], "name": device["name"], "queue_depth": qdepth})

        token = ctx._make_broadcast_confirm_token(command, actor["username"], ids)
        return {
            "ok": True,
            "dry_run": True,
            "command": command,
            "targets": targets,
            "confirm_token": token,
            "confirm_ttl_seconds": ctx.BROADCAST_CONFIRM_TTL_SECONDS,
        }

    @app.post("/api/terminal/broadcast/execute")
    def terminal_broadcast_execute(payload: ctx.BroadcastExecuteIn, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        command = ctx.validate_terminal_command(payload.command)
        token_payload = ctx._verify_broadcast_confirm_token(payload.confirm_token, command, actor["username"])
        allowed_ids = token_payload.get("ids", [])

        with closing(ctx.db_conn()) as conn:
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
                password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
                output = ctx.safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
                results.append({"device_id": row["id"], "name": row["name"], "ok": True, "output": output})
            except HTTPException as e:
                results.append({"device_id": row["id"], "name": row["name"], "ok": False, "error": str(e.detail)})
            except Exception as e:
                results.append({"device_id": row["id"], "name": row["name"], "ok": False, "error": str(e)})

        ctx.log_audit(actor["username"], actor["role"], "terminal_broadcast_safe", None, command)
        return {"ok": True, "command": command, "results": results}

    @app.get("/api/devices/{device_id}/backups")
    def list_backups(device_id: int, request: Request) -> list[dict]:
        actor = ctx.require_role(request, "viewer")
        ctx.load_device(device_id, actor)
        with closing(ctx.db_conn()) as conn:
            rows = conn.execute(
                "SELECT id, name, created_at FROM backups WHERE device_id = ? ORDER BY id DESC",
                (device_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    @app.post("/api/devices/{device_id}/backups/capture")
    def capture_backup(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        out = ctx.exec_feature_command(
            row["host"],
            row["port"],
            row["username"],
            password,
            "backup_export",
            int(row["id"]),
        )
        content = out.get("output", "")
        if re.search(r"expected end of command|syntax error|input does not match any value", content, re.IGNORECASE):
            raise HTTPException(status_code=400, detail=f"Backup export failed: {content[:300]}")
        backup = ctx.save_backup(device_id, f"{row['name']}_export", content)
        cmd = out.get("command", "")
        ctx.log_audit(actor["username"], actor["role"], "backup_capture", device_id, f"{backup['name']} via {cmd}")
        return {"ok": True, "backup": {"id": backup["id"], "name": backup["name"]}}

    @app.post("/api/devices/{device_id}/backups/upload")
    def upload_backup(device_id: int, payload: ctx.BackupUpload, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        ctx.load_device(device_id, actor)
        backup = ctx.save_backup(device_id, payload.name, payload.content)
        ctx.log_audit(actor["username"], actor["role"], "backup_upload", device_id, backup["name"])
        return {"ok": True, "backup": {"id": backup["id"], "name": backup["name"]}}

    @app.get("/api/devices/{device_id}/backups/{backup_id}/download")
    def download_backup(device_id: int, backup_id: int, request: Request) -> PlainTextResponse:
        actor = ctx.require_role(request, "viewer")
        ctx.load_device(device_id, actor)
        backup = ctx.load_backup(device_id, backup_id)
        path = Path(backup["file_path"])
        if not path.exists():
            raise HTTPException(status_code=404, detail="Backup file missing")
        content = path.read_text(encoding="utf-8", errors="replace")
        headers = {"Content-Disposition": f'attachment; filename="{backup["name"]}"'}
        return PlainTextResponse(content=content, headers=headers)

    @app.delete("/api/devices/{device_id}/backups/{backup_id}")
    def delete_backup(device_id: int, backup_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        ctx.load_device(device_id, actor)
        backup = ctx.load_backup(device_id, backup_id)
        path = Path(backup["file_path"])

        with closing(ctx.db_conn()) as conn:
            conn.execute("DELETE FROM backups WHERE id = ? AND device_id = ?", (backup_id, device_id))
            conn.commit()

        if path.exists():
            path.unlink()

        ctx.log_audit(actor["username"], actor["role"], "backup_delete", device_id, backup["name"])
        return {"ok": True}

    @app.post("/api/devices/{device_id}/backups/{backup_id}/restore")
    def restore_backup(device_id: int, backup_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        row = ctx.load_device(device_id, actor)
        backup = ctx.load_backup(device_id, backup_id)
        path = Path(backup["file_path"])
        if not path.exists():
            raise HTTPException(status_code=404, detail="Backup file missing")

        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        content = path.read_text(encoding="utf-8", errors="replace")
        output = ctx.ssh_import_script(row["host"], row["port"], row["username"], password, content)
        ctx.log_audit(actor["username"], actor["role"], "backup_restore", device_id, backup["name"])
        return {"ok": True, "backup": backup["name"], "output": output}