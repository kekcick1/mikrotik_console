import asyncio
import json
import re
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse


def register_device_routes(app, ctx) -> None:
    def _parse_uptime(raw: str) -> str | None:
        """Parse uptime from MikroTik '/system resource print' output."""
        text = (raw or "").replace("\r", "")
        pairs = {}
        for line in text.split("\n"):
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            pairs[k.strip().lower()] = v.strip()

        uptime = pairs.get("uptime")

        if not uptime:
            m = re.search(r"uptime:\s*([^\s]+)", text, flags=re.IGNORECASE)
            if m:
                uptime = m.group(1)
        return uptime

    def _parse_iso_utc(value: str | None) -> float | None:
        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except Exception:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return float(dt.timestamp())

    def _read_stream_actor(request: Request) -> object:
        token = (request.query_params.get("access_token") or "").strip()
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1].strip()
        if not token:
            raise HTTPException(status_code=401, detail="Missing bearer token")

        payload = ctx.parse_token(token)
        username = payload.get("u", "")
        with closing(ctx.db_conn()) as conn:
            row = conn.execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="User not found")
        return row

    def _load_visible_device_rows(actor: object) -> list[object]:
        with closing(ctx.db_conn()) as conn:
            if ctx.ROLE_LEVEL.get(actor["role"], 0) >= ctx.ROLE_LEVEL["admin"]:
                rows = conn.execute(
                    "SELECT id, name, host, port, username, password_enc, ros_version, profile_key FROM devices ORDER BY name"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, name, host, port, username, password_enc, ros_version, profile_key FROM devices WHERE owner_id = ? ORDER BY name",
                    (actor["id"],),
                ).fetchall()
        return rows

    def _build_device_status(row: object, lite: bool = False) -> dict:
        dkey = ctx._device_key(row["host"], row["port"])
        stale_threshold = max(30, int(getattr(ctx, "HEALTH_STALE_SECONDS", 120)))
        high_queue_threshold = max(1, int(getattr(ctx, "HEALTH_HIGH_QUEUE_DEPTH", 3)))

        try:
            password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
            key = ctx._ssh_pool_key(row["host"], row["port"], row["username"], password)
        except Exception:
            password = None
            key = None

        active = False
        idle_seconds = None
        uptime = None
        if key:
            with ctx.SSH_POOL_LOCK:
                entry = ctx.SSH_POOL.get(key)
                if entry and ctx._is_pool_entry_active(entry):
                    active = True
                    idle_seconds = int(max(0, time.time() - entry.get("last_used", time.time())))

        queue_depth = 0
        with ctx.DEVICE_QUEUES_LOCK:
            queue = ctx.DEVICE_QUEUES.get(dkey)
            if queue:
                queue_depth = len(queue.get("tokens", []))

        if active and (not lite) and password:
            try:
                out_ctx = ctx.exec_feature_command(
                    row["host"],
                    int(row["port"]),
                    row["username"],
                    password,
                    "resource_print",
                    int(row["id"]),
                )
                uptime = _parse_uptime(out_ctx.get("output", ""))
            except Exception:
                # Keep list/status calls resilient even if resource command fails.
                pass

        diag = ctx._diag_get(dkey).copy()
        last_health_check_at = diag.get("last_health_check_at") or diag.get("last_success_at") or diag.get("last_attempt_at")
        last_health_check_ts = _parse_iso_utc(last_health_check_at)
        freshness_seconds = None
        stale = False
        if last_health_check_ts is not None:
            freshness_seconds = int(max(0, time.time() - last_health_check_ts))
            stale = freshness_seconds > stale_threshold

        session_state = "active" if active else "reconnect"
        last_error = diag.get("last_error")
        last_event = diag.get("last_event")
        high_queue = queue_depth >= high_queue_threshold

        if last_event == "disconnected_by_user":
            health_state = "offline"
        elif session_state == "active":
            if stale or last_error or high_queue:
                health_state = "degraded"
            else:
                health_state = "online"
        else:
            if last_error or stale:
                health_state = "offline"
            elif last_health_check_at:
                health_state = "degraded"
            else:
                health_state = "unknown"

        slo = ctx.get_device_slo_snapshot(int(row["id"])) or {}
        return {
            "id": int(row["id"]),
            "name": row["name"],
            "host": row["host"],
            "port": int(row["port"]),
            "profile_key": row["profile_key"] or "branch-small",
            "ros_version": row["ros_version"],
            "status": session_state,
            "session_state": session_state,
            "health_state": health_state,
            "health_rtt_ms": diag.get("last_rtt_ms"),
            "last_health_check_at": last_health_check_at,
            "freshness_seconds": freshness_seconds,
            "stale": stale,
            "high_queue": high_queue,
            "queue_depth": int(queue_depth),
            "idle_seconds": idle_seconds,
            "last_error": last_error,
            "last_event": last_event,
            "reconnect_count": int(diag.get("reconnect_count", 0)),
            "last_success_at": diag.get("last_success_at"),
            "uptime": uptime,
            "slo_state": slo.get("slo_state"),
            "slo_violations": slo.get("violations", []),
        }

    def _build_fleet_summary(items: list[dict]) -> dict:
        online = sum(1 for x in items if x.get("health_state") == "online")
        degraded = sum(1 for x in items if x.get("health_state") == "degraded")
        offline = sum(1 for x in items if x.get("health_state") == "offline")
        unknown = sum(1 for x in items if x.get("health_state") == "unknown")
        stale = sum(1 for x in items if x.get("stale"))
        errors = sum(1 for x in items if x.get("last_error"))
        active_sessions = sum(1 for x in items if x.get("session_state") == "active")

        scored = []
        for item in items:
            score = 0
            if item.get("last_error"):
                score += 100
            score += int(item.get("reconnect_count") or 0) * 5
            if item.get("stale"):
                score += 30
            if item.get("high_queue"):
                score += 15
            if item.get("session_state") != "active":
                score += 5
            if score > 0:
                scored.append((score, item))

        scored.sort(key=lambda t: (-t[0], t[1].get("name") or ""))
        top_problematic = [
            {
                "id": x["id"],
                "name": x["name"],
                "health_state": x.get("health_state"),
                "session_state": x.get("session_state"),
                "stale": bool(x.get("stale")),
                "high_queue": bool(x.get("high_queue")),
                "queue_depth": int(x.get("queue_depth") or 0),
                "reconnect_count": int(x.get("reconnect_count") or 0),
                "last_error": x.get("last_error"),
                "freshness_seconds": x.get("freshness_seconds"),
                "score": int(score),
            }
            for score, x in scored[:8]
        ]

        return {
            "devices_total": len(items),
            "active_sessions": int(active_sessions),
            "online": int(online),
            "degraded": int(degraded),
            "offline": int(offline),
            "unknown": int(unknown),
            "stale": int(stale),
            "errors": int(errors),
            "top_problematic": top_problematic,
        }

    @app.get("/api/devices")
    def list_devices(request: Request) -> list[dict]:
        actor = ctx.require_role(request, "viewer")
        with closing(ctx.db_conn()) as conn:
            if ctx.ROLE_LEVEL.get(actor["role"], 0) >= ctx.ROLE_LEVEL["admin"]:
                rows = conn.execute(
                    "SELECT id, name, host, port, username, ros_version, ros_version_checked_at, profile_key, created_at FROM devices ORDER BY name"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, name, host, port, username, ros_version, ros_version_checked_at, profile_key, created_at FROM devices WHERE owner_id = ? ORDER BY name",
                    (actor["id"],),
                ).fetchall()
        return [dict(r) for r in rows]

    @app.get("/api/devices/ssh-concurrency")
    def get_ssh_concurrency(request: Request) -> dict:
        ctx.require_role(request, "viewer")
        return {"ok": True, **ctx.get_global_ssh_runtime()}

    @app.put("/api/devices/ssh-concurrency")
    def set_ssh_concurrency(payload: ctx.SSHConcurrencyIn, request: Request) -> dict:
        actor = ctx.require_role(request, "admin")
        new_limit = ctx.set_global_ssh_limit(int(payload.limit))
        ctx.set_setting("global_ssh_limit", str(new_limit))
        ctx.log_audit(actor["username"], actor["role"], "ssh_concurrency_set", None, f"limit={new_limit}")
        return {"ok": True, **ctx.get_global_ssh_runtime()}

    @app.post("/api/devices/refresh-versions")
    def refresh_devices_versions(request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        force = request.query_params.get("force") == "1"
        with closing(ctx.db_conn()) as conn:
            if ctx.ROLE_LEVEL.get(actor["role"], 0) >= ctx.ROLE_LEVEL["admin"]:
                rows = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
            else:
                rows = conn.execute("SELECT * FROM devices WHERE owner_id = ? ORDER BY name", (actor["id"],)).fetchall()

        results = []
        for row in rows:
            try:
                password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
                if force:
                    ctx.reset_device_profile(row["host"], int(row["port"]))
                ver = ctx.detect_ros_version(row["host"], int(row["port"]), row["username"], password)
                ctx.set_device_ros_version(int(row["id"]), ver)
                ctx.remember_device_profile_version(row["host"], int(row["port"]), ver)
                results.append({"id": int(row["id"]), "name": row["name"], "ok": True, "version": ver})
            except Exception as e:
                results.append({"id": int(row["id"]), "name": row["name"], "ok": False, "error": str(e)})
        return {"ok": True, "force": force, "results": results}

    @app.post("/api/devices")
    def create_device(request: Request, payload: ctx.DeviceIn) -> dict:
        actor = ctx.require_role(request, "operator")
        password_enc = ctx.fernet.encrypt(payload.password.encode()).decode()
        with closing(ctx.db_conn()) as conn:
            cur = conn.execute(
                "INSERT INTO devices(name, host, port, username, password_enc, owner_id) VALUES (?, ?, ?, ?, ?, ?)",
                (payload.name.strip(), payload.host.strip(), payload.port, payload.username.strip(), password_enc, int(actor["id"])),
            )
            conn.commit()
            device_id = cur.lastrowid
        ctx.log_audit(actor["username"], actor["role"], "device_create", device_id, payload.name.strip())
        return {"id": device_id}

    @app.post("/api/devices/import")
    def import_devices(request: Request, payload: ctx.DeviceBulkImportIn) -> dict:
        actor = ctx.require_role(request, "operator")

        raw_content = (payload.content or "").strip()
        if not raw_content and payload.server_path:
            requested = Path(payload.server_path).expanduser()
            candidates = [requested]

            try:
                rel = requested.resolve().relative_to(Path("/home/user"))
                candidates.append(Path("/host-home") / rel)
            except Exception:
                pass

            allowed_roots = [
                Path("/home/user").resolve(),
                Path("/host-home").resolve(),
                Path("/data").resolve(),
                Path("/app/data").resolve(),
            ]

            resolved_path = None
            for candidate in candidates:
                c_abs = candidate.resolve()
                if not any(str(c_abs).startswith(str(root)) for root in allowed_roots):
                    continue
                if c_abs.exists() and c_abs.is_file():
                    resolved_path = c_abs
                    break

            if not resolved_path:
                raise HTTPException(
                    status_code=404,
                    detail="server_path file not found (try /home/user/... with /host-home mount, or import from uploaded file)",
                )

            raw_content = resolved_path.read_text(encoding="utf-8", errors="replace")

        if not raw_content:
            raise HTTPException(status_code=400, detail="Provide import content or server_path")

        parsed, parse_errors = ctx.parse_device_import_lines(raw_content)
        if not parsed and parse_errors:
            raise HTTPException(status_code=400, detail="No valid devices found in import content")

        password_enc = ctx.fernet.encrypt(payload.password.encode()).decode()
        created = 0
        skipped = 0
        updated = 0
        errors = list(parse_errors)

        with closing(ctx.db_conn()) as conn:
            if ctx.ROLE_LEVEL.get(actor["role"], 0) >= ctx.ROLE_LEVEL["admin"]:
                existing_rows = conn.execute("SELECT id, host, port FROM devices").fetchall()
            else:
                existing_rows = conn.execute(
                    "SELECT id, host, port FROM devices WHERE owner_id = ?", (actor["id"],)
                ).fetchall()
            existing_map = {(r["host"], int(r["port"])): int(r["id"]) for r in existing_rows}

            for item in parsed:
                key = (item["host"], payload.port)
                if key in existing_map:
                    if payload.update_existing:
                        try:
                            conn.execute(
                                "UPDATE devices SET name = ?, username = ?, password_enc = ? WHERE id = ?",
                                (item["name"], payload.username.strip(), password_enc, existing_map[key]),
                            )
                            updated += 1
                        except Exception as e:
                            errors.append(f"{item['host']}: {e}")
                    else:
                        skipped += 1
                    continue

                try:
                    conn.execute(
                        "INSERT INTO devices(name, host, port, username, password_enc, owner_id) VALUES (?, ?, ?, ?, ?, ?)",
                        (item["name"], item["host"], payload.port, payload.username.strip(), password_enc, int(actor["id"])),
                    )
                    row = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
                    existing_map[key] = int(row["id"]) if row else -1
                    created += 1
                except Exception as e:
                    errors.append(f"{item['host']}: {e}")
            conn.commit()

        ctx.log_audit(
            actor["username"],
            actor["role"],
            "device_bulk_import",
            None,
            f"created={created}, updated={updated}, skipped={skipped}, errors={len(errors)}",
        )
        return {
            "ok": True,
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "errors": errors[:80],
            "parsed": len(parsed),
        }

    @app.get("/api/devices/export")
    def export_devices(request: Request) -> PlainTextResponse:
        actor = ctx.require_role(request, "viewer")
        with closing(ctx.db_conn()) as conn:
            if ctx.ROLE_LEVEL.get(actor["role"], 0) >= ctx.ROLE_LEVEL["admin"]:
                rows = conn.execute(
                    "SELECT name, host, port, username FROM devices ORDER BY name"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT name, host, port, username FROM devices WHERE owner_id = ? ORDER BY name",
                    (actor["id"],),
                ).fetchall()

        lines = ["# host\tname\tport\tusername"]
        for row in rows:
            lines.append(f"{row['host']}\t{row['name']}\t{row['port']}\t{row['username']}")
        content = "\n".join(lines) + "\n"
        headers = {"Content-Disposition": "attachment; filename=mikrotik-devices-export.txt"}
        return PlainTextResponse(content=content, headers=headers)

    @app.get("/api/devices/status-overview")
    def devices_status_overview(request: Request) -> list[dict]:
        actor = ctx.require_role(request, "viewer")
        lite = request.query_params.get("lite") == "1"
        rows = _load_visible_device_rows(actor)
        return [_build_device_status(row, lite=lite) for row in rows]

    @app.get("/api/devices/{device_id}/status-overview")
    def device_status_overview(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        lite = request.query_params.get("lite") == "1"
        row = ctx.load_device(device_id, actor)
        return _build_device_status(row, lite=lite)

    @app.get("/api/devices/fleet-summary")
    def devices_fleet_summary(request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        rows = _load_visible_device_rows(actor)
        items = [_build_device_status(row, lite=True) for row in rows]
        out = _build_fleet_summary(items)
        out["generated_at"] = datetime.utcnow().isoformat() + "Z"
        return out

    @app.get("/api/devices/status-stream")
    async def devices_status_stream(request: Request) -> StreamingResponse:
        actor = _read_stream_actor(request)
        if ctx.ROLE_LEVEL.get(actor["role"], 0) < ctx.ROLE_LEVEL["viewer"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        lite = request.query_params.get("lite", "1") != "0"
        interval_raw = request.query_params.get("interval")
        try:
            interval_sec = float(interval_raw) if interval_raw is not None else 4.0
        except Exception:
            interval_sec = 4.0
        interval_sec = max(2.0, min(15.0, interval_sec))

        async def _events():
            while True:
                if await request.is_disconnected():
                    break
                rows = _load_visible_device_rows(actor)
                items = [_build_device_status(row, lite=lite) for row in rows]
                payload = {
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "items": items,
                    "summary": _build_fleet_summary(items),
                }
                yield "event: fleet\n"
                yield f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"
                await asyncio.sleep(interval_sec)

        headers = {
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
        return StreamingResponse(_events(), media_type="text/event-stream", headers=headers)

    @app.delete("/api/devices/{device_id}")
    def delete_device(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        with closing(ctx.db_conn()) as conn:
            row = conn.execute(
                "SELECT id, name, host, port, username, password_enc, owner_id FROM devices WHERE id = ?",
                (device_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Device not found")
            if ctx.ROLE_LEVEL.get(actor["role"], 0) < ctx.ROLE_LEVEL["admin"]:
                if row["owner_id"] is None or int(row["owner_id"]) != int(actor["id"]):
                    raise HTTPException(status_code=404, detail="Device not found")

            conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            conn.commit()

        ctx._cleanup_deleted_device_runtime(
            row["host"],
            int(row["port"]),
            row["username"],
            row["password_enc"],
        )
        ctx.log_audit(
            actor["username"],
            actor["role"],
            "device_delete",
            None,
            f"deleted_id={row['id']}, name={row['name']}, host={row['host']}:{row['port']}",
        )
        return {"ok": True}

    @app.put("/api/devices/{device_id}")
    def update_device(device_id: int, payload: ctx.DeviceUpdateIn, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        with closing(ctx.db_conn()) as conn:
            row = conn.execute(
                "SELECT id, name, host, port, username, password_enc, owner_id FROM devices WHERE id = ?",
                (device_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Device not found")
            if ctx.ROLE_LEVEL.get(actor["role"], 0) < ctx.ROLE_LEVEL["admin"]:
                if row["owner_id"] is None or int(row["owner_id"]) != int(actor["id"]):
                    raise HTTPException(status_code=404, detail="Device not found")

            new_name = payload.name.strip()
            new_host = payload.host.strip()
            new_username = payload.username.strip()
            new_port = int(payload.port)
            password_enc = row["password_enc"]

            if payload.password is not None:
                password_enc = ctx.fernet.encrypt(payload.password.encode()).decode()

            conn.execute(
                "UPDATE devices SET name = ?, host = ?, port = ?, username = ?, password_enc = ? WHERE id = ?",
                (new_name, new_host, new_port, new_username, password_enc, device_id),
            )
            conn.commit()

        # Drop old runtime SSH state; it may no longer match host/port/credentials.
        ctx._cleanup_deleted_device_runtime(
            row["host"],
            int(row["port"]),
            row["username"],
            row["password_enc"],
        )
        ctx.log_audit(
            actor["username"],
            actor["role"],
            "device_update",
            device_id,
            f"{row['name']} -> {new_name}; {row['host']}:{row['port']} -> {new_host}:{new_port}",
        )
        return {"ok": True}

    @app.post("/api/devices/{device_id}/test")
    def test_device(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        out = ctx.exec_feature_command(row["host"], row["port"], row["username"], password, "identity_print", int(row["id"]))
        version = out.get("version") or row["ros_version"]
        if not version:
            try:
                version = ctx.detect_ros_version(row["host"], int(row["port"]), row["username"], password)
            except Exception:
                version = None
        if version:
            ctx.set_device_ros_version(int(row["id"]), version)
            ctx.remember_device_profile_version(row["host"], int(row["port"]), version)
        return {"ok": True, "output": out.get("output", ""), "command": out.get("command"), "ros_version": version}

    @app.post("/api/devices/{device_id}/test-api")
    def test_device_api(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        api_port_raw = request.query_params.get("api_port")
        api_ssl_raw = request.query_params.get("api_ssl")
        api_port = int(api_port_raw) if api_port_raw else 8728
        api_ssl = str(api_ssl_raw).lower() in {"1", "true", "yes", "on"}
        out = ctx.test_routeros_api(row["host"], row["username"], password, api_port=api_port, use_ssl=api_ssl)
        version = out.get("ros_version")
        if version:
            ctx.set_device_ros_version(int(row["id"]), version)
            ctx.remember_device_profile_version(row["host"], int(row["port"]), version)
        ctx.log_audit(actor["username"], actor["role"], "device_test_api", device_id, f"{row['name']}:{api_port} ssl={api_ssl}")
        return out

    @app.post("/api/devices/{device_id}/refresh-version")
    def refresh_device_version(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        force = request.query_params.get("force") == "1"
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        if force:
            ctx.reset_device_profile(row["host"], int(row["port"]))
        version = ctx.detect_ros_version(row["host"], int(row["port"]), row["username"], password)
        ctx.set_device_ros_version(int(row["id"]), version)
        ctx.remember_device_profile_version(row["host"], int(row["port"]), version)
        return {"ok": True, "id": int(row["id"]), "version": version, "force": force}

    @app.get("/api/devices/{device_id}/ssh-status")
    def device_ssh_status(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        row = ctx.load_device(device_id, actor)
        status = _build_device_status(row, lite=True)
        return {
            "status": status["session_state"],
            "session_state": status["session_state"],
            "health_state": status["health_state"],
            "idle_seconds": status["idle_seconds"],
            "queue_depth": status["queue_depth"],
            "stale": status["stale"],
            "freshness_seconds": status["freshness_seconds"],
            "last_health_check_at": status["last_health_check_at"],
        }

    @app.post("/api/devices/{device_id}/disconnect")
    def device_disconnect(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        key = ctx._ssh_pool_key(row["host"], row["port"], row["username"], password)
        dkey = ctx._device_key(row["host"], row["port"])
        ctx._drop_pooled_client(key)
        ctx._diag_mark_event(dkey, "disconnected_by_user")
        ctx.log_audit(actor["username"], actor["role"], "device_disconnect", device_id, row["name"])
        return {"ok": True, "status": "disconnected"}

    @app.get("/api/devices/{device_id}/ssh-diagnostics")
    def device_ssh_diagnostics(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        row = ctx.load_device(device_id, actor)
        dkey = ctx._device_key(row["host"], row["port"])
        diag = ctx._diag_get(dkey).copy()
        status = _build_device_status(row, lite=True)
        return {
            "device_id": device_id,
            "status": status["session_state"],
            "session_state": status["session_state"],
            "health_state": status["health_state"],
            "queue_depth": status["queue_depth"],
            "idle_seconds": status["idle_seconds"],
            "stale": status["stale"],
            "freshness_seconds": status["freshness_seconds"],
            "last_health_check_at": status["last_health_check_at"],
            "rtt_ms": diag.get("last_rtt_ms"),
            "last_error": diag.get("last_error"),
            "reconnect_count": diag.get("reconnect_count", 0),
            "last_event": diag.get("last_event"),
            "last_connected_at": diag.get("last_connected_at"),
            "last_success_at": diag.get("last_success_at"),
            "last_attempt_at": diag.get("last_attempt_at"),
            "ros_version": row["ros_version"],
            "ros_version_checked_at": row["ros_version_checked_at"],
        }

    @app.get("/api/devices/{device_id}/interfaces")
    def list_interfaces(device_id: int, request: Request) -> list[dict]:
        actor = ctx.require_role(request, "viewer")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        out = ctx.exec_feature_command(row["host"], row["port"], row["username"], password, "interfaces_list", int(row["id"]))
        raw = out.get("output", "")
        return ctx.parse_interfaces(raw)

    @app.get("/api/devices/{device_id}/router-logs")
    def router_logs(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()
        out = ctx.exec_feature_command(row["host"], row["port"], row["username"], password, "logs_read", int(row["id"]))
        return {"ok": True, "output": out.get("output", ""), "command": out.get("command"), "ros_version": out.get("version")}

    @app.post("/api/devices/{device_id}/interfaces/{interface_name}")
    def toggle_interface(device_id: int, interface_name: str, payload: ctx.InterfaceToggle, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()

        if not re.fullmatch(r"[\w\-.@:+/]+", interface_name):
            raise HTTPException(status_code=400, detail="Invalid interface name")

        escaped_name = interface_name.replace('"', "")
        action = "disable" if payload.disabled else "enable"
        command = f'/interface {action} [find where name="{escaped_name}"]'
        output = ctx.safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
        ctx.log_audit(actor["username"], actor["role"], "interface_toggle", device_id, f"{interface_name}:{action}")
        return {"ok": True, "action": action, "output": output}

    @app.post("/api/devices/{device_id}/interfaces/{interface_name}/edit")
    def edit_interface(device_id: int, interface_name: str, payload: ctx.InterfaceEdit, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        row = ctx.load_device(device_id, actor)
        password = ctx.fernet.decrypt(row["password_enc"].encode()).decode()

        if not re.fullmatch(r"[\w\-.@:+/]+", interface_name):
            raise HTTPException(status_code=400, detail="Invalid interface name")

        updates = []
        if payload.mtu is not None:
            updates.append(f"mtu={payload.mtu}")
        if payload.comment is not None:
            safe_comment = payload.comment.replace("\n", " ").replace("\r", " ").replace('"', "").strip()
            updates.append(f'comment="{safe_comment}"')
        if payload.new_name is not None:
            new_name = payload.new_name.strip()
            if not new_name:
                raise HTTPException(status_code=400, detail="New interface name cannot be empty")
            if not re.fullmatch(r"[\w\-.@:+/]+", new_name):
                raise HTTPException(status_code=400, detail="Invalid new interface name")
            updates.append(f'name="{new_name}"')
        if not updates:
            raise HTTPException(status_code=400, detail="No interface changes provided")

        escaped_name = interface_name.replace('"', "")
        command = f'/interface set [find where name="{escaped_name}"] ' + " ".join(updates)
        output = ctx.safe_ssh_exec(row["host"], row["port"], row["username"], password, command)
        ctx.log_audit(actor["username"], actor["role"], "interface_edit", device_id, f"{interface_name}: {'; '.join(updates)}")
        return {"ok": True, "output": output, "updated": updates}
