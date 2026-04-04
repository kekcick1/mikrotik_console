from contextlib import closing
from datetime import datetime, timedelta

from fastapi import Request
from fastapi.responses import FileResponse


def register_system_routes(app, ctx) -> None:
    @app.get("/api/audit")
    def list_audit(request: Request, limit: int = 200) -> list[dict]:
        ctx.require_role(request, "operator")
        limit = max(1, min(1000, int(limit)))
        with closing(ctx.db_conn()) as conn:
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

    @app.get("/api/system/dashboard")
    def system_dashboard(request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")

        with closing(ctx.db_conn()) as conn:
            if ctx.ROLE_LEVEL.get(actor["role"], 0) >= ctx.ROLE_LEVEL["admin"]:
                device_count = conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"]
            else:
                device_count = conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE owner_id = ?", (actor["id"],)
                ).fetchone()["c"]
            user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            backup_count = conn.execute("SELECT COUNT(*) AS c FROM backups").fetchone()["c"]
            audit_count = conn.execute("SELECT COUNT(*) AS c FROM audit_logs").fetchone()["c"]

            seven_days_ago = (datetime.utcnow() - timedelta(days=6)).strftime("%Y-%m-%d")
            per_day_rows = conn.execute(
                """
                SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS c
                FROM audit_logs
                WHERE substr(created_at, 1, 10) >= ?
                GROUP BY day
                ORDER BY day
                """,
                (seven_days_ago,),
            ).fetchall()

            top_action_rows = conn.execute(
                """
                SELECT action, COUNT(*) AS c
                FROM audit_logs
                GROUP BY action
                ORDER BY c DESC, action ASC
                LIMIT 6
                """
            ).fetchall()

        days = [(datetime.utcnow() - timedelta(days=x)).strftime("%Y-%m-%d") for x in range(6, -1, -1)]
        per_day_map = {row["day"]: int(row["c"]) for row in per_day_rows}
        per_day = [{"day": day, "count": int(per_day_map.get(day, 0))} for day in days]
        top_actions = [{"action": row["action"], "count": int(row["c"])} for row in top_action_rows]

        with ctx.SSH_POOL_LOCK:
            active_ssh = sum(1 for entry in ctx.SSH_POOL.values() if ctx._is_pool_entry_active(entry))

        with ctx.DEVICE_QUEUES_LOCK:
            queued_total = sum(len(queue.get("tokens", [])) for queue in ctx.DEVICE_QUEUES.values())

        return {
            "devices": int(device_count),
            "users": int(user_count),
            "backups": int(backup_count),
            "audit_total": int(audit_count),
            "active_ssh": int(active_ssh),
            "queue_depth_total": int(queued_total),
            "audit_last_7_days": per_day,
            "top_actions": top_actions,
        }

    @app.post("/api/system/backup/create")
    def create_system_backup(request: Request) -> dict:
        actor = ctx.require_role(request, "admin")
        path = ctx.create_system_backup_archive()
        stat = path.stat()
        ctx.log_audit(actor["username"], actor["role"], "system_backup_create", None, path.name)
        return {
            "ok": True,
            "name": path.name,
            "size_bytes": int(stat.st_size),
            "created_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
        }

    @app.get("/api/system/backup/list")
    def get_system_backups(request: Request) -> list[dict]:
        ctx.require_role(request, "admin")
        return ctx.list_system_backups()

    @app.get("/api/system/backup/{backup_name}/download")
    def download_system_backup(backup_name: str, request: Request) -> FileResponse:
        ctx.require_role(request, "admin")
        path = ctx.resolve_system_backup_path(backup_name)
        return FileResponse(str(path), media_type="application/gzip", filename=path.name)

    @app.post("/api/system/backup/{backup_name}/restore")
    def restore_system_backup(backup_name: str, request: Request) -> dict:
        actor = ctx.require_role(request, "admin")
        out = ctx.restore_system_backup_archive(backup_name)
        ctx.log_audit(actor["username"], actor["role"], "system_backup_restore", None, backup_name)
        return out