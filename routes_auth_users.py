import re
from contextlib import closing

from fastapi import HTTPException, Request
from fastapi.responses import FileResponse


def register_auth_user_routes(app, ctx) -> None:
    @app.get("/")
    def index() -> FileResponse:
        return FileResponse("static/index.html")

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True}

    @app.post("/api/auth/login")
    def auth_login(payload: ctx.LoginIn) -> dict:
        with closing(ctx.db_conn()) as conn:
            row = conn.execute(
                "SELECT id, username, role, password_hash FROM users WHERE username = ?",
                (payload.username.strip(),),
            ).fetchone()
        if not row or not ctx.verify_password(payload.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        token = ctx.make_token(row["username"], row["role"])
        return {"token": token, "user": {"id": row["id"], "username": row["username"], "role": row["role"]}}

    @app.get("/api/auth/me")
    def auth_me(request: Request) -> dict:
        user = ctx.require_role(request, "viewer")
        return {"id": user["id"], "username": user["username"], "role": user["role"]}

    @app.get("/api/users")
    def list_users(request: Request) -> list[dict]:
        ctx.require_role(request, "admin")
        with closing(ctx.db_conn()) as conn:
            rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY username").fetchall()
        return [dict(r) for r in rows]

    @app.post("/api/users")
    def create_user(request: Request, payload: ctx.UserIn) -> dict:
        actor = ctx.require_role(request, "admin")
        role = payload.role.strip().lower()
        if role not in ctx.ROLE_LEVEL:
            raise HTTPException(status_code=400, detail="Invalid role")
        username = payload.username.strip().lower()
        if not re.fullmatch(r"[a-z0-9._-]{3,80}", username):
            raise HTTPException(status_code=400, detail="Invalid username format")

        with closing(ctx.db_conn()) as conn:
            exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if exists:
                raise HTTPException(status_code=400, detail="User already exists")
            cur = conn.execute(
                "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                (username, ctx.hash_password(payload.password), role),
            )
            conn.commit()

        ctx.log_audit(actor["username"], actor["role"], "user_create", None, f"created={username}, role={role}")
        return {"id": cur.lastrowid, "username": username, "role": role}

    @app.delete("/api/users/{user_id}")
    def delete_user(request: Request, user_id: int) -> dict:
        actor = ctx.require_role(request, "admin")
        with closing(ctx.db_conn()) as conn:
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

        ctx.log_audit(actor["username"], actor["role"], "user_delete", None, f"deleted={row['username']}")
        return {"ok": True}

    @app.put("/api/users/{user_id}/password")
    def change_user_password(user_id: int, request: Request, payload: ctx.ChangePasswordIn) -> dict:
        actor = ctx.require_role(request, "viewer")
        if int(actor["id"]) != user_id and ctx.ROLE_LEVEL.get(actor["role"], 0) < ctx.ROLE_LEVEL["admin"]:
            raise HTTPException(status_code=403, detail="Cannot change another user's password")
        with closing(ctx.db_conn()) as conn:
            row = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (ctx.hash_password(payload.new_password), user_id),
            )
            conn.commit()
        ctx.log_audit(actor["username"], actor["role"], "user_password_change", None, f"target={row['username']}")
        return {"ok": True}