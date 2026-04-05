from fastapi import HTTPException, Request


def register_fleet_policy_routes(app, ctx) -> None:
    @app.get("/api/device-profiles")
    def list_profiles(request: Request) -> list[dict]:
        ctx.require_role(request, "viewer")
        return ctx.list_device_profiles()

    @app.put("/api/devices/{device_id}/profile")
    def set_device_profile(device_id: int, payload: ctx.DeviceProfileAssignIn, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        profile = ctx.assign_device_profile(device_id, payload.profile_key, actor)
        return {"ok": True, "device_id": int(device_id), "profile": profile}

    @app.post("/api/changes/preview")
    def change_preview(payload: ctx.ChangePreviewIn, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        return ctx.create_change_preview(actor, payload.command, payload.device_ids)

    @app.get("/api/changes/{preview_id}")
    def change_preview_get(preview_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        row = ctx.get_change_preview(preview_id)
        if row.get("created_by") != actor["username"] and ctx.ROLE_LEVEL.get(actor["role"], 0) < ctx.ROLE_LEVEL["admin"]:
            raise HTTPException(status_code=403, detail="Cannot access another user's preview")
        return row

    @app.post("/api/changes/{preview_id}/approve")
    def change_preview_approve(preview_id: int, payload: ctx.ChangeApproveIn, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        token = (payload.confirm_token or "").strip() or None
        return ctx.approve_change_preview(preview_id, actor, confirm_token=token)

    @app.post("/api/changes/{preview_id}/execute")
    def change_preview_execute(preview_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        return ctx.execute_change_preview(preview_id, actor)

    @app.get("/api/slo/devices")
    def fleet_slo(request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        items = ctx.list_fleet_slo(actor)
        healthy = sum(1 for x in items if x.get("slo_state") == "healthy")
        degraded = sum(1 for x in items if x.get("slo_state") == "degraded")
        offline = sum(1 for x in items if x.get("slo_state") == "offline")
        unknown = sum(1 for x in items if not x.get("slo_state"))
        return {
            "items": items,
            "summary": {
                "total": len(items),
                "healthy": int(healthy),
                "degraded": int(degraded),
                "offline": int(offline),
                "unknown": int(unknown),
            },
        }

    @app.get("/api/devices/{device_id}/slo")
    def device_slo(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "viewer")
        row = ctx.load_device(device_id, actor)
        snap = ctx.get_device_slo_snapshot(int(device_id))
        if not snap:
            return {
                "device_id": int(row["id"]),
                "name": row["name"],
                "profile_key": row["profile_key"] or "branch-small",
                "slo_state": "unknown",
            }
        return {
            "device_id": int(row["id"]),
            "name": row["name"],
            "profile_key": row["profile_key"] or "branch-small",
            **snap,
        }

    @app.post("/api/devices/{device_id}/slo/baseline/capture")
    def capture_baseline(device_id: int, request: Request) -> dict:
        actor = ctx.require_role(request, "operator")
        return {"ok": True, **ctx.capture_device_config_baseline(device_id, actor)}
