# Rebuild and Smoke Log (2026-04-05)

## Goal
Rebuild and restart mikrotik-console container from current source, verify runtime, and prepare changes for commit.

## Actions Performed
1. Verified Docker Compose service name and build source in ../docker-compose.yml:
   - service: mikrotik-console
   - build context: ./mikrotik-console
2. Rebuilt image:
   - docker compose build mikrotik-console
3. Recreated container with updated image:
   - docker compose up -d --force-recreate mikrotik-console
4. Verified container status and image freshness:
   - docker compose ps mikrotik-console
   - Result: Up, mapped 0.0.0.0:8080->8080
   - Image: traefik-mikrotik-console:latest created a few seconds before check
5. Ran runtime health check:
   - curl http://127.0.0.1:8080/api/health
   - Result: {"ok":true}
6. Checked runtime logs:
   - docker compose logs --tail 40 mikrotik-console
   - Result: Uvicorn startup complete; health request returned 200 OK

## Commit Preparation Snapshot
Modified files:
- app.py
- routes_devices.py
- routes_terminal_backups.py
- static/js/pages/dashboard.js
- static/js/pages/devices.js

Suggested commit title:
feat(compat): add RouterOS version-aware command fallback and version UI in devices

Suggested commit body:
- add RouterOS detection and per-feature command fallback cache
- store ros_version and ros_version_checked_at in devices
- add refresh version endpoints (single and bulk)
- switch backups/interfaces/logs/test flows to feature-based command execution
- show RouterOS version in Devices UI and add Refresh Versions action
- route dashboard logs to dedicated router-logs endpoint

## Follow-up Fix (router logs false negative)

### Reported issue
- UI error: Feature 'logs_read' is not supported ... while device actually returned valid logs text.
- Symptom: logs were partially visible in error text, and full logs were not shown in panel.

### Root cause
- Compatibility detection treated any output containing generic error-like fragments as incompatibility.
- For logs, this is unsafe because log lines can contain words like failure/syntax in normal operational messages.

### Fix applied
1. Refined compatibility checks in app.py:
   - replaced broad text check with:
     - _is_compat_error_detail(text): for exception details
     - _looks_like_command_error_output(text): only when first non-empty line matches command-error patterns
2. Added feature-specific handling for logs_read:
   - any non-empty output is accepted as success
   - prevents false fallback loops and wrong "not supported" errors

### Validation
- py_compile passed for updated backend modules
- docker compose build/up completed for mikrotik-console
- health check: GET /api/health -> {"ok": true}
