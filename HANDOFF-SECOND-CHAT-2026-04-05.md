# Handoff for Second Chat (2026-04-05)

## Scope
This handoff captures all actions completed in this session after previous release work, including RouterOS compatibility updates, UI changes, rebuild/deploy checks, git commit, and stable tag/release-note recovery.

## Current High-Level State
- Code changes are committed on main.
- Latest commit:
  - f4d8878 feat(routeros): add version-aware compatibility and surface ROS in UI
- `origin/main` points to f4d8878.
- `stable` tag points to f4d8878 (annotated tag object differs, expected).
- Stable tag annotation was restored with full EN/UA long description.
- Runtime health checks are passing after rebuild (`/api/health -> {"ok":true}`).

## Chronological Actions Performed

1. Added RouterOS compatibility core in backend.
- File: app.py
- Added:
  - per-device profile cache (`DEVICE_PROFILE`) for version/feature command memory
  - DB migration columns in `devices`: `ros_version`, `ros_version_checked_at`
  - version detection helpers
  - feature-based command candidates and execution (`exec_feature_command`)

2. Rewired backend routes to feature-based execution.
- File: routes_devices.py
- Updates:
  - `GET /api/devices` now includes RouterOS metadata fields
  - `POST /api/devices/refresh-versions` (bulk)
  - `POST /api/devices/{id}/refresh-version` (single)
  - `status-overview` includes `ros_version`
  - test/identity, interfaces list, and router logs switched to feature execution
  - new `GET /api/devices/{id}/router-logs`

3. Rewired backup capture to compatibility logic.
- File: routes_terminal_backups.py
- `capture_backup` now uses `backup_export` feature execution and writes command used into audit details.

4. Switched dashboard router log loading to dedicated endpoint.
- File: static/js/pages/dashboard.js
- `loadRouterLogs()` now calls `/api/devices/{id}/router-logs` instead of raw terminal command.

5. Added RouterOS visibility in Devices page.
- File: static/js/pages/devices.js
- Added:
  - display of RouterOS version per device card
  - search includes `ros_version`
  - `Refresh Versions` button calling bulk refresh endpoint

6. Found and fixed false negative for router logs compatibility.
- Reported issue:
  - UI showed: Feature 'logs_read' is not supported...
  - while output contained real router log lines.
- Root cause:
  - overly broad compatibility error matching in output.
- Fix in app.py:
  - replaced broad checker with:
    - `_is_compat_error_detail(...)`
    - `_looks_like_command_error_output(...)` (first-line signature based)
  - for `logs_read`, non-empty output is treated as success.

7. Added RouterOS near uptime on Dashboard card.
- File: static/js/pages/dashboard.js
- Added `RouterOS` field in Device Status card metadata and live refresh update.

8. Added RouterOS to Terminal diagnostics.
- Files:
  - routes_devices.py
  - static/js/pages/tools.js
- API `ssh-diagnostics` now returns `ros_version` and `ros_version_checked_at`.
- Terminal diagnostics panel shows `RouterOS` field (`diagRos`).

9. Fixed frontend cache issue preventing visibility of latest JS changes.
- File: static/index.html
- Bumped static asset version query from `v=20260404a` to `v=20260405a` for:
  - app-core.js
  - dashboard.js
  - devices.js
  - tools.js
  - app-init.js

10. Rebuild/redeploy cycles executed multiple times after key changes.
- Commands repeatedly used:
  - `docker compose build mikrotik-console`
  - `docker compose up -d --force-recreate mikrotik-console`
  - `docker compose ps mikrotik-console`
  - `curl http://127.0.0.1:8080/api/health`
- Result each final cycle: service up and health OK.

11. Validation checks executed.
- Python syntax checks:
  - `python3 -m py_compile app.py routes_devices.py routes_terminal_backups.py routes_system.py routes_auth_users.py`
- IDE/Problems check:
  - no errors in touched files and workspace checks done in-session.

12. Added operational log document.
- File created: `HANDOFF-REBUILD-2026-04-05.md`
- Contains rebuild steps, root cause note for logs false negative, and validation summary.

13. Created commit.
- Commit:
  - `f4d8878` feat(routeros): add version-aware compatibility and surface ROS in UI
- Included files:
  - HANDOFF-REBUILD-2026-04-05.md
  - app.py
  - routes_devices.py
  - routes_terminal_backups.py
  - static/index.html
  - static/js/pages/dashboard.js
  - static/js/pages/devices.js
  - static/js/pages/tools.js

14. Stable release/tag maintenance.
- Problem introduced during tag rewrite:
  - stable annotation became short (long EN/UA description disappeared in GitHub UI).
- Cause:
  - `stable` tag was force-updated with short message initially.
- Fix applied:
  - rewrote annotated `stable` tag with full EN/UA long release text and force-pushed.
- Current remote pointers:
  - `refs/tags/stable` -> annotated tag object
  - `refs/tags/stable^{}` -> `f4d8878` target commit

## Important Technical Notes for Next Chat

1. Router logs compatibility logic intentionally allows non-empty output for `logs_read`.
- Do not revert this to broad keyword matching; it causes false errors on valid logs.

2. Frontend cache-busting is required for JS visibility after release.
- If users report missing UI changes, verify script `?v=` in `static/index.html` first.

3. Terminal RouterOS display depends on diagnostics endpoint payload.
- Keep `ros_version` in `/api/devices/{id}/ssh-diagnostics` response.

4. Tag annotation and release notes are separate from commit content.
- Re-tagging can overwrite visible long description in GitHub release/tag page.

## What Is Done vs Pending

Done:
- RouterOS version-aware compatibility core.
- RouterOS visibility in Devices, Dashboard, Terminal diagnostics.
- router-logs endpoint and dashboard usage.
- False negative fix for logs compatibility.
- Cache busting update.
- Rebuild + health verification.
- Commit created and pushed (`f4d8878`).
- Stable tag points to latest commit.
- Stable long EN/UA annotation restored.

Potential follow-ups:
1. Manual UI smoke on real devices:
   - Dashboard card shows RouterOS
   - Terminal diagnostics shows RouterOS
   - Devices `Refresh Versions` fills unknown values
2. Optional: update README/CHANGELOG to explicitly mention Terminal RouterOS diagnostics field (if desired for public docs parity).
3. Optional: verify GitHub release page rendering after CDN delay; if still wrong, edit release body manually in UI.

## Quick Command Reference for Next Chat
- Check runtime:
  - `cd /home/user/Docker/traefik && docker compose ps mikrotik-console`
  - `curl -sS http://127.0.0.1:8080/api/health`
- Rebuild deploy:
  - `cd /home/user/Docker/traefik && docker compose build mikrotik-console && docker compose up -d --force-recreate mikrotik-console`
- Verify stable pointers:
  - `cd /home/user/Docker/traefik/mikrotik-console && git ls-remote --tags origin | cat`
- See latest commit:
  - `git log -1 --oneline`

## Suggested Prompt for Second Chat
Continue from commit `f4d8878` and run focused live smoke tests against 2-3 real MikroTik devices (mixed RouterOS versions) for these flows: `router-logs`, `interfaces`, `backup capture`, `terminal diagnostics`, and `dashboard status cards`. If all pass, update public CHANGELOG/release text only if anything visible changed beyond what stable already states.

## Session Delta (Performance + Stability Hardening)

This section captures follow-up changes made after the original handoff body above.

1. Root cause investigation for lag/freezes under many routers.
- Symptoms from user:
  - connect flow hangs for long time
  - reconnect behavior is poor
  - routers can become overloaded/frozen during mass connect attempts
- Findings:
  - expensive repeated version-probing in some flows
  - periodic dashboard polling used heavy endpoint behavior too often
  - command bursts occurred during connect/disconnect loops

2. Fail-fast transport handling and lighter polling behavior.
- app.py:
  - transport/auth/network errors in RouterOS version detection now fail fast (no wasteful fallback loops on unreachable devices)
- routes_devices.py:
  - added lightweight mode for `status-overview` via query `?lite=1` to skip expensive uptime SSH calls during frequent poll cycles
- static/js/pages/dashboard.js:
  - polling switched to lightweight status refresh where possible
  - removed heavy auto-calls after connect/disconnect

3. Global SSH concurrency limiter implemented.
- app.py:
  - new global runtime limit for simultaneous SSH operations across all devices
  - defaults from env: `MIM_GLOBAL_SSH_LIMIT` (default 4)
  - runtime counters: active/waiting
  - integrated limiter inside queued execution path
  - added persistent settings table `app_settings`
  - settings load on startup (`load_runtime_settings`)

4. New API endpoints for concurrency control.
- routes_devices.py:
  - `GET /api/devices/ssh-concurrency` -> returns `{limit, active, waiting}`
  - `PUT /api/devices/ssh-concurrency` (admin only) -> updates global limit + persists setting

5. Devices UI control panel added.
- static/js/pages/devices.js:
  - new "SSH Concurrency" card in Devices page
  - shows current limit and runtime active/waiting
  - Refresh button for all roles with access
  - Apply button for admin only

6. Frontend cache-busting incremented to force latest JS.
- static/index.html:
  - script query version bumped to `v=20260405b`

7. Runtime verification performed.
- container rebuilt/recreated successfully
- `/api/health` returned `{"ok":true}`
- authenticated API smoke checks passed:
  - GET `/api/devices/ssh-concurrency`
  - PUT `/api/devices/ssh-concurrency` with `{"limit":4}`

8. Git state before final commit/tag action.
- changed/staged set includes:
  - HANDOFF-SECOND-CHAT-2026-04-05.md
  - app.py
  - routes_devices.py
  - static/index.html
  - static/js/pages/dashboard.js
  - static/js/pages/devices.js

9. Versioning intent requested by user.
- User requested naming/version marker as `latest` (not `stable`).
- Finalization step should include:
  - commit all above changes
  - create/update annotated tag `latest` to current commit
  - keep `stable` untouched unless explicitly requested.

## Session Delta 2 (Final Additions)

1. Version memory + forced refresh improvements.
- app.py:
  - added helpers to persist/reuse RouterOS version in-memory profile and DB bridge:
    - `get_device_ros_version(...)`
    - `remember_device_profile_version(...)`
    - `reset_device_profile(...)`
  - `exec_feature_command(...)` now reuses DB version when profile cache is missing.
  - profile cache is cleared during runtime cleanup of removed/updated devices.
- routes_devices.py:
  - `POST /api/devices/refresh-versions?force=1`
  - `POST /api/devices/{id}/refresh-version?force=1`
  - force mode resets cached profile before re-detecting version.
- static/js/pages/devices.js:
  - Refresh Versions now calls forced refresh endpoint.

2. RouterOS API connectivity support added (in addition to SSH).
- requirements.txt:
  - added dependency: `routeros-api==0.21.0`
- app.py:
  - added `test_routeros_api(...)` helper (plain/TLS options, timeout, identity read)
- routes_devices.py:
  - added endpoint: `POST /api/devices/{id}/test-api?api_port=...&api_ssl=...`
- static/js/pages/dashboard.js:
  - added `Connect API` button and flow (prompt port + TLS, then API test)

3. Uptime/RouterOS disappearing issue fixed in Dashboard.
- Problem:
  - lite polling sometimes returns no uptime; UI replaced uptime with `-`.
- Fix:
  - added `_lastStatusCache` in dashboard page state.
  - merged incoming status with cached values so `uptime`/`ros_version` persist when absent in lightweight refresh.
  - UI now keeps last known values when user does nothing.

4. Frontend cache-busting increments during final sequence.
- static/index.html script version values were bumped incrementally to force fresh JS fetches:
  - `20260405b` -> `20260405c` -> `20260405d` -> `20260405e`

5. Runtime status in final phase.
- service recovered and confirmed healthy after intermittent terminal/session interruptions.
- `/api/health` returned `{"ok":true}`.

## Session Delta 3 (Uptime Immediate/Sticky Fix)

1. Reported user issue.
- `uptime` appeared briefly and then disappeared.
- Desired behavior: when user clicks/connects, uptime should appear immediately; when idle, keep last known value.

2. Root cause.
- Background refresh used lightweight status mode (`lite=1`) that may omit `uptime`.
- UI update path replaced absent values with `-` in some flows.

3. Backend fix.
- Added per-device status endpoint:
  - `GET /api/devices/{id}/status-overview?lite=0|1`
- This enables immediate full refresh for exactly one device after connect.
- File: routes_devices.py

4. Frontend fix.
- Dashboard now performs targeted full status refresh (`lite=0`) for selected device after successful connect (SSH/API).
- Background polling still uses lightweight mode for performance.
- Last-known cache is preserved so missing lightweight fields do not wipe visible values.
- File: static/js/pages/dashboard.js

5. Cache-busting.
- Incremented static script version to force browser update:
  - `v=20260405f`
- File: static/index.html

6. Validation.
- py_compile: OK
- service status: running
- health check: `/api/health` -> `{"ok":true}`

## Session Delta 4 (RouterOS Version Visibility Regression)

1. Reported issue.
- After recent fixes, RouterOS version stopped showing reliably in UI.

2. Root cause.
- Connect/test flows did not consistently persist/return version values in all paths.
- API test path returned identity but version was not always propagated to DB/profile cache.

3. Backend fixes.
- app.py:
  - `test_routeros_api(...)` now also reads `/system/resource` version when available and returns `ros_version`.
- routes_devices.py:
  - `/api/devices/{id}/test` now persists version from output or fallback detection into DB/profile cache.
  - `/api/devices/{id}/test-api` now persists API-returned version into DB/profile cache.

4. Frontend fix.
- dashboard connection status messages (SSH/API) now display ROS version immediately when returned.
- file: `static/js/pages/dashboard.js`

5. Cache-busting update.
- bumped static script version to `v=20260405g`.
- file: `static/index.html`

6. Validation.
- py_compile: OK
- editor error check for touched files: no errors
- health check remained OK during session (`/api/health` returned ok)
