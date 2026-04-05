# Next Bot Workflow (Mandatory)

This file defines required behavior for the next assistant session in this repository.

## 1) Action Logging (Always)
- After each meaningful operation, update a handoff log with:
  - what was changed
  - why it was changed
  - how it was validated
- Use clear chronological numbering.
- Include command-level evidence for deploy checks and health checks.

## 2) Commit Discipline (Always)
- Before commit:
  - run `git status --short`
  - verify only relevant files are staged
  - run syntax/quick checks when applicable
- Commit message rules:
  - one clear subject line
  - concise bullet body for key technical changes
- Never leave critical runtime changes uncommitted at end of task.

## 3) Runtime Safety Rules
- If service/container exits unexpectedly:
  - recover service first (`docker compose up -d ...`)
  - confirm health (`/api/health`) before continuing
- Prefer light polling and avoid command bursts against routers.
- Preserve user-facing state when possible (last-known values for dashboard fields).

## 4) Release/Tag Rules
- `stable` must not be changed unless user explicitly requests it.
- If user asks for `latest`, update only `latest` tag.
- Remember: tag annotation text and release body are separate on GitHub.

## 5) Final Response Checklist
Before finishing a user request, report:
- exact files changed
- validation performed and outcome
- git state (commit hash/tag if updated)
- any known residual risks

## 6) Minimal Commands Reference
- Status: `git status --short`
- Syntax (backend): `python3 -m py_compile app.py routes_devices.py routes_terminal_backups.py routes_system.py routes_auth_users.py`
- Rebuild/restart: `docker compose build mikrotik-console && docker compose up -d --force-recreate mikrotik-console`
- Health: `curl -sS http://127.0.0.1:8080/api/health`

## 7) Current Technical Priorities
- Keep RouterOS version cache stable and avoid unnecessary re-detection.
- Keep global SSH concurrency limit configurable and respected.
- Keep dashboard responsive under multi-device load.
- Prefer explicit user-triggered refresh for expensive operations.
