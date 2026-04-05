# Mikrotik Console Refactor Plan

Goal: reduce coupling in `app.py` and remove the implicit `SimpleNamespace(**globals())` route context without breaking API behavior, DB schema, or frontend flows.

## Current Issues

- `app.py` mixes config, schema migration, auth, SSH runtime, RouterOS compatibility logic, backup logic, and app wiring.
- Route modules depend on a broad dynamic context object, so imports are implicit and fragile during refactors.
- Shared state is module-global (`SSH_POOL`, `DEVICE_QUEUES`, `SSH_DIAG`, `DEVICE_PROFILE`), which makes ownership and future testing harder.
- Config is read directly from environment across the startup path instead of being grouped in one typed settings layer.

## Refactor Principles

- Keep API paths, payloads, and auth semantics stable.
- Preserve SQLite file format and migration behavior.
- Move code by responsibility first, not by framework abstraction.
- Replace implicit globals with explicit dependencies in small steps.

## Target Layout

- `app.py`: app factory and route registration only.
- `settings.py`: environment parsing and validated runtime settings.
- `db.py`: connection factory, migrations, and low-level helpers.
- `auth.py`: password hashing, token signing/parsing, current-user resolution.
- `services/ssh_runtime.py`: pools, queues, diagnostics, concurrency limiter.
- `services/routeros.py`: version detection, feature command resolution, command execution wrappers.
- `services/backups.py`: per-device backup persistence and system backup/restore.
- `services/devices.py`: ownership-aware device loading and device-related orchestration.
- `routes/*.py`: thin HTTP adapters receiving explicit service objects.

## Recommended Migration Phases

### Phase 1: Introduce Typed Dependencies

- Create `Settings` and `AppServices` containers.
- Move env parsing and derived values into `Settings`.
- Build one explicit dependency object during startup and pass that to route registration.
- Keep existing function names as wrappers so route behavior stays unchanged.

### Phase 2: Extract Infrastructure Modules

- Move DB helpers and migrations from `app.py` into `db.py`.
- Move auth/token/password helpers into `auth.py`.
- Move SSH pool and queue management into `services/ssh_runtime.py`.
- Leave route handlers unchanged except for updated imports/context access.

### Phase 3: Extract Domain Services

- Move RouterOS feature detection and compatibility logic into `services/routeros.py`.
- Move backup file and system archive logic into `services/backups.py`.
- Move device lookup, ownership checks, and cleanup orchestration into `services/devices.py`.

### Phase 4: Replace Dynamic Route Context

- Replace `ctx.some_function` usage with explicit service fields, for example `services.auth.require_role` or `services.devices.load_device`.
- Narrow each route module dependency surface to only what it actually uses.
- Add one small integration test per route module before deleting legacy compatibility wrappers.

### Phase 5: App Factory and Tests

- Introduce `create_app(settings: Settings | None = None) -> FastAPI`.
- Register startup/shutdown using the service container rather than module globals.
- Add smoke tests for login, device CRUD, terminal, backup capture/upload, and system backup flows.

## Safe First Step

The least risky first refactor is:

1. Add `settings.py` and `services.py` containers.
2. Move config/env parsing there.
3. Change route registration to receive `services` instead of `SimpleNamespace(**globals())`.
4. Keep old helper functions in `app.py` temporarily delegating to the new modules.

This step gives immediate structure without changing API responses or frontend code.

## What Not To Change During Refactor

- Do not change API URLs.
- Do not change token format until a dedicated auth migration is planned.
- Do not replace SQLite or Paramiko in the same refactor.
- Do not combine UI refactors with backend extraction.

## Validation Checklist

- Login and token reuse still work.
- Admin/operator/viewer permissions remain unchanged.
- Device ownership filters still apply on all sub-routes.
- SSH pool reuse, disconnect, diagnostics, and concurrency controls still behave the same.
- Backup files and system restore keep the same on-disk paths.
- Existing Docker and Traefik compose files still start without extra mandatory variables.