# Mikrotik Console

Web console for MikroTik fleet operations with role-based access, SSH diagnostics, safe broadcast flow, backups, and audit logs.

## Features

- Device inventory and SSH connectivity test
- Interface list and enable/disable actions
- Terminal commands on one device
- Safe broadcast workflow (dry-run + confirm token)
- Backup capture, upload, download, restore, delete
- SSH status and diagnostics panel
- User roles: admin, operator, viewer
- Audit log for critical actions

## Tech Stack

- FastAPI
- SQLite
- Paramiko (SSH)
- Vanilla HTML/CSS/JS frontend
- Docker

## Run With Docker

Build and run service locally:

```bash
docker build -t mikrotik-console .
docker run --rm -p 8080:8080 \
  -e MIM_SECRET="change-me" \
  -v "$(pwd)/data:/app/data" \
  mikrotik-console
```

Then open http://localhost:8080

## Environment Variables

Required:

- `MIM_SECRET` - auth/signing secret

Optional tuning:

- `MIM_SSH_IDLE_TTL_SECONDS` (default: 120)
- `MIM_SSH_KEEPALIVE_SECONDS` (default: 20)
- `MIM_SSH_CONNECT_TIMEOUT` (default: 10)
- `MIM_SSH_COMMAND_TIMEOUT` (default: 25)
- `MIM_SSH_RETRY_ATTEMPTS` (default: 2)
- `MIM_SSH_RETRY_BASE_MS` (default: 220)
- `MIM_BROADCAST_CONFIRM_TTL_SECONDS` (default: 120)

## Docker Compose Integration

This service is designed to run behind Traefik in your existing stack.

Typical compose service settings:

- Build context: `./mikro-interface-manager`
- Internal port: `8080`
- Persistent volume: `./mikro-interface-manager/data:/app/data`
- Traefik router + TLS labels

## API Highlights

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/devices`
- `POST /api/devices/{id}/disconnect` (manual SSH disconnect)
- `GET /api/devices/{id}/ssh-status`
- `GET /api/devices/{id}/ssh-diagnostics`
- `POST /api/devices/{id}/terminal`
- `POST /api/terminal/broadcast/preview`
- `POST /api/terminal/broadcast/execute`

## Security Notes

- Change default admin credentials immediately after first login.
- Keep `MIM_SECRET` private and strong.
- Restrict public access with firewall or VPN where possible.

## Development

Run app directly:

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8080
```
