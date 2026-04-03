# Mikrotik Console

English and Ukrainian documentation are provided below.

---

## English

Web console for MikroTik fleet operations with role-based access, SSH diagnostics, safe broadcast flow, backups, and audit logs.

### Features

- Device inventory and SSH connectivity test
- Interface list and enable/disable actions
- Interface edit menu (MTU, comment, rename)
- Terminal commands on one device
- Safe broadcast workflow (dry-run + confirm token)
- Backup capture, upload, download, restore, delete
- SSH status and diagnostics panel
- User roles: admin, operator, viewer
- Audit log for critical actions

### Tech Stack

- FastAPI
- SQLite
- Paramiko (SSH)
- Vanilla HTML/CSS/JS frontend
- Docker

### Run With Docker

Build and run service locally:

```bash
docker build -t mikrotik-console .
docker run --rm -p 8080:8080 \
  -e MIM_SECRET="change-me" \
  -v "$(pwd)/data:/app/data" \
  mikrotik-console
```

Open `http://localhost:8080`.

### Environment Variables

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

### Docker Compose Integration

This service is designed to run behind Traefik in your existing stack.

Typical compose service settings:

- Build context: `./mikrotik-console`
- Internal port: `8080`
- Host port (standalone access): `${MIM_PORT:-8080}:8080`
- Persistent volume: `./mikrotik-console/data:/data`
- Traefik router + TLS labels

### Run Without Traefik (Standalone Compose)

From your stack folder:

```bash
cd /home/user/Docker/traefik
docker compose up -d --build mikrotik-console
```

The service is also published directly to host port `8080` by default.

- Local URL: `http://<host-ip>:8080`
- Health check: `http://<host-ip>:8080/api/health`

Override host port:

```bash
MIM_PORT=18080 docker compose up -d --build mikrotik-console
```

### API Highlights

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/devices`
- `POST /api/devices/{id}/disconnect`
- `GET /api/devices/{id}/ssh-status`
- `GET /api/devices/{id}/ssh-diagnostics`
- `GET /api/devices/{id}/interfaces`
- `POST /api/devices/{id}/interfaces/{name}` (enable/disable)
- `POST /api/devices/{id}/interfaces/{name}/edit`
- `POST /api/devices/{id}/terminal`
- `POST /api/terminal/broadcast/preview`
- `POST /api/terminal/broadcast/execute`

### Security Notes

- Change default admin credentials immediately after first login.
- Keep `MIM_SECRET` private and strong.
- Restrict public access with firewall or VPN where possible.

### Development

Run app directly:

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8080
```

---

## Українська

Веб-консоль для керування флотом MikroTik з рольовим доступом, SSH-діагностикою, безпечним broadcast, бекапами та журналом дій.

### Можливості

- Список пристроїв і тест SSH-з'єднання
- Перегляд інтерфейсів і дії enable/disable
- Меню редагування інтерфейсів (MTU, comment, перейменування)
- Виконання команд на одному пристрої
- Безпечний broadcast (dry-run + token підтвердження)
- Створення, завантаження, вивантаження, відновлення та видалення бекапів
- Панель SSH статусу та діагностики
- Ролі користувачів: admin, operator, viewer
- Журнал критичних дій (audit)

### Технології

- FastAPI
- SQLite
- Paramiko (SSH)
- Vanilla HTML/CSS/JS frontend
- Docker

### Запуск через Docker

Збірка і запуск локально:

```bash
docker build -t mikrotik-console .
docker run --rm -p 8080:8080 \
  -e MIM_SECRET="change-me" \
  -v "$(pwd)/data:/app/data" \
  mikrotik-console
```

Відкрийте `http://localhost:8080`.

### Змінні середовища

Обов'язково:

- `MIM_SECRET` - секрет для авторизації/підпису

Додаткові параметри:

- `MIM_SSH_IDLE_TTL_SECONDS` (типово: 120)
- `MIM_SSH_KEEPALIVE_SECONDS` (типово: 20)
- `MIM_SSH_CONNECT_TIMEOUT` (типово: 10)
- `MIM_SSH_COMMAND_TIMEOUT` (типово: 25)
- `MIM_SSH_RETRY_ATTEMPTS` (типово: 2)
- `MIM_SSH_RETRY_BASE_MS` (типово: 220)
- `MIM_BROADCAST_CONFIRM_TTL_SECONDS` (типово: 120)

### Інтеграція в Docker Compose

Сервіс розрахований на роботу за Traefik у вашому існуючому стеку.

Типові параметри сервісу в compose:

- Build context: `./mikrotik-console`
- Внутрішній порт: `8080`
- Порт хоста (standalone доступ): `${MIM_PORT:-8080}:8080`
- Постійне сховище: `./mikrotik-console/data:/data`
- Traefik labels для роутингу і TLS

### Запуск без Traefik (Standalone Compose)

Із папки стеку:

```bash
cd /home/user/Docker/traefik
docker compose up -d --build mikrotik-console
```

Сервіс за замовчуванням доступний на порту `8080` хоста.

- URL: `http://<ip-сервера>:8080`
- Перевірка: `http://<ip-сервера>:8080/api/health`

Зміна порту хоста:

```bash
MIM_PORT=18080 docker compose up -d --build mikrotik-console
```

### Основні API

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/devices`
- `POST /api/devices/{id}/disconnect`
- `GET /api/devices/{id}/ssh-status`
- `GET /api/devices/{id}/ssh-diagnostics`
- `GET /api/devices/{id}/interfaces`
- `POST /api/devices/{id}/interfaces/{name}` (enable/disable)
- `POST /api/devices/{id}/interfaces/{name}/edit`
- `POST /api/devices/{id}/terminal`
- `POST /api/terminal/broadcast/preview`
- `POST /api/terminal/broadcast/execute`

### Безпека

- Після першого входу обов'язково змініть пароль admin.
- Тримайте `MIM_SECRET` приватним і складним.
- Обмежте публічний доступ через firewall або VPN.

### Розробка

Локальний запуск без Docker:

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8080
```
