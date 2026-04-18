# AIVPN Admin v1

Standalone control plane for key issuing and client operations (`aivpn-admin`) plus invite-only Telegram issuing (`aivpn-telegram-bot`), without changing VPN dataplane internals.

## Features

- Single admin login (username + Argon2id password hash)
- Client CRUD: list, create, bulk create, enable/disable, delete
- Connection material: show `aivpn://...` key and QR per client
- Runtime status in client list:
  - `online: bool`
  - `last_seen_seconds: number | null`
- Invite management (`single-use`):
  - create invite (plaintext code shown once)
  - list invites
  - revoke invite
- Telegram bot issuing flow:
  - `/start` + invite code redeem
  - idempotent per Telegram user (`tg_<telegram_user_id>`)
  - returns existing key on repeated `/start`/`/key`
- Security controls:
  - CSRF protection on mutations
  - rate limits for login and mutation APIs
  - audit log (`/etc/aivpn/admin-audit.log`)

## Runtime Refresh Model

- `aivpn-server` periodically flushes client stats to `clients.json`.
  - Env: `AIVPN_STATS_FLUSH_INTERVAL_SECS` (default `10`, range `1..=3600`)
- `aivpn-admin` reloads `clients.json` every `3s`.
- Dashboard uses short polling every `5s` for `/api/clients` and `/api/invites`.

## Data Files (`AIVPN_CONFIG_DIR`, default `/etc/aivpn`)

- `clients.json`
- `server.key`
- `invites.json`
- `tg_users.json`
- `admin-audit.log`

## ENV

### Admin (`aivpn-admin`)

Required:

- `AIVPN_CONFIG_DIR` (default: `/etc/aivpn`)
- `AIVPN_SERVER_ADDR`
- `AIVPN_ADMIN_USER`
- `AIVPN_ADMIN_PASSWORD_HASH`
- `AIVPN_SESSION_SECRET` (>= 32 bytes)

Optional:

- `AIVPN_ADMIN_BIND` (default: `127.0.0.1:8081`)
- `AIVPN_COOKIE_SECURE` (default: `true`)
- `AIVPN_LOGIN_RATE_LIMIT_PER_MINUTE` (default: `20`)
- `AIVPN_MUTATION_RATE_LIMIT_PER_MINUTE` (default: `120`)

### Telegram Bot (`aivpn-telegram-bot`)

Required:

- `AIVPN_TG_BOT_TOKEN`
- `AIVPN_CONFIG_DIR` (same as admin/server)
- `AIVPN_SERVER_ADDR`

Optional:

- `AIVPN_TG_REDEEM_RATE_PER_MINUTE` (default: `6`)

Use `config/admin.env.example` as template.

## API

### Auth

- `POST /api/login`
- `POST /api/logout`

### Clients

- `GET /api/clients`
- `POST /api/clients`
- `POST /api/clients/bulk`
- `GET /api/clients/{id}`
- `POST /api/clients/{id}/enable`
- `POST /api/clients/{id}/disable`
- `DELETE /api/clients/{id}`
- `GET /api/clients/{id}/connection-key`
- `GET /api/clients/{id}/qr`

`GET /api/clients` includes runtime fields `online` and `last_seen_seconds`.

### Invites

- `GET /api/invites`
- `POST /api/invites`
- `POST /api/invites/{id}/revoke`

## Deploy (HTTPS admin + telegram bot)

1. Copy env template:

```bash
cp config/admin.env.example config/admin.env
```

2. Fill secrets, domain, bot token values.
   For `AIVPN_ADMIN_PASSWORD_HASH` in compose env file, escape `$` as `$$`.

3. Start admin backend + Caddy reverse proxy + telegram bot:

```bash
docker compose -f docker-compose.admin.yml up -d --build
```

4. Ensure `aivpn-server` has stats flush configured (optional override):

```bash
export AIVPN_STATS_FLUSH_INTERVAL_SECS=10
docker compose up -d aivpn-server
```

Proxy config: `deploy/admin/Caddyfile`.
