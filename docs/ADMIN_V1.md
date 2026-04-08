# AIVPN Admin v1

Standalone admin panel (`aivpn-admin`) for client management without modifying VPN dataplane.

## Features

- Single admin login (username + Argon2id password hash)
- Client list
- Create client
- Bulk create clients
- Enable / disable client
- Delete client
- Show connection key (`aivpn://...`)
- Show QR for connection key
- CSRF checks for mutating endpoints
- Rate limiting for login and mutating API
- Audit log (`/etc/aivpn/admin-audit.log`)

## Required ENV

- `AIVPN_CONFIG_DIR` (default: `/etc/aivpn`)
- `AIVPN_SERVER_ADDR`
- `AIVPN_ADMIN_USER`
- `AIVPN_ADMIN_PASSWORD_HASH`
- `AIVPN_SESSION_SECRET`

Optional:

- `AIVPN_ADMIN_BIND` (default: `127.0.0.1:8081`)
- `AIVPN_COOKIE_SECURE` (default: `true`)
- `AIVPN_LOGIN_RATE_LIMIT_PER_MINUTE` (default: `20`)
- `AIVPN_MUTATION_RATE_LIMIT_PER_MINUTE` (default: `120`)

Use `config/admin.env.example` as template.

## API

- `POST /api/login`
- `POST /api/logout`
- `GET /api/clients`
- `POST /api/clients`
- `POST /api/clients/bulk`
- `GET /api/clients/{id}`
- `POST /api/clients/{id}/enable`
- `POST /api/clients/{id}/disable`
- `DELETE /api/clients/{id}`
- `GET /api/clients/{id}/connection-key`
- `GET /api/clients/{id}/qr`

## Deploy with HTTPS

1. Copy env template:

```bash
cp config/admin.env.example config/admin.env
```

2. Fill secrets and domain values.
   For `AIVPN_ADMIN_PASSWORD_HASH` in compose env file, escape `$` as `$$`.

3. Start admin + proxy:

```bash
docker compose -f docker-compose.admin.yml up -d --build
```

Proxy config: `deploy/admin/Caddyfile`.
