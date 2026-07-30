# Public Route Manager

Simple web UI for Traefik **file-provider** routes on a Headscale VPS.

## What it does

- Lists public `Host(...)` HTTPS routes from `traefik-dynamic.yaml`
- Add / edit / delete: **hostname → backend URL**
- Auto Let’s Encrypt via your existing Traefik cert resolver
- Password-protected; backups on every write

## Deploy (this VPS)

```bash
cd /root/route-manager
export APP_PASSWORD='your-password'
export APP_SECRET=$(openssl rand -hex 32)
docker compose up -d --build
```

Open **https://routes.jail.sale** (DNS A → VPS).

## Example

| Field | Value |
| --- | --- |
| Hostname | `claw.jail.sale` |
| Backend | `http://100.64.0.12:18789` |

Point DNS for `claw.jail.sale` at the VPS IP, save the route, wait for LE cert.

## API

- `GET /api/routes`
- `POST /api/routes` JSON `{host, backend, hsts?, hsts_subdomains?}`
- `PUT /api/routes/{id}`
- `DELETE /api/routes/{id}`

Cookie session after `POST /login`.
