# wispr-api

FastAPI (Python 3.12) backend for [Wispr](https://wispr.rushyendra.dev) — a web-only zero-knowledge clipboard.

**Frontend counterpart:** [`dog-broad/wispr-web`](https://github.com/dog-broad/wispr-web) (Next.js 15 + TS + Tailwind).

Private repo. Deploys via docker-compose behind a shared Caddy reverse proxy, exposed to the internet through a Cloudflare Tunnel (no inbound ports on the host).

## Quickstart — Docker Compose (preferred)

Requires Docker Desktop (or Docker Engine + the Compose v2 plugin).

```bash
cp .env.example .env
docker compose up -d --build
curl http://localhost:8000/health
```

The stack runs three containers:

| Service | Image | Host port | Container hostname |
|---|---|---|---|
| `api`   | built from `./Dockerfile` (`dev` target) | `8000` | `api`   |
| `db`    | `postgres:16` | `5432` | `db`    |
| `redis` | `redis:7`     | `6379` | `redis` |

The api container mounts the source tree at `/app` and runs `uvicorn --reload`, so host-side edits hot-reload inside the container.

Tear down with `docker compose down` (add `-v` to wipe the postgres/redis volumes).

### Run the whole stack locally

Two terminals — one for each repo. Web calls api via `http://localhost:8000` and CORS is preconfigured to allow `http://localhost:3000`:

```bash
# terminal 1 — this repo
docker compose up -d --build

# terminal 2 — sibling wispr-web repo
cd ../wispr-web && pnpm dev
```

Then open <http://localhost:3000>. Open the browser devtools network panel to confirm fetches against the api succeed.

## Quickstart — native uv (DB + Redis still in compose)

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env
docker compose up -d db redis     # bring up just the data services
uv sync --all-groups
uv run uvicorn app.main:app --reload
```

This path is useful when iterating on the FastAPI process directly with IDE debugging. The `.env` `DATABASE_URL`/`REDIS_URL` use `localhost` for this reason.

### Tests, lint, types

```bash
uv run pytest
uv run ruff check .
uv run ruff format .
uv run mypy app/ alembic/ tests/
```

## Production deploy

The API is self-hosted: each project lives in `~/<project>/` with its own docker-compose and joins a shared external `web` Docker network. A separate `~/infra/` compose runs the front door — **Caddy** + **cloudflared** — and TLS terminates at the **Cloudflare edge** via the tunnel, so nothing on the host binds a public port.

- Public services join the external `web` network; private services (postgres, redis) stay on the project's default network — never exposed.
- A `docker-compose.prod.yml` overlay layers production-only changes on the dev compose: the `prod` image (baked source, no dev deps), no host port bindings, `restart: unless-stopped`, and `env_file` to inject the deployment secrets into the api container.

Bring it up on the host:

```bash
# Once, on first deploy
cd ~ && git clone https://github.com/dog-broad/wispr-api.git
cd ~/wispr-api
cp .env.example .env
```

Fill in `.env` with the deployment secrets — a strong `POSTGRES_PASSWORD`, a `SERVER_PEPPER`, a base64 32-byte `KEY_VAULT_MASTER_V1`, and the Resend / Turnstile / R2 keys — plus the production URLs:

```dotenv
ENVIRONMENT=production
DATABASE_URL=postgresql+asyncpg://wispr:<password>@db:5432/wispr
CORS_ALLOWED_ORIGINS=https://wispr.rushyendra.dev
APP_BASE_URL=https://wispr.rushyendra.dev
SESSION_COOKIE_DOMAIN=.rushyendra.dev
SESSION_COOKIE_SECURE=true
```

Then build the stack and run migrations:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec api alembic upgrade head
```

Route it through the front door. In `~/infra/Caddyfile`, add a block matching the app's hostname and reverse-proxying to its service on the `web` network — TLS is handled upstream by Cloudflare, so serve plain HTTP:

```caddyfile
http://wispr-api.rushyendra.dev {
    reverse_proxy api:8000
}
```

Reload Caddy (`docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`), then add `wispr-api.rushyendra.dev` as a public hostname on the Cloudflare tunnel pointing at `http://caddy:80`. Because the origin is reachable only through the tunnel, `CF-Connecting-IP` arrives trusted — no header-stripping guard is needed.

## Environment

`.env.example` is the canonical contract. Copy it to `.env` for both quickstart paths above. Two routes for two contexts:

- **Native dev** reads `DATABASE_URL` and `REDIS_URL` from `.env` (literal `localhost` URLs).
- **Compose api service** overrides both in `docker-compose.yml`, pointing at the sibling `db` / `redis` service names. The `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` vars in `.env` are the single source of truth for the postgres credentials, substituted into both the `db` service and the api's reconstructed `DATABASE_URL`.
- **`CORS_ALLOWED_ORIGINS`** is a comma-separated list, defaulting to `http://localhost:3000` so the sibling wispr-web dev server can call this api without preflight failures. Production sets the canonical custom domain.
- **`CORS_ALLOWED_ORIGIN_REGEX`** is an optional regex matched against the request `Origin` in addition to the exact-match list. Production sets it to cover the platform-provided deployment URLs (alias + per-deployment + per-preview-branch variants all share a single shape). Local dev leaves it empty.

The split exists because `localhost` makes sense for a process running directly on the host, while a containerized api needs to reach sibling services by their compose service name. Keeping postgres credentials as discrete `POSTGRES_*` variables lets both paths share one source of truth.

## Layout

```
app/
├── main.py            FastAPI app factory + CORS + security headers + lifespan (purge + alert loops)
├── config.py          Settings (pydantic-settings, env-driven)
├── db.py              SQLAlchemy 2.0 async base + engine
├── redis_client.py    Redis async client, lifespan-managed
├── lib/               crypto + infra helpers: tokens, credentials, keyvault, keyrotation,
│                      storage (R2), email, turnstile, clientip, ratelimit, lockout, invites,
│                      reauth, audit, killswitch, dashboard, providers, backup, and the
│                      pair / sync / watch signaling buses
├── jobs/              Background loops: purge sweeper + red-state alert poll
├── middleware/        Security headers
├── models/            ORM models: snippets, accounts, reports, admin
├── routes/            One router per concern: health, snippets, snippet_watch, pair (+ pair_ws),
│                      auth, account, me, files, sync_ws, reports, admin (+ admin_ws)
└── schemas/           Pydantic request/response shapes
alembic/               Async migrations
tests/                 pytest mirror of app/
Dockerfile             Multi-stage: dev (--reload + bind-mount) and prod (baked source, no dev deps)
docker-compose.yml     api + postgres:16 + redis:7 (dev defaults)
docker-compose.prod.yml  Overlay: prod image, shared `web` network, no host ports, restart, env_file
```
