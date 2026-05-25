# wispr-api

FastAPI (Python 3.12) backend for [Wispr](https://wispr.rushyendra.dev) — a web-only zero-knowledge clipboard.

**Frontend counterpart:** [`dog-broad/wispr-web`](https://github.com/dog-broad/wispr-web) (Next.js 15 + TS + Tailwind).

Private repo. Deploys to an Azure VM (later: Oracle Cloud Free Tier) via docker-compose behind a shared Caddy reverse proxy.

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

Production runs on a shared VM behind a single Caddy reverse proxy that fronts every project on the box. The setup follows the conventions documented in `~/proxy/HOSTING.md` on the VM:

- Each project lives in `~/<project>/` with its own docker-compose.
- Public-facing services join the external `web` Docker network.
- Private services (postgres, redis) stay on the project's default network — never exposed.
- A `docker-compose.prod.yml` overlay layers production-only changes on top of the dev compose.

Bring it up on the VM:

```bash
# Once, on first deploy
cd ~ && git clone https://github.com/dog-broad/wispr-api.git
cd ~/wispr-api
cp .env.example .env
# Generate a strong postgres password and rewrite the .env values:
NEW_PW=$(openssl rand -hex 24)
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$NEW_PW/" .env
sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+asyncpg://wispr:$NEW_PW@localhost:5432/wispr|" .env
sed -i 's|^CORS_ALLOWED_ORIGINS=.*|CORS_ALLOWED_ORIGINS=https://wispr.rushyendra.dev|' .env
sed -i 's|^CORS_ALLOWED_ORIGIN_REGEX=.*|CORS_ALLOWED_ORIGIN_REGEX=^https://wispr-web(\\?:-[a-z0-9-]+)\\?\\.vercel\\.app$|' .env

# Bring up the prod stack
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# Run schema migrations (idempotent — safe to re-run on redeploy)
docker compose exec api alembic upgrade head
```

Then add the Caddyfile entry for the api hostname:

```caddyfile
api.wispr.rushyendra.dev {
    encode gzip

    # Trust boundary: no Cloudflare in front of this host, so any
    # client-supplied CF-Connecting-IP is untrusted. Strip it, then
    # set it to the actual connecting peer so the FastAPI rate-limiter
    # buckets on the real client IP. Without these two lines an attacker
    # can rotate CF-Connecting-IP to bypass per-IP rate limits. When
    # Cloudflare is added later, swap for a trusted_proxies block that
    # re-trusts CF-Connecting-IP only from inside the CF IP range.
    request_header -CF-Connecting-IP
    request_header CF-Connecting-IP {http.request.remote.host}

    reverse_proxy wispr-api-api-1:8000
}
```

…in `~/proxy/Caddyfile`, then `docker exec proxy-caddy caddy reload --config /etc/caddy/Caddyfile` (graceful) or `sudo docker restart proxy-caddy` (heavier). Let's Encrypt provisions the cert on the first request.

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
├── main.py            FastAPI app factory + CORS + security headers + lifespan
├── config.py          Settings (pydantic-settings, env-driven)
├── db.py              SQLAlchemy 2.0 async base + engine
├── redis_client.py    Redis async client with lifespan-managed lifecycle
├── lib/               clientip, ratelimit, ids
├── jobs/              Background tasks (purge sweeper)
├── middleware/        Security headers middleware
├── models/            ORM models (snippets)
├── routes/            One router per concern (health, snippets)
└── schemas/           Pydantic request/response shapes
alembic/               Async migrations
tests/                 pytest mirror of app/
Dockerfile             Multi-stage: dev (with --reload + bind-mount) and prod (baked source, no dev deps)
docker-compose.yml     api + postgres:16 + redis:7 (dev defaults)
docker-compose.prod.yml  Overlay: joins shared `web` network, strips host ports, restart: unless-stopped
```
