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

Then open <http://localhost:3000>. The `/styleguide` page has a "live env" smoke badge that pings `/health` from the running api, so you can see at a glance whether the wire is up.

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

## Environment

`.env.example` is the canonical contract. Copy it to `.env` for both quickstart paths above. Two routes for two contexts:

- **Native dev** reads `DATABASE_URL` and `REDIS_URL` from `.env` (literal `localhost` URLs).
- **Compose api service** overrides both in `docker-compose.yml`, pointing at the sibling `db` / `redis` service names. The `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` vars in `.env` are the single source of truth for the postgres credentials, substituted into both the `db` service and the api's reconstructed `DATABASE_URL`.
- **`CORS_ALLOWED_ORIGIN`** defaults to `http://localhost:3000` so the sibling wispr-web dev server can call this api without preflight failures. Production overrides to `https://wispr.rushyendra.dev`.

The split exists because `localhost` makes sense for a process running directly on the host, while a containerized api needs to reach sibling services by their compose service name. Keeping postgres credentials as discrete `POSTGRES_*` variables lets both paths share one source of truth.

## Layout

```
app/
├── main.py        FastAPI app factory + CORS wiring
├── config.py      Settings (pydantic-settings, env-driven)
├── db.py          SQLAlchemy 2.0 async base + engine
└── routes/        One router per concern
alembic/           Migrations (async template)
tests/             Pytest mirror of app/
Dockerfile         Dev image (python:3.12-slim + uv)
docker-compose.yml api + postgres:16 + redis:7
```
