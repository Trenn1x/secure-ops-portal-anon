# Secure Ops Portal

A production-ready MVP for Operations Provider to monitor guards in real time, manage incidents, and publish client-facing updates.

## Why this is valuable

- Gives dispatch one operational view for shift status, incidents, and updates.
- Gives guards a fast check-in/check-out and incident workflow.
- Gives clients transparent updates without exposing internal chatter.
- Supports Connecteam operations through CSV shift import.

## Core workflows

1. Dispatcher logs in and creates/adjusts assignments.
2. Guard logs patrol check-ins and submits incidents from assignment context.
3. Dispatcher triages incidents, updates status, and sends client messages.
4. Dispatcher monitors a patrol alert board for active shifts with stale/no recent check-ins.
5. Client logs in to view approved incident visibility and status updates.
6. Dispatcher imports shift CSV exported from Connecteam.
7. Client downloads a report package (`.zip`) containing summary + CSV exports for incident/update records.
8. Dispatcher downloads an operations brief package (`.zip`) with priority action queue, patrol alerts, incident SLA radar, watchlist, and guard activity.

## Demo accounts

- Dispatcher: `dispatcher` / `ops123!`
- Guard: `guard.alpha` / `ops123!`
- Client: `client.portal` / `ops123!`

## Run locally

```bash
cd /Users/thomasverdier/projects/omega-guard-ops
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python app.py
```

Open `http://localhost:8000`.

## Production run (Gunicorn)

```bash
source .venv/bin/activate
export APP_SECRET="replace-with-strong-secret"
export DATABASE_PATH="/Users/thomasverdier/projects/omega-guard-ops/data/ops_portal.db"  # sqlite fallback
export PORT=8000
export CHECKIN_ALERT_MINUTES=60
export OPERATIONS_BRIEF_LOOKBACK_HOURS=24
gunicorn --bind 0.0.0.0:${PORT} app:app
```

## Postgres (durable production)

Set `DATABASE_URL` and the app auto-switches to Postgres:

```bash
export DATABASE_URL="postgresql://user:password@host:5432/ops_portal"
```

Notes:

- `DATABASE_URL` takes precedence over `DATABASE_PATH`.
- Schema auto-initializes on startup (`CREATE TABLE IF NOT EXISTS`).
- Existing SQLite data is not auto-migrated; export/import is needed for cutover.

### SQLite -> Postgres migration

Use the included migration helper:

```bash
cd /Users/thomasverdier/projects/omega-guard-ops
source .venv/bin/activate
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path ./data/ops_portal.db \
  --postgres-url "postgresql://user:password@host:5432/ops_portal"
```

Dry-run first:

```bash
python scripts/migrate_sqlite_to_postgres.py --dry-run
```

## Deploy options

### Fly.io

```bash
fly launch --no-deploy --name secure-ops-portal
fly volumes create ops_portal_data --region ewr --size 1
fly secrets set APP_SECRET="replace-with-strong-secret"
fly deploy
```

### Vercel (fastest path)

```bash
vercel --prod
```

Set runtime env vars in the Vercel project:

- `APP_SECRET` = strong random value
- `DATABASE_URL` = managed Postgres connection string (recommended)
- `DATABASE_PATH` = `/tmp/ops_portal.db` (demo-only fallback)

Note: `/tmp` is ephemeral on Vercel serverless; use `DATABASE_URL` for durable production data.

### Render

- Connect this repo and use `render.yaml`.
- Render provisions a persistent disk at `/data`.

## Notes on Connecteam import

Import accepts common column names and auto-maps these fields:

- Site: `site`, `site name`, `location`, `job site`
- Guard: `guard username`, `username`, `employee`, `employee name`
- Start/End: `shift start` + `shift end` (or common variants)

Rows with missing required values or unknown guards are skipped.

## API endpoint

- `GET /api/status` (dispatcher session required): JSON live snapshot for guard status.
- `GET /client/exports/site-package` (client session required): downloadable `.zip` with `summary.txt`, `client_updates.csv`, and `incident_visibility.csv`.
- `GET /dispatcher/exports/operations-brief` (dispatcher session required): downloadable `.zip` with `summary.txt`, `action_queue.csv`, `patrol_alerts.csv`, `incidents_watchlist.csv`, `incident_sla_radar.csv`, and `guard_activity.csv`.

## Alerting behavior

- Active assignments are flagged on the dispatcher dashboard when no check-in is logged within `CHECKIN_ALERT_MINUTES`.
- Dispatcher can acknowledge an alert; this writes an internal update entry prefixed with `[ALERT ACK]`.

## Test

```bash
source .venv/bin/activate
pytest
```
