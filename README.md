# Security Operations Command Portal

A role-based Flask operations portal for shift coverage, patrol visibility, incident triage, client updates, and handoff reporting.

This public portfolio version uses synthetic users and records. It is built from real security-operations constraints, but it is not presented as a deployed client system.

## Start here

The fastest way to evaluate the project is to run it locally, sign in as each role, and follow one incident from guard submission through dispatcher acknowledgement and client-visible reporting.

```bash
git clone https://github.com/Trenn1x/secure-ops-portal-anon.git
cd secure-ops-portal-anon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python app.py
```

Open `http://localhost:8000`.

Demo-only accounts:

| Role | Username | Password |
|---|---|---|
| Dispatcher | `dispatcher` | `ops123!` |
| Guard | `guard.alpha` | `ops123!` |
| Client | `client.portal` | `ops123!` |

## What this project demonstrates

| Capability | Evidence in the repository |
|---|---|
| Workflow design | Separate dispatcher, guard, and client paths with explicit visibility boundaries |
| Operational prioritization | Patrol-gap alerts, severity-based acknowledgement SLAs, and action queues |
| Data integration | Idempotent Connecteam-compatible CSV imports with validation and audit fields |
| Reporting | Client packages, dispatcher operations briefs, and shift-handoff ZIP exports |
| Persistence | SQLite for local use, Postgres support for durable deployment, and a migration helper |
| Delivery discipline | Docker, Fly.io, Render, Vercel, environment examples, and 10 checked-in integration tests |

## Core workflow

1. A dispatcher creates assignments or imports shifts from CSV.
2. A guard starts an assignment, records patrol check-ins, and submits incidents.
3. The portal flags stale patrol activity and overdue incident acknowledgements.
4. A dispatcher acknowledges, triages, and updates each incident.
5. A client sees only approved records and can download a site report package.
6. Dispatch exports an operations brief or shift-handoff package for the next operator.

## Architecture

```text
Browser roles
  |-- Dispatcher
  |-- Guard
  `-- Client
        |
        v
Flask application
  |-- session and role checks
  |-- assignment, patrol, incident, and update workflows
  |-- CSV import and ZIP/CSV report generation
  `-- operational alert and SLA logic
        |
        v
SQLite locally / Postgres in durable deployments
```

The application uses a Flask app factory, server-rendered templates, role-aware routes, and SQL persistence. `DATABASE_URL` selects Postgres; otherwise the app uses SQLite.

## Verification

```bash
pytest -q
```

The 10 integration tests in `tests/test_app.py` cover:

- role login and guard dashboard access
- incident submission
- shift-template download and CSV import
- idempotent external shift updates
- stale-patrol alert acknowledgement
- client report packages
- dispatcher operations briefs
- incident acknowledgement and SLA escalation
- shift-handoff packages

## Import behavior

The CSV importer recognizes common shift-export fields, including:

- site or location
- guard username or employee name
- shift start and end
- external shift and job IDs
- notes

When an external shift ID is supplied, re-importing updates the scheduled record instead of duplicating it. Active and completed assignments are protected from overwrite. Rejected rows are reported with a reason, while the raw source payload and source system remain available for audit.

## Export surfaces

- Client site package: summary, client updates, and client-visible incidents
- Dispatcher operations brief: action queue, patrol alerts, incident watchlist, SLA radar, and guard activity
- Shift handoff: coverage window, incident follow-ups, patrol follow-ups, and internal updates
- Connecteam-compatible shift template

## Production configuration

```bash
export APP_SECRET="replace-with-a-strong-secret"
export DATABASE_URL="postgresql://user:password@host:5432/ops_portal"
export PORT=8000
export CHECKIN_ALERT_MINUTES=60
export OPERATIONS_BRIEF_LOOKBACK_HOURS=24
export SHIFT_HANDOFF_LOOKAHEAD_HOURS=12
gunicorn --bind 0.0.0.0:${PORT} app:app
```

To migrate an existing SQLite database:

```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path ./data/ops_portal.db \
  --postgres-url "postgresql://user:password@host:5432/ops_portal"
```

Use `--dry-run` before a real migration.

## Deployment files

- `Dockerfile`
- `fly.toml`
- `render.yaml`
- `vercel.json`
- `.env.example`

For durable production data, use managed Postgres. A Vercel `/tmp` SQLite database is suitable only for a disposable demo.

## Scope and security notes

- The included credentials are demo credentials and must be replaced before deployment.
- This repository contains synthetic portfolio data, not operational client records.
- A real deployment still requires a security review, stronger identity controls, secrets management, backup and retention policy, monitoring, and organization-specific authorization rules.

