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
export APP_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
APP_DEMO_MODE=1 DATABASE_URL= python app.py
```

Open `http://localhost:8000`.

Demo mode runs on loopback and stores synthetic data in a separate local database.

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
| Delivery discipline | Docker, Fly.io, Render, Vercel, environment examples, and GitHub Actions checks |

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

The integration tests use temporary SQLite databases and cover:

- account provisioning, session expiry and revocation, password resets, and sign-in throttling
- role login, guard dashboard access, and offline check-in receipts
- incident submission
- shift-template download and CSV import
- idempotent external shift updates
- stale-patrol alert acknowledgement
- client report packages
- dispatcher operations briefs
- incident acknowledgement and SLA escalation
- shift-handoff packages

GitHub Actions runs the suite, checks JavaScript syntax, and builds and starts the Docker image on pull requests and pushes to `main`.

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

## Offline guard check-ins

On HTTPS or localhost, sign in as a guard to load your assignments. The check-in form saves entries in this browser before attempting to sync. On a trusted device, use **Enable or refresh offline access** to save the current assignments and bookmark **Open or bookmark offline check-ins**. Refresh the saved list after assignments change.

When connectivity returns, open either check-in page in the same browser and sign in with the same guard account if prompted. Pending entries survive page reloads and clear after server acknowledgement. Keep the browser's site data until entries have synced. Removing offline access clears the saved assignment list and retains pending entries.

The dispatcher’s **Check-In Receipts** table updates every five seconds while the page is visible. It shows the latest 30 entries by receipt time, with device capture and server sync times in UTC. Receipts that arrive at least five minutes after capture are marked **Synced late**. Set `CHECKIN_LATE_SYNC_MINUTES` to change the threshold. Use **Late check-ins only** to filter the current list and **Acknowledge** to record who reviewed a late receipt and when. The live **Late Check-In Review Queue** counts all unacknowledged late receipts and shows the oldest 30 awaiting review, regardless of the recent receipts window. Entries that are still on the guard's device become visible only after the server receives them.

## Production configuration

```bash
# Set APP_SECRET to a persistent, randomly generated secret via your secret store.
export DATABASE_URL="postgresql://user:password@host:5432/ops_portal"
export PORT=8000
export CHECKIN_ALERT_MINUTES=60
export OPERATIONS_BRIEF_LOOKBACK_HOURS=24
export SHIFT_HANDOFF_LOOKAHEAD_HOURS=12
gunicorn --bind 0.0.0.0:${PORT} app:app
```

Serve the portal over HTTPS. Gunicorn can listen over HTTP behind a TLS-terminating reverse proxy. Production session cookies use Secure, HttpOnly, and SameSite=Lax. The direct loopback launcher supports local HTTP.

Sessions expire on the server 12 hours after sign-in by default. Set `APP_SESSION_HOURS` to a whole number from 1 to 24 for new sessions. Signing out revokes that session on the server. When upgrading from older versions, users must sign in again. Queued offline check-ins stay on the device and sync once the same guard signs in.

Sign-in allows ten failed attempts per username in a five-minute window shared across workers. A correct sign-in releases its own attempt slot. An operator password reset clears the username limit, and existing sessions can continue during throttling. For direct deployments, `APP_LOGIN_SOURCE_LIMIT` can also cap attempts per address over five minutes. The default is `0` because reverse proxies and shared networks can group many users under one address. Configure source-based limits at a trusted reverse proxy when it identifies client addresses. The app ignores forwarded addresses.

### Provision production accounts and sites

From an operator shell configured with the production `APP_SECRET` and database connection, create real accounts and sites before first sign-in.

```bash
flask --app app provision-user --username dispatch.lead --role dispatcher --full-name "Dispatch Lead"
flask --app app provision-user --username guard.smith --role guard --full-name "Sam Smith"
flask --app app provision-user --username client.river --role client --full-name "River Site Representative"
flask --app app provision-site --name "River Site" --client client.river
```

Each user command prompts for a password without echoing it. Usernames are normalized to lowercase. Demo usernames are reserved. A site can be created without `--client` and linked later. Each client account is scoped to one site, and provisioning preserves existing links.

To offboard an account, run `flask --app app set-user-access guard.smith disabled`. This revokes every active session for the account and blocks future sign-ins. Dispatch cannot create new assignments for disabled guards through the shift builder or CSV import. Existing assignments, site links, and historical records are retained. To restore access, run the same command with `enabled`. The user must sign in again.

For a lost or compromised password, verify the account holder's identity and run `flask --app app reset-user-password guard.smith`. Enter and confirm a new password at the hidden prompt. The reset revokes every session for that account. Disabled accounts stay disabled until an operator restores access. Share the new credential through an approved secure channel.

During an upgrade, existing accounts with a built-in demo username and either the original role and display name or the shared demo password are marked as demo users. Production blocks their sign-ins and existing sessions. Review legacy demo accounts whose identifiers or profiles were customized. Historical records are retained.

Initialize the target with the current app version before migrating an existing SQLite database.

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

- Demo credentials work only in the opt-in loopback demo. Production accounts are provisioned separately.
- This repository contains synthetic portfolio data, not operational client records.
- A real deployment still requires a security review, stronger identity controls, secrets management, backup and retention policy, monitoring, and organization-specific authorization rules.
