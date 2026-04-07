import csv
import io
import os
import re
import sqlite3
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

ALLOWED_ROLES = {"dispatcher", "guard", "client"}
ALLOWED_INCIDENT_STATUS = {"open", "in_review", "resolved", "closed"}
ALLOWED_INCIDENT_SEVERITY = {"low", "medium", "high", "critical"}
ALLOWED_CHECKIN_TYPES = {"IN", "PATROL", "OUT"}
DEFAULT_CHECKIN_ALERT_MINUTES = 60
DEFAULT_OPERATIONS_BRIEF_LOOKBACK_HOURS = 24


def to_utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_to_utc(value: str | None) -> datetime | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None

    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_timestamp(value: str | None) -> str | None:
    parsed = parse_iso_to_utc(value)
    if parsed is None:
        return value
    return to_utc_iso(parsed)


def minutes_since(timestamp: str | None, reference_utc: datetime) -> int | None:
    parsed = parse_iso_to_utc(timestamp)
    if parsed is None:
        return None
    delta_seconds = int((reference_utc - parsed).total_seconds())
    return max(0, delta_seconds // 60)


def utc_now_iso() -> str:
    return to_utc_iso(datetime.now(timezone.utc))


def normalize_header(value: str) -> str:
    return " ".join((value or "").strip().lower().replace("_", " ").split())


def pick_csv_value(row: dict[str, str], names: list[str]) -> str:
    if not row:
        return ""

    normalized = {normalize_header(k): (v or "").strip() for k, v in row.items()}
    for name in names:
        value = normalized.get(normalize_header(name), "")
        if value:
            return value
    return ""


def safe_filename_fragment(value: str, fallback: str = "site") -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return cleaned or fallback


def detect_db_backend(database_value: str) -> str:
    normalized = (database_value or "").strip().lower()
    if (
        normalized.startswith("postgres://")
        or normalized.startswith("postgresql://")
        or normalized.startswith("postgresql+")
    ):
        return "postgres"
    return "sqlite"


def adapt_query(query: str, backend: str) -> str:
    if backend == "postgres":
        return query.replace("?", "%s")
    return query


class DbConnection:
    def __init__(self, raw_conn, backend: str) -> None:
        self._raw = raw_conn
        self._backend = backend

    def execute(self, query: str, params: tuple = ()):
        return self._raw.execute(adapt_query(query, self._backend), params)

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def __enter__(self):
        self._raw.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._raw.__exit__(exc_type, exc, tb)

    def __getattr__(self, name):
        return getattr(self._raw, name)


def open_raw_connection(database_value: str, backend: str):
    if backend == "postgres":
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError(
                "Postgres backend selected but psycopg is not installed. "
                "Install dependencies from requirements.txt."
            ) from exc
        return psycopg.connect(database_value, row_factory=dict_row)

    conn = sqlite3.connect(database_value)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(database_value: str, backend: str) -> None:
    if backend == "sqlite":
        db_dir = os.path.dirname(database_value)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        with sqlite3.connect(database_value) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('dispatcher', 'guard', 'client')),
                    full_name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    client_user_id INTEGER,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(client_user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id INTEGER NOT NULL,
                    guard_user_id INTEGER NOT NULL,
                    shift_start TEXT NOT NULL,
                    shift_end TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'scheduled' CHECK(status IN ('scheduled', 'active', 'completed', 'missed')),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(site_id) REFERENCES sites(id),
                    FOREIGN KEY(guard_user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS checkins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assignment_id INTEGER NOT NULL,
                    guard_user_id INTEGER NOT NULL,
                    check_type TEXT NOT NULL CHECK(check_type IN ('IN', 'PATROL', 'OUT')),
                    note TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(assignment_id) REFERENCES assignments(id),
                    FOREIGN KEY(guard_user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id INTEGER NOT NULL,
                    assignment_id INTEGER,
                    guard_user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in_review', 'resolved', 'closed')),
                    client_visible INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(site_id) REFERENCES sites(id),
                    FOREIGN KEY(assignment_id) REFERENCES assignments(id),
                    FOREIGN KEY(guard_user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id INTEGER NOT NULL,
                    incident_id INTEGER,
                    author_user_id INTEGER NOT NULL,
                    audience TEXT NOT NULL CHECK(audience IN ('internal', 'client')),
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(site_id) REFERENCES sites(id),
                    FOREIGN KEY(incident_id) REFERENCES incidents(id),
                    FOREIGN KEY(author_user_id) REFERENCES users(id)
                );
                """
            )
        return

    with open_raw_connection(database_value, backend) as conn:
        db = DbConnection(conn, backend)
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('dispatcher', 'guard', 'client')),
                full_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sites (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                client_user_id BIGINT REFERENCES users(id),
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS assignments (
                id BIGSERIAL PRIMARY KEY,
                site_id BIGINT NOT NULL REFERENCES sites(id),
                guard_user_id BIGINT NOT NULL REFERENCES users(id),
                shift_start TEXT NOT NULL,
                shift_end TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'scheduled' CHECK(status IN ('scheduled', 'active', 'completed', 'missed')),
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS checkins (
                id BIGSERIAL PRIMARY KEY,
                assignment_id BIGINT NOT NULL REFERENCES assignments(id),
                guard_user_id BIGINT NOT NULL REFERENCES users(id),
                check_type TEXT NOT NULL CHECK(check_type IN ('IN', 'PATROL', 'OUT')),
                note TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id BIGSERIAL PRIMARY KEY,
                site_id BIGINT NOT NULL REFERENCES sites(id),
                assignment_id BIGINT REFERENCES assignments(id),
                guard_user_id BIGINT NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in_review', 'resolved', 'closed')),
                client_visible INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS updates (
                id BIGSERIAL PRIMARY KEY,
                site_id BIGINT NOT NULL REFERENCES sites(id),
                incident_id BIGINT REFERENCES incidents(id),
                author_user_id BIGINT NOT NULL REFERENCES users(id),
                audience TEXT NOT NULL CHECK(audience IN ('internal', 'client')),
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.commit()


def seed_data(database_value: str, backend: str) -> None:
    with open_raw_connection(database_value, backend) as conn:
        db = DbConnection(conn, backend)
        count = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if count > 0:
            return

        now = utc_now_iso()
        dispatcher_id = db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at)
            VALUES (?, ?, 'dispatcher', ?, ?)
            RETURNING id
            """,
            ("dispatcher", generate_password_hash("ops123!"), "Operations Desk", now),
        ).fetchone()["id"]

        guard_one_id = db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at)
            VALUES (?, ?, 'guard', ?, ?)
            RETURNING id
            """,
            ("guard.alpha", generate_password_hash("ops123!"), "Guard Alpha", now),
        ).fetchone()["id"]

        guard_two_id = db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at)
            VALUES (?, ?, 'guard', ?, ?)
            RETURNING id
            """,
            ("guard.bravo", generate_password_hash("ops123!"), "Guard Bravo", now),
        ).fetchone()["id"]

        client_id = db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at)
            VALUES (?, ?, 'client', ?, ?)
            RETURNING id
            """,
            ("client.portal", generate_password_hash("ops123!"), "Client Representative", now),
        ).fetchone()["id"]

        site_id = db.execute(
            """
            INSERT INTO sites (name, client_user_id, created_at)
            VALUES (?, ?, ?)
            RETURNING id
            """,
            ("Client Site A", client_id, now),
        ).fetchone()["id"]

        start = datetime.now(timezone.utc).replace(microsecond=0)
        end = start + timedelta(hours=8)
        assignment_one_id = db.execute(
            """
            INSERT INTO assignments (site_id, guard_user_id, shift_start, shift_end, status, created_at)
            VALUES (?, ?, ?, ?, 'scheduled', ?)
            RETURNING id
            """,
            (site_id, guard_one_id, to_utc_iso(start), to_utc_iso(end), now),
        ).fetchone()["id"]

        db.execute(
            """
            INSERT INTO assignments (site_id, guard_user_id, shift_start, shift_end, status, created_at)
            VALUES (?, ?, ?, ?, 'scheduled', ?)
            """,
            (
                site_id,
                guard_two_id,
                to_utc_iso(start + timedelta(hours=8)),
                to_utc_iso(end + timedelta(hours=8)),
                now,
            ),
        )

        incident_id = db.execute(
            """
            INSERT INTO incidents
                (site_id, assignment_id, guard_user_id, title, details, severity, status, client_visible, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'medium', 'in_review', 1, ?, ?)
            RETURNING id
            """,
            (
                site_id,
                assignment_one_id,
                guard_one_id,
                "Perimeter access hardware issue",
                "Guard noted intermittent latch behavior on an exterior access point. Temporary control applied.",
                now,
                now,
            ),
        ).fetchone()["id"]

        db.execute(
            """
            INSERT INTO updates (site_id, incident_id, author_user_id, audience, message, created_at)
            VALUES (?, ?, ?, 'client', ?, ?)
            """,
            (
                site_id,
                incident_id,
                dispatcher_id,
                "Security team identified an access hardware issue, applied temporary mitigation, and requested maintenance.",
                now,
            ),
        )
        db.commit()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    configured_database_url = (os.getenv("DATABASE_URL") or "").strip()
    if configured_database_url:
        default_db = configured_database_url
    elif os.getenv("DATABASE_PATH"):
        default_db = os.getenv("DATABASE_PATH", "")
    elif os.getenv("VERCEL"):
        default_db = "/tmp/ops_portal.db"
    else:
        default_db = os.path.join(app.root_path, "data", "ops_portal.db")
    default_backend = detect_db_backend(default_db)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("APP_SECRET", "ops-portal-dev-secret"),
        DATABASE=default_db,
        DB_BACKEND=default_backend,
        CHECKIN_ALERT_MINUTES=int(
            os.getenv("CHECKIN_ALERT_MINUTES", str(DEFAULT_CHECKIN_ALERT_MINUTES))
        ),
        OPERATIONS_BRIEF_LOOKBACK_HOURS=int(
            os.getenv(
                "OPERATIONS_BRIEF_LOOKBACK_HOURS",
                str(DEFAULT_OPERATIONS_BRIEF_LOOKBACK_HOURS),
            )
        ),
    )

    if test_config:
        app.config.update(test_config)

    app.config["DB_BACKEND"] = detect_db_backend(app.config["DATABASE"])

    init_db(app.config["DATABASE"], app.config["DB_BACKEND"])
    seed_data(app.config["DATABASE"], app.config["DB_BACKEND"])

    def get_conn() -> DbConnection:
        return DbConnection(
            open_raw_connection(app.config["DATABASE"], app.config["DB_BACKEND"]),
            app.config["DB_BACKEND"],
        )

    def fetch_one(query: str, params: tuple = ()):
        with get_conn() as conn:
            return conn.execute(query, params).fetchone()

    def fetch_all(query: str, params: tuple = ()):
        with get_conn() as conn:
            return conn.execute(query, params).fetchall()

    def execute(query: str, params: tuple = ()) -> int:
        with get_conn() as conn:
            cur = conn.execute(query, params)
            conn.commit()
            last_row_id = getattr(cur, "lastrowid", 0) or 0
            return int(last_row_id)

    def fetch_client_site(client_user_id: int):
        return fetch_one(
            """
            SELECT id, name
            FROM sites
            WHERE client_user_id = ?
            """,
            (client_user_id,),
        )

    def build_patrol_alerts(
        alert_threshold_minutes: int, now_utc: datetime | None = None
    ) -> list[dict]:
        active_guard_assignments = fetch_all(
            """
            SELECT a.id,
                   a.site_id,
                   a.shift_start,
                   a.status,
                   s.name AS site_name,
                   u.full_name AS guard_name,
                   last_check.check_type AS last_check_type,
                   last_check.created_at AS last_check_at
            FROM assignments a
            JOIN users u ON u.id = a.guard_user_id
            JOIN sites s ON s.id = a.site_id
            LEFT JOIN (
                SELECT c1.assignment_id, c1.check_type, c1.created_at
                FROM checkins c1
                INNER JOIN (
                    SELECT assignment_id, MAX(id) AS max_id
                    FROM checkins
                    GROUP BY assignment_id
                ) latest_check ON latest_check.max_id = c1.id
            ) AS last_check ON last_check.assignment_id = a.id
            WHERE a.status = 'active'
            ORDER BY a.shift_start ASC
            LIMIT 80
            """
        )

        reference_time = now_utc or datetime.now(timezone.utc)
        patrol_alerts: list[dict] = []
        for assignment in active_guard_assignments:
            last_check_minutes = minutes_since(assignment["last_check_at"], reference_time)
            shift_start_minutes = minutes_since(assignment["shift_start"], reference_time)

            if last_check_minutes is None:
                stale_minutes = shift_start_minutes if shift_start_minutes is not None else 0
                alert_reason = "No check-in logged on this active shift."
            else:
                stale_minutes = last_check_minutes
                alert_reason = f"No patrol update for {stale_minutes} minutes."

            patrol_alerts.append(
                {
                    "assignment_id": assignment["id"],
                    "site_id": assignment["site_id"],
                    "site_name": assignment["site_name"],
                    "guard_name": assignment["guard_name"],
                    "last_check_type": assignment["last_check_type"] or "none",
                    "last_check_at": assignment["last_check_at"] or "none",
                    "stale_minutes": stale_minutes,
                    "needs_follow_up": stale_minutes >= alert_threshold_minutes,
                    "alert_reason": alert_reason,
                }
            )

        patrol_alerts.sort(
            key=lambda item: (
                not item["needs_follow_up"],
                -item["stale_minutes"],
                item["guard_name"],
            )
        )
        return patrol_alerts

    def build_dispatcher_operations_brief() -> dict:
        lookback_hours = max(1, int(app.config["OPERATIONS_BRIEF_LOOKBACK_HOURS"]))
        alert_threshold_minutes = max(1, int(app.config["CHECKIN_ALERT_MINUTES"]))
        now_utc = datetime.now(timezone.utc).replace(microsecond=0)
        lookback_start_iso = to_utc_iso(now_utc - timedelta(hours=lookback_hours))

        patrol_alerts = build_patrol_alerts(alert_threshold_minutes, now_utc)
        open_patrol_alerts = [item for item in patrol_alerts if item["needs_follow_up"]]

        incidents_watchlist = fetch_all(
            """
            SELECT i.id,
                   i.title,
                   i.severity,
                   i.status,
                   i.client_visible,
                   i.created_at,
                   i.updated_at,
                   s.name AS site_name,
                   u.full_name AS guard_name
            FROM incidents i
            JOIN sites s ON s.id = i.site_id
            JOIN users u ON u.id = i.guard_user_id
            WHERE i.status IN ('open', 'in_review')
              AND i.severity IN ('high', 'critical')
            ORDER BY
                CASE i.severity WHEN 'critical' THEN 2 WHEN 'high' THEN 1 ELSE 0 END DESC,
                i.created_at ASC
            """
        )

        incidents_last_lookback = fetch_all(
            """
            SELECT id, severity
            FROM incidents
            WHERE created_at >= ?
            """,
            (lookback_start_iso,),
        )

        guard_activity = fetch_all(
            """
            SELECT u.id,
                   u.full_name,
                   u.username,
                   COALESCE(active_assignments.count_active, 0) AS active_assignments,
                   COALESCE(recent_incidents.count_recent_incidents, 0) AS incidents_recent,
                   COALESCE(last_check.check_type, 'none') AS last_check_type,
                   last_check.created_at AS last_check_at
            FROM users u
            LEFT JOIN (
                SELECT guard_user_id, COUNT(*) AS count_active
                FROM assignments
                WHERE status = 'active'
                GROUP BY guard_user_id
            ) AS active_assignments ON active_assignments.guard_user_id = u.id
            LEFT JOIN (
                SELECT guard_user_id, COUNT(*) AS count_recent_incidents
                FROM incidents
                WHERE created_at >= ?
                GROUP BY guard_user_id
            ) AS recent_incidents ON recent_incidents.guard_user_id = u.id
            LEFT JOIN (
                SELECT c1.guard_user_id, c1.check_type, c1.created_at
                FROM checkins c1
                INNER JOIN (
                    SELECT guard_user_id, MAX(id) AS max_id
                    FROM checkins
                    GROUP BY guard_user_id
                ) latest ON latest.max_id = c1.id
            ) AS last_check ON last_check.guard_user_id = u.id
            WHERE u.role = 'guard'
            ORDER BY u.full_name ASC
            """,
            (lookback_start_iso,),
        )

        open_incident_count = fetch_one(
            """
            SELECT COUNT(*) AS c
            FROM incidents
            WHERE status IN ('open', 'in_review')
            """
        )["c"]
        active_assignment_count = fetch_one(
            "SELECT COUNT(*) AS c FROM assignments WHERE status = 'active'"
        )["c"]
        checkins_recent_count = fetch_one(
            "SELECT COUNT(*) AS c FROM checkins WHERE created_at >= ?",
            (lookback_start_iso,),
        )["c"]
        client_updates_recent_count = fetch_one(
            """
            SELECT COUNT(*) AS c
            FROM updates
            WHERE audience = 'client' AND created_at >= ?
            """,
            (lookback_start_iso,),
        )["c"]

        incident_severity_counts: dict[str, int] = {"critical": 0, "high": 0, "other": 0}
        for row in incidents_last_lookback:
            severity = (row["severity"] or "").lower()
            if severity == "critical":
                incident_severity_counts["critical"] += 1
            elif severity == "high":
                incident_severity_counts["high"] += 1
            else:
                incident_severity_counts["other"] += 1

        action_queue: list[dict] = []
        for incident in incidents_watchlist:
            age_minutes = minutes_since(incident["created_at"], now_utc) or 0
            severity = (incident["severity"] or "").lower()
            priority_rank = 1 if severity == "critical" else 2
            priority = "P1" if priority_rank == 1 else "P2"
            action_queue.append(
                {
                    "priority_rank": priority_rank,
                    "priority": priority,
                    "category": "Incident",
                    "site_name": incident["site_name"],
                    "owner": incident["guard_name"],
                    "created_at": incident["created_at"],
                    "details": (
                        f"#{incident['id']} {incident['title']} "
                        f"({incident['severity']}/{incident['status']}) open for {age_minutes} min"
                    ),
                    "sort_minutes": age_minutes,
                }
            )

        for alert in open_patrol_alerts:
            priority_rank = 1 if alert["stale_minutes"] >= (alert_threshold_minutes * 2) else 2
            priority = "P1" if priority_rank == 1 else "P2"
            action_queue.append(
                {
                    "priority_rank": priority_rank,
                    "priority": priority,
                    "category": "Patrol gap",
                    "site_name": alert["site_name"],
                    "owner": alert["guard_name"],
                    "created_at": alert["last_check_at"]
                    if alert["last_check_at"] != "none"
                    else to_utc_iso(now_utc),
                    "details": (
                        f"{alert['alert_reason']} (assignment #{alert['assignment_id']})"
                    ),
                    "sort_minutes": alert["stale_minutes"],
                }
            )

        action_queue.sort(
            key=lambda item: (item["priority_rank"], -item["sort_minutes"], item["site_name"])
        )
        for item in action_queue:
            item.pop("sort_minutes", None)

        guard_activity_rows: list[dict] = []
        for row in guard_activity:
            last_check_age_minutes = minutes_since(row["last_check_at"], now_utc)
            guard_activity_rows.append(
                {
                    "guard_name": row["full_name"],
                    "username": row["username"],
                    "active_assignments": row["active_assignments"],
                    "incidents_recent": row["incidents_recent"],
                    "last_check_type": row["last_check_type"] or "none",
                    "last_check_at": row["last_check_at"] or "none",
                    "last_check_age_minutes": (
                        "" if last_check_age_minutes is None else last_check_age_minutes
                    ),
                }
            )

        return {
            "generated_at": to_utc_iso(now_utc),
            "lookback_hours": lookback_hours,
            "lookback_start": lookback_start_iso,
            "alert_threshold_minutes": alert_threshold_minutes,
            "summary": {
                "open_incidents": open_incident_count,
                "active_assignments": active_assignment_count,
                "patrol_alerts": len(open_patrol_alerts),
                "incidents_recent": len(incidents_last_lookback),
                "checkins_recent": checkins_recent_count,
                "client_updates_recent": client_updates_recent_count,
                "critical_incidents_recent": incident_severity_counts["critical"],
                "high_incidents_recent": incident_severity_counts["high"],
            },
            "action_queue": action_queue,
            "guard_activity": guard_activity_rows,
            "incidents_watchlist": [dict(row) for row in incidents_watchlist],
            "patrol_alerts": patrol_alerts,
            "open_patrol_alerts": open_patrol_alerts,
        }

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Please sign in first.", "warning")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    def roles_required(*roles):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if g.user is None:
                    flash("Please sign in first.", "warning")
                    return redirect(url_for("login"))
                if g.user["role"] not in roles:
                    flash("You do not have access to that area.", "error")
                    return redirect(url_for("dashboard"))
                return view(*args, **kwargs)

            return wrapped

        return decorator

    @app.before_request
    def load_logged_in_user() -> None:
        user_id = session.get("user_id")
        if user_id is None:
            g.user = None
            return
        g.user = fetch_one(
            "SELECT id, username, role, full_name FROM users WHERE id = ?",
            (user_id,),
        )
        if g.user is None:
            session.clear()

    @app.get("/health")
    def health() -> tuple[dict[str, str], int]:
        return {"status": "ok", "service": "secure-ops-portal"}, 200

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip().lower()
            password = request.form.get("password") or ""

            user = fetch_one(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            )
            if user is None or not check_password_hash(user["password_hash"], password):
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            session.clear()
            session["user_id"] = int(user["id"])
            flash("Signed in.", "success")
            return redirect(url_for("dashboard"))

        if g.user is not None:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard():
        assert g.user is not None

        if g.user["role"] == "dispatcher":
            guards = fetch_all(
                """
                SELECT u.id,
                       u.full_name,
                       u.username,
                       COALESCE(last_check.check_type, 'none') AS last_check_type,
                       last_check.created_at AS last_check_at,
                       COALESCE(site.name, 'No site') AS site_name,
                       COALESCE(last_assignment.status, 'unassigned') AS assignment_status
                FROM users u
                LEFT JOIN (
                    SELECT c1.guard_user_id, c1.check_type, c1.created_at
                    FROM checkins c1
                    INNER JOIN (
                        SELECT guard_user_id, MAX(id) AS max_id
                        FROM checkins
                        GROUP BY guard_user_id
                    ) latest ON latest.max_id = c1.id
                ) AS last_check ON last_check.guard_user_id = u.id
                LEFT JOIN (
                    SELECT a1.guard_user_id, a1.site_id, a1.status
                    FROM assignments a1
                    INNER JOIN (
                        SELECT guard_user_id, MAX(id) AS max_id
                        FROM assignments
                        GROUP BY guard_user_id
                    ) latest_assignment ON latest_assignment.max_id = a1.id
                ) AS last_assignment ON last_assignment.guard_user_id = u.id
                LEFT JOIN sites site ON site.id = last_assignment.site_id
                WHERE u.role = 'guard'
                ORDER BY u.full_name ASC
                """
            )

            incidents = fetch_all(
                """
                SELECT i.id,
                       i.title,
                       i.severity,
                       i.status,
                       i.client_visible,
                       i.created_at,
                       s.name AS site_name,
                       u.full_name AS guard_name
                FROM incidents i
                JOIN sites s ON s.id = i.site_id
                JOIN users u ON u.id = i.guard_user_id
                ORDER BY i.created_at DESC
                LIMIT 30
                """
            )

            assignments = fetch_all(
                """
                SELECT a.id,
                       a.shift_start,
                       a.shift_end,
                       a.status,
                       s.name AS site_name,
                       u.full_name AS guard_name
                FROM assignments a
                JOIN sites s ON s.id = a.site_id
                JOIN users u ON u.id = a.guard_user_id
                ORDER BY a.shift_start DESC
                LIMIT 30
                """
            )

            updates = fetch_all(
                """
                SELECT up.id,
                       up.audience,
                       up.message,
                       up.created_at,
                       s.name AS site_name,
                       au.full_name AS author_name
                FROM updates up
                JOIN sites s ON s.id = up.site_id
                JOIN users au ON au.id = up.author_user_id
                ORDER BY up.created_at DESC
                LIMIT 30
                """
            )

            sites = fetch_all(
                """
                SELECT s.id,
                       s.name,
                       COALESCE(c.full_name, 'Unassigned client') AS client_name
                FROM sites s
                LEFT JOIN users c ON c.id = s.client_user_id
                ORDER BY s.name ASC
                """
            )

            guards_lookup = fetch_all(
                """
                SELECT id, full_name, username
                FROM users
                WHERE role = 'guard'
                ORDER BY full_name ASC
                """
            )

            ops_brief = build_dispatcher_operations_brief()
            alert_threshold_minutes = ops_brief["alert_threshold_minutes"]
            patrol_alerts = ops_brief["patrol_alerts"]
            open_patrol_alerts = ops_brief["open_patrol_alerts"]

            return render_template(
                "dashboard_dispatcher.html",
                guards=guards,
                incidents=incidents,
                assignments=assignments,
                updates=updates,
                sites=sites,
                guards_lookup=guards_lookup,
                statuses=sorted(ALLOWED_INCIDENT_STATUS),
                patrol_alerts=patrol_alerts,
                open_patrol_alerts=open_patrol_alerts,
                alert_threshold_minutes=alert_threshold_minutes,
                ops_brief=ops_brief,
            )

        if g.user["role"] == "guard":
            assignments = fetch_all(
                """
                SELECT a.id,
                       a.site_id,
                       a.shift_start,
                       a.shift_end,
                       a.status,
                       s.name AS site_name
                FROM assignments a
                JOIN sites s ON s.id = a.site_id
                WHERE a.guard_user_id = ?
                ORDER BY a.shift_start DESC
                LIMIT 30
                """,
                (g.user["id"],),
            )

            open_assignments = [a for a in assignments if a["status"] in {"scheduled", "active"}]

            checkins = fetch_all(
                """
                SELECT c.id,
                       c.check_type,
                       c.note,
                       c.created_at,
                       s.name AS site_name
                FROM checkins c
                JOIN assignments a ON a.id = c.assignment_id
                JOIN sites s ON s.id = a.site_id
                WHERE c.guard_user_id = ?
                ORDER BY c.created_at DESC
                LIMIT 20
                """,
                (g.user["id"],),
            )

            incidents = fetch_all(
                """
                SELECT i.id,
                       i.title,
                       i.severity,
                       i.status,
                       i.client_visible,
                       i.created_at,
                       s.name AS site_name
                FROM incidents i
                JOIN sites s ON s.id = i.site_id
                WHERE i.guard_user_id = ?
                ORDER BY i.created_at DESC
                LIMIT 20
                """,
                (g.user["id"],),
            )

            return render_template(
                "dashboard_guard.html",
                assignments=assignments,
                open_assignments=open_assignments,
                checkins=checkins,
                incidents=incidents,
                checkin_types=sorted(ALLOWED_CHECKIN_TYPES),
                severities=sorted(ALLOWED_INCIDENT_SEVERITY),
            )

        if g.user["role"] == "client":
            site = fetch_client_site(g.user["id"])

            if site is None:
                return render_template(
                    "dashboard_client.html",
                    site=None,
                    incidents=[],
                    updates=[],
                )

            incidents = fetch_all(
                """
                SELECT id,
                       title,
                       details,
                       severity,
                       status,
                       created_at,
                       updated_at
                FROM incidents
                WHERE site_id = ? AND client_visible = 1
                ORDER BY created_at DESC
                LIMIT 30
                """,
                (site["id"],),
            )

            updates = fetch_all(
                """
                SELECT message, created_at
                FROM updates
                WHERE site_id = ? AND audience = 'client'
                ORDER BY created_at DESC
                LIMIT 40
                """,
                (site["id"],),
            )

            return render_template(
                "dashboard_client.html",
                site=site,
                incidents=incidents,
                updates=updates,
            )

        flash("Unknown role.", "error")
        return redirect(url_for("logout"))

    @app.get("/client/exports/site-package")
    @roles_required("client")
    def download_client_site_package():
        assert g.user is not None
        site = fetch_client_site(g.user["id"])
        if site is None:
            flash("Your account is not linked to a site yet.", "error")
            return redirect(url_for("dashboard"))

        incidents = fetch_all(
            """
            SELECT id,
                   title,
                   details,
                   severity,
                   status,
                   created_at,
                   updated_at
            FROM incidents
            WHERE site_id = ? AND client_visible = 1
            ORDER BY created_at DESC
            """,
            (site["id"],),
        )
        updates = fetch_all(
            """
            SELECT created_at, message
            FROM updates
            WHERE site_id = ? AND audience = 'client'
            ORDER BY created_at DESC
            """,
            (site["id"],),
        )

        incident_status_counts: dict[str, int] = {}
        incident_severity_counts: dict[str, int] = {}
        for incident in incidents:
            status_key = (incident["status"] or "unknown").lower()
            severity_key = (incident["severity"] or "unknown").lower()
            incident_status_counts[status_key] = incident_status_counts.get(status_key, 0) + 1
            incident_severity_counts[severity_key] = incident_severity_counts.get(severity_key, 0) + 1

        updates_csv = io.StringIO(newline="")
        updates_writer = csv.writer(updates_csv)
        updates_writer.writerow(["created_at_utc", "message"])
        for update in updates:
            updates_writer.writerow([update["created_at"], update["message"]])

        incidents_csv = io.StringIO(newline="")
        incidents_writer = csv.writer(incidents_csv)
        incidents_writer.writerow(
            [
                "incident_id",
                "title",
                "details",
                "severity",
                "status",
                "created_at_utc",
                "updated_at_utc",
            ]
        )
        for incident in incidents:
            incidents_writer.writerow(
                [
                    incident["id"],
                    incident["title"],
                    incident["details"],
                    incident["severity"],
                    incident["status"],
                    incident["created_at"],
                    incident["updated_at"],
                ]
            )

        generated_at = utc_now_iso()
        status_breakdown = ", ".join(
            f"{name}:{count}" for name, count in sorted(incident_status_counts.items())
        ) or "none"
        severity_breakdown = ", ".join(
            f"{name}:{count}" for name, count in sorted(incident_severity_counts.items())
        ) or "none"
        summary_txt = (
            f"Site: {site['name']}\n"
            f"Generated at (UTC): {generated_at}\n"
            f"Client-visible incidents: {len(incidents)}\n"
            f"Client updates: {len(updates)}\n"
            f"Incident status breakdown: {status_breakdown}\n"
            f"Incident severity breakdown: {severity_breakdown}\n"
        )
        readme_txt = (
            "Secure Ops Portal client export package\n\n"
            "Files included:\n"
            "- summary.txt: high-level counts and generation timestamp\n"
            "- client_updates.csv: updates sent to client audience\n"
            "- incident_visibility.csv: client-visible incident register\n"
        )

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("README.txt", readme_txt)
            archive.writestr("summary.txt", summary_txt)
            archive.writestr("client_updates.csv", updates_csv.getvalue())
            archive.writestr("incident_visibility.csv", incidents_csv.getvalue())

        archive_buffer.seek(0)
        filename = (
            f"{safe_filename_fragment(site['name'])}-client-report-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d')}.zip"
        )
        response = make_response(archive_buffer.getvalue())
        response.headers["Content-Type"] = "application/zip"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/dispatcher/exports/operations-brief")
    @roles_required("dispatcher")
    def download_dispatcher_operations_brief():
        brief = build_dispatcher_operations_brief()

        summary = brief["summary"]
        summary_txt = (
            f"Secure Ops Portal - Dispatcher Operations Brief\n"
            f"Generated at (UTC): {brief['generated_at']}\n"
            f"Lookback window: last {brief['lookback_hours']} hour(s)\n"
            f"Lookback start (UTC): {brief['lookback_start']}\n"
            f"Open incidents (open/in_review): {summary['open_incidents']}\n"
            f"Active assignments: {summary['active_assignments']}\n"
            f"Patrol alerts needing follow-up: {summary['patrol_alerts']}\n"
            f"Incidents created in lookback: {summary['incidents_recent']}\n"
            f"Critical incidents in lookback: {summary['critical_incidents_recent']}\n"
            f"High incidents in lookback: {summary['high_incidents_recent']}\n"
            f"Guard check-ins in lookback: {summary['checkins_recent']}\n"
            f"Client updates posted in lookback: {summary['client_updates_recent']}\n"
            f"Action queue items: {len(brief['action_queue'])}\n"
        )
        readme_txt = (
            "Secure Ops Portal dispatcher operations brief package\n\n"
            "Files included:\n"
            "- summary.txt: headline metrics and lookback window\n"
            "- action_queue.csv: prioritized dispatcher actions\n"
            "- patrol_alerts.csv: active shift patrol staleness board\n"
            "- incidents_watchlist.csv: high/critical open or in-review incidents\n"
            "- guard_activity.csv: per-guard latest check-in and recent incident volume\n"
        )

        action_queue_csv = io.StringIO(newline="")
        action_queue_writer = csv.writer(action_queue_csv)
        action_queue_writer.writerow(
            ["priority", "category", "site_name", "owner", "created_at_utc", "details"]
        )
        for item in brief["action_queue"]:
            action_queue_writer.writerow(
                [
                    item["priority"],
                    item["category"],
                    item["site_name"],
                    item["owner"],
                    item["created_at"],
                    item["details"],
                ]
            )

        patrol_alerts_csv = io.StringIO(newline="")
        patrol_alerts_writer = csv.writer(patrol_alerts_csv)
        patrol_alerts_writer.writerow(
            [
                "assignment_id",
                "site_name",
                "guard_name",
                "last_check_type",
                "last_check_at_utc",
                "stale_minutes",
                "needs_follow_up",
                "alert_reason",
            ]
        )
        for alert in brief["patrol_alerts"]:
            patrol_alerts_writer.writerow(
                [
                    alert["assignment_id"],
                    alert["site_name"],
                    alert["guard_name"],
                    alert["last_check_type"],
                    alert["last_check_at"],
                    alert["stale_minutes"],
                    "yes" if alert["needs_follow_up"] else "no",
                    alert["alert_reason"],
                ]
            )

        incidents_csv = io.StringIO(newline="")
        incidents_writer = csv.writer(incidents_csv)
        incidents_writer.writerow(
            [
                "incident_id",
                "title",
                "site_name",
                "guard_name",
                "severity",
                "status",
                "client_visible",
                "created_at_utc",
                "updated_at_utc",
            ]
        )
        for incident in brief["incidents_watchlist"]:
            incidents_writer.writerow(
                [
                    incident["id"],
                    incident["title"],
                    incident["site_name"],
                    incident["guard_name"],
                    incident["severity"],
                    incident["status"],
                    "yes" if incident["client_visible"] else "no",
                    incident["created_at"],
                    incident["updated_at"],
                ]
            )

        guard_activity_csv = io.StringIO(newline="")
        guard_activity_writer = csv.writer(guard_activity_csv)
        guard_activity_writer.writerow(
            [
                "guard_name",
                "username",
                "active_assignments",
                "incidents_in_lookback",
                "last_check_type",
                "last_check_at_utc",
                "last_check_age_minutes",
            ]
        )
        for guard in brief["guard_activity"]:
            guard_activity_writer.writerow(
                [
                    guard["guard_name"],
                    guard["username"],
                    guard["active_assignments"],
                    guard["incidents_recent"],
                    guard["last_check_type"],
                    guard["last_check_at"],
                    guard["last_check_age_minutes"],
                ]
            )

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("README.txt", readme_txt)
            archive.writestr("summary.txt", summary_txt)
            archive.writestr("action_queue.csv", action_queue_csv.getvalue())
            archive.writestr("patrol_alerts.csv", patrol_alerts_csv.getvalue())
            archive.writestr("incidents_watchlist.csv", incidents_csv.getvalue())
            archive.writestr("guard_activity.csv", guard_activity_csv.getvalue())

        archive_buffer.seek(0)
        filename = f"dispatcher-operations-brief-{datetime.now(timezone.utc).strftime('%Y%m%d')}.zip"
        response = make_response(archive_buffer.getvalue())
        response.headers["Content-Type"] = "application/zip"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/dispatcher/assignments")
    @roles_required("dispatcher")
    def create_assignment():
        guard_user_id = (request.form.get("guard_user_id") or "").strip()
        site_id = (request.form.get("site_id") or "").strip()
        new_site_name = (request.form.get("new_site_name") or "").strip()
        shift_start = (request.form.get("shift_start") or "").strip()
        shift_end = (request.form.get("shift_end") or "").strip()

        if not guard_user_id or not shift_start or not shift_end:
            flash("Guard, shift start, and shift end are required.", "error")
            return redirect(url_for("dashboard"))

        if site_id and new_site_name:
            flash("Select an existing site or provide a new site name, not both.", "error")
            return redirect(url_for("dashboard"))

        with get_conn() as conn:
            if new_site_name:
                existing_site = conn.execute(
                    "SELECT id FROM sites WHERE LOWER(name) = LOWER(?)", (new_site_name,)
                ).fetchone()
                if existing_site is not None:
                    site_id_value = existing_site["id"]
                else:
                    site_id_value = conn.execute(
                        "INSERT INTO sites (name, created_at) VALUES (?, ?) RETURNING id",
                        (new_site_name, utc_now_iso()),
                    ).fetchone()["id"]
            else:
                if not site_id:
                    flash("Site is required.", "error")
                    return redirect(url_for("dashboard"))
                site_row = conn.execute("SELECT id FROM sites WHERE id = ?", (site_id,)).fetchone()
                if site_row is None:
                    flash("Selected site does not exist.", "error")
                    return redirect(url_for("dashboard"))
                site_id_value = site_row["id"]

            guard_row = conn.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'guard'", (guard_user_id,)
            ).fetchone()
            if guard_row is None:
                flash("Selected guard is invalid.", "error")
                return redirect(url_for("dashboard"))

            conn.execute(
                """
                INSERT INTO assignments (site_id, guard_user_id, shift_start, shift_end, status, created_at)
                VALUES (?, ?, ?, ?, 'scheduled', ?)
                """,
                (
                    site_id_value,
                    guard_row["id"],
                    normalize_timestamp(shift_start),
                    normalize_timestamp(shift_end),
                    utc_now_iso(),
                ),
            )
            conn.commit()

        flash("Shift assignment created.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/dispatcher/updates")
    @roles_required("dispatcher")
    def post_update():
        assert g.user is not None
        site_id = (request.form.get("site_id") or "").strip()
        message = (request.form.get("message") or "").strip()
        audience = (request.form.get("audience") or "internal").strip().lower()
        if audience not in {"internal", "client"}:
            flash("Audience must be internal or client.", "error")
            return redirect(url_for("dashboard"))
        if not site_id or not message:
            flash("Site and message are required.", "error")
            return redirect(url_for("dashboard"))

        execute(
            """
            INSERT INTO updates (site_id, incident_id, author_user_id, audience, message, created_at)
            VALUES (?, NULL, ?, ?, ?, ?)
            """,
            (site_id, g.user["id"], audience, message, utc_now_iso()),
        )

        flash("Update posted.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/dispatcher/alerts/<int:assignment_id>/ack")
    @roles_required("dispatcher")
    def acknowledge_patrol_alert(assignment_id: int):
        assert g.user is not None

        note = (request.form.get("note") or "").strip()
        assignment = fetch_one(
            """
            SELECT a.id, a.site_id, s.name AS site_name, u.full_name AS guard_name
            FROM assignments a
            JOIN sites s ON s.id = a.site_id
            JOIN users u ON u.id = a.guard_user_id
            WHERE a.id = ? AND a.status = 'active'
            """,
            (assignment_id,),
        )
        if assignment is None:
            flash("Active assignment not found.", "error")
            return redirect(url_for("dashboard"))

        default_message = (
            f"Dispatch acknowledged patrol alert for {assignment['guard_name']} at "
            f"{assignment['site_name']}."
        )
        log_message = note if note else default_message
        execute(
            """
            INSERT INTO updates (site_id, incident_id, author_user_id, audience, message, created_at)
            VALUES (?, NULL, ?, 'internal', ?, ?)
            """,
            (assignment["site_id"], g.user["id"], f"[ALERT ACK] {log_message}", utc_now_iso()),
        )

        flash("Patrol alert acknowledged and logged.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/dispatcher/incidents/<int:incident_id>/status")
    @roles_required("dispatcher")
    def update_incident_status(incident_id: int):
        assert g.user is not None

        status = (request.form.get("status") or "").strip().lower()
        client_visible = 1 if request.form.get("client_visible") == "on" else 0
        client_message = (request.form.get("client_message") or "").strip()

        if status not in ALLOWED_INCIDENT_STATUS:
            flash("Invalid incident status.", "error")
            return redirect(url_for("dashboard"))

        incident = fetch_one(
            "SELECT id, site_id, title FROM incidents WHERE id = ?", (incident_id,)
        )
        if incident is None:
            flash("Incident not found.", "error")
            return redirect(url_for("dashboard"))

        execute(
            """
            UPDATE incidents
            SET status = ?,
                client_visible = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (status, client_visible, utc_now_iso(), incident_id),
        )

        if client_message:
            execute(
                """
                INSERT INTO updates (site_id, incident_id, author_user_id, audience, message, created_at)
                VALUES (?, ?, ?, 'client', ?, ?)
                """,
                (incident["site_id"], incident_id, g.user["id"], client_message, utc_now_iso()),
            )

        flash("Incident status updated.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/dispatcher/connecteam/import")
    @roles_required("dispatcher")
    def import_connecteam_csv():
        csv_file = request.files.get("csv_file")
        if csv_file is None or csv_file.filename == "":
            flash("Choose a CSV file first.", "error")
            return redirect(url_for("dashboard"))

        content = csv_file.stream.read().decode("utf-8-sig", errors="ignore")
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames:
            flash("CSV header row not found.", "error")
            return redirect(url_for("dashboard"))

        added = 0
        skipped = 0

        with get_conn() as conn:
            for row in reader:
                site_name = pick_csv_value(
                    row,
                    [
                        "site",
                        "site name",
                        "location",
                        "job site",
                        "client site",
                        "work location",
                    ],
                )
                guard_identifier = pick_csv_value(
                    row,
                    [
                        "guard username",
                        "username",
                        "guard",
                        "employee",
                        "employee name",
                        "worker",
                    ],
                )
                shift_start = pick_csv_value(
                    row,
                    [
                        "shift start",
                        "start",
                        "start time",
                        "from",
                        "clock in",
                    ],
                )
                shift_end = pick_csv_value(
                    row,
                    [
                        "shift end",
                        "end",
                        "end time",
                        "to",
                        "clock out",
                    ],
                )

                if not site_name or not guard_identifier or not shift_start or not shift_end:
                    skipped += 1
                    continue

                guard = conn.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE role = 'guard'
                      AND (LOWER(username) = LOWER(?) OR LOWER(full_name) = LOWER(?))
                    LIMIT 1
                    """,
                    (guard_identifier, guard_identifier),
                ).fetchone()
                if guard is None:
                    skipped += 1
                    continue

                site = conn.execute(
                    "SELECT id FROM sites WHERE LOWER(name) = LOWER(?)",
                    (site_name,),
                ).fetchone()
                if site is None:
                    site_id = conn.execute(
                        "INSERT INTO sites (name, created_at) VALUES (?, ?) RETURNING id",
                        (site_name, utc_now_iso()),
                    ).fetchone()["id"]
                else:
                    site_id = site["id"]

                conn.execute(
                    """
                    INSERT INTO assignments (site_id, guard_user_id, shift_start, shift_end, status, created_at)
                    VALUES (?, ?, ?, ?, 'scheduled', ?)
                    """,
                    (
                        site_id,
                        guard["id"],
                        normalize_timestamp(shift_start),
                        normalize_timestamp(shift_end),
                        utc_now_iso(),
                    ),
                )
                added += 1

            conn.commit()

        flash(f"Connecteam import complete: {added} shift(s) added, {skipped} skipped.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/guard/checkins")
    @roles_required("guard")
    def guard_checkin():
        assert g.user is not None
        assignment_id = (request.form.get("assignment_id") or "").strip()
        check_type = (request.form.get("check_type") or "").strip().upper()
        note = (request.form.get("note") or "").strip()

        if not assignment_id:
            flash("Select an assignment.", "error")
            return redirect(url_for("dashboard"))
        if check_type not in ALLOWED_CHECKIN_TYPES:
            flash("Invalid check-in type.", "error")
            return redirect(url_for("dashboard"))

        assignment = fetch_one(
            """
            SELECT id, status
            FROM assignments
            WHERE id = ? AND guard_user_id = ?
            """,
            (assignment_id, g.user["id"]),
        )
        if assignment is None:
            flash("Assignment not found for your user.", "error")
            return redirect(url_for("dashboard"))

        execute(
            """
            INSERT INTO checkins (assignment_id, guard_user_id, check_type, note, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (assignment_id, g.user["id"], check_type, note, utc_now_iso()),
        )

        next_status = None
        if check_type == "IN":
            next_status = "active"
        elif check_type == "OUT":
            next_status = "completed"

        if next_status is not None:
            execute(
                "UPDATE assignments SET status = ? WHERE id = ?",
                (next_status, assignment_id),
            )

        flash("Check-in recorded.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/guard/incidents")
    @roles_required("guard")
    def create_incident():
        assert g.user is not None
        assignment_id = (request.form.get("assignment_id") or "").strip()
        title = (request.form.get("title") or "").strip()
        details = (request.form.get("details") or "").strip()
        severity = (request.form.get("severity") or "").strip().lower()
        client_visible = 1 if request.form.get("client_visible") == "on" else 0

        if not assignment_id or not title or not details:
            flash("Assignment, title, and details are required.", "error")
            return redirect(url_for("dashboard"))

        if severity not in ALLOWED_INCIDENT_SEVERITY:
            flash("Invalid severity.", "error")
            return redirect(url_for("dashboard"))

        assignment = fetch_one(
            """
            SELECT a.id, a.site_id
            FROM assignments a
            WHERE a.id = ? AND a.guard_user_id = ?
            """,
            (assignment_id, g.user["id"]),
        )
        if assignment is None:
            flash("Assignment not found for your user.", "error")
            return redirect(url_for("dashboard"))

        execute(
            """
            INSERT INTO incidents
                (site_id, assignment_id, guard_user_id, title, details, severity, status, client_visible, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
            """,
            (
                assignment["site_id"],
                assignment_id,
                g.user["id"],
                title,
                details,
                severity,
                client_visible,
                utc_now_iso(),
                utc_now_iso(),
            ),
        )

        flash("Incident submitted to dispatch.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/api/status")
    @roles_required("dispatcher")
    def status_api():
        guards = fetch_all(
            """
            SELECT u.username,
                   u.full_name,
                   a.status AS assignment_status,
                   s.name AS site_name,
                   c.check_type AS last_check_type,
                   c.created_at AS last_check_at
            FROM users u
            LEFT JOIN assignments a ON a.id = (
                SELECT id
                FROM assignments
                WHERE guard_user_id = u.id
                ORDER BY id DESC
                LIMIT 1
            )
            LEFT JOIN sites s ON s.id = a.site_id
            LEFT JOIN checkins c ON c.id = (
                SELECT id
                FROM checkins
                WHERE guard_user_id = u.id
                ORDER BY id DESC
                LIMIT 1
            )
            WHERE u.role = 'guard'
            ORDER BY u.full_name
            """
        )
        return jsonify({"guards": [dict(row) for row in guards]})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
