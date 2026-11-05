import csv
import io
import json
import os
import re
import secrets
import sqlite3
import zipfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps
from hashlib import sha256
from hmac import digest as hmac_digest
from pathlib import Path
from time import time
from unicodedata import category, normalize
from uuid import UUID

import click
from flask import (
    Flask,
    abort,
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

DEMO_PROFILES = {
    "dispatcher": ("dispatcher", "Operations Desk"),
    "guard.alpha": ("guard", "Guard Alpha"),
    "guard.bravo": ("guard", "Guard Bravo"),
    "client.portal": ("client", "Client Representative"),
}
DEMO_PASSWORD = "ops123!"

ALLOWED_ROLES = {"dispatcher", "guard", "client"}
ALLOWED_INCIDENT_STATUS = {"open", "in_review", "resolved", "closed"}
ALLOWED_INCIDENT_SEVERITY = {"low", "medium", "high", "critical"}
ALLOWED_CHECKIN_TYPES = {"IN", "PATROL", "OUT"}
DEFAULT_SESSION_HOURS = 12
LOGIN_ACCOUNT_LIMIT = 10
LOGIN_WINDOW_SECONDS = 300
DEFAULT_CHECKIN_ALERT_MINUTES = 60
DEFAULT_CHECKIN_LATE_SYNC_MINUTES = 5
DEFAULT_OPERATIONS_BRIEF_LOOKBACK_HOURS = 24
DEFAULT_SHIFT_HANDOFF_LOOKAHEAD_HOURS = 12
CONNECTEAM_SOURCE_SYSTEM = "connecteam"
INCIDENT_SLA_WARNING_WINDOW_MINUTES = 10
INCIDENT_SLA_TARGET_MINUTES = {
    "critical": 15,
    "high": 30,
    "medium": 60,
    "low": 120,
}


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


def incident_sla_target_minutes(severity: str | None) -> int:
    key = (severity or "").strip().lower()
    return INCIDENT_SLA_TARGET_MINUTES.get(key, INCIDENT_SLA_TARGET_MINUTES["medium"])


def incident_sla_state(minutes_to_breach: int) -> str:
    if minutes_to_breach < 0:
        return "breached"
    if minutes_to_breach <= INCIDENT_SLA_WARNING_WINDOW_MINUTES:
        return "due_soon"
    return "on_track"


def parse_shift_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None

    parsed = parse_iso_to_utc(cleaned)
    if parsed is not None:
        return parsed

    common_formats = [
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y %I:%M %p",
        "%m/%d/%Y %H:%M:%S",
    ]
    for fmt in common_formats:
        try:
            parsed_local = datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        return parsed_local.replace(tzinfo=timezone.utc)

    return None


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


def spreadsheet_cell(value):
    if not isinstance(value, str):
        return value

    for char in value:
        normalized = normalize("NFKC", char)
        if normalized in {"=", "+", "-", "@"} or char in "\t\r\n\x00":
            # Keep the prefix in the cell value, independent of CSV quoting.
            return f"[text] {value}"
        if not (char.isspace() or normalized in {"'", "\""} or category(char) in {"Cc", "Cf"}):
            break
    return value


class SpreadsheetCsvWriter:
    def __init__(self, output: io.StringIO):
        self.writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    def writerow(self, values):
        self.writer.writerow(spreadsheet_cell(value) for value in values)


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
        return query.replace("%", "%%").replace("?", "%s")
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


def database_is_ready(database_value: str, backend: str) -> bool:
    if backend == "postgres":
        import psycopg

        try:
            with psycopg.connect(database_value, connect_timeout=2, autocommit=True) as conn:
                conn.execute("SELECT 1").fetchone()
        except psycopg.Error:
            return False
    else:
        database_uri = f"{Path(database_value).absolute().as_uri()}?mode=ro"
        try:
            with closing(sqlite3.connect(database_uri, uri=True, timeout=1)) as conn:
                conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        except sqlite3.Error:
            return False
    return True


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
                    is_demo INTEGER NOT NULL DEFAULT 0 CHECK(is_demo IN (0, 1)),
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
                    source_system TEXT NOT NULL DEFAULT 'manual',
                    external_shift_id TEXT,
                    external_job_id TEXT,
                    source_payload TEXT,
                    imported_at TEXT,
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
                is_demo INTEGER NOT NULL DEFAULT 0 CHECK(is_demo IN (0, 1)),
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
                source_system TEXT NOT NULL DEFAULT 'manual',
                external_shift_id TEXT,
                external_job_id TEXT,
                source_payload TEXT,
                imported_at TEXT,
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


def upgrade_schema(database_value: str, backend: str) -> None:
    assignment_extra_columns = {
        "source_system": "TEXT NOT NULL DEFAULT 'manual'",
        "external_shift_id": "TEXT",
        "external_job_id": "TEXT",
        "source_payload": "TEXT",
        "imported_at": "TEXT",
    }

    checkin_columns = {
        "client_event_id": "TEXT",
        "synced_at": "TEXT",
        "acknowledged_at": "TEXT",
        "acknowledged_by": "BIGINT REFERENCES users(id)",
    }
    checkin_unique_index = """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_checkins_client_event
        ON checkins(guard_user_id, client_event_id)
    """

    checkin_receipt_index = """
        CREATE INDEX IF NOT EXISTS idx_checkins_receipt_order
        ON checkins((COALESCE(synced_at, created_at)) DESC, id DESC)
    """

    auth_session_table = """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_digest TEXT PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at BIGINT NOT NULL
        )
    """
    auth_session_expiry_index = """
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at)
    """

    auth_session_user_index = """
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id)
    """

    login_attempts_table = """
        CREATE TABLE IF NOT EXISTS login_attempts (
            bucket TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL,
            expires_at BIGINT NOT NULL
        )
    """
    login_attempts_expiry_index = """
        CREATE INDEX IF NOT EXISTS idx_login_attempts_expires_at ON login_attempts(expires_at)
    """

    user_columns = {
        "is_demo": "INTEGER NOT NULL DEFAULT 0 CHECK(is_demo IN (0, 1))",
        "disabled_at": "TEXT",
    }

    if backend == "sqlite":
        with sqlite3.connect(database_value) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing_user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
            for column, spec in user_columns.items():
                if column not in existing_user_columns:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {column} {spec}")
            existing_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(assignments)").fetchall()
            }
            for column_name, column_spec in assignment_extra_columns.items():
                if column_name not in existing_columns:
                    conn.execute(
                        f"ALTER TABLE assignments ADD COLUMN {column_name} {column_spec}"
                    )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_assignments_external_shift
                ON assignments(external_shift_id)
                WHERE external_shift_id IS NOT NULL
                """
            )
            existing_checkin_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(checkins)")
            }
            for column, spec in checkin_columns.items():
                if column not in existing_checkin_columns:
                    conn.execute(f"ALTER TABLE checkins ADD COLUMN {column} {spec}")
            conn.execute(checkin_unique_index)
            conn.execute(checkin_receipt_index)
            conn.execute(auth_session_table)
            conn.execute(auth_session_expiry_index)
            conn.execute(auth_session_user_index)
            conn.execute(login_attempts_table)
            conn.execute(login_attempts_expiry_index)
            conn.commit()
        return

    with open_raw_connection(database_value, backend) as conn:
        db = DbConnection(conn, backend)
        for column, spec in user_columns.items():
            db.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {column} {spec}")
        existing_columns_rows = db.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'assignments'
            """
        ).fetchall()
        existing_columns = {row["column_name"] for row in existing_columns_rows}
        for column_name, column_spec in assignment_extra_columns.items():
            if column_name not in existing_columns:
                db.execute(f"ALTER TABLE assignments ADD COLUMN {column_name} {column_spec}")
        db.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_assignments_external_shift
            ON assignments(external_shift_id)
            WHERE external_shift_id IS NOT NULL
            """
        )
        for column, spec in checkin_columns.items():
            db.execute(f"ALTER TABLE checkins ADD COLUMN IF NOT EXISTS {column} {spec}")
        db.execute(checkin_unique_index)
        db.execute(checkin_receipt_index)
        db.execute(auth_session_table)
        db.execute(auth_session_expiry_index)
        db.execute(auth_session_user_index)
        db.execute(login_attempts_table)
        db.execute(login_attempts_expiry_index)
        db.commit()


def mark_legacy_demo_users(database_value: str, backend: str) -> None:
    with open_raw_connection(database_value, backend) as conn:
        db = DbConnection(conn, backend)
        candidates = db.execute(
            """
            SELECT id, username, password_hash, role, full_name FROM users
            WHERE is_demo = 0 AND username IN (?, ?, ?, ?)
            """,
            tuple(DEMO_PROFILES),
        ).fetchall()
        for user in candidates:
            original_profile = (user["role"], user["full_name"]) == DEMO_PROFILES[user["username"]]
            if original_profile or check_password_hash(user["password_hash"], DEMO_PASSWORD):
                db.execute(
                    "UPDATE users SET is_demo = 1 WHERE id = ? AND password_hash = ?",
                    (user["id"], user["password_hash"]),
                )
        db.commit()


def seed_demo_data(database_value: str, backend: str) -> None:
    with open_raw_connection(database_value, backend) as conn:
        db = DbConnection(conn, backend)
        if backend == "sqlite":
            db.execute("BEGIN IMMEDIATE")
        else:
            db.execute("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")
        count = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if count > 0:
            return

        now = utc_now_iso()
        dispatcher_id = db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at, is_demo)
            VALUES (?, ?, 'dispatcher', ?, ?, 1)
            RETURNING id
            """,
            ("dispatcher", generate_password_hash(DEMO_PASSWORD), "Operations Desk", now),
        ).fetchone()["id"]

        guard_one_id = db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at, is_demo)
            VALUES (?, ?, 'guard', ?, ?, 1)
            RETURNING id
            """,
            ("guard.alpha", generate_password_hash(DEMO_PASSWORD), "Guard Alpha", now),
        ).fetchone()["id"]

        guard_two_id = db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at, is_demo)
            VALUES (?, ?, 'guard', ?, ?, 1)
            RETURNING id
            """,
            ("guard.bravo", generate_password_hash(DEMO_PASSWORD), "Guard Bravo", now),
        ).fetchone()["id"]

        client_id = db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at, is_demo)
            VALUES (?, ?, 'client', ?, ?, 1)
            RETURNING id
            """,
            ("client.portal", generate_password_hash(DEMO_PASSWORD), "Client Representative", now),
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
            INSERT INTO assignments
                (site_id, guard_user_id, shift_start, shift_end, status, source_system, created_at)
            VALUES (?, ?, ?, ?, 'scheduled', 'manual', ?)
            RETURNING id
            """,
            (site_id, guard_one_id, to_utc_iso(start), to_utc_iso(end), now),
        ).fetchone()["id"]

        db.execute(
            """
            INSERT INTO assignments
                (site_id, guard_user_id, shift_start, shift_end, status, source_system, created_at)
            VALUES (?, ?, ?, ?, 'scheduled', 'manual', ?)
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
        SECRET_KEY=os.getenv("APP_SECRET"),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_HOURS=os.getenv("APP_SESSION_HOURS", str(DEFAULT_SESSION_HOURS)),
        LOGIN_SOURCE_LIMIT=os.getenv("APP_LOGIN_SOURCE_LIMIT", "0"),
        DEMO_MODE=False,
        DATABASE=default_db,
        DB_BACKEND=default_backend,
        CHECKIN_ALERT_MINUTES=int(
            os.getenv("CHECKIN_ALERT_MINUTES", str(DEFAULT_CHECKIN_ALERT_MINUTES))
        ),
        CHECKIN_LATE_SYNC_MINUTES=int(
            os.getenv("CHECKIN_LATE_SYNC_MINUTES", str(DEFAULT_CHECKIN_LATE_SYNC_MINUTES))
        ),
        OPERATIONS_BRIEF_LOOKBACK_HOURS=int(
            os.getenv(
                "OPERATIONS_BRIEF_LOOKBACK_HOURS",
                str(DEFAULT_OPERATIONS_BRIEF_LOOKBACK_HOURS),
            )
        ),
        SHIFT_HANDOFF_LOOKAHEAD_HOURS=int(
            os.getenv(
                "SHIFT_HANDOFF_LOOKAHEAD_HOURS",
                str(DEFAULT_SHIFT_HANDOFF_LOOKAHEAD_HOURS),
            )
        ),
    )

    if test_config:
        app.config.update(test_config)

    secret = app.config["SECRET_KEY"]
    if not secret or secret.strip() in {
        "",
        "ops-portal-dev-secret",
        "replace-this-with-a-long-random-secret",
        "replace-with-strong-secret",
    }:
        raise RuntimeError("Set APP_SECRET to a strong random session-signing secret.")

    session_hours = str(app.config["SESSION_HOURS"])
    if not re.fullmatch(r"(?:[1-9]|1[0-9]|2[0-4])", session_hours):
        raise RuntimeError("Set APP_SESSION_HOURS to a whole number from 1 to 24.")
    session_lifetime_seconds = int(session_hours) * 3600

    source_limit_value = str(app.config["LOGIN_SOURCE_LIMIT"])
    if not re.fullmatch(r"[0-9]{1,5}", source_limit_value) or int(source_limit_value) > 10000:
        raise RuntimeError("Set APP_LOGIN_SOURCE_LIMIT to a whole number from 0 to 10000.")
    source_limit = int(source_limit_value)
    login_bucket_secret = secret if isinstance(secret, bytes) else secret.encode()

    app.config["DB_BACKEND"] = detect_db_backend(app.config["DATABASE"])

    init_db(app.config["DATABASE"], app.config["DB_BACKEND"])
    upgrade_schema(app.config["DATABASE"], app.config["DB_BACKEND"])
    mark_legacy_demo_users(app.config["DATABASE"], app.config["DB_BACKEND"])
    demo_mode = app.config["DEMO_MODE"]
    late_sync_minutes = max(1, app.config["CHECKIN_LATE_SYNC_MINUTES"])
    if demo_mode:
        seed_demo_data(app.config["DATABASE"], app.config["DB_BACKEND"])

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

    def login_bucket(kind: str, identifier: str) -> str:
        return hmac_digest(login_bucket_secret, f"{kind}:{identifier}".encode(), "sha256").hex()

    def prompt_account_password(label: str) -> str:
        password = click.prompt(label, hide_input=True, confirmation_prompt=True)
        if not 15 <= len(password) <= 128:
            raise click.ClickException("Use a password of 15–128 characters.")
        return password

    @app.cli.command("provision-user")
    @click.option("--username", required=True)
    @click.option("--role", required=True, type=click.Choice(sorted(ALLOWED_ROLES)))
    @click.option("--full-name", required=True)
    def provision_user(username: str, role: str, full_name: str) -> None:
        """Create an operator-provisioned account."""
        username = username.strip().lower()
        full_name = full_name.strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", username):
            raise click.BadParameter("Start with a letter or digit. Use up to 64 letters, digits, dots, hyphens or underscores.", param_hint="--username")
        if username in DEMO_PROFILES:
            raise click.BadParameter("This username is reserved for local demos.", param_hint="--username")
        if not full_name or "\x00" in full_name:
            raise click.BadParameter("Enter a valid display name.", param_hint="--full-name")

        password_hash = generate_password_hash(prompt_account_password("Password"))
        with get_conn() as db:
            user = db.execute(
                """
                INSERT INTO users (username, password_hash, role, full_name, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (username) DO NOTHING
                RETURNING id
                """,
                (username, password_hash, role, full_name, utc_now_iso()),
            ).fetchone()
            if user is None:
                raise click.ClickException("That username already exists.")
        click.echo(f"Created {role} account {username}.")

    @app.cli.command("reset-user-password")
    @click.argument("username")
    def reset_user_password(username: str) -> None:
        """Set a new password and revoke sessions for a provisioned account."""
        username = username.strip().lower()
        account = fetch_one(
            "SELECT id, password_hash FROM users WHERE username = ? AND is_demo = 0",
            (username,),
        )
        if account is None:
            raise click.ClickException("Choose a provisioned account.")

        password = prompt_account_password("New password")
        if check_password_hash(account["password_hash"], password):
            raise click.ClickException("Choose a password different from the current password.")
        password_hash = generate_password_hash(password)
        with get_conn() as db:
            updated = db.execute(
                """
                UPDATE users SET password_hash = ?
                WHERE id = ? AND password_hash = ? AND is_demo = 0
                RETURNING id
                """,
                (password_hash, account["id"], account["password_hash"]),
            ).fetchone()
            if updated is None:
                raise click.ClickException("The account changed during the reset. Run the command again.")
            db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (updated["id"],))
            db.execute("DELETE FROM login_attempts WHERE bucket = ?", (login_bucket("username", username),))
        click.echo(f"Password reset for {username}. All existing sessions were revoked.")

    @app.cli.command("set-user-access")
    @click.argument("username")
    @click.argument("access", type=click.Choice(("enabled", "disabled")))
    def set_user_access(username: str, access: str) -> None:
        """Enable or disable a provisioned account."""
        username = username.strip().lower()
        disabled = access == "disabled"
        with get_conn() as db:
            user = db.execute(
                """
                UPDATE users
                SET disabled_at = CASE WHEN ? THEN COALESCE(disabled_at, ?) ELSE NULL END
                WHERE username = ? AND is_demo = 0
                RETURNING id
                """,
                (disabled, utc_now_iso(), username),
            ).fetchone()
            if user is None:
                raise click.ClickException("Choose a provisioned account.")
            if disabled:
                db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user["id"],))
        click.echo(f"Access for {username} is {access}.")

    @app.cli.command("provision-site")
    @click.option("--name", required=True)
    @click.option("--client", help="Username of a provisioned client account.")
    def provision_site(name: str, client: str | None) -> None:
        """Create a site or link an existing site to a client."""
        name = name.strip()
        if not name or "\x00" in name:
            raise click.BadParameter("Enter a valid site name.", param_hint="--name")

        with get_conn() as db:
            client_id = None
            if client is not None:
                if app.config["DB_BACKEND"] == "sqlite":
                    db.execute("BEGIN IMMEDIATE")
                    lock = ""
                else:
                    lock = " FOR UPDATE"
                user = db.execute(
                    "SELECT id FROM users WHERE username = ? AND role = 'client' AND is_demo = 0 AND disabled_at IS NULL" + lock,
                    (client.strip().lower(),),
                ).fetchone()
                if user is None:
                    raise click.ClickException("Choose a provisioned client account with access enabled.")
                client_id = user["id"]
                other_site = db.execute(
                    "SELECT id FROM sites WHERE client_user_id = ? AND name <> ? LIMIT 1",
                    (client_id, name),
                ).fetchone()
                if other_site is not None:
                    raise click.ClickException("That client account is already linked to another site.")

            db.execute(
                """
                INSERT INTO sites (name, client_user_id, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT (name) DO NOTHING
                """,
                (name, client_id, utc_now_iso()),
            )
            if client_id is not None:
                linked_site = db.execute(
                    """
                    UPDATE sites SET client_user_id = ?
                    WHERE name = ? AND (client_user_id IS NULL OR client_user_id = ?)
                    RETURNING id
                    """,
                    (client_id, name, client_id),
                ).fetchone()
                if linked_site is None:
                    raise click.ClickException("That site is already linked to another client.")
        click.echo(f"Site {name} is ready.")

    def fetch_client_site(client_user_id: int):
        return fetch_one(
            """
            SELECT id, name
            FROM sites
            WHERE client_user_id = ?
            """,
            (client_user_id,),
        )

    def fetch_incident_sla_radar_rows(now_utc: datetime) -> list[dict]:
        incidents_open = fetch_all(
            """
            SELECT i.id,
                   i.site_id,
                   i.title,
                   i.severity,
                   i.status,
                   i.client_visible,
                   i.created_at,
                   i.updated_at,
                   incident_updates.last_update_at,
                   ack_updates.last_ack_at AS last_dispatch_ack_at,
                   s.name AS site_name,
                   u.full_name AS guard_name
            FROM incidents i
            JOIN sites s ON s.id = i.site_id
            JOIN users u ON u.id = i.guard_user_id
            LEFT JOIN (
                SELECT incident_id, MAX(created_at) AS last_update_at
                FROM updates
                WHERE incident_id IS NOT NULL
                GROUP BY incident_id
            ) AS incident_updates ON incident_updates.incident_id = i.id
            LEFT JOIN (
                SELECT incident_id, MAX(created_at) AS last_ack_at
                FROM updates
                WHERE incident_id IS NOT NULL
                  AND audience = 'internal'
                  AND message LIKE '[ACK]%'
                GROUP BY incident_id
            ) AS ack_updates ON ack_updates.incident_id = i.id
            WHERE i.status IN ('open', 'in_review')
            ORDER BY
                CASE i.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,
                i.created_at ASC
            """
        )

        incident_sla_radar: list[dict] = []
        for incident in incidents_open:
            severity_key = (incident["severity"] or "").lower()
            sla_target_minutes = incident_sla_target_minutes(severity_key)
            ack_reference_at = incident["last_dispatch_ack_at"] or incident["created_at"]
            minutes_since_ack = minutes_since(ack_reference_at, now_utc) or 0
            minutes_to_breach = sla_target_minutes - minutes_since_ack
            sla_state = incident_sla_state(minutes_to_breach)
            incident_age_minutes = minutes_since(incident["created_at"], now_utc) or 0
            last_touch_at = (
                incident["last_update_at"] or incident["updated_at"] or incident["created_at"]
            )

            incident_sla_radar.append(
                {
                    "id": incident["id"],
                    "site_id": incident["site_id"],
                    "title": incident["title"],
                    "severity": severity_key or "unknown",
                    "status": incident["status"],
                    "client_visible": incident["client_visible"],
                    "created_at": incident["created_at"],
                    "updated_at": incident["updated_at"],
                    "last_touch_at": last_touch_at,
                    "last_dispatch_ack_at": incident["last_dispatch_ack_at"] or "none",
                    "ack_reference_at": ack_reference_at,
                    "site_name": incident["site_name"],
                    "guard_name": incident["guard_name"],
                    "sla_target_minutes": sla_target_minutes,
                    "minutes_since_ack": minutes_since_ack,
                    "minutes_to_breach": minutes_to_breach,
                    "sla_state": sla_state,
                    "incident_age_minutes": incident_age_minutes,
                }
            )

        incident_sla_radar.sort(
            key=lambda item: (
                {"breached": 0, "due_soon": 1, "on_track": 2}.get(item["sla_state"], 9),
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item["severity"], 9),
                item["minutes_to_breach"],
                -item["incident_age_minutes"],
                item["site_name"],
            )
        )
        return incident_sla_radar

    def ensure_incident_sla_escalations(
        incident_sla_radar: list[dict], author_user_id: int | None = None
    ) -> int:
        escalation_author = author_user_id
        if escalation_author is None:
            dispatcher = fetch_one(
                "SELECT id FROM users WHERE role = 'dispatcher' ORDER BY id ASC LIMIT 1"
            )
            if dispatcher is None:
                return 0
            escalation_author = dispatcher["id"]

        inserted = 0
        with get_conn() as conn:
            for incident in incident_sla_radar:
                if incident["sla_state"] != "breached":
                    continue

                existing_note = conn.execute(
                    """
                    SELECT id
                    FROM updates
                    WHERE incident_id = ?
                      AND audience = 'internal'
                      AND message LIKE '[SLA ESCALATION]%'
                    LIMIT 1
                    """,
                    (incident["id"],),
                ).fetchone()
                if existing_note is not None:
                    continue

                breach_minutes = abs(int(incident["minutes_to_breach"]))
                escalation_message = (
                    f"[SLA ESCALATION] Incident #{incident['id']} exceeded dispatcher "
                    f"acknowledgement SLA by {breach_minutes} minute(s). Immediate follow-up required."
                )
                conn.execute(
                    """
                    INSERT INTO updates (site_id, incident_id, author_user_id, audience, message, created_at)
                    VALUES (?, ?, ?, 'internal', ?, ?)
                    """,
                    (
                        incident["site_id"],
                        incident["id"],
                        escalation_author,
                        escalation_message,
                        utc_now_iso(),
                    ),
                )
                inserted += 1

            if inserted:
                conn.commit()

        return inserted

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
                SELECT assignment_id, check_type, created_at
                FROM (
                    SELECT assignment_id, check_type, created_at,
                           ROW_NUMBER() OVER (PARTITION BY assignment_id ORDER BY created_at DESC, id DESC) AS position
                    FROM checkins
                ) ranked
                WHERE position = 1
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

    def build_dispatcher_operations_brief(author_user_id: int | None = None) -> dict:
        lookback_hours = max(1, int(app.config["OPERATIONS_BRIEF_LOOKBACK_HOURS"]))
        alert_threshold_minutes = max(1, int(app.config["CHECKIN_ALERT_MINUTES"]))
        now_utc = datetime.now(timezone.utc).replace(microsecond=0)
        lookback_start_iso = to_utc_iso(now_utc - timedelta(hours=lookback_hours))

        patrol_alerts = build_patrol_alerts(alert_threshold_minutes, now_utc)
        open_patrol_alerts = [item for item in patrol_alerts if item["needs_follow_up"]]

        incident_sla_radar = fetch_incident_sla_radar_rows(now_utc)
        ensure_incident_sla_escalations(incident_sla_radar, author_user_id=author_user_id)
        incident_sla_radar = fetch_incident_sla_radar_rows(now_utc)

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
                SELECT guard_user_id, check_type, created_at
                FROM (
                    SELECT guard_user_id, check_type, created_at,
                           ROW_NUMBER() OVER (PARTITION BY guard_user_id ORDER BY created_at DESC, id DESC) AS position
                    FROM checkins
                ) ranked
                WHERE position = 1
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

        incident_sla_counts: dict[str, int] = {"breached": 0, "due_soon": 0, "on_track": 0}
        for incident in incident_sla_radar:
            incident_sla_counts[incident["sla_state"]] += 1

        incidents_watchlist = [
            item for item in incident_sla_radar if item["severity"] in {"critical", "high"}
        ]

        action_queue: list[dict] = []
        for incident in incident_sla_radar:
            if incident["sla_state"] == "on_track" and incident["severity"] not in {
                "critical",
                "high",
            }:
                continue

            if incident["sla_state"] == "breached":
                priority_rank = 1
                priority = "P1"
                urgency_score = 5000 + abs(incident["minutes_to_breach"])
                sla_message = f"SLA breached by {abs(incident['minutes_to_breach'])} min"
            elif incident["severity"] == "critical" or incident["sla_state"] == "due_soon":
                priority_rank = 2
                priority = "P2"
                urgency_score = 3000 - incident["minutes_to_breach"]
                sla_message = f"{incident['minutes_to_breach']} min to SLA breach"
            else:
                priority_rank = 3
                priority = "P3"
                urgency_score = 1000 - incident["minutes_to_breach"]
                sla_message = f"{incident['minutes_to_breach']} min to SLA breach"

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
                        f"({incident['severity']}/{incident['status']}) age {incident['incident_age_minutes']} min, {sla_message}"
                    ),
                    "sort_minutes": urgency_score,
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
                "incidents_sla_breached": incident_sla_counts["breached"],
                "incidents_sla_due_soon": incident_sla_counts["due_soon"],
                "incidents_recent": len(incidents_last_lookback),
                "checkins_recent": checkins_recent_count,
                "client_updates_recent": client_updates_recent_count,
                "critical_incidents_recent": incident_severity_counts["critical"],
                "high_incidents_recent": incident_severity_counts["high"],
            },
            "action_queue": action_queue,
            "guard_activity": guard_activity_rows,
            "incidents_watchlist": incidents_watchlist,
            "incident_sla_radar": incident_sla_radar,
            "patrol_alerts": patrol_alerts,
            "open_patrol_alerts": open_patrol_alerts,
        }

    def build_shift_handoff_brief(author_user_id: int | None = None) -> dict:
        lookahead_hours = max(1, int(app.config["SHIFT_HANDOFF_LOOKAHEAD_HOURS"]))
        alert_threshold_minutes = max(1, int(app.config["CHECKIN_ALERT_MINUTES"]))
        now_utc = datetime.now(timezone.utc).replace(microsecond=0)
        lookahead_end_utc = now_utc + timedelta(hours=lookahead_hours)
        now_iso = to_utc_iso(now_utc)
        lookahead_end_iso = to_utc_iso(lookahead_end_utc)

        patrol_alerts = build_patrol_alerts(alert_threshold_minutes, now_utc)
        open_patrol_alerts = [item for item in patrol_alerts if item["needs_follow_up"]]

        incident_sla_radar = fetch_incident_sla_radar_rows(now_utc)
        ensure_incident_sla_escalations(incident_sla_radar, author_user_id=author_user_id)
        incident_sla_radar = fetch_incident_sla_radar_rows(now_utc)
        incident_followups = [
            item
            for item in incident_sla_radar
            if item["sla_state"] in {"breached", "due_soon"}
            or item["severity"] in {"critical", "high"}
        ]

        coverage_rows = fetch_all(
            """
            SELECT a.id,
                   a.status,
                   a.shift_start,
                   a.shift_end,
                   s.name AS site_name,
                   u.full_name AS guard_name
            FROM assignments a
            JOIN sites s ON s.id = a.site_id
            JOIN users u ON u.id = a.guard_user_id
            WHERE a.shift_end >= ?
              AND (
                    a.status = 'active'
                    OR (a.status = 'scheduled' AND a.shift_start <= ?)
              )
            ORDER BY a.shift_start ASC
            """,
            (now_iso, lookahead_end_iso),
        )

        coverage_summary: list[dict] = []
        active_ending_soon = 0
        for assignment in coverage_rows:
            start_dt = parse_iso_to_utc(assignment["shift_start"]) or now_utc
            end_dt = parse_iso_to_utc(assignment["shift_end"]) or now_utc
            minutes_until_start = int((start_dt - now_utc).total_seconds() // 60)
            minutes_until_end = int((end_dt - now_utc).total_seconds() // 60)
            if assignment["status"] == "active" and minutes_until_end <= 120:
                active_ending_soon += 1

            coverage_summary.append(
                {
                    "assignment_id": assignment["id"],
                    "status": assignment["status"],
                    "shift_start": assignment["shift_start"],
                    "shift_end": assignment["shift_end"],
                    "site_name": assignment["site_name"],
                    "guard_name": assignment["guard_name"],
                    "minutes_until_start": minutes_until_start,
                    "minutes_until_end": minutes_until_end,
                }
            )

        recent_internal_updates = fetch_all(
            """
            SELECT up.created_at,
                   up.message,
                   s.name AS site_name,
                   au.full_name AS author_name
            FROM updates up
            JOIN sites s ON s.id = up.site_id
            JOIN users au ON au.id = up.author_user_id
            WHERE up.audience = 'internal'
            ORDER BY up.created_at DESC
            LIMIT 15
            """
        )

        return {
            "generated_at": now_iso,
            "lookahead_hours": lookahead_hours,
            "lookahead_end": lookahead_end_iso,
            "summary": {
                "coverage_rows": len(coverage_summary),
                "active_assignments": len(
                    [row for row in coverage_summary if row["status"] == "active"]
                ),
                "scheduled_assignments": len(
                    [row for row in coverage_summary if row["status"] == "scheduled"]
                ),
                "active_ending_soon": active_ending_soon,
                "incident_followups": len(incident_followups),
                "patrol_followups": len(open_patrol_alerts),
                "recent_internal_updates": len(recent_internal_updates),
            },
            "coverage_rows": coverage_summary,
            "incident_followups": incident_followups,
            "patrol_followups": open_patrol_alerts,
            "recent_internal_updates": [dict(row) for row in recent_internal_updates],
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
        g.user = None
        g.auth_session_digest = None
        if request.endpoint in {"health", "readiness"}:
            return
        token = session.get("auth_token")
        if not token:
            if "user_id" in session:
                session.clear()
            return

        token_digest = sha256(token.encode()).hexdigest()
        g.user = fetch_one(
            """
            SELECT u.id, u.username, u.role, u.full_name
            FROM auth_sessions a JOIN users u ON u.id = a.user_id
            WHERE a.token_digest = ? AND a.expires_at > ?
              AND u.disabled_at IS NULL AND (u.is_demo = 0 OR ?)
            """,
            (token_digest, int(time()), demo_mode),
        )
        if g.user is None:
            session.clear()
        else:
            g.auth_session_digest = token_digest

    @app.template_global()
    def csrf_token() -> str:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    @app.before_request
    def protect_form_submissions() -> None:
        if request.method != "POST" or request.endpoint is None:
            return
        expected = session.get("csrf_token")
        supplied = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected.encode(), supplied.encode()):
            abort(400, description="Invalid form token. Reload the page and try again.")

    @app.after_request
    def prevent_form_caching(response):
        if getattr(g, "user", None) is not None or "csrf_token" in session:
            response.cache_control.no_store = True
        return response

    @app.get("/health")
    def health() -> tuple[dict[str, str], int]:
        return {"status": "ok", "service": "omega-guard-ops-portal"}, 200

    @app.get("/ready")
    def readiness():
        ready = database_is_ready(app.config["DATABASE"], app.config["DB_BACKEND"])
        response = make_response(
            {"status": "ready"} if ready else {"status": "database_unavailable"},
            200 if ready else 503,
        )
        response.cache_control.no_store = True
        return response

    def reserve_login_attempts(username: str):
        buckets = []
        if source_limit and request.remote_addr:
            buckets.append((login_bucket("source", request.remote_addr), source_limit))
        buckets.append((login_bucket("username", username), LOGIN_ACCOUNT_LIMIT))

        now = int(time())
        reservations = []
        with get_conn() as db:
            db.execute("DELETE FROM login_attempts WHERE expires_at <= ?", (now,))
            for bucket, limit in buckets:
                reserved = db.execute(
                    """
                    INSERT INTO login_attempts (bucket, attempts, expires_at)
                    VALUES (?, 1, ?)
                    ON CONFLICT (bucket) DO UPDATE SET attempts = login_attempts.attempts + 1
                    WHERE login_attempts.attempts < ?
                    RETURNING expires_at
                    """,
                    (bucket, now + LOGIN_WINDOW_SECONDS, limit),
                ).fetchone()
                if reserved is None:
                    blocked = db.execute(
                        "SELECT expires_at FROM login_attempts WHERE bucket = ?", (bucket,)
                    ).fetchone()
                    return [], max(1, blocked["expires_at"] - now)
                reservations.append((bucket, reserved["expires_at"]))
        return reservations, None

    def issue_auth_session(user, login_reservations):
        token = secrets.token_urlsafe(32)
        with get_conn() as db:
            # Serialize session creation with account changes, after checking the password.
            lock = " FOR UPDATE" if app.config["DB_BACKEND"] == "postgres" else ""
            if not lock:
                db.execute("BEGIN IMMEDIATE")
            active = db.execute(
                """
                SELECT id FROM users WHERE id = ? AND password_hash = ?
                  AND disabled_at IS NULL AND (is_demo = 0 OR ?)
                """ + lock,
                (user["id"], user["password_hash"], demo_mode),
            ).fetchone()
            if active is None:
                return None
            now = int(time())
            db.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))
            if g.auth_session_digest is not None:
                db.execute("DELETE FROM auth_sessions WHERE token_digest = ?", (g.auth_session_digest,))
            db.execute(
                "INSERT INTO auth_sessions (token_digest, user_id, expires_at) VALUES (?, ?, ?)",
                (sha256(token.encode()).hexdigest(), user["id"], now + session_lifetime_seconds),
            )
            for bucket, expires_at in login_reservations:
                db.execute(
                    """
                    UPDATE login_attempts SET attempts = attempts - 1
                    WHERE bucket = ? AND expires_at = ? AND attempts > 0
                    """,
                    (bucket, expires_at),
                )
        return token

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip().lower()
            password = request.form.get("password") or ""

            reservations, retry_after = reserve_login_attempts(username)
            if retry_after is not None:
                flash("Too many sign-in attempts. Wait a few minutes and try again.", "error")
                response = make_response(render_template("login.html"), 429)
                response.headers["Retry-After"] = str(retry_after)
                return response

            user = fetch_one(
                """
                SELECT id, password_hash FROM users
                WHERE username = ? AND disabled_at IS NULL AND (is_demo = 0 OR ?)
                """,
                (username, demo_mode),
            )
            token = None
            if user is not None and check_password_hash(user["password_hash"], password):
                token = issue_auth_session(user, reservations)
            if token is None:
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            session.clear()
            session["auth_token"] = token
            flash("Signed in.", "success")
            return redirect(url_for("dashboard"))

        if g.user is not None:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        execute("DELETE FROM auth_sessions WHERE token_digest = ?", (g.auth_session_digest,))
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
                    SELECT guard_user_id, check_type, created_at
                    FROM (
                        SELECT guard_user_id, check_type, created_at,
                               ROW_NUMBER() OVER (PARTITION BY guard_user_id ORDER BY created_at DESC, id DESC) AS position
                        FROM checkins
                    ) ranked
                    WHERE position = 1
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

            incident_rows = fetch_all(
                """
                SELECT i.id,
                       i.site_id,
                       i.title,
                       i.details,
                       i.severity,
                       i.status,
                       i.client_visible,
                       i.created_at,
                       ack_updates.last_ack_at AS last_dispatch_ack_at,
                       s.name AS site_name,
                       u.full_name AS guard_name
                FROM incidents i
                JOIN sites s ON s.id = i.site_id
                JOIN users u ON u.id = i.guard_user_id
                LEFT JOIN (
                    SELECT incident_id, MAX(created_at) AS last_ack_at
                    FROM updates
                    WHERE incident_id IS NOT NULL
                      AND audience = 'internal'
                      AND message LIKE '[ACK]%'
                    GROUP BY incident_id
                ) AS ack_updates ON ack_updates.incident_id = i.id
                ORDER BY i.created_at DESC
                LIMIT 30
                """
            )
            dashboard_now_utc = datetime.now(timezone.utc).replace(microsecond=0)
            incidents: list[dict] = []
            for incident in incident_rows:
                item = dict(incident)
                severity = (item["severity"] or "").lower()
                if item["status"] in {"open", "in_review"}:
                    ack_target = incident_sla_target_minutes(severity)
                    ack_reference = item["last_dispatch_ack_at"] or item["created_at"]
                    ack_elapsed = minutes_since(ack_reference, dashboard_now_utc) or 0
                    minutes_to_breach = ack_target - ack_elapsed
                    item["ack_target_minutes"] = ack_target
                    item["ack_elapsed_minutes"] = ack_elapsed
                    item["minutes_to_ack_breach"] = minutes_to_breach
                    item["ack_state"] = incident_sla_state(minutes_to_breach)
                    item["ack_reference_at"] = ack_reference
                else:
                    item["ack_target_minutes"] = ""
                    item["ack_elapsed_minutes"] = ""
                    item["minutes_to_ack_breach"] = ""
                    item["ack_state"] = "not_required"
                    item["ack_reference_at"] = item["last_dispatch_ack_at"] or "none"
                incidents.append(item)

            assignments = fetch_all(
                """
                SELECT a.id,
                       a.shift_start,
                       a.shift_end,
                       a.status,
                       a.source_system,
                       a.external_shift_id,
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
                WHERE role = 'guard' AND disabled_at IS NULL
                ORDER BY full_name ASC
                """
            )

            ops_brief = build_dispatcher_operations_brief(author_user_id=g.user["id"])
            shift_handoff = build_shift_handoff_brief(author_user_id=g.user["id"])
            alert_threshold_minutes = ops_brief["alert_threshold_minutes"]
            patrol_alerts = ops_brief["patrol_alerts"]
            open_patrol_alerts = ops_brief["open_patrol_alerts"]

            review_checkins, pending_review_count = pending_checkin_review()
            return render_template(
                "dashboard_dispatcher.html",
                received_checkins=recent_checkin_receipts(),
                review_checkins=review_checkins,
                pending_review_count=pending_review_count,
                late_sync_minutes=late_sync_minutes,
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
                shift_handoff=shift_handoff,
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
        updates_writer = SpreadsheetCsvWriter(updates_csv)
        updates_writer.writerow(["created_at_utc", "message"])
        for update in updates:
            updates_writer.writerow([update["created_at"], update["message"]])

        incidents_csv = io.StringIO(newline="")
        incidents_writer = SpreadsheetCsvWriter(incidents_csv)
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
            "Omega Guard Services client export package\n\n"
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
        assert g.user is not None
        brief = build_dispatcher_operations_brief(author_user_id=g.user["id"])

        summary = brief["summary"]
        summary_txt = (
            f"Omega Guard Services - Dispatcher Operations Brief\n"
            f"Generated at (UTC): {brief['generated_at']}\n"
            f"Lookback window: last {brief['lookback_hours']} hour(s)\n"
            f"Lookback start (UTC): {brief['lookback_start']}\n"
            f"Open incidents (open/in_review): {summary['open_incidents']}\n"
            f"Active assignments: {summary['active_assignments']}\n"
            f"Patrol alerts needing follow-up: {summary['patrol_alerts']}\n"
            f"SLA breached incidents: {summary['incidents_sla_breached']}\n"
            f"SLA due-soon incidents: {summary['incidents_sla_due_soon']}\n"
            f"Incidents created in lookback: {summary['incidents_recent']}\n"
            f"Critical incidents in lookback: {summary['critical_incidents_recent']}\n"
            f"High incidents in lookback: {summary['high_incidents_recent']}\n"
            f"Guard check-ins in lookback: {summary['checkins_recent']}\n"
            f"Client updates posted in lookback: {summary['client_updates_recent']}\n"
            f"Action queue items: {len(brief['action_queue'])}\n"
        )
        readme_txt = (
            "Omega Guard Services dispatcher operations brief package\n\n"
            "Files included:\n"
            "- summary.txt: headline metrics and lookback window\n"
            "- action_queue.csv: prioritized dispatcher actions\n"
            "- patrol_alerts.csv: active shift patrol staleness board\n"
            "- incidents_watchlist.csv: high/critical open or in-review incident watchlist\n"
            "- incident_sla_radar.csv: SLA state for all open/in-review incidents\n"
            "- guard_activity.csv: per-guard latest check-in and recent incident volume\n"
        )

        action_queue_csv = io.StringIO(newline="")
        action_queue_writer = SpreadsheetCsvWriter(action_queue_csv)
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
        patrol_alerts_writer = SpreadsheetCsvWriter(patrol_alerts_csv)
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
        incidents_writer = SpreadsheetCsvWriter(incidents_csv)
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
                "sla_state",
                "sla_target_minutes",
                "minutes_since_ack",
                "minutes_to_breach",
                "last_dispatch_ack_at_utc",
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
                    incident["sla_state"],
                    incident["sla_target_minutes"],
                    incident["minutes_since_ack"],
                    incident["minutes_to_breach"],
                    incident["last_dispatch_ack_at"],
                ]
            )

        incident_sla_csv = io.StringIO(newline="")
        incident_sla_writer = SpreadsheetCsvWriter(incident_sla_csv)
        incident_sla_writer.writerow(
            [
                "incident_id",
                "title",
                "site_name",
                "guard_name",
                "severity",
                "status",
                "client_visible",
                "created_at_utc",
                "last_dispatch_ack_at_utc",
                "sla_target_minutes",
                "minutes_since_ack",
                "minutes_to_breach",
                "sla_state",
            ]
        )
        for incident in brief["incident_sla_radar"]:
            incident_sla_writer.writerow(
                [
                    incident["id"],
                    incident["title"],
                    incident["site_name"],
                    incident["guard_name"],
                    incident["severity"],
                    incident["status"],
                    "yes" if incident["client_visible"] else "no",
                    incident["created_at"],
                    incident["last_dispatch_ack_at"],
                    incident["sla_target_minutes"],
                    incident["minutes_since_ack"],
                    incident["minutes_to_breach"],
                    incident["sla_state"],
                ]
            )

        guard_activity_csv = io.StringIO(newline="")
        guard_activity_writer = SpreadsheetCsvWriter(guard_activity_csv)
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
            archive.writestr("incident_sla_radar.csv", incident_sla_csv.getvalue())
            archive.writestr("guard_activity.csv", guard_activity_csv.getvalue())

        archive_buffer.seek(0)
        filename = f"dispatcher-operations-brief-{datetime.now(timezone.utc).strftime('%Y%m%d')}.zip"
        response = make_response(archive_buffer.getvalue())
        response.headers["Content-Type"] = "application/zip"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/dispatcher/exports/shift-handoff")
    @roles_required("dispatcher")
    def download_dispatcher_shift_handoff_brief():
        assert g.user is not None
        handoff = build_shift_handoff_brief(author_user_id=g.user["id"])
        summary = handoff["summary"]

        summary_txt = (
            f"Omega Guard Services - Shift Handoff Brief\n"
            f"Generated at (UTC): {handoff['generated_at']}\n"
            f"Coverage lookahead window: next {handoff['lookahead_hours']} hour(s)\n"
            f"Lookahead end (UTC): {handoff['lookahead_end']}\n"
            f"Assignments in handoff window: {summary['coverage_rows']}\n"
            f"Active assignments: {summary['active_assignments']}\n"
            f"Scheduled assignments: {summary['scheduled_assignments']}\n"
            f"Active assignments ending within 120 min: {summary['active_ending_soon']}\n"
            f"Incident follow-ups: {summary['incident_followups']}\n"
            f"Patrol follow-ups: {summary['patrol_followups']}\n"
            f"Recent internal updates included: {summary['recent_internal_updates']}\n"
        )
        readme_txt = (
            "Omega Guard Services shift handoff package\n\n"
            "Files included:\n"
            "- summary.txt: handoff metrics and window\n"
            "- shift_coverage.csv: assignments across the handoff lookahead window\n"
            "- incident_followups.csv: incidents requiring continued dispatcher attention\n"
            "- patrol_followups.csv: patrol gaps requiring follow-up\n"
            "- internal_updates.csv: latest internal notes for context transfer\n"
        )

        coverage_csv = io.StringIO(newline="")
        coverage_writer = SpreadsheetCsvWriter(coverage_csv)
        coverage_writer.writerow(
            [
                "assignment_id",
                "status",
                "site_name",
                "guard_name",
                "shift_start_utc",
                "shift_end_utc",
                "minutes_until_start",
                "minutes_until_end",
            ]
        )
        for row in handoff["coverage_rows"]:
            coverage_writer.writerow(
                [
                    row["assignment_id"],
                    row["status"],
                    row["site_name"],
                    row["guard_name"],
                    row["shift_start"],
                    row["shift_end"],
                    row["minutes_until_start"],
                    row["minutes_until_end"],
                ]
            )

        incident_followups_csv = io.StringIO(newline="")
        incident_followups_writer = SpreadsheetCsvWriter(incident_followups_csv)
        incident_followups_writer.writerow(
            [
                "incident_id",
                "site_name",
                "guard_name",
                "severity",
                "status",
                "sla_state",
                "minutes_to_breach",
                "last_dispatch_ack_at_utc",
                "created_at_utc",
                "title",
            ]
        )
        for incident in handoff["incident_followups"]:
            incident_followups_writer.writerow(
                [
                    incident["id"],
                    incident["site_name"],
                    incident["guard_name"],
                    incident["severity"],
                    incident["status"],
                    incident["sla_state"],
                    incident["minutes_to_breach"],
                    incident["last_dispatch_ack_at"],
                    incident["created_at"],
                    incident["title"],
                ]
            )

        patrol_followups_csv = io.StringIO(newline="")
        patrol_followups_writer = SpreadsheetCsvWriter(patrol_followups_csv)
        patrol_followups_writer.writerow(
            [
                "assignment_id",
                "site_name",
                "guard_name",
                "last_check_type",
                "last_check_at_utc",
                "stale_minutes",
                "alert_reason",
            ]
        )
        for alert in handoff["patrol_followups"]:
            patrol_followups_writer.writerow(
                [
                    alert["assignment_id"],
                    alert["site_name"],
                    alert["guard_name"],
                    alert["last_check_type"],
                    alert["last_check_at"],
                    alert["stale_minutes"],
                    alert["alert_reason"],
                ]
            )

        internal_updates_csv = io.StringIO(newline="")
        internal_updates_writer = SpreadsheetCsvWriter(internal_updates_csv)
        internal_updates_writer.writerow(
            ["created_at_utc", "site_name", "author_name", "message"]
        )
        for update in handoff["recent_internal_updates"]:
            internal_updates_writer.writerow(
                [
                    update["created_at"],
                    update["site_name"],
                    update["author_name"],
                    update["message"],
                ]
            )

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("README.txt", readme_txt)
            archive.writestr("summary.txt", summary_txt)
            archive.writestr("shift_coverage.csv", coverage_csv.getvalue())
            archive.writestr("incident_followups.csv", incident_followups_csv.getvalue())
            archive.writestr("patrol_followups.csv", patrol_followups_csv.getvalue())
            archive.writestr("internal_updates.csv", internal_updates_csv.getvalue())

        archive_buffer.seek(0)
        filename = f"dispatcher-shift-handoff-{datetime.now(timezone.utc).strftime('%Y%m%d')}.zip"
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
            guard_row = conn.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'guard' AND disabled_at IS NULL", (guard_user_id,)
            ).fetchone()
            if guard_row is None:
                flash("Select a guard with access enabled.", "error")
                return redirect(url_for("dashboard"))

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

            conn.execute(
                """
                INSERT INTO assignments
                    (site_id, guard_user_id, shift_start, shift_end, status, source_system, created_at)
                VALUES (?, ?, ?, ?, 'scheduled', 'manual', ?)
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

    @app.post("/dispatcher/incidents/<int:incident_id>/ack")
    @roles_required("dispatcher")
    def acknowledge_incident(incident_id: int):
        assert g.user is not None
        note = (request.form.get("note") or "").strip()

        incident = fetch_one(
            """
            SELECT id, site_id, title, severity, status
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        )
        if incident is None:
            flash("Incident not found.", "error")
            return redirect(url_for("dashboard"))

        if incident["status"] not in {"open", "in_review"}:
            flash("Acknowledgement applies to open or in-review incidents only.", "warning")
            return redirect(url_for("dashboard"))

        target_minutes = incident_sla_target_minutes(incident["severity"])
        ack_message = (
            f"[ACK] Dispatcher acknowledged incident #{incident['id']} "
            f"(target {target_minutes} min)."
        )
        if note:
            ack_message = f"{ack_message} Note: {note}"

        execute(
            """
            INSERT INTO updates (site_id, incident_id, author_user_id, audience, message, created_at)
            VALUES (?, ?, ?, 'internal', ?, ?)
            """,
            (incident["site_id"], incident["id"], g.user["id"], ack_message, utc_now_iso()),
        )
        execute(
            """
            UPDATE incidents
            SET updated_at = ?
            WHERE id = ?
            """,
            (utc_now_iso(), incident["id"]),
        )

        flash("Incident acknowledgement recorded.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/dispatcher/connecteam/template")
    @roles_required("dispatcher")
    def download_connecteam_template():
        template_csv = io.StringIO(newline="")
        writer = csv.writer(template_csv)
        writer.writerow(
            [
                "shift id",
                "site",
                "guard username",
                "shift start",
                "shift end",
                "job id",
                "notes",
            ]
        )
        writer.writerow(
            [
                "ct-shift-10001",
                "Kiawah River",
                "guard.alpha",
                "2026-04-08T08:00:00Z",
                "2026-04-08T16:00:00Z",
                "ct-job-501",
                "Front gate coverage",
            ]
        )
        writer.writerow(
            [
                "ct-shift-10002",
                "The Belmont",
                "guard.bravo",
                "2026-04-08T16:00:00Z",
                "2026-04-09T00:00:00Z",
                "ct-job-502",
                "Evening lobby rotation",
            ]
        )

        filename = f"connecteam-shift-import-template-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
        response = make_response(template_csv.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Cache-Control"] = "no-store"
        return response

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

        created = 0
        updated = 0
        skipped = 0
        skip_reasons: dict[str, int] = {}
        skipped_rows_preview: list[str] = []
        import_now = utc_now_iso()

        def record_skip(reason: str, row_number: int, details: str) -> None:
            nonlocal skipped
            skipped += 1
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            if len(skipped_rows_preview) < 5:
                skipped_rows_preview.append(f"row {row_number}: {details}")

        with get_conn() as conn:
            for row_number, row in enumerate(reader, start=2):
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
                external_shift_id = pick_csv_value(
                    row,
                    [
                        "shift id",
                        "shift_id",
                        "id",
                        "timesheet id",
                        "timesheet_id",
                        "schedule id",
                    ],
                )
                external_job_id = pick_csv_value(
                    row,
                    [
                        "job id",
                        "job_id",
                        "job code",
                        "position id",
                        "task id",
                    ],
                )

                if not site_name or not guard_identifier or not shift_start or not shift_end:
                    record_skip(
                        "missing_required_fields",
                        row_number,
                        "site/guard/shift start/shift end required",
                    )
                    continue

                shift_start_dt = parse_shift_timestamp(shift_start)
                shift_end_dt = parse_shift_timestamp(shift_end)
                if shift_start_dt is None or shift_end_dt is None:
                    record_skip(
                        "invalid_datetime",
                        row_number,
                        f"could not parse start '{shift_start}' or end '{shift_end}'",
                    )
                    continue
                if shift_end_dt <= shift_start_dt:
                    record_skip(
                        "invalid_shift_window",
                        row_number,
                        "shift end must be after shift start",
                    )
                    continue

                shift_start_utc = to_utc_iso(shift_start_dt)
                shift_end_utc = to_utc_iso(shift_end_dt)

                guard = conn.execute(
                    """
                    SELECT id, disabled_at
                    FROM users
                    WHERE role = 'guard'
                      AND (LOWER(username) = LOWER(?) OR LOWER(full_name) = LOWER(?))
                    ORDER BY CASE WHEN LOWER(username) = LOWER(?) THEN 0 ELSE 1 END, id
                    LIMIT 1
                    """,
                    (guard_identifier, guard_identifier, guard_identifier),
                ).fetchone()
                if guard is None or guard["disabled_at"] is not None:
                    record_skip(
                        "guard_not_found",
                        row_number,
                        f"guard '{guard_identifier}' is unknown or disabled",
                    )
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

                normalized_payload = {
                    str(k or ""): (v or "").strip()
                    for k, v in row.items()
                }
                source_payload = json.dumps(normalized_payload, sort_keys=True)

                if external_shift_id:
                    existing_external = conn.execute(
                        """
                        SELECT id, status
                        FROM assignments
                        WHERE external_shift_id = ?
                        LIMIT 1
                        """,
                        (external_shift_id,),
                    ).fetchone()
                    if existing_external is not None:
                        if existing_external["status"] in {"active", "completed"}:
                            record_skip(
                                "existing_locked_shift",
                                row_number,
                                f"external shift {external_shift_id} already active/completed",
                            )
                            continue
                        conn.execute(
                            """
                            UPDATE assignments
                            SET site_id = ?,
                                guard_user_id = ?,
                                shift_start = ?,
                                shift_end = ?,
                                status = 'scheduled',
                                source_system = ?,
                                external_job_id = ?,
                                source_payload = ?,
                                imported_at = ?
                            WHERE id = ?
                            """,
                            (
                                site_id,
                                guard["id"],
                                shift_start_utc,
                                shift_end_utc,
                                CONNECTEAM_SOURCE_SYSTEM,
                                external_job_id or None,
                                source_payload,
                                import_now,
                                existing_external["id"],
                            ),
                        )
                        updated += 1
                        continue

                exact_duplicate = conn.execute(
                    """
                    SELECT id
                    FROM assignments
                    WHERE source_system = ?
                      AND site_id = ?
                      AND guard_user_id = ?
                      AND shift_start = ?
                      AND shift_end = ?
                    LIMIT 1
                    """,
                    (
                        CONNECTEAM_SOURCE_SYSTEM,
                        site_id,
                        guard["id"],
                        shift_start_utc,
                        shift_end_utc,
                    ),
                ).fetchone()
                if exact_duplicate is not None:
                    record_skip(
                        "duplicate_shift_window",
                        row_number,
                        "same guard/site/start/end already imported",
                    )
                    continue

                conn.execute(
                    """
                    INSERT INTO assignments
                        (site_id, guard_user_id, shift_start, shift_end, status, source_system, external_shift_id, external_job_id, source_payload, imported_at, created_at)
                    VALUES (?, ?, ?, ?, 'scheduled', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        site_id,
                        guard["id"],
                        shift_start_utc,
                        shift_end_utc,
                        CONNECTEAM_SOURCE_SYSTEM,
                        external_shift_id or None,
                        external_job_id or None,
                        source_payload,
                        import_now,
                        import_now,
                    ),
                )
                created += 1

            conn.commit()

        flash(
            (
                "Connecteam import complete: "
                f"{created} created, {updated} updated, {skipped} skipped."
            ),
            "success",
        )
        if skip_reasons:
            reason_text = ", ".join(
                f"{reason}:{count}" for reason, count in sorted(skip_reasons.items())
            )
            flash(f"Skipped reason breakdown: {reason_text}", "warning")
        if skipped_rows_preview:
            flash(
                "Sample skipped rows: " + " | ".join(skipped_rows_preview),
                "warning",
            )
        return redirect(url_for("dashboard"))

    def record_checkin(guard_id, assignment_id, check_type, note, captured_at, event_id=None):
        received_at = utc_now_iso()
        with get_conn() as db:
            if app.config["DB_BACKEND"] == "sqlite":
                db.execute("BEGIN IMMEDIATE")
                lock = ""
            else:
                lock = " FOR UPDATE"
            assignment = db.execute(
                "SELECT id FROM assignments WHERE id = ? AND guard_user_id = ?" + lock,
                (assignment_id, guard_id),
            ).fetchone()
            if assignment is None:
                return None, "Assignment not found for your user.", 404

            checkin = db.execute(
                """
                INSERT INTO checkins
                    (assignment_id, guard_user_id, check_type, note, created_at, client_event_id, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (guard_user_id, client_event_id) DO NOTHING
                RETURNING id, synced_at
                """,
                (assignment_id, guard_id, check_type, note, captured_at, event_id,
                 received_at if event_id else None),
            ).fetchone()
            if checkin is None:
                previous = db.execute(
                    """
                    SELECT id, assignment_id, check_type, note, created_at, synced_at
                    FROM checkins WHERE guard_user_id = ? AND client_event_id = ?
                    """,
                    (guard_id, event_id),
                ).fetchone()
                original = (previous["assignment_id"], previous["check_type"],
                            previous["note"], previous["created_at"])
                if original != (assignment_id, check_type, note, captured_at):
                    return None, "This check-in ID was already used for a different entry.", 409
                return previous, None, 200

            if check_type in {"IN", "OUT"}:
                latest = db.execute(
                    """
                    SELECT id FROM checkins
                    WHERE assignment_id = ? AND check_type IN ('IN', 'OUT')
                    ORDER BY created_at DESC, id DESC LIMIT 1
                    """,
                    (assignment_id,),
                ).fetchone()
                if latest["id"] == checkin["id"]:
                    db.execute(
                        "UPDATE assignments SET status = ? WHERE id = ?",
                        ("active" if check_type == "IN" else "completed", assignment_id),
                    )
            db.commit()
            return checkin, None, 201

    def checkin_form_fields():
        assignment_id = request.form.get("assignment_id", "").strip()
        check_type = request.form.get("check_type", "").strip().upper()
        note = request.form.get("note", "").strip()
        if not re.fullmatch(r"[0-9]{1,19}", assignment_id) or not 0 < int(assignment_id) < 2**63:
            return None, "Select a valid assignment."
        if check_type not in ALLOWED_CHECKIN_TYPES:
            return None, "Invalid check-in type."
        if len(note) > 2000 or "\x00" in note:
            return None, "Use a note of 2,000 characters or fewer with no null characters."
        return (int(assignment_id), check_type, note), None

    @app.post("/guard/checkins")
    @roles_required("guard")
    def guard_checkin():
        fields, error = checkin_form_fields()
        if fields is not None:
            _, error, _ = record_checkin(g.user["id"], *fields, utc_now_iso())
        flash(error or "Check-in recorded.", "error" if error else "success")
        return redirect(url_for("dashboard"))

    @app.get("/guard/checkins/offline")
    def offline_checkins():
        return app.send_static_file("offline-checkins.html")

    @app.get("/guard/checkins/worker.js")
    def checkin_worker():
        return app.send_static_file("checkin-worker.js")

    @app.get("/guard/checkins/session")
    @roles_required("guard")
    def checkin_sync_session():
        return jsonify(guard_id=str(g.user["id"]), csrf_token=csrf_token())

    @app.post("/guard/checkins/sync")
    @roles_required("guard")
    def sync_checkin():
        if request.form.get("guard_id") != str(g.user["id"]):
            return jsonify(error="Sign in with the guard account that saved this check-in."), 403
        fields, error = checkin_form_fields()
        if fields is None:
            return jsonify(error=error), 422
        try:
            event_id = str(UUID(request.form.get("event_id", "")))
            timestamp = request.form.get("captured_at", "")
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", timestamp):
                raise ValueError("Invalid capture timestamp")
            captured = parse_iso_to_utc(timestamp)
        except ValueError:
            return jsonify(error="Invalid check-in ID or capture time."), 422
        if captured is None or captured > datetime.now(timezone.utc) + timedelta(minutes=5):
            return jsonify(error="Check the device clock. Capture time is invalid or in the future."), 422

        checkin, error, status = record_checkin(
            g.user["id"], *fields, to_utc_iso(captured), event_id
        )
        if error:
            return jsonify(error=error), status
        return jsonify(event_id=event_id, checkin_id=checkin["id"], synced_at=checkin["synced_at"]), status

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

    def late_sync_delay_minutes(receipt):
        captured = parse_iso_to_utc(receipt["created_at"])
        synced = parse_iso_to_utc(receipt["synced_at"])
        if captured is None or synced is None:
            return None
        delay = synced - captured
        if delay < timedelta(minutes=late_sync_minutes):
            return None
        return int(delay.total_seconds()) // 60

    def recent_checkin_receipts():
        rows = fetch_all(
            """
            SELECT c.id, c.assignment_id, c.check_type, c.created_at, c.synced_at,
                   u.full_name AS guard_name, s.name AS site_name,
                   c.acknowledged_at, dispatcher.full_name AS acknowledged_by
            FROM checkins c
            JOIN users u ON u.id = c.guard_user_id
            JOIN assignments a ON a.id = c.assignment_id
            JOIN sites s ON s.id = a.site_id
            LEFT JOIN users dispatcher ON dispatcher.id = c.acknowledged_by
            ORDER BY COALESCE(c.synced_at, c.created_at) DESC, c.id DESC
            LIMIT 30
            """
        )
        return [{**dict(row), "late_minutes": late_sync_delay_minutes(row)} for row in rows]

    def pending_checkin_review():
        if app.config["DB_BACKEND"] == "postgres":
            delay = "EXTRACT(EPOCH FROM (CAST(c.synced_at AS timestamptz) - CAST(c.created_at AS timestamptz)))"
        else:
            delay = "CAST(strftime('%s', c.synced_at) AS INTEGER) - CAST(strftime('%s', c.created_at) AS INTEGER)"
        rows = fetch_all(
            f"""
            SELECT c.id, c.assignment_id, c.check_type, c.created_at, c.synced_at,
                   u.full_name AS guard_name, s.name AS site_name,
                   c.acknowledged_at, COUNT(*) OVER () AS pending_count
            FROM checkins c
            JOIN users u ON u.id = c.guard_user_id
            JOIN assignments a ON a.id = c.assignment_id
            JOIN sites s ON s.id = a.site_id
            WHERE c.acknowledged_at IS NULL
              AND CASE WHEN c.synced_at IS NOT NULL THEN ({delay}) >= ? ELSE FALSE END
            ORDER BY c.synced_at, c.id
            LIMIT 30
            """,
            (late_sync_minutes * 60,),
        )
        count = rows[0]["pending_count"] if rows else 0
        return [{**dict(row), "late_minutes": late_sync_delay_minutes(row)} for row in rows], count

    @app.get("/dispatcher/checkin-receipts")
    @roles_required("dispatcher")
    def checkin_receipts():
        markup = render_template("_checkin_receipt_rows.html", received_checkins=recent_checkin_receipts())
        if request.args.get("include_review") == "1":
            review_checkins, pending_count = pending_checkin_review()
            response = jsonify(
                receipts=markup,
                review=render_template("_checkin_receipt_rows.html", received_checkins=review_checkins, review_queue=True),
                pending_count=pending_count,
            )
        else:
            response = make_response(markup)
        response.cache_control.no_store = True
        return response

    @app.post("/dispatcher/checkin-receipts/<int:checkin_id>/ack")
    @roles_required("dispatcher")
    def acknowledge_checkin_receipt(checkin_id):
        if not 0 < checkin_id < 2**63:
            abort(404)
        receipt = fetch_one(
            "SELECT created_at, synced_at, acknowledged_at FROM checkins WHERE id = ?",
            (checkin_id,),
        )
        if receipt is None:
            abort(404)
        if receipt["acknowledged_at"] is None:
            if late_sync_delay_minutes(receipt) is None:
                abort(409, description="Only late check-ins can be acknowledged.")
            execute(
                """
                UPDATE checkins SET acknowledged_at = ?, acknowledged_by = ?
                WHERE id = ? AND acknowledged_at IS NULL
                """,
                (utc_now_iso(), g.user["id"], checkin_id),
            )

        if request.accept_mimetypes.best == "application/json":
            return "", 204
        return redirect(url_for("dashboard", _anchor="checkin-receipts"), code=303)

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
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            )
            WHERE u.role = 'guard'
            ORDER BY u.full_name
            """
        )
        return jsonify({"guards": [dict(row) for row in guards]})

    return app


if __name__ == "__main__":
    local_demo = os.getenv("APP_DEMO_MODE") == "1"
    if local_demo and (os.getenv("DATABASE_URL") or "").strip():
        raise RuntimeError("Clear DATABASE_URL before starting the local demo.")
    local_config = {"SESSION_COOKIE_SECURE": False}
    if local_demo:
        local_config.update(
            DEMO_MODE=True,
            DATABASE=os.path.join(os.path.dirname(__file__), "data", "demo.db"),
        )
    app = create_app(local_config)
    app.run(host="127.0.0.1", port=8000)
else:
    app = create_app()
