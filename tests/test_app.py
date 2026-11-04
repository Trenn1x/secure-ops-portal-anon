import io
import os
import re
import sqlite3
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

import pytest

from werkzeug.security import generate_password_hash

with TemporaryDirectory() as import_db_dir:
    with patch.dict(os.environ, {
        "APP_SECRET": "test-import-secret",
        "DATABASE_URL": "",
        "DATABASE_PATH": str(Path(import_db_dir) / "import.db"),
    }):
        from app import create_app


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test.db"
    app = create_app(
        {
            "TESTING": True,
            "DEMO_MODE": True,
            "CHECKIN_LATE_SYNC_MINUTES": 5,
            "SECRET_KEY": "test-secret",
            "DATABASE": str(db_path),
        }
    )
    with app.test_client() as client:
        yield client, db_path


def login(client, username, password):
    page = client.get("/login")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token.decode()},
        follow_redirects=True,
    )


def post_form(web, path, *, data=None, **kwargs):
    with web.session_transaction() as session:
        token = session["csrf_token"]
    return web.post(path, data={**(data or {}), "csrf_token": token}, **kwargs)


def test_postgres_checkin_workflow_smoke():
    database_url = os.getenv("OMEGA_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("Set OMEGA_TEST_POSTGRES_URL to a fresh disposable PostgreSQL database.")

    app = create_app({
        "TESTING": True,
        "DATABASE": database_url,
        "SECRET_KEY": "postgres-smoke-test-secret",
        "CHECKIN_LATE_SYNC_MINUTES": 5,
    })
    assert app.config["DB_BACKEND"] == "postgres"
    runner = app.test_cli_runner()
    password = "disposable smoke test passphrase"
    for role in ("dispatcher", "guard"):
        result = runner.invoke(
            args=["provision-user", "--username", f"smoke.{role}", "--role", role, "--full-name", f"Smoke {role}"],
            input=f"{password}\n{password}\n",
        )
        assert result.exit_code == 0, result.output

    dispatch, guard = app.test_client(), app.test_client()
    assert b"Dispatcher Workspace" in login(dispatch, "smoke.dispatcher", password).data
    assert b"Guard Workspace" in login(guard, "smoke.guard", password).data
    guard_id = guard.get("/guard/checkins/session").json["guard_id"]
    now = datetime.now(timezone.utc)
    assignment = post_form(
        dispatch, "/dispatcher/assignments", follow_redirects=True,
        data={
            "guard_user_id": guard_id,
            "new_site_name": "PostgreSQL Smoke Site",
            "shift_start": (now - timedelta(minutes=30)).isoformat(),
            "shift_end": (now + timedelta(hours=7)).isoformat(),
        },
    )
    assert b"Shift assignment created." in assignment.data
    option = re.search(rb'<option value="(\d+)">#\d+ PostgreSQL Smoke Site', guard.get("/").data)
    assert option is not None

    event = {
        "guard_id": guard_id,
        "assignment_id": option.group(1).decode(),
        "check_type": "IN",
        "event_id": str(uuid4()),
        "captured_at": (now - timedelta(minutes=10)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }
    first = post_form(guard, "/guard/checkins/sync", data=event)
    assert first.status_code == 201, first.data
    retry = post_form(guard, "/guard/checkins/sync", data=event)
    assert retry.status_code == 200
    assert retry.json == first.json

    receipts = "/dispatcher/checkin-receipts?include_review=1"
    assert dispatch.get(receipts).json["pending_count"] == 1
    acknowledged = post_form(
        dispatch, f"/dispatcher/checkin-receipts/{first.json['checkin_id']}/ack",
        headers={"Accept": "application/json"},
    )
    assert acknowledged.status_code == 204
    assert dispatch.get(receipts).json["pending_count"] == 0


def test_operator_can_provision_a_fresh_production_database(tmp_path):
    database = tmp_path / "production.db"
    app = create_app({"DATABASE": str(database), "SECRET_KEY": "test-secret"})
    runner = app.test_cli_runner()
    password = "a long unique test passphrase"

    for username, role in (
        ("Dispatch.Lead", "dispatcher"),
        ("guard.smith", "guard"),
        ("client.river", "client"),
        ("client.other", "client"),
    ):
        result = runner.invoke(
            args=["provision-user", "--username", username, "--role", role, "--full-name", username],
            input=f"{password}\n{password}\n",
        )
        assert result.exit_code == 0, result.output
        assert password not in result.output

    duplicate = runner.invoke(
        args=["provision-user", "--username", " DISPATCH.LEAD ", "--role", "guard", "--full-name", "Duplicate"],
        input="another long test passphrase\nanother long test passphrase\n",
    )
    assert "username already exists" in duplicate.output
    reserved = runner.invoke(
        args=["provision-user", "--username", "dispatcher", "--role", "dispatcher", "--full-name", "Reserved"]
    )
    assert "reserved for local demos" in reserved.output

    def provision_site(name, client=None):
        args = ["provision-site", "--name", name]
        if client:
            args += ["--client", client]
        return runner.invoke(args=args)

    assert provision_site("River Site").exit_code == 0
    assert provision_site("River Site", "CLIENT.RIVER").exit_code == 0
    assert provision_site("River Site", "client.river").exit_code == 0
    assert "already linked to another client" in provision_site("River Site", "client.other").output
    assert "already linked to another site" in provision_site("Other Site", "client.river").output
    assert "Choose a provisioned client" in provision_site("Other Site", "guard.smith").output

    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE is_demo = 0").fetchone() == (4,)
        assert conn.execute("SELECT COUNT(*) FROM sites").fetchone() == (1,)

    with app.test_client() as web:
        dispatch = login(web, "dispatch.lead", password)
        assert b"Dispatcher Workspace" in dispatch.data
        post_form(web, "/logout")
        client = login(web, "client.river", password)
        assert b"River Site" in client.data


@pytest.mark.parametrize("secret", [None, "", "   ", "ops-portal-dev-secret"])
def test_app_requires_explicit_secret(tmp_path, monkeypatch, secret):
    if secret is None:
        monkeypatch.delenv("APP_SECRET", raising=False)
    else:
        monkeypatch.setenv("APP_SECRET", secret)
    database = tmp_path / "unused.db"
    with pytest.raises(RuntimeError, match="Set APP_SECRET"):
        create_app({"DATABASE": str(database)})
    assert not database.exists()


def test_wsgi_starts_without_demo_users_even_with_demo_flag(tmp_path):
    database = tmp_path / "production.db"
    env = {
        **os.environ,
        "APP_DEMO_MODE": "1",
        "APP_SECRET": "test-wsgi-secret",
        "DATABASE_URL": "",
        "DATABASE_PATH": str(database),
    }
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from app import app; page = app.test_client().get('/login'); "
            "assert page.status_code == 200 and b'Demo Accounts' not in page.data",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        check=True,
    )
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone() == (0,)


def test_legacy_demo_users_lose_access_but_real_users_can_sign_in(client):
    demo_web, db_path = client
    assert b"Log Check-In" in login(demo_web, "guard.alpha", "ops123!").data
    old_cookie = demo_web.get_cookie("session")
    assert old_cookie is not None

    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE users DROP COLUMN is_demo")
        conn.execute(
            "UPDATE users SET password_hash = ?, full_name = ? WHERE username = 'dispatcher'",
            (generate_password_hash("a-real-dispatcher-password"), "Morgan Lee"),
        )
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = 'guard.bravo'",
            (generate_password_hash("rotated-demo-password"),),
        )

    production = create_app({"DATABASE": str(db_path), "SECRET_KEY": "test-secret"})
    web = production.test_client()
    web.set_cookie("session", old_cookie.value)
    assert web.get("/").headers["Location"] == "/login"
    assert b"Invalid username or password." in login(web, "guard.alpha", "ops123!").data
    assert b"Invalid username or password." in login(web, "guard.bravo", "rotated-demo-password").data
    assert b"Signed in." in login(web, "dispatcher", "a-real-dispatcher-password").data
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE is_demo = 1").fetchone() == (3,)
        assert conn.execute("SELECT COUNT(*) FROM assignments").fetchone() == (2,)


def test_password_reset_revokes_only_target_sessions_and_preserves_disabled_status(client):
    dispatch, database = client
    app = create_app({"DATABASE": str(database), "SECRET_KEY": "test-secret", "DEMO_MODE": True})
    runner = app.test_cli_runner()
    original = "original production passphrase"
    replacement = "different production passphrase"
    provisioned = runner.invoke(
        args=["provision-user", "--username", "guard.smith", "--role", "guard", "--full-name", "Sam Smith"],
        input=f"{original}\n{original}\n",
    )
    assert provisioned.exit_code == 0, provisioned.output

    def reset(password):
        return runner.invoke(args=["reset-user-password", " GUARD.SMITH "], input=f"{password}\n{password}\n")

    first, second = app.test_client(), app.test_client()
    for web in (first, second):
        assert b"Signed in." in login(web, "guard.smith", original).data
    login(dispatch, "dispatcher", "ops123!")

    assert reset(original).exit_code != 0
    assert first.get("/guard/checkins/session").status_code == 200
    for _ in range(10):
        login(app.test_client(), "guard.smith", "wrong password")
    assert login(app.test_client(), "guard.smith", original).status_code == 429
    result = reset(replacement)
    assert result.exit_code == 0, result.output
    assert replacement not in result.output
    for web in (first, second):
        assert web.get("/guard/checkins/session").headers["Location"] == "/login"
    assert dispatch.get("/api/status").status_code == 200
    assert b"Invalid username or password." in login(first, "guard.smith", original).data
    assert b"Signed in." in login(first, "guard.smith", replacement).data

    assert runner.invoke(args=["set-user-access", "guard.smith", "disabled"]).exit_code == 0
    assert reset(original).exit_code == 0
    assert b"Invalid username or password." in login(second, "guard.smith", original).data


def test_offboarding_revokes_all_sessions_and_preserves_history(tmp_path):
    database = tmp_path / "offboarding.db"
    app = create_app({"DATABASE": str(database), "SECRET_KEY": "test-secret", "DEMO_MODE": True})
    with sqlite3.connect(database) as db:
        # Treat the seeded guard as a provisioned account while keeping their assignment.
        db.execute("UPDATE users SET username = 'guard.smith', is_demo = 0 WHERE username = 'guard.alpha'")
        guard_id = db.execute("SELECT id FROM users WHERE username = 'guard.smith'").fetchone()[0]

    first, second, dispatch = [app.test_client() for _ in range(3)]
    for web in (first, second):
        assert b"Log Check-In" in login(web, "guard.smith", "ops123!").data
    old_cookie = second.get_cookie("session")
    runner = app.test_cli_runner()
    assert runner.invoke(args=["set-user-access", " GUARD.SMITH ", "disabled"]).exit_code == 0

    assert first.get("/guard/checkins/session").headers["Location"] == "/login"
    assert b"Invalid username or password." in login(first, "guard.smith", "ops123!").data

    login(dispatch, "dispatcher", "ops123!")
    assignment = post_form(dispatch, "/dispatcher/assignments", data={
        "guard_user_id": str(guard_id), "new_site_name": "Uncreated Site",
        "shift_start": "2026-11-04T08:00", "shift_end": "2026-11-04T16:00",
    }, follow_redirects=True)
    assert b"Select a guard with access enabled." in assignment.data
    upload = io.BytesIO(
        b"Site,Guard Username,Shift Start,Shift End\n"
        b"Uncreated Site,guard.smith,2026-11-04T08:00,2026-11-04T16:00\n"
    )
    imported = post_form(dispatch, "/dispatcher/connecteam/import",
                         data={"csv_file": (upload, "shifts.csv")}, follow_redirects=True)
    assert b"guard_not_found" in imported.data

    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM auth_sessions WHERE user_id = ?", (guard_id,)).fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM assignments WHERE guard_user_id = ?", (guard_id,)).fetchone() == (1,)
        assert db.execute("SELECT COUNT(*) FROM sites WHERE name = 'Uncreated Site'").fetchone() == (0,)

    assert runner.invoke(args=["set-user-access", "guard.smith", "enabled"]).exit_code == 0
    second.set_cookie("session", old_cookie.value)
    assert second.get("/guard/checkins/session").headers["Location"] == "/login"
    assert b"Log Check-In" in login(first, "guard.smith", "ops123!").data


def test_login_rechecks_access_after_password_verification(tmp_path, monkeypatch):
    from app import check_password_hash

    database = tmp_path / "login-race.db"
    app = create_app({"DATABASE": str(database), "SECRET_KEY": "test-secret"})
    with sqlite3.connect(database) as db:
        db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at)
            VALUES ('guard.smith', ?, 'guard', 'Sam Smith', '2026-11-04T00:00:00Z')
            """,
            (generate_password_hash("test passphrase"),),
        )

    def verify_then_disable(password_hash, password):
        valid = check_password_hash(password_hash, password)
        assert valid
        result = app.test_cli_runner().invoke(args=["set-user-access", "guard.smith", "disabled"])
        assert result.exit_code == 0, result.output
        return valid

    monkeypatch.setattr("app.check_password_hash", verify_then_disable)
    web = app.test_client()
    assert b"Invalid username or password." in login(web, "guard.smith", "test passphrase").data
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone() == (0,)


def test_logout_revokes_a_copied_cookie_across_workers(client):
    web, database = client
    assert b"Signed in." in login(web, "dispatcher", "ops123!").data
    cookie = web.get_cookie("session")
    assert cookie.secure and cookie.http_only and cookie.same_site == "Lax"
    other_worker = create_app(
        {"DATABASE": str(database), "SECRET_KEY": "test-secret", "DEMO_MODE": True}
    )
    replay = other_worker.test_client()
    replay.set_cookie("session", cookie.value)
    assert replay.get("/api/status").status_code == 200

    assert post_form(web, "/logout").status_code == 302
    assert replay.get("/api/status").headers["Location"] == "/login"
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone() == (0,)


def test_session_expires_from_sign_in_and_old_cookies_require_reauthentication(client, monkeypatch):
    web, database = client
    with web.session_transaction() as legacy:
        legacy["user_id"] = 1
    assert web.get("/api/status").headers["Location"] == "/login"

    assert b"Signed in." in login(web, "dispatcher", "ops123!").data
    with sqlite3.connect(database) as conn:
        expiry = conn.execute("SELECT expires_at FROM auth_sessions").fetchone()[0]
    monkeypatch.setattr("app.time", lambda: expiry - 1)
    assert web.get("/api/status").status_code == 200
    monkeypatch.setattr("app.time", lambda: expiry)
    assert web.get("/api/status").headers["Location"] == "/login"

    assert b"Signed in." in login(web, "dispatcher", "ops123!").data
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone() == (1,)


def test_login_throttle_is_shared_and_denials_do_not_extend_the_window(client, monkeypatch):
    web, database = client
    other_worker = create_app(
        {"DATABASE": str(database), "SECRET_KEY": "test-secret", "DEMO_MODE": True}
    ).test_client()
    monkeypatch.setattr("app.time", lambda: 1000)
    for _ in range(10):
        assert b"Invalid username or password." in login(web, "guard.alpha", "wrong password").data

    limited = login(other_worker, " GUARD.ALPHA ", "ops123!")
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "300"
    assert limited.cache_control.no_store
    assert b"Signed in." in login(web, "guard.bravo", "ops123!").data

    monkeypatch.setattr("app.time", lambda: 1299)
    assert login(other_worker, "guard.alpha", "ops123!").headers["Retry-After"] == "1"
    monkeypatch.setattr("app.time", lambda: 1300)
    assert b"Signed in." in login(other_worker, "guard.alpha", "ops123!").data


def test_source_throttle_ignores_spoofed_forwarding_headers(tmp_path):
    app = create_app({
        "DATABASE": str(tmp_path / "throttle.db"),
        "SECRET_KEY": "test-secret",
        "LOGIN_SOURCE_LIMIT": 2,
    })
    web = app.test_client()
    web.get("/login")
    for index in range(3):
        response = post_form(
            web, "/login",
            data={"username": f"unknown.{index}", "password": "wrong password"},
            headers={"X-Forwarded-For": f"192.0.2.{index + 1}"},
        )
        assert response.status_code == (429 if index == 2 else 200)
    different_peer = post_form(
        web, "/login",
        data={"username": "unknown.3", "password": "wrong password"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.99"},
    )
    assert different_peer.status_code == 200


def test_post_requires_a_token_from_the_current_session(client):
    web, _ = client
    login_page = web.get("/login")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', login_page.data).group(1)
    assert login_page.cache_control.no_store
    assert web.post("/login", data={"username": "dispatcher", "password": "ops123!"}).status_code == 400

    assert login(web, "dispatcher", "ops123!").status_code == 200
    for data in ({}, {"csrf_token": token.decode()}, {"csrf_token": "☃"}):
        assert web.post("/logout", data=data).status_code == 400
    assert web.get("/api/status").status_code == 200
    assert post_form(web, "/logout").status_code == 302


def test_login_and_guard_dashboard(client):
    web, _ = client
    response = login(web, "guard.alpha", "ops123!")
    assert response.status_code == 200
    assert b"Log Check-In" in response.data


def test_offline_checkins_retry_safely_and_dispatch_sees_receipts(client):
    web, db_path = client
    login(web, "guard.alpha", "ops123!")
    session = web.get("/guard/checkins/session").json
    with sqlite3.connect(db_path) as conn:
        assignment, other_assignment = [
            row[0] for row in conn.execute("SELECT id FROM assignments ORDER BY id")
        ]

    now = datetime.now(timezone.utc)
    checkout = {
        "guard_id": session["guard_id"],
        "assignment_id": str(assignment),
        "check_type": "OUT",
        "captured_at": (now - timedelta(minutes=10)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "event_id": str(uuid4()),
        "note": "Finished patrol",
    }
    path = "/guard/checkins/sync"
    assert web.post(path, data=checkout).status_code == 400
    assert post_form(web, path, data={**checkout, "guard_id": "0"}).status_code == 403
    assert post_form(web, path, data={**checkout, "assignment_id": str(other_assignment)}).status_code == 404
    first = post_form(web, path, data=checkout)
    assert first.status_code == 201
    retry = post_form(web, path, data=checkout)
    assert retry.status_code == 200
    assert retry.json == first.json
    assert post_form(web, path, data={**checkout, "note": "different"}).status_code == 409

    checkin = {
        **checkout,
        "check_type": "IN",
        "captured_at": (now - timedelta(hours=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "event_id": str(uuid4()),
        "note": "",
    }
    assert post_form(web, path, data=checkin).status_code == 201
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM checkins").fetchone() == (2,)
        assert conn.execute("SELECT status FROM assignments WHERE id = ?", (assignment,)).fetchone() == ("completed",)

    post_form(web, "/logout")
    dispatch = login(web, "dispatcher", "ops123!")
    assert b"Check-In Receipts" in dispatch.data
    assert b"Synced" in dispatch.data
    assert first.json["synced_at"].encode() in dispatch.data
    guards = web.get("/api/status").json["guards"]
    assert next(guard for guard in guards if guard["username"] == "guard.alpha")["last_check_type"] == "OUT"


def test_live_checkin_receipts_flag_late_syncs_and_require_dispatch(client):
    web, db_path = client
    path = "/dispatcher/checkin-receipts"
    assert web.get(path).headers["Location"] == "/login"
    login(web, "guard.alpha", "ops123!")
    assert web.get(path).headers["Location"] == "/"
    post_form(web, "/logout")

    with sqlite3.connect(db_path) as conn:
        assignment_id, guard_id = conn.execute(
            "SELECT id, guard_user_id FROM assignments ORDER BY id LIMIT 1"
        ).fetchone()
        conn.executemany(
            """
            INSERT INTO checkins (assignment_id, guard_user_id, check_type, created_at, synced_at)
            VALUES (?, ?, 'PATROL', ?, ?)
            """,
            [
                (assignment_id, guard_id, "2026-11-03T10:00:00Z", "2026-11-03T10:05:00Z"),
                (assignment_id, guard_id, "2026-11-03T10:01:00Z", "2026-11-03T10:05:59Z"),
                (assignment_id, guard_id, "2026-11-03T10:06:00Z", None),
            ],
        )

    dashboard = login(web, "dispatcher", "ops123!")
    response = web.get(path)
    assert response.status_code == 200
    assert response.cache_control.no_store
    assert response.data.count(b"Synced late") == 1
    assert b"5 min delay" in response.data
    assert b">Synced</span>" in response.data
    assert b"Direct entry" in response.data
    assert response.data.index(b"Direct entry") < response.data.index(b"Synced late")
    assert response.data.strip() in dashboard.data


def test_late_receipt_acknowledgement_is_dispatch_only_and_idempotent(client):
    web, db_path = client
    with sqlite3.connect(db_path) as conn:
        assignment_id, guard_id = conn.execute(
            "SELECT id, guard_user_id FROM assignments ORDER BY id LIMIT 1"
        ).fetchone()
        late_id, on_time_id = [
            conn.execute(
                """
                INSERT INTO checkins (assignment_id, guard_user_id, check_type, created_at, synced_at)
                VALUES (?, ?, 'PATROL', '2026-11-03T10:00:00Z', ?) RETURNING id
                """,
                (assignment_id, guard_id, synced_at),
            ).fetchone()[0]
            for synced_at in ("2026-11-03T10:05:00Z", "2026-11-03T10:04:59Z")
        ]
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, created_at)
            VALUES ('dispatcher.two', ?, 'dispatcher', 'Second Dispatcher', '2026-11-03T10:00:00Z')
            """,
            (generate_password_hash("second-password"),),
        )

    path = f"/dispatcher/checkin-receipts/{late_id}/ack"
    headers = {"Accept": "application/json"}
    login(web, "guard.alpha", "ops123!")
    assert post_form(web, path, headers=headers).headers["Location"] == "/"
    post_form(web, "/logout")

    login(web, "dispatcher", "ops123!")
    assert web.post(path, headers=headers).status_code == 400
    assert post_form(web, f"/dispatcher/checkin-receipts/{on_time_id}/ack", headers=headers).status_code == 409
    assert post_form(web, path, headers=headers).status_code == 204
    post_form(web, "/logout")

    login(web, "dispatcher.two", "second-password")
    assert post_form(web, path, headers=headers).status_code == 204
    receipt_rows = web.get("/dispatcher/checkin-receipts").data
    assert b"data-late-receipt" in receipt_rows
    assert b"Acknowledged" in receipt_rows
    assert b"Operations Desk" in receipt_rows
    assert b"Second Dispatcher" not in receipt_rows
    assert b"data-receipt-ack" not in receipt_rows


def test_late_review_queue_outlives_recent_receipts_and_refills_after_ack(client):
    web, db_path = client
    with sqlite3.connect(db_path) as conn:
        assignment_id, guard_id = conn.execute(
            "SELECT id, guard_user_id FROM assignments ORDER BY id LIMIT 1"
        ).fetchone()
        late_ids = []
        for index in range(61):
            late = index < 31
            row = conn.execute(
                """
                INSERT INTO checkins (assignment_id, guard_user_id, check_type, created_at, synced_at)
                VALUES (?, ?, 'PATROL', '2026-11-03T10:00:00Z', ?) RETURNING id
                """,
                (assignment_id, guard_id, "2026-11-03T10:05:00Z" if late else None),
            ).fetchone()
            if late:
                late_ids.append(row[0])
        conn.execute("UPDATE checkins SET created_at = '2026-11-03T11:00:00Z' WHERE synced_at IS NULL")

    first = f"/dispatcher/checkin-receipts/{late_ids[0]}/ack"
    last = f"/dispatcher/checkin-receipts/{late_ids[-1]}/ack"
    dashboard = login(web, "dispatcher", "ops123!")
    assert b"31 awaiting acknowledgement" in dashboard.data
    path = "/dispatcher/checkin-receipts?include_review=1"
    response = web.get(path)
    assert response.cache_control.no_store
    assert response.json["pending_count"] == 31
    assert "Synced late" not in response.json["receipts"]
    assert response.json["review"].count("data-receipt-ack") == 30
    assert first in response.json["review"]
    assert last not in response.json["review"]

    assert post_form(web, first, headers={"Accept": "application/json"}).status_code == 204
    updated = web.get(path).json
    assert updated["pending_count"] == 30
    assert first not in updated["review"]
    assert last in updated["review"]


def test_guard_can_submit_incident(client):
    web, db_path = client
    login(web, "guard.alpha", "ops123!")

    with sqlite3.connect(db_path) as conn:
        assignment = conn.execute(
            "SELECT id FROM assignments WHERE guard_user_id = (SELECT id FROM users WHERE username='guard.alpha') LIMIT 1"
        ).fetchone()
    assert assignment is not None

    response = post_form(
        web,
        "/guard/incidents",
        data={
            "assignment_id": str(assignment[0]),
            "title": "Unauthorized rear entry attempt",
            "details": "Observed and de-escalated. No breach.",
            "severity": "high",
            "client_visible": "on",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Incident submitted to dispatch" in response.data


def test_dispatcher_can_import_connecteam_csv(client):
    web, _ = client
    login(web, "dispatcher", "ops123!")

    csv_data = (
        "site,guard username,shift start,shift end\n"
        "Client Site A,guard.alpha,2026-03-05T09:00,2026-03-05T17:00\n"
    )

    response = post_form(
        web,
        "/dispatcher/connecteam/import",
        data={"csv_file": (io.BytesIO(csv_data.encode("utf-8")), "shifts.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Connecteam import complete" in response.data


def test_dispatcher_can_download_connecteam_template(client):
    web, _ = client
    login(web, "dispatcher", "ops123!")

    response = web.get("/dispatcher/connecteam/template", follow_redirects=False)
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/csv")
    assert "attachment;" in response.headers.get("Content-Disposition", "")

    text = response.data.decode("utf-8")
    assert "shift id,site,guard username,shift start,shift end,job id,notes" in text
    assert "ct-shift-10001" in text


def test_connecteam_import_is_idempotent_by_external_shift_id(client):
    web, db_path = client
    login(web, "dispatcher", "ops123!")

    first_csv = (
        "shift id,site,guard username,shift start,shift end,job id\n"
        "ct-shift-777,Client Site A,guard.alpha,2026-04-09T10:00:00Z,2026-04-09T16:00:00Z,ct-job-22\n"
    )
    second_csv = (
        "shift id,site,guard username,shift start,shift end,job id\n"
        "ct-shift-777,Client Site A,guard.alpha,2026-04-09T10:00:00Z,2026-04-09T18:00:00Z,ct-job-22\n"
    )

    first = post_form(
        web,
        "/dispatcher/connecteam/import",
        data={"csv_file": (io.BytesIO(first_csv.encode("utf-8")), "shifts.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert first.status_code == 200
    assert b"1 created" in first.data

    second = post_form(
        web,
        "/dispatcher/connecteam/import",
        data={"csv_file": (io.BytesIO(second_csv.encode("utf-8")), "shifts.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert second.status_code == 200
    assert b"1 updated" in second.data

    with sqlite3.connect(db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM assignments WHERE external_shift_id = 'ct-shift-777'"
        ).fetchone()[0]
        row = conn.execute(
            """
            SELECT shift_end, source_system
            FROM assignments
            WHERE external_shift_id = 'ct-shift-777'
            LIMIT 1
            """
        ).fetchone()

    assert count == 1
    assert row is not None
    assert "18:00:00Z" in row[0]
    assert row[1] == "connecteam"


def test_dispatcher_patrol_alert_workflow(client):
    web, db_path = client
    login(web, "dispatcher", "ops123!")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    old_shift_start = (now - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    old_check_time = (now - timedelta(minutes=95)).isoformat().replace("+00:00", "Z")
    created_at = now.isoformat().replace("+00:00", "Z")

    with sqlite3.connect(db_path) as conn:
        guard_id = conn.execute(
            "SELECT id FROM users WHERE username='guard.alpha'"
        ).fetchone()[0]
        site_id = conn.execute("SELECT id FROM sites LIMIT 1").fetchone()[0]
        assignment_id = conn.execute(
            """
            INSERT INTO assignments (site_id, guard_user_id, shift_start, shift_end, status, created_at)
            VALUES (?, ?, ?, ?, 'active', ?)
            """,
            (site_id, guard_id, old_shift_start, old_shift_start, created_at),
        ).lastrowid
        conn.execute(
            """
            INSERT INTO checkins (assignment_id, guard_user_id, check_type, note, created_at)
            VALUES (?, ?, 'PATROL', ?, ?)
            """,
            (assignment_id, guard_id, "Last patrol logged from test", old_check_time),
        )
        conn.commit()

    dashboard = web.get("/", follow_redirects=True)
    assert dashboard.status_code == 200
    assert b"Patrol Alert Board" in dashboard.data
    assert b"needs follow-up" in dashboard.data

    ack = post_form(
        web,
        f"/dispatcher/alerts/{assignment_id}/ack",
        data={"note": "Supervisor notified and radio check initiated."},
        follow_redirects=True,
    )
    assert ack.status_code == 200
    assert b"acknowledged and logged" in ack.data

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT message FROM updates WHERE message LIKE '%[ALERT ACK]%' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    assert "radio check" in row[0].lower()


def test_client_can_download_report_package(client):
    web, _ = client
    login(web, "client.portal", "ops123!")

    response = web.get("/client/exports/site-package", follow_redirects=False)
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("application/zip")
    assert "attachment;" in response.headers.get("Content-Disposition", "")

    archive = zipfile.ZipFile(io.BytesIO(response.data))
    names = set(archive.namelist())
    assert {"README.txt", "summary.txt", "client_updates.csv", "incident_visibility.csv"} <= names

    summary_text = archive.read("summary.txt").decode("utf-8")
    incidents_csv = archive.read("incident_visibility.csv").decode("utf-8")
    updates_csv = archive.read("client_updates.csv").decode("utf-8")

    assert "Client Site A" in summary_text
    assert "Perimeter access hardware issue" in incidents_csv
    assert "Security team identified an access hardware issue" in updates_csv


def test_dispatcher_can_download_operations_brief_package(client):
    web, db_path = client
    login(web, "dispatcher", "ops123!")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    old_shift_start = (now - timedelta(hours=4)).isoformat().replace("+00:00", "Z")
    old_patrol_time = (now - timedelta(minutes=130)).isoformat().replace("+00:00", "Z")
    created_at = (now - timedelta(minutes=80)).isoformat().replace("+00:00", "Z")

    with sqlite3.connect(db_path) as conn:
        guard_id = conn.execute(
            "SELECT id FROM users WHERE username='guard.alpha'"
        ).fetchone()[0]
        site_id = conn.execute("SELECT id FROM sites LIMIT 1").fetchone()[0]
        assignment_id = conn.execute(
            """
            INSERT INTO assignments (site_id, guard_user_id, shift_start, shift_end, status, created_at)
            VALUES (?, ?, ?, ?, 'active', ?)
            """,
            (site_id, guard_id, old_shift_start, old_shift_start, created_at),
        ).lastrowid
        conn.execute(
            """
            INSERT INTO checkins (assignment_id, guard_user_id, check_type, note, created_at)
            VALUES (?, ?, 'PATROL', ?, ?)
            """,
            (assignment_id, guard_id, "Patrol aging test", old_patrol_time),
        )
        conn.execute(
            """
            INSERT INTO incidents
                (site_id, assignment_id, guard_user_id, title, details, severity, status, client_visible, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'critical', 'open', 1, ?, ?)
            """,
            (
                site_id,
                assignment_id,
                guard_id,
                "Gate forced entry alarm",
                "Critical event waiting dispatch review.",
                created_at,
                created_at,
            ),
        )
        conn.commit()

    response = web.get("/dispatcher/exports/operations-brief", follow_redirects=False)
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("application/zip")
    assert "attachment;" in response.headers.get("Content-Disposition", "")

    archive = zipfile.ZipFile(io.BytesIO(response.data))
    names = set(archive.namelist())
    assert {
        "README.txt",
        "summary.txt",
        "action_queue.csv",
        "patrol_alerts.csv",
        "incidents_watchlist.csv",
        "incident_sla_radar.csv",
        "guard_activity.csv",
    } <= names

    summary_text = archive.read("summary.txt").decode("utf-8")
    action_queue_csv = archive.read("action_queue.csv").decode("utf-8")
    watchlist_csv = archive.read("incidents_watchlist.csv").decode("utf-8")
    incident_sla_csv = archive.read("incident_sla_radar.csv").decode("utf-8")

    assert "Dispatcher Operations Brief" in summary_text
    assert "Patrol alerts needing follow-up" in summary_text
    assert "SLA breached incidents" in summary_text
    assert "Patrol gap" in action_queue_csv
    assert "Gate forced entry alarm" in watchlist_csv
    assert "Gate forced entry alarm" in incident_sla_csv
    assert "breached" in incident_sla_csv

    with sqlite3.connect(db_path) as conn:
        escalation_row = conn.execute(
            """
            SELECT message
            FROM updates
            WHERE message LIKE '[SLA ESCALATION]%'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    assert escalation_row is not None
    assert "exceeded dispatcher acknowledgement sla" in escalation_row[0].lower()


def test_dispatcher_can_acknowledge_incident(client):
    web, db_path = client
    login(web, "dispatcher", "ops123!")

    with sqlite3.connect(db_path) as conn:
        incident_id = conn.execute(
            "SELECT id FROM incidents WHERE status IN ('open', 'in_review') ORDER BY id ASC LIMIT 1"
        ).fetchone()[0]

    response = post_form(
        web,
        f"/dispatcher/incidents/{incident_id}/ack",
        data={"note": "Supervisor taking ownership."},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"acknowledgement recorded" in response.data.lower()

    with sqlite3.connect(db_path) as conn:
        ack_row = conn.execute(
            """
            SELECT message
            FROM updates
            WHERE incident_id = ? AND message LIKE '[ACK]%'
            ORDER BY id DESC
            LIMIT 1
            """,
            (incident_id,),
        ).fetchone()
    assert ack_row is not None
    assert "taking ownership" in ack_row[0].lower()


def test_dispatcher_can_download_shift_handoff_package(client):
    web, db_path = client
    login(web, "dispatcher", "ops123!")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    upcoming_start = (now + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    upcoming_end = (now + timedelta(hours=10)).isoformat().replace("+00:00", "Z")
    created_at = (now - timedelta(minutes=50)).isoformat().replace("+00:00", "Z")

    with sqlite3.connect(db_path) as conn:
        guard_id = conn.execute(
            "SELECT id FROM users WHERE username='guard.bravo'"
        ).fetchone()[0]
        site_id = conn.execute("SELECT id FROM sites LIMIT 1").fetchone()[0]
        assignment_id = conn.execute(
            """
            INSERT INTO assignments (site_id, guard_user_id, shift_start, shift_end, status, created_at)
            VALUES (?, ?, ?, ?, 'scheduled', ?)
            """,
            (site_id, guard_id, upcoming_start, upcoming_end, created_at),
        ).lastrowid
        conn.execute(
            """
            INSERT INTO incidents
                (site_id, assignment_id, guard_user_id, title, details, severity, status, client_visible, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'high', 'open', 1, ?, ?)
            """,
            (
                site_id,
                assignment_id,
                guard_id,
                "Lobby access control fault",
                "Needs follow-up for handoff.",
                created_at,
                created_at,
            ),
        )
        conn.commit()

    response = web.get("/dispatcher/exports/shift-handoff", follow_redirects=False)
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("application/zip")
    assert "attachment;" in response.headers.get("Content-Disposition", "")

    archive = zipfile.ZipFile(io.BytesIO(response.data))
    names = set(archive.namelist())
    assert {
        "README.txt",
        "summary.txt",
        "shift_coverage.csv",
        "incident_followups.csv",
        "patrol_followups.csv",
        "internal_updates.csv",
    } <= names

    summary_text = archive.read("summary.txt").decode("utf-8")
    coverage_csv = archive.read("shift_coverage.csv").decode("utf-8")
    followups_csv = archive.read("incident_followups.csv").decode("utf-8")

    assert "Shift Handoff Brief" in summary_text
    assert "Assignments in handoff window" in summary_text
    assert "Guard Bravo" in coverage_csv
    assert "Lobby access control fault" in followups_csv
