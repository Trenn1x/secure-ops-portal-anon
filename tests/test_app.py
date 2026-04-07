import io
import sqlite3
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test.db"
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "DATABASE": str(db_path),
        }
    )
    with app.test_client() as client:
        yield client, db_path


def login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def test_login_and_guard_dashboard(client):
    web, _ = client
    response = login(web, "guard.alpha", "ops123!")
    assert response.status_code == 200
    assert b"Log Check-In" in response.data


def test_guard_can_submit_incident(client):
    web, db_path = client
    login(web, "guard.alpha", "ops123!")

    with sqlite3.connect(db_path) as conn:
        assignment = conn.execute(
            "SELECT id FROM assignments WHERE guard_user_id = (SELECT id FROM users WHERE username='guard.alpha') LIMIT 1"
        ).fetchone()
    assert assignment is not None

    response = web.post(
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

    response = web.post(
        "/dispatcher/connecteam/import",
        data={"csv_file": (io.BytesIO(csv_data.encode("utf-8")), "shifts.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Connecteam import complete" in response.data


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

    ack = web.post(
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
