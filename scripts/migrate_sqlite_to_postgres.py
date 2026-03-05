#!/usr/bin/env python3
"""Copy Secure Ops Portal data from SQLite into Postgres.

Usage:
  python scripts/migrate_sqlite_to_postgres.py \
    --sqlite-path /path/to/ops_portal.db \
    --postgres-url postgresql://user:pass@host:5432/db

Defaults:
  --sqlite-path uses DATABASE_PATH or ./data/ops_portal.db
  --postgres-url uses DATABASE_URL
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from typing import Iterable

import psycopg
from psycopg import sql

TABLES_IN_ORDER = [
    "users",
    "sites",
    "assignments",
    "checkins",
    "incidents",
    "updates",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate Secure Ops Portal data from SQLite to Postgres."
    )
    parser.add_argument(
        "--sqlite-path",
        default=os.getenv("DATABASE_PATH", "./data/ops_portal.db"),
        help="Path to SQLite DB (default: DATABASE_PATH or ./data/ops_portal.db)",
    )
    parser.add_argument(
        "--postgres-url",
        default=os.getenv("DATABASE_URL", ""),
        help="Postgres connection string (default: DATABASE_URL)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be migrated without writing to Postgres.",
    )
    return parser.parse_args()


def get_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row[1] for row in rows]


def fetch_table_rows(conn: sqlite3.Connection, table: str, columns: Iterable[str]) -> list[tuple]:
    cols = ", ".join(columns)
    return conn.execute(f"SELECT {cols} FROM {table}").fetchall()


def upsert_table(pg_conn: psycopg.Connection, table: str, columns: list[str], rows: list[tuple]) -> None:
    if not rows:
        return

    update_columns = [col for col in columns if col != "id"]

    col_identifiers = sql.SQL(", ").join(sql.Identifier(col) for col in columns)
    value_placeholders = sql.SQL(", ").join(sql.Placeholder() for _ in columns)

    if update_columns:
        updates = sql.SQL(", ").join(
            sql.SQL("{} = EXCLUDED.{}").format(sql.Identifier(col), sql.Identifier(col))
            for col in update_columns
        )
        query = sql.SQL(
            """
            INSERT INTO {table} ({columns})
            VALUES ({values})
            ON CONFLICT (id) DO UPDATE SET {updates}
            """
        ).format(
            table=sql.Identifier(table),
            columns=col_identifiers,
            values=value_placeholders,
            updates=updates,
        )
    else:
        query = sql.SQL(
            """
            INSERT INTO {table} ({columns})
            VALUES ({values})
            ON CONFLICT (id) DO NOTHING
            """
        ).format(
            table=sql.Identifier(table),
            columns=col_identifiers,
            values=value_placeholders,
        )

    with pg_conn.cursor() as cur:
        cur.executemany(query, rows)


def reset_sequence(pg_conn: psycopg.Connection, table: str) -> None:
    with pg_conn.cursor() as cur:
        cur.execute(
            sql.SQL(
                """
                SELECT setval(
                    pg_get_serial_sequence(%s, 'id'),
                    COALESCE((SELECT MAX(id) FROM {table}), 1),
                    true
                )
                """
            ).format(table=sql.Identifier(table)),
            (table,),
        )


def main() -> int:
    args = parse_args()

    if not args.postgres_url:
        print("Error: --postgres-url (or DATABASE_URL) is required.", file=sys.stderr)
        return 2

    if not os.path.exists(args.sqlite_path):
        print(f"Error: SQLite DB not found at {args.sqlite_path}", file=sys.stderr)
        return 2

    sqlite_conn = sqlite3.connect(args.sqlite_path)
    try:
        all_data: dict[str, tuple[list[str], list[tuple]]] = {}
        for table in TABLES_IN_ORDER:
            columns = get_columns(sqlite_conn, table)
            rows = fetch_table_rows(sqlite_conn, table, columns)
            all_data[table] = (columns, rows)

        print("Planned migration:")
        for table in TABLES_IN_ORDER:
            print(f"- {table}: {len(all_data[table][1])} row(s)")

        if args.dry_run:
            print("Dry run complete. No changes written.")
            return 0

        with psycopg.connect(args.postgres_url) as pg_conn:
            for table in TABLES_IN_ORDER:
                columns, rows = all_data[table]
                upsert_table(pg_conn, table, columns, rows)
                reset_sequence(pg_conn, table)
                print(f"Migrated {table}: {len(rows)} row(s)")
            pg_conn.commit()

        print("Migration complete.")
        return 0
    finally:
        sqlite_conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
