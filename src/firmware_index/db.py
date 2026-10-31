"""The database on the data volume: sources, rules, uploads, checked files and runs."""

import datetime
import json
import sqlite3
from pathlib import Path

from firmware_index import sources

SCHEMA = """
CREATE TABLE sources (
  name TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  config TEXT NOT NULL,
  priority INTEGER NOT NULL,
  delay_days INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_ok TEXT,
  last_error TEXT,
  last_candidates TEXT
);
CREATE TABLE rules (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  match TEXT NOT NULL,
  set_fields TEXT NOT NULL DEFAULT '{}',
  note TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  author TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL
);
CREATE TABLE uploads (
  sha512 TEXT PRIMARY KEY,
  file_name TEXT NOT NULL,
  fields TEXT NOT NULL,
  author TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL
);
CREATE TABLE files (
  download_key TEXT PRIMARY KEY,
  sha512 TEXT NOT NULL,
  upstream_sha512 TEXT,
  size INTEGER NOT NULL,
  header_string TEXT NOT NULL,
  path TEXT NOT NULL,
  stored INTEGER NOT NULL DEFAULT 0,
  checked TEXT NOT NULL
);
CREATE TABLE seen (
  entry_key TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL
);
CREATE TABLE runs (
  id INTEGER PRIMARY KEY,
  started TEXT NOT NULL,
  finished TEXT,
  status TEXT,
  anyway INTEGER NOT NULL DEFAULT 0,
  report TEXT
);
CREATE TABLE published (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  snapshot TEXT NOT NULL,
  sha512 TEXT NOT NULL,
  entries TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE TABLE lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  holder TEXT NOT NULL,
  since TEXT NOT NULL
);
"""

LOCK_EXPIRES = datetime.timedelta(hours=6)


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def iso(t: datetime.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path, isolation_level=None, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    if db.execute("PRAGMA user_version").fetchone()[0] == 0:
        # IF NOT EXISTS and INSERT OR IGNORE: serve and publish may both start on a new volume.
        db.executescript(
            "BEGIN;"
            + SCHEMA.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS")
            + "PRAGMA user_version = 1; COMMIT;"
        )
        seed(db)
    return db


def seed(db: sqlite3.Connection) -> None:
    for s in sources.DEFAULTS:
        db.execute(
            "INSERT OR IGNORE INTO sources (name, type, config, priority, delay_days, enabled)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                s["name"],
                s["type"],
                json.dumps(s["config"]),
                s["priority"],
                s["delay_days"],
                int(s.get("enabled", True)),
            ),
        )


def take_lock(db: sqlite3.Connection, holder: str, at: datetime.datetime) -> bool:
    """One run at a time. A lock older than LOCK_EXPIRES was left by a run that died."""
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT since FROM lock WHERE id = 1").fetchone()
        if row and at - datetime.datetime.fromisoformat(row["since"]) < LOCK_EXPIRES:
            db.execute("ROLLBACK")
            return False
        db.execute(
            "INSERT OR REPLACE INTO lock (id, holder, since) VALUES (1, ?, ?)",
            (holder, at.isoformat()),
        )
        db.execute("COMMIT")
        return True
    except BaseException:
        db.execute("ROLLBACK")
        raise


def release_lock(db: sqlite3.Connection, holder: str) -> None:
    db.execute("DELETE FROM lock WHERE id = 1 AND holder = ?", (holder,))
