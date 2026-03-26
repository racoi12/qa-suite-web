"""SQLite database — users, scans, results, artifacts, configs, schedules, api_keys, webhooks."""

import sqlite3
import os
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(os.getenv("DB_PATH", "/data/qa.db"))


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT DEFAULT '',
                url TEXT NOT NULL,
                batch_id TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'queued',
                progress TEXT DEFAULT '',
                config TEXT DEFAULT '{}',
                score REAL DEFAULT 0,
                summary TEXT DEFAULT '',
                video_path TEXT DEFAULT '',
                trace_path TEXT DEFAULT '',
                har_path TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                finished_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                test_name TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                message TEXT DEFAULT '',
                details TEXT DEFAULT '{}',
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                filename TEXT NOT NULL,
                content_type TEXT DEFAULT 'image/png',
                size_bytes INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                config TEXT NOT NULL,
                is_default INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                urls TEXT NOT NULL,
                config TEXT NOT NULL,
                cron_expression TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                last_run TIMESTAMP,
                next_run TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                last_used TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                events TEXT NOT NULL,
                secret TEXT DEFAULT '',
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS teams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                logo_url TEXT DEFAULT '',
                primary_color TEXT DEFAULT '#7c6cf0',
                secondary_color TEXT DEFAULT '#b4a8ff',
                custom_domain TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS team_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)

        # Migration helpers for existing installs
        for col, dtype, default in [
            ("name", "TEXT DEFAULT ''", ""),
            ("batch_id", "TEXT DEFAULT ''", ""),
            ("trace_path", "TEXT DEFAULT ''", ""),
            ("har_path", "TEXT DEFAULT ''", ""),
        ]:
            try:
                db.execute(f"ALTER TABLE scans ADD COLUMN {col} {dtype}")
            except Exception:
                pass

        for col, dtype in [
            ("name", "TEXT NOT NULL"),
            ("config", "TEXT NOT NULL"),
            ("is_default", "INTEGER DEFAULT 0"),
        ]:
            try:
                db.execute(f"ALTER TABLE configs ADD COLUMN {col} {dtype}")
            except Exception:
                pass

        for col, dtype in [
            ("name", "TEXT NOT NULL"),
            ("urls", "TEXT NOT NULL"),
            ("config", "TEXT NOT NULL"),
            ("cron_expression", "TEXT NOT NULL"),
            ("enabled", "INTEGER DEFAULT 1"),
            ("last_run", "TIMESTAMP"),
            ("next_run", "TIMESTAMP"),
        ]:
            try:
                db.execute(f"ALTER TABLE schedules ADD COLUMN {col} {dtype}")
            except Exception:
                pass

        for col, dtype in [
            ("name", "TEXT NOT NULL"),
            ("key_hash", "TEXT NOT NULL"),
            ("last_used", "TIMESTAMP"),
        ]:
            try:
                db.execute(f"ALTER TABLE api_keys ADD COLUMN {col} {dtype}")
            except Exception:
                pass

        for col, dtype in [
            ("name", "TEXT NOT NULL"),
            ("url", "TEXT NOT NULL"),
            ("events", "TEXT NOT NULL"),
            ("secret", "TEXT DEFAULT ''"),
            ("active", "INTEGER DEFAULT 1"),
        ]:
            try:
                db.execute(f"ALTER TABLE webhooks ADD COLUMN {col} {dtype}")
            except Exception:
                pass

        for col, dtype in [
            ("name", "TEXT NOT NULL"),
            ("logo_url", "TEXT DEFAULT ''"),
            ("primary_color", "TEXT DEFAULT '#7c6cf0'"),
            ("secondary_color", "TEXT DEFAULT '#b4a8ff'"),
            ("custom_domain", "TEXT DEFAULT ''"),
        ]:
            try:
                db.execute(f"ALTER TABLE teams ADD COLUMN {col} {dtype}")
            except Exception:
                pass

        for col, dtype in [
            ("team_id", "INTEGER NOT NULL"),
            ("role", "TEXT NOT NULL DEFAULT 'member'"),
        ]:
            try:
                db.execute(f"ALTER TABLE team_members ADD COLUMN {col} {dtype}")
            except Exception:
                pass


@contextmanager
def get_db():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_artifact(scan_id: int, category: str, artifact_type: str, filename: str,
                  content_type: str = "image/png", size_bytes: int = 0):
    with get_db() as db:
        db.execute(
            "INSERT INTO artifacts (scan_id, category, artifact_type, filename, content_type, size_bytes) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, category, artifact_type, filename, content_type, size_bytes),
        )


def get_artifacts(scan_id: int, artifact_type: str = ""):
    with get_db() as db:
        if artifact_type:
            rows = db.execute(
                "SELECT * FROM artifacts WHERE scan_id = ? AND artifact_type = ? ORDER BY id",
                (scan_id, artifact_type),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM artifacts WHERE scan_id = ? ORDER BY artifact_type, id",
                (scan_id,),
            ).fetchall()
    return [dict(r) for r in rows]
