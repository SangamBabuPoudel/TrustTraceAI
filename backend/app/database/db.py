import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parents[2] / "trusttrace.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS message_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_hash TEXT NOT NULL UNIQUE,
                sender TEXT,
                subject TEXT,
                source_url TEXT,
                normalized_preview TEXT,
                risk_level TEXT,
                phishing_probability REAL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                scan_count INTEGER NOT NULL
            )
            """
        )
