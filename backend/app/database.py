import sqlite3
from contextlib import contextmanager
from app.config import settings

DB_PATH = settings.DATABASE_URL.replace("sqlite:///", "")


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                status TEXT DEFAULT 'uploaded',
                uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                email_id TEXT NOT NULL,
                risk_score INTEGER,
                risk_category TEXT,
                result_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails (id)
            )
        """)
        # Module 4: every report (url / message / email) lands here so related
        # reports can be correlated on exact indicators.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                input_type TEXT NOT NULL,
                input_text TEXT,
                final_url TEXT,
                domain TEXT,
                brand TEXT,
                risk_class TEXT,
                risk_score REAL,
                indicators_json TEXT,
                evidence_json TEXT,
                report_json TEXT NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports (created_at DESC)"
        )
        conn.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()