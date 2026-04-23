"""IOC (Indicator of Compromise) database for AegisEDR."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional


class IOCDatabase:
    """SQLite-backed IOC hash reputation database."""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".aegisedr" / "ioc.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    reputation TEXT NOT NULL,
                    source TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    tags TEXT,
                    confidence REAL DEFAULT 0.5,
                    notes TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_value
                ON iocs(type, value)
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS ioc_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    user TEXT,
                    details TEXT,
                    FOREIGN KEY (ioc_id) REFERENCES iocs(id)
                )
            """)

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        reputation: str,
        source: str = "manual",
        tags: str = "",
        confidence: float = 0.5,
        notes: str = "",
    ) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat() + "Z"
            cursor.execute("""
                INSERT OR REPLACE INTO iocs (
                    type, value, reputation, source,
                    first_seen, last_seen, tags,
                    confidence, notes
                ) VALUES (?, ?, ?, ?, COALESCE((SELECT first_seen FROM iocs WHERE value = ?), ?), ?, ?, ?, ?)
            """, (
                ioc_type, value, reputation, source,
                value, now, now, tags, confidence, notes,
            ))
            cursor.execute("SELECT last_insert_rowid()")
            return cursor.fetchone()[0]

    def bulk_add(self, iocs: Iterable[Dict]) -> int:
        count = 0
        for ioc in iocs:
            self.add_ioc(
                ioc.get("type", "sha256"),
                ioc.get("value", ""),
                ioc.get("reputation", "unknown"),
                ioc.get("source", "bulk"),
                ioc.get("tags", ""),
                ioc.get("confidence", 0.5),
            )
            count += 1
        return count

    def lookup(self, ioc_type: str, value: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM iocs
                WHERE type = ? AND value = ?
            """, (ioc_type, value))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_reputation(self, reputation: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM iocs
                WHERE reputation = ?
                ORDER BY last_seen DESC
            """, (reputation,))
            return [dict(row) for row in cursor.fetchall()]

    def check_hash(self, sha256: str) -> Optional[Dict]:
        return self.lookup("sha256", sha256.lower())

    def record_detection(self, ioc_id: int, action: str, user: str = "") -> None:
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.utcnow().isoformat() + "Z"
            conn.execute("""
                INSERT INTO ioc_history (ioc_id, action, timestamp, user)
                VALUES (?, ?, ?, ?)
            """, (ioc_id, action, now, user))

            conn.execute("""
                UPDATE iocs
                SET last_seen = ?
                WHERE id = ?
            """, (now, ioc_id))

    def get_stats(self) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM iocs WHERE reputation = 'malicious'")
            malicious = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM iocs WHERE reputation = 'benign'")
            benign = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM iocs")
            total = cursor.fetchone()[0]

            return {
                "total": total,
                "malicious": malicious,
                "benign": benign,
                "unknown": total - malicious - benign,
            }


def get_ioc_db(db_path: Path | None = None) -> IOCDatabase:
    """Factory function for getting IOC database."""
    return IOCDatabase(db_path)


MALICIOUS_HASHES = [
    {"type": "sha256", "value": "aaaabbbbcccc1111222233334444555566667777888899990000aaaabbbb", "reputation": "malicious", "source": "known-bad", "tags": "mimikatz,credential-theft", "confidence": 0.95},
    {"type": "sha256", "value": "bbbbccccdddd1111222233334444555566667777888899990000aaaacccc", "reputation": "malicious", "source": "known-bad", "tags": "mimikatz,credential-theft", "confidence": 0.95},
]


def seed_malicious_hashes(db_path: Path | None = None) -> int:
    """Seed known malicious hashes for demo purposes."""
    db = IOCDatabase(db_path)
    return db.bulk_add(MALICIOUS_HASHES)