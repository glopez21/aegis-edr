"""SQLite persistence layer for AegisEDR incidents."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional


class IncidentStore:
    """SQLite-backed incident storage with deduplication."""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".aegisedr" / "incidents.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    technique TEXT,
                    mitre_phase TEXT,
                    severity TEXT,
                    score REAL,
                    host TEXT NOT NULL,
                    process TEXT,
                    command_line TEXT,
                    parent_process TEXT,
                    user TEXT,
                    sha256 TEXT,
                    timestamp TEXT NOT NULL,
                    detection_time TEXT NOT NULL,
                    response_action TEXT,
                    responded INTEGER DEFAULT 0,
                    UNIQUE(rule_name, host, process, timestamp)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_detection_time
                ON incidents(detection_time)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_severity
                ON incidents(severity)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_host
                ON incidents(host)
            """)

    def insert(self, detection: Dict) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO incidents (
                    rule_name, technique, mitre_phase, severity, score,
                    host, process, command_line, parent_process,
                    user, sha256, timestamp, detection_time,
                    responded
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                detection.get("rule", ""),
                detection.get("technique", ""),
                detection.get("mitre_phase", ""),
                detection.get("severity", "Medium"),
                detection.get("score", 0),
                detection.get("event", {}).get("host", ""),
                detection.get("event", {}).get("process", ""),
                detection.get("event", {}).get("command_line", ""),
                detection.get("event", {}).get("parent", ""),
                detection.get("event", {}).get("user", ""),
                detection.get("event", {}).get("sha256", ""),
                detection.get("event", {}).get("timestamp", ""),
                datetime.utcnow().isoformat() + "Z",
            ))
            return cursor.lastrowid

    def insert_batch(self, detections: Iterable[Dict]) -> int:
        count = 0
        for detection in detections:
            if self.insert(detection):
                count += 1
        return count

    def mark_responded(self, incident_id: int, action: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE incidents
                SET responded = 1, response_action = ?
                WHERE id = ?
            """, (action, incident_id))

    def get_recent(self, limit: int = 100, severity: str | None = None) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            query = "SELECT * FROM incidents"
            params = []
            if severity:
                query += " WHERE severity = ?"
                params.append(severity)
            query += " ORDER BY detection_time DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_by_host(self, host: str, limit: int = 50) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM incidents
                WHERE host = ?
                ORDER BY detection_time DESC
                LIMIT ?
            """, (host, limit))
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM incidents")
            total = cursor.fetchone()[0]

            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM incidents
                GROUP BY severity
            """)
            by_severity = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("""
                SELECT mitre_phase, COUNT(*) as count
                FROM incidents
                GROUP BY mitre_phase
            """)
            by_phase = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("""
                SELECT COUNT(*) FROM incidents
                WHERE responded = 1
            """)
            responded = cursor.fetchone()[0]

            return {
                "total": total,
                "by_severity": by_severity,
                "by_mitre_phase": by_phase,
                "responded": responded,
            }

    def deduplicate(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM incidents
                WHERE id NOT IN (
                    SELECT MIN(id)
                    FROM incidents
                    GROUP BY rule_name, host, process, timestamp
                )
            """)
            return cursor.rowcount


def get_store(db_path: Path | None = None) -> IncidentStore:
    """Factory function for getting incident store."""
    return IncidentStore(db_path)