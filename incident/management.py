"""Incident Management for AegisEDR."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Incident:
    """Incident with full lifecycle."""

    id: int
    title: str
    description: str = ""
    status: str = "Open"
    severity: str = "Medium"
    assignee: str = ""
    created_at: str = ""
    updated_at: str = ""
    resolved_at: str = ""
    detection_ids: List[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "severity": self.severity,
            "assignee": self.assignee,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "resolved_at": self.resolved_at,
            "detection_ids": self.detection_ids or [],
        }


class IncidentManager:
    """Full incident lifecycle management."""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".aegisedr" / "incidents_full.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'Open',
                    severity TEXT DEFAULT 'Medium',
                    assignee TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    resolved_at TEXT,
                    detection_ids TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    author TEXT,
                    body TEXT,
                    created_at TEXT,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    action TEXT,
                    actor TEXT,
                    details TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                )
            """)

            conn.execute("""
                CREATE INDEX idx_incident_status
                ON incidents(status)
            """)

            conn.execute("""
                CREATE INDEX idx_incident_assignee
                ON incidents(assignee)
            """)

    def create(
        self,
        title: str,
        description: str = "",
        severity: str = "Medium",
        detection_ids: List[int] | None = None,
    ) -> int:
        import json

        now = datetime.utcnow().isoformat() + "Z"
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incidents (
                    title, description, status, severity,
                    created_at, updated_at, detection_ids
                ) VALUES (?, ?, 'Open', ?, ?, ?, ?)
            """, (
                title,
                description,
                severity,
                now,
                now,
                json.dumps(detection_ids or []),
            ))
            incident_id = cursor.lastrowid

            self._add_timeline(incident_id, "created", "system", f"Incident created: {title}")

        return incident_id

    def _add_timeline(self, incident_id: int, action: str, actor: str, details: str = ""):
        now = datetime.utcnow().isoformat() + "Z"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO timeline (incident_id, action, actor, details, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (incident_id, action, actor, details, now))

    def get(self, incident_id: int) -> Optional[Incident]:
        import json

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM incidents WHERE id = ?",
                (incident_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            return Incident(
                id=row["id"],
                title=row["title"],
                description=row["description"],
                status=row["status"],
                severity=row["severity"],
                assignee=row["assignee"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                resolved_at=row["resolved_at"] or "",
                detection_ids=json.loads(row["detection_ids"] or "[]"),
            )

    def update_status(
        self,
        incident_id: int,
        status: str,
        actor: str = "system",
    ) -> bool:
        now = datetime.utcnow().isoformat() + "Z"
        resolved_at = now if status in ("Resolved", "Closed") else ""

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE incidents
                SET status = ?, updated_at = ?, resolved_at = ?
                WHERE id = ?
            """, (status, now, resolved_at, incident_id))

            self._add_timeline(incident_id, f"status_changed", actor, f"Status -> {status}")

        return True

    def assign(
        self,
        incident_id: int,
        assignee: str,
        actor: str = "system",
    ) -> bool:
        now = datetime.utcnow().isoformat() + "Z"

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE incidents
                SET assignee = ?, updated_at = ?
                WHERE id = ?
            """, (assignee, now, incident_id))

            self._add_timeline(incident_id, "assigned", actor, f"Assigned to {assignee}")

        return True

    def add_comment(
        self,
        incident_id: int,
        author: str,
        body: str,
    ) -> int:
        now = datetime.utcnow().isoformat() + "Z"

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO comments (incident_id, author, body, created_at)
                VALUES (?, ?, ?, ?)
            """, (incident_id, author, body, now))
            comment_id = cursor.lastrowid

            conn.execute("""
                UPDATE incidents
                SET updated_at = ?
                WHERE id = ?
            """, (now, incident_id))

        return comment_id

    def get_comments(self, incident_id: int) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM comments WHERE incident_id = ? ORDER BY created_at DESC",
                (incident_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_timeline(self, incident_id: int) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM timeline WHERE incident_id = ? ORDER BY timestamp DESC",
                (incident_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def list_all(
        self,
        status: str | None = None,
        assignee: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> List[Incident]:
        import json

        query = "SELECT * FROM incidents WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if assignee:
            query += " AND assignee = ?"
            params.append(assignee)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [
                Incident(
                    id=row["id"],
                    title=row["title"],
                    description=row["description"],
                    status=row["status"],
                    severity=row["severity"],
                    assignee=row["assignee"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    resolved_at=row["resolved_at"] or "",
                    detection_ids=json.loads(row["detection_ids"] or "[]"),
                )
                for row in cursor.fetchall()
            ]

    def get_stats(self) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM incidents")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT status, COUNT(*) FROM incidents GROUP BY status")
            by_status = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
            by_severity = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("""
                SELECT COUNT(*) FROM incidents
                WHERE created_at >= date('now', '-7 days')
            """)
            last_7_days = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*) FROM incidents
                WHERE status IN ('Resolved', 'Closed')
                AND resolved_at >= date('now', '-7 days')
            """)
            resolved_7_days = cursor.fetchone()[0]

            return {
                "total": total,
                "by_status": by_status,
                "by_severity": by_severity,
                "last_7_days": last_7_days,
                "resolved_7_days": resolved_7_days,
                "resolution_rate": resolved_7_days / last_7_days if last_7_days else 0,
            }

    def escalate(self, incident_id: int, reason: str = "") -> bool:
        with sqlite3.connect(self.db_path) as conn:
            severity_map = {"Low": "Medium", "Medium": "High", "High": "Critical", "Critical": "Critical"}
            current = conn.execute(
                "SELECT severity FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()

            if current:
                new_severity = severity_map.get(current[0], "Critical")
                now = datetime.utcnow().isoformat() + "Z"

                conn.execute("""
                    UPDATE incidents
                    SET severity = ?, updated_at = ?
                    WHERE id = ?
                """, (new_severity, now, incident_id))

                self._add_timeline(incident_id, "escalated", "system", reason)

        return True


def get_manager(db_path: Path | None = None) -> IncidentManager:
    """Get incident manager."""
    return IncidentManager(db_path)