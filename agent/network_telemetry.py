"""Network telemetry monitoring for AegisEDR."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class NetworkEvent:
    """Network connection event."""

    timestamp: str
    host: str
    user: str
    process: str
    protocol: str = ""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    dns_query: str = ""
    url: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    direction: str = "outbound"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "user": self.user,
            "process": self.process,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "dns_query": self.dns_query,
            "url": self.url,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "direction": self.direction,
        }


class DNSMonitor:
    """DNS query monitor."""

    def __init__(self):
        self._queries: List[str] = []
        self._lock = threading.Lock()
        self._suspicious_domains = [
            ".xyz", ".top", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq",
            "pastebin", "mega", "dropbox", "googledrive",
            "suspicious", "malware", "payload",
        ]

    def log_query(self, domain: str):
        with self._lock:
            self._queries.append(domain)

    def get_queries(self, limit: int = 100) -> List[str]:
        with self._lock:
            return self._queries[-limit:]

    def check_suspicious(self, domain: str) -> bool:
        domain_lower = domain.lower()
        return any(susp in domain_lower for susp in self._suspicious_domains)


class HTTPMonitor:
    """HTTP/HTTPS request monitor."""

    def __init__(self):
        self._requests: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._suspicious_urls = []

    def log_request(
        self,
        method: str,
        url: str,
        status_code: int,
        user: str,
    ):
        with self._lock:
            self._requests.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "method": method,
                "url": url,
                "status_code": status_code,
                "user": user,
                "suspicious": self._is_suspicious(url),
            })

    def _is_suspicious(self, url: str) -> bool:
        suspicious_patterns = [
            "/evil.", "/malware", "/payload", "/exploit",
            "data:;", "javascript:", "vbscript:",
        ]
        return any(p in url.lower() for p in suspicious_patterns)

    def get_requests(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return self._requests[-limit:]


class NetworkMonitor:
    """Combined network monitoring."""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".aegisedr" / "network_telemetry.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self.dns = DNSMonitor()
        self.http = HTTPMonitor()
        self._init_db()
        self._running = False

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    host TEXT,
                    user TEXT,
                    process TEXT,
                    protocol TEXT,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    dns_query TEXT,
                    url TEXT,
                    bytes_in INTEGER,
                    bytes_out INTEGER,
                    direction TEXT,
                    event_type TEXT
                )
            """)

            conn.execute("""
                CREATE INDEX idx_timestamp
                ON network_events(timestamp)
            """)

            conn.execute("""
                CREATE INDEX idx_dst_ip
                ON network_events(dst_ip)
            """)

            conn.execute("""
                CREATE INDEX idx_dns_query
                ON network_events(dns_query)
            """)

    def log_dns_query(self, event: NetworkEvent):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO network_events (
                    timestamp, host, user, process, protocol,
                    dns_query, direction, event_type
                ) VALUES (?, ?, ?, ?, 'DNS', ?, ?, ?, 'dns')
            """, (
                event.timestamp, event.host, event.user, event.process,
                event.dns_query, event.direction,
            ))

        self.dns.log_query(event.dns_query)

    def log_connection(self, event: NetworkEvent):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO network_events (
                    timestamp, host, user, process, protocol,
                    src_ip, src_port, dst_ip, dst_port,
                    bytes_in, bytes_out, direction, event_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'connection')
            """, (
                event.timestamp, event.host, event.user, event.process,
                event.protocol, event.src_ip, event.src_port,
                event.dst_ip, event.dst_port,
                event.bytes_in, event.bytes_out, event.direction,
            ))

    def log_http_request(self, event: NetworkEvent):
        self.http.log_request("GET", event.url, 200, event.user)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO network_events (
                    timestamp, host, user, process, protocol,
                    url, bytes_in, bytes_out, event_type
                ) VALUES (?, ?, ?, ?, 'HTTP', ?, ?, ?, 'http')
            """, (
                event.timestamp, event.host, event.user, event.process,
                event.url, event.bytes_in, event.bytes_out,
            ))

    def get_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        dst_ip: str | None = None,
    ) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            query = "SELECT * FROM network_events WHERE 1=1"
            params = []

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)
            if dst_ip:
                query += " AND dst_ip = ?"
                params.append(dst_ip)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_dns_queries(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.dns.get_queries(limit)

    def check_dga(self, domain: str) -> bool:
        length = len(domain)
        if length > 20:
            return True

        entropy = self._calculate_entropy(domain)
        if entropy > 4.0:
            return True

        return False

    def _calculate_entropy(self, s: str) -> float:
        from collections import Counter
        import math

        prob = [float(c) / len(s) for c in Counter(s).values()]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def get_stats(self) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM network_events")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT event_type, COUNT(*) FROM network_events GROUP BY event_type")
            by_type = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("SELECT DISTINCT dst_ip FROM network_events")
            unique_ips = len(cursor.fetchall())

            cursor.execute("SELECT DISTINCT dns_query FROM network_events WHERE dns_query != ''")
            unique_domains = len(cursor.fetchall())

            return {
                "total_events": total,
                "by_type": by_type,
                "unique_dst_ips": unique_ips,
                "unique_domains": unique_domains,
            }

    def generate_sample_events(self) -> List[NetworkEvent]:
        """Generate sample network events for testing."""
        now = datetime.utcnow().isoformat() + "Z"
        return [
            NetworkEvent(
                timestamp=now,
                host="workstation01",
                user="admin",
                process="chrome.exe",
                protocol="HTTPS",
                dst_ip="142.250.185.78",
                dst_port=443,
                url="https://www.google.com",
                bytes_in=15234,
                bytes_out=2345,
                direction="outbound",
            ),
            NetworkEvent(
                timestamp=now,
                host="workstation01",
                user="admin",
                process="chrome.exe",
                protocol="DNS",
                dns_query="evil-domain.xyz",
                direction="outbound",
            ),
            NetworkEvent(
                timestamp=now,
                host="workstation02",
                user="system",
                process="svchost.exe",
                protocol="DNS",
                dst_ip="8.8.8.8",
                dst_port=53,
                dns_query="command-and-control.malware.top",
                direction="outbound",
            ),
            NetworkEvent(
                timestamp=now,
                host="workstation01",
                user="admin",
                process="powershell.exe",
                protocol="HTTPS",
                dst_ip="203.0.113.50",
                dst_port=443,
                url="https://evil-domain.xyz/payload.exe",
                bytes_in=0,
                bytes_out=45056,
                direction="outbound",
            ),
        ]


def create_sample_events() -> List[NetworkEvent]:
    """Helper to create sample network events."""
    return NetworkMonitor().generate_sample_events()


def detect_exfiltration(detections: List[Dict[str, Any]], network_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect potential exfiltration based on network events."""
    alerts = []

    suspicious_ports = [20, 21, 22, 23, 25, 53, 4444, 4443, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669]
    large_data_threshold = 10 * 1024 * 1024

    for event in network_events:
        if event.get("bytes_out", 0) > large_data_threshold:
            alerts.append({
                "rule": "Large Data Exfiltration",
                "severity": "High",
                "event": event,
                "reason": f"Large outbound: {event.get('bytes_out')} bytes",
            })

        if event.get("dst_port") in suspicious_ports:
            alerts.append({
                "rule": "Suspicious Port",
                "severity": "Medium",
                "event": event,
                "reason": f"Connection to suspicious port: {event.get('dst_port')}",
            })

        dns = event.get("dns_query", "")
        if dns and any(s in dns.lower() for s in [".xyz", ".top", ".pw", ".tk"]):
            alerts.append({
                "rule": "Suspicious TLD",
                "severity": "High",
                "event": event,
                "reason": f"Suspicious TLD in query: {dns}",
            })

    return alerts