"""SIEM connectors for forwarding detections and events."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class SplunkHECConnector:
    """Splunk HTTP Event Collector connector."""

    url: str = ""
    token: str = ""
    index: str = "main"
    source: str = "aegisedr"
    sourcetype: str = "aegis:detection"
    verify_ssl: bool = False
    _client: Optional[httpx.Client] = None

    def __post_init__(self):
        if self.url and self.token:
            self._client = httpx.Client(
                base_url=self.url,
                headers={"Authorization": f"Splunk {self.token}"},
                verify=self.verify_ssl,
            )

    def send_event(self, event: Dict[str, Any], event_type: str = "detection") -> bool:
        """Send a single event to Splunk HEC."""
        payload = {
            "time": datetime.utcnow().timestamp(),
            "host": event.get("host", "unknown"),
            "source": self.source,
            "sourcetype": f"{self.sourcetype}:{event_type}",
            "index": self.index,
            "event": event,
        }
        try:
            if self._client:
                resp = self._client.post("/services/collector", json=payload)
                return resp.status_code == 200
            return False
        except Exception:
            return False

    def send_batch(self, events: List[Dict[str, Any]]) -> int:
        """Send multiple events. Returns count of successful sends."""
        count = 0
        for event in events:
            if self.send_event(event):
                count += 1
        return count

    def close(self):
        if self._client:
            self._client.close()


@dataclass
class ElasticsearchConnector:
    """Elasticsearch connector for detections."""

    url: str = "http://localhost:9200"
    index: str = "aegis-detections"
    api_key: str = ""
    username: str = ""
    password: str = ""
    verify_ssl: bool = False
    _client: Optional[httpx.Client] = None

    def __post_init__(self):
        if self.url:
            auth = None
            if self.api_key:
                auth = (self.api_key, "")
            elif self.username:
                auth = (self.username, self.password)
            self._client = httpx.Client(
                base_url=self.url,
                auth=auth,
                verify=self.verify_ssl,
            )

    def create_index_if_not_exists(self) -> bool:
        """Create the index with mapping if it doesn't exist."""
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "rule": {"type": "keyword"},
                    "technique": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "score": {"type": "integer"},
                    "host": {"type": "keyword"},
                    "process": {"type": "keyword"},
                    "event": {"type": "object"},
                }
            }
        }
        try:
            if self._client:
                resp = self._client.get(f"/{self.index}")
                if resp.status_code == 404:
                    self._client.put(f"/{self.index}", json=mapping)
                return True
            return False
        except Exception:
            return False

    def index_event(self, event: Dict[str, Any]) -> bool:
        """Index a single event."""
        doc = {
            "@timestamp": datetime.utcnow().isoformat(),
            **event,
        }
        try:
            if self._client:
                resp = self._client.post(
                    f"/{self.index}/_doc",
                    json=doc,
                )
                return resp.status_code in (200, 201)
            return False
        except Exception:
            return False

    def index_batch(self, events: List[Dict[str, Any]]) -> int:
        """Index multiple events using bulk API."""
        if not events or not self._client:
            return 0

        payload = "\n".join([
            json.dumps({"index": {"_index": self.index}}),
            json.dumps({"@timestamp": datetime.utcnow().isoformat(), **event}),
        ]) + "\n"

        try:
            resp = self._client.post(
                "/_bulk",
                content=payload.encode(),
                headers={"Content-Type": "application/x-ndjson"},
            )
            return len(events) if resp.status_code in (200, 201) else 0
        except Exception:
            return 0

    def close(self):
        if self._client:
            self._client.close()


@dataclass
class SyslogConnector:
    """Syslog connector (RFC 5424 format)."""

    host: str = "localhost"
    port: int = 514
    protocol: str = "udp"
    app_name: str = "aegisedr"
    facility: int = 16
    _socket: Optional[socket.socket] = None

    def __post_init__(self):
        if self.protocol == "udp":
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((self.host, self.port))

    def _format_syslog(self, message: str, level: int = 3) -> bytes:
        """Format as RFC 5424 syslog message."""
        pri = (self.facility * 8) + level
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M.%fZ")
        return f"<{pri}>1 {timestamp} {socket.gethostname()} {self.app_name} - - {message}".encode()

    def send(self, message: str, level: int = 3) -> bool:
        """Send syslog message."""
        try:
            msg = self._format_syslog(message, level)
            if self.protocol == "udp":
                self._socket.sendto(msg, (self.host, self.port))
            else:
                self._socket.send(msg)
            return True
        except Exception:
            return False

    def send_detection(self, detection: Dict[str, Any]) -> bool:
        """Send detection as syslog."""
        msg = json.dumps({
            "rule": detection.get("rule"),
            "severity": detection.get("severity"),
            "host": detection.get("event", {}).get("host"),
            "process": detection.get("event", {}).get("process"),
        })
        level_map = {"Critical": 0, "High": 3, "Medium": 4, "Low": 6}
        level = level_map.get(detection.get("severity", ""), 4)
        return self.send(msg, level)

    def close(self):
        if self._socket:
            self._socket.close()


class SIEMManager:
    """Manager for multiple SIEM connectors."""

    def __init__(self):
        self.connectors: Dict[str, Any] = {}

    def add_connector(self, name: str, connector: Any) -> None:
        self.connectors[name] = connector

    def add_splunk(self, **kwargs) -> SplunkHECConnector:
        connector = SplunkHECConnector(**kwargs)
        self.add_connector("splunk", connector)
        return connector

    def add_elasticsearch(self, **kwargs) -> ElasticsearchConnector:
        connector = ElasticsearchConnector(**kwargs)
        self.add_connector("elasticsearch", connector)
        return connector

    def add_syslog(self, **kwargs) -> SyslogConnector:
        connector = SyslogConnector(**kwargs)
        self.add_connector("syslog", connector)
        return connector

    def forward(self, detection: Dict[str, Any]) -> Dict[str, int]:
        """Forward detection to all connectors. Returns dict of connector -> success count."""
        results = {}
        for name, conn in self.connectors.items():
            if hasattr(conn, "send_event"):
                results[name] = 1 if conn.send_event(detection) else 0
            elif hasattr(conn, "index_event"):
                results[name] = 1 if conn.index_event(detection) else 0
            elif hasattr(conn, "send_detection"):
                results[name] = 1 if conn.send_detection(detection) else 0
        return results

    def forward_batch(self, detections: List[Dict[str, Any]]) -> Dict[str, int]:
        """Forward batch to all connectors."""
        results = {name: 0 for name in self.connectors}
        for detection in detections:
            for name, conn in self.connectors.items():
                if hasattr(conn, "send_batch"):
                    results[name] += conn.send_batch([detection])
                elif hasattr(conn, "index_event"):
                    results[name] += conn.index_event(detection)
                elif hasattr(conn, "send_detection"):
                    results[name] += 1 if conn.send_detection(detection) else 0
        return results

    def close_all(self):
        for conn in self.connectors.values():
            if hasattr(conn, "close"):
                conn.close()