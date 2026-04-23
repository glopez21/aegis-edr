"""Threat Intelligence integration for AegisEDR."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class MISPClient:
    """MISP (Malware Information Sharing Platform) client."""

    url: str = ""
    api_key: str = ""
    verify_ssl: bool = False
    _client: Optional[httpx.AsyncClient] = None

    def __post_init__(self):
        if self.url and self.api_key:
            self._client = httpx.AsyncClient(
                base_url=self.url,
                headers={"Authorization": self.api_key, "Content-Type": "application/json"},
                verify=self.verify_ssl,
            )

    async def search_hashes(self, hash_type: str, value: str) -> List[Dict[str, Any]]:
        """Search for indicator by hash."""
        if not self._client:
            return []

        search = {
            "returnFormat": "json",
            "attribute": {
                "type": hash_type,
                "value": value,
            },
        }
        try:
            resp = await self._client.post("/attributes/restSearch", json=search)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("response", {}).get("Attribute", [])
        except Exception:
            pass
        return []

    async def search_iocs(self, query: str) -> List[Dict[str, Any]]:
        """Search IOC by自由 query."""
        if not self._client:
            return []

        search = {
            "returnFormat": "json",
            "value": query,
        }
        try:
            resp = await self._client.post("/events/restSearch", json=search)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("response", {})
        except Exception:
            pass
        return []

    async def get_threat_levels(self) -> Dict[str, Any]:
        """Get threat levels from MISP."""
        if not self._client:
            return {}

        resp = await self._client.get("/users/statistics")
        if resp.status_code == 200:
            return resp.json()
        return {}

    async def close(self):
        if self._client:
            await self._client.aclose()

    def is_configured(self) -> bool:
        return bool(self.url and self.api_key)


@dataclass
class AlienVaultOTXClient:
    """AlienVault OTX (Open Threat Exchange) client."""

    api_key: str = ""
    base_url: str = "https://otx.alienvault.com/api/v1"
    _client: Optional[httpx.AsyncClient] = None

    def __post_init__(self):
        if self.api_key:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={"X-OTX-API-KEY": self.api_key},
            )

    async def check_hash(self, sha256: str) -> Dict[str, Any]:
        """Check if hash is known malicious."""
        if not self._client:
            return {}

        try:
            resp = await self._client.get(f"/indicators/hash/{sha256}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation."""
        if not self._client:
            return {}

        try:
            resp = await self._client.get(f"/indicators/domain/{domain}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation."""
        if not self._client:
            return {}

        try:
            resp = await self._client.get(f"/indicators/IPv4/{ip}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    async def get_pulse(self, pulse_id: str) -> Dict[str, Any]:
        """Get threat intelligence pulse."""
        if not self._client:
            return {}

        try:
            resp = await self._client.get(f"/pulses/{pulse_id}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    async def search_pules(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search pulses."""
        if not self._client:
            return []

        try:
            resp = await self._client.get(f"/search/pules", params={"query": query, "limit": limit})
            if resp.status_code == 200:
                data = resp.json()
                return data.get("results", [])
        except Exception:
            pass
        return []

    async def close(self):
        if self._client:
            await self._client.aclose()

    def is_configured(self) -> bool:
        return bool(self.api_key)


@dataclass
class STIXClient:
    """STIX/TAXII threat intelligence client."""

    server_url: str = ""
    api_key: str = ""
    collection: str = ""
    _client: Optional[httpx.AsyncClient] = None

    def __post_init__(self):
        if self.server_url:
            self._client = httpx.AsyncClient(base_url=self.server_url)

    async def get_bundles(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get STIX bundles."""
        if not self._client:
            return []

        try:
            resp = await self._client.get(
                "/api/v1/bundles",
                params={"limit": limit},
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("objects", [])
        except Exception:
            pass
        return []

    async def close(self):
        if self._client:
            await self._client.aclose()

    def is_configured(self) -> bool:
        return bool(self.server_url)


class ThreatIntelManager:
    """Manager for multiple threat intelligence sources."""

    def __init__(self):
        self.sources: Dict[str, Any] = {}

    def add_misp(self, **kwargs) -> MISPClient:
        client = MISPClient(**kwargs)
        self.sources["misp"] = client
        return client

    def add_otx(self, **kwargs) -> AlienVaultOTXClient:
        client = AlienVaultOTXClient(**kwargs)
        self.sources["otx"] = client
        return client

    def add_stix(self, **kwargs) -> STIXClient:
        client = STIXClient(**kwargs)
        self.sources["stix"] = client
        return client

    async def check_hash(self, sha256: str) -> Dict[str, Any]:
        """Check hash across all sources."""
        results = {}
        for name, client in self.sources.items():
            if hasattr(client, "check_hash"):
                result = await client.check_hash(sha256)
                results[name] = result
        return results

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP across all sources."""
        results = {}
        for name, client in self.sources.items():
            if hasattr(client, "check_ip"):
                result = await client.check_ip(ip)
                results[name] = result
        return results

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain across all sources."""
        results = {}
        for name, client in self.sources.items():
            if hasattr(client, "check_domain"):
                result = await client.check_domain(domain)
                results[name] = result
        return results


class ThreatIntelCache:
    """Local cache for threat intelligence."""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".aegisedr" / "threat_intel.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cached_iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    source TEXT,
                    reputation TEXT,
                    last_seen TEXT,
                    tags TEXT
                )
            """)

    def cache_result(self, ioc_type: str, value: str, source: str, reputation: str, tags: str = ""):
        now = datetime.utcnow().isoformat() + "Z"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO cached_iocs
                (type, value, source, reputation, last_seen, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ioc_type, value, source, reputation, now, tags))

    def get_cached(self, ioc_type: str, value: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM cached_iocs
                WHERE type = ? AND value = ?
            """, (ioc_type, value))
            row = cursor.fetchone()
            return dict(row) if row else None


def get_manager() -> ThreatIntelManager:
    """Get threat intel manager."""
    return ThreatIntelManager()


def enrich_detection(detection: Dict[str, Any], manager: ThreatIntelManager | None = None) -> Dict[str, Any]:
    """Enrich detection with threat intel."""
    if manager is None:
        manager = get_manager()

    event = detection.get("event", {})
    sha256 = event.get("sha256", "")

    if sha256:
        import asyncio
        results = asyncio.run(manager.check_hash(sha256))
        if results:
            detection["threat_intel"] = results

    return detection