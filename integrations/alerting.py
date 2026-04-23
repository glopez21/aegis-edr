"""Alerting webhooks for AegisEDR."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class SlackWebhook:
    """Slack webhook notifier."""

    webhook_url: str = ""
    channel: str = ""
    username: str = "AegisEDR"
    icon_emoji: str = ":shield:"
    _client: Optional[httpx.AsyncClient] = None

    def __post_init__(self):
        if self.webhook_url:
            self._client = httpx.AsyncClient()

    def format_message(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        severity_emoji = {
            "Critical": ":rotating_light:",
            "High": ":warning:",
            "Medium": ":large_blue_circle:",
            "Low": ":white_circle:",
        }
        emoji = severity_emoji.get(detection.get("severity", ""), ":shield:")

        event = detection.get("event", {})
        fields = [
            {"title": "Host", "value": event.get("host", "unknown"), "short": True},
            {"title": "Process", "value": event.get("process", "unknown"), "short": True},
            {"title": "User", "value": event.get("user", "unknown"), "short": True},
            {"title": "Score", "value": str(detection.get("score", 0)), "short": True},
        ]

        return {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [{
                "color": "danger" if detection.get("severity") in ["Critical", "High"] else "warning",
                "blocks": [{
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} {detection.get('rule', 'Detection Alert')}",
                    },
                }, {
                    "type": "section",
                    "fields": fields,
                }, {
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": f"ATT&CK: `{detection.get('technique', 'N/A')}` | Phase: {detection.get('mitre_phase', 'N/A')}",
                    }],
                }],
            }],
        }

    async def send(self, detection: Dict[str, Any]) -> bool:
        """Send alert to Slack."""
        if not self._client:
            return False

        payload = self.format_message(detection)
        try:
            resp = await self._client.post(self.webhook_url, json=payload)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self):
        if self._client:
            await self._client.aclose()


@dataclass
class PagerDutyWebhook:
    """PagerDuty webhook notifier."""

    api_key: str = ""
    integration_key: str = ""
    service_id: str = ""
    _client: Optional[httpx.AsyncClient] = None

    def __post_init__(self):
        if self.api_key and self.integration_key:
            self._client = httpx.AsyncClient(
                base_url="https://events.pagerduty.com",
                headers={"Content-Type": "application/json"},
            )

    def format_event(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        severity_map = {"Critical": "critical", "High": "high", "Medium": "standard", "Low": "low"}

        event = detection.get("event", {})
        return {
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"{detection.get('rule')} on {event.get('host')}",
                "severity": severity_map.get(detection.get("severity"), "warning"),
                "source": event.get("host", "unknown"),
                "timestamp": datetime.utcnow().isoformat(),
                "custom_details": {
                    "rule": detection.get("rule"),
                    "technique": detection.get("technique"),
                    "process": event.get("process"),
                    "command_line": event.get("command_line"),
                    "user": event.get("user"),
                },
            },
        }

    async def send(self, detection: Dict[str, Any]) -> bool:
        """Send alert to PagerDuty."""
        if not self._client:
            return False

        payload = self.format_event(detection)
        try:
            resp = await self._client.post("/v2/enqueue", json=payload)
            return resp.status_code == 202
        except Exception:
            return False

    async def close(self):
        if self._client:
            await self._client.aclose()


@dataclass
class TeamsWebhook:
    """Microsoft Teams webhook notifier."""

    webhook_url: str = ""
    _client: Optional[httpx.AsyncClient] = None

    def __post_init__(self):
        if self.webhook_url:
            self._client = httpx.AsyncClient()

    def format_message(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        severity_colors = {
            "Critical": "FF0000",
            "High": "FF8800",
            "Medium": "FFAA00",
            "Low": "00AAFF",
        }
        color = severity_colors.get(detection.get("severity", ""), "00AAFF")

        event = detection.get("event", {})
        facts = [
            {"name": "Host", "value": event.get("host", "unknown")},
            {"name": "Process", "value": event.get("process", "unknown")},
            {"name": "User", "value": event.get("user", "unknown")},
            {"name": "ATT&CK", "value": detection.get("technique", "N/A")},
        ]

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"{detection.get('rule')} Alert",
            "sections": [{
                "activityTitle": f"🛡️ {detection.get('rule')}",
                "facts": facts,
                "markdown": True,
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "View in Dashboard",
                "targets": [{"os": "default", "uri": "http://localhost:8000"}],
            }],
        }

    async def send(self, detection: Dict[str, Any]) -> bool:
        """Send alert to Teams."""
        if not self._client:
            return False

        payload = self.format_message(detection)
        try:
            resp = await self._client.post(self.webhook_url, json=payload)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self):
        if self._client:
            await self._client.aclose()


@dataclass
class EmailNotifier:
    """Email notifier (SMTP)."""

    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = "aegisedr@example.com"
    to_addrs: List[str] = List[str]()

    async def send(self, detection: Dict[str, Any], subject: str | None = None) -> bool:
        """Send email alert. (Requires aiosmtplib)"""
        import aiosmtplib
        import email.utils

        if not self.smtp_host:
            return False

        event = detection.get("event", {})
        body = f"""
AegisEDR Detection Alert

Rule: {detection.get('rule')}
Severity: {detection.get('severity')}
Score: {detection.get('score')}

Host: {event.get('host')}
Process: {event.get('process')}
User: {event.get('user')}
Command: {event.get('command_line')}

ATT&CK: {detection.get('technique')}
Phase: {detection.get('mitre_phase')}
        """

        msg = email.message.EmailMessage()
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        msg["Date"] = email.utils.formatdate()
        msg["Subject"] = subject or f"AegisEDR Alert: {detection.get('rule')}"
        msg.set_content(body)

        try:
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.username,
                password=self.password,
            )
            return True
        except Exception:
            return False


class AlertManager:
    """Manager for multiple alerting channels."""

    def __init__(self):
        self.channels: Dict[str, Any] = {}

    def add_slack(self, **kwargs) -> SlackWebhook:
        channel = SlackWebhook(**kwargs)
        self.channels["slack"] = channel
        return channel

    def add_pagerduty(self, **kwargs) -> PagerDutyWebhook:
        channel = PagerDutyWebhook(**kwargs)
        self.channels["pagerduty"] = channel
        return channel

    def add_teams(self, **kwargs) -> TeamsWebhook:
        channel = TeamsWebhook(**kwargs)
        self.channels["teams"] = channel
        return channel

    def add_email(self, **kwargs) -> EmailNotifier:
        channel = EmailNotifier(**kwargs)
        self.channels["email"] = channel
        return channel

    async def send_all(self, detection: Dict[str, Any]) -> Dict[str, bool]:
        """Send alert to all channels."""
        results = {}
        for name, channel in self.channels.items():
            if hasattr(channel, "send"):
                results[name] = await channel.send(detection)
        return results

    async def close_all(self):
        for channel in self.channels.values():
            if hasattr(channel, "close"):
                await channel.close()


class AlertConfig:
    """Alert configuration storage."""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".aegisedr" / "alerts.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT
                )
            """)

    def save_config(self, alert_type: str, config: Dict[str, Any], enabled: bool = True):
        import json
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO alert_configs (type, config_json, enabled, created_at)
                VALUES (?, ?, ?, ?)
            """, (alert_type, json.dumps(config), enabled, datetime.utcnow().isoformat()))

    def get_configs(self, alert_type: str | None = None) -> List[Dict]:
        import json
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM alert_configs" +
                (" WHERE type = ?" if alert_type else ""),
                (alert_type,) if alert_type else (),
            )
            return [{"id": row[0], "type": row[1], **json.loads(row[2]), "enabled": row[3]} for row in cursor.fetchall()]

    def toggle(self, alert_type: str, enabled: bool):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE alert_configs SET enabled = ? WHERE type = ?",
                (enabled, alert_type),
            )


def get_alert_manager() -> AlertManager:
    """Get alert manager."""
    return AlertManager()