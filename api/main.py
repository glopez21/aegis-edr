"""Full REST API Server for AegisEDR."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import typer
import yaml
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.telemetry_collector import TelemetryCollector, TelemetryEvent
from automations.edr_integrations import CrowdStrikeClient, DefenderEprClient
from detections.ioc_db import IOCDatabase
from detections.matcher import DetectionEngine, calculate_severity_score
from detections.storage import IncidentStore
from integrations.siem_connectors import SIEMManager

app = FastAPI(
    title="AegisEDR API",
    version="0.3.0",
    description="Complete REST API for AegisEDR Endpoint Detection & Response",
)

store = IncidentStore()
ioc_db = IOCDatabase()
siem = SIEMManager()
collector = TelemetryCollector()


class DetectionCreate(BaseModel):
    rule: str
    technique: str
    severity: str
    host: str
    process: str
    command_line: str = ""
    parent: str = ""
    user: str = ""
    sha256: str = ""


class RuleUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    severity: str | None = None
    priority: int | None = None


class IOCCreate(BaseModel):
    type: str = "sha256"
    value: str
    reputation: str
    tags: str = ""
    confidence: float = 0.5


class IncidentUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    notes: str | None = None


class AlertConfig(BaseModel):
    type: str
    webhook_url: str
    enabled: bool = True


alert_configs: List[Dict[str, Any]] = []


@app.get("/")
async def root():
    return {
        "service": "AegisEDR API",
        "version": "0.3.0",
        "status": "running",
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/incidents")
async def get_incidents(
    limit: int = 100,
    severity: str | None = None,
    host: str | None = None,
):
    """Get incidents with optional filtering."""
    if host:
        return store.get_by_host(host, limit)
    return store.get_recent(limit, severity)


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: int):
    """Get a single incident by ID."""
    with store.db_path.parent / "incidents.db" as conn:
        import sqlite3
        conn = sqlite3.connect(store.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        return dict(row)


@app.post("/api/incidents")
async def create_incident(detection: DetectionCreate):
    """Create a new incident from detection."""
    event = detection.dict()
    detection_data = {
        "rule": detection.rule,
        "technique": detection.technique,
        "mitre_phase": "unknown",
        "severity": detection.severity,
        "score": 0,
        "event": event,
    }
    detection_data = calculate_severity_score([detection_data])[0]
    store.insert(detection_data)
    return {"status": "created", "id": detection_data.get("id")}


@app.patch("/api/incidents/{incident_id}")
async def update_incident(incident_id: int, update: IncidentUpdate):
    """Update incident status/assignment."""
    data = update.dict(exclude_unset=True)
    if "status" in data:
        store.mark_responded(incident_id, data["status"])
    return {"status": "updated"}


@app.delete("/api/incidents/{incident_id}")
async def delete_incident(incident_id: int):
    """Delete an incident."""
    with store.db_path as conn:
        import sqlite3
        conn = sqlite3.connect(store.db_path)
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
    return {"status": "deleted"}


@app.get("/api/rules")
async def get_rules():
    """Get all detection rules."""
    rules_path = PROJECT_ROOT / "detections" / "rules.yaml"
    with rules_path.open() as f:
        rules = yaml.safe_load(f)
    return rules


@app.post("/api/rules")
async def add_rule(rule: Dict[str, Any]):
    """Add a new detection rule."""
    rules_path = PROJECT_ROOT / "detections" / "rules.yaml"
    with rules_path.open() as f:
        rules = yaml.safe_load(f)
    rules.append(rule)
    with rules_path.open("w") as f:
        yaml.dump(rules, f, default_flow_style=False)
    return {"status": "added", "rule": rule.get("name")}


@app.patch("/api/rules/{rule_name}")
async def update_rule(rule_name: str, update: RuleUpdate):
    """Update a detection rule."""
    rules_path = PROJECT_ROOT / "detections" / "rules.yaml"
    with rules_path.open() as f:
        rules = yaml.safe_load(f)
    for rule in rules:
        if rule.get("name") == rule_name:
            if update.name is not None:
                rule["name"] = update.name
            if update.enabled is not None:
                rule["enabled"] = update.enabled
            if update.severity is not None:
                rule["severity"] = update.severity
            if update.priority is not None:
                rule["priority"] = update.priority
            break
    with rules_path.open("w") as f:
        yaml.dump(rules, f, default_flow_style=False)
    return {"status": "updated"}


@app.delete("/api/rules/{rule_name}")
async def delete_rule(rule_name: str):
    """Delete a detection rule."""
    rules_path = PROJECT_ROOT / "detections" / "rules.yaml"
    with rules_path.open() as f:
        rules = yaml.safe_load(f)
    rules = [r for r in rules if r.get("name") != rule_name]
    with rules_path.open("w") as f:
        yaml.dump(rules, f, default_flow_style=False)
    return {"status": "deleted"}


@app.get("/api/iocs")
async def get_iocs(
    reputation: str | None = None,
    limit: int = 100,
):
    """Get IOC database entries."""
    if reputation:
        return ioc_db.get_by_reputation(reputation)
    with ioc_db.db_path as conn:
        import sqlite3
        conn = sqlite3.connect(ioc_db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM iocs ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]


@app.post("/api/iocs")
async def create_ioc(ioc: IOCCreate):
    """Add IOC to database."""
    ioc_id = ioc_db.add_ioc(
        ioc_type=ioc.type,
        value=ioc.value,
        reputation=ioc.reputation,
        tags=ioc.tags,
        confidence=ioc.confidence,
    )
    return {"status": "created", "id": ioc_id}


@app.get("/api/iocs/{ioc_type}/{value}")
async def lookup_ioc(ioc_type: str, value: str):
    """Lookup IOC by type and value."""
    result = ioc_db.lookup(ioc_type, value)
    if not result:
        raise HTTPException(status_code=404, detail="IOC not found")
    return result


@app.delete("/api/iocs/{ioc_type}/{value}")
async def delete_ioc(ioc_type: str, value: str):
    """Delete IOC."""
    result = ioc_db.lookup(ioc_type, value)
    if not result:
        raise HTTPException(status_code=404, detail="IOC not found")
    with ioc_db.db_path as conn:
        import sqlite3
        conn = sqlite3.connect(ioc_db.db_path)
        conn.execute(
            "DELETE FROM iocs WHERE type = ? AND value = ?",
            (ioc_type, value),
        )
        conn.commit()
    return {"status": "deleted"}


@app.post("/api/analyze")
async def analyze_events(events: List[Dict[str, Any]]):
    """Analyze events against rules."""
    rules_path = PROJECT_ROOT / "detections" / "rules.yaml"
    with rules_path.open() as f:
        rules = yaml.safe_load(f)
    engine = DetectionEngine(rules)
    detections = engine.evaluate(events)
    detections = calculate_severity_score(detections)
    stored = store.insert_batch(detections)
    return {"detections": detections, "stored": stored}


@app.post("/api/analyze/file")
async def analyze_file(file_path: str):
    """Analyze telemetry from file."""
    path = PROJECT_ROOT / file_path
    with path.open() as f:
        events = json.load(f)
    return await analyze_events(events)


@app.get("/api/stats")
async def get_stats():
    """Get system statistics."""
    return store.get_stats()


@app.get("/api/telemetry")
async def get_telemetry(limit: int = 100):
    """Get collected telemetry events."""
    return collector.get_events(limit)


@app.post("/api/telemetry")
async def submit_telemetry(event: Dict[str, Any]):
    """Submit a telemetry event."""
    tevent = TelemetryEvent(**event)
    collector.on_event(tevent)
    return {"status": "accepted"}


@app.post("/api/telemetry/collect")
async def collect_from_source(source: str = "etw"):
    """Start collecting from a source."""
    if source == "etw":
        collector.collect_etw().start()
    elif source == "eventlog":
        collector.collect_eventlog().start()
    return {"status": "started", "source": source}


@app.post("/api/siem/forward")
async def forward_to_siem(detection: Dict[str, Any]):
    """Forward detection to configured SIEM connectors."""
    return siem.forward(detection)


@app.get("/api/alerts")
async def get_alerts():
    """Get alert configurations."""
    return alert_configs


@app.post("/api/alerts")
async def create_alert(config: AlertConfig):
    """Create alert webhook configuration."""
    alert_configs.append(config.dict())
    return {"status": "created"}


@app.post("/api/alerts/{alert_type}/test")
async def test_alert(alert_type: str):
    """Test alert webhook."""
    for config in alert_configs:
        if config.get("type") == alert_type and config.get("enabled"):
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        config["webhook_url"],
                        json={"test": True, "message": "AegisEDR test alert"},
                    )
                    return {"status": "sent", "code": resp.status_code}
            except Exception as e:
                return {"status": "error", "detail": str(e)}
    raise HTTPException(status_code=404, detail="Alert config not found")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time detection streaming."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            event = json.loads(data)
            events = [event]
            rules_path = PROJECT_ROOT / "detections" / "rules.yaml"
            with rules_path.open() as f:
                rules = yaml.safe_load(f)
            engine = DetectionEngine(rules)
            detections = engine.evaluate(events)
            detections = calculate_severity_score(detections)
            await websocket.send_json({"detections": detections})
    except WebSocketDisconnect:
        pass


def run_api(host: str = "0.0.0.0", port: int = 8080):
    """Run the FastAPI server."""
    import uvicorn
    print(f"Starting AegisEDR API on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    typer.run(run_api)