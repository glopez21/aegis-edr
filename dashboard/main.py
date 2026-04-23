"""AegisEDR Web Dashboard with FastAPI and WebSocket streaming."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path

import typer
import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from rich.console import Console

PROJECT_ROOT = Path(__file__).resolve().parent.parent
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detections.matcher import DetectionEngine
from detections.storage import IncidentStore

app = FastAPI(title="AegisEDR Dashboard", version="0.2.0")

store = IncidentStore()
websocket_connections: list[WebSocket] = []


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for live detection streaming."""
    await websocket.accept()
    websocket_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(json.dumps({"status": "ok"}))
    except WebSocketDisconnect:
        websocket_connections.remove(websocket)


async def broadcast_detection(detection: dict):
    """Broadcast detection to all connected WebSocket clients."""
    for ws in websocket_connections:
        try:
            await ws.send_json(detection)
        except Exception:
            pass


@app.get("/")
async def root():
    """Dashboard home with embedded UI."""
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>AegisEDR Dashboard</title>
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; }
        h1 { color: #00ff88; }
        .card { background: #252525; padding: 15px; margin: 10px 0; border-radius: 8px; }
        .critical { border-left: 4px solid #ff4444; }
        .high { border-left: 4px solid #ff8800; }
        .medium { border-left: 4px solid #ffaa00; }
        .low { border-left: 4px solid #00aaff; }
        #feed { max-height: 600px; overflow-y: auto; }
        .stat { display: inline-block; margin-right: 30px; }
        .stat-value { font-size: 2em; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🛡️ AegisEDR Dashboard v0.2.0</h1>
    <div>
        <span class="stat"><div class="stat-value" id="total">0</div>Total</span>
        <span class="stat"><div class="stat-value" id="critical">0</div>Critical</span>
        <span class="stat"><div class="stat-value" id="high">0</div>High</span>
        <span class="stat"><div class="stat-value" id="responded">0</div>Responded</span>
    </div>
    <h2>Live Detection Feed</h2>
    <div id="feed"></div>
    <script>
        const ws = new WebSocket("ws://" + location.host + "/ws");
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            if (data.rule) {
                const feed = document.getElementById("feed");
                const div = document.createElement("div");
                div.className = "card " + (data.severity || "medium").toLowerCase();
                div.textContent = `[${data.severity}] ${data.rule} on ${data.event?.host}`;
                feed.insertBefore(div, feed.firstChild);
                updateStats();
            }
        };
        function updateStats() {
            fetch("/api/stats").then(r => r.json()).then(data => {
                document.getElementById("total").textContent = data.total || 0;
                document.getElementById("critical").textContent = data.by_severity?.Critical || 0;
                document.getElementById("high").textContent = data.by_severity?.High || 0;
                document.getElementById("responded").textContent = data.responded || 0;
            });
        }
        setInterval(updateStats, 5000);
    </script>
</body>
</html>
    """
    return HTMLResponse(html)


@app.get("/api/stats")
async def api_stats():
    """API endpoint for incident statistics."""
    return store.get_stats()


@app.get("/api/incidents")
async def api_incidents(limit: int = 100):
    """API endpoint for recent incidents."""
    return store.get_recent(limit=limit)


@app.get("/api/analyze")
async def api_analyze(telemetry: str = "samples/telemetry_sample.json"):
    """API endpoint to analyze telemetry file."""
    telemetry_path = PROJECT_ROOT / telemetry
    events = json.loads(telemetry_path.read_text())
    rules_path = PROJECT_ROOT / "detections" / "rules.yaml"
    rules = yaml.safe_load(rules_path.read_text())
    engine = DetectionEngine(rules)
    detections = engine.evaluate(events)
    from detections.matcher import calculate_severity_score
    detections = calculate_severity_score(detections)
    inserted = store.insert_batch(detections)
    return {"detections": detections, "stored": inserted}


console = Console()


def run_dashboard(host: str = "0.0.0.0", port: int = 8000):
    """Run the FastAPI server."""
    import uvicorn
    console.print(f"[green]Starting AegisEDR Dashboard on http://{host}:{port}[/green]")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    typer.run(run_dashboard)