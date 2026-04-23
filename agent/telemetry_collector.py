"""Real-time telemetry collection for AegisEDR."""

from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from rich.console import Console


@dataclass
class TelemetryEvent:
    """Normalized telemetry event."""

    timestamp: str
    host: str
    user: str
    process: str
    parent: str = ""
    command_line: str = ""
    pid: int = 0
    parent_pid: int = 0
    path: str = ""
    sha256: str = ""
    integrity_level: str = ""
    source: str = "manual"
    event_type: str = "process"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "user": self.user,
            "process": self.process,
            "parent": self.parent,
            "command_line": self.command_line,
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "path": self.path,
            "sha256": self.sha256,
            "integrity_level": self.integrity_level,
            "source": self.source,
            "event_type": self.event_type,
        }


class EventLogListener:
    """Windows Event Log listener (simulated for cross-platform)."""

    def __init__(self, channels: List[str] | None = None):
        self.channels = channels or ["Security", "System", "Application"]
        self._running = False
        self._callbacks: List[Callable[[TelemetryEvent], None]] = []

    def add_callback(self, callback: Callable[[TelemetryEvent], None]) -> None:
        self._callbacks.append(callback)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def emit(self, event: TelemetryEvent) -> None:
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass


class MockETWCollector:
    """Simulated ETW (Event Tracing for Windows) collector for cross-platform demo."""

    def __init__(self):
        self._running = False
        self._callbacks: List[Callable[[TelemetryEvent], None]] = []
        self._thread: Optional[threading.Thread] = None

    def add_callback(self, callback: Callable[[TelemetryEvent], None]) -> None:
        self._callbacks.append(callback)

    def _emit_sample_events(self):
        """Emit sample events for demonstration."""
        samples = [
            TelemetryEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                host="workstation01",
                user="admin",
                process="powershell.exe",
                parent="WINWORD.EXE",
                command_line='powershell.exe -enc SQBbAGgAdAAtAH',
                pid=1234,
                parent_pid=5678,
                path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                integrity_level="High",
                source="etw",
            ),
            TelemetryEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                host="workstation01",
                user="admin",
                process="cmd.exe",
                parent="explorer.exe",
                command_line="cmd.exe /c dir",
                pid=1235,
                parent_pid=9999,
                path="C:\\Windows\\System32\\cmd.exe",
                integrity_level="Medium",
                source="etw",
            ),
            TelemetryEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                host="workstation02",
                user="system",
                process="mimikatz.exe",
                parent="cmd.exe",
                command_line="mimikatz.exe privilege::debug",
                pid=2000,
                parent_pid=1235,
                path="C:\\Temp\\mimikatz.exe",
                integrity_level="System",
                source="etw",
            ),
        ]
        while self._running:
            for event in samples:
                for callback in self._callbacks:
                    try:
                        callback(event)
                    except Exception:
                        pass
            break

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._emit_sample_events, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def is_running(self) -> bool:
        return self._running


@dataclass
class TelemetryCollector:
    """Main telemetry collector with multiple sources."""

    sources: List[str] = field(default_factory=list)
    _listeners: Dict[str, Any] = field(default_factory=dict)
    _events: List[TelemetryEvent] = field(default_factory=list)
    _callbacks: List[Callable[[TelemetryEvent], None]] = field(default_factory=list)

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)

    def add_callback(self, callback: Callable[[TelemetryEvent], None]) -> None:
        self._callbacks.append(callback)

    def on_event(self, event: TelemetryEvent) -> None:
        self._events.append(event)
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass

    def collect_eventlog(self, channels: List[str] | None = None) -> EventLogListener:
        listener = EventLogListener(channels)
        listener.add_callback(self.on_event)
        self._listeners["eventlog"] = listener
        return listener

    def collect_etw(self) -> MockETWCollector:
        collector = MockETWCollector()
        collector.add_callback(self.on_event)
        self._listeners["etw"] = collector
        return collector

    def replay_file(self, file_path: Path) -> List[TelemetryEvent]:
        events = []
        with file_path.open("r") as f:
            data = json.load(f)
        for item in data:
            event = TelemetryEvent(**item) if isinstance(item, dict) else TelemetryEvent(
                timestamp=item.get("timestamp", ""),
                host=item.get("host", ""),
                user=item.get("user", ""),
                process=item.get("process", ""),
                parent=item.get("parent", ""),
                command_line=item.get("command_line", ""),
                pid=item.get("pid", 0),
                parent_pid=item.get("parent_pid", 0),
                path=item.get("path", ""),
                sha256=item.get("sha256", ""),
                integrity_level=item.get("integrity_level", ""),
            )
            events.append(event)
            self._events.append(event)
        return events

    def get_events(self, limit: int = 100) -> List[TelemetryEvent]:
        return self._events[-limit:]

    def clear_events(self) -> None:
        self._events.clear()

    def start_all(self) -> None:
        for listener in self._listeners.values():
            listener.start()

    def stop_all(self) -> None:
        for listener in self._listeners.values():
            listener.stop()


def stream_telemetry(
    file_path: Path | None = None,
    callback: Callable[[TelemetryEvent], None] | None = None,
    interval: float = 1.0,
):
    """Stream telemetry events with optional callback."""
    collector = TelemetryCollector()

    if callback:
        collector.add_callback(callback)

    if file_path:
        collector.replay_file(file_path)

    for event in collector.get_events():
        print(json.dumps(event.to_dict()))


def live_monitor(console: Console | None = None):
    """Interactive live monitoring mode."""
    if console is None:
        console = Console()

    collector = TelemetryCollector()
    etw = collector.collect_etw()

    console.print("[bold green]Starting live telemetry monitoring...[/bold green]")
    console.print("[yellow]Press Ctrl+C to stop[/yellow]")

    etw.start()

    try:
        while etw.is_running():
            events = collector.get_events(limit=10)
            for event in events:
                console.print(f"[cyan]{event.timestamp}[/cyan] {event.host} {event.process}")
    except KeyboardInterrupt:
        etw.stop()
        console.print("[red]Stopped[/red]")