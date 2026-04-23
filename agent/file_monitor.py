"""Real-time file system monitoring for AegisEDR."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Dict, List, Optional

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer


class FileEventHandler(FileSystemEventHandler):
    """Handler for file system events."""

    def __init__(self, callback: Callable[[Dict], None] | None = None):
        self.callback = callback
        self.events: List[Dict] = []
        self.suspicious_extensions = [".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".hta"]
        self.suspicious_paths = ["\\Temp\\", "%TEMP%", "AppData\\Local\\Temp", "\\Downloads\\"]

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._handle_event("created", event)

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._handle_event("modified", event)

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._handle_event("deleted", event)

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._handle_event("moved", event)

    def _handle_event(self, event_type: str, event: FileSystemEvent):
        import datetime
        path = event.src_path

        evt = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "path": path,
            "filename": os.path.basename(path),
            "extension": os.path.splitext(path)[1],
            "suspicious": self._is_suspicious(path),
        }

        self.events.append(evt)
        if self.callback:
            self.callback(evt)

    def _is_suspicious(self, path: str) -> bool:
        path_lower = path.lower()
        return any(susp in path_lower for susp in self.suspicious_paths)


class FileSystemMonitor:
    """Real-time file system monitoring."""

    def __init__(self, paths: List[str] | None = None, callback: Callable[[Dict], None] | None = None):
        self.paths = paths or [str(Path.home())]
        self.callback = callback
        self.observer = Observer()
        self.handlers: List[FileEventHandler] = []
        self._running = False

    def add_watch_path(self, path: str) -> None:
        """Add a path to watch."""
        if path not in self.paths:
            self.paths.append(path)

    def start(self) -> None:
        """Start monitoring."""
        handler = FileEventHandler(callback=self.callback)
        self.handlers.append(handler)

        for path in self.paths:
            if os.path.exists(path):
                self.observer.schedule(handler, path, recursive=True)

        self.observer.start()
        self._running = True

    def stop(self) -> None:
        """Stop monitoring."""
        self.observer.stop()
        self.observer.join(timeout=5)
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def get_events(self, limit: int = 100) -> List[Dict]:
        events = []
        for handler in self.handlers:
            events.extend(handler.events[-limit:])
        return events


def monitor_directory(path: str, callback: Callable[[Dict], None] | None = None):
    """Convenience function to monitor a directory."""
    monitor = FileSystemMonitor(paths=[path], callback=callback)
    monitor.start()
    return monitor


class WindowsEventLogCollector:
    """Windows Event Log collector (Windows only)."""

    def __init__(self, log_names: List[str] | None = None):
        self.log_names = log_names or ["Security", "System", "Application"]
        self._running = False
        self._events: List[Dict] = []

    def _collect_events(self):
        """Collect events (Windows only - simulated for cross-platform)."""
        import datetime

        sample_events = [
            {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "log": "Security",
                "event_id": 4624,
                "message": "An account was successfully logged on",
                "user": "SYSTEM",
                "host": "WORKSTATION01",
            },
            {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "log": "Security",
                "event_id": 4672,
                "message": "Special privileges assigned to new logon",
                "user": "SYSTEM",
                "host": "WORKSTATION01",
            },
            {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "log": "System",
                "event_id": 7036,
                "message": "The Windows Defender service entered the running state",
                "user": "SYSTEM",
                "host": "WORKSTATION01",
            },
        ]

        for event in sample_events:
            self._events.append(event)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def get_events(self, limit: int = 100) -> List[Dict]:
        return self._events[-limit:]


class SyslogListener:
    """Real-time syslog listener (UDP/TCP)."""

    def __init__(self, host: str = "0.0.0.0", port: int = 514, protocol: str = "udp"):
        self.host = host
        self.port = port
        self.protocol = protocol
        self._running = False
        self._messages: List[str] = []
        self._socket = None

    def start(self) -> bool:
        """Start listening for syslog messages."""
        import socket

        try:
            if self.protocol == "udp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.bind((self.host, self.port))
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.bind((self.host, self.port))
                self._socket.listen(5)

            self._running = True
            return True
        except Exception:
            return False

    def stop(self) -> None:
        if self._socket:
            self._socket.close()
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def receive(self, timeout: float = 1.0) -> List[str]:
        """Receive available syslog messages."""
        messages = []
        if not self._running or not self._socket:
            return messages

        self._socket.settimeout(timeout)
        try:
            if self.protocol == "udp":
                data, _ = self._socket.recvfrom(4096)
                messages.append(data.decode("utf-8", errors="ignore"))
            else:
                conn, _ = self._socket.accept()
                data = conn.recv(4096)
                messages.append(data.decode("utf-8", errors="ignore"))
                conn.close()
        except socket.timeout:
            pass

        return messages


def create_live_monitor(
    config: Dict,
    detection_callback: Callable[[Dict], None] | None = None,
) -> FileSystemMonitor | SyslogListener | WindowsEventLogCollector:
    """Factory to create appropriate live monitor based on config."""
    monitor_type = config.get("type", "filesystem")

    if monitor_type == "filesystem":
        return FileSystemMonitor(
            paths=config.get("paths", []),
            callback=detection_callback,
        )
    elif monitor_type == "syslog":
        return SyslogListener(
            host=config.get("host", "0.0.0.0"),
            port=config.get("port", 514),
            protocol=config.get("protocol", "udp"),
        )
    elif monitor_type == "eventlog":
        return WindowsEventLogCollector(
            log_names=config.get("logs", ["Security", "System"]),
        )

    raise ValueError(f"Unknown monitor type: {monitor_type}")