"""Real-time process monitoring for AegisEDR."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional


@dataclass
class ProcessEvent:
    """Process creation/termination event."""

    timestamp: str
    event_type: str
    pid: int
    ppid: int
    name: str
    path: str
    user: str
    command_line: str = ""
    integrity_level: str = ""

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "path": self.path,
            "user": self.user,
            "command_line": self.command_line,
            "integrity_level": self.integrity_level,
        }


class ProcessMonitor:
    """Real-time process monitoring using psutil."""

    def __init__(self, callback: Callable[[ProcessEvent], None] | None = None):
        self.callback = callback
        self._running = False
        self._thread: threading.Thread | None = None
        self._known_pids: Dict[int, Dict] = {}
        self._events: List[ProcessEvent] = []

        self.suspicious_processes = [
            "mimikatz", "pwdump", "procdump", "lsass",
            "psexec", "wce", "gsecdump", "mempgdump",
        ]
        self.suspicious_paths = ["\\Temp\\", "%TEMP%", "Downloads\\"]

    def _get_current_user(self) -> str:
        """Get current user."""
        try:
            return os.environ.get("USERNAME", os.environ.get("USER", "unknown"))
        except Exception:
            return "unknown"

    def _scan_processes(self):
        """Scan for new/terminated processes."""
        try:
            import psutil

            current_pids = set()
            for proc in psutil.process_iter(["pid", "name", "ppid", "username", "exe", "cmdline"]):
                try:
                    pinfo = proc.info
                    pid = pinfo["pid"]
                    current_pids.add(pid)

                    if pid not in self._known_pids:
                        exe_path = pinfo.get("exe", "")
                        cmdline = " ".join(pinfo.get("cmdline", []))
                        user = pinfo.get("username", self._get_current_user())

                        event = ProcessEvent(
                            timestamp=datetime.utcnow().isoformat() + "Z",
                            event_type="created",
                            pid=pid,
                            ppid=pinfo.get("ppid", 0),
                            name=pinfo["name"] or "unknown",
                            path=exe_path,
                            user=user,
                            command_line=cmdline,
                            integrity_level="Medium",
                        )
                        self._events.append(event)
                        if self.callback:
                            self.callback(event)
                        self._known_pids[pid] = {
                            "name": pinfo["name"],
                            "exe": exe_path,
                        }

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            for old_pid in set(self._known_pids.keys()) - current_pids:
                del self._known_pids[old_pid]

        except ImportError:
            self._sample_events()

    def _sample_events(self):
        """Generate sample events for demo."""
        events = [
            ProcessEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                event_type="created",
                pid=5678,
                ppid=1234,
                name="powershell.exe",
                path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                user="admin",
                command_line="powershell.exe -enc SQBbAGgAdAAtAH",
            ),
            ProcessEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                event_type="created",
                pid=9000,
                ppid=5678,
                name="cmd.exe",
                path="C:\\Windows\\System32\\cmd.exe",
                user="admin",
                command_line="cmd.exe /c whoami",
            ),
        ]
        for event in events:
            self._events.append(event)
            if self.callback:
                self.callback(event)

    def start(self, interval: float = 1.0) -> None:
        """Start monitoring processes."""
        self._running = True

        def scan_loop():
            while self._running:
                self._scan_processes()
                import time
                time.sleep(interval)

        self._thread = threading.Thread(target=scan_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def is_running(self) -> bool:
        return self._running

    def get_events(self, limit: int = 100) -> List[ProcessEvent]:
        return self._events[-limit:]


class NetworkConnectionMonitor:
    """Monitor active network connections."""

    def __init__(self, callback: Callable[[Dict], None] | None = None):
        self.callback = callback
        self._running = False
        self._thread: threading.Thread | None = None
        self._connections: List[Dict] = []

        self.suspicious_ports = [4444, 4443, 8080, 31337, 1337]
        self.suspicious_ips = ["10.0.0.1", "192.168.1.100"]

    def _scan_connections(self):
        """Scan active network connections."""
        try:
            import psutil

            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED":
                    evt = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "protocol": "tcp" if conn.type == 1 else "udp",
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "pid": conn.pid,
                        "status": conn.status,
                        "suspicious": self._is_suspicious(conn),
                    }
                    self._connections.append(evt)
                    if self.callback and self._is_suspicious(conn):
                        self.callback(evt)

        except ImportError:
            self._sample_connections()

    def _is_suspicious(self, conn) -> bool:
        """Check if connection is suspicious."""
        if not conn.raddr:
            return False
        return (
            conn.raddr.port in self.suspicious_ports
            or conn.raddr.ip in self.suspicious_ips
        )

    def _sample_connections(self):
        """Generate sample connections."""
        samples = [
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "protocol": "tcp",
                "local_addr": "192.168.1.100:443",
                "remote_addr": "142.250.185.78:443",
                "pid": 1234,
                "status": "ESTABLISHED",
                "suspicious": False,
            },
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "protocol": "tcp",
                "local_addr": "192.168.1.100:52341",
                "remote_addr": "203.0.113.50:4444",
                "pid": 5678,
                "status": "ESTABLISHED",
                "suspicious": True,
            },
        ]
        for conn in samples:
            self._connections.append(conn)
            if self.callback and conn["suspicious"]:
                self.callback(conn)

    def start(self, interval: float = 2.0) -> None:
        """Start monitoring connections."""
        self._running = True

        def scan_loop():
            while self._running:
                self._scan_connections()
                import time
                time.sleep(interval)

        self._thread = threading.Thread(target=scan_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def is_running(self) -> bool:
        return self._running

    def get_connections(self, limit: int = 100) -> List[Dict]:
        return self._connections[-limit:]


def create_monitor(
    monitor_type: str,
    callback: Callable | None = None,
) -> ProcessMonitor | NetworkConnectionMonitor:
    """Factory for creating monitors."""
    if monitor_type == "process":
        return ProcessMonitor(callback=callback)
    elif monitor_type == "network":
        return NetworkConnectionMonitor(callback=callback)
    raise ValueError(f"Unknown monitor type: {monitor_type}")