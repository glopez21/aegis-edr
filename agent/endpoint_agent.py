"""Endpoint agent simulator for AegisEDR."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class ProcessEvent:
    """Simple representation of a process execution event."""

    host: str
    user: str
    process: str
    command_line: str
    sha256: str
    parent: str
    integrity_level: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class EndpointAgent:
    """Simulate EDR endpoint telemetry generation."""

    def __init__(self, hostname: str, user: str) -> None:
        self.hostname = hostname
        self.user = user

    def simulate_process(self, **overrides: Any) -> ProcessEvent:
        base_event = ProcessEvent(
            host=self.hostname,
            user=self.user,
            process="powershell.exe",
            command_line="powershell.exe -nop -w hidden",
            sha256="d41d8cd98f00b204e9800998ecf8427e",
            parent="explorer.exe",
            integrity_level="High",
        )
        for key, value in overrides.items():
            setattr(base_event, key, value)
        return base_event

    @staticmethod
    def load_playback(file_path: Path) -> List[Dict[str, Any]]:
        import json

        return json.loads(file_path.read_text())


def main() -> None:  # pragma: no cover - manual smoke test helper
    agent = EndpointAgent("lab-endpoint01", "analyst")
    sample = agent.simulate_process(command_line="powershell -enc ...", parent="winword.exe")
    print(sample.to_dict())


if __name__ == "__main__":  # pragma: no cover
    main()
