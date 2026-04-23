"""Automation helpers for AegisEDR."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from rich.console import Console


@dataclass
class AutomationEngine:
    console: Optional[Console] = None

    def _log(self, message: str) -> None:
        if self.console:
            self.console.print(message)
        else:
            print(message)

    def isolate_host(self, host: str, reason: str) -> None:
        self._log(f"[bold red]Isolating[/bold red] host {host} due to {reason}")

    def kill_process(self, host: str, process: str) -> None:
        self._log(f"Terminating process {process} on {host}")

    def ban_hash(self, sha256: str) -> None:
        self._log(f"Banning hash {sha256}")
