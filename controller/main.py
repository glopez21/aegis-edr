"""AegisEDR control-plane CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from automations.respond import AutomationEngine
from detections.matcher import DetectionEngine, calculate_severity_score

app = typer.Typer(help="AegisEDR control utility")
console = Console()


def load_events(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_rules(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@app.command()
def analyze(
    telemetry: Path = typer.Argument(..., help="JSON list of endpoint events"),
    rules: Path = typer.Option(Path("detections/rules.yaml"), help="Detection rules YAML"),
    respond: bool = typer.Option(True, help="Run automation when high-severity hit occurs"),
    store: bool = typer.Option(True, help="Store detections to database"),
    ioc_check: bool = typer.Option(True, help="Check IOC database"),
) -> None:
    """Analyze telemetry and optionally trigger automated response."""

    events = load_events(telemetry)
    engine = DetectionEngine(load_rules(rules))
    detections = engine.evaluate(events)
    detections = calculate_severity_score(detections)

    if ioc_check:
        from detections.ioc_db import IOCDatabase
        ioc_db = IOCDatabase()
        for finding in detections:
            sha256 = finding.get("event", {}).get("sha256", "")
            if sha256:
                ioc = ioc_db.check_hash(sha256)
                if ioc and ioc.get("reputation") == "malicious":
                    finding["ioc_match"] = ioc

    if not detections:
        console.print(Panel.fit("No detections fired", title="Status"))
        return

    table = Table(title="Detection Hits")
    table.add_column("Rule", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Score")
    table.add_column("Host")
    table.add_column("Process")
    table.add_column("IOC")
    for finding in detections:
        ioc_status = "✓" if "ioc_match" in finding else ""
        table.add_row(
            finding["rule"],
            finding["severity"],
            str(finding.get("score", "")),
            finding["event"]["host"],
            finding["event"].get("process", "unknown"),
            ioc_status,
        )
    console.print(table)

    if store:
        from detections.storage import IncidentStore
        store_db = IncidentStore()
        stored_count = store_db.insert_batch(detections)
        console.print(f"[green]Stored {stored_count} incidents to database[/green]")

    if respond:
        auto = AutomationEngine(console=console)
        for finding in detections:
            if finding.get("score", 0) >= 75:
                auto.isolate_host(finding["event"]["host"], reason=finding["rule"])
                auto.kill_process(
                    host=finding["event"]["host"],
                    process=finding["event"].get("process", "unknown"),
                )


@app.command()
def ruleset(rules: Path = typer.Argument(Path("detections/rules.yaml"))) -> None:
    """List loaded detection rules."""

    rule_docs = load_rules(rules)
    table = Table(title="Detection Rules")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("ATT&CK")
    table.add_column("Phase")
    table.add_column("Operator")
    table.add_column("Enabled")
    for rule in rule_docs:
        table.add_row(
            rule["name"],
            rule.get("severity", "Medium"),
            rule.get("technique", "-"),
            rule.get("mitre_phase", "-"),
            rule.get("operator", "contains"),
            "✓" if rule.get("enabled", True) else "✗",
        )
    console.print(table)


@app.command()
def monitor(
    path: str = typer.Option(str(Path.home()), help="Directory to monitor"),
    duration: int = typer.Option(60, help="Duration in seconds"),
    detect: bool = typer.Option(True, help="Run detection on file events"),
) -> None:
    """Start real-time file system monitoring."""
    from agent.file_monitor import FileSystemMonitor
    from detections.matcher import DetectionEngine, calculate_severity_score
    import yaml

    console.print(Panel.fit(f"[bold green]Monitoring:[/bold green] {path}", title="Live Monitor"))
    console.print(f"[yellow]Duration: {duration}s | Detection: {detect}[/yellow]")

    events = []

    def on_event(evt):
        events.append(evt)
        if detect:
            rule_docs = load_rules(Path("detections/rules.yaml"))
            engine = DetectionEngine(rule_docs)
            detections = engine.evaluate([evt])
            if detections:
                detections = calculate_severity_score(detections)
                table = Table(title="Detection Hits")
                table.add_column("Rule", style="cyan")
                table.add_column("Severity", style="magenta")
                table.add_column("Path", style="white")
                for finding in detections:
                    table.add_row(
                        finding["rule"],
                        finding["severity"],
                        evt.get("path", ""),
                    )
                console.print(table)
        else:
            console.print(f"[cyan]{evt['timestamp']}[/cyan] {evt['event_type']}: {evt['path']}")

    monitor = FileSystemMonitor(paths=[path], callback=on_event)
    monitor.start()

    import time
    try:
        for remaining in range(duration, 0, -1):
            console.print(f"\r[yellow]Running... {remaining}s (events: {len(events)})[/yellow]", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()

    console.print(f"\n[green]Captured {len(events)} events[/green]")


@app.command()
def watch_process(
    duration: int = typer.Option(30, help="Duration in seconds"),
    detect: bool = typer.Option(True, help="Run detection on process events"),
) -> None:
    """Start real-time process monitoring."""
    from agent.process_monitor import ProcessMonitor
    from detections.matcher import DetectionEngine, calculate_severity_score

    console.print(Panel.fit("[bold green]Process Monitor[/bold green]", title="Live Monitor"))
    console.print(f"[yellow]Duration: {duration}s | Detection: {detect}[/yellow]")

    events = []

    def on_process(evt):
        events.append(evt)
        if detect:
            evt_dict = evt.to_dict()
            rule_docs = load_rules(Path("detections/rules.yaml"))
            engine = DetectionEngine(rule_docs)
            detections = engine.evaluate([evt_dict])
            if detections:
                detections = calculate_severity_score(detections)
                table = Table(title="Detection Hits")
                table.add_column("Rule", style="cyan")
                table.add_column("Severity", style="magenta")
                table.add_column("Process", style="white")
                for finding in detections:
                    table.add_row(
                        finding["rule"],
                        finding["severity"],
                        evt.name,
                    )
                console.print(table)
        else:
            console.print(f"[cyan]{evt.timestamp}[/cyan] {evt.event_type}: {evt.name} (PID: {evt.pid})")

    monitor = ProcessMonitor(callback=on_process)
    monitor.start(interval=1.0)

    import time
    try:
        for remaining in range(duration, 0, -1):
            console.print(f"\r[yellow]Watching... {remaining}s (processes: {len(events)})[/yellow]", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()

    console.print(f"\n[green]Captured {len(events)} process events[/green]")


@app.command()
def watch_network(
    duration: int = typer.Option(30, help="Duration in seconds"),
    suspicious_only: bool = typer.Option(True, help="Show suspicious connections only"),
) -> None:
    """Start real-time network connection monitoring."""
    from agent.process_monitor import NetworkConnectionMonitor

    console.print(Panel.fit("[bold green]Network Monitor[/bold green]", title="Live Monitor"))
    console.print(f"[yellow]Duration: {duration}s | Suspicious: {suspicious_only}[/yellow]")

    connections = []

    def on_connection(evt):
        if suspicious_only and not evt.get("suspicious"):
            return
        connections.append(evt)
        table = Table(title="Connection")
        table.add_column("Protocol", style="cyan")
        table.add_column("Local", style="white")
        table.add_column("Remote", style="white")
        table.add_column("Suspicious", style="red")
        table.add_row(
            evt.get("protocol", ""),
            evt.get("local_addr", ""),
            evt.get("remote_addr", ""),
            "⚠️" if evt.get("suspicious") else "",
        )
        console.print(table)

    monitor = NetworkConnectionMonitor(callback=on_connection)
    monitor.start(interval=2.0)

    import time
    try:
        for remaining in range(duration, 0, -1):
            console.print(f"\r[yellow]Watching... {remaining}s[/yellow]", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()

    console.print(f"\n[green]Captured {len(connections)} connections[/green]")


if __name__ == "__main__":
    app()
