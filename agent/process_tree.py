"""Process tree visualization for AegisEDR."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from rich.console import Console
from rich.tree import Tree


@dataclass
class ProcessNode:
    """Represents a process in the tree."""

    pid: int
    name: str
    user: str = ""
    command_line: str = ""
    parent_pid: Optional[int] = None
    children: List["ProcessNode"] = field(default_factory=list)
    is_malicious: bool = False
    severity: str = ""

    def add_child(self, node: "ProcessNode") -> None:
        node.parent_pid = self.pid
        self.children.append(node)


@dataclass
class ProcessTree:
    """Process tree builder and renderer."""

    processes: List[ProcessNode] = field(default_factory=list)
    root_processes: List[ProcessNode] = field(default_factory=list)

    def build_from_events(self, events: Iterable[Dict]) -> None:
        """Build process tree from telemetry events."""
        pid_map: Dict[int, ProcessNode] = {}

        for event in events:
            pid = event.get("pid", 0)
            if not pid:
                continue

            node = ProcessNode(
                pid=pid,
                name=event.get("process", "unknown"),
                user=event.get("user", ""),
                command_line=event.get("command_line", ""),
            )
            pid_map[pid] = node

            parent_pid = event.get("parent_pid", 0)
            if parent_pid and parent_pid in pid_map:
                pid_map[parent_pid].add_child(node)
            else:
                self.root_processes.append(node)

            self.processes.append(node)

    def find_by_name(self, name: str) -> List[ProcessNode]:
        """Find all processes matching name."""
        return [p for p in self.processes if name.lower() in p.name.lower()]

    def render_rich(self, console: Console | None = None) -> Tree:
        """Render process tree using Rich."""
        if console is None:
            console = Console()

        tree = Tree("[bold]Process Tree[/bold]")

        def add_nodes(parent_node: ProcessNode, tree_node: Tree):
            style = ""
            if parent_node.is_malicious:
                style = "bold red"
            elif parent_node.severity:
                if parent_node.severity == "Critical":
                    style = "bold red"
                elif parent_node.severity == "High":
                    style = "red"
                elif parent_node.severity == "Medium":
                    style = "yellow"

            label = f"{parent_node.pid}: {parent_node.name}"
            if parent_node.user:
                label += f" ({parent_node.user})"
            if parent_node.is_malicious:
                label += " ⚠"

            branch = tree_node.add(f"[{style}]{label}[/{style}]" if style else label)
            for child in parent_node.children:
                add_nodes(child, branch)

        for root in self.root_processes:
            add_nodes(root, tree)

        return tree

    def print_tree(self, console: Console | None = None) -> None:
        """Print the process tree to console."""
        if console is None:
            console = Console()

        tree = self.render_rich(console)
        console.print(tree)


def render_process_tree(events: Iterable[Dict], console: Console | None = None) -> None:
    """Convenience function to render events as process tree."""
    tree = ProcessTree()
    tree.build_from_events(events)
    tree.print_tree(console)


def get_anomalous_paths() -> List[str]:
    """Get list of anomalous process paths for detection."""
    return [
        "%TEMP%",
        "%APPDATA%",
        "AppData\\Local\\Temp",
        "Downloads",
        "\\Windows\\Temp",
        "\\ ??",
    ]