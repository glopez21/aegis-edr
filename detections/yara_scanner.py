"""Simple YARA-style rule scanner for AegisEDR."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional


@dataclass
class YaraRule:
    """Simple YARA-like rule definition."""

    name: str
    strings: List[str] = field(default_factory=list)
    condition: str = "any of them"
    meta: Dict[str, str] = field(default_factory=dict)

    def match(self, data: str) -> bool:
        """Check if data matches the rule."""
        if not self.strings:
            return False

        data_lower = data.lower()
        matches = [s.lower() in data_lower for s in self.strings]

        if self.condition == "any of them":
            return any(matches)
        elif self.condition == "all of them":
            return all(matches)
        elif self.condition == "none of them":
            return not any(matches)

        return any(matches)


@dataclass
class YaraScanner:
    """Simple YARA scanner for strings and files."""

    rules: List[YaraRule] = field(default_factory=list)

    def add_rule(self, rule: YaraRule) -> None:
        self.rules.append(rule)

    def add_rules_from_dict(self, rules_data: List[Dict]) -> None:
        for r in rules_data:
            self.add_rule(YaraRule(
                name=r.get("name", "unnamed"),
                strings=r.get("strings", []),
                condition=r.get("condition", "any of them"),
                meta=r.get("meta", {}),
            ))

    def scan_string(self, data: str) -> List[Dict]:
        """Scan a string for rule matches."""
        results = []
        for rule in self.rules:
            if rule.match(data):
                results.append({
                    "rule": rule.name,
                    "matches": rule.strings,
                    "meta": rule.meta,
                })
        return results

    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan a file for rule matches."""
        try:
            with file_path.open("rb") as f:
                data = f.read()
            return self.scan_string(data.decode("utf-8", errors="ignore"))
        except Exception:
            return []

    def scan_events(self, events: Iterable[Dict]) -> List[Dict]:
        """Scan event field values for rule matches."""
        results = []
        for event in events:
            for field_name, field_value in event.items():
                if isinstance(field_value, str):
                    matches = self.scan_string(field_value)
                    for match in matches:
                        results.append({
                            "event": event,
                            "field": field_name,
                            "matched": match,
                        })
        return results


STOCK_YARA_RULES = [
    YaraRule(
        name="mimikatz_credential_dumper",
        strings=["mimikatz", "privilege::debug", "sekurlsa::logonpasswords", "lsadump::"],
        condition="any of them",
        meta={"author": "aegis-edr", " severity": "critical"},
    ),
    YaraRule(
        name="powershell_encoded_command",
        strings=["powershell.exe -enc", "-encodedcommand", "-enc "],
        condition="any of them",
        meta={"author": "aegis-edr", "severity": "high"},
    ),
    YaraRule(
        name="suspicious_powershell",
        strings=["Invoke-Expression", "Invoke-WebRequest", "IEX", "DownloadString", "DownloadData"],
        condition="any of them",
        meta={"author": "aegis-edr", "severity": "medium"},
    ),
    YaraRule(
        name="reverse_shell",
        strings=["/bin/sh -i", "nc -e", "bash -i", "python.*socket", "powershell.*tcp"],
        condition="any of them",
        meta={"author": "aegis-edr", "severity": "critical"},
    ),
    YaraRule(
        name="network_exfiltration",
        strings=["ftp ", "tftp ", "nc ", "wget", "curl ", " bitsadmin"],
        condition="any of them",
        meta={"author": "aegis-edr", "severity": "high"},
    ),
    YaraRule(
        name="credential_access",
        strings=["procdump", "lsass", "pwdump", "cachedump", "SamDump", "WCE"],
        condition="any of them",
        meta={"author": "aegis-edr", "severity": "high"},
    ),
    YaraRule(
        name="persistence_registry",
        strings=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        condition="any of them",
        meta={"author": "aegis-edr", "severity": "high"},
    ),
    YaraRule(
        name="ransomware_extensions",
        strings=[".encrypted", ".locked", ".crypto", ".crypt", ".locked", "WANNACRY"],
        condition="any of them",
        meta={"author": "aegis-edr", "severity": "critical"},
    ),
]


def get_default_scanner() -> YaraScanner:
    """Get a scanner pre-loaded with stock rules."""
    scanner = YaraScanner()
    for rule in STOCK_YARA_RULES:
        scanner.add_rule(rule)
    return scanner


def scan_telemetry(telemetry: Iterable[Dict]) -> List[Dict]:
    """Convenience function to scan telemetry events."""
    scanner = get_default_scanner()
    return scanner.scan_events(telemetry)