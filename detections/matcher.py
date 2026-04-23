"""Enhanced detection engine for AegisEDR with multiple operators."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional


class DetectionEngine:
    """Detection engine supporting multiple matching operators."""

    def __init__(self, rules: Iterable[Dict]):
        self.rules = [r for r in list(rules) if r.get("enabled", True)]

    def evaluate(self, events: Iterable[Dict]) -> List[Dict]:
        findings: List[Dict] = []
        for event in events:
            for rule in self.rules:
                match_result = self._evaluate_rule(rule, event)
                if match_result:
                    findings.append({
                        "rule": rule["name"],
                        "technique": rule.get("technique", "unknown"),
                        "mitre_phase": rule.get("mitre_phase", "unknown"),
                        "severity": rule.get("severity", "Medium"),
                        "priority": rule.get("priority", 50),
                        "event": event,
                        "match_value": match_result,
                    })
        return findings

    def _evaluate_rule(self, rule: Dict, event: Dict) -> Optional[str]:
        field = rule.get("field")
        if not field:
            return None

        operator = rule.get("operator", "contains").lower()
        query = rule.get("match", "")
        event_value = event.get(field)

        if operator == "exists":
            return str(event_value) if field in event else None
        elif operator == "not_exists":
            return None if field in event else "present"
        elif operator == "equals":
            return event_value if str(event_value) == query else None
        elif operator == "not_equals":
            return event_value if str(event_value) != query else None
        elif operator == "contains":
            return event_value if query.lower() in str(event_value).lower() else None
        elif operator == "regex":
            if re.search(query, str(event_value), re.IGNORECASE):
                return event_value
            return None
        elif operator in ("gt", "greater_than"):
            try:
                return event_value if float(event_value) > float(query) else None
            except (ValueError, TypeError):
                return None
        elif operator in ("lt", "less_than"):
            try:
                return event_value if float(event_value) < float(query) else None
            except (ValueError, TypeError):
                return None
        elif operator in ("gte", "greater_than_or_equal"):
            try:
                return event_value if float(event_value) >= float(query) else None
            except (ValueError, TypeError):
                return None
        elif operator in ("lte", "less_than_or_equal"):
            try:
                return event_value if float(event_value) <= float(query) else None
            except (ValueError, TypeError):
                return None
        elif operator == "startswith":
            return event_value if str(event_value).lower().startswith(query.lower()) else None
        elif operator == "endswith":
            return event_value if str(event_value).lower().endswith(query.lower()) else None
        elif operator == "in":
            values = [v.strip() for v in query.split(",")]
            return event_value if str(event_value) in values else None
        else:
            return event_value if query.lower() in str(event_value).lower() else None


def calculate_severity_score(findings: List[Dict]) -> List[Dict]:
    """Calculate composite severity score based on MITRE tier and priority."""
    severity_map = {"Critical": 100, "High": 75, "Medium": 50, "Low": 25, "Info": 10}

    for finding in findings:
        base_score = severity_map.get(finding["severity"], 50)
        priority_mod = finding.get("priority", 50) / 100 * 20
        tier_mod = 0
        technique = finding.get("technique", "")

        if technique.startswith(("T1003", "T1053", "T1486", "T1489")):
            tier_mod = 20
        elif technique.startswith(("T1547", "T1070", "T1021")):
            tier_mod = 15
        elif technique.startswith(("T1059", "T1204", "T1087")):
            tier_mod = 10

        finding["score"] = min(base_score + priority_mod + tier_mod, 100)

    return findings