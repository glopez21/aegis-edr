"""Sigma rule import converter for AegisEDR."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List


MITRE_MAPPING = {
    "Execution": "Execution",
    "Privilege Escalation": "Privilege Escalation",
    "Defense Evasion": "Defense Evasion",
    "Credential Access": "Credential Access",
    "Discovery": "Discovery",
    "Lateral Movement": "Lateral Movement",
    "Collection": "Collection",
    "Command and Control": "Command and Control",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
    "Initial Access": "Initial Access",
    "Persistence": "Persistence",
}


TECHNIQUE_PATTERN = r"(?P<id>T\d{4}(\.\d{3})?) (?P<name>.+)"


def convert_sigma_rule(sigma_rule: Dict) -> Dict:
    """Convert a Sigma rule to AegisEDR format."""
    title = sigma_rule.get("title", "Unknown Rule")

    detection = sigma_rule.get("detection", {})
    condition = detection.get("condition", "selection")

    selection = detection.get("selection", {})

    mapped_field = None
    mapped_value = None

    for field, value in selection.items():
        if isinstance(value, str):
            mapped_field = field
            mapped_value = value
            break

    if "process_name" in selection:
        mapped_field = "process"
        mapped_value = selection["process_name"]
    elif "Image" in selection:
        mapped_field = "process"
        mapped_value = selection["Image"]
    elif "ParentImage" in selection:
        mapped_field = "parent"
        mapped_value = selection["ParentImage"]
    elif "CommandLine" in selection:
        mapped_field = "command_line"
        mapped_value = selection["CommandLine"]

    operator = "contains"
    if sigma_rule.get("level") == "critical":
        severity = "Critical"
    elif sigma_rule.get("level") == "high":
        severity = "High"
    elif sigma_rule.get("level") == "medium":
        severity = "Medium"
    else:
        severity = "Medium"

    rule = {
        "name": title,
        "field": mapped_field,
        "match": mapped_value,
        "operator": operator,
        "severity": severity,
        "priority": 50,
        "enabled": True,
    }

    return rule


def convert_sigma_file(file_path: Path) -> List[Dict]:
    """Convert a Sigma rules file to AegisEDR format."""
    import yaml

    with file_path.open("r") as f:
        sigma_rules = yaml.safe_load(f)

    if isinstance(sigma_rules, list):
        rules = [convert_sigma_rule(r) for r in sigma_rules]
    else:
        rules = [convert_sigma_rule(sigma_rules)]

    return rules


def import_sigma_rules(sigma_path: Path | str, output_path: Path | None = None) -> List[Dict]:
    """Import Sigma rules and optionally save as AegisEDR rules."""
    sigma_path = Path(sigma_path)
    rules = convert_sigma_file(sigma_path)

    if output_path:
        import yaml

        output_path = Path(output_path)
        with output_path.open("w") as f:
            yaml.dump(rules, f, default_flow_style=False)

    return rules