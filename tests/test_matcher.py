"""Unit tests for AegisEDR detection engine."""

import pytest
from detections.matcher import DetectionEngine, calculate_severity_score


@pytest.fixture
def sample_rules():
    return [
        {
            "name": "powershell encoding",
            "technique": "T1059.001",
            "mitre_phase": "Execution",
            "field": "command_line",
            "match": "powershell.exe -enc",
            "operator": "contains",
            "severity": "High",
            "priority": 80,
            "enabled": True,
        },
        {
            "name": "credential dumping",
            "technique": "T1003",
            "mitre_phase": "Credential Access",
            "field": "process",
            "match": "mimikatz.exe",
            "operator": "contains",
            "severity": "Critical",
            "priority": 100,
            "enabled": True,
        },
        {
            "name": "process equals",
            "technique": "T1082",
            "mitre_phase": "Discovery",
            "field": "process",
            "match": "systeminfo.exe",
            "operator": "equals",
            "severity": "Low",
            "priority": 30,
            "enabled": True,
        },
    ]


@pytest.fixture
def sample_events():
    return [
        {
            "host": "workstation01",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc SQBbAGgAdAAtAH",
            "user": "admin",
        },
        {
            "host": "workstation02",
            "process": "mimikatz.exe",
            "command_line": "mimikatz.exe privilege::debug",
            "user": "system",
        },
        {
            "host": "workstation03",
            "process": "systeminfo.exe",
            "command_line": "systeminfo.exe",
            "user": "user",
        },
    ]


class TestDetectionEngine:
    def test_contains_operator(self, sample_rules):
        engine = DetectionEngine(sample_rules)
        event = {
            "host": "test",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc SQBbAGgAdAAtAH",
        }
        findings = engine.evaluate([event])
        assert any(f["rule"] == "powershell encoding" for f in findings)

    def test_equals_operator(self, sample_rules):
        engine = DetectionEngine(sample_rules)
        event = {"host": "test", "process": "systeminfo.exe", "command_line": "test"}
        findings = engine.evaluate([event])
        assert any(f["rule"] == "process equals" for f in findings)

    def test_regex_operator(self, sample_rules):
        rules = [
            {
                "name": "regex test",
                "technique": "T1000",
                "field": "command_line",
                "match": r"powershell.*( Invoke-WebRequest | -enc )",
                "operator": "regex",
                "severity": "High",
                "priority": 70,
            }
        ]
        engine = DetectionEngine(rules)
        event = {
            "host": "test",
            "command_line": "powershell.exe -enc SQBbAGgAdAAtAH",
        }
        findings = engine.evaluate([event])
        assert len(findings) == 1

    def test_in_operator(self, sample_rules):
        rules = [
            {
                "name": "office parent",
                "technique": "T1566",
                "field": "parent",
                "match": "WINWORD.EXE,EXCEL.EXE",
                "operator": "in",
                "severity": "High",
                "priority": 80,
            }
        ]
        engine = DetectionEngine(rules)
        event = {"host": "test", "parent": "WINWORD.EXE"}
        findings = engine.evaluate([event])
        assert len(findings) == 1

    def test_gt_operator(self, sample_rules):
        rules = [
            {
                "name": "number greater",
                "technique": "T1000",
                "field": "integrity_level",
                "match": "1000",
                "operator": "gt",
                "severity": "Medium",
                "priority": 50,
            }
        ]
        engine = DetectionEngine(rules)
        event = {"host": "test", "integrity_level": 1500}
        findings = engine.evaluate([event])
        assert len(findings) == 1

    def test_disabled_rule(self, sample_rules):
        rules = [
            {
                "name": "disabled rule",
                "technique": "T1000",
                "field": "process",
                "match": "test.exe",
                "operator": "contains",
                "severity": "High",
                "enabled": False,
            }
        ]
        engine = DetectionEngine(rules)
        event = {"host": "test", "process": "test.exe"}
        findings = engine.evaluate([event])
        assert len(findings) == 0

    def test_no_field(self, sample_rules):
        rules = [{"name": "no field", "field": None, "match": "test"}]
        engine = DetectionEngine(rules)
        event = {"host": "test"}
        findings = engine.evaluate([event])
        assert len(findings) == 0


class TestSeverityScoring:
    def test_critical_score(self, sample_rules):
        findings = [
            {
                "rule": "test",
                "technique": "T1003",
                "severity": "Critical",
                "priority": 100,
                "event": {},
            }
        ]
        scored = calculate_severity_score(findings)
        assert scored[0]["score"] == 100

    def test_high_with_tier_mod(self, sample_rules):
        findings = [
            {
                "rule": "test",
                "technique": "T1547",
                "severity": "High",
                "priority": 50,
                "event": {},
            }
        ]
        scored = calculate_severity_score(findings)
        assert scored[0]["score"] > 75


class TestIntegration:
    def test_full_evaluation(self, sample_rules, sample_events):
        engine = DetectionEngine(sample_rules)
        findings = engine.evaluate(sample_events)
        assert len(findings) == 3

    def test_empty_events(self, sample_rules):
        engine = DetectionEngine(sample_rules)
        findings = engine.evaluate([])
        assert len(findings) == 0

    def test_empty_rules(self, sample_events):
        engine = DetectionEngine([])
        findings = engine.evaluate(sample_events)
        assert len(findings) == 0