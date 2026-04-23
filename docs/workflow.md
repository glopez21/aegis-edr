# AegisEDR Workflow

```
Endpoint Agent -> Telemetry JSON -> Detection Engine -> Automation Engine -> Ticket Narrative
```

1. **Endpoint Agent Simulator** generates process events for a host.
2. **Controller CLI** ingests telemetry (`controller/main.py analyze`).
3. **Detection Engine** loads YAML rules (`detections/rules.yaml`).
4. **Automation Engine** executes host isolation, process kill, or hash banning.
5. **Docs/Templates** provide guidance for real-world EDR integrations.

Use `samples/telemetry_sample.json` to walkthrough end-to-end.
