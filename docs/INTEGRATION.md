# AegisEDR + ThreatPulse Integration Plan

> **Status**: Planning Document  
> **Last Updated**: 2026-04-18  
> **Version**: 0.1.0

---

## Executive Summary

This document outlines the integration pathway for combining **AegisEDR** (Endpoint Detection & Response) with **ThreatPulse** (Unified SOC Platform) as side-by-side services with shared data storage.

**Integration Model**: Option 3 - Side-by-Side Services  
**Rationale**: Maintain independent development while enabling data sharing

---

## 1. Current State Analysis

### 1.1 AegisEDR (Standalone)

| Component | Technology | Port |
|-----------|------------|------|
| REST API | FastAPI | 8080 |
| Web Dashboard | FastAPI + WebSocket | 8000 |
| CLI Controller | Typer | N/A |
| Database | SQLite | `~/.aegisedr/incidents.db` |

**Key Modules:**
- Detection engine with 12 operators
- 30 MITRE ATT&CK rules
- IOC database
- Live monitors (process, network, file)
- SIEM connectors

### 1.2 ThreatPulse (Existing SOC Platform)

| Component | Technology | Port |
|-----------|------------|------|
| Backend API | FastAPI | 8000 |
| Frontend | React | 3000 |
| SIEM Data | Elasticsearch | 9200 |
| Network Monitor | Scapy | N/A |
| Vulnerability Scanner | OpenVAS | N/A |

**Key Modules:**
- SIEM query engine
- Network monitoring
- Vulnerability scanning
- Threat intelligence (MISP)
- Incident management

---

## 2. Integration Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      threatPulse                      │
│                    (Port 8000)                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────────┐│
│  │Dashboard│ │  SIEM    │ │    Incident Manager      ││
│  └──────────┘ └──────────┘ └──────────────────────────┘│
└─────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │   API Gateway    │
                    │  (nginx/caddy)  │
                    └─────────┬─────────┘
                              │
          ┌───────────────────┬─┴───────────────────┐
          │                   │                     │
          ▼                   ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  threatPulse API │  │  AegisEDR API   │  │ Elasticsearch  │
│   (Port 8000)   │  │  (Port 8080)   │  │ (Port 9200)    │
└─────────────────┘  └─────────────────┘  └─────────────────┘
                               │
                    ┌───────────┴───────────┐
                    │  Shared SQLite DB    │
                    │ ~/.aegisedr/*.db   │
                    │                   │
                    │ - incidents      │
                    │ - iocs           │
                    │ - rules          │
                    │ - network_events │
                    └───────────────────┘
```

---

## 3. Integration Points

### 3.1 Shared Database Schema

**Option A: AegisEDR as Source of Truth**
- threatPulse reads from AegisEDR SQLite
- No schema changes to threatPulse
- Read-only integration

**Option B: Shared Tables**
- Create shared database `~/.aegisedr/shared.db`
- Both services write/read
- Requires schema coordination

**Option C: AegisEDR as Microservice**
- AegisEDR API exposes all data
- threatPulse calls AegisEDR endpoints
- Cleaner separation (Recommended)

### 3.2 API Endpoints Mapping

| AegisEDR Endpoint | ThreatPulse Integration |
|-------------------|----------------------|
| `GET /api/incidents` | → SIEM event log |
| `GET /api/iocs` | → IOC management |
| `GET /api/rules` | → Detection rules UI |
| `POST /api/analyze` | → Manual triage |
| WebSocket `/ws` | → Live feed |

### 3.3 Data Flow

```
AegisEDR Live Monitors
        │
        ├── Detection Engine
        ├── Incident Store (SQLite)
        │
        └─► Shared DB ──► ThreatPulse READS ──► Dashboard
                            │
                     ┌──────┴──────┐
                     │ Queries    │
                     │ Incidents  │
                     │ IOCs     │
```

---

## 4. Implementation Phases

### Phase 1: Basic Integration (MVP)
> **Goal**: threatPulse displays AegisEDR alerts without code changes

- [ ] Run both services on different ports
- [ ] Configure nginx proxy for AegisEDR API
- [ ] threatPulse front-end adds iframe/redirect to AegisEDR dashboard

### Phase 2: Data Integration
> **Goal**: Shared incidents and IOCs

- [ ] Move AegisEDR incidents to threatPulse database
- [ ] Map AegisEDR incident fields to threatPulse schema
- [ ] Create sync script for bidirectional updates

### Phase 3: Deep Integration
> **Goal**: Unified UI with AegisEDR detection in threatPulse

- [ ] Add `/api/edr/*` endpoints to threatPulse backend
- [ ] Merge detection rules management UI
- [ ] Add live monitoring tabs

### Phase 4: Full Merge
> **Goal**: Single codebase

- [ ] Move AegisEDR modules into threatPulse structure
- [ ] Unify database schema
- [ ] Decommission AegisEDR standalone

---

## 5. Technical Details

### 5.1 Nginx Proxy Configuration

```nginx
# threatPulse nginx config
server {
    listen 8000;
    
    # ThreatPulse backend
    location /api/ {
        proxy_pass http://localhost:8000;
    }
    
    # AegisEDR integration
    location /api/edr/ {
        proxy_pass http://localhost:8080/api/;
    }
    
    location /edr-ws/ {
        proxy_pass http://localhost:8080/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### 5.2 Environment Variables

```bash
# AegisEDR (aegis-edr/.env)
AEGIS_DB_PATH=~/.aegisedr
AEGIS_API_HOST=0.0.0.0
AEGIS_API_PORT=8080

# threatPulse (threat-pulse/.env)
THREATPULSE_EDR_ENABLED=true
THREATPULSE_EDR_API_URL=http://localhost:8080
```

### 5.3 Docker Compose

```yaml
version: '3.8'

services:
  threatpulse:
    image: threatpulse:latest
    ports:
      - "8000:8000"
      - "3000:3000"
    environment:
      - THREATPULSE_EDR_ENABLED=true
    depends_on:
      - elasticsearch
      
  aegisedr:
    build: ./aegis-edr
    ports:
      - "8080:8080"
    volumes:
      - aegis-data:/home/w01f/.aegisedr
      
  elasticsearch:
    image: elasticsearch:8.11.0
    
volumes:
  aegis-data:
```

---

## 6. Module Mapping

### 6.1 AegisEDR → ThreatPulse

| AegisEDR Module | ThreatPulse Destination | Status |
|----------------|----------------------|--------|
| `detections/matcher.py` | New: `backend/edr/detector.py` | Merge |
| `detections/rules.yaml` | New: `backend/edr/rules.yaml` | Move |
| `detections/storage.py` | Use threatPulse DB | Move data |
| `detections/ioc_db.py` | New: `backend/threat_intel/iocs.py` | Merge |
| `detections/yara_scanner.py` | New: `backend/edr/yara.py` | Merge |
| `agent/process_monitor.py` | New: `backend/agents/endpoint.py` | Merge |
| `agent/file_monitor.py` | New: `backend/agents/filesystem.py` | Merge |
| `api/main.py` | Add: `/api/edr/*` routes | Merge |
| `integrations/siem_forward.py` | Reuse in SIEM module | Keep |

### 6.2 Duplicates to Resolve

| AegisEDR | threatPulse | Resolution |
|----------|------------|-------------|
| Incident storage | SQLAlchemy incidents table | Choose schema, migrate data |
| IOC DB | threat-intel module | Merge into threat-intel |
| MISP integration | MISP client | Keep both or consolidate |

---

## 7. Decision Points

### 7.1 Open Questions

| Decision | Options | Recommendation |
|----------|---------|--------------|
| Database | Shared SQLite vs separate | Shared SQLite initially |
| Live monitors | Run in AegisEDR or merge | Keep in AegisEDR |
| Detection rules | YAML vs database | Migrate to database |
| Frontend | iframe vs rewrite | Rewrite for unified UX |

### 7.2 Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|----------|
| Schema conflicts | Medium | High | Define schema early |
| API version mismatch | Low | Medium | Pin versions |
| Performance degradation | Medium | Medium | Monitor endpoints |

---

## 8. Development Roadmap

### Sprint 1: Infrastructure
- [ ] Document current threatPulse architecture
- [ ] Set up shared dev environment
- [ ] Configure nginx proxy

### Sprint 2: MVP
- [ ] Add AegisEDR to docker-compose
- [ ] Create iframe integration
- [ ] Test API connectivity

### Sprint 3: Data Integration
- [ ] Implement incident sync
- [ ] Add IOC sharing
- [ ] Test detection + response flow

### Sprint 4: Full Integration
- [ ] Merge frontend
- [ ] Unified dashboard
- [ ] Decommission standalone

---

## 9. Reference Materials

- AegisEDR README: `projects/aegis-edr/README.md`
- AegisEDR Dev Notes: `projects/aegis-edr/dev_notes.md`
- ThreatPulse README: `projects/threat-pulse/README.md`
- ThreatPulse Architecture: `projects/threat-pulse/docs/`

---

## 10. Action Items (Pre-implementation)

- [ ] Review this document
- [ ] Validate architecture decisions
- [ ] Confirm database schema approach
- [ ] Define phase 1 scope
- [ ] Allocate development time

---

*This document is a living planning document. Revise and amend before implementation.*