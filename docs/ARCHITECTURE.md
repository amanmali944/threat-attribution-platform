# System Architecture

## Overview

The Cross-Layer Threat Detection & Attribution Platform ingests telemetry events from multi-layer sensors (Endpoint, Network, Identity, Cloud), processes them through correlation and attribution engines, and exposes APIs and visualizations for security analysts.

```mermaid
flowchart TD
    subgraph Ingestion Layer
        E1[Endpoint Sensors] --> Collector[Telemetry Collector]
        N1[Network Probes] --> Collector
        C1[Cloud Audit Logs] --> Collector
        I1[Identity Providers] --> Collector
    end

    subgraph Data Pipeline & Storage
        Collector --> IngestAPI[FastAPI Ingestion Endpoint]
        IngestAPI --> DB[(PostgreSQL Database)]
        IngestAPI --> EventStream[Telemetry Event Stream]
    end

    subgraph Processing Engine - Dev A Owner
        EventStream --> DetectionEngine[Rule & ML Detection Engine]
        DetectionEngine --> CorrelationEngine[Cross-Layer Graph Correlation]
        CorrelationEngine --> AttributionEngine[Attribution & TTP Engine]
    end

    subgraph Platform & API Layer - Dev B Owner
        DetectionEngine --> DB
        CorrelationEngine --> DB
        AttributionEngine --> DB
        DB --> RESTAPI[FastAPI Platform Services]
    end

    subgraph Presentation Layer - Dev B Owner
        RESTAPI --> Frontend[Web Console / UI Dashboard]
        RESTAPI --> GraphVis[Entity Graph Visualizer]
    end
```

## Module Ownership & Boundary Isolation

| Module | Responsible Role | Key Artifacts |
| :--- | :--- | :--- |
| Telemetry Schema & Contracts | Developer B (Platform) | `docs/EVENT_SCHEMA.md`, `docs/API_CONTRACT.md` |
| Database & ORM | Developer B (Platform) | `backend/app/models/`, `docs/DATABASE_SCHEMA.md` |
| REST API & Fixtures | Developer B (Platform) | `backend/app/api/`, `data/fixtures/` |
| Detection & Fusion Engine | Developer A (ML / Security) | `backend/app/services/detection/` |
| Attribution & TTP Engine | Developer A (ML / Security) | `backend/app/services/attribution/` |
| Presentation / Frontend UI | Developer B (Platform) | `frontend/` |
