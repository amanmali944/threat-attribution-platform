# Cross-Layer Threat Detection & Attribution Platform - Documentation

Welcome to the central documentation repository for the **Cross-Layer Threat Detection & Attribution Platform**.

## Document Index

1. [ARCHITECTURE.md](file:///c:/Users/Asus/Desktop/threat-attribution-platform/docs/ARCHITECTURE.md) - System architecture, component flow, and module boundaries between Developer A (ML/Detection) and Developer B (Platform/API/UI).
2. [EVENT_SCHEMA.md](file:///c:/Users/Asus/Desktop/threat-attribution-platform/docs/EVENT_SCHEMA.md) - Canonical v1.0 telemetry event format for multi-layer ingestion (Endpoint, Network, Cloud, Identity).
3. [API_CONTRACT.md](file:///c:/Users/Asus/Desktop/threat-attribution-platform/docs/API_CONTRACT.md) - REST API specifications for `/events`, `/alerts`, `/incidents`, `/graph`, and `/summary`.
4. [DATABASE_SCHEMA.md](file:///c:/Users/Asus/Desktop/threat-attribution-platform/docs/DATABASE_SCHEMA.md) - PostgreSQL entity relationship definitions, indexes (`tenant_id`, `observed_at`), and data dictionary.
5. [INTEGRATION_RULES.md](file:///c:/Users/Asus/Desktop/threat-attribution-platform/docs/INTEGRATION_RULES.md) - Hand-off guardrails, contract isolation, and development responsibilities between Platform & Detection teams.

---
*Maintained by Developer B (Platform & Presentation Owner)*
