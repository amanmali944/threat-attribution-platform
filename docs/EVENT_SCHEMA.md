# Canonical Telemetry Event Schema v1.0

## Specification Standard

All telemetry ingested into the platform MUST conform to the Canonical Telemetry Format (v1.0). This contract provides standard normalization across heterogeneous data sources (Endpoint EDR, Network NTA/Zeek, Identity IDP/AD, and Cloud Audit logs).

## JSON Structure

```json
{
  "event_id": "evt-uuid-v4-string",
  "tenant_id": "tenant-default-001",
  "source_layer": "endpoint | network | cloud | identity",
  "event_type": "process_execution | network_connection | user_login | cloud_api_call",
  "observed_at": "2026-10-05T12:00:00.000Z",
  "severity": "info | low | medium | high | critical",
  "entities": [
    {
      "entity_type": "host | user | ip | process | file",
      "identifier": "workstation-01.corp.internal"
    }
  ],
  "payload": {
    "process_name": "cmd.exe",
    "command_line": "cmd.exe /c powershell -ExecutionPolicy Bypass",
    "parent_process": "explorer.exe",
    "user_sid": "S-1-5-21-..."
  },
  "metadata": {
    "agent_version": "2.4.1",
    "collector_node": "collector-us-east-1"
  }
}
```

## Field Specification

| Field Name | Data Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `event_id` | String (UUIDv4) | Yes | Globally unique event identifier |
| `tenant_id` | String | Yes | Tenant isolation identifier (indexed in database) |
| `source_layer` | Enum String | Yes | Telemetry origin: `endpoint`, `network`, `cloud`, `identity` |
| `event_type` | String | Yes | Categorized event action (e.g. `process_execution`) |
| `observed_at` | ISO 8601 Timestamp | Yes | Time telemetry was recorded at source (UTC) |
| `severity` | Enum String | Yes | Baseline severity (`info`, `low`, `medium`, `high`, `critical`) |
| `entities` | Array of Objects | Yes | Key entities associated with this event |
| `payload` | Object (JSONB) | Yes | Layer-specific structured payload details |
| `metadata` | Object (JSONB) | No | Agent / collector provenance metadata |
