# Canonical Telemetry Event Schema v1.0

## Specification Standard

All telemetry ingested into the platform MUST conform to the Canonical Telemetry Format (v1.0). This contract provides standard normalization across heterogeneous data sources (Endpoint EDR, Network NTA/Zeek, Identity IDP/AD, and Cloud Audit logs).

## JSON Structure

```json
{
  "event_id": "evt-uuid-v4-string",
  "tenant_id": "tenant-default-001",
  "source_layer": "endpoint | network | cloud | identity | application | database",
  "event_type": "process_execution | network_connection | user_login | cloud_api_call | http_request | db_query",
  "observed_at": "2026-10-05T12:00:00.000Z",
  "severity": "info | low | medium | high | critical",
  "entities": [
    {
      "entity_type": "host | user | ip | process | file | domain | cloud_identity | application | database | device",
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
| `source_layer` | Enum String | Yes | Telemetry origin: `endpoint`, `network`, `cloud`, `identity`, `application`, `database` (CR-01) |
| `event_type` | String | Yes | Categorized event action (e.g. `process_execution`, `http_request`, `db_query`) |
| `observed_at` | ISO 8601 Timestamp | Yes | Time telemetry was recorded at source (UTC) |
| `severity` | Enum String | Yes | Baseline severity (`info`, `low`, `medium`, `high`, `critical`) |
| `entities` | Array of Objects | Yes | Key entities associated with this event (persisted in DB per CR-07) |
| `payload` | Object (JSONB) | Yes | Layer-specific structured payload details |
| `metadata` | Object (JSONB) | No | Agent / collector provenance metadata (persisted in DB per CR-07) |

## Supported Telemetry Layers (CR-01)

| Layer | Value | Description | Example Event Types |
| :--- | :--- | :--- | :--- |
| **Endpoint** | `endpoint` | Host OS, process execution, local authentication | `process_execution`, `remote_session` |
| **Network** | `network` | Netflow, Zeek, DNS requests, packet metadata | `network_connection`, `dns_query` |
| **Cloud** | `cloud` | Cloud audit trails (AWS CloudTrail, GCP Audit, Azure Activity) | `cloud_api_call` |
| **Identity** | `identity` | Identity provider, directory service (Okta, Entra ID, AD) | `user_login`, `mfa_challenge`, `privilege_change`, `token_issued` |
| **Application** | `application` | Microservice, API gateway, HTTP web applications | `http_request` |
| **Database** | `database` | Relational & NoSQL query telemetry, access audit logs | `db_query` |

## Supported Entity Types (CR-02)

| Entity Type | Description | Canonical Identifier Format |
| :--- | :--- | :--- |
| `user` | Human user account or principal | Username or UPN (e.g. `corp\jdoe`, `analyst@corp.internal`) |
| `host` | Physical server, virtual machine, or workstation | FQDN or hostname (e.g. `workstation-01.corp.internal`) |
| `ip` | Network IP address (IPv4 or IPv6) | Standard IP notation (e.g. `192.168.1.50`, `185.220.101.4`) |
| `process` | Operating system running process | Process path or executable name (e.g. `powershell.exe`) |
| `file` | Filesystem object or binary | File path or SHA-256 hash |
| `domain` | Network domain or Active Directory realm | Domain name (e.g. `corp.internal`, `c2-tracker.org`) |
| `cloud_identity` | Cloud IAM user, role, or service principal | ARN, service account email, or cloud ID |
| `application` | Business application, microservice, or web service | Application slug / service identifier (e.g. `customer-portal`) |
| `database` | Database cluster, schema, or instance | Database name or connection target (e.g. `prod-customers-db`) |
| `device` | Hardware asset, mobile device, or IoT appliance | Hardware ID or device UUID (e.g. `dev-macbook-99`) |
