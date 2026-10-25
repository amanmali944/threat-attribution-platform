"""Demo Simulator Router (Developer B - Platform & Presentation).

Provides POST /api/v1/demo/simulate to trigger realistic attack scenarios
directly through Developer A's detection pipeline (run_pipeline) and deliver
events, alerts, incidents, and attributions to the platform database.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.services.attribution.correlation import AssetInventory
from app.services.pipeline import deliver, run_pipeline

router = APIRouter(prefix="/demo", tags=["Demo Simulator"])

DEFAULT_TENANT = "tenant-default-001"
DAY0 = "2026-10-24"
DAY1 = "2026-10-25"


class SimulationRequest(BaseModel):
    scenario_id: str = Field(..., description="Scenario ID to execute")
    tenant_id: Optional[str] = Field(default=DEFAULT_TENANT, description="Target tenant ID")


class ScenarioMetadata(BaseModel):
    scenario_id: str
    name: str
    target_vector: str
    difficulty: str
    severity: str
    mitre_techniques: List[str]
    description: str


class SimulationResponse(BaseModel):
    status: str
    scenario_id: str
    scenario: ScenarioMetadata
    events_injected: int
    alerts_generated: int
    incidents_generated: int
    attributions_generated: int
    incident_ids: List[str]
    alert_ids: List[str]
    delivery_report: Dict[str, Any]
    execution_logs: List[Dict[str, Any]]


def _make_event(
    eid: str,
    when: str,
    layer: str,
    etype: str,
    entities: List[Dict[str, Any]],
    payload: Dict[str, Any],
    tenant_id: str = DEFAULT_TENANT,
) -> Dict[str, Any]:
    return {
        "event_id": eid,
        "tenant_id": tenant_id,
        "source_layer": layer,
        "event_type": etype,
        "observed_at": when,
        "severity": "info",
        "entities": entities,
        "payload": payload,
        "metadata": {"source": "demo_simulator", "run_id": str(uuid.uuid4())[:8]},
    }


# ---------------------------------------------------------------------------
# SCENARIO 1: apt29_intrusion (Full Kill Chain)
# ---------------------------------------------------------------------------
def build_apt29_intrusion(tenant_id: str) -> Tuple[List[Dict[str, Any]], AssetInventory, ScenarioMetadata, List[Dict[str, Any]]]:
    meta = ScenarioMetadata(
        scenario_id="apt29_intrusion",
        name="APT29 / Cozy Bear Multi-Stage Intrusion",
        target_vector="Identity VPN -> Intranet Web -> Host Privilege Escalation -> DNS Exfil",
        difficulty="Advanced / APT",
        severity="critical",
        mitre_techniques=["T1078 (Valid Accounts)", "T1595 (Active Scanning)", "T1548 (Privilege Escalation)", "T1003.008 (/etc/shadow)", "T1071.004 (DNS Tunneling)"],
        description="Full kill chain execution mimicking Russian state-sponsored actor Cozy Bear. Uses compromised VPN credentials, pivots to internal web service, escalates to root, and tunnels exfiltrated intelligence out via high-entropy DNS subdomains.",
    )
    assets = AssetInventory(
        tenant_id=tenant_id,
        ip_to_host={"10.0.0.5": "vpn-gateway", "10.0.1.4": "app-server"},
        fqdn_to_host={"intranet.example.com": "app-server"},
        criticality={"vpn-gateway": 4, "app-server": 4},
    )
    raw: List[Dict[str, Any]] = []
    run_seed = int(time.time())

    # Baseline (Day 0): Normal jdoe VPN activity
    for i, h in enumerate((8, 10, 12, 14, 16)):
        raw.append(_make_event(
            f"apt-base-vpn-{run_seed}-{i}",
            f"{DAY0}T{h:02d}:00:00Z",
            "identity",
            "user_login",
            [{"entity_type": "user", "identifier": "jdoe"}, {"entity_type": "host", "identifier": "vpn-gateway"}],
            {"result": "SUCCESS", "source_ip": "198.51.100.9", "service": "openvpn"},
            tenant_id=tenant_id,
        ))
        raw.append(_make_event(
            f"apt-base-web-{run_seed}-{i}",
            f"{DAY0}T{h:02d}:05:00Z",
            "application",
            "http_request",
            [{"entity_type": "application", "identifier": "intranet.example.com"}],
            {"method": "GET", "path": "/home", "status_code": 200, "source_ip": "10.0.0.5"},
            tenant_id=tenant_id,
        ))

    # Score (Day 1): Attack Kill Chain
    # 1. Stolen credentials login from attacker IP
    raw.append(_make_event(
        f"apt-atk-vpn-{run_seed}",
        f"{DAY1}T03:01:00Z",
        "identity",
        "user_login",
        [{"entity_type": "user", "identifier": "jdoe"}, {"entity_type": "host", "identifier": "vpn-gateway"}],
        {"result": "SUCCESS", "source_ip": "203.0.113.66", "service": "openvpn"},
        tenant_id=tenant_id,
    ))
    # 2. Web scanning / directory probing from VPN IP
    for k in range(35):
        raw.append(_make_event(
            f"apt-atk-scan-{run_seed}-{k:02d}",
            f"{DAY1}T03:06:{k:02d}Z",
            "application",
            "http_request",
            [{"entity_type": "application", "identifier": "intranet.example.com"}],
            {"method": "GET", "path": f"/v1/internal/admin/path_{k:02d}", "status_code": 404, "source_ip": "10.0.0.5"},
            tenant_id=tenant_id,
        ))
    # 3. Web shell account switch
    raw.append(_make_event(
        f"apt-atk-su-{run_seed}",
        f"{DAY1}T03:40:00Z",
        "endpoint",
        "process_execution",
        [{"entity_type": "host", "identifier": "app-server"}, {"entity_type": "user", "identifier": "www-data"}],
        {"process_name": "su", "command_line": "su jdoe"},
        tenant_id=tenant_id,
    ))
    # 4. Shadow file read
    raw.append(_make_event(
        f"apt-atk-shadow-{run_seed}",
        f"{DAY1}T03:40:15Z",
        "endpoint",
        "process_execution",
        [{"entity_type": "host", "identifier": "app-server"}, {"entity_type": "user", "identifier": "jdoe"}],
        {"process_name": "sudo", "command_line": "/bin/cat /etc/shadow"},
        tenant_id=tenant_id,
    ))
    # 5. DNS exfiltration via long query names
    for k in range(12):
        raw.append(_make_event(
            f"apt-atk-dns-{run_seed}-{k:02d}",
            f"{DAY1}T03:45:{k:02d}Z",
            "network",
            "dns_query",
            [{"entity_type": "ip", "identifier": "10.0.0.5"}],
            {"query_name": f"chunk{k:02d}.apt29-exfil-c2-payload-enc-b64-0000000000000000000000000000000000000000000000000000000000000000.c2-apt29.net"},
            tenant_id=tenant_id,
        ))

    logs = [
        {"timestamp": "03:01:00Z", "level": "PAYLOAD", "target": "10.0.0.5 (vpn-gateway)", "message": "[T1078] Initial Access via stolen credentials: jdoe from 203.0.113.66 (ESTABLISHED)"},
        {"timestamp": "03:06:12Z", "level": "SCAN", "target": "10.0.1.4 (app-server)", "message": "[T1595] Internal network directory fuzzing: 35 endpoints probed across intranet.example.com"},
        {"timestamp": "03:40:00Z", "level": "EXPLOIT", "target": "10.0.1.4 (app-server)", "message": "[T1548] Web shell payload active: www-data invoked unauthorized su switch to jdoe"},
        {"timestamp": "03:40:15Z", "level": "CRITICAL", "target": "10.0.1.4 (app-server)", "message": "[T1003.008] Privilege escalation: sudo reading /etc/shadow credential store"},
        {"timestamp": "03:45:00Z", "level": "EXFIL", "target": "c2-apt29.net", "message": "[T1071.004] Initiating DNS data tunneling: 12 high-entropy chunks dispatched"},
    ]
    return raw, assets, meta, logs


# ---------------------------------------------------------------------------
# SCENARIO 2: ssh_bruteforce (Spike -> Compromise -> Private Key Access)
# ---------------------------------------------------------------------------
def build_ssh_bruteforce(tenant_id: str) -> Tuple[List[Dict[str, Any]], AssetInventory, ScenarioMetadata, List[Dict[str, Any]]]:
    meta = ScenarioMetadata(
        scenario_id="ssh_bruteforce",
        name="SSH Brute-Force & Credential Harvesting",
        target_vector="Identity SSH -> Host Endpoint Lateral Movement",
        difficulty="Intermediate",
        severity="high",
        mitre_techniques=["T1110.001 (Password Guessing)", "T1110 (Brute Force)", "T1003.008 (Private Keys)"],
        description="High-frequency automated SSH password spray against perimeter bastion gateway. Breaches target ops_admin account after consecutive failures and extracts SSH private keys for lateral movement.",
    )
    assets = AssetInventory(
        tenant_id=tenant_id,
        ip_to_host={"10.0.0.20": "bastion-host"},
        criticality={"bastion-host": 4},
    )
    raw: List[Dict[str, Any]] = []
    run_seed = int(time.time())

    # Baseline: Normal ops_admin logins
    for i, h in enumerate((8, 10, 12, 14, 16)):
        raw.append(_make_event(
            f"ssh-base-{run_seed}-{i}",
            f"{DAY0}T{h:02d}:00:00Z",
            "identity",
            "user_login",
            [{"entity_type": "user", "identifier": "ops_admin"}, {"entity_type": "host", "identifier": "bastion-host"}],
            {"result": "SUCCESS", "source_ip": "10.0.0.99", "service": "sshd"},
            tenant_id=tenant_id,
        ))

    # Score (Day 1): 12 consecutive failures, then 1 success, then credential file theft
    for k in range(12):
        raw.append(_make_event(
            f"ssh-fail-{run_seed}-{k:02d}",
            f"{DAY1}T02:10:{k*2:02d}Z",
            "identity",
            "user_login",
            [{"entity_type": "user", "identifier": "ops_admin"}, {"entity_type": "host", "identifier": "bastion-host"}],
            {"result": "FAILURE", "source_ip": "198.51.100.88", "service": "sshd"},
            tenant_id=tenant_id,
        ))
    raw.append(_make_event(
        f"ssh-succ-{run_seed}",
        f"{DAY1}T02:10:30Z",
        "identity",
        "user_login",
        [{"entity_type": "user", "identifier": "ops_admin"}, {"entity_type": "host", "identifier": "bastion-host"}],
        {"result": "SUCCESS", "source_ip": "198.51.100.88", "service": "sshd"},
        tenant_id=tenant_id,
    ))
    raw.append(_make_event(
        f"ssh-key-{run_seed}",
        f"{DAY1}T02:15:10Z",
        "endpoint",
        "process_execution",
        [{"entity_type": "host", "identifier": "bastion-host"}, {"entity_type": "user", "identifier": "ops_admin"}],
        {"process_name": "sudo", "command_line": "sudo cp /root/.ssh/id_rsa /tmp/.key"},
        tenant_id=tenant_id,
    ))

    logs = [
        {"timestamp": "02:10:00Z", "level": "ATTACK", "target": "10.0.0.20:22 (bastion-host)", "message": "[T1110.001] SSH dictionary attack launched from 198.51.100.88 targeting ops_admin"},
        {"timestamp": "02:10:20Z", "level": "WARN", "target": "10.0.0.20:22 (bastion-host)", "message": "[T1110] 12 consecutive authentication failures recorded"},
        {"timestamp": "02:10:30Z", "level": "BREACH", "target": "10.0.0.20:22 (bastion-host)", "message": "[T1110] Password hash match cracked: authenticated session established"},
        {"timestamp": "02:15:10Z", "level": "CRITICAL", "target": "10.0.0.20 (bastion-host)", "message": "[T1003.008] Credential extraction: sudo cp /root/.ssh/id_rsa /tmp/.key"},
    ]
    return raw, assets, meta, logs


# ---------------------------------------------------------------------------
# SCENARIO 3: dns_tunneling (High-Entropy Subdomains to C2)
# ---------------------------------------------------------------------------
def build_dns_tunneling(tenant_id: str) -> Tuple[List[Dict[str, Any]], AssetInventory, ScenarioMetadata, List[Dict[str, Any]]]:
    meta = ScenarioMetadata(
        scenario_id="dns_tunneling",
        name="High-Entropy DNS C2 Tunneling",
        target_vector="Network DNS -> External Command & Control",
        difficulty="Intermediate",
        severity="high",
        mitre_techniques=["T1071.004 (DNS Protocol C2)", "T1048 (Exfiltration Over Alternative Protocol)"],
        description="Adversary establishes covert bi-directional communications channel over DNS protocol, packing encrypted payloads into subdomains over 110 characters long destined for external C2 domain.",
    )
    assets = AssetInventory(
        tenant_id=tenant_id,
        ip_to_host={"10.0.2.88": "workstation-eng-04"},
        criticality={"workstation-eng-04": 3},
    )
    raw: List[Dict[str, Any]] = []
    run_seed = int(time.time())

    # Baseline: Normal standard DNS lookups
    for i, h in enumerate((8, 10, 12, 14, 16)):
        raw.append(_make_event(
            f"dns-base-{run_seed}-{i}",
            f"{DAY0}T{h:02d}:00:00Z",
            "network",
            "dns_query",
            [{"entity_type": "ip", "identifier": "10.0.2.88"}],
            {"query_name": "internal.service.corp"},
            tenant_id=tenant_id,
        ))

    # Score (Day 1): 16 DNS queries > 100 characters in length
    for k in range(16):
        raw.append(_make_event(
            f"dns-tune-{run_seed}-{k:02d}",
            f"{DAY1}T04:20:{k*2:02d}Z",
            "network",
            "dns_query",
            [{"entity_type": "ip", "identifier": "10.0.2.88"}],
            {"query_name": f"chunk-{k:02d}-f9e8d7c6b5a43210123456789abcdef0123456789abcdef0123456789abcdef0123456789.c2-exfil.ghostthreat.net"},
            tenant_id=tenant_id,
        ))

    logs = [
        {"timestamp": "04:20:00Z", "level": "BEACON", "target": "10.0.2.88 (workstation-eng-04)", "message": "[T1071.004] Covert channel heartbeat established from 10.0.2.88 to authoritative nameserver"},
        {"timestamp": "04:20:15Z", "level": "PAYLOAD", "target": "c2-exfil.ghostthreat.net", "message": "[T1071.004] Packing binary stream into Base32 encoded DNS labels (len > 110)"},
        {"timestamp": "04:20:30Z", "level": "EXFIL", "target": "c2-exfil.ghostthreat.net", "message": "[T1071.004] 16 long-name DNS exfiltration requests successfully resolved"},
    ]
    return raw, assets, meta, logs


# ---------------------------------------------------------------------------
# SCENARIO 4: privilege_escalation (Service Account Executing Unauthorized Sudo)
# ---------------------------------------------------------------------------
def build_privilege_escalation(tenant_id: str) -> Tuple[List[Dict[str, Any]], AssetInventory, ScenarioMetadata, List[Dict[str, Any]]]:
    meta = ScenarioMetadata(
        scenario_id="privilege_escalation",
        name="Service Account Sudo Escalation",
        target_vector="Endpoint Host -> System Identity Privileges",
        difficulty="High",
        severity="critical",
        mitre_techniques=["T1548.003 (Sudo and Sudo Caching)", "T1003.008 (/etc/shadow Access)", "T1098 (Account Manipulation)"],
        description="Compromised web server service account (www-data) leverages privilege escalation flaw to spawn interactive root shells, read protected shadow files, and add administrative groups.",
    )
    assets = AssetInventory(
        tenant_id=tenant_id,
        ip_to_host={"10.0.1.50": "web-server-01"},
        criticality={"web-server-01": 4},
    )
    raw: List[Dict[str, Any]] = []
    run_seed = int(time.time())

    # Baseline: Normal web requests under www-data
    for i, h in enumerate((8, 10, 12, 14, 16)):
        raw.append(_make_event(
            f"priv-base-{run_seed}-{i}",
            f"{DAY0}T{h:02d}:00:00Z",
            "application",
            "http_request",
            [{"entity_type": "host", "identifier": "web-server-01"}, {"entity_type": "user", "identifier": "www-data"}],
            {"method": "GET", "path": "/health", "status_code": 200, "source_ip": "10.0.1.50"},
            tenant_id=tenant_id,
        ))

    # Score (Day 1): Service account sudo execution + shadow access + role change
    raw.append(_make_event(
        f"priv-sudo-{run_seed}",
        f"{DAY1}T05:10:00Z",
        "endpoint",
        "process_execution",
        [{"entity_type": "host", "identifier": "web-server-01"}, {"entity_type": "user", "identifier": "www-data"}],
        {"process_name": "sudo", "command_line": "sudo -u root /bin/bash"},
        tenant_id=tenant_id,
    ))
    raw.append(_make_event(
        f"priv-shadow-{run_seed}",
        f"{DAY1}T05:10:15Z",
        "endpoint",
        "process_execution",
        [{"entity_type": "host", "identifier": "web-server-01"}, {"entity_type": "user", "identifier": "www-data"}],
        {"process_name": "sudo", "command_line": "sudo /bin/cat /etc/shadow"},
        tenant_id=tenant_id,
    ))
    raw.append(_make_event(
        f"priv-role-{run_seed}",
        f"{DAY1}T05:10:30Z",
        "identity",
        "privilege_change",
        [{"entity_type": "user", "identifier": "www-data"}, {"entity_type": "host", "identifier": "web-server-01"}],
        {"role_before": "service", "role_after": "root"},
        tenant_id=tenant_id,
    ))

    logs = [
        {"timestamp": "05:10:00Z", "level": "INTRUSION", "target": "10.0.1.50 (web-server-01)", "message": "[T1548.003] Sudoers abuse: service account www-data spawning root interactive shell"},
        {"timestamp": "05:10:15Z", "level": "HARVEST", "target": "10.0.1.50 (web-server-01)", "message": "[T1003.008] In-memory shadow file extraction: sudo /bin/cat /etc/shadow"},
        {"timestamp": "05:10:30Z", "level": "PERSIST", "target": "10.0.1.50 (web-server-01)", "message": "[T1098] Account manipulation: elevated www-data to root administrative group"},
    ]
    return raw, assets, meta, logs


# ---------------------------------------------------------------------------
# SCENARIO 5: web_recon (Rapid Directory Traversal & Endpoint Scanning)
# ---------------------------------------------------------------------------
def build_web_recon(tenant_id: str) -> Tuple[List[Dict[str, Any]], AssetInventory, ScenarioMetadata, List[Dict[str, Any]]]:
    meta = ScenarioMetadata(
        scenario_id="web_recon",
        name="Web Application Directory Traversal & Fuzzing",
        target_vector="Application HTTP -> Web Server Exposure",
        difficulty="Foundational",
        severity="medium",
        mitre_techniques=["T1595.002 (Vulnerability Scanning)", "T1083 (File and Directory Discovery)", "T1548 (Privileged Operations)"],
        description="High-velocity automated HTTP directory fuzzer (Nikto/ffuf) sweeps public web portal probing sensitive files (.git, .env, /etc/passwd) and uncovers unprotected administrative execution hooks.",
    )
    assets = AssetInventory(
        tenant_id=tenant_id,
        ip_to_host={"10.0.1.10": "web-frontend"},
        fqdn_to_host={"portal.corp.internal": "web-frontend"},
        criticality={"web-frontend": 3},
    )
    raw: List[Dict[str, Any]] = []
    run_seed = int(time.time())

    # Baseline: Normal traffic
    for i, h in enumerate((8, 10, 12, 14, 16)):
        raw.append(_make_event(
            f"recon-base-{run_seed}-{i}",
            f"{DAY0}T{h:02d}:00:00Z",
            "application",
            "http_request",
            [{"entity_type": "application", "identifier": "portal.corp.internal"}],
            {"method": "GET", "path": "/index.html", "status_code": 200, "source_ip": "10.0.1.10"},
            tenant_id=tenant_id,
        ))

    # Score (Day 1): 35 rapid 404s + exposed shell execution
    paths = ["/etc/passwd", "/.git/config", "/.env", "/admin.php", "/wp-login.php", "/shell.php", "/backup.sql"]
    for k in range(35):
        raw.append(_make_event(
            f"recon-scan-{run_seed}-{k:02d}",
            f"{DAY1}T06:15:{k:02d}Z",
            "application",
            "http_request",
            [{"entity_type": "application", "identifier": "portal.corp.internal"}, {"entity_type": "ip", "identifier": "198.51.100.155"}],
            {"method": "GET", "path": paths[k % len(paths)], "status_code": 404, "source_ip": "198.51.100.155"},
            tenant_id=tenant_id,
        ))
    raw.append(_make_event(
        f"recon-rce-{run_seed}",
        f"{DAY1}T06:16:00Z",
        "endpoint",
        "process_execution",
        [{"entity_type": "host", "identifier": "web-frontend"}, {"entity_type": "user", "identifier": "www-data"}],
        {"process_name": "su", "command_line": "su - nobody"},
        tenant_id=tenant_id,
    ))

    logs = [
        {"timestamp": "06:15:00Z", "level": "SCAN", "target": "portal.corp.internal (10.0.1.10)", "message": "[T1595.002] Nikto vulnerability scanner dispatched from 198.51.100.155"},
        {"timestamp": "06:15:20Z", "level": "SCAN", "target": "portal.corp.internal (10.0.1.10)", "message": "[T1595.002] Probing 35 sensitive files: /.git/config, /.env, /admin.php, /etc/passwd"},
        {"timestamp": "06:16:00Z", "level": "EXPLOIT", "target": "portal.corp.internal (10.0.1.10)", "message": "[T1548] Exposed admin debug script executed: unauthorized www-data process execution"},
    ]
    return raw, assets, meta, logs


SCENARIO_BUILDERS = {
    "apt29_intrusion": build_apt29_intrusion,
    "ssh_bruteforce": build_ssh_bruteforce,
    "dns_tunneling": build_dns_tunneling,
    "privilege_escalation": build_privilege_escalation,
    "web_recon": build_web_recon,
}


@router.get("/scenarios", response_model=List[ScenarioMetadata])
def list_available_scenarios():
    """Returns available simulation attack scenarios with metadata."""
    scenarios = []
    for sid, builder in SCENARIO_BUILDERS.items():
        _, _, meta, _ = builder(DEFAULT_TENANT)
        scenarios.append(meta)
    return scenarios


@router.post("/simulate", response_model=SimulationResponse, status_code=status.HTTP_200_OK)
def simulate_attack(req: SimulationRequest):
    """
    Executes an attack scenario stream through Developer A's ML/rules pipeline (run_pipeline)
    and delivers generated events, alerts, incidents, and attributions to the platform DB.
    """
    sid = req.scenario_id.strip().lower()
    if sid not in SCENARIO_BUILDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scenario_id: '{req.scenario_id}'. Available: {list(SCENARIO_BUILDERS.keys())}",
        )

    tenant_id = req.tenant_id or DEFAULT_TENANT
    builder = SCENARIO_BUILDERS[sid]
    raw_events, assets, meta, logs = builder(tenant_id)

    # 1. Run detection & attribution pipeline
    result = run_pipeline(
        raw_events=raw_events,
        baseline=(f"{DAY0}T00:00:00Z", f"{DAY1}T00:00:00Z"),
        score=(f"{DAY1}T00:00:00Z", f"{DAY1}T23:59:59Z"),
        assets=assets,
    )

    # 2. Deliver results to platform API endpoints (persisting into DB)
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    def post(path: str, payload: Dict[str, Any]):
        resp = client.post(path, json=payload)
        return resp.status_code, (resp.json() if resp.content else None)

    delivery_report = deliver(post, result, raw_events=raw_events)

    incident_ids = list(delivery_report.get("incident_ids", {}).values())
    alert_ids = list(delivery_report.get("alert_ids", {}).values())

    return SimulationResponse(
        status="success",
        scenario_id=sid,
        scenario=meta,
        events_injected=len(raw_events),
        alerts_generated=len(result.get("fused_alerts", [])),
        incidents_generated=len(result.get("incidents", [])),
        attributions_generated=len(result.get("attributions", [])),
        incident_ids=incident_ids,
        alert_ids=alert_ids,
        delivery_report=delivery_report,
        execution_logs=logs,
    )
