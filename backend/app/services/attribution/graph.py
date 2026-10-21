"""Attribution (Phase 6, contract section 7): one incident -> its causal account.

Method ``graph-attribution-1.0.0``:

1. **Graph.** Nodes are canonical entities (company addresses and vhosts mapped to their host
   by the asset inventory). Each event of the incident's alerts gives directed, timestamped
   edges that cite it:
       user_login           ip -> account (AUTHENTICATED_AS), account -> host / app (LOGGED_INTO)
       process_execution    account -> host (EXECUTED_ON)
       http_request         ip -> application / host (HTTP_REQUEST)
       dns_query            ip -> domain (DNS_QUERY)
       anything else        first actor -> target (EVENT_TYPE)
2. **Entry point.** 1.1.0 (default): the incident graph's ROOT - among nodes with no in-edge
   at all in the alert-level graph, the one whose first out-edge is earliest; that edge is the
   entry event. 1.0.0 took the earliest alert-level edge, which breaks when an alert window on a
   shared address (the VPN server) also holds other users' requests made minutes before the
   attacker logged in (shaw, wilson). If the entry edge is an authentication, the entry is the
   ACCOUNT that was used (the foothold) and the root address is its origin.
3. **Attack path.** One pass over the alert-level events in time order gives the earliest time
   each entity is reached from the entry through time-respecting edges, and the event that
   reached it. The path to an asset is followed back through those events; every step cites a
   real event, and steps never go back in time.
4. **Reached assets** = company hosts (inventory) and accounts reached after the entry.
   **Blast radius**: reached count, potential reach (entities forward-reachable from the reached
   ones in the tenant's observed access graph, if given) and critical assets (criticality >= 4).
5. **Confidence** = min(entry confidence, mean anomaly score along the path) - contract v1.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import networkx as nx

from app.services.attribution.correlation import EMPTY_INVENTORY, AssetInventory
from app.services.detection import contract as C
from app.services.detection.resolve import EnrichedEvent, EntityRef, entity_id

METHOD = "graph-attribution-1.1.0"
METHODS = ("graph-attribution-1.0.0", "graph-attribution-1.1.0")   # entry rule: earliest edge / graph root
TACTICS = {
    "reconnaissance": "Reconnaissance", "initial_access": "Initial Access", "credential_access": "Credential Access",
    "execution": "Execution", "persistence": "Persistence", "privilege_escalation": "Privilege Escalation",
    "discovery": "Discovery", "lateral_movement": "Lateral Movement", "collection": "Collection",
    "exfiltration": "Exfiltration",
}
TECHNIQUE_NAMES = {
    "T1078": "Valid Accounts", "T1110": "Brute Force", "T1110.003": "Password Spraying", "T1548": "Abuse Elevation Control Mechanism",
    "T1548.003": "Sudo and Sudo Caching", "T1003.008": "/etc/passwd and /etc/shadow", "T1071.004": "Application Layer Protocol: DNS",
    "T1595": "Active Scanning", "T1098": "Account Manipulation", "T1213": "Data from Information Repositories",
}
Edge = Tuple[str, str, str]   # (source, target, relation)


def _iso(ts_us: int) -> str:
    return datetime.fromtimestamp(ts_us / 1e6, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Namer:
    """Canonical entity IDs plus their display type / label."""

    def __init__(self, assets: AssetInventory):
        self.assets = assets
        self.info: Dict[str, Tuple[str, str]] = {}

    def __call__(self, ref: EntityRef) -> str:
        cid = self.assets.canonical(ref)
        if cid not in self.info:
            host = None
            if cid != ref.entity_id:
                host = (self.assets.ip_to_host.get(ref.identifier) if ref.entity_type == "ip"
                        else self.assets.fqdn_to_host.get(ref.identifier.lower()))
            self.info[cid] = ("host", host) if host else (ref.entity_type, ref.identifier)
        return cid


def event_edges(event: EnrichedEvent, name: _Namer) -> List[Edge]:
    """Directed edges an event proves (canonical IDs). Self-loops are dropped."""
    ip = name(event.actor_ip) if event.actor_ip else None
    user = name(event.actor_user) if event.actor_user else None
    host = name(event.actor_host) if event.actor_host else None
    target = name(event.target) if event.target else None
    out: List[Edge] = []
    if event.event_type == "user_login":
        if ip and user:
            out.append((ip, user, "AUTHENTICATED_AS"))
        if (user or ip) and target:
            out.append((user or ip, target, "LOGGED_INTO"))
    elif event.event_type == "process_execution":
        if user and (target or host):
            out.append((user, target or host, "EXECUTED_ON"))
    elif event.event_type == "http_request":
        if (ip or user) and target:
            out.append((ip or user, target, "HTTP_REQUEST"))
    elif event.event_type == "dns_query":
        if ip and target:
            out.append((ip, target, "DNS_QUERY"))
    else:
        source = user or ip or host
        if source and target:
            out.append((source, target, event.event_type.upper()))
    return [e for e in out if e[0] != e[1]]


def observed_graph(events: Iterable[EnrichedEvent], assets: AssetInventory = EMPTY_INVENTORY) -> nx.DiGraph:
    """The tenant's observed access graph (for potential reach): every edge any event proves."""
    name = _Namer(assets)
    g = nx.DiGraph()
    for event in events:
        for u, v, _ in event_edges(event, name):
            g.add_edge(u, v)
    return g


def attribution_id(incident_id: str) -> str:
    return "att-" + incident_id.split("-", 1)[-1]


def _entry_edge(anomalous: Sequence[EnrichedEvent], name: "_Namer", method: str) -> Tuple[EnrichedEvent, List[Edge]]:
    """The event and its edges that start the story (see module docstring, point 2)."""
    with_edges = [(e, edges) for e in anomalous if (edges := event_edges(e, name))]
    if not with_edges:
        return anomalous[0], []
    if method == "graph-attribution-1.0.0":
        return with_edges[0]
    indegree: Dict[str, int] = {}
    for _, edges in with_edges:
        for u, v, _ in edges:
            indegree.setdefault(u, 0)
            indegree[v] = indegree.get(v, 0) + 1
    for event, edges in with_edges:              # chronological: the first edge out of a root wins
        if any(indegree[u] == 0 for u, _, _ in edges):
            return event, [e for e in edges if indegree[e[0]] == 0] + [e for e in edges if indegree[e[0]] != 0]
    return with_edges[0]                          # no root (every node has an in-edge): earliest edge


def attribute(incident: Mapping[str, Any], fused_alerts: Sequence[Mapping[str, Any]],
              events: Mapping[str, EnrichedEvent], assets: AssetInventory = EMPTY_INVENTORY,
              access_graph: Optional[nx.DiGraph] = None, method: str = METHOD) -> Dict[str, Any]:
    """Attribution Result (contract section 7) for one incident."""
    if method not in METHODS:
        raise ValueError(f"unknown attribution method: {method}")
    members = [a for a in fused_alerts if a["fused_alert_id"] in set(incident["fused_alert_ids"])]
    name = _Namer(assets)
    score_of: Dict[str, float] = {}
    alert_level: Set[str] = set()
    for alert in members:
        for eid in alert.get("event_ids", []):
            score_of[eid] = max(score_of.get(eid, 0.0), float(alert["confidence"]))
            if alert["decision"] == "alert":
                alert_level.add(eid)
    ordered = sorted((events[e] for e in score_of if e in events), key=lambda e: (e.ts_us, e.event_id))
    anomalous = [e for e in ordered if e.event_id in alert_level] or ordered
    if not anomalous:
        raise ValueError(f"{incident['incident_id']}: no resolvable events")

    # ---- entry point
    entry_event, entry_edges = _entry_edge(anomalous, name, method)
    origin = None
    if entry_edges and entry_edges[0][2] == "AUTHENTICATED_AS":
        origin, entry = entry_edges[0][0], entry_edges[0][1]
    elif entry_edges:
        entry = entry_edges[0][0]
    else:
        ref = entry_event.actor_user or entry_event.actor_ip or entry_event.actor_host
        entry = name(ref)

    # ---- earliest arrival from the entry (time-respecting, alert-level events)
    arrival: Dict[str, int] = {entry: entry_event.ts_us}
    via: Dict[str, Tuple[str, str, EnrichedEvent]] = {}
    for event in anomalous:
        if event.ts_us < entry_event.ts_us:
            continue
        for u, v, relation in event_edges(event, name):
            if u in arrival and arrival[u] <= event.ts_us and (v not in arrival or event.ts_us < arrival[v]):
                if v == entry:
                    continue
                arrival[v], via[v] = event.ts_us, (u, relation, event)

    def path_to(node: str) -> List[Tuple[str, str, str, EnrichedEvent]]:
        steps = []
        while node in via:
            u, relation, event = via[node]
            steps.append((u, node, relation, event))
            node = u
        return list(reversed(steps))

    company = _company_hosts(assets)
    reached = []
    for node, ts in sorted(arrival.items(), key=lambda kv: (kv[1], kv[0])):
        if node == entry:
            continue
        etype, label = name.info.get(node, ("unknown", node))
        if (etype == "host" and label in company) or etype == "user":
            reached.append({"entity_id": node, "entity_type": etype, "identifier": label,
                            "criticality": company.get(label, 1) if etype == "host" else 1,
                            "first_reached_at": _iso(ts)})

    # the attack path: union of the time-respecting paths to every reached asset, in time order
    step_set: Dict[Tuple[str, str, str], Tuple[str, str, str, EnrichedEvent]] = {}
    if origin:
        step_set[(origin, entry, entry_event.event_id)] = (origin, entry, "AUTHENTICATED_AS", entry_event)
    for asset in reached:
        for u, v, relation, event in path_to(asset["entity_id"]):
            step_set[(u, v, event.event_id)] = (u, v, relation, event)
    steps = sorted(step_set.values(), key=lambda s: (s[3].ts_us, s[3].event_id, s[0], s[1]))
    attack_path = [{"step": i + 1, "source_entity_id": u, "target_entity_id": v, "action": event.event_type,
                    "relation": relation, "layer": event.source_layer, "event_id": event.event_id,
                    "observed_at": _iso(event.ts_us), "anomaly_score": round(score_of.get(event.event_id, 0.0), 6)}
                   for i, (u, v, relation, event) in enumerate(steps)]

    potential = None
    if access_graph is not None:
        frontier = {a["entity_id"] for a in reached} | {entry}
        reachable: Set[str] = set()
        for node in frontier:
            if node in access_graph:
                reachable |= nx.descendants(access_graph, node)
        hosts = _host_ids(assets)
        potential = len({n for n in reachable - frontier if n.startswith("ent-user-") or n in hosts})

    entry_conf = round(score_of.get(entry_event.event_id, 0.0), 6)
    path_scores = [s["anomaly_score"] for s in attack_path]
    confidence = round(min(entry_conf, sum(path_scores) / len(path_scores)) if path_scores else entry_conf, 6)
    last_seen = max(e.ts_us for e in ordered)
    techniques = []
    for alert in sorted(members, key=lambda a: a["window_start"]):
        if alert.get("technique") in TACTICS and alert.get("technique_id"):
            item = {"tactic": TACTICS[alert["technique"]], "technique_id": alert["technique_id"],
                    "technique_name": TECHNIQUE_NAMES.get(alert["technique_id"], alert["technique_id"])}
            if item not in techniques:
                techniques.append(item)

    entry_type, entry_label = name.info.get(entry, ("unknown", entry))
    nodes = {entry} | {a["entity_id"] for a in reached} | {s["source_entity_id"] for s in attack_path} | \
        {s["target_entity_id"] for s in attack_path}
    graph = {
        "nodes": [{"id": n, "label": name.info.get(n, ("unknown", n))[1], "type": name.info.get(n, ("unknown", n))[0],
                   "properties": {"is_entry_point": n == entry, "is_origin": n == origin,
                                  "reached": any(a["entity_id"] == n for a in reached)}} for n in sorted(nodes)],
        "edges": [{"source": s["source_entity_id"], "target": s["target_entity_id"], "relation": s["relation"],
                   "weight": s["anomaly_score"]} for s in attack_path],
    }
    critical = [a for a in reached if a["criticality"] >= 4]
    origin_label = name.info.get(origin, ("", origin))[1] if origin else None
    explanation = (f"Entry via {entry_type} {entry_label}"
                   + (f" from {origin_label}" if origin_label else "")
                   + f" at {_iso(entry_event.ts_us)} ({entry_event.event_type}); "
                   + (f"reached {', '.join(a['identifier'] for a in reached)} " if reached else "no further asset reached ")
                   + f"over {len(attack_path)} step(s) across {len({s['layer'] for s in attack_path})} layer(s); "
                   + f"dwell time {_duration((last_seen - entry_event.ts_us) // 1_000_000)}.")
    return {
        "schema_version": C.SCHEMA_VERSION,
        "attribution_id": attribution_id(incident["incident_id"]),
        "tenant_id": incident.get("tenant_id"),
        "incident_id": incident["incident_id"],
        "method": method,
        "entry_point": {"entity_id": entry, "entity_type": entry_type, "identifier": entry_label,
                        "origin_entity_id": origin, "first_anomalous_event_id": entry_event.event_id,
                        "observed_at": _iso(entry_event.ts_us), "confidence": entry_conf},
        "attack_path": attack_path,
        "reached_assets": reached,
        "blast_radius": {"reached_count": len(reached), "potential_reach_count": potential,
                         "critical_assets_reached": len(critical)},
        "dwell_time_seconds": int((last_seen - entry_event.ts_us) // 1_000_000),
        "confidence": confidence,
        "techniques": techniques,
        "graph": graph,
        "explanation": explanation,
    }


def _company_hosts(assets: AssetInventory) -> Dict[str, int]:
    """Every host the inventory knows (by address, vhost or criticality) -> criticality (default 1)."""
    names = set(assets.criticality) | set(assets.ip_to_host.values()) | set(assets.fqdn_to_host.values())
    return {h: int(assets.criticality.get(h, 1)) for h in names}


def _host_ids(assets: AssetInventory) -> Set[str]:
    """Entity IDs of the company's hosts (potential reach counts company hosts and accounts only)."""
    return {entity_id("host", assets.tenant_id, h) for h in _company_hosts(assets)}


def _duration(seconds: int) -> str:
    h, rest = divmod(int(seconds), 3600)
    m, s = divmod(rest, 60)
    return f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"
