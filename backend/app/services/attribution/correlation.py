"""Correlation (Phase 5, contract section 6): Fused Alerts -> Incident Objects.

Method ``entity-time-graph-1.0.0``. Nodes are Fused Alerts; two alerts are linked when

* **shared actor** - the same canonical entity *acts* in both (a user, a source address, a
  host running commands) and they are at most ``horizon`` apart; or
* **pivot** - an entity the earlier alert *targeted* later *acts* in the other alert (the
  attacker logged into the VPN server, then traffic comes from the VPN server; the web shell
  was planted on the intranet server, then the intranet server runs su / sudo). A pivot links
  only to the MOST RECENT earlier alert that targeted the entity, so ordinary traffic aimed at
  a busy server long before does not get pulled in.

Connected components are incidents. Entities are canonicalised with the asset inventory
first: a company address or a web vhost (FQDN) becomes the host that owns it, so activity seen
in different layers meets on one node.

Actors and targets come from the Enriched Events behind each alert (``resolve.py`` roles):
actor_user / actor_ip / actor_host are actors, ``target`` is the target.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from app.services.detection import contract as C
from app.services.detection.labeling import to_us
from app.services.detection.resolve import EnrichedEvent, EntityRef, entity_id

METHOD = "entity-time-graph-1.0.0"
DEFAULT_HORIZON_SECONDS = 86_400
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Kill-chain order used to sort stages and to say whether links respect it.
TECHNIQUE_ORDER = ("reconnaissance", "initial_access", "credential_access", "execution", "persistence",
                   "privilege_escalation", "discovery", "lateral_movement", "collection", "exfiltration",
                   "unknown")
TECHNIQUE_TITLES = {
    "reconnaissance": "reconnaissance", "initial_access": "initial access", "credential_access": "credential access",
    "execution": "execution", "persistence": "persistence", "privilege_escalation": "privilege escalation",
    "discovery": "discovery", "lateral_movement": "lateral movement", "collection": "collection",
    "exfiltration": "exfiltration", "unknown": "anomalous activity",
}


@dataclass(frozen=True)
class AssetInventory:
    """What the defender knows about its own hosts (from the CMDB / ``ait_assets.py``)."""

    tenant_id: str
    ip_to_host: Mapping[str, str] = field(default_factory=dict)
    fqdn_to_host: Mapping[str, str] = field(default_factory=dict)
    criticality: Mapping[str, int] = field(default_factory=dict)      # hostname -> 1..5

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AssetInventory":
        return cls(tenant_id=data["tenant_id"], ip_to_host=dict(data.get("ip_to_host", {})),
                   fqdn_to_host={k.lower(): v for k, v in data.get("fqdn_to_host", {}).items()},
                   criticality={h["hostname"]: int(h["criticality"]) for h in data.get("hosts", [])})

    def canonical(self, ref: EntityRef) -> str:
        """Entity ID after mapping company addresses and vhosts to the host that owns them."""
        host = None
        if ref.entity_type == "ip":
            host = self.ip_to_host.get(ref.identifier)
        elif ref.entity_type in ("application", "domain"):
            host = self.fqdn_to_host.get(ref.identifier.lower())
        return entity_id("host", self.tenant_id, host) if host else ref.entity_id


EMPTY_INVENTORY = AssetInventory(tenant_id="")


@dataclass
class _Node:
    index: int
    alert: Mapping[str, Any]
    start_us: int
    end_us: int
    actors: Set[str]
    targets: Set[str]
    layers: Set[str]
    entity_ids: Set[str]


def _profile(index: int, alert: Mapping[str, Any], events: Mapping[str, EnrichedEvent],
             assets: AssetInventory) -> _Node:
    actors: Set[str] = set()
    targets: Set[str] = set()
    layers: Set[str] = set()
    raw_ids: Set[str] = {alert["entity_id"]}
    times = []
    for eid in alert.get("event_ids", []):
        event = events.get(eid)
        if event is None:
            continue
        times.append(event.ts_us)
        layers.add(event.source_layer)
        for ref in (event.actor_user, event.actor_ip, event.actor_host):
            if ref is not None:
                actors.add(assets.canonical(ref))
                raw_ids.add(ref.entity_id)
        if event.target is not None:
            targets.add(assets.canonical(event.target))
            raw_ids.add(event.target.entity_id)
    if not times:  # an alert without resolvable events still carries its own entity and window
        actors.add(alert["entity_id"])
    start = min(times) if times else to_us(alert["window_start"])
    end = max(times) if times else to_us(alert["window_end"])
    return _Node(index, alert, start, end, actors, targets - actors, layers, raw_ids)


def _gap_us(a: _Node, b: _Node) -> int:
    """Time between two alerts' spans (0 if they overlap)."""
    return max(0, max(a.start_us, b.start_us) - min(a.end_us, b.end_us))


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def link(nodes: Sequence[_Node], horizon_us: int) -> List[Tuple[int, int, str]]:
    """Links (i, j, reason) with i earlier than j."""
    order = sorted(range(len(nodes)), key=lambda i: (nodes[i].start_us, nodes[i].alert["entity_id"]))
    links: List[Tuple[int, int, str]] = []
    for pos, j in enumerate(order):
        later = nodes[j]
        latest_target: Dict[str, int] = {}
        for i in order[:pos]:
            earlier = nodes[i]
            if _gap_us(earlier, later) > horizon_us:
                continue
            shared = sorted(earlier.actors & later.actors)
            if shared:
                links.append((i, j, f"shared_entity:{shared[0]}"))
            for x in earlier.targets & later.actors:
                latest_target[x] = i            # order is chronological: the last one written wins
        for x, i in sorted(latest_target.items()):
            links.append((i, j, f"pivot:{x}"))
    return links


def incident_id(fused_alert_ids: Iterable[str]) -> str:
    return "inc-" + hashlib.sha256("|".join(sorted(fused_alert_ids)).encode("utf-8")).hexdigest()[:8]


def _iso(ts_us: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts_us / 1e6, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def correlate(fused_alerts: Sequence[Mapping[str, Any]], events: Mapping[str, EnrichedEvent],
              assets: AssetInventory = EMPTY_INVENTORY,
              horizon_seconds: int = DEFAULT_HORIZON_SECONDS) -> List[Dict[str, Any]]:
    """Incident Objects (contract section 6), one per connected group of Fused Alerts."""
    nodes = [_profile(i, a, events, assets) for i, a in enumerate(fused_alerts)]
    links = link(nodes, horizon_seconds * 1_000_000)
    uf = _UnionFind(len(nodes))
    for i, j, _ in links:
        uf.union(i, j)
    groups: Dict[int, List[int]] = {}
    for i in range(len(nodes)):
        groups.setdefault(uf.find(i), []).append(i)
    reasons: Dict[int, List[str]] = {}
    for i, j, reason in links:
        reasons.setdefault(uf.find(i), []).append(reason)

    incidents = []
    for root, members in groups.items():
        members.sort(key=lambda i: (nodes[i].start_us, nodes[i].alert["entity_id"]))
        alerts = [nodes[i].alert for i in members]
        first_by_technique: Dict[str, int] = {}
        for i in members:
            t = nodes[i].alert.get("technique") or "unknown"
            first_by_technique[t] = min(first_by_technique.get(t, nodes[i].start_us), nodes[i].start_us)
        stages = sorted(first_by_technique.items(), key=lambda kv: (kv[1], TECHNIQUE_ORDER.index(kv[0])
                                                                      if kv[0] in TECHNIQUE_ORDER else 99))
        known = [t for t, _ in stages if t != "unknown"] or [t for t, _ in stages]
        stage_ranks = [TECHNIQUE_ORDER.index(t) for t, _ in stages if t in TECHNIQUE_ORDER and t != "unknown"]
        link_reasons = sorted(set(reasons.get(root, [])))
        if len(stage_ranks) > 1 and stage_ranks == sorted(stage_ranks):
            link_reasons.append("stage_order")
        severity = max((a.get("severity", "low") for a in alerts), key=lambda s: SEVERITY_RANK.get(s, 0))
        fused_ids = [a["fused_alert_id"] for a in alerts]
        first_seen = min(nodes[i].start_us for i in members)
        last_seen = max(nodes[i].end_us for i in members)
        title = (TECHNIQUE_TITLES[known[0]].capitalize() if len(known) == 1 else
                 f"{TECHNIQUE_TITLES[known[0]].capitalize()} leading to {TECHNIQUE_TITLES[known[-1]]}")
        entities = sorted(set().union(*(nodes[i].entity_ids for i in members)))
        layers = sorted(set().union(*(nodes[i].layers for i in members)))
        incidents.append({
            "schema_version": C.SCHEMA_VERSION,
            "incident_id": incident_id(fused_ids),
            "tenant_id": alerts[0].get("tenant_id") or assets.tenant_id or None,
            "title": title,
            "description": (f"{len(alerts)} fused alert(s) across {len(layers)} layer(s) and {len(entities)} "
                            f"entities: " + " -> ".join(TECHNIQUE_TITLES.get(t, t) for t, _ in stages)),
            "severity": "critical" if severity == "high" and len(known) >= 3 else severity,
            "status": "open",
            "fused_alert_ids": fused_ids,
            "alert_ids": sorted({m for a in alerts for m in a.get("member_alert_ids", [])}),
            "entity_ids": entities,
            "layers": layers,
            "stages": [{"technique": t, "first_seen": _iso(ts)} for t, ts in stages],
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
            "correlation": {"method": METHOD, "link_reasons": link_reasons,
                            "horizon_seconds": horizon_seconds, "links": len(reasons.get(root, []))},
        })
    incidents.sort(key=lambda inc: (inc["first_seen"], inc["incident_id"]))
    return incidents


def consolidation(fused_alerts: Sequence[Any], incidents: Sequence[Any]) -> Optional[float]:
    """Fused Alerts per incident (higher = more consolidation)."""
    return round(len(fused_alerts) / len(incidents), 3) if incidents else None
