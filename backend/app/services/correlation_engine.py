"""
backend/app/services/correlation_engine.py

Milestone 3 — Step 3: Event Correlation & Attack Chain Detection Service Module

Implements the deterministic Event Correlation Engine for the Security Operations
Dashboard, detecting multi-stage cyber attack chains across 4 canonical rules:
    - Rule 1: Same User + Short Sliding Time Window
    - Rule 2: Same Source IP + Multiple Suspicious Events
    - Rule 3: Same Asset + Multiple Threat Events
    - Rule 4: MITRE Multi-Stage Kill Chain Sequence Progression
              (Initial Access -> Credential Access -> Privilege Escalation ->
               Lateral Movement -> Exfiltration)

Features:
- Configurable sliding time window (default: 15 minutes, tunable 5-30m)
- Safe timestamp parsing and robust handling of missing/null values
- Automatic graph-based cluster deduplication (zero redundant attack chains)
- Deterministic attack chain ID generation
- Single isolated event non-chaining guarantee
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
import hashlib
import logging
from typing import Dict, Any, List, Optional, Set, Tuple, Union

from backend.app.schemas.correlation import (
    AttackChain,
    CorrelatedEventSummary,
    CorrelationResult
)

logger = logging.getLogger("CorrelationEngine")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")

# Default sliding correlation window (in minutes) per Milestone 3 specification
DEFAULT_CORRELATION_WINDOW_MINUTES = 15

# Canonical 5-Stage MITRE Progression Hierarchy
MITRE_STAGE_ORDER = [
    "Initial Access",
    "Credential Access",
    "Privilege Escalation",
    "Lateral Movement",
    "Exfiltration"
]

STAGE_SEVERITY_INDEX = {stage: idx for idx, stage in enumerate(MITRE_STAGE_ORDER, start=1)}

# Canonical Mapping from Technique ID / Tactic / Event Type to M3 Stages
TECHNIQUE_STAGE_MAP = {
    # 1. Initial Access
    "T1190": "Initial Access",
    "T1566": "Initial Access",
    "T1133": "Initial Access",
    "Initial Access": "Initial Access",
    "Phishing": "Initial Access",
    "Phishing Email": "Initial Access",
    "Port Scan": "Initial Access",

    # 2. Credential Access
    "T1110": "Credential Access",
    "T1078": "Credential Access",
    "T1003": "Credential Access",
    "T1555": "Credential Access",
    "T1558": "Credential Access",
    "Credential Access": "Credential Access",
    "Brute Force": "Credential Access",
    "Failed Login": "Credential Access",
    "Authentication Anomaly": "Credential Access",

    # 3. Privilege Escalation
    "T1068": "Privilege Escalation",
    "T1548": "Privilege Escalation",
    "Privilege Escalation": "Privilege Escalation",
    "Unauthorized Access": "Privilege Escalation",
    "Unauthorized File Access": "Privilege Escalation",

    # 4. Lateral Movement
    "T1021": "Lateral Movement",
    "T1071": "Lateral Movement",
    "T1570": "Lateral Movement",
    "Lateral Movement": "Lateral Movement",
    "Remote Services": "Lateral Movement",
    "Network Infiltration": "Lateral Movement",

    # 5. Exfiltration
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1567": "Exfiltration",
    "Exfiltration": "Exfiltration",
    "Data Exfiltration": "Exfiltration",
    "File Exfiltration": "Exfiltration"
}


def parse_event_timestamp(ts: Any) -> Optional[datetime]:
    """
    Safely parses an event timestamp string, integer/float epoch, or datetime object.
    Returns timezone-aware UTC datetime or None if invalid.
    """
    if ts is None:
        return None

    if isinstance(ts, datetime):
        return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)

    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (ValueError, OSError):
            return None

    ts_str = str(ts).strip()
    if not ts_str:
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d"
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # Attempt standard ISO 8601 fromisoformat as fallback
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def is_suspicious_event(event: Dict[str, Any]) -> bool:
    """
    Determines if a security event qualifies as suspicious or threat-related.
    Events with purely 'Normal' prediction and Low severity are excluded from
    forming suspicious attack chains.
    """
    pred = str(event.get("prediction", event.get("ml_prediction", ""))).strip().lower()
    if pred in ("suspicious", "anomaly", "-1"):
        return True

    sev = str(event.get("severity", event.get("event_severity", ""))).strip().lower()
    if sev in ("critical", "high"):
        return True

    try:
        conf = float(event.get("confidence_score", event.get("ml_confidence", 0)))
        if conf >= 50.0:
            return True
    except (ValueError, TypeError):
        pass

    threat = str(event.get("threat_type", "")).strip().lower()
    if threat and threat not in ("normal activity", "normal", "none", "unknown"):
        return True

    ioc = event.get("threat_intel_match", event.get("ioc_status", False))
    if ioc is True or str(ioc).strip().lower() in ("true", "malicious", "1"):
        return True

    try:
        failed_logins = int(event.get("failed_login_attempts", 0))
        if failed_logins >= 3:
            return True
    except (ValueError, TypeError):
        pass

    return False


def map_event_mitre_stage(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Maps an event's MITRE attributes (mitre_id, technique_name, tactic, event_type)
    to a canonical MITRE technique ID and M3 progression stage.
    Returns (technique_id, stage_name).
    """
    technique_id = None
    stage = None

    # Check mitre_id (e.g. "T1110")
    raw_mitre = event.get("mitre_id")
    if raw_mitre and str(raw_mitre).strip() and str(raw_mitre).strip().lower() != "none":
        technique_id = str(raw_mitre).strip()
        stage = TECHNIQUE_STAGE_MAP.get(technique_id)

    # Check technique_name (e.g. "Brute Force")
    if not stage:
        tech_name = event.get("technique_name")
        if tech_name and str(tech_name).strip():
            stage = TECHNIQUE_STAGE_MAP.get(str(tech_name).strip())

    # Check tactic (e.g. "Credential Access")
    if not stage:
        tactic = event.get("tactic")
        if tactic and str(tactic).strip():
            stage = TECHNIQUE_STAGE_MAP.get(str(tactic).strip())

    # Check event_type / threat_type
    if not stage:
        e_type = event.get("event_type", event.get("threat_type"))
        if e_type and str(e_type).strip():
            stage = TECHNIQUE_STAGE_MAP.get(str(e_type).strip())

    return (technique_id, stage)


def generate_deterministic_chain_id(event_ids: List[str], index: Optional[int] = None) -> str:
    """
    Generates a deterministic attack chain identifier.
    If an index is provided, formats as 'AC-001'.
    Otherwise, computes an 8-character hex digest of the sorted event IDs: 'AC-a1b2c3d4'.
    """
    if index is not None and index > 0:
        return f"AC-{index:03d}"

    sorted_ids = ",".join(sorted(event_ids))
    digest = hashlib.sha256(sorted_ids.encode("utf-8")).hexdigest()[:8]
    return f"AC-{digest}"


class EventCorrelationEngine:
    """
    Deterministic Event Correlation Engine.
    Evaluates ingested security events, applies the 4 correlation rules within a
    configurable sliding time window, and produces deduplicated multi-stage attack chains.
    """

    def __init__(self, correlation_window_minutes: float = DEFAULT_CORRELATION_WINDOW_MINUTES):
        self.window_minutes = max(1.0, float(correlation_window_minutes))
        self.window_delta = timedelta(minutes=self.window_minutes)

    def correlate(self, events: List[Dict[str, Any]]) -> CorrelationResult:
        """
        Executes complete event correlation and attack-chain detection over a list of events.
        """
        if not events or not isinstance(events, list):
            return CorrelationResult(
                total_events_analyzed=0,
                suspicious_events_count=0,
                attack_chains_count=0,
                attack_chains=[],
                correlated_event_ids=[],
                isolated_event_ids=[]
            )

        # 1. Normalize and parse event timestamps
        parsed_events: List[Dict[str, Any]] = []
        for e in events:
            if not isinstance(e, dict):
                continue
            e_id = str(e.get("event_id", "")).strip()
            if not e_id:
                continue

            dt = parse_event_timestamp(e.get("timestamp"))
            tech_id, stage = map_event_mitre_stage(e)
            
            parsed_e = dict(e)
            parsed_e["_parsed_id"] = e_id
            parsed_e["_parsed_dt"] = dt
            parsed_e["_parsed_mitre_id"] = tech_id
            parsed_e["_parsed_stage"] = stage
            parsed_e["_is_suspicious"] = is_suspicious_event(e)
            parsed_events.append(parsed_e)

        total_analyzed = len(parsed_events)
        suspicious_events = [e for e in parsed_events if e["_is_suspicious"]]
        suspicious_count = len(suspicious_events)

        if suspicious_count < 2:
            # Single or zero suspicious events cannot form a multi-event attack chain
            all_ids = [e["_parsed_id"] for e in parsed_events]
            return CorrelationResult(
                total_events_analyzed=total_analyzed,
                suspicious_events_count=suspicious_count,
                attack_chains_count=0,
                attack_chains=[],
                correlated_event_ids=[],
                isolated_event_ids=all_ids
            )

        # Sort suspicious events chronologically by timestamp (events with None placed last)
        valid_time_events = [e for e in suspicious_events if e["_parsed_dt"] is not None]
        valid_time_events.sort(key=lambda x: x["_parsed_dt"])

        # 2. Apply Correlation Rules to generate raw candidate clusters
        # Candidate format: (set_of_event_ids, rule_name)
        candidate_clusters: List[Tuple[Set[str], str]] = []

        # Rule 1: Same User + Sliding Time Window
        candidate_clusters.extend(self._correlate_by_user(valid_time_events))

        # Rule 2: Same Source IP + Multiple Suspicious Events
        candidate_clusters.extend(self._correlate_by_source_ip(valid_time_events))

        # Rule 3: Same Asset + Multiple Threat Events
        candidate_clusters.extend(self._correlate_by_asset(valid_time_events))

        # Rule 4: MITRE Sequence Progression
        candidate_clusters.extend(self._correlate_by_mitre_sequence(valid_time_events))

        # 3. Graph-Based Connected Component Deduplication
        # Merges overlapping candidate clusters into unified, distinct event clusters
        deduplicated_chains = self._deduplicate_and_build_chains(
            candidate_clusters=candidate_clusters,
            event_lookup={e["_parsed_id"]: e for e in parsed_events}
        )

        # Collect correlated and isolated event IDs
        correlated_ids: Set[str] = set()
        for chain in deduplicated_chains:
            correlated_ids.update(chain.events)

        all_ids_list = [e["_parsed_id"] for e in parsed_events]
        isolated_ids = [eid for eid in all_ids_list if eid not in correlated_ids]

        return CorrelationResult(
            total_events_analyzed=total_analyzed,
            suspicious_events_count=suspicious_count,
            attack_chains_count=len(deduplicated_chains),
            attack_chains=deduplicated_chains,
            correlated_event_ids=sorted(list(correlated_ids)),
            isolated_event_ids=isolated_ids
        )

    def _correlate_by_user(self, events: List[Dict[str, Any]]) -> List[Tuple[Set[str], str]]:
        """
        Rule 1: Correlates events sharing the same user within the sliding time window.
        """
        candidates: List[Tuple[Set[str], str]] = []
        by_user: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for e in events:
            user = str(e.get("username", e.get("user_id", ""))).strip()
            if user and user.lower() not in ("none", "null", "unknown", "anonymous", ""):
                by_user[user].append(e)

        for user, user_events in by_user.items():
            if len(user_events) < 2:
                continue
            clusters = self._cluster_by_time_window(user_events)
            for c in clusters:
                if len(c) >= 2:
                    candidates.append((set(c), f"Rule 1: Same User ({user})"))

        return candidates

    def _correlate_by_source_ip(self, events: List[Dict[str, Any]]) -> List[Tuple[Set[str], str]]:
        """
        Rule 2: Correlates multiple suspicious events sharing the same source IP within the time window.
        """
        candidates: List[Tuple[Set[str], str]] = []
        by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for e in events:
            ip = str(e.get("source_ip", "")).strip()
            if ip and ip.lower() not in ("none", "null", "unknown", "0.0.0.0", "127.0.0.1", ""):
                by_ip[ip].append(e)

        for ip, ip_events in by_ip.items():
            if len(ip_events) < 2:
                continue
            clusters = self._cluster_by_time_window(ip_events)
            for c in clusters:
                if len(c) >= 2:
                    candidates.append((set(c), f"Rule 2: Same Source IP ({ip})"))

        return candidates

    def _correlate_by_asset(self, events: List[Dict[str, Any]]) -> List[Tuple[Set[str], str]]:
        """
        Rule 3: Correlates multiple threat events targeting the same asset within the time window.
        """
        candidates: List[Tuple[Set[str], str]] = []
        by_asset: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for e in events:
            asset = str(e.get("asset_name", e.get("asset_id", ""))).strip()
            if asset and asset.lower() not in ("none", "null", "unknown", ""):
                by_asset[asset].append(e)

        for asset, asset_events in by_asset.items():
            if len(asset_events) < 2:
                continue
            clusters = self._cluster_by_time_window(asset_events)
            for c in clusters:
                if len(c) >= 2:
                    candidates.append((set(c), f"Rule 3: Same Asset ({asset})"))

        return candidates

    def _correlate_by_mitre_sequence(self, events: List[Dict[str, Any]]) -> List[Tuple[Set[str], str]]:
        """
        Rule 4: Detects MITRE multi-stage kill chain progression across events within the time window.
        Progression: Initial Access -> Credential Access -> Privilege Escalation -> Lateral Movement -> Exfiltration
        """
        candidates: List[Tuple[Set[str], str]] = []
        if len(events) < 2:
            return candidates

        # Group events by common entity (user, IP, or asset) to ensure logical progression linkage
        entity_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for e in events:
            user = str(e.get("username", "")).strip()
            ip = str(e.get("source_ip", "")).strip()
            asset = str(e.get("asset_name", "")).strip()

            if user:
                entity_groups[f"user:{user}"].append(e)
            if ip:
                entity_groups[f"ip:{ip}"].append(e)
            if asset:
                entity_groups[f"asset:{asset}"].append(e)

        for entity_key, grp_events in entity_groups.items():
            if len(grp_events) < 2:
                continue

            time_clusters = self._cluster_by_time_window(grp_events)
            for cluster_ids in time_clusters:
                if len(cluster_ids) < 2:
                    continue

                cluster_evts = [e for e in grp_events if e["_parsed_id"] in cluster_ids]
                stages_seen = []
                for ce in cluster_evts:
                    stg = ce.get("_parsed_stage")
                    if stg and stg in STAGE_SEVERITY_INDEX:
                        if not stages_seen or stages_seen[-1] != stg:
                            stages_seen.append(stg)

                # Check if at least 2 distinct stages are observed
                unique_stages = set(stages_seen)
                if len(unique_stages) >= 2:
                    stage_flow = " -> ".join(stages_seen)
                    candidates.append((set(cluster_ids), f"Rule 4: MITRE Progression ({stage_flow})"))

        return candidates

    def _cluster_by_time_window(self, events: List[Dict[str, Any]]) -> List[List[str]]:
        """
        Clusters a chronologically sorted list of events into groups where consecutive
        events occur within the configured correlation time window.
        """
        if not events:
            return []

        clusters: List[List[str]] = []
        current_cluster: List[Dict[str, Any]] = [events[0]]

        for i in range(1, len(events)):
            prev_e = current_cluster[-1]
            curr_e = events[i]

            prev_dt = prev_e["_parsed_dt"]
            curr_dt = curr_e["_parsed_dt"]

            if prev_dt is not None and curr_dt is not None:
                diff = curr_dt - prev_dt
                if diff <= self.window_delta:
                    current_cluster.append(curr_e)
                else:
                    clusters.append([e["_parsed_id"] for e in current_cluster])
                    current_cluster = [curr_e]
            else:
                clusters.append([e["_parsed_id"] for e in current_cluster])
                current_cluster = [curr_e]

        if current_cluster:
            clusters.append([e["_parsed_id"] for e in current_cluster])

        return clusters

    def _deduplicate_and_build_chains(
        self,
        candidate_clusters: List[Tuple[Set[str], str]],
        event_lookup: Dict[str, Dict[str, Any]]
    ) -> List[AttackChain]:
        """
        Merges overlapping candidate clusters using graph connected component analysis.
        Constructs canonical AttackChain objects.
        """
        if not candidate_clusters:
            return []

        # 1. Build adjacency graph of event IDs
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        event_rules: Dict[str, Set[str]] = defaultdict(set)

        for event_set, rule_name in candidate_clusters:
            evt_list = list(event_set)
            for eid in evt_list:
                event_rules[eid].add(rule_name)
                for other_eid in evt_list:
                    if eid != other_eid:
                        adjacency[eid].add(other_eid)

        # 2. Extract connected components (BFS / DFS)
        visited: Set[str] = set()
        merged_groups: List[Tuple[List[str], Set[str]]] = []

        all_nodes = sorted(list(adjacency.keys()))
        for node in all_nodes:
            if node not in visited:
                comp_nodes: Set[str] = set()
                comp_rules: Set[str] = set()
                queue = [node]
                visited.add(node)

                while queue:
                    curr = queue.pop(0)
                    comp_nodes.add(curr)
                    comp_rules.update(event_rules[curr])

                    for neighbor in adjacency[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)

                if len(comp_nodes) >= 2:
                    merged_groups.append((sorted(list(comp_nodes)), comp_rules))

        # 3. Construct canonical AttackChain objects
        chains: List[AttackChain] = []
        for idx, (group_event_ids, rules_set) in enumerate(merged_groups, start=1):
            group_events = [event_lookup[eid] for eid in group_event_ids if eid in event_lookup]
            
            # Sort events in chronological sequence
            group_events.sort(key=lambda x: x.get("_parsed_dt") or datetime.min.replace(tzinfo=timezone.utc))
            sorted_event_ids = [e["_parsed_id"] for e in group_events]

            # Collect unique techniques and stages
            techniques_seen: List[str] = []
            stages_seen: List[str] = []
            for ge in group_events:
                tech = ge.get("_parsed_mitre_id")
                if tech and tech not in techniques_seen:
                    techniques_seen.append(tech)

                stg = ge.get("_parsed_stage")
                if stg and (not stages_seen or stages_seen[-1] != stg):
                    stages_seen.append(stg)

            # Determine highest or latest progression stage
            if stages_seen:
                # Pick highest index in MITRE_STAGE_ORDER
                highest_stage = max(stages_seen, key=lambda s: STAGE_SEVERITY_INDEX.get(s, 0))
            else:
                highest_stage = "Execution"

            # Compute composite risk score from participating events
            event_risks = []
            event_confs = []
            for ge in group_events:
                if "risk_score" in ge and ge["risk_score"] is not None:
                    try:
                        event_risks.append(float(ge["risk_score"]))
                    except (ValueError, TypeError):
                        pass
                if "confidence_score" in ge or "ml_confidence" in ge or "confidence" in ge:
                    c_val = ge.get("confidence_score", ge.get("ml_confidence", ge.get("confidence")))
                    try:
                        event_confs.append(float(c_val))
                    except (ValueError, TypeError):
                        pass

            if event_risks:
                # Use maximum risk score observed with progression augmentation
                base_risk = max(event_risks)
                progression_bonus = 5.0 if len(set(stages_seen)) >= 2 else 0.0
                composite_risk = int(min(100.0, base_risk + progression_bonus))
            else:
                # Default high risk for confirmed multi-event attack chain
                composite_risk = 85

            if event_confs:
                composite_conf = int(max(event_confs))
            else:
                composite_conf = 80

            # Determine predominant asset, user, source IP
            assets = [ge.get("asset_name", ge.get("asset_id")) for ge in group_events if ge.get("asset_name") or ge.get("asset_id")]
            users = [ge.get("username", ge.get("user_id")) for ge in group_events if ge.get("username") or ge.get("user_id")]
            ips = [ge.get("source_ip") for ge in group_events if ge.get("source_ip")]

            predominant_asset = max(set(assets), key=assets.count) if assets else None
            predominant_user = max(set(users), key=users.count) if users else None
            predominant_ip = max(set(ips), key=ips.count) if ips else None

            # Build summaries
            summaries = []
            for ge in group_events:
                summaries.append(CorrelatedEventSummary(
                    event_id=ge["_parsed_id"],
                    timestamp=str(ge.get("timestamp")) if ge.get("timestamp") else None,
                    event_type=ge.get("event_type"),
                    threat_type=ge.get("threat_type"),
                    severity=ge.get("severity", ge.get("event_severity")),
                    username=ge.get("username", ge.get("user_id")),
                    source_ip=ge.get("source_ip"),
                    destination_ip=ge.get("destination_ip"),
                    asset_name=ge.get("asset_name", ge.get("asset_id")),
                    mitre_id=ge.get("_parsed_mitre_id"),
                    stage=ge.get("_parsed_stage"),
                    risk_score=ge.get("risk_score"),
                    confidence=ge.get("confidence_score", ge.get("ml_confidence", ge.get("confidence")))
                ))

            chain_id = generate_deterministic_chain_id(sorted_event_ids, index=idx)
            threat_name = group_events[0].get("threat_type", "Multi-Vector Threat")

            chain_name = f"Correlated {threat_name} Campaign ({highest_stage})"
            if predominant_asset:
                chain_name += f" targeting {predominant_asset}"

            chain = AttackChain(
                attack_chain_id=chain_id,
                name=chain_name,
                events=sorted_event_ids,
                techniques=techniques_seen,
                stages=stages_seen,
                stage=highest_stage,
                risk_score=composite_risk,
                confidence=composite_conf,
                correlation_rules=sorted(list(rules_set)),
                affected_asset=predominant_asset,
                target_user=predominant_user,
                source_ip=predominant_ip,
                event_details=summaries,
                created_at=str(group_events[-1].get("timestamp")) if group_events[-1].get("timestamp") else datetime.now(timezone.utc).isoformat()
            )
            chains.append(chain)

        return chains
