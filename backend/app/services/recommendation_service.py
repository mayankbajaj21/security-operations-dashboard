"""
backend/app/services/recommendation_service.py

Milestone 3 — Step 4: Prescriptive Analyst Recommendation Service Module

Generates deterministic, prescriptive response actions for SOC analysts based on
the evaluated threat classification.

SAFETY & COMPLIANCE RULES:
- All recommendations are strictly HUMAN-IN-THE-LOOP guidance for SOC analysts.
- Recommendations DO NOT execute shell commands, API drops, account locks,
  endpoint isolation, or any destructive automated modifications.
- Zero LLM dependencies (deterministic, auditable rule matrix).
"""

from typing import List, Optional, Dict
from backend.app.schemas.incident import RecommendationItem


# Canonical Threat-to-Recommendation Matrix per M3 Specification & M2 Threat Types
THREAT_RECOMMENDATION_MATRIX: Dict[str, List[Dict[str, str]]] = {
    # 1. Brute Force (M3 Specification Benchmark)
    "brute force": [
        {"action": "Temporarily lock account", "category": "Immediate Containment", "rationale": "Prevents ongoing automated password guessing attempts."},
        {"action": "Investigate source IP in threat intelligence feeds", "category": "Investigation", "rationale": "Identifies if source IP belongs to known botnet or malicious proxy."},
        {"action": "Check authentication logs for unauthorized access", "category": "Investigation", "rationale": "Verifies whether any prior login attempt succeeded."},
        {"action": "Enable Multi-Factor Authentication (MFA)", "category": "Remediation", "rationale": "Eliminates single-factor credential stuffing vulnerability."}
    ],

    # 2. Malware (M3 Specification Benchmark)
    "malware": [
        {"action": "Isolate endpoint from network subnet", "category": "Immediate Containment", "rationale": "Halts potential lateral movement and C2 beaconing."},
        {"action": "Scan system with updated anti-malware engine", "category": "Remediation", "rationale": "Cleans residual infected binaries and persistence artifacts."},
        {"action": "Investigate file hash and active processes", "category": "Investigation", "rationale": "Traces parent-child process tree and binary provenance."}
    ],
    "malware detection": [
        {"action": "Isolate endpoint from network subnet", "category": "Immediate Containment", "rationale": "Halts potential lateral movement and C2 beaconing."},
        {"action": "Scan system with updated anti-malware engine", "category": "Remediation", "rationale": "Cleans residual infected binaries and persistence artifacts."},
        {"action": "Investigate file hash and active processes", "category": "Investigation", "rationale": "Traces parent-child process tree and binary provenance."}
    ],

    # 3. Data Exfiltration (M3 Specification Benchmark)
    "data exfiltration": [
        {"action": "Investigate destination IP and network reputation", "category": "Investigation", "rationale": "Determines target external drop server and ASN ownership."},
        {"action": "Restrict suspicious outbound connection on perimeter firewall", "category": "Immediate Containment", "rationale": "Stops ongoing data transfer stream immediately."},
        {"action": "Review data transfer volume and cloud egress logs", "category": "Investigation", "rationale": "Quantifies total sensitive records or payload size exfiltrated."},
        {"action": "Escalate to Tier-3 incident response team", "category": "Remediation", "rationale": "Initiates enterprise incident response and breach notification protocols."}
    ],
    "exfiltration": [
        {"action": "Investigate destination IP and network reputation", "category": "Investigation", "rationale": "Determines target external drop server and ASN ownership."},
        {"action": "Restrict suspicious outbound connection on perimeter firewall", "category": "Immediate Containment", "rationale": "Stops ongoing data transfer stream immediately."},
        {"action": "Review data transfer volume and cloud egress logs", "category": "Investigation", "rationale": "Quantifies total sensitive records or payload size exfiltrated."},
        {"action": "Escalate to Tier-3 incident response team", "category": "Remediation", "rationale": "Initiates enterprise incident response and breach notification protocols."}
    ],

    # 4. Phishing / Phishing Email
    "phishing": [
        {"action": "Block sender domain and malicious URLs on email security gateway", "category": "Immediate Containment", "rationale": "Prevents delivery of companion lure emails to other staff."},
        {"action": "Check mailbox delivery logs for secondary recipients", "category": "Investigation", "rationale": "Identifies full blast radius across the organization."},
        {"action": "Reset credentials for targeted user account", "category": "Remediation", "rationale": "Neutralizes captured credentials entered on fake landing pages."}
    ],
    "phishing email": [
        {"action": "Block sender domain and malicious URLs on email security gateway", "category": "Immediate Containment", "rationale": "Prevents delivery of companion lure emails to other staff."},
        {"action": "Check mailbox delivery logs for secondary recipients", "category": "Investigation", "rationale": "Identifies full blast radius across the organization."},
        {"action": "Reset credentials for targeted user account", "category": "Remediation", "rationale": "Neutralizes captured credentials entered on fake landing pages."}
    ],

    # 5. SQL Injection
    "sql injection": [
        {"action": "Inspect web application firewall (WAF) query logs for injected payloads", "category": "Investigation", "rationale": "Identifies vulnerable URI parameter and injection syntax."},
        {"action": "Apply parameterized queries and input validation to affected endpoints", "category": "Remediation", "rationale": "Permanently remediates unsanitized SQL concatenation."},
        {"action": "Audit database access logs for data tampering", "category": "Investigation", "rationale": "Checks for unauthorized schema changes or table dumps."}
    ],

    # 6. Privilege Escalation
    "privilege escalation": [
        {"action": "Revoke escalated administrative permissions for account", "category": "Immediate Containment", "rationale": "Restricts user to standard least-privilege role."},
        {"action": "Audit user account privilege change logs and sudo usage", "category": "Investigation", "rationale": "Determines exact exploit or misconfiguration exploited."},
        {"action": "Force immediate session termination and password reset", "category": "Remediation", "rationale": "Invalidates active Kerberos/OAuth tokens."}
    ],

    # 7. Port Scan
    "port scan": [
        {"action": "Inspect perimeter firewall drop logs for source IP activity", "category": "Investigation", "rationale": "Quantifies reconnaissance breadth and targeted port list."},
        {"action": "Verify target ports and services are appropriately filtered", "category": "Remediation", "rationale": "Ensures closed ports do not respond to external probes."}
    ],

    # 8. Unauthorized File Access / File Access
    "unauthorized file access": [
        {"action": "Review file integrity monitoring (FIM) access logs", "category": "Investigation", "rationale": "Identifies accessed confidential files and read/write timestamps."},
        {"action": "Verify directory permissions and access control lists (ACLs)", "category": "Remediation", "rationale": "Restores strict role-based access controls."}
    ],
    "file access": [
        {"action": "Review file integrity monitoring (FIM) access logs", "category": "Investigation", "rationale": "Identifies accessed confidential files and read/write timestamps."},
        {"action": "Verify directory permissions and access control lists (ACLs)", "category": "Remediation", "rationale": "Restores strict role-based access controls."}
    ],

    # 9. USB / Removable Media
    "usb / removable media": [
        {"action": "Inspect endpoint device control logs for unauthorized mass storage", "category": "Investigation", "rationale": "Verifies vendor and serial number of connected USB hardware."},
        {"action": "Execute anti-malware scan on connected storage volume", "category": "Remediation", "rationale": "Scans for auto-run payloads or weaponized documents."}
    ],

    # 10. Authentication Anomaly
    "authentication anomaly": [
        {"action": "Verify user login location and device fingerprint", "category": "Investigation", "rationale": "Confirms whether travel velocity or new ASN is legitimate."},
        {"action": "Enforce step-up multi-factor authentication", "category": "Remediation", "rationale": "Validates analyst identity with secondary authentication challenge."}
    ]
}


class RecommendationService:
    """
    Deterministic Prescriptive Analyst Recommendation Service.
    Maps threat classifications into actionable, categorized guidance for SOC analysts.
    """

    @classmethod
    def get_recommendations(
        cls,
        threat_type: str,
        asset_criticality: Optional[str] = None,
        ioc_status: Optional[str] = None,
        attack_chain_id: Optional[str] = None
    ) -> List[str]:
        """
        Returns a list of prescriptive recommendation strings for the given threat context.
        """
        structured = cls.get_structured_recommendations(
            threat_type=threat_type,
            asset_criticality=asset_criticality,
            ioc_status=ioc_status,
            attack_chain_id=attack_chain_id
        )
        return [item.action for item in structured]

    @classmethod
    def get_structured_recommendations(
        cls,
        threat_type: str,
        asset_criticality: Optional[str] = None,
        ioc_status: Optional[str] = None,
        attack_chain_id: Optional[str] = None
    ) -> List[RecommendationItem]:
        """
        Returns structured recommendation objects with categories and rationales.
        """
        clean_threat = str(threat_type or "").strip().lower()
        raw_items = THREAT_RECOMMENDATION_MATRIX.get(clean_threat, [])

        results: List[RecommendationItem] = []
        for item in raw_items:
            results.append(RecommendationItem(
                action=item["action"],
                category=item.get("category", "Containment"),
                rationale=item.get("rationale")
            ))

        # Contextual Augmentations (if applicable)
        if asset_criticality and str(asset_criticality).strip().lower() == "critical":
            results.append(RecommendationItem(
                action="Initiate priority forensic snapshot of host virtual machine before reboot",
                category="Investigation",
                rationale="Preserves volatile RAM and disk evidence on critical tier-1 infrastructure."
            ))

        if ioc_status and str(ioc_status).strip().lower() in ("true", "malicious"):
            results.append(RecommendationItem(
                action="Add source IP to perimeter edge firewall blackhole list",
                category="Immediate Containment",
                rationale="Drops inbound packets from confirmed malicious threat intelligence indicator."
            ))

        if attack_chain_id:
            results.append(RecommendationItem(
                action=f"Review connected attack chain {attack_chain_id} for secondary lateral movement indicators",
                category="Investigation",
                rationale="Verifies whether attacker has pivoted across additional network segments."
            ))

        return results
