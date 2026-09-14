"""
tests/test_incident_service.py

Milestone 3 — Step 4: Incident Management Service & Lifecycle Test Suite

Validates:
A. Incident Creation from Risk Engine outputs & telemetry
B. Field Preservation (risk_score, risk_level, reasons, asset, user, etc.)
C. Default 'Open' status upon incident generation
D. Valid Lifecycle Transition: Open -> Investigating
E. Valid Lifecycle Transition: Investigating -> Resolved
F. Valid Lifecycle Transition: Investigating -> False Positive
G. Valid Lifecycle Transition: Open -> False Positive
H. Invalid Lifecycle Transitions (Resolved -> Open, False Positive -> Investigating, Resolved -> Investigating)
I. Incident ID Determinism (reproducible hashing of event IDs)
J. Priority field preserved as None (no invented P1-P4 formula)
K. Correlated Incident Creation with AttackChain linkage
L. Incident Retrieval and Status-Filtered Listing
"""

from pathlib import Path
import sys
import unittest

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.schemas.incident import Incident, IncidentStatus
from backend.app.schemas.risk import RiskCalculateResponse, RiskComponentBreakdown, ComponentScore
from backend.app.schemas.correlation import AttackChain
from backend.app.services.incident_service import (
    IncidentService,
    validate_status_transition,
    generate_deterministic_incident_id
)


class TestIncidentService(unittest.TestCase):
    """
    Unit and integration test suite for the Milestone 3 Incident Service.
    """

    def setUp(self):
        # Initialized with in-memory fallback for deterministic isolated testing
        self.service = IncidentService(db=None)

    def test_incident_creation_and_field_preservation(self):
        risk_res = {
            "event_id": "EVT00034",
            "risk_score": 94,
            "risk_level": "Critical",
            "threat_type": "Brute Force",
            "reasons": ["18 failed logins", "After-hours activity"]
        }
        event_telemetry = {
            "asset_name": "DB-SRV-PROD-01",
            "username": "admin_mayank",
            "source_ip": "198.51.100.45",
            "destination_ip": "10.0.1.50",
            "confidence_score": 89,
            "mitre_id": "T1110",
            "threat_intel_match": True,
            "timestamp": "2026-09-06T15:30:00Z"
        }

        incident = self.service.create_incident_from_risk(
            risk_result=risk_res,
            event_telemetry=event_telemetry
        )

        # Assert field preservation from M3 risk engine
        self.assertIsInstance(incident, Incident)
        self.assertEqual(incident.risk_score, 94)
        self.assertEqual(incident.risk_level, "Critical")
        self.assertEqual(incident.threat_type, "Brute Force")
        self.assertEqual(incident.affected_asset, "DB-SRV-PROD-01")
        self.assertEqual(incident.affected_user, "admin_mayank")
        self.assertEqual(incident.source_ip, "198.51.100.45")
        self.assertEqual(incident.ml_confidence, 89)
        self.assertEqual(incident.related_events, ["EVT00034"])
        self.assertEqual(incident.mitre_techniques, ["T1110"])
        self.assertEqual(incident.ioc_status, "Malicious")
        self.assertEqual(incident.status, IncidentStatus.OPEN.value)

        # Assert priority is preserved as None (per explicit specification rule)
        self.assertIsNone(incident.priority)

        # Assert recommendations were attached
        self.assertIsInstance(incident.recommendations, list)
        self.assertGreater(len(incident.recommendations), 0)
        self.assertIn("Temporarily lock account", incident.recommendations)

    def test_open_to_investigating_transition(self):
        risk_res = {"event_id": "EVT01", "risk_score": 80, "risk_level": "High", "threat_type": "Malware"}
        incident = self.service.create_incident_from_risk(risk_res, index=1)
        self.assertEqual(incident.status, "Open")

        updated = self.service.update_incident_status(
            incident_id=incident.incident_id,
            new_status="Investigating",
            assigned_to="Mayank Bajaj",
            notes="Triage commenced"
        )
        self.assertEqual(updated.status, "Investigating")
        self.assertEqual(updated.assigned_to, "Mayank Bajaj")

    def test_investigating_to_resolved_transition(self):
        risk_res = {"event_id": "EVT02", "risk_score": 75, "risk_level": "High", "threat_type": "SQL Injection"}
        incident = self.service.create_incident_from_risk(risk_res, index=2)

        self.service.update_incident_status(incident.incident_id, "Investigating")
        resolved = self.service.update_incident_status(
            incident.incident_id,
            "Resolved",
            notes="WAF patch applied"
        )
        self.assertEqual(resolved.status, "Resolved")

    def test_investigating_to_false_positive_transition(self):
        risk_res = {"event_id": "EVT03", "risk_score": 65, "risk_level": "High", "threat_type": "Port Scan"}
        incident = self.service.create_incident_from_risk(risk_res, index=3)

        self.service.update_incident_status(incident.incident_id, "Investigating")
        fp = self.service.update_incident_status(
            incident.incident_id,
            "False Positive",
            notes="Authorized penetration test scan"
        )
        self.assertEqual(fp.status, "False Positive")

    def test_open_to_false_positive_transition(self):
        risk_res = {"event_id": "EVT04", "risk_score": 62, "risk_level": "High", "threat_type": "Phishing"}
        incident = self.service.create_incident_from_risk(risk_res, index=4)

        fp = self.service.update_incident_status(incident.incident_id, "False Positive")
        self.assertEqual(fp.status, "False Positive")

    def test_invalid_lifecycle_transitions_raise_error(self):
        # 1. Open -> Resolved (Must go through Investigating first)
        with self.assertRaises(ValueError):
            validate_status_transition("Open", "Resolved")

        # 2. Resolved -> Open
        with self.assertRaises(ValueError):
            validate_status_transition("Resolved", "Open")

        # 3. Resolved -> False Positive (Must reopen to Investigating first)
        with self.assertRaises(ValueError):
            validate_status_transition("Resolved", "False Positive")

        # 4. False Positive -> Open
        with self.assertRaises(ValueError):
            validate_status_transition("False Positive", "Open")

        # 5. False Positive -> Resolved (Must reopen to Investigating first)
        with self.assertRaises(ValueError):
            validate_status_transition("False Positive", "Resolved")

    def test_reopen_lifecycle_transitions(self):
        # 1. Resolved -> Investigating (Reopen is explicitly allowed)
        validate_status_transition("Resolved", "Investigating")

        # 2. False Positive -> Investigating (Reopen is explicitly allowed)
        validate_status_transition("False Positive", "Investigating")

        # 3. Reopened incident (Investigating) -> Resolved
        validate_status_transition("Investigating", "Resolved")

        # 4. Reopened incident (Investigating) -> False Positive
        validate_status_transition("Investigating", "False Positive")

    def test_deterministic_incident_id(self):
        events_1 = ["EVT00001", "EVT00002"]
        events_2 = ["EVT00002", "EVT00001"] # Permuted order

        id_1 = generate_deterministic_incident_id(events_1)
        id_2 = generate_deterministic_incident_id(events_2)

        self.assertEqual(id_1, id_2)
        self.assertTrue(id_1.startswith("INC-"))

        # Indexed format
        indexed = generate_deterministic_incident_id(events_1, index=10)
        self.assertEqual(indexed, "INC-2026-010")

    def test_incident_creation_from_attack_chain(self):
        chain = AttackChain(
            attack_chain_id="AC-001",
            events=["EVT01", "EVT02", "EVT03"],
            techniques=["T1110", "T1078"],
            stage="Credential Access",
            risk_score=92,
            confidence=88,
            affected_asset="AUTH-SERVER",
            target_user="sysadmin",
            source_ip="198.51.100.99"
        )
        risk_res = {"event_id": "EVT01", "risk_score": 92, "risk_level": "Critical", "threat_type": "Brute Force"}

        incident = self.service.create_incident_from_risk(
            risk_result=risk_res,
            attack_chain=chain
        )

        self.assertEqual(incident.attack_chain_id, "AC-001")
        self.assertEqual(incident.related_events, ["EVT01", "EVT02", "EVT03"])
        self.assertEqual(incident.mitre_techniques, ["T1110", "T1078"])
        self.assertEqual(incident.affected_asset, "AUTH-SERVER")
        self.assertEqual(incident.affected_user, "sysadmin")
        self.assertEqual(incident.source_ip, "198.51.100.99")
        self.assertIn("AC-001", " ".join(incident.recommendations))

    def test_list_incidents_with_status_filter(self):
        # Create 2 Open, 1 Investigating
        inc1 = self.service.create_incident_from_risk({"event_id": "E1", "risk_score": 70, "risk_level": "High"}, index=101)
        inc2 = self.service.create_incident_from_risk({"event_id": "E2", "risk_score": 75, "risk_level": "High"}, index=102)
        inc3 = self.service.create_incident_from_risk({"event_id": "E3", "risk_score": 80, "risk_level": "High"}, index=103)

        self.service.update_incident_status(inc3.incident_id, "Investigating")

        open_list = self.service.list_incidents(status="Open")
        inv_list = self.service.list_incidents(status="Investigating")

        self.assertTrue(any(i.incident_id == inc1.incident_id for i in open_list))
        self.assertTrue(any(i.incident_id == inc2.incident_id for i in open_list))
        self.assertTrue(any(i.incident_id == inc3.incident_id for i in inv_list))


if __name__ == "__main__":
    unittest.main()
