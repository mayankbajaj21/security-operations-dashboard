"""
tests/test_correlation_engine.py

Milestone 3 — Step 3: Event Correlation & Attack Chain Detection Test Suite

Validates:
A. Rule 1: Same User Correlation within sliding time window
B. Different users do not correlate under Rule 1
C. Rule 2: Same Source IP Correlation with multiple suspicious events
D. Different source IPs do not correlate under Rule 2
E. Rule 3: Same Asset Correlation with multiple threat events
F. Different assets do not correlate under Rule 3
G. Normal events do not generate false positive suspicious attack chains
H. Events outside time window do not correlate (boundary test)
I. Multi-Rule deduplication produces exactly one merged attack chain
J. Rule 4: Full MITRE multi-stage progression sequence
K. Rule 4: Partial MITRE progression sequence (2 stages)
L. Single isolated suspicious event produces NO attack chain
M. Missing / Null user handled safely
N. Missing / Null source IP handled safely
O. Missing / Null asset handled safely
P. Invalid / unparseable timestamp handled safely without crashing
Q. Configurable sliding window parameter verification (5m vs 30m)
R. Deterministic attack_chain_id reproducibility
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import unittest

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.schemas.correlation import AttackChain, CorrelationResult
from backend.app.services.correlation_engine import (
    EventCorrelationEngine,
    parse_event_timestamp,
    is_suspicious_event,
    map_event_mitre_stage,
    generate_deterministic_chain_id,
    DEFAULT_CORRELATION_WINDOW_MINUTES
)


class TestEventCorrelationEngine(unittest.TestCase):
    """
    Comprehensive test suite for the Milestone 3 Event Correlation Engine.
    """

    def setUp(self):
        self.engine = EventCorrelationEngine(correlation_window_minutes=15)
        self.base_time = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

    # -------------------------------------------------------------------------
    # A. Rule 1: Same User Correlation
    # -------------------------------------------------------------------------
    def test_same_user_correlation(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=5)).isoformat()

        events = [
            {
                "event_id": "EVT_U1",
                "timestamp": t1,
                "username": "admin_mayank",
                "event_type": "Failed Login",
                "prediction": "Suspicious",
                "threat_type": "Brute Force",
                "severity": "High",
                "source_ip": "192.168.1.50"
            },
            {
                "event_id": "EVT_U2",
                "timestamp": t2,
                "username": "admin_mayank",
                "event_type": "Unauthorized Access",
                "prediction": "Suspicious",
                "threat_type": "Privilege Escalation",
                "severity": "Critical",
                "source_ip": "192.168.1.51"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)
        chain = result.attack_chains[0]
        self.assertEqual(chain.events, ["EVT_U1", "EVT_U2"])
        self.assertEqual(chain.target_user, "admin_mayank")
        self.assertTrue(any("Rule 1: Same User" in r for r in chain.correlation_rules))

    # -------------------------------------------------------------------------
    # B. Different Users Do Not Correlate Under Rule 1
    # -------------------------------------------------------------------------
    def test_different_users_do_not_correlate(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=5)).isoformat()

        events = [
            {
                "event_id": "EVT_U_ALICE",
                "timestamp": t1,
                "username": "alice",
                "source_ip": "10.0.0.1",
                "asset_name": "Host-A",
                "prediction": "Suspicious",
                "threat_type": "Brute Force"
            },
            {
                "event_id": "EVT_U_BOB",
                "timestamp": t2,
                "username": "bob",
                "source_ip": "10.0.0.2",
                "asset_name": "Host-B",
                "prediction": "Suspicious",
                "threat_type": "Port Scan"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 0)
        self.assertEqual(len(result.isolated_event_ids), 2)

    # -------------------------------------------------------------------------
    # C. Rule 2: Same Source IP Correlation
    # -------------------------------------------------------------------------
    def test_same_source_ip_correlation(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=8)).isoformat()

        events = [
            {
                "event_id": "EVT_IP1",
                "timestamp": t1,
                "source_ip": "198.51.100.25",
                "username": "user1",
                "asset_name": "SRV-1",
                "prediction": "Suspicious",
                "threat_type": "Port Scan"
            },
            {
                "event_id": "EVT_IP2",
                "timestamp": t2,
                "source_ip": "198.51.100.25",
                "username": "user2",
                "asset_name": "SRV-2",
                "prediction": "Suspicious",
                "threat_type": "Brute Force"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)
        chain = result.attack_chains[0]
        self.assertEqual(chain.events, ["EVT_IP1", "EVT_IP2"])
        self.assertEqual(chain.source_ip, "198.51.100.25")
        self.assertTrue(any("Rule 2: Same Source IP" in r for r in chain.correlation_rules))

    # -------------------------------------------------------------------------
    # D. Different Source IPs Do Not Correlate
    # -------------------------------------------------------------------------
    def test_different_source_ips_do_not_correlate(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=5)).isoformat()

        events = [
            {
                "event_id": "EVT_IP_A",
                "timestamp": t1,
                "source_ip": "198.51.100.1",
                "username": "user_a",
                "asset_name": "Asset-A",
                "prediction": "Suspicious"
            },
            {
                "event_id": "EVT_IP_B",
                "timestamp": t2,
                "source_ip": "198.51.100.2",
                "username": "user_b",
                "asset_name": "Asset-B",
                "prediction": "Suspicious"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 0)

    # -------------------------------------------------------------------------
    # E. Rule 3: Same Asset Correlation
    # -------------------------------------------------------------------------
    def test_same_asset_correlation(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=10)).isoformat()

        events = [
            {
                "event_id": "EVT_AST1",
                "timestamp": t1,
                "asset_name": "DB-SRV-PROD",
                "source_ip": "10.0.1.1",
                "username": "app1",
                "prediction": "Suspicious",
                "threat_type": "SQL Injection"
            },
            {
                "event_id": "EVT_AST2",
                "timestamp": t2,
                "asset_name": "DB-SRV-PROD",
                "source_ip": "10.0.1.2",
                "username": "app2",
                "prediction": "Suspicious",
                "threat_type": "Data Exfiltration"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)
        chain = result.attack_chains[0]
        self.assertEqual(chain.events, ["EVT_AST1", "EVT_AST2"])
        self.assertEqual(chain.affected_asset, "DB-SRV-PROD")
        self.assertTrue(any("Rule 3: Same Asset" in r for r in chain.correlation_rules))

    # -------------------------------------------------------------------------
    # F. Different Assets Do Not Correlate Under Rule 3
    # -------------------------------------------------------------------------
    def test_different_assets_do_not_correlate(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=5)).isoformat()

        events = [
            {
                "event_id": "EVT_AST_A",
                "timestamp": t1,
                "asset_name": "WebServer-01",
                "username": "user_a",
                "source_ip": "1.1.1.1",
                "prediction": "Suspicious"
            },
            {
                "event_id": "EVT_AST_B",
                "timestamp": t2,
                "asset_name": "Database-99",
                "username": "user_b",
                "source_ip": "2.2.2.2",
                "prediction": "Suspicious"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 0)

    # -------------------------------------------------------------------------
    # G. Normal Events Do Not Form False Positive Suspicious Chains
    # -------------------------------------------------------------------------
    def test_normal_events_do_not_correlate_as_threat_chains(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=3)).isoformat()
        t3 = (self.base_time + timedelta(minutes=6)).isoformat()

        events = [
            {
                "event_id": "EVT_NORM_1",
                "timestamp": t1,
                "username": "regular_user",
                "source_ip": "192.168.1.10",
                "asset_name": "Office-PC",
                "prediction": "Normal",
                "severity": "Low",
                "threat_type": "Normal Activity"
            },
            {
                "event_id": "EVT_NORM_2",
                "timestamp": t2,
                "username": "regular_user",
                "source_ip": "192.168.1.10",
                "asset_name": "Office-PC",
                "prediction": "Normal",
                "severity": "Low",
                "threat_type": "Normal Activity"
            },
            {
                "event_id": "EVT_NORM_3",
                "timestamp": t3,
                "username": "regular_user",
                "source_ip": "192.168.1.10",
                "asset_name": "Office-PC",
                "prediction": "Normal",
                "severity": "Low",
                "threat_type": "Normal Activity"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 0)
        self.assertEqual(result.suspicious_events_count, 0)
        self.assertEqual(len(result.isolated_event_ids), 3)

    # -------------------------------------------------------------------------
    # H. Events Outside Time Window Do Not Correlate
    # -------------------------------------------------------------------------
    def test_events_outside_time_window_do_not_correlate(self):
        t1 = self.base_time.isoformat()
        # 25 minutes later (exceeds default 15m window)
        t2 = (self.base_time + timedelta(minutes=25)).isoformat()

        events = [
            {
                "event_id": "EVT_TIME_1",
                "timestamp": t1,
                "username": "target_user",
                "source_ip": "10.0.0.1",
                "prediction": "Suspicious",
                "threat_type": "Brute Force"
            },
            {
                "event_id": "EVT_TIME_2",
                "timestamp": t2,
                "username": "target_user",
                "source_ip": "10.0.0.1",
                "prediction": "Suspicious",
                "threat_type": "Brute Force"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 0)

    # -------------------------------------------------------------------------
    # I. Multi-Rule Deduplication
    # -------------------------------------------------------------------------
    def test_multi_rule_deduplication_single_merged_chain(self):
        """
        Events share Same User AND Same Source IP AND Same Asset.
        Must produce EXACTLY ONE unified attack chain, not 3 duplicate chains.
        """
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=4)).isoformat()

        events = [
            {
                "event_id": "EVT_M1",
                "timestamp": t1,
                "username": "admin",
                "source_ip": "192.168.1.100",
                "asset_name": "DC-PRIMARY",
                "prediction": "Suspicious",
                "threat_type": "Failed Login",
                "mitre_id": "T1110"
            },
            {
                "event_id": "EVT_M2",
                "timestamp": t2,
                "username": "admin",
                "source_ip": "192.168.1.100",
                "asset_name": "DC-PRIMARY",
                "prediction": "Suspicious",
                "threat_type": "Privilege Escalation",
                "mitre_id": "T1068"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)
        chain = result.attack_chains[0]
        self.assertEqual(chain.events, ["EVT_M1", "EVT_M2"])
        
        # Verify multiple satisfied rules are captured in the single merged chain
        rules_str = " ".join(chain.correlation_rules)
        self.assertIn("Rule 1", rules_str)
        self.assertIn("Rule 2", rules_str)
        self.assertIn("Rule 3", rules_str)

    # -------------------------------------------------------------------------
    # J. Rule 4: Full MITRE Multi-Stage Progression
    # -------------------------------------------------------------------------
    def test_full_mitre_multistage_progression(self):
        """
        Sequence:
        1. Port Scan / Initial Access (T1190)
        2. Brute Force / Credential Access (T1110)
        3. Privilege Escalation (T1068)
        4. Remote Services / Lateral Movement (T1021)
        5. Data Exfiltration (T1041)
        """
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=2)).isoformat()
        t3 = (self.base_time + timedelta(minutes=5)).isoformat()
        t4 = (self.base_time + timedelta(minutes=8)).isoformat()
        t5 = (self.base_time + timedelta(minutes=11)).isoformat()

        events = [
            {
                "event_id": "EVT_P1",
                "timestamp": t1,
                "source_ip": "198.51.100.77",
                "mitre_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "prediction": "Suspicious",
                "threat_type": "Port Scan"
            },
            {
                "event_id": "EVT_P2",
                "timestamp": t2,
                "source_ip": "198.51.100.77",
                "mitre_id": "T1110",
                "technique_name": "Brute Force",
                "prediction": "Suspicious",
                "threat_type": "Brute Force"
            },
            {
                "event_id": "EVT_P3",
                "timestamp": t3,
                "source_ip": "198.51.100.77",
                "mitre_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "prediction": "Suspicious",
                "threat_type": "Privilege Escalation"
            },
            {
                "event_id": "EVT_P4",
                "timestamp": t4,
                "source_ip": "198.51.100.77",
                "mitre_id": "T1021",
                "technique_name": "Remote Services",
                "prediction": "Suspicious",
                "threat_type": "Lateral Movement"
            },
            {
                "event_id": "EVT_P5",
                "timestamp": t5,
                "source_ip": "198.51.100.77",
                "mitre_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "prediction": "Suspicious",
                "threat_type": "Data Exfiltration"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)
        chain = result.attack_chains[0]
        self.assertEqual(len(chain.events), 5)
        self.assertEqual(chain.stage, "Exfiltration")
        self.assertIn("T1190", chain.techniques)
        self.assertIn("T1110", chain.techniques)
        self.assertIn("T1068", chain.techniques)
        self.assertIn("T1021", chain.techniques)
        self.assertIn("T1041", chain.techniques)

    # -------------------------------------------------------------------------
    # K. Rule 4: Partial MITRE Progression (2 Stages)
    # -------------------------------------------------------------------------
    def test_partial_mitre_progression(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=4)).isoformat()

        events = [
            {
                "event_id": "EVT_PART_1",
                "timestamp": t1,
                "username": "operator",
                "mitre_id": "T1110",
                "prediction": "Suspicious",
                "threat_type": "Failed Login"
            },
            {
                "event_id": "EVT_PART_2",
                "timestamp": t2,
                "username": "operator",
                "mitre_id": "T1068",
                "prediction": "Suspicious",
                "threat_type": "Privilege Escalation"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)
        chain = result.attack_chains[0]
        self.assertEqual(chain.stage, "Privilege Escalation")
        self.assertIn("Credential Access", chain.stages)
        self.assertIn("Privilege Escalation", chain.stages)

    # -------------------------------------------------------------------------
    # L. Single Suspicious Event Produces No Attack Chain
    # -------------------------------------------------------------------------
    def test_single_suspicious_event_no_chain(self):
        events = [
            {
                "event_id": "EVT_ISOLATED",
                "timestamp": self.base_time.isoformat(),
                "username": "lone_user",
                "source_ip": "1.2.3.4",
                "prediction": "Suspicious",
                "threat_type": "Malware"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 0)
        self.assertEqual(result.isolated_event_ids, ["EVT_ISOLATED"])

    # -------------------------------------------------------------------------
    # M. Missing / Null User Handled Safely
    # -------------------------------------------------------------------------
    def test_missing_user_handled_safely(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=3)).isoformat()

        events = [
            {
                "event_id": "EVT_NO_USER_1",
                "timestamp": t1,
                "username": None,
                "source_ip": "10.10.10.10",
                "prediction": "Suspicious"
            },
            {
                "event_id": "EVT_NO_USER_2",
                "timestamp": t2,
                "username": "",
                "source_ip": "10.10.10.10",
                "prediction": "Suspicious"
            }
        ]

        # Correlates under IP rule safely without throwing on missing username
        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)

    # -------------------------------------------------------------------------
    # N. Missing / Null Source IP Handled Safely
    # -------------------------------------------------------------------------
    def test_missing_source_ip_handled_safely(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=3)).isoformat()

        events = [
            {
                "event_id": "EVT_NO_IP_1",
                "timestamp": t1,
                "source_ip": None,
                "username": "user_shared",
                "prediction": "Suspicious"
            },
            {
                "event_id": "EVT_NO_IP_2",
                "timestamp": t2,
                "source_ip": "",
                "username": "user_shared",
                "prediction": "Suspicious"
            }
        ]

        # Correlates under User rule safely
        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)

    # -------------------------------------------------------------------------
    # O. Missing / Null Asset Handled Safely
    # -------------------------------------------------------------------------
    def test_missing_asset_handled_safely(self):
        t1 = self.base_time.isoformat()
        t2 = (self.base_time + timedelta(minutes=3)).isoformat()

        events = [
            {
                "event_id": "EVT_NO_AST_1",
                "timestamp": t1,
                "asset_name": None,
                "username": "test_acc",
                "prediction": "Suspicious"
            },
            {
                "event_id": "EVT_NO_AST_2",
                "timestamp": t2,
                "asset_name": "",
                "username": "test_acc",
                "prediction": "Suspicious"
            }
        ]

        result = self.engine.correlate(events)
        self.assertEqual(result.attack_chains_count, 1)

    # -------------------------------------------------------------------------
    # P. Invalid Timestamp Handled Safely
    # -------------------------------------------------------------------------
    def test_invalid_timestamp_handled_safely(self):
        events = [
            {
                "event_id": "EVT_BAD_TIME_1",
                "timestamp": "INVALID-DATE-STRING-999",
                "username": "user1",
                "prediction": "Suspicious"
            },
            {
                "event_id": "EVT_BAD_TIME_2",
                "timestamp": None,
                "username": "user1",
                "prediction": "Suspicious"
            }
        ]

        # Does not crash; since timestamps cannot be ordered, does not falsely chain
        result = self.engine.correlate(events)
        self.assertIsInstance(result, CorrelationResult)

    # -------------------------------------------------------------------------
    # Q. Configurable Sliding Time Window (5m vs 30m)
    # -------------------------------------------------------------------------
    def test_configurable_time_window(self):
        t1 = self.base_time.isoformat()
        # 12 minutes later
        t2 = (self.base_time + timedelta(minutes=12)).isoformat()

        events = [
            {
                "event_id": "EVT_WIN_1",
                "timestamp": t1,
                "username": "shared_user",
                "prediction": "Suspicious"
            },
            {
                "event_id": "EVT_WIN_2",
                "timestamp": t2,
                "username": "shared_user",
                "prediction": "Suspicious"
            }
        ]

        # Window = 5 minutes -> 12 minutes gap exceeds window -> 0 chains
        engine_5m = EventCorrelationEngine(correlation_window_minutes=5)
        res_5m = engine_5m.correlate(events)
        self.assertEqual(res_5m.attack_chains_count, 0)

        # Window = 15 minutes -> 12 minutes gap is within window -> 1 chain
        engine_15m = EventCorrelationEngine(correlation_window_minutes=15)
        res_15m = engine_15m.correlate(events)
        self.assertEqual(res_15m.attack_chains_count, 1)

        # Window = 30 minutes -> 12 minutes gap is within window -> 1 chain
        engine_30m = EventCorrelationEngine(correlation_window_minutes=30)
        res_30m = engine_30m.correlate(events)
        self.assertEqual(res_30m.attack_chains_count, 1)

    # -------------------------------------------------------------------------
    # R. Deterministic Attack Chain ID Generation
    # -------------------------------------------------------------------------
    def test_deterministic_chain_id(self):
        event_ids_a = ["EVT00001", "EVT00002"]
        event_ids_b = ["EVT00002", "EVT00001"] # Permuted order

        id_a = generate_deterministic_chain_id(event_ids_a)
        id_b = generate_deterministic_chain_id(event_ids_b)

        # Must produce the identical deterministic ID regardless of input list order
        self.assertEqual(id_a, id_b)
        self.assertTrue(id_a.startswith("AC-"))

        # Indexed format
        indexed_id = generate_deterministic_chain_id(event_ids_a, index=1)
        self.assertEqual(indexed_id, "AC-001")


if __name__ == "__main__":
    unittest.main()
