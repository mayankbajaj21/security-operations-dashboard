"""
scripts/verify_m4_task2_contracts.py

Milestone 4 — Task 2 Non-Browser Contract Verification Script
Validates all Task 2 API endpoints, data boundaries, authoritative M3 risk engine reuse,
exact terminology, and 6 KPI card requirements.
"""

import sys
import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

def get(path: str) -> dict:
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "M4Task2Verification/1.0"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def run_tests():
    print("==================================================")
    print("M4 TASK 2: SOC OVERVIEW DASHBOARD VERIFICATION")
    print("==================================================")
    passed = 0
    total = 0

    # TEST 1: GET /metrics overview contains all required KPI fields
    total += 1
    try:
        metrics = get("/metrics")
        overview = metrics.get("overview", {})
        assert "total_events" in overview, "Missing total_events"
        assert "critical_events" in overview, "Missing critical_events"
        assert "high_events" in overview, "Missing high_events"
        assert "affected_assets" in overview, "Missing affected_assets in overview"
        assert overview["total_events"] == 1800, f"Expected 1800 total_events, got {overview['total_events']}"
        assert overview["critical_events"] == 346, f"Expected 346 critical_events, got {overview['critical_events']}"
        assert overview["high_events"] == 573, f"Expected 573 high_events, got {overview['high_events']}"
        assert overview["affected_assets"] == 5, f"Expected 5 affected_assets, got {overview['affected_assets']}"
        print("[PASS] Test 1: GET /metrics contains authoritative total_events (1800), critical_events (346), high_events (573), affected_assets (5)")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 1: {e}")

    # TEST 2: GET /threat-summary contains M2 detected anomalies and threat_types
    total += 1
    try:
        ts = get("/threat-summary")
        assert "anomalies_detected" in ts, "Missing anomalies_detected"
        assert "threat_types" in ts, "Missing threat_types"
        assert ts["anomalies_detected"] == 90, f"Expected 90 anomalies_detected, got {ts['anomalies_detected']}"
        tt = ts["threat_types"]
        assert isinstance(tt, dict), "threat_types must be a dict"
        assert "Brute Force" in tt, "Missing 'Brute Force' in threat_types"
        assert "SQL Injection" in tt, "Missing 'SQL Injection' in threat_types"
        print(f"[PASS] Test 2: GET /threat-summary supplies anomalies_detected (90) and {len(tt)} authoritative threat types")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 2: {e}")

    # TEST 3: GET /api/v1/incidents/summary contains authoritative active and high-risk incident metrics
    total += 1
    try:
        isum = get("/api/v1/incidents/summary")
        assert isum["total_incidents"] == 38, f"Expected 38 incidents, got {isum['total_incidents']}"
        assert isum["active_incidents"] == 24, f"Expected 24 active_incidents, got {isum['active_incidents']}"
        assert isum["high_risk_incidents"] == 36, f"Expected 36 high_risk_incidents, got {isum['high_risk_incidents']}"
        st = isum["by_status"]
        assert st["Open"] == 15, f"Expected 15 Open, got {st.get('Open')}"
        assert st["Investigating"] == 9, f"Expected 9 Investigating, got {st.get('Investigating')}"
        assert st["Resolved"] == 6, f"Expected 6 Resolved, got {st.get('Resolved')}"
        assert st["False Positive"] == 8, f"Expected 8 False Positive, got {st.get('False Positive')}"
        rl = isum["by_risk_level"]
        assert rl["Critical"] == 17, f"Expected 17 Critical, got {rl.get('Critical')}"
        assert rl["High"] == 19, f"Expected 19 High, got {rl.get('High')}"
        assert rl["Moderate"] == 1, f"Expected 1 Moderate, got {rl.get('Moderate')}"
        assert rl["Medium"] == 1, f"Expected 1 Medium, got {rl.get('Medium')}"
        print("[PASS] Test 3: GET /api/v1/incidents/summary provides authoritative active_incidents (24), high_risk_incidents (36), and exact M3 lifecycle status breakdown")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 3: {e}")

    # TEST 4: GET /events/trend?range=24h validates real 24h telemetry window without synthetic padding
    total += 1
    try:
        t24 = get("/events/trend?range=24h")
        assert t24["range"] == "24h"
        tw = t24["telemetry_window"]
        assert tw["hours_covered"] == 24.0, f"Expected 24.0 hours, got {tw['hours_covered']}"
        assert len(t24["trend"]) == 25, f"Expected 25 hourly buckets across boundary, got {len(t24['trend'])}"
        sample = t24["trend"][0]
        assert "avg_risk_score" in sample, "Missing avg_risk_score in trend"
        assert "max_risk_score" in sample, "Missing max_risk_score in trend"
        assert 0 <= sample["avg_risk_score"] <= 100, f"Invalid avg_risk_score: {sample['avg_risk_score']}"
        print(f"[PASS] Test 4: GET /events/trend?range=24h returns 25 buckets over exactly 24.0h with authoritative M3 risk scores (sample avg: {sample['avg_risk_score']})")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 4: {e}")

    # TEST 5: GET /events/trend?range=7d validates honest telemetry window (6.25 days covered)
    total += 1
    try:
        t7 = get("/events/trend?range=7d")
        assert t7["range"] == "7d"
        tw = t7["telemetry_window"]
        assert tw["days_covered"] == 6.25, f"Expected 6.25 days, got {tw['days_covered']}"
        assert tw["is_partial"] is True, "Expected is_partial=True since dataset is 6.25 days"
        assert len(t7["trend"]) == 150, f"Expected 150 hourly buckets, got {len(t7['trend'])}"
        sample = t7["trend"][0]
        assert "avg_risk_score" in sample
        assert 0 <= sample["avg_risk_score"] <= 100
        print(f"[PASS] Test 5: GET /events/trend?range=7d returns honest 6.25-day metadata (150 buckets) without fabricating nonexistent days")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 5: {e}")

    # TEST 6: GET /events/trend?range=30d validates zero fabrication for 30d window
    total += 1
    try:
        t30 = get("/events/trend?range=30d")
        assert t30["range"] == "30d"
        tw = t30["telemetry_window"]
        assert tw["days_covered"] == 6.25, f"Expected 6.25 days, got {tw['days_covered']}"
        assert tw["is_partial"] is True, "Expected is_partial=True"
        assert len(t30["trend"]) == 150, f"Expected 150 real buckets, got {len(t30['trend'])}"
        print(f"[PASS] Test 6: GET /events/trend?range=30d returns only real available telemetry without synthetic zero-filling")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 6: {e}")

    print("==================================================")
    print(f"VERIFICATION RESULT: {passed}/{total} tests passed")
    print("==================================================")
    if passed == total:
        print("ALL TASK 2 BACKEND CONTRACT TESTS PASSED!")
        return 0
    else:
        print("SOME CONTRACT TESTS FAILED!")
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())
