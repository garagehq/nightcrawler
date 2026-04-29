#!/usr/bin/env python3
"""API tests for Offline Mode — WiFi attack pipeline.

Tests the full simulation pipeline: scan → select → capture → crack → connect.
Uses simulation mode (NC_OFFLINE_SIM) to avoid actual WiFi operations.

Run: python3 tests/test_offline_api.py
"""

import json
import time
import requests
import urllib3
urllib3.disable_warnings()

BASE = "https://127.0.0.1:8888"
RESULTS = {"passed": 0, "failed": 0, "errors": []}


def test(name, condition, detail=""):
    if condition:
        RESULTS["passed"] += 1
        print(f"  PASS: {name}")
    else:
        RESULTS["failed"] += 1
        RESULTS["errors"].append(f"{name}: {detail}")
        print(f"  FAIL: {name} — {detail}")


def get(path):
    return requests.get(f"{BASE}{path}", verify=False, timeout=10).json()


def post(path, data=None):
    return requests.post(f"{BASE}{path}", json=data or {}, verify=False, timeout=10).json()


def run_tests():
    print("\n=== Offline Mode API Tests ===\n")

    # --- Setup: enable simulation + reset state ---
    print("--- Setup ---")
    r = post("/api/offline/simulate", {"enabled": True})
    test("Enable simulation mode", r.get("ok") and r.get("simulate"))

    # Force clean online state first
    post("/api/offline/force", {"mode": "online"})
    # Clear leftover state by forcing offline then online
    post("/api/offline/force", {"mode": "offline"})
    post("/api/offline/force", {"mode": "online"})

    # --- Test initial state (should be ONLINE) ---
    print("\n--- Initial State ---")
    state = get("/api/offline/state")
    test("Initial stage is ONLINE (5)", state["stage"] == 5)
    test("Initial stage_name is ONLINE", state["stage_name"] == "ONLINE")
    test("No target set", state["target_bssid"] == "")
    test("No password", state["password"] == "")
    test("WiFi feed exists", "wifi_feed" in state)

    # --- Force offline ---
    print("\n--- Force Offline ---")
    r = post("/api/offline/force", {"mode": "offline"})
    test("Force offline OK", r.get("ok"))
    state = get("/api/offline/state")
    test("Stage is SCANNING (0)", state["stage"] == 0)

    # --- Start scan ---
    print("\n--- Scan ---")
    r = post("/api/offline/scan/start")
    test("Scan start OK", r.get("ok"))
    test("Networks found", r.get("networks", 0) > 0)

    networks = get("/api/offline/networks")
    test("Networks list not empty", len(networks) > 0)
    test("Networks have BSSID", all("bssid" in n for n in networks))
    test("Networks have SSID", all("ssid" in n for n in networks))
    test("Networks have signal", all("signal" in n for n in networks))
    test("Networks have encryption", all("encryption" in n for n in networks))
    test("Networks sorted by signal (strongest first)", networks[0]["signal"] >= networks[-1]["signal"])

    # Check specific simulated networks
    ssids = [n["ssid"] for n in networks]
    test("HomeNetwork in scan results", "HomeNetwork" in ssids)
    test("Hidden network present", "(hidden)" in ssids)
    test("Open network present", any(n["encryption"] == "OPN" for n in networks))
    test("WPA3 network present", any(n["encryption"] == "WPA3" for n in networks))

    # --- Stop scan ---
    print("\n--- Stop Scan ---")
    r = post("/api/offline/scan/stop")
    test("Stop scan OK", r.get("ok"))

    # --- Select target (without ROE) ---
    print("\n--- Target Selection ---")
    r = post("/api/offline/target", {"bssid": "AA:BB:CC:DD:EE:01", "confirm_roe": False})
    test("Rejects without ROE confirmation", "error" in r)

    # Select with ROE
    r = post("/api/offline/target", {"bssid": "AA:BB:CC:DD:EE:01", "confirm_roe": True})
    test("Select target OK", r.get("ok"))
    test("Target info returned", r.get("target", {}).get("ssid") == "HomeNetwork")

    state = get("/api/offline/state")
    test("Target BSSID set", state["target_bssid"] == "AA:BB:CC:DD:EE:01")
    test("Target SSID set", state["target_ssid"] == "HomeNetwork")
    test("Target channel set", state["target_channel"] == 6)

    # --- Select nonexistent target ---
    r = post("/api/offline/target", {"bssid": "XX:XX:XX:XX:XX:XX", "confirm_roe": True})
    test("Rejects unknown BSSID", "error" in r)

    # --- Capture ---
    print("\n--- Handshake Capture ---")
    r = post("/api/offline/capture/start")
    test("Capture start OK", r.get("ok"))

    # Wait for simulated capture
    time.sleep(12)

    state = get("/api/offline/state")
    test("Handshake captured", state["handshake_captured"])
    test("Capture file exists", state["capture_file"] != "")
    test("Deauth count > 0", state["deauth_count"] > 0)

    # --- Handshakes list ---
    hs = get("/api/offline/handshakes")
    test("Handshake in list", len(hs) > 0)
    test("Handshake has BSSID", hs[0].get("bssid") == "AA:BB:CC:DD:EE:01")
    test("Handshake has SSID", hs[0].get("ssid") == "HomeNetwork")
    test("Handshake not yet cracked", not hs[0].get("cracked"))

    # --- Crack ---
    print("\n--- Cracking ---")
    r = post("/api/offline/crack/start")
    test("Crack start OK", r.get("ok"))

    # Wait for simulated crack
    time.sleep(15)

    status = get("/api/offline/crack/status")
    test("Crack progress 100%", status["progress"] == 100)
    test("Password found", status["password"] == "password123")
    test("Speed reported", status["speed"] != "")
    test("Wordlist reported", "rockyou" in status["wordlist"].lower())

    state = get("/api/offline/state")
    test("Password in state", state["password"] == "password123")

    # Verify handshake updated
    hs = get("/api/offline/handshakes")
    test("Handshake marked cracked", hs[0].get("cracked"))

    # --- Connect ---
    print("\n--- Connect ---")
    r = post("/api/offline/connect")
    test("Connect OK", r.get("ok"))
    test("IP returned", r.get("ip") == "192.168.0.184")

    state = get("/api/offline/state")
    test("Stage is ONLINE (5)", state["stage"] == 5)
    test("Stage name is ONLINE", state["stage_name"] == "ONLINE")

    # --- WiFi feed ---
    print("\n--- WiFi Feed ---")
    state = get("/api/offline/state")
    feed = state.get("wifi_feed", [])
    test("Feed has entries", len(feed) > 0)
    types = [e["type"] for e in feed]
    test("Feed has scan events", "scan" in types)
    test("Feed has target events", "target" in types)
    test("Feed has capture events", "capture" in types)
    test("Feed has deauth events", "deauth" in types)
    test("Feed has crack events", "crack" in types)
    test("Feed has connect events", "connect" in types)

    # --- Force back to online and verify online state ---
    print("\n--- Online Transition Verification ---")
    r = post("/api/offline/force", {"mode": "online"})
    test("Force online OK", r.get("ok"))

    # Verify online API still works
    online_state = get("/api/state")
    test("Online /api/state still works", "phase" in online_state)
    test("Phase is present", online_state["phase"] != "")

    # --- Re-enter offline and verify clean state ---
    print("\n--- Re-enter Offline ---")
    r = post("/api/offline/force", {"mode": "offline"})
    state = get("/api/offline/state")
    test("Clean re-entry: stage 0", state["stage"] == 0)
    test("Clean re-entry: no target", state["target_bssid"] == "")
    test("Clean re-entry: no password", state["password"] == "")

    # Restore to online for clean exit
    post("/api/offline/force", {"mode": "online"})
    post("/api/offline/simulate", {"enabled": False})

    # --- Summary ---
    print(f"\n{'='*50}")
    total = RESULTS["passed"] + RESULTS["failed"]
    print(f"Results: {RESULTS['passed']}/{total} passed, {RESULTS['failed']} failed")
    if RESULTS["errors"]:
        print("\nFailures:")
        for e in RESULTS["errors"]:
            print(f"  - {e}")
    print()
    return RESULTS["failed"] == 0


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
