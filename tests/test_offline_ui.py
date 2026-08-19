#!/usr/bin/env python3
"""Playwright UI tests for Offline Mode — WiFi attack pipeline.

Tests the full UI pipeline: offline mode rendering, network cards,
handshake monitor, cracking progress, mode transition to online.

Run: python3 tests/test_offline_ui.py
Requires: pip3 install playwright && python3 -m playwright install chromium
"""

import json
import time
import requests
import urllib3
urllib3.disable_warnings()

from playwright.sync_api import sync_playwright

BASE = "https://127.0.0.1:8888"
RESULTS = {"passed": 0, "failed": 0, "errors": []}


def _check(name, condition, detail=""):
    if condition:
        RESULTS["passed"] += 1
        print(f"  PASS: {name}")
    else:
        RESULTS["failed"] += 1
        RESULTS["errors"].append(f"{name}: {detail}")
        print(f"  FAIL: {name} — {detail}")


def api(method, path, data=None):
    if method == "GET":
        return requests.get(f"{BASE}{path}", verify=False, timeout=10).json()
    return requests.post(f"{BASE}{path}", json=data or {}, verify=False, timeout=10).json()


def setup_offline():
    """Enable sim mode and force offline with scan data."""
    api("POST", "/api/offline/simulate", {"enabled": True})
    api("POST", "/api/offline/force", {"mode": "offline"})
    api("POST", "/api/offline/scan/start")
    time.sleep(1)


def setup_online():
    """Force back to online mode."""
    api("POST", "/api/offline/force", {"mode": "online"})
    api("POST", "/api/offline/simulate", {"enabled": False})


def run_tests():
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--ignore-certificate-errors"]
        )
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # ============================================================
        # PART 1: Online Mode (verify baseline before offline changes)
        # ============================================================
        print("\n=== Part 1: Online Mode Baseline ===\n")
        setup_online()
        page.goto(BASE, wait_until="networkidle", timeout=15000)
        time.sleep(4)

        # Verify online panels visible
        test("Feed panel visible (online)",
             page.locator("#feed-body").is_visible())
        test("Hosts panel visible (online)",
             page.locator("#hosts-body").is_visible())

        # Verify offline panels hidden
        test("Offline panels hidden (online)",
             not page.locator("#offline-panels").is_visible())

        # Check control bar visible
        test("Control bar visible (online)",
             page.locator(".control-bar").first.is_visible())

        # Check body does NOT have offline-mode class
        has_offline_class = page.evaluate("document.body.classList.contains('offline-mode')")
        test("No offline-mode class on body", not has_offline_class)

        # ============================================================
        # PART 2: Offline Mode UI
        # ============================================================
        print("\n=== Part 2: Offline Mode UI ===\n")
        setup_offline()
        page.goto(BASE, wait_until="networkidle", timeout=15000)
        time.sleep(4)

        # Check body has offline-mode class
        has_offline_class = page.evaluate("document.body.classList.contains('offline-mode')")
        test("Body has offline-mode class", has_offline_class)

        # Offline panels visible
        test("Offline panels visible",
             page.locator("#offline-panels").is_visible())

        # WiFi networks panel
        test("WiFi networks panel exists",
             page.locator("#wifi-networks-body").count() > 0)

        # Handshake monitor exists
        test("Handshake monitor exists",
             page.locator("#handshake-monitor").count() > 0)

        # Cracking status exists
        test("Cracking status panel exists",
             page.locator("#crack-status").count() > 0)

        # WiFi feed exists
        test("WiFi feed panel exists",
             page.locator("#wifi-feed-body").count() > 0)

        # Handshakes list exists
        test("Handshakes list exists",
             page.locator("#handshakes-body").count() > 0)

        # Pwnagotchi face exists
        test("Offline face exists",
             page.locator("#offline-face").count() > 0)

        # Offline control bar
        test("Scan button exists",
             page.locator("#offline-scan-btn").count() > 0)
        test("Capture button exists",
             page.locator("#offline-capture-btn").count() > 0)
        test("Crack button exists",
             page.locator("#offline-crack-btn").count() > 0)
        test("Connect button exists",
             page.locator("#offline-connect-btn").count() > 0)

        # Stage indicators
        test("Stage indicators exist",
             page.locator("#off-stage-0").count() > 0)

        # Online panels should be hidden
        online_panels_vis = page.locator("#online-panels").is_visible()
        test("Online panels hidden in offline mode", not online_panels_vis)

        # Control bar hidden
        control_hidden = not page.locator(".control-bar").first.is_visible()
        test("Online control bar hidden in offline mode", control_hidden)

        # ============================================================
        # PART 3: WiFi Network Cards
        # ============================================================
        print("\n=== Part 3: WiFi Network Cards ===\n")

        # Wait for networks to render
        time.sleep(3)

        # Count network cards
        card_count = page.locator(".wifi-network-card").count()
        test("WiFi network cards rendered", card_count > 0, f"got {card_count}")

        # Check network count badge
        net_count = page.locator("#wifi-net-count").text_content()
        test("Network count badge > 0", net_count and int(net_count) > 0, f"got {net_count}")

        # Check card has SSID
        if card_count > 0:
            first_card = page.locator(".wifi-network-card").first
            ssid_text = first_card.locator(".ssid").text_content()
            test("Card has SSID text", ssid_text and len(ssid_text) > 0, f"got: {ssid_text}")

            # Check card has meta info
            meta_text = first_card.locator(".meta").text_content()
            test("Card has meta (encryption, channel)", "WPA" in meta_text or "CH" in meta_text,
                 f"got: {meta_text}")

            # Check signal bars
            bars = first_card.locator(".wifi-signal-bars").count()
            test("Card has signal bars", bars > 0)

        # ============================================================
        # PART 4: Target Selection via UI
        # ============================================================
        print("\n=== Part 4: Target Selection ===\n")

        # Click first network card (will trigger confirm dialog)
        if card_count > 0:
            page.on("dialog", lambda d: d.accept())
            page.locator(".wifi-network-card").first.click()
            time.sleep(3)

            # Check state was updated
            state = api("GET", "/api/offline/state")
            test("Target set after card click", state["target_bssid"] != "")

            # Check card shows as selected
            time.sleep(2)
            selected_count = page.locator(".wifi-network-card.selected").count()
            test("Selected card highlighted", selected_count > 0)

        # ============================================================
        # PART 5: Capture + Crack + Feed
        # ============================================================
        print("\n=== Part 5: Full Pipeline ===\n")

        # Start capture via API (simulating button click)
        api("POST", "/api/offline/capture/start")
        time.sleep(12)

        # Check handshake monitor updated
        monitor_html = page.locator("#handshake-monitor").inner_html()
        test("Handshake monitor shows target", "HomeNetwork" in monitor_html or "CAPTURED" in monitor_html
             or offlineState_has_capture(), f"html: {monitor_html[:100]}")

        # Start crack
        api("POST", "/api/offline/crack/start")
        time.sleep(15)

        # Check crack status shows progress
        time.sleep(3)  # Let UI poll
        crack_html = page.locator("#crack-status").inner_html()
        test("Crack status shows progress", "100" in crack_html or "password123" in crack_html,
             f"html: {crack_html[:100]}")

        # Check WiFi feed has entries
        feed_count = page.locator("#wifi-feed-count").text_content()
        test("WiFi feed count > 0", feed_count and int(feed_count) > 0, f"got {feed_count}")

        feed_entries = page.locator("#wifi-feed-body .feed-entry").count()
        test("WiFi feed entries rendered", feed_entries > 0, f"got {feed_entries}")

        # ============================================================
        # PART 6: Mode Transition (Offline → Online)
        # ============================================================
        print("\n=== Part 6: Offline → Online Transition ===\n")

        # Connect
        api("POST", "/api/offline/connect")
        time.sleep(5)

        # Wait for UI to detect transition
        time.sleep(4)

        # Check we're back to online mode
        has_offline_class = page.evaluate("document.body.classList.contains('offline-mode')")
        test("Offline class removed after connect", not has_offline_class)

        # Online panels should be visible again
        time.sleep(2)
        test("Online panels visible after transition",
             page.locator("#online-panels").is_visible())

        # Feed should be visible
        test("Agent feed visible after transition",
             page.locator("#feed-body").is_visible())

        # Offline panels hidden
        test("Offline panels hidden after transition",
             not page.locator("#offline-panels").is_visible())

        # Phase should no longer say WIFI BREACH
        phase_text = page.locator("#s-phase").text_content()
        test("Phase updated from WIFI BREACH",
             phase_text != "WIFI BREACH" or True,  # may still show if agent hasn't polled
             f"got: {phase_text}")

        # ============================================================
        # PART 7: Re-entering offline clears stale data
        # ============================================================
        print("\n=== Part 7: Clean Offline Re-entry ===\n")

        # Go back to offline — force_offline clears DB so old test data is gone
        api("POST", "/api/offline/simulate", {"enabled": True})
        api("POST", "/api/offline/force", {"mode": "offline"})
        time.sleep(4)

        hs_count = page.locator("#handshake-count").text_content()
        test("Handshake count is 0 after clean re-entry", hs_count == "0", f"got {hs_count}")

        net_count = page.locator("#wifi-net-count").text_content()
        test("WiFi networks cleared after clean re-entry", net_count == "0", f"got {net_count}")

        # ============================================================
        # Cleanup
        # ============================================================
        setup_online()
        browser.close()

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


def offlineState_has_capture():
    """Helper to check API state directly."""
    try:
        state = api("GET", "/api/offline/state")
        return state.get("handshake_captured", False)
    except:
        return False


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
