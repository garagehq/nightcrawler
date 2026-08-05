"""Unit tests for agent/wifi_connect.py — on-demand connect to open + saved
private networks, with NO cracking. Runs entirely in simulation.

Run: python3 -m pytest tests/test_wifi_connect.py -q
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import wifi_connect


@pytest.fixture(autouse=True)
def sim(tmp_db, monkeypatch):
    """Every test runs in SIM mode against a fresh temp DB."""
    monkeypatch.setattr(wifi_connect, "SIMULATE", True)
    yield


# ── open/locked classification ────────────────────────────────────────────

def test_is_open():
    assert wifi_connect._is_open("[ESS]")
    assert wifi_connect._is_open("")
    assert not wifi_connect._is_open("[WPA2-PSK-CCMP][ESS]")
    assert not wifi_connect._is_open("[WPA3-SAE][ESS]")
    assert not wifi_connect._is_open("[WEP]")


# ── scanning & joinability ─────────────────────────────────────────────────

def test_scan_lists_and_flags_joinability():
    by = {n["ssid"]: n for n in wifi_connect.scan_available()}
    # open network -> joinable with one tap
    assert by["CoffeeShop"]["open"] and by["CoffeeShop"]["joinable"]
    # locked + not saved -> shown but NOT joinable (never cracked)
    assert not by["HomeNet"]["open"]
    assert not by["HomeNet"]["joinable"]
    # third-party hidden network -> surfaced for awareness, never joinable
    assert "(hidden network)" in by
    assert by["(hidden network)"]["hidden"]
    assert not by["(hidden network)"]["joinable"]


def test_saving_password_makes_locked_network_joinable():
    assert not any(n["ssid"] == "HomeNet" and n["joinable"]
                   for n in wifi_connect.scan_available())
    wifi_connect.add_saved("HomeNet", "correcthorsebatterystaple")
    assert any(n["ssid"] == "HomeNet" and n["joinable"]
               for n in wifi_connect.scan_available())


# ── saved-network store ────────────────────────────────────────────────────

def test_add_saved_requires_a_password():
    r = wifi_connect.add_saved("MyNet", "")
    assert "error" in r  # tool never invents a password


def test_add_and_remove_saved_roundtrip():
    wifi_connect.add_saved("HomeNet", "pw", hidden=True)
    assert any(n["ssid"] == "HomeNet" and n["hidden"]
               for n in wifi_connect.list_saved())
    wifi_connect.remove_saved("HomeNet")
    assert all(n["ssid"] != "HomeNet" for n in wifi_connect.list_saved())


# ── connecting ─────────────────────────────────────────────────────────────

def test_connect_open_ok_and_flags_portal():
    r = wifi_connect.connect_to("CoffeeShop")
    assert r.get("ok")
    assert r.get("portal") is True  # SIM CoffeeShop is behind a captive portal


def test_connect_locked_unsaved_is_refused_never_cracks():
    r = wifi_connect.connect_to("Neighbor5G")
    assert "error" in r
    assert "crack" in r["error"].lower() or "saved" in r["error"].lower()


def test_connect_saved_ok():
    wifi_connect.add_saved("HomeNet", "correcthorse")
    r = wifi_connect.connect_to("HomeNet")
    assert r.get("ok")


def test_connect_hidden_placeholder_refused():
    r = wifi_connect.connect_to("(hidden network)")
    assert "error" in r


# ── captive-portal detection (detect only, never bypass) ───────────────────

def test_captive_portal_detection(monkeypatch):
    class Resp:
        def __init__(self, status):
            self.status = status

        def getcode(self):
            return self.status

    monkeypatch.setattr(wifi_connect.urllib.request, "urlopen",
                        lambda *a, **k: Resp(204))
    assert wifi_connect._captive_portal_present() is False  # clean internet

    monkeypatch.setattr(wifi_connect.urllib.request, "urlopen",
                        lambda *a, **k: Resp(200))
    assert wifi_connect._captive_portal_present() is True   # portal redirect

    def boom(*a, **k):
        raise OSError("no route")

    monkeypatch.setattr(wifi_connect.urllib.request, "urlopen", boom)
    assert wifi_connect._captive_portal_present() is True   # unreachable


# ── scan parsers ───────────────────────────────────────────────────────────

def test_parse_iw():
    sample = """BSS aa:bb:cc:dd:ee:01(on wlan0)
\tsignal: -42.00 dBm
\tSSID: CoffeeShop
BSS aa:bb:cc:dd:ee:02(on wlan0)
\tsignal: -60.00 dBm
\tSSID: HomeNet
\tRSN:\t * Version: 1
"""
    by = {n["ssid"]: n for n in wifi_connect._parse_iw(sample)}
    assert wifi_connect._is_open(by["CoffeeShop"]["security"])  # no RSN/WPA
    assert by["CoffeeShop"]["signal"] == -42
    assert not wifi_connect._is_open(by["HomeNet"]["security"])  # has RSN


def test_parse_cmd_wifi_preserves_digits_in_ssid():
    sample = (
        "BSSID              Frequency  RSSI   SSID        Flags\n"
        "aa:bb:cc:dd:ee:01  2412       -45    CoffeeShop  [ESS]\n"
        "aa:bb:cc:dd:ee:02  5180       -60    Neighbor5G  [WPA2-PSK-CCMP][ESS]\n"
    )
    by = {n["ssid"]: n for n in wifi_connect._parse_cmd_wifi(sample)}
    assert "CoffeeShop" in by and by["CoffeeShop"]["signal"] == -45
    assert wifi_connect._is_open(by["CoffeeShop"]["security"])
    # SSID with a digit survives parsing, and locked flags are detected
    assert "Neighbor5G" in by
    assert not wifi_connect._is_open(by["Neighbor5G"]["security"])
