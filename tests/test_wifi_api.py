"""API tests for /api/wifi/* — one-tap connect endpoints, in simulation mode.

Uses the shared `test_client` fixture (Flask test client + temp DB) from
conftest.py. No SSH or real radio is touched.

Run: python3 -m pytest tests/test_wifi_api.py -q
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import wifi_connect


@pytest.fixture(autouse=True)
def sim(monkeypatch):
    monkeypatch.setattr(wifi_connect, "SIMULATE", True)
    yield


def test_scan_endpoint_lists_networks(test_client):
    r = test_client.get("/api/wifi/scan")
    assert r.status_code == 200
    nets = r.get_json()["networks"]
    cs = next(n for n in nets if n["ssid"] == "CoffeeShop")
    assert cs["open"] and cs["joinable"]
    home = next(n for n in nets if n["ssid"] == "HomeNet")
    assert not home["joinable"]  # locked + not saved


def test_connect_open_ok(test_client):
    r = test_client.post("/api/wifi/connect", json={"ssid": "CoffeeShop"})
    assert r.get_json().get("ok")


def test_connect_locked_unsaved_refused(test_client):
    r = test_client.post("/api/wifi/connect", json={"ssid": "Neighbor5G"})
    body = r.get_json()
    assert "error" in body and "ok" not in body


def test_saved_add_then_joinable_and_psk_never_leaks(test_client):
    add = test_client.post(
        "/api/wifi/saved",
        json={"ssid": "HomeNet", "psk": "s3cret", "hidden": True})
    assert add.get_json().get("ok")

    saved = test_client.get("/api/wifi/saved").get_json()["saved"]
    entry = next(n for n in saved if n["ssid"] == "HomeNet")
    assert "psk" not in entry            # password never returned by the API
    assert entry["hidden"] is True

    r = test_client.post("/api/wifi/connect", json={"ssid": "HomeNet"})
    assert r.get_json().get("ok")        # now joinable via saved credential


def test_saved_remove(test_client):
    test_client.post("/api/wifi/saved", json={"ssid": "HomeNet", "psk": "x"})
    test_client.post("/api/wifi/saved", json={"action": "remove", "ssid": "HomeNet"})
    saved = test_client.get("/api/wifi/saved").get_json()["saved"]
    assert all(n["ssid"] != "HomeNet" for n in saved)


def test_status_endpoint(test_client):
    r = test_client.get("/api/wifi/status")
    assert r.status_code == 200
    assert "connected" in r.get_json()
