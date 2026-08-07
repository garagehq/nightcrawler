"""Tests for the non-rooted 'lite' build primitives:
  * agent/net_detect.py  — Termux-API detection + strict/fail-loud mode
  * kali_executor.py      — mcp-kali-server-compatible /api/command endpoint

Run: python3 -m pytest tests/test_lite_mode.py -q
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import net_detect
import kali_executor


class _FakeProc:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


@pytest.fixture(autouse=True)
def clear_cache():
    net_detect._cache.clear()
    yield
    net_detect._cache.clear()


# ── net_detect: strict / fail-loud ────────────────────────────────────────

def test_strict_returns_none_when_no_source_detects(monkeypatch):
    monkeypatch.setattr(net_detect, "_detect", lambda: None)
    assert net_detect.get_current_network(strict=True) == (None, None, None, None)


def test_nonstrict_falls_back_to_legacy_subnet(monkeypatch):
    monkeypatch.setattr(net_detect, "_detect", lambda: None)
    assert net_detect.get_current_network(strict=False) == net_detect._FALLBACK


def test_nc_lite_env_makes_strict_the_default(monkeypatch):
    monkeypatch.setenv("NC_LITE", "1")
    monkeypatch.setattr(net_detect, "_detect", lambda: None)
    assert net_detect.get_current_network() == (None, None, None, None)


def test_no_lite_env_defaults_to_fallback(monkeypatch):
    monkeypatch.setenv("NC_LITE", "0")
    monkeypatch.setattr(net_detect, "_detect", lambda: None)
    assert net_detect.get_current_network() == net_detect._FALLBACK


def test_miss_is_not_cached(monkeypatch):
    """A failed detection must not be cached, so a later success is picked up."""
    monkeypatch.setattr(net_detect, "_detect", lambda: None)
    net_detect.get_current_network(strict=True)
    assert "ts" not in net_detect._cache


# ── net_detect: Termux-API path ────────────────────────────────────────────

def test_termux_wifi_connectioninfo_parses_ip_as_24(monkeypatch):
    payload = json.dumps({"ssid": "MyHome", "ip": "192.168.7.42", "bssid": "x"})

    def fake_run(cmd, **kw):
        assert cmd == ["termux-wifi-connectioninfo"]
        return _FakeProc(stdout=payload)

    monkeypatch.setattr(net_detect.subprocess, "run", fake_run)
    assert net_detect._detect_from_termux() == (
        "192.168.7.0/24", "192.168.7.", "192.168.7.42", "192.168.7.1")


def test_termux_ignores_zero_ip(monkeypatch):
    monkeypatch.setattr(net_detect.subprocess, "run",
                        lambda *a, **k: _FakeProc(stdout='{"ip": "0.0.0.0"}'))
    assert net_detect._detect_from_termux() is None


def test_ip_source_takes_priority_over_termux(monkeypatch):
    monkeypatch.setattr(net_detect, "_detect_from_ip",
                        lambda: ("10.0.0.0/24", "10.0.0.", "10.0.0.5", "10.0.0.1"))
    monkeypatch.setattr(net_detect, "_detect_from_termux",
                        lambda: ("192.168.1.0/24", "192.168.1.", "192.168.1.9", "192.168.1.1"))
    assert net_detect._detect()[2] == "10.0.0.5"


# ── net_detect: is_target_ip fail-closed ───────────────────────────────────

def test_is_target_ip_false_when_network_unconfirmed(monkeypatch):
    monkeypatch.setattr(net_detect, "get_current_network",
                        lambda *a, **k: (None, None, None, None))
    assert net_detect.is_target_ip("192.168.1.5") is False


def test_is_target_ip_matches_confirmed_subnet(monkeypatch):
    monkeypatch.setattr(net_detect, "get_current_network",
                        lambda *a, **k: ("192.168.1.0/24", "192.168.1.", "192.168.1.9", "192.168.1.1"))
    assert net_detect.is_target_ip("192.168.1.50") is True
    assert net_detect.is_target_ip("10.0.0.1") is False


# ── kali_executor: mcp-kali-server-compatible /api/command ─────────────────

@pytest.fixture
def client():
    kali_executor.app.config["TESTING"] = True
    with kali_executor.app.test_client() as c:
        yield c


def test_api_command_success_shape(client):
    r = client.post("/api/command", json={"command": "echo hello"})
    body = r.get_json()
    # exactly the fields scope_proxy.py reads (scope_proxy.py:136-148)
    assert set(body) >= {"stdout", "stderr", "return_code", "success", "timed_out"}
    assert "hello" in body["stdout"]
    assert body["success"] is True and body["return_code"] == 0
    assert body["timed_out"] is False


def test_api_command_failure_marks_success_false(client):
    r = client.post("/api/command", json={"command": "false"})
    body = r.get_json()
    assert body["success"] is False
    assert body["return_code"] != 0


def test_api_command_empty_is_400(client):
    r = client.post("/api/command", json={"command": "  "})
    assert r.status_code == 400
    assert r.get_json()["success"] is False


def test_execute_legacy_shape_still_works(client):
    r = client.post("/execute", json={"command": "echo hi"})
    body = r.get_json()
    assert set(body) >= {"status", "output", "return_code"}
    assert body["status"] == "success" and "hi" in body["output"]
