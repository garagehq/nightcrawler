"""Tests for web API endpoints."""

import json
import pytest


class TestCoreAPI:
    """Test existing core endpoints."""

    def test_state_endpoint(self, test_client):
        resp = test_client.get("/api/state")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "findings" in data
        assert "hosts" in data or "feed" in data

    def test_findings_endpoint(self, test_client):
        resp = test_client.get("/api/findings")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "live_hosts" in data

    def test_networks_endpoint(self, test_client):
        resp = test_client.get("/api/networks")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_timeline_endpoint(self, test_client):
        resp = test_client.get("/api/timeline")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_host_history(self, test_client):
        resp = test_client.get("/api/host/192.168.1.2/history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_export_all(self, test_client):
        resp = test_client.get("/api/export")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "findings" in data


class TestStarHosts:
    """Test host starring/prioritization."""

    def test_star_host(self, test_client):
        resp = test_client.post("/api/hosts/star",
                                json={"mac": "DC:A6:32:5C:8D:5F", "iterations": 5})
        assert resp.status_code == 200

    def test_get_starred(self, test_client):
        # Star first
        test_client.post("/api/hosts/star",
                         json={"mac": "DC:A6:32:5C:8D:5F", "iterations": 3})
        resp = test_client.get("/api/hosts/starred")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert any(s["mac"] == "DC:A6:32:5C:8D:5F" for s in data)

    def test_unstar_host(self, test_client):
        test_client.post("/api/hosts/star",
                         json={"mac": "DC:A6:32:5C:8D:5F", "iterations": 5})
        resp = test_client.delete("/api/hosts/star",
                                  json={"mac": "DC:A6:32:5C:8D:5F"})
        assert resp.status_code == 200


class TestPhaseControl:
    """Test force phase change."""

    def test_force_phase(self, test_client):
        resp = test_client.post("/api/phase", json={"phase": "recon"})
        assert resp.status_code == 200

    def test_force_invalid_phase(self, test_client):
        resp = test_client.post("/api/phase", json={"phase": "invalid_phase"})
        assert resp.status_code in [200, 400]  # depends on validation


class TestPauseResume:
    """Test agent pause/resume."""

    def test_pause(self, test_client):
        resp = test_client.post("/api/agent/pause")
        assert resp.status_code == 200

    def test_resume(self, test_client):
        resp = test_client.post("/api/agent/resume")
        assert resp.status_code == 200

    def test_pause_resume_cycle(self, test_client):
        test_client.post("/api/agent/pause")
        resp = test_client.get("/api/state")
        # State should indicate paused somehow

        test_client.post("/api/agent/resume")


class TestCommandQueue:
    """Test manual command injection."""

    def test_queue_command(self, test_client):
        resp = test_client.post("/api/commands/queue",
                                json={"command": "nmap -sV 192.168.1.2"})
        assert resp.status_code == 200

    def test_get_queue(self, test_client):
        test_client.post("/api/commands/queue",
                         json={"command": "nmap -sV 192.168.1.2"})
        test_client.post("/api/commands/queue",
                         json={"command": "curl http://192.168.1.2/"})
        resp = test_client.get("/api/commands/queue")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 2


class TestToolPreferences:
    """Test tool preference management."""

    def test_set_preferences(self, test_client):
        resp = test_client.post("/api/tools/preferences",
                                json={"disabled": ["nikto"], "preferred": ["nmap"]})
        assert resp.status_code == 200

    def test_get_preferences(self, test_client):
        test_client.post("/api/tools/preferences",
                         json={"disabled": ["nikto"], "preferred": ["nmap"]})
        resp = test_client.get("/api/tools/preferences")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "nikto" in data.get("disabled", [])


class TestHostNotes:
    """Test analyst notes on hosts."""

    def test_add_note(self, test_client):
        resp = test_client.post("/api/hosts/DC:A6:32:5C:8D:5F/notes",
                                json={"note": "This is a Pi-hole DNS server"})
        assert resp.status_code == 200

    def test_get_notes(self, test_client):
        test_client.post("/api/hosts/DC:A6:32:5C:8D:5F/notes",
                         json={"note": "Pi-hole DNS"})
        resp = test_client.get("/api/hosts/DC:A6:32:5C:8D:5F/notes")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "Pi-hole" in data.get("note", "")


class TestKillSwitch:
    """Test emergency kill switch."""

    def test_kill_switch(self, test_client):
        resp = test_client.post("/api/killswitch")
        assert resp.status_code == 200


class TestAgentConfig:
    """Test live agent config changes."""

    def test_get_config(self, test_client):
        resp = test_client.get("/api/config")
        assert resp.status_code == 200

    def test_patch_config(self, test_client):
        resp = test_client.patch("/api/config",
                                 json={"temperature": 0.3, "max_tokens": 250})
        assert resp.status_code == 200


class TestCommandSearch:
    """Test command history search."""

    def test_search(self, test_client):
        resp = test_client.get("/api/commands/search?q=nmap")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_search_empty(self, test_client):
        resp = test_client.get("/api/commands/search?q=nonexistent_xyz")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 0
