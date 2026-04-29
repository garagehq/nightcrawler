"""Tests for agent control state integration."""

import pytest
from agent import db


class TestAgentControlState:
    """Test that C2 control state works correctly for the agent loop."""

    def test_starred_hosts_decrement(self, tmp_db):
        """Starred hosts should have remaining counter that decrements."""
        starred = [
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.2", "remaining": 3},
            {"mac": "11:22:33:44:55:66", "ip": "192.168.1.5", "remaining": 1},
        ]
        db.set_state("starred_hosts", starred)

        # Simulate agent iteration: decrement remaining
        current = db.get_state("starred_hosts", [])
        updated = []
        for s in current:
            s["remaining"] -= 1
            if s["remaining"] > 0:
                updated.append(s)
        db.set_state("starred_hosts", updated)

        result = db.get_state("starred_hosts", [])
        assert len(result) == 1  # second one expired
        assert result[0]["remaining"] == 2

    def test_forced_phase_cleared_after_read(self, tmp_db):
        """Forced phase should be consumed (set to None) after being read."""
        db.set_state("forced_phase", "recon")
        phase = db.get_state("forced_phase")
        assert phase == "recon"

        # Agent would clear it after processing
        db.set_state("forced_phase", None)
        assert db.get_state("forced_phase") is None

    def test_command_queue_fifo_pop(self, tmp_db):
        """Command queue should behave as FIFO."""
        db.set_state("command_queue", [
            "nmap -sV 192.168.1.2",
            "curl http://192.168.1.2/",
            "smbclient -N -L //192.168.1.2/",
        ])

        queue = db.get_state("command_queue", [])
        cmd = queue.pop(0)
        db.set_state("command_queue", queue)

        assert cmd == "nmap -sV 192.168.1.2"
        assert len(db.get_state("command_queue")) == 2

    def test_tool_preferences_in_prompt(self, tmp_db):
        """Tool preferences should be translatable to prompt text."""
        prefs = {"disabled": ["nikto", "sqlmap"], "preferred": ["nmap", "curl"]}
        db.set_state("tool_preferences", prefs)

        loaded = db.get_state("tool_preferences", {})
        disabled = loaded.get("disabled", [])
        preferred = loaded.get("preferred", [])

        # Build prompt fragment (what the agent loop would do)
        prompt = ""
        if disabled:
            prompt += f"AVOID: {', '.join(disabled)}. "
        if preferred:
            prompt += f"PREFER: {', '.join(preferred)}."

        assert "nikto" in prompt
        assert "nmap" in prompt

    def test_agent_config_override(self, tmp_db):
        """Agent config should override defaults."""
        db.set_state("agent_config", {"temperature": 0.3, "max_tokens": 250})
        config = db.get_state("agent_config", {})
        assert config["temperature"] == 0.3
        assert config["max_tokens"] == 250

    def test_host_notes_persist(self, tmp_db):
        """Host notes should persist across reads."""
        notes = {"DC:A6:32:5C:8D:5F": "Pi-hole DNS sinkhole, Samba shares exposed"}
        db.set_state("host_notes", notes)

        loaded = db.get_state("host_notes", {})
        assert "Pi-hole" in loaded["DC:A6:32:5C:8D:5F"]


class TestNetworkIdentity:
    """Test network identity generation."""

    def test_network_id_from_gateway_mac(self):
        """network_id should be deterministic from gateway MAC."""
        import hashlib
        mac = "AA:BB:CC:DD:EE:FF"
        nid = hashlib.sha256(mac.encode()).hexdigest()[:12]
        assert len(nid) == 12
        # Same MAC = same ID
        nid2 = hashlib.sha256(mac.encode()).hexdigest()[:12]
        assert nid == nid2

    def test_different_macs_different_ids(self):
        """Different gateway MACs must produce different network_ids."""
        import hashlib
        id1 = hashlib.sha256("AA:BB:CC:DD:EE:01".encode()).hexdigest()[:12]
        id2 = hashlib.sha256("AA:BB:CC:DD:EE:02".encode()).hexdigest()[:12]
        assert id1 != id2

    def test_network_with_full_metadata(self, tmp_db):
        """Network should store all metadata."""
        db.upsert_network(
            network_id="test_meta_123",
            cidr="10.0.0.0/24",
            gateway_mac="AA:BB:CC:DD:EE:FF",
            ssid="OfficeWiFi",
            public_ip="203.0.113.50",
            gateway="10.0.0.1",
        )
        nets = db.get_networks()
        n = next(net for net in nets if net["network_id"] == "test_meta_123")
        assert n["gateway_mac"] == "AA:BB:CC:DD:EE:FF"
        assert n["ssid"] == "OfficeWiFi"
        assert n["public_ip"] == "203.0.113.50"
