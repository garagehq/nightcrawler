"""Tests for SQLite database operations."""

import pytest
from agent import db


class TestNetworkDiscrimination:
    """Two networks with same CIDR but different gateway MACs must be separate."""

    def test_different_gateway_macs_different_ids(self, tmp_db):
        """Same CIDR, different routers = different network_ids."""
        db.upsert_network(
            network_id="net_office_a",
            cidr="192.168.1.0/24",
            gateway_mac="AA:BB:CC:DD:EE:01",
            ssid="OfficeA",
        )
        db.upsert_network(
            network_id="net_office_b",
            cidr="192.168.1.0/24",
            gateway_mac="AA:BB:CC:DD:EE:02",
            ssid="OfficeB",
        )
        nets = db.get_networks()
        net_ids = {n["network_id"] for n in nets}
        assert "net_office_a" in net_ids
        assert "net_office_b" in net_ids

    def test_hosts_scoped_by_network_id(self, tmp_db):
        """Same IP on two networks should be two separate hosts."""
        db.upsert_network(network_id="net_a", cidr="192.168.1.0/24")
        db.upsert_network(network_id="net_b", cidr="192.168.1.0/24")

        db.upsert_host(ip="192.168.1.2", ports=[22], mac="AA:AA:AA:AA:AA:01",
                       network_id="net_a")
        db.upsert_host(ip="192.168.1.2", ports=[80], mac="BB:BB:BB:BB:BB:01",
                       network_id="net_b")

        all_hosts = db.get_hosts()
        assert len(all_hosts) == 2

        net_a_hosts = db.get_hosts(network_id="net_a")
        assert len(net_a_hosts) == 1
        assert 22 in net_a_hosts[0]["ports"]

        net_b_hosts = db.get_hosts(network_id="net_b")
        assert len(net_b_hosts) == 1
        assert 80 in net_b_hosts[0]["ports"]

    def test_findings_scoped_by_network(self, tmp_db):
        """get_findings_summary filters by network_id."""
        db.upsert_network(network_id="net_a", cidr="192.168.1.0/24")
        db.upsert_network(network_id="net_b", cidr="192.168.1.0/24")

        db.upsert_host(ip="192.168.1.2", ports=[22, 80], mac="AA:01:01:01:01:01",
                       network_id="net_a")
        db.upsert_host(ip="192.168.1.5", ports=[443], mac="BB:01:01:01:01:01",
                       network_id="net_b")

        summary_a = db.get_findings_summary(network_id="net_a")
        assert summary_a["live_hosts"] == 1
        assert summary_a["open_ports"] == 2

        summary_b = db.get_findings_summary(network_id="net_b")
        assert summary_b["live_hosts"] == 1
        assert summary_b["open_ports"] == 1


class TestHostOperations:
    """Test MAC-keyed host upsert and merge."""

    def test_upsert_merges_ports(self, tmp_db):
        db.upsert_host(ip="192.168.1.2", ports=[22, 80], mac="AA:BB:CC:DD:EE:FF")
        db.upsert_host(ip="192.168.1.2", ports=[443, 22], mac="AA:BB:CC:DD:EE:FF")
        hosts = db.get_hosts()
        assert len(hosts) == 1
        assert set(hosts[0]["ports"]) == {22, 80, 443}

    def test_mac_extracted_from_info(self, tmp_db):
        db.upsert_host(ip="192.168.1.2", ports=[22],
                       info="MAC:DC:A6:32:5C:8D:5F (Raspberry Pi)")
        hosts = db.get_hosts()
        assert hosts[0]["mac"] == "DC:A6:32:5C:8D:5F"

    def test_host_history(self, tmp_db):
        db.add_timeline(command="nmap -sS 192.168.1.2", status="success",
                        output_preview="22/tcp open")
        db.add_timeline(command="curl http://192.168.1.2/", status="success",
                        output_preview="HTTP 200")
        db.add_timeline(command="nmap 192.168.1.99", status="success")

        history = db.get_host_history("192.168.1.2")
        assert len(history) == 2  # only commands mentioning .2


class TestControlState:
    """Test C2 control state via get_state/set_state."""

    def test_starred_hosts(self, tmp_db):
        db.set_state("starred_hosts", [
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.2", "remaining": 5}
        ])
        starred = db.get_state("starred_hosts", [])
        assert len(starred) == 1
        assert starred[0]["remaining"] == 5

    def test_pause_resume(self, tmp_db):
        assert db.get_state("paused", False) is False
        db.set_state("paused", True)
        assert db.get_state("paused", False) is True
        db.set_state("paused", False)
        assert db.get_state("paused", False) is False

    def test_command_queue_fifo(self, tmp_db):
        db.set_state("command_queue", ["cmd1", "cmd2", "cmd3"])
        queue = db.get_state("command_queue", [])
        first = queue.pop(0)
        db.set_state("command_queue", queue)
        assert first == "cmd1"
        assert db.get_state("command_queue") == ["cmd2", "cmd3"]

    def test_kill_switch(self, tmp_db):
        assert db.get_state("kill_switch", False) is False
        db.set_state("kill_switch", True)
        assert db.get_state("kill_switch", False) is True

    def test_tool_preferences(self, tmp_db):
        prefs = {"disabled": ["nikto"], "preferred": ["nmap", "curl"]}
        db.set_state("tool_preferences", prefs)
        loaded = db.get_state("tool_preferences", {})
        assert "nikto" in loaded["disabled"]
        assert "nmap" in loaded["preferred"]


class TestExport:
    """Test Thor export functionality."""

    def test_export_network(self, populated_db):
        export = db.export_network("abc123def456")
        assert export["network"] == "abc123def456"
        assert export["findings"]["live_hosts"] == 3
        assert len(export["timeline"]) == 2

    def test_export_all(self, populated_db):
        export = db.export_network(None)
        assert export["network"] == "all"
        assert export["findings"]["live_hosts"] >= 3


class TestCommandSearch:
    """Test command history search."""

    def test_search_by_tool(self, populated_db):
        results = db.get_commands_search("nmap", limit=10)
        assert len(results) >= 1
        assert all("nmap" in r.get("command", "") or "nmap" in r.get("reasoning", "")
                    for r in results)

    def test_search_empty(self, populated_db):
        results = db.get_commands_search("nonexistent_tool_xyz", limit=10)
        assert len(results) == 0


class TestHostMemory:
    """Test host memory system."""

    def test_add_observation(self, tmp_db):
        from agent.host_memory import add_observation, get_memory
        add_observation("AA:BB:CC:DD:EE:FF", "Pi-hole detected", source="agent", ip="192.168.1.2")
        mem = get_memory("AA:BB:CC:DD:EE:FF")
        assert len(mem["observations"]) == 1
        assert "Pi-hole" in mem["observations"][0]["text"]

    def test_auto_extract(self, tmp_db):
        from agent.host_memory import auto_extract_observations, get_memory
        db.upsert_host(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:FF")
        auto_extract_observations(
            "192.168.1.2", "AA:BB:CC:DD:EE:FF",
            "curl -s -I http://192.168.1.2/",
            "HTTP/1.1 403 Forbidden\nServer: lighttpd/1.4.53\n",
            "success"
        )
        mem = get_memory("AA:BB:CC:DD:EE:FF")
        assert len(mem["observations"]) >= 1
        assert any("lighttpd" in o["text"] for o in mem["observations"])

    def test_build_prompt_context(self, tmp_db):
        from agent.host_memory import add_observation, build_prompt_context
        add_observation("AA:BB:CC:DD:EE:FF", "Test observation", ip="192.168.1.2")
        ctx = build_prompt_context(max_tokens=200)
        assert "HOST MEMORY" in ctx
        assert "192.168.1.2" in ctx

    def test_export(self, tmp_db):
        from agent.host_memory import add_observation, export_memories
        add_observation("AA:BB:CC:DD:EE:FF", "Test", ip="192.168.1.2")
        export = export_memories()
        assert "host_memories" in export
        assert "AA:BB:CC:DD:EE:FF" in export["host_memories"]
