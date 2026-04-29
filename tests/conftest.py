"""Shared fixtures for Nightcrawler tests."""

import os
import sys
import tempfile
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary SQLite database."""
    from agent import db
    db_dir = str(tmp_path / "logs")
    db.init_db(db_dir)
    yield db_dir
    # Reset global state
    db.DB_PATH = None
    db._local = type(db._local)()


@pytest.fixture
def populated_db(tmp_db):
    """DB with sample data for testing."""
    from agent import db

    # Add a network
    db.upsert_network(
        network_id="abc123def456",
        cidr="192.168.1.0/24",
        gateway_mac="AA:BB:CC:DD:EE:FF",
        ssid="TestNetwork",
        public_ip="203.0.113.1",
        gateway="192.168.1.1",
    )

    # Add hosts
    db.upsert_host(
        ip="192.168.1.2", ports=[22, 80, 443], mac="DC:A6:32:5C:8D:5F",
        hostname="pihole", network_id="abc123def456",
        info="22/ssh, 80/http, 443/https",
    )
    db.upsert_host(
        ip="192.168.1.13", ports=[], mac="90:A8:22:17:6C:61",
        hostname="", network_id="abc123def456",
        info="MAC:90:A8:22:17:6C:61 (Amazon)",
    )
    db.upsert_host(
        ip="192.168.1.25", ports=[8888], mac="1C:93:C4:1D:65:5F",
        hostname="", network_id="abc123def456",
        info="8888/tcpwrapped",
    )

    # Add timeline
    db.add_timeline(
        reasoning="Ping sweep", command="nmap -sn 192.168.1.0/24",
        status="success", output_preview="3 hosts up",
        network_id="abc123def456",
    )
    db.add_timeline(
        reasoning="Port scan", command="nmap -sS -T2 --top-ports 100 192.168.1.2",
        status="success", output_preview="22/tcp open ssh",
        network_id="abc123def456",
    )

    yield tmp_db


@pytest.fixture
def test_client(populated_db):
    """Flask test client with populated DB."""
    from webui.server import app
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
