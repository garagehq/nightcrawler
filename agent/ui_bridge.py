"""Bridge between agent and webui — writes state to SQLite.

The agent imports update_state() and push_feed() from here instead of
webui.server. This eliminates the Flask dependency from the agent process,
allowing the webui to run as a fully separate process.

Data flow:
  Agent → ui_bridge (SQLite writes) → webui daemon (SQLite reads) → browser
"""

import time
import json
from agent import db


def update_state(updates: dict):
    """Persist agent state to SQLite for the webui to read."""
    try:
        db.set_state("agent_ui_state", {
            "phase": updates.get("phase", ""),
            "mode": updates.get("mode", ""),
            "uptime": updates.get("uptime", ""),
            "commands_total": updates.get("commands_total", 0),
            "commands_blocked": updates.get("commands_blocked", 0),
            "errors": updates.get("errors", 0),
            "iteration": updates.get("iteration", 0),
            "thor_online": updates.get("thor_online", False),
            "wifi_up": updates.get("wifi_up", False),
        })
    except Exception:
        pass


def push_feed(event_type: str, content: str):
    """Append a feed entry to SQLite for the webui to read. Tagged with network."""
    # Detect current network for tagging
    _net_id = ""
    try:
        from agent.net_detect import get_current_network
        _subnet = get_current_network()[0]
        for _n in db.get_networks():
            if _n.get("cidr", "") == _subnet:
                _net_id = _n["network_id"]
                break
    except Exception:
        pass

    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "type": event_type,
        "content": content[:500],
        "network": _net_id,
    }
    try:
        feed = db.get_state("agent_feed", [])
        feed.append(entry)
        if len(feed) > 500:
            feed = feed[-500:]
        db.set_state("agent_feed", feed)
    except Exception:
        pass
