"""Network-wide attack planner — strategic directives for the 2B model.

Runs periodically (every ~50 commands) to analyze the state of all hosts
and generate a strategic summary. This gets injected into the system prompt
so the 2B model has "big picture" awareness it can't generate itself.

The planner answers: "Given everything we know, what should we focus on?"
"""

import re
from agent import db
from agent import host_memory


def generate_plan(max_tokens: int = 150) -> str:
    """Analyze all hosts and generate a strategic directive.

    Returns a compact string for the system prompt, or "" if nothing useful.
    """
    hosts = db.get_hosts()
    memories = host_memory.get_all_memories()

    if not hosts:
        return ""

    # Classify hosts
    untested_ssh = []      # have SSH but no cred attempts
    failed_ssh = []        # have SSH with failed creds
    open_access = []       # confirmed access (shares, admin panels)
    no_follow_through = [] # found something but didn't go deeper
    never_scanned = []     # have ports but zero observations

    for h in hosts:
        ip = h.get("ip", "")
        mac = h.get("mac", "")
        ports = set(h.get("ports", []))
        if not ports:
            continue

        mem = memories.get(mac, {})
        obs = [o["text"] for o in mem.get("observations", [])]
        failed = [o for o in obs if o.startswith("FAILED ")]
        tried = [o for o in obs if o.startswith("TRIED ")]
        access = [o for o in obs if any(w in o for w in [
            "shares accessible", "Pi-hole", "HTTP server",
            "ACCESS GAINED", "DNS resolver", "Samba version"])]
        status = mem.get("status", "unknown")

        if status == "dead-end":
            continue

        # Has SSH but no cred testing
        if 22 in ports and not any("SSH" in f for f in failed):
            untested_ssh.append(ip)

        # Has SSH with failed creds
        if any("SSH" in f for f in failed):
            failed_ssh.append(ip)

        # Confirmed access but incomplete follow-through
        if access:
            open_access.append(ip)
            share_found = any("shares accessible" in a for a in access)
            share_read = any("Interesting files" in o or "recurse" in o
                            for o in obs)
            if share_found and not share_read:
                no_follow_through.append(f"{ip} (SMB shares not read)")

            pihole = any("Pi-hole" in a for a in access)
            post_tried = any("POST" in o for o in obs)
            if pihole and not post_tried:
                no_follow_through.append(f"{ip} (Pi-hole not POST-tested)")

        # Has ports but zero observations
        if not obs and ports:
            never_scanned.append(ip)

    # Build directive
    lines = []

    if no_follow_through:
        lines.append(f"PRIORITY: Follow up on {', '.join(no_follow_through[:3])}")

    if open_access:
        lines.append(f"HIGH-VALUE: {', '.join(open_access[:3])} have confirmed access")

    if untested_ssh and len(untested_ssh) > 2:
        lines.append(f"UNTESTED SSH: {', '.join(untested_ssh[:5])} — try default creds")

    if never_scanned:
        lines.append(f"UNEXPLORED: {', '.join(never_scanned[:5])} have ports but no recon")

    cred_count = db.get_cred_count()
    vuln_count = db.get_vuln_count()
    if cred_count > 0:
        lines.append(f"CREDS FOUND: {cred_count} — try lateral movement with them")
    if vuln_count > 0:
        lines.append(f"VULNS: {vuln_count} documented — check if any are exploitable")

    if not lines:
        return ""

    plan = "ATTACK PLAN:\n  " + "\n  ".join(lines[:4])

    # Truncate to token budget
    if len(plan) > max_tokens * 4:
        plan = plan[:max_tokens * 4]

    return plan
