#!/usr/bin/env python3
"""Unit tests for CVE-aware vulnerability dedup in agent/db.py.

Uses a throwaway temp DB dir — never the production DB. Regression test for
"repeat CVEs being reported": output_parser emits "CVE: X" and host_memory
emits "CVE found: X" for the same finding; the old first-40-char dedup stored
both. add_vulnerability must now dedup on the CVE id per host regardless of
surrounding phrasing.
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent import db  # noqa: E402


def run():
    tmp = tempfile.mkdtemp(prefix="nc_vulndedup_")
    db.init_db(tmp)
    failures = []
    h = "10.255.255.1"

    # Same CVE, three different phrasings from the real code paths -> 1 row.
    r1 = db.add_vulnerability(h, "ssh", "CVE: CVE-9999-0001", "medium")
    r2 = db.add_vulnerability(h, "ssh", "CVE found: CVE-9999-0001", "medium")
    r3 = db.add_vulnerability(h, "nse", "VULNERABLE: CVE-9999-0001 regreSSHion", "critical")
    # lowercase variant still matches
    r4 = db.add_vulnerability(h, "ssh", "cve-9999-0001 seen again", "low")
    # Distinct CVE -> inserts.
    r5 = db.add_vulnerability(h, "ssh", "CVE: CVE-9999-0002", "medium")
    # Same CVE on a DIFFERENT host -> inserts (legit: affects multiple hosts).
    r6 = db.add_vulnerability("10.255.255.2", "ssh", "CVE found: CVE-9999-0001", "medium")
    # Non-CVE finding -> unaffected by CVE logic.
    r7 = db.add_vulnerability(h, "http", "[MISCONFIG] server-status exposed", "low")

    returns = (r1, r2, r3, r4, r5, r6, r7)
    expected = (True, False, False, False, True, True, True)
    if returns != expected:
        failures.append(f"returns {returns}, expected {expected}")

    con = sqlite3.connect(os.path.join(tmp, "nightcrawler.db"))
    n_h1 = con.execute("SELECT COUNT(*) FROM vulnerabilities WHERE host=?", (h,)).fetchone()[0]
    # host h: CVE-9999-0001 (1) + CVE-9999-0002 (1) + misconfig (1) = 3
    if n_h1 != 3:
        failures.append(f"host {h} has {n_h1} rows, expected 3")
    n_cve1 = con.execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE host=? AND upper(vuln) LIKE '%CVE-9999-0001%'",
        (h,)).fetchone()[0]
    if n_cve1 != 1:
        failures.append(f"CVE-9999-0001 on {h} stored {n_cve1}x, expected 1")

    if failures:
        print("FAIL:")
        for f in failures:
            print("  x", f)
        return 1
    print("PASS: CVE-aware vuln dedup (7 cases)")
    return 0


if __name__ == "__main__":
    sys.exit(run())
