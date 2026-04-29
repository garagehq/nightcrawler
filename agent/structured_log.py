"""Structured plaintext agent log.

Writes clean, ANSI-free log lines to a file for easy debugging.
Format: YYYY-MM-DD HH:MM:SS [LEVEL] message

Usage:
    from agent import structured_log
    structured_log.init()
    structured_log.log("CMD", "nmap -sS -T2 -p 22 192.168.1.84")
"""

import datetime
import os

_file = None
_path = None

LEVELS = {"CMD", "RESULT", "ERROR", "THOUGHT", "WARNING", "RESET", "INIT", "SYSTEM"}


def init(path="/tmp/nc-agent-structured.log"):
    """Open the log file in append mode. Safe to call multiple times."""
    global _file, _path
    try:
        if _file is not None:
            return  # already initialized
        _path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _file = open(path, "a", encoding="utf-8")
    except Exception:
        _file = None


def log(level, message):
    """Write a single timestamped log line and flush immediately."""
    global _file
    if _file is None:
        return
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Collapse multi-line messages to single line for grep-ability
        clean = message.replace("\n", " | ").replace("\r", "")
        _file.write(f"{ts} [{level}] {clean}\n")
        _file.flush()
    except Exception:
        # Never crash the agent over logging
        try:
            _file.close()
        except Exception:
            pass
        _file = None
