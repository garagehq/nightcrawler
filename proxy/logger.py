"""Command audit logging — SQLite backed with JSONL compat."""

import json
import time
import os

from agent import db


class AuditLogger:
    """Logs every command (allowed or blocked) to SQLite + commands.jsonl."""

    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.commands_file = os.path.join(log_dir, "commands.jsonl")
        self.timeline_file = os.path.join(log_dir, "timeline.jsonl")
        db.init_db(log_dir)

    def log_command(self, command: str, allowed: bool, reason: str,
                    result_status: str = None):
        # SQLite
        db.add_command_log(command, allowed, reason, result_status)
        # JSONL compat
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "command": command,
            "allowed": allowed,
            "reason": reason,
            "result_status": result_status,
        }
        self._append(self.commands_file, entry)

    def log_event(self, event_type: str, data: dict):
        db.add_timeline_event(event_type, json.dumps(data))
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event_type,
            **data,
        }
        self._append(self.timeline_file, entry)

    def _append(self, filepath: str, entry: dict):
        try:
            with open(filepath, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except IOError:
            pass
