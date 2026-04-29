"""Destructive command blocklist."""

import re
from typing import Tuple

# Patterns that should NEVER be allowed through
BLOCKED_PATTERNS = [
    (r'\brm\s+-rf\b', "rm -rf"),
    (r'\bmkfs\b', "mkfs"),
    (r'\bdd\s+if=', "dd"),
    (r'\bshred\b', "shred"),
    (r'\breboot\b', "reboot"),
    (r'\bshutdown\b', "shutdown"),
    (r'\binit\s+[06]\b', "init 0/6"),
    (r'\biptables\s+-F\b', "iptables flush"),
    (r'\bsystemctl\s+(stop|disable)\s', "systemctl stop/disable"),
    (r'\bkill\s+-9\s+1\b', "kill init"),
    (r':\(\)\s*\{\s*:\|:\s*&\s*\}\s*;', "fork bomb"),
    (r'\bchmod\s+-R\s+777\s+/', "chmod 777 /"),
    (r'\b>\s*/dev/sd[a-z]', "write to block device"),
    (r'\bwget\b.*\|\s*sh', "pipe wget to shell"),
    (r'\bcurl\b.*\|\s*sh', "pipe curl to shell"),
]


def check_command(command: str) -> Tuple[bool, str]:
    """Returns (allowed, reason). Checks command against destructive patterns."""
    for pattern, name in BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"BLOCKED: destructive command ({name})"
    return True, "OK"
