"""Phase state machine for the mission."""

import os
from enum import IntEnum


class Phase(IntEnum):
    WIFI_BREACH = 0
    RECON = 1
    ENUMERATE = 2
    EXPLOIT = 3
    CLEANUP = 4


PHASE_NAMES = {
    Phase.WIFI_BREACH: "WIFI BREACH",
    Phase.RECON: "RECON & MAP",
    Phase.ENUMERATE: "ENUMERATE",
    Phase.EXPLOIT: "EXPLOIT & PIVOT",
    Phase.CLEANUP: "CLEANUP & REPORT",
}

def _load_prompt(filename: str) -> str:
    """Load a prompt from the prompts/ directory."""
    # Try relative to nightcrawler root
    for base in [os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "/root/nightcrawler", "/opt/nightcrawler"]:
        path = os.path.join(base, "prompts", filename)
        if os.path.exists(path):
            with open(path) as f:
                return f.read().strip()
    return f"(prompt file {filename} not found)"


# Phase-specific prompt files
PHASE_PROMPT_FILES = {
    Phase.WIFI_BREACH: "phase0_wifi.md",
    Phase.RECON: "phase1_recon.md",
    Phase.ENUMERATE: "phase2_enumerate.md",
    Phase.EXPLOIT: "phase3_exploit.md",
    Phase.CLEANUP: "phase4_cleanup.md",
}


def get_phase_context(phase: Phase) -> str:
    """Load phase context from markdown file (re-reads each time for hot reload)."""
    return _load_prompt(PHASE_PROMPT_FILES[phase])


class PhasePlanner:
    """Manages phase transitions based on mission state."""

    def __init__(self, config: dict):
        # If we already have network connectivity, skip WiFi breach
        self.current_phase = Phase.WIFI_BREACH
        self.mission_complete = False
        self.phase_start_time = None
        self.config = config
        self._phase_timeouts = {
            Phase.WIFI_BREACH: 60 * 45,  # 45 min
            Phase.RECON: 60 * 30,        # 30 min
            Phase.ENUMERATE: 60 * 60,    # 60 min
            Phase.EXPLOIT: 60 * 90,      # 90 min
            Phase.CLEANUP: 60 * 15,      # 15 min
        }

    @property
    def phase_name(self) -> str:
        return PHASE_NAMES[self.current_phase]

    @property
    def phase_context(self) -> str:
        return get_phase_context(self.current_phase)

    def evaluate(self, mission_log) -> bool:
        """Check if we should transition phases. Returns True if phase changed."""
        findings = mission_log.get_findings_summary()

        if self.current_phase == Phase.WIFI_BREACH:
            if findings.get("wifi_connected"):
                return self._advance()

        elif self.current_phase == Phase.RECON:
            hosts = findings.get("live_hosts", 0)
            if hosts >= 3:
                return self._advance()

        elif self.current_phase == Phase.ENUMERATE:
            vulns = findings.get("vulnerabilities", 0)
            creds = findings.get("credentials", 0)
            hosts = findings.get("live_hosts", 0)
            ports = findings.get("open_ports", 0)
            # Advance on findings OR after sufficient enumeration:
            # 10+ hosts with 15+ ports = enough data to start exploiting
            if vulns > 0 or creds > 0 or (hosts >= 10 and ports >= 15):
                return self._advance()

        elif self.current_phase == Phase.EXPLOIT:
            if findings.get("impact_documented"):
                return self._advance()

        elif self.current_phase == Phase.CLEANUP:
            if findings.get("cleanup_done"):
                self.mission_complete = True
                return True

        return False

    def force_phase(self, phase_name: str):
        """Force transition to a specific phase (e.g., watchdog expiry)."""
        name_map = {
            "wifi": Phase.WIFI_BREACH,
            "recon": Phase.RECON,
            "enumerate": Phase.ENUMERATE,
            "exploit": Phase.EXPLOIT,
            "cleanup": Phase.CLEANUP,
        }
        if phase_name in name_map:
            self.current_phase = name_map[phase_name]

    def _advance(self) -> bool:
        if self.current_phase < Phase.CLEANUP:
            self.current_phase = Phase(self.current_phase + 1)
            return True
        return False
