"""Main TUI renderer for Nightcrawler."""

import sys
import time

from ui.colors import C, BANNER
from ui.matrix import matrix_rain, hex_spinner, glitch_text
from ui.panels import status_bar, findings_bar


class TerminalUI:
    """Renders the Nightcrawler terminal interface."""

    def __init__(self):
        self.phase = "INIT"
        self.mode = "LOCAL"
        self.uptime = "00:00:00"
        self.thor_online = False
        self.wifi_up = False
        self.commands = 0
        self.blocked = 0
        self.errors = 0
        self.hosts = 0
        self.ports = 0
        self.creds = 0
        self.vulns = 0

    def render_banner(self):
        print(BANNER)
        print()

    def render_boot_sequence(self, services: list[dict]):
        """Show boot sequence with service status."""
        self.render_banner()
        for svc in services:
            name = svc["name"]
            dots = "." * (45 - len(name))
            status = svc.get("status", "OK")
            if status == "OK":
                color_status = C.OK
            elif status == "SKIP":
                color_status = C.SKIP
            elif status == "FAIL":
                color_status = C.FAIL
            else:
                color_status = f"{C.GREEN}{status}{C.RESET}"
            detail = svc.get("detail", "")
            if detail:
                detail = f"  [{detail}]"
            print(f"  {C.GRAY}[INIT]{C.RESET} {name}{dots} {color_status}{detail}")
        print()

    def render_boot_complete(self):
        print(f"  {C.GREEN}{' ' * 2}╔═══════════════════════════════════════════╗{C.RESET}")
        print(f"  {C.GREEN}{' ' * 2}║  ALL SYSTEMS GREEN                       ║{C.RESET}")
        print(f"  {C.GREEN}{' ' * 2}║  NIGHTCRAWLER ACTIVE                     ║{C.RESET}")
        print(f"  {C.GREEN}{' ' * 2}╚═══════════════════════════════════════════╝{C.RESET}")
        print()

    def render_thinking(self):
        """Brief matrix rain while LLM is thinking."""
        sys.stdout.write(f"  {C.GRAY}[THINKING]{C.RESET} ")
        sys.stdout.flush()
        matrix_rain(duration=0.5, width=40)

    def render_agent_thought(self, reasoning: str):
        ts = time.strftime("%H:%M:%S")
        print(f"  {C.GRAY}[{ts}]{C.RESET} {reasoning}")

    def render_command(self, command: str):
        ts = time.strftime("%H:%M:%S")
        print(f"  {C.GRAY}[{ts}]{C.RESET} {C.CYAN}>>>{C.RESET} {C.GREEN}{command}{C.RESET}")
        print(hex_spinner())

    def render_result(self, result: dict):
        status = result.get("status", "unknown")
        output = result.get("output", "")

        if status == "blocked":
            print(f"  {C.RED}[BLOCKED]{C.RESET} {result.get('error', '')}")
            return

        if status == "error":
            print(f"  {C.RED}[ERROR]{C.RESET} {result.get('error', '')}")
            return

        # Truncate long output for display
        lines = output.split("\n")
        if len(lines) > 20:
            for line in lines[:18]:
                print(f"  {C.GRAY}│{C.RESET} {line}")
            print(f"  {C.GRAY}│ ... ({len(lines) - 18} more lines){C.RESET}")
            print(f"  {C.GRAY}│{C.RESET} {lines[-1]}")
        else:
            for line in lines:
                print(f"  {C.GRAY}│{C.RESET} {line}")

    def render_warning(self, msg: str):
        print(f"  {C.YELLOW}[WARNING]{C.RESET} {msg}")

    def render_error(self, msg: str):
        print(f"  {C.RED}[ERROR]{C.RESET} {msg}")

    def render_phase_transition(self, new_phase: str):
        print()
        for i in range(3):
            glitched = glitch_text(f"  ENTERING PHASE: {new_phase}", intensity=5)
            sys.stdout.write(f"\r{C.GREEN}{glitched}{C.RESET}")
            sys.stdout.flush()
            time.sleep(0.15)
        print(f"\r  {C.GREEN}{'═' * 50}{C.RESET}")
        print(f"  {C.GREEN}  ENTERING PHASE: {new_phase}{C.RESET}")
        print(f"  {C.GREEN}{'═' * 50}{C.RESET}")
        print()

    def render_mission_complete(self):
        print()
        print(f"  {C.GREEN}╔═══════════════════════════════════════════╗{C.RESET}")
        print(f"  {C.GREEN}║  MISSION COMPLETE                        ║{C.RESET}")
        print(f"  {C.GREEN}╚═══════════════════════════════════════════╝{C.RESET}")

    def update_phase(self, phase: str):
        self.phase = phase

    def update_stats(self, uptime: str = None,
                     commands: int = None, blocked: int = None,
                     errors: int = None, **kwargs):
        if uptime is not None:
            self.uptime = uptime
        if commands is not None:
            self.commands = commands
        if blocked is not None:
            self.blocked = blocked
        if errors is not None:
            self.errors = errors

    def update_backend_status(self, health: dict):
        self.thor_online = health.get("thor", False)
        if self.thor_online:
            self.mode = "THOR"
        else:
            self.mode = "LOCAL"

    def render_status(self):
        """Print full status bar."""
        print(status_bar(
            phase=self.phase, mode=self.mode,
            uptime=self.uptime, watchdog="",
            thor=self.thor_online, wifi=self.wifi_up,
            commands=self.commands, blocked=self.blocked,
            errors=self.errors,
        ))
