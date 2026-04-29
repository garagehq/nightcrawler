"""Status panels and display components."""

import shutil

from ui.colors import C, BOX_H, BOX_V, BOX_TL, BOX_TR, BOX_BL, BOX_BR


def status_bar(phase: str, mode: str, uptime: str, watchdog: str,
               thor: bool, wifi: bool, commands: int, blocked: int,
               errors: int) -> str:
    """Render the two-column status bar."""
    thor_s = f"{C.GREEN}ONLINE{C.RESET}" if thor else f"{C.GRAY}OFFLINE{C.RESET}"
    wifi_s = f"{C.GREEN}UP{C.RESET}" if wifi else f"{C.RED}DOWN{C.RESET}"

    left = [
        f"  PHASE: {C.GREEN}{phase}{C.RESET}",
        f"  MODE:  {C.GREEN}{mode}{C.RESET}",
        f"  TMUX:  nightcrawler",
        f"  WATCHDOG: {C.GREEN}{watchdog}{C.RESET}",
    ]
    right = [
        f"UPTIME: {uptime}",
        f"THOR: {thor_s}    WIFI: {wifi_s}",
        f"CMDS: {commands}    BLOCKED: {blocked}",
        f"ERRS: {errors}",
    ]

    lines = []
    w = min(shutil.get_terminal_size().columns, 80)
    lines.append(f"{C.DGREEN}{'─' * w}{C.RESET}")
    for l, r in zip(left, right):
        # Raw length approximation (strip ANSI for padding)
        lines.append(f"{l}    {r}")
    lines.append(f"{C.DGREEN}{'─' * w}{C.RESET}")
    return "\n".join(lines)


def findings_bar(hosts: int, ports: int, creds: int, vulns: int,
                 progress: int = 0) -> str:
    """Bottom findings summary bar."""
    w = min(shutil.get_terminal_size().columns, 80)
    bar_w = 20
    filled = int(bar_w * progress / 100) if progress else 0
    bar = f"{C.GREEN}{'█' * filled}{C.GRAY}{'░' * (bar_w - filled)}{C.RESET}"
    return (
        f"{C.DGREEN}{'─' * w}{C.RESET}\n"
        f"  FINDINGS: {hosts} hosts  {ports} ports  "
        f"{creds} creds  {vulns} vulns  "
        f"{bar} {progress}%\n"
        f"{C.DGREEN}{'─' * w}{C.RESET}"
    )
