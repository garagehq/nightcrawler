"""ANSI color and style definitions for the Nightcrawler TUI."""


class C:
    """ANSI escape codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    BLINK = "\033[5m"

    # Greens (primary palette)
    GREEN = "\033[1;32m"
    DGREEN = "\033[38;5;22m"
    LGREEN = "\033[38;5;46m"
    MATRIX = "\033[38;5;34m"

    # Accents
    RED = "\033[1;31m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"
    GRAY = "\033[38;5;240m"
    ORANGE = "\033[38;5;208m"

    # Backgrounds
    BG_BLACK = "\033[40m"
    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"

    # Status shortcuts
    OK = f"{GREEN}OK{RESET}"
    FAIL = f"{RED}FAIL{RESET}"
    SKIP = f"{DGREEN}SKIP{RESET}"
    BLOCKED = f"{RED}BLOCKED{RESET}"
    WARN = f"{YELLOW}WARN{RESET}"


# Box drawing
BOX_H = "═"
BOX_V = "║"
BOX_TL = "╔"
BOX_TR = "╗"
BOX_BL = "╚"
BOX_BR = "╝"

BANNER = f"""{C.GREEN}
 ░█▄░█ █ █▀▀ █░█ ▀█▀ █▀▀ █▀█ ▄▀█ █░█░█ █░░ █▀▀ █▀█
 ░█░▀█ █ █▄█ █▀█ ░█░ █▄▄ █▀▄ █▀█ ▀▄▀▄▀ █▄▄ ██▄ █▀▄  v0.1.0{C.RESET}"""
