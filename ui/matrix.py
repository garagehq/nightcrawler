"""Matrix rain and visual effects for the TUI."""

import random
import sys
import time

from ui.colors import C


# Characters for matrix rain
MATRIX_CHARS = "ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ012345789ABCDEF"
HEX_CHARS = "0123456789ABCDEF"


def matrix_rain(duration: float = 1.0, width: int = 60):
    """Show brief matrix rain effect."""
    cols = [0] * width
    end_time = time.time() + duration
    while time.time() < end_time:
        line = []
        for i in range(width):
            if random.random() < 0.1:
                cols[i] = random.randint(3, 8)
            if cols[i] > 0:
                char = random.choice(MATRIX_CHARS)
                if cols[i] > 5:
                    line.append(f"{C.LGREEN}{char}")
                else:
                    line.append(f"{C.DGREEN}{char}")
                cols[i] -= 1
            else:
                line.append(" ")
        sys.stdout.write(f"\r  {''.join(line)}{C.RESET}")
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write("\r" + " " * (width + 4) + "\r")
    sys.stdout.flush()


def hex_spinner(label: str = "EXECUTING", width: int = 40):
    """Show hex byte spinner for command execution."""
    hexbytes = " ".join(
        f"0x{random.choice(HEX_CHARS)}{random.choice(HEX_CHARS)}"
        for _ in range(6)
    )
    bar_fill = random.randint(3, width - 3)
    bar = "█" * bar_fill + "░" * (width - bar_fill)
    pct = int(bar_fill / width * 100)
    return (
        f"  {C.MATRIX}░░▒▒▓▓██ {label} ██▓▓▒▒░░{C.RESET}\n"
        f"  {C.GRAY}[{hexbytes}]  {C.GREEN}{bar}  {pct}%{C.RESET}"
    )


def glitch_text(text: str, intensity: int = 3) -> str:
    """Add glitch characters to text for phase transitions."""
    result = list(text)
    for _ in range(intensity):
        pos = random.randint(0, len(result) - 1)
        result[pos] = random.choice("█▓▒░╳╱╲")
    return "".join(result)
