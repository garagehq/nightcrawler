"""Uptime tracker. No expiry — agent runs until killed."""

import time


class Watchdog:
    """Tracks uptime only. No expiry or warnings."""

    def __init__(self, max_hours: float = 0):
        self.start_time = None

    def start(self):
        self.start_time = time.time()

    def check(self) -> str:
        return "ok"

    def elapsed(self) -> float:
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time

    def format_elapsed(self) -> str:
        return self._fmt(self.elapsed())

    def format_remaining(self) -> str:
        return ""

    @staticmethod
    def _fmt(seconds: float) -> str:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        return f"{h:02d}:{m:02d}:{s:02d}"
