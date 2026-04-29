"""Command rate limiting with jitter."""

import time
import random


class RateLimiter:
    """Enforces rate limits between commands with random jitter."""

    def __init__(self, scan_rate_per_min: int = 50,
                 cred_rate_per_min: int = 10,
                 jitter_range_ms: list = None):
        self.scan_interval = 60.0 / scan_rate_per_min
        self.cred_interval = 60.0 / cred_rate_per_min
        self.jitter_min = (jitter_range_ms or [200, 2000])[0] / 1000.0
        self.jitter_max = (jitter_range_ms or [200, 2000])[1] / 1000.0
        self.last_scan_time = 0.0
        self.last_cred_time = 0.0

        # Keywords that indicate credential operations
        self._cred_keywords = ['hydra', 'nxc', 'crackmapexec', 'spray',
                               'brute', '-u ', '--user', '--pass']

    def wait_if_needed(self, command: str):
        """Block until rate limit is satisfied, adding jitter."""
        now = time.time()
        is_cred = any(kw in command.lower() for kw in self._cred_keywords)

        if is_cred:
            elapsed = now - self.last_cred_time
            if elapsed < self.cred_interval:
                time.sleep(self.cred_interval - elapsed)
            self.last_cred_time = time.time()
        else:
            elapsed = now - self.last_scan_time
            if elapsed < self.scan_interval:
                time.sleep(self.scan_interval - elapsed)
            self.last_scan_time = time.time()

        # Always add jitter
        jitter = random.uniform(self.jitter_min, self.jitter_max)
        time.sleep(jitter)

    def get_stats(self) -> dict:
        return {
            "scan_interval": self.scan_interval,
            "cred_interval": self.cred_interval,
            "jitter_range": [self.jitter_min, self.jitter_max],
        }
