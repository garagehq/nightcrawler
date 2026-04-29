"""Cover Traffic Generator — blends offensive activity with normal web traffic.

Generates realistic-looking HTTP traffic to popular websites so the phone's
network footprint looks like a normal user, not a red team device.

Key design:
- Uses curl (low RAM, no browser needed)
- Mix of pre-generated URLs + LLM-generated search queries
- Separate logging from offensive commands (not in agent feed/report)
- Respects operating hours and screen state
- Configurable ratio via slider (0-100% cover traffic)
"""

import asyncio
import json
import os
import random
import subprocess
import time
import threading
from datetime import datetime

# Pre-generated traffic patterns — common sites a phone user would visit
WEBSITES = [
    "https://www.google.com/search?q={query}",
    "https://www.instagram.com/",
    "https://www.youtube.com/",
    "https://www.reddit.com/",
    "https://twitter.com/",
    "https://www.amazon.com/",
    "https://www.facebook.com/",
    "https://www.netflix.com/",
    "https://www.tiktok.com/",
    "https://www.spotify.com/",
    "https://www.wikipedia.org/wiki/Special:Random",
    "https://www.cnn.com/",
    "https://www.bbc.com/news",
    "https://news.ycombinator.com/",
    "https://www.weather.com/",
    "https://www.espn.com/",
    "https://www.nytimes.com/",
    "https://www.apple.com/",
    "https://www.microsoft.com/",
    "https://www.github.com/",
    "https://www.stackoverflow.com/",
    "https://www.linkedin.com/",
    "https://www.twitch.tv/",
    "https://www.walmart.com/",
    "https://www.target.com/",
    "https://www.ebay.com/",
    "https://mail.google.com/",
    "https://outlook.live.com/",
    "https://www.discord.com/",
    "https://www.whatsapp.com/",
]

# Realistic search queries a phone user might search
SEARCH_QUERIES = [
    "weather today", "best restaurants near me", "news today",
    "how to cook pasta", "movie times", "football scores",
    "pizza delivery", "gas prices near me", "walmart hours",
    "iphone 16 review", "best netflix shows 2026", "recipe chicken parmesan",
    "traffic near me", "stock market today", "crypto prices",
    "gym near me", "flight status", "package tracking",
    "how to fix wifi", "best headphones 2026", "oil change near me",
    "mortgage rates", "job openings near me", "car insurance quotes",
    "dog breeds", "hiking trails near me", "coffee shops near me",
    "home depot hours", "dentist near me", "pharmacy near me",
    "hotel deals", "beach vacation", "camping gear",
    "baby names", "wedding venues", "birthday gift ideas",
    "how to tie a tie", "resume template", "interview tips",
    "python tutorial", "javascript frameworks", "react vs vue",
    "best laptop 2026", "gaming pc build", "mechanical keyboard",
]

# API-like traffic (simulates apps checking for updates, notifications, etc.)
API_TRAFFIC = [
    "https://api.openweathermap.org/",
    "https://graph.instagram.com/",
    "https://api.twitter.com/",
    "https://www.googleapis.com/",
    "https://api.spotify.com/",
    "https://fcm.googleapis.com/",
    "https://play.googleapis.com/",
    "https://time.google.com/",
    "https://connectivitycheck.gstatic.com/generate_204",
    "https://clients3.google.com/generate_204",
]

COVER_LOG = "/tmp/nc-cover-traffic.jsonl"
COVER_STATS_FILE = "/tmp/nc-cover-stats.json"

_running = False
_thread = None
_stats = {"total": 0, "hourly": {}}


def is_screen_on():
    """Check if the phone's display is on (brightness > 0)."""
    try:
        result = subprocess.run(
            ["ssh", "-p", "9022", "-o", "ConnectTimeout=2", "-o", "BatchMode=yes",
             "shell@127.0.0.1", "cat /sys/class/backlight/*/brightness 2>/dev/null || echo 0"],
            capture_output=True, text=True, timeout=5)
        val = result.stdout.strip().split('\n')[0]
        return int(val) > 0
    except Exception:
        return False  # assume screen off if we can't check


def is_off_hours():
    """Check if we're in off-hours (operating hours disabled)."""
    try:
        import sqlite3
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "logs", "nightcrawler.db")
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT value FROM state WHERE key='operating_hours'").fetchone()
        conn.close()
        if row:
            hours = json.loads(row[0])
            if hours.get("enabled"):
                now_h = datetime.now().hour
                start_h = hours.get("start", 7)
                end_h = hours.get("end", 23)
                if start_h <= end_h:
                    return not (start_h <= now_h < end_h)
                else:
                    return not (now_h >= start_h or now_h < end_h)
    except Exception:
        pass
    return False


def get_cover_ratio():
    """Get the cover traffic ratio (0-100) from config."""
    try:
        import sqlite3
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "logs", "nightcrawler.db")
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT value FROM state WHERE key='cover_traffic'").fetchone()
        conn.close()
        if row:
            config = json.loads(row[0])
            return config.get("ratio", 85)
    except Exception:
        pass
    return 85  # default 85% cover traffic


def generate_llm_query():
    """Ask the 2B model for a random search query (fast, low-token)."""
    try:
        import httpx
        resp = httpx.post("http://127.0.0.1:8080/v1/chat/completions",
                          json={
                              "messages": [{"role": "user",
                                            "content": "Give me one random Google search query a person might type. Just the query, nothing else."}],
                              "max_tokens": 15,
                              "temperature": 1.5,  # high temp for randomness
                          }, timeout=10)
        if resp.status_code == 200:
            query = resp.json()["choices"][0]["message"]["content"].strip()
            query = query.strip('"\'').replace('\n', ' ')[:50]
            if len(query) > 3:
                return query
    except Exception:
        pass
    return random.choice(SEARCH_QUERIES)


def make_request():
    """Make a single cover traffic request. Returns (url, status, bytes)."""
    # Decide what type of traffic
    roll = random.random()
    if roll < 0.50:
        # Regular website visit
        url = random.choice(WEBSITES)
        if "{query}" in url:
            # Use LLM 10% of the time for queries, pre-generated otherwise
            if random.random() < 0.10:
                query = generate_llm_query()
            else:
                query = random.choice(SEARCH_QUERIES)
            url = url.format(query=query.replace(" ", "+"))
    elif roll < 0.75:
        # Google search
        if random.random() < 0.15:
            query = generate_llm_query()
        else:
            query = random.choice(SEARCH_QUERIES)
        url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
    else:
        # API-like traffic (app background checks)
        url = random.choice(API_TRAFFIC)

    try:
        # Use curl with realistic headers, follow redirects, timeout quickly
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
             "-L", "--max-time", "8",
             "-H", "User-Agent: Mozilla/5.0 (Linux; Android 12; OnePlus8) AppleWebKit/537.36 Chrome/120.0",
             "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
             "-H", "Accept-Language: en-US,en;q=0.9",
             url],
            capture_output=True, text=True, timeout=15)
        parts = result.stdout.strip().split()
        status = int(parts[0]) if parts else 0
        size = int(parts[1]) if len(parts) > 1 else 0
        return url, status, size
    except Exception:
        return url, 0, 0


def log_request(url, status, size):
    """Log cover traffic to separate file (not agent feed)."""
    global _stats
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "url": url[:120],
        "status": status,
        "bytes": size,
    }
    try:
        with open(COVER_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    # Update hourly stats
    hour_key = datetime.utcnow().strftime("%Y-%m-%dT%H")
    _stats["total"] += 1
    _stats["hourly"][hour_key] = _stats["hourly"].get(hour_key, 0) + 1

    # Save stats periodically
    if _stats["total"] % 10 == 0:
        try:
            with open(COVER_STATS_FILE, "w") as f:
                json.dump(_stats, f)
        except Exception:
            pass


def _traffic_loop():
    """Main traffic generation loop — runs in background thread."""
    global _running

    while _running:
        try:
            ratio = get_cover_ratio()
            if ratio <= 0:
                time.sleep(30)
                continue

            # Skip during off-hours
            if is_off_hours():
                time.sleep(60)
                continue

            # Skip when screen is on (user is using the phone)
            if is_screen_on():
                time.sleep(30)
                continue

            # Generate traffic at a rate proportional to the ratio
            # At 85%: ~12-20 requests per minute (realistic phone traffic)
            # At 50%: ~6-10 per minute
            # At 100%: ~15-25 per minute
            requests_per_min = max(1, int(ratio / 5))
            delay = 60.0 / requests_per_min

            # Add jitter (±30%) to look natural
            jittered_delay = delay * (0.7 + random.random() * 0.6)

            # Make the request
            url, status, size = make_request()
            log_request(url, status, size)

            time.sleep(jittered_delay)

        except Exception:
            time.sleep(10)


def start():
    """Start the cover traffic generator in a background thread."""
    global _running, _thread
    if _running:
        return
    _running = True
    _thread = threading.Thread(target=_traffic_loop, daemon=True)
    _thread.start()


def stop():
    """Stop the cover traffic generator."""
    global _running
    _running = False


def get_stats():
    """Return cover traffic statistics."""
    global _stats
    try:
        if os.path.exists(COVER_STATS_FILE):
            with open(COVER_STATS_FILE) as f:
                _stats = json.load(f)
    except Exception:
        pass
    return _stats


def get_recent_log(limit=50):
    """Return recent cover traffic entries."""
    entries = []
    try:
        if os.path.exists(COVER_LOG):
            with open(COVER_LOG) as f:
                lines = f.readlines()
            for line in lines[-limit:]:
                try:
                    entries.append(json.loads(line.strip()))
                except Exception:
                    pass
    except Exception:
        pass
    return entries
