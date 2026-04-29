#!/bin/bash
# Nightcrawler — Start all services
set -e

NC_HOME="${NC_HOME:-/opt/nightcrawler}"
MODEL="${NC_HOME}/models/Qwen3.5-2B-Q8_0.gguf"
THREADS=4
CTX=4096
LLM_PORT=8080
KALI_MCP_PORT=5000
PROXY_PORT=8800

G="\033[1;32m"; D="\033[38;5;22m"; R="\033[0m"
OK="${G}OK${R}"; FAIL="\033[1;31mFAIL${R}"

echo -e "${G}[■■■■■■■■■■] NIGHTCRAWLER v0.1.0${R}"
echo ""

# ── Android persistence ────────────────────────────
echo -ne "[INIT] Acquiring CPU wake lock................. "
echo "nightcrawler" > /sys/power/wake_lock 2>/dev/null && echo -e "$OK" || {
    command -v termux-wake-lock &>/dev/null && termux-wake-lock
    echo -e "${G}OK (termux)${R}"
} 2>/dev/null || echo -e "${D}SKIP${R}"

echo -ne "[INIT] Disabling Android Doze.................. "
dumpsys deviceidle disable > /dev/null 2>&1 && echo -e "$OK" || echo -e "${D}SKIP${R}"

# ── Tailscale (optional) ─────────────────────────────
echo -ne "[INIT] Tailscale daemon........................ "
if pgrep -x tailscaled > /dev/null 2>&1; then
    echo -e "${G}ALREADY RUNNING${R}"
else
    if command -v tailscaled &>/dev/null; then
        tailscaled --state=/var/lib/tailscale/tailscaled.state \
                   --socket=/var/run/tailscale/tailscaled.sock &
        sleep 2
        echo -e "${G}STARTED${R}"
    else
        echo -e "${D}NOT INSTALLED${R}"
    fi
fi

# ── SSH ────────────────────────────────────────────
echo -ne "[INIT] SSH daemon.............................. "
pgrep -x sshd > /dev/null 2>&1 || /usr/sbin/sshd 2>/dev/null
echo -e "$OK"

# ── llama.cpp ──────────────────────────────────────
echo -ne "[INIT] llama-server (Q8_0, ctx=$CTX)......... "
if command -v llama-server &>/dev/null; then
    llama-server \
        -m "$MODEL" \
        -c "$CTX" \
        -t "$THREADS" \
        --port "$LLM_PORT" \
        --jinja \
        --chat-template-kwargs '{"enable_thinking":false}' \
        --log-disable \
        > /tmp/llama-server.log 2>&1 &
    echo $! > /tmp/llama.pid
    renice -n -10 -p $(cat /tmp/llama.pid) > /dev/null 2>&1
    sleep 3
    echo -e "$OK"
else
    echo -e "$FAIL  [llama-server not found]"
fi

# ── Official Kali MCP Server ──────────────────────
echo -ne "[INIT] kali-server-mcp :$KALI_MCP_PORT................. "
if command -v kali-server-mcp &>/dev/null; then
    kali-server-mcp --port "$KALI_MCP_PORT" > /tmp/kali-mcp.log 2>&1 &
    echo $! > /tmp/kali-mcp.pid
    sleep 1
    echo -e "$OK"
elif [ "${NC_DRY_RUN:-0}" = "1" ]; then
    # Use mock server for dry-run
    cd "$NC_HOME"
    python3 -m simulation.mock_kali_server "$KALI_MCP_PORT" > /tmp/kali-mcp.log 2>&1 &
    echo $! > /tmp/kali-mcp.pid
    sleep 1
    echo -e "${G}OK (mock)${R}"
else
    echo -e "$FAIL  [not installed]"
fi

# ── Scope Enforcement Proxy ───────────────────────
echo -ne "[INIT] Scope proxy :$PROXY_PORT...................... "
cd "$NC_HOME"
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi
python3 scope_proxy.py \
    --config config.yaml \
    --upstream "http://127.0.0.1:$KALI_MCP_PORT" \
    --port "$PROXY_PORT" \
    $([ "${NC_DRY_RUN:-0}" = "1" ] && echo "--dry-run") \
    > /tmp/scope-proxy.log 2>&1 &
echo $! > /tmp/proxy.pid
echo -e "$OK"

# ── Mode ──────────────────────────────────────────
echo ""
if [ "${NC_DRY_RUN:-0}" = "1" ]; then
    echo -e "[INIT] Mode: ${G}DRY RUN (simulation)${R}"
else
    echo -e "[INIT] Mode: ${G}AUTONOMOUS${R}"
fi

# ── Thor (optional) ──────────────────────────────
THOR_ENDPOINT=$(grep -A2 'thor:' "$NC_HOME/config.yaml" | grep 'endpoint' | awk '{print $2}' | tr -d '"')
echo -ne "[INIT] Thor................................... "
if [ -n "$THOR_ENDPOINT" ] && curl -s --connect-timeout 3 "$THOR_ENDPOINT/models" > /dev/null 2>&1; then
    echo -e "${G}ONLINE${R}"
else
    echo -e "${D}OFFLINE (standalone mode)${R}"
fi

# ── Watchdog ──────────────────────────────────────
MAX_HOURS=$(grep 'max_runtime_hours' "$NC_HOME/config.yaml" | awk '{print $2}')
echo -e "[INIT] Watchdog: ${G}${MAX_HOURS}h${R} max runtime"

# ── Launch ────────────────────────────────────────
echo ""
echo -e "  ${G}╔═══════════════════════════════════════════════════════╗${R}"
echo -e "  ${G}║  ALL SYSTEMS GREEN — NIGHTCRAWLER ACTIVE             ║${R}"
echo -e "  ${G}╚═══════════════════════════════════════════════════════╝${R}"
echo ""

cd "$NC_HOME"
python3 main.py
