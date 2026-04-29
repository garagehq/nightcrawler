#!/bin/bash
# Nightcrawler Installer
#
# Installs the Nightcrawler autonomous pentest agent to /opt/nightcrawler.
# Run inside the Kali NetHunter chroot.
#
# This script handles Nightcrawler's Python stack and Kali tool dependencies.
# For the GPU/llama.cpp/OpenCL setup, see docs/INSTALL-GPU.sh.
#
# Usage: bash /root/nightcrawler/INSTALL.sh
#
set -e

NC_SRC="$(cd "$(dirname "$0")" && pwd)"
NC_INSTALL="/opt/nightcrawler"

G="\033[1;32m"; Y="\033[1;33m"; R="\033[1;31m"; D="\033[38;5;22m"; N="\033[0m"
OK="${G}OK${N}"; SKIP="${D}SKIP${N}"; FAIL="${R}FAIL${N}"

echo -e "${G}"
echo ' ░█▄░█ █ █▀▀ █░█ ▀█▀ █▀▀ █▀█ ▄▀█ █░█░█ █░░ █▀▀ █▀█'
echo ' ░█░▀█ █ █▄█ █▀█ ░█░ █▄▄ █▀▄ █▀█ ▀▄▀▄▀ █▄▄ ██▄ █▀▄  INSTALLER'
echo -e "${N}"

# ── Verify Kali chroot ──────────────────────────────
echo -ne "[1/8] Checking environment..................... "
if [ -f /etc/kali-motd ] || [ -d /usr/share/kali-defaults ]; then
    echo -e "$OK  [Kali chroot]"
else
    echo -e "$FAIL"
    echo "  This script must run inside the Kali NetHunter chroot."
    echo "  Enter chroot: /data/data/com.offsec.nhterm/files/usr/bin_aarch64/kali"
    exit 1
fi

# ── Install Kali tool dependencies ──────────────────
echo -ne "[2/8] Installing Kali tools.................... "
apt-get update -qq 2>/dev/null
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    git tmux openssh-server curl jq \
    aircrack-ng nmap hydra smbclient \
    netexec gobuster nikto sqlmap wpscan enum4linux \
    2>&1 | tail -1
echo -e "$OK"

# ── Install mcp-kali-server ─────────────────────────
echo -ne "[3/8] Installing mcp-kali-server............... "
if command -v kali-server-mcp &>/dev/null; then
    echo -e "$OK  [already installed]"
elif apt-get install -y -qq mcp-kali-server 2>/dev/null; then
    echo -e "$OK"
else
    echo -e "${Y}NOT IN REPOS${N}  [agent will use dry-run / mock mode]"
fi

# ── Check Tailscale ──────────────────────────────────
echo -ne "[4/8] Checking Tailscale....................... "
if ip link show tailscale0 &>/dev/null; then
    TS_IP=$(ip -4 addr show tailscale0 2>/dev/null | grep -oP 'inet \K[\d.]+')
    echo -e "$OK  [$TS_IP]"
elif command -v tailscaled &>/dev/null; then
    echo -e "${Y}INSTALLED (interface down)${N}"
else
    echo -e "${Y}NOT FOUND${N}  [web UI will bind to localhost]"
    echo "    Install: curl -fsSL https://tailscale.com/install.sh | sh"
fi

# ── Copy source to /opt/nightcrawler ─────────────────
echo -ne "[5/8] Installing to ${NC_INSTALL}......... "
mkdir -p "$NC_INSTALL"
for item in main.py config.yaml scope_proxy.py \
            agent proxy ui webui simulation scripts playbooks; do
    if [ -e "$NC_SRC/$item" ]; then
        cp -r "$NC_SRC/$item" "$NC_INSTALL/"
    fi
done
mkdir -p "$NC_INSTALL/logs"
chmod +x "$NC_INSTALL/scripts/"*.sh 2>/dev/null
echo -e "$OK"

# ── Python venv + deps ──────────────────────────────
echo -ne "[6/8] Setting up Python venv................... "
if [ ! -d "$NC_INSTALL/.venv" ]; then
    python3 -m venv "$NC_INSTALL/.venv"
fi
source "$NC_INSTALL/.venv/bin/activate"
pip install -q httpx pyyaml cryptography flask requests 2>/dev/null
echo -e "$OK"

# ── Link model files ────────────────────────────────
echo -ne "[7/8] Linking models........................... "
mkdir -p "$NC_INSTALL/models"
MODEL_COUNT=0
if [ -d "$NC_SRC/models" ]; then
    for model in "$NC_SRC/models/"*.gguf; do
        [ -f "$model" ] || continue
        ln -sf "$model" "$NC_INSTALL/models/" 2>/dev/null
        MODEL_COUNT=$((MODEL_COUNT + 1))
    done
fi
if [ "$MODEL_COUNT" -gt 0 ]; then
    echo -e "$OK  [${MODEL_COUNT} models linked]"
else
    echo -e "${Y}NONE FOUND${N}  [download .gguf files to $NC_SRC/models/]"
fi

# ── Verify imports ──────────────────────────────────
echo -ne "[8/8] Verifying Python imports................. "
cd "$NC_INSTALL"
ERRORS=0
python3 -c "from agent.loop import AgentLoop" 2>/dev/null || ERRORS=$((ERRORS + 1))
python3 -c "from proxy.scope import ScopeValidator" 2>/dev/null || ERRORS=$((ERRORS + 1))
python3 -c "from webui.server import run_webui" 2>/dev/null || ERRORS=$((ERRORS + 1))
python3 -c "from simulation.mock_kali_server import MockKaliServer" 2>/dev/null || ERRORS=$((ERRORS + 1))
if [ "$ERRORS" -eq 0 ]; then
    echo -e "$OK  [all modules]"
else
    echo -e "${R}${ERRORS} FAILED${N}  [check Python deps]"
fi

# ── Done ─────────────────────────────────────────────
echo ""
echo -e "${G}╔═══════════════════════════════════════════════════════╗${N}"
echo -e "${G}║  NIGHTCRAWLER INSTALLED                              ║${N}"
echo -e "${G}╚═══════════════════════════════════════════════════════╝${N}"
echo ""
echo "  Installed to: $NC_INSTALL"
echo ""
echo "  Commands:"
echo -e "    Dry-run:  ${G}cd $NC_INSTALL && NC_DRY_RUN=1 python3 main.py${N}"
echo -e "    Launch:   ${G}bash $NC_INSTALL/scripts/launch.sh${N}"
echo -e "    Stop:     ${G}bash $NC_INSTALL/scripts/stop.sh${N}"
echo -e "    Wipe:     ${G}bash $NC_INSTALL/scripts/wipe.sh${N}"
echo ""
echo "  Web UI:     http://<tailscale-ip>:8888"
echo "  tmux:       tmux attach -t nightcrawler"
echo ""
echo -e "${Y}Before launching, you still need:${N}"
echo "  1. Edit scope in $NC_INSTALL/config.yaml"
echo "  2. Start llama-server from Android/Termux side (see docs/COMMANDS.md)"
echo "  3. Start kali-server-mcp:  kali-server-mcp --port 5000 &"
echo ""
echo "  For GPU/OpenCL setup, see: docs/INSTALL-GPU.sh"
echo ""
