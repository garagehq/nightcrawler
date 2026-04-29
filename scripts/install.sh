#!/bin/bash
# Nightcrawler — Install to /opt/nightcrawler
set -e

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="/opt/nightcrawler"

G="\033[1;32m"; R="\033[0m"

echo -e "${G}[INSTALL] Nightcrawler → ${INSTALL_DIR}${R}"

# Create install directory
mkdir -p "$INSTALL_DIR"

# Copy source files
echo -ne "[INSTALL] Copying source files... "
for item in main.py config.yaml scope_proxy.py system_prompt.md \
            agent proxy ui simulation scripts playbooks; do
    if [ -e "$SRC_DIR/$item" ]; then
        cp -r "$SRC_DIR/$item" "$INSTALL_DIR/"
    fi
done
echo -e "${G}OK${R}"

# Create required directories
mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/models"

# Set permissions
chmod +x "$INSTALL_DIR/scripts/"*.sh 2>/dev/null

# Create venv if needed
if [ ! -d "$INSTALL_DIR/.venv" ]; then
    echo -ne "[INSTALL] Creating Python venv... "
    python3 -m venv "$INSTALL_DIR/.venv"
    source "$INSTALL_DIR/.venv/bin/activate"
    pip install -q httpx pyyaml cryptography flask requests
    echo -e "${G}OK${R}"
fi

# Link models if they exist in source
if [ -d "$SRC_DIR/models" ] && [ "$(ls -A "$SRC_DIR/models/"*.gguf 2>/dev/null)" ]; then
    echo -ne "[INSTALL] Linking models... "
    for model in "$SRC_DIR/models/"*.gguf; do
        ln -sf "$model" "$INSTALL_DIR/models/" 2>/dev/null
    done
    echo -e "${G}OK${R}"
fi

echo ""
echo -e "${G}[INSTALL] Complete.${R}"
echo -e "  Launch:   ${INSTALL_DIR}/scripts/launch.sh"
echo -e "  Dry-run:  NC_DRY_RUN=1 ${INSTALL_DIR}/scripts/launch.sh"
