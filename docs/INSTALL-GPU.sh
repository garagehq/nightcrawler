#!/bin/bash
# Cyberclaw Installer - Full OpenCL GPU + CPU Setup
# 
# This script sets up everything needed for local LLM inference on
# a Kali NetHunter phone with Snapdragon 865 (Adreno 650).
#
# Prerequisites:
#   1. Rooted phone with Magisk
#   2. Kali NetHunter chroot working
#   3. Termux installed with: pkg install clang cmake ninja git python shaderc
#   4. Adreno driver v819.2 Magisk module installed (A65X-819v2.zip from XDA)
#   5. SSH access working (port 9022)
#
# This script has TWO parts:
#   Part 1: Run inside Kali chroot (ollama + models + Mesa Turnip)
#   Part 2: Run as instructions for Termux (OpenCL llama.cpp build)
#
# Usage: bash /root/cyberclaw/docs/INSTALL.sh
#
set -e

echo "============================================"
echo "=== Cyberclaw Installer ===================="
echo "=== Snapdragon 865 / Adreno 650 ==========="
echo "============================================"
echo ""

# Detect if we're in the Kali chroot
if [ -f /etc/kali-motd ] || [ -d /usr/share/kali-defaults ]; then
    IN_KALI=true
    echo "[*] Running inside Kali chroot"
else
    IN_KALI=false
    echo "[!] Not in Kali chroot. Run this from inside the chroot."
    echo "    Enter chroot: /data/data/com.offsec.nhterm/files/usr/bin_aarch64/kali"
    exit 1
fi

##############################
# Part 1: Kali Chroot Setup
##############################

echo ""
echo "[1/5] Installing Kali dependencies..."
apt-get update -qq
apt-get install -y -qq \
    curl wget git strace \
    vulkan-tools libvulkan-dev mesa-vulkan-drivers \
    meson ninja-build python3 python3-mako cmake \
    libdrm-dev libwayland-dev zlib1g-dev libzstd-dev \
    pkg-config flex bison glslang-dev glslang-tools glslc \
    libdisplay-info-dev ccache \
    2>&1 | tail -3

echo ""
echo "[2/5] Building Mesa Turnip with KGSL support..."
MESA_VER="26.0.0"
cd /tmp
if [ ! -f "mesa-${MESA_VER}.tar.xz" ]; then
    echo "  Downloading Mesa ${MESA_VER}..."
    wget -q "https://archive.mesa3d.org/mesa-${MESA_VER}.tar.xz"
fi
if [ ! -d "mesa-${MESA_VER}" ]; then
    tar xf "mesa-${MESA_VER}.tar.xz"
fi
cd "mesa-${MESA_VER}"
if [ ! -d build ]; then
    meson setup build \
        -Dvulkan-drivers=freedreno \
        -Dgallium-drivers= \
        -Dglx=disabled -Degl=disabled -Dopengl=false \
        -Dgles1=disabled -Dgles2=disabled \
        -Dplatforms=wayland,x11 \
        -Dfreedreno-kmds=msm,kgsl \
        -Dbuildtype=release -Dprefix=/usr \
        -Dlibdir=lib/aarch64-linux-gnu
fi
echo "  Building (takes ~10 min on device)..."
ninja -C build -j4 2>&1 | tail -3
TURNIP="/usr/lib/aarch64-linux-gnu/libvulkan_freedreno.so"
[ ! -f "${TURNIP}.orig" ] && cp "$TURNIP" "${TURNIP}.orig"
cp build/src/freedreno/vulkan/libvulkan_freedreno.so "$TURNIP"
echo "  Turnip with KGSL: installed"

echo ""
echo "[3/5] Installing ollama..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi
echo "  ollama: $(ollama --version 2>/dev/null || echo 'installed')"

# Configure environment
grep -q "OLLAMA_VULKAN" /etc/environment 2>/dev/null || echo "OLLAMA_VULKAN=1" >> /etc/environment
grep -q "OLLAMA_FLASH_ATTENTION" /etc/environment 2>/dev/null || echo "OLLAMA_FLASH_ATTENTION=false" >> /etc/environment

echo ""
echo "[4/5] Downloading models..."
mkdir -p /root/cyberclaw/models
cd /root/cyberclaw/models
for model in "Qwen3.5-0.8B-Q8_0" "Qwen3.5-0.8B-Q4_0"; do
    if [ ! -f "${model}.gguf" ]; then
        echo "  Downloading ${model}..."
        curl -L -o "${model}.gguf" \
            "https://huggingface.co/unsloth/Qwen3.5-0.8B-GGUF/resolve/main/${model}.gguf" 2>&1 | tail -1
    else
        echo "  ${model}: already exists"
    fi
done
if [ ! -f "Qwen3.5-2B-Q4_K_M.gguf" ]; then
    echo "  Downloading Qwen3.5-2B-Q4_K_M..."
    curl -L -o "Qwen3.5-2B-Q4_K_M.gguf" \
        "https://huggingface.co/unsloth/Qwen3.5-2B-GGUF/resolve/main/Qwen3.5-2B-Q4_K_M.gguf" 2>&1 | tail -1
fi
echo "  Models downloaded"

echo ""
echo "[5/5] Kali setup complete!"
echo ""
echo "============================================"
echo "=== PART 2: Termux Setup (Manual Steps) ===="
echo "============================================"
echo ""
echo "The OpenCL GPU build must be done in Termux (bionic libc)."
echo "Run these commands in Termux (NOT in this script):"
echo ""
echo "--- Step 1: Install Termux packages ---"
echo "  pkg install clang cmake ninja git python shaderc opencl-headers"
echo ""
echo "--- Step 2: Clone and patch llama.cpp ---"
echo "  cd ~"
echo "  git clone --depth 1 https://github.com/ggml-org/llama.cpp.git"
echo ""
echo "  # Apply patches (see /root/cyberclaw/patches/ for details):"
echo "  # In ggml/src/ggml-opencl/ggml-opencl.cpp:"
echo "  #   1. Change 'if (platform_version.major >= 3)' to 'if (0)'"
echo "  #   2. Add '-Dcl_khr_subgroups' to compile_opts string"
echo "  #   3. Replace clGetKernelSubGroupInfo with 'sgs = 128;'"
echo ""
echo "--- Step 3: Build ---"
echo "  cmake -S . -B build-generic -G Ninja \\"
echo "    -DGGML_OPENCL=ON \\"
echo "    -DGGML_OPENCL_USE_ADRENO_KERNELS=OFF \\"
echo "    -DGGML_OPENCL_EMBED_KERNELS=OFF \\"
echo "    -DCMAKE_BUILD_TYPE=Release \\"
echo "    -DOpenCL_LIBRARY=/vendor/lib64/libOpenCL.so \\"
echo "    -DOpenCL_INCLUDE_DIR=\$PREFIX/include"
echo "  cmake --build build-generic --target llama-cli -j3"
echo ""
echo "--- Step 4: Copy models ---"
echo "  mkdir -p ~/models"
echo "  # Copy from Kali chroot (run as root from Android shell):"
echo "  # cp /data/local/nhsystem/kalifs/root/cyberclaw/models/*.gguf \\"
echo "  #    /data/data/com.termux/files/home/models/"
echo "  # chown -R 10393:10393 /data/data/com.termux/files/home/models/"
echo ""
echo "--- Step 5: Run ---"
echo "  cd ~/llama.cpp/ggml/src/ggml-opencl/kernels"
echo "  GGML_OPENCL_PLATFORM=0 GGML_OPENCL_DEVICE=0 \\"
echo "    LD_LIBRARY_PATH=/vendor/lib64 \\"
echo "    ~/llama.cpp/build-generic/bin/llama-cli \\"
echo "    -m ~/models/Qwen3.5-0.8B-Q8_0.gguf \\"
echo "    -ngl 99 -c 512 -n 100 -no-cnv -p 'Your prompt'"
echo ""
echo "============================================"
echo "=== Installation Summary ==================="
echo "============================================"
echo ""
echo "Kali chroot:"
echo "  - ollama: ready (CPU inference)"
echo "  - Mesa Turnip: installed (KGSL Vulkan, limited use)"
echo "  - Models: /root/cyberclaw/models/"
echo "  - Docs: /root/cyberclaw/docs/"
echo ""
echo "Termux (manual setup required):"
echo "  - llama.cpp with OpenCL: see instructions above"
echo "  - GPU inference: 4.6 t/s (0.8B), 1.8 t/s (2B)"
echo ""
echo "Magisk modules needed:"
echo "  - openssh (SSH persistence)"
echo "  - adreno-650_819v2 (GPU driver v819.2, E031.50)"
