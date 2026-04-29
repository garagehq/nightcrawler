# Kernel Module Build Prompt

Copy-paste this to your kernel build agent.

---

## Task: Add WiFi driver modules + pentest features to Nightcrawler kernel

**Device:** OnePlus 8 (kebab), Snapdragon 865
**Kernel:** `4.19.297-perf-g8228d522e928-dirty` (custom from Nameless AOSP `thirteen` branch)
**Kernel source:** https://github.com/garagehq/kernel_oneplus_sm8250_nethunter
**Build headers:** Already on-device at `/lib/modules/$(uname -r)/build/`
**Existing modules dir:** `/root/nightcrawler/kernels/modules/` (has 8821cu.ko, 8188eu.ko, 88XXau.ko)
**MODULE_SIG and MODVERSIONS:** Both disabled — modules load without signing

### What's already working
- `CONFIG_CFG80211=y` (built-in)
- `CONFIG_MAC80211=y` (built-in)
- `CONFIG_WIRELESS=y` (built-in)
- `CONFIG_PACKET=y`, `CONFIG_TUN=y`, `CONFIG_BRIDGE=y`, `CONFIG_VETH=y`
- `CONFIG_NETFILTER=y` (full stack)
- `CONFIG_IP_SCTP=y`
- `CONFIG_BT_HCIBTUSB=y` (Bluetooth USB)
- `CONFIG_USB_GADGET=y`, `CONFIG_USB_F_HID=y` (HID gadget)
- `CONFIG_FW_LOADER=y` with user helper fallback
- `CONFIG_CRYPTO_AES=y` + ARM64 CE variants

### Priority 1: Ralink RT3572 driver (rt2800usb)

We have a physical RT3572 USB adapter. Need these kernel configs enabled and built as modules:

```
CONFIG_WLAN_VENDOR_RALINK=y
CONFIG_RT2X00=m
CONFIG_RT2X00_LIB=m
CONFIG_RT2X00_LIB_USB=m
CONFIG_RT2X00_LIB_FIRMWARE=y
CONFIG_RT2X00_LIB_CRYPTO=y
CONFIG_RT2X00_LIB_LEDS=y
CONFIG_RT2800_LIB=m
CONFIG_RT2800USB=m
CONFIG_RT2800USB_RT3572=y
CONFIG_RT2800USB_RT33XX=y
CONFIG_RT2800USB_RT35XX=y
CONFIG_RT2800USB_RT53XX=y
CONFIG_RT2800USB_RT55XX=y
CONFIG_RT2800USB_UNKNOWN=y
```

The RT3572 also needs firmware files at runtime:
- `rt2870.bin` — should already be in `/lib/firmware/` or install via `apt install firmware-misc-nonfree`

**Build approach (preferred):** Build just the Ralink modules without full kernel rebuild:
```bash
# In kernel source directory:
# 1. Copy current .config
cp /lib/modules/$(uname -r)/build/.config .config
# 2. Enable Ralink options in .config (use sed or menuconfig)
# 3. Build only the ralink subtree
make modules M=drivers/net/wireless/ralink/rt2x00 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
# 4. Copy resulting .ko files
```

If partial build fails due to dependencies, do a full `make modules` and extract:
- `drivers/net/wireless/ralink/rt2x00/rt2x00lib.ko`
- `drivers/net/wireless/ralink/rt2x00/rt2x00usb.ko`
- `drivers/net/wireless/ralink/rt2x00/rt2800lib.ko`
- `drivers/net/wireless/ralink/rt2x00/rt2800usb.ko`

### Priority 2: Atheros AR9271 driver (carl9170 + ath9k_htc)

Another classic pentest chipset. Good to have even if we don't have the adapter yet — someone always has one lying around.

```
CONFIG_WLAN_VENDOR_ATH=y
CONFIG_ATH_COMMON=m
CONFIG_ATH9K=m
CONFIG_ATH9K_COMMON=m
CONFIG_ATH9K_HTC=m
CONFIG_ATH9K_HTC_DEBUGFS=n
CONFIG_CARL9170=m
CONFIG_CARL9170_LEDS=y
CONFIG_CARL9170_WPC=y
```

Firmware: `carl9170-1.fw`, `htc_9271.fw` — `/lib/firmware/`

### Priority 3: Additional pentest kernel features

These are currently disabled but useful:

```
# MACVLAN — needed for rogue AP setups and network namespace tricks
CONFIG_MACVLAN=m

# DCCP protocol — nmap DCCP scanning support
CONFIG_IP_DCCP=m

# SCTP netfilter match — for iptables SCTP rules
CONFIG_NETFILTER_XT_MATCH_SCTP=m
CONFIG_NETFILTER_XT_MATCH_DCCP=m

# USB network drivers (useful for USB tethering/MITM)
CONFIG_USB_NET_DM9601=m
CONFIG_USB_NET_SMSC95XX=m
CONFIG_USB_NET_CDC_MBIM=m
```

### Priority 4: MediaTek MT76 driver (future-proofing)

MediaTek adapters are becoming the new standard for pentest. MT7612U supports 5GHz injection.

```
CONFIG_WLAN_VENDOR_MEDIATEK=y
CONFIG_MT76_USB=m
CONFIG_MT76x02_LIB=m
CONFIG_MT76x02_USB=m
CONFIG_MT76x2U=m
```

Firmware: `mt7662u.bin`, `mt7662u_rom_patch.bin` — `/lib/firmware/mediatek/`

### Output

Place compiled `.ko` files in `/root/nightcrawler/kernels/modules/` alongside the existing ones. Test loading with:

```bash
# RT3572
insmod rt2x00lib.ko && insmod rt2x00usb.ko && insmod rt2800lib.ko && insmod rt2800usb.ko
# Verify
dmesg | tail -10  # should show rt2800usb registration
```

### On-device compilation (proven working)

We've successfully compiled three out-of-tree drivers directly on the device.
This is the **preferred approach** if cross-compile has issues (wrong vermagic,
missing symbols, etc). On-device builds guarantee ABI match.

**Environment:**
- Build runs in Kali chroot (`/data/local/nhsystem/kalifs/`)
- Kernel headers at `/lib/modules/$(uname -r)/build/`
- vermagic: `4.19.297-perf-g8228d522e928-dirty SMP preempt mod_unload aarch64`
- Takes ~5-10 min per out-of-tree driver, ~2-3h for full `make modules`

**Critical fixes needed before first on-device build:**

1. **Rebuild host tools** — kernel headers ship with x86 binaries that can't run on arm64:
   ```bash
   cd /lib/modules/$(uname -r)/build
   make scripts ARCH=arm64
   # This rebuilds scripts/mod/modpost and scripts/basic/fixdep natively
   ```

2. **Create module linker script** (if missing):
   ```bash
   cat > /lib/modules/$(uname -r)/build/arch/arm64/kernel/module.lds << 'EOF'
   SECTIONS {
       .plt (NOLOAD) : { BYTE(0) }
       .init.plt (NOLOAD) : { BYTE(0) }
       .text.ftrace_trampoline (NOLOAD) : { BYTE(0) }
   }
   EOF
   ```

3. **Install build dependencies:**
   ```bash
   apt install bc build-essential libelf-dev libssl-dev
   ```

**Build command for out-of-tree drivers:**
```bash
cd /path/to/driver-source
make -j4 ARCH=arm64 KSRC=/lib/modules/$(uname -r)/build modules
# Output: *.ko in current directory
cp *.ko /root/nightcrawler/kernels/modules/
```

**Driver-specific build notes:**

| Driver | Source repo | On-device build notes |
|--------|-----------|----------------------|
| 8821cu.ko | https://github.com/morrownr/8821cu-20210916 | Comment out `EXTRA_CFLAGS += $(ccflags-y)` — recursive variable crashes make |
| 88XXau.ko | https://github.com/aircrack-ng/rtl8812au | Works out of the box |
| 8188eu.ko | (cross-compiled from WSL) | Was cross-compiled; on-device should also work |

**Existing driver source on device:**
- `/root/rtl8812au-aircrack/` — RTL8812AU (aircrack-ng fork, built successfully)
- `/root/rtl8821cu/` — RTL8821CU (morrownr fork, built successfully)

**For in-tree drivers (rt2800usb, ath9k, mt76):**

If cross-compiling fails or produces wrong vermagic, build on-device:
```bash
# Clone kernel source (or use existing if available)
cd /root
git clone --depth 1 -b thirteen https://github.com/garagehq/kernel_oneplus_sm8250_nethunter.git kernel-src

# Copy running config
cp /lib/modules/$(uname -r)/build/.config kernel-src/.config

# Enable the drivers you need (edit .config or use menuconfig)
cd kernel-src
scripts/config --enable WLAN_VENDOR_RALINK
scripts/config --module RT2X00
scripts/config --module RT2X00_LIB
scripts/config --module RT2X00_LIB_USB
scripts/config --enable RT2X00_LIB_FIRMWARE
scripts/config --enable RT2X00_LIB_CRYPTO
scripts/config --module RT2800_LIB
scripts/config --module RT2800USB
scripts/config --enable RT2800USB_RT3572
scripts/config --enable RT2800USB_RT35XX
scripts/config --enable RT2800USB_UNKNOWN

# Prepare + build only the subtree
make olddefconfig ARCH=arm64
make modules_prepare ARCH=arm64
make -j4 M=drivers/net/wireless/ralink/rt2x00 ARCH=arm64

# Copy modules
cp drivers/net/wireless/ralink/rt2x00/*.ko /root/nightcrawler/kernels/modules/
```

If `make M=` fails with missing dependencies, fall back to full module build:
```bash
make -j4 modules ARCH=arm64  # ~2-3 hours on Snapdragon 865
find . -path "*/ralink/*.ko" -exec cp {} /root/nightcrawler/kernels/modules/ \;
```

### Include kernel headers in output

The on-device build environment needs kernel headers installed at `/lib/modules/$(uname -r)/build/`. After building, **package the headers** so we can compile additional out-of-tree drivers on-device without the full source tree:

```bash
# From the kernel source directory after build:
make modules_install INSTALL_MOD_PATH=/tmp/kernel-out ARCH=arm64
make headers_install INSTALL_HDR_PATH=/tmp/kernel-out/headers ARCH=arm64

# Also copy the build artifacts needed for out-of-tree module compilation:
HDRS=/tmp/kernel-out/lib/modules/$(make kernelrelease)/build
mkdir -p $HDRS
cp .config Module.symvers Makefile $HDRS/
cp -r scripts include arch/arm64/include $HDRS/
cp -r arch/arm64/kernel/module.lds $HDRS/arch/arm64/kernel/ 2>/dev/null
# Copy Kbuild files needed by module Makefiles
find . -name "Kbuild" -o -name "Kbuild.include" -o -name "Makefile" | \
    cpio -pd $HDRS 2>/dev/null

# Ensure host tools (modpost, fixdep) are compiled for arm64:
make scripts ARCH=arm64
cp scripts/mod/modpost scripts/basic/fixdep $HDRS/scripts/mod/ $HDRS/scripts/basic/ 2>/dev/null
```

The headers directory should be deployable to the phone at `/lib/modules/$(uname -r)/build/`. This is critical — without headers we can't compile new drivers on-device (which is our preferred build method for ABI compatibility).

### Important notes
- Kernel is 4.19.x — don't use features that require 5.x+
- `MODULE_SIG` and `MODVERSIONS` are both disabled — no signing needed
- ARM64 architecture, `CROSS_COMPILE=aarch64-linux-gnu-` if cross-compiling
- The defconfig is at `arch/arm64/configs/vendor/kebab_defconfig` in the source tree
- On-device build works and is **preferred for ABI compatibility**. Cross-compile is faster but may have vermagic issues.
- Boot image backup at `/sdcard/nightcrawler-kernels/boot-backup-20260324.img`
- Existing compiled modules at `/root/nightcrawler/kernels/modules/` and `/sdcard/nightcrawler-kernels/modules_v5/`
