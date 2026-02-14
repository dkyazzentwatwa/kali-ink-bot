#!/bin/bash
#
# Nexmon Install Script for Kali Ink Bot
# Enables monitor mode on Raspberry Pi's built-in WiFi
#
# Supported:
#   - Pi Zero 2W (BCM43436)
#   - Pi Zero W (BCM43430)
#   - Pi 3B/3B+ (BCM43455)
#   - Pi 4B (BCM43455)
#
# Usage: sudo ./install-nexmon.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root: sudo $0"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
if [[ "$ARCH" != "armv"* && "$ARCH" != "aarch64" ]]; then
    log_error "This script only works on Raspberry Pi (ARM). Detected: $ARCH"
    exit 1
fi

echo ""
echo "============================================"
echo "  Nexmon Install Script for Kali Ink Bot"
echo "============================================"
echo ""

# ============================================
# Step 1: Detect Pi Model and WiFi Chip
# ============================================

log_info "Detecting Raspberry Pi model..."

# Get Pi model
if [ -f /sys/firmware/devicetree/base/model ]; then
    PI_MODEL=$(tr -d '\0' < /sys/firmware/devicetree/base/model)
else
    PI_MODEL=$(grep "Model" /proc/cpuinfo | cut -d: -f2 | xargs)
fi

log_info "Detected: $PI_MODEL"

# Detect WiFi chip
log_info "Detecting WiFi chip..."

# Method 1: Check dmesg for brcmfmac
CHIP_INFO=$(dmesg | grep -i "brcmfmac.*chip" | tail -1 || true)

# Method 2: Check kernel module info
if [ -z "$CHIP_INFO" ]; then
    CHIP_INFO=$(modinfo brcmfmac 2>/dev/null | grep -i "description" || true)
fi

# Method 3: Check firmware loaded
FW_INFO=$(dmesg | grep -i "brcmfmac.*firmware" | tail -1 || true)

# Determine chip type based on Pi model
case "$PI_MODEL" in
    *"Zero 2"*)
        CHIP="bcm43436b0"
        CHIP_NAME="BCM43436 (Pi Zero 2W)"
        FW_VERSION="9_88_4_65"
        ;;
    *"Zero W"*)
        CHIP="bcm43430a1"
        CHIP_NAME="BCM43430 (Pi Zero W)"
        FW_VERSION="7_45_41_46"
        ;;
    *"3 Model B Plus"* | *"3B+"*)
        CHIP="bcm43455c0"
        CHIP_NAME="BCM43455 (Pi 3B+)"
        FW_VERSION="7_45_189"
        ;;
    *"3 Model B"* | *"3B"*)
        CHIP="bcm43430a1"
        CHIP_NAME="BCM43430 (Pi 3B)"
        FW_VERSION="7_45_41_46"
        ;;
    *"4 Model B"* | *"4B"*)
        CHIP="bcm43455c0"
        CHIP_NAME="BCM43455 (Pi 4B)"
        FW_VERSION="7_45_189"
        ;;
    *)
        log_error "Unsupported Pi model: $PI_MODEL"
        log_error "Supported: Pi Zero W, Pi Zero 2W, Pi 3B, Pi 3B+, Pi 4B"
        exit 1
        ;;
esac

log_success "WiFi Chip: $CHIP_NAME"
log_info "Firmware version: $FW_VERSION"

# ============================================
# Step 2: Install Dependencies
# ============================================

log_info "Installing build dependencies..."

apt-get update
apt-get install -y \
    git \
    libgmp3-dev \
    gawk \
    qpdf \
    bison \
    flex \
    make \
    automake \
    texinfo \
    libtool-bin \
    build-essential \
    bc \
    raspberrypi-kernel-headers \
    libssl-dev

log_success "Dependencies installed"

# ============================================
# Step 3: Download Nexmon
# ============================================

NEXMON_DIR="/opt/nexmon"
BACKUP_DIR="/opt/nexmon-backup"

if [ -d "$NEXMON_DIR" ]; then
    log_warn "Nexmon directory exists, updating..."
    cd "$NEXMON_DIR"
    git pull || true
else
    log_info "Cloning Nexmon repository..."
    git clone https://github.com/seemoo-lab/nexmon.git "$NEXMON_DIR"
    cd "$NEXMON_DIR"
fi

log_success "Nexmon downloaded to $NEXMON_DIR"

# ============================================
# Step 4: Build Nexmon
# ============================================

log_info "Building Nexmon (this may take 20-40 minutes on Pi Zero)..."
echo ""
log_warn "Go grab a coffee..."
echo ""

cd "$NEXMON_DIR"

# Set up build environment
log_info "Setting up build environment..."
source setup_env.sh

# Build tools first
log_info "Building buildtools..."
cd buildtools
make

cd "$NEXMON_DIR"

# Build firmware utilities
log_info "Building firmware utilities..."
cd utilities/libnexmon
make

cd "$NEXMON_DIR"

# Check if patch directory exists
PATCH_DIR="$NEXMON_DIR/patches/$CHIP/$FW_VERSION/nexmon"

if [ ! -d "$PATCH_DIR" ]; then
    # Try alternate path structure
    PATCH_DIR=$(find "$NEXMON_DIR/patches" -type d -name "nexmon" -path "*/$CHIP/*" | head -1)
fi

if [ ! -d "$PATCH_DIR" ]; then
    log_error "Patch directory not found for $CHIP"
    log_error "Available patches:"
    ls -la "$NEXMON_DIR/patches/"
    exit 1
fi

log_info "Using patch: $PATCH_DIR"

# Build the patch
cd "$PATCH_DIR"
log_info "Compiling firmware patch..."
make clean 2>/dev/null || true
make

log_success "Nexmon compiled successfully!"

# ============================================
# Step 5: Backup Original Firmware
# ============================================

log_info "Backing up original firmware..."

mkdir -p "$BACKUP_DIR"

# Find and backup firmware files
FIRMWARE_PATH="/lib/firmware/brcm"

# BCM43436 (Pi Zero 2W)
if [ -f "$FIRMWARE_PATH/brcmfmac43436-sdio.bin" ]; then
    cp "$FIRMWARE_PATH/brcmfmac43436-sdio.bin" "$BACKUP_DIR/" 2>/dev/null || true
fi

# BCM43430 (Pi Zero W, Pi 3B)
if [ -f "$FIRMWARE_PATH/brcmfmac43430-sdio.bin" ]; then
    cp "$FIRMWARE_PATH/brcmfmac43430-sdio.bin" "$BACKUP_DIR/" 2>/dev/null || true
fi

# BCM43455 (Pi 3B+, Pi 4B)
if [ -f "$FIRMWARE_PATH/brcmfmac43455-sdio.bin" ]; then
    cp "$FIRMWARE_PATH/brcmfmac43455-sdio.bin" "$BACKUP_DIR/" 2>/dev/null || true
fi

# Also backup using make if available
cd "$PATCH_DIR"
make backup-firmware 2>/dev/null || true

log_success "Firmware backed up to $BACKUP_DIR"

# ============================================
# Step 6: Install Patched Firmware
# ============================================

log_info "Installing patched firmware..."

cd "$PATCH_DIR"
make install-firmware

# Also install nexutil
log_info "Installing nexutil..."
cd "$NEXMON_DIR/utilities/nexutil"
make
make install

log_success "Patched firmware installed!"

# ============================================
# Step 7: Create Kernel Update Hook
# ============================================

log_info "Creating kernel update warning hook..."

HOOK_FILE="/etc/kernel/postinst.d/zz-nexmon-warning"

cat > "$HOOK_FILE" << 'HOOK'
#!/bin/bash
#
# Nexmon Kernel Update Warning
# This hook warns when kernel is updated, as Nexmon may need recompilation
#

echo ""
echo "============================================"
echo "  WARNING: Kernel Updated!"
echo "============================================"
echo ""
echo "You have updated your kernel. Nexmon firmware"
echo "may no longer work correctly for monitor mode."
echo ""
echo "To recompile Nexmon, run:"
echo "  sudo /opt/nexmon/scripts/rebuild-nexmon.sh"
echo ""
echo "Or to restore original firmware:"
echo "  sudo /opt/nexmon/scripts/restore-firmware.sh"
echo ""
echo "============================================"
echo ""
HOOK

chmod +x "$HOOK_FILE"

log_success "Kernel update hook installed"

# ============================================
# Step 8: Create Helper Scripts
# ============================================

log_info "Creating helper scripts..."

mkdir -p "$NEXMON_DIR/scripts"

# Rebuild script
cat > "$NEXMON_DIR/scripts/rebuild-nexmon.sh" << REBUILD
#!/bin/bash
# Rebuild Nexmon after kernel update
set -e
cd /opt/nexmon
source setup_env.sh
cd patches/$CHIP/$FW_VERSION/nexmon
make clean
make
make install-firmware
echo "Nexmon rebuilt and installed!"
echo "Reboot to apply changes: sudo reboot"
REBUILD
chmod +x "$NEXMON_DIR/scripts/rebuild-nexmon.sh"

# Restore script
cat > "$NEXMON_DIR/scripts/restore-firmware.sh" << RESTORE
#!/bin/bash
# Restore original firmware
set -e
BACKUP_DIR="/opt/nexmon-backup"
FIRMWARE_PATH="/lib/firmware/brcm"

if [ -f "\$BACKUP_DIR/brcmfmac43436-sdio.bin" ]; then
    cp "\$BACKUP_DIR/brcmfmac43436-sdio.bin" "\$FIRMWARE_PATH/"
fi
if [ -f "\$BACKUP_DIR/brcmfmac43430-sdio.bin" ]; then
    cp "\$BACKUP_DIR/brcmfmac43430-sdio.bin" "\$FIRMWARE_PATH/"
fi
if [ -f "\$BACKUP_DIR/brcmfmac43455-sdio.bin" ]; then
    cp "\$BACKUP_DIR/brcmfmac43455-sdio.bin" "\$FIRMWARE_PATH/"
fi

echo "Original firmware restored!"
echo "Reboot to apply changes: sudo reboot"
RESTORE
chmod +x "$NEXMON_DIR/scripts/restore-firmware.sh"

# Monitor mode scripts (Pwnagotchi-style)
cat > "$NEXMON_DIR/scripts/monstart.sh" << 'MONSTART'
#!/bin/bash
# Enable monitor mode (Pwnagotchi-style)
set -e
IFACE="${1:-wlan0}"
MON_IFACE="${IFACE}mon"

# Unblock rfkill
rfkill unblock all 2>/dev/null || true

# Bring interface up
ifconfig "$IFACE" up 2>/dev/null || ip link set "$IFACE" up

# Disable power save
iw dev "$IFACE" set power_save off 2>/dev/null || true

# Get phy
PHY=$(iw dev "$IFACE" info | grep wiphy | awk '{print "phy"$2}')

# Create monitor interface
iw phy "$PHY" interface add "$MON_IFACE" type monitor 2>/dev/null || true

# Bring monitor interface up
ifconfig "$MON_IFACE" up 2>/dev/null || ip link set "$MON_IFACE" up

echo "Monitor mode enabled: $MON_IFACE"
MONSTART
chmod +x "$NEXMON_DIR/scripts/monstart.sh"

cat > "$NEXMON_DIR/scripts/monstop.sh" << 'MONSTOP'
#!/bin/bash
# Disable monitor mode
set -e
IFACE="${1:-wlan0}"
MON_IFACE="${IFACE}mon"

# Bring monitor interface down and delete
ifconfig "$MON_IFACE" down 2>/dev/null || ip link set "$MON_IFACE" down 2>/dev/null || true
iw dev "$MON_IFACE" del 2>/dev/null || true

# Bring original interface up
ifconfig "$IFACE" up 2>/dev/null || ip link set "$IFACE" up

echo "Monitor mode disabled"
MONSTOP
chmod +x "$NEXMON_DIR/scripts/monstop.sh"

# Add to PATH
if ! grep -q "/opt/nexmon/scripts" /etc/profile; then
    echo 'export PATH="$PATH:/opt/nexmon/scripts"' >> /etc/profile
fi

log_success "Helper scripts created in $NEXMON_DIR/scripts/"

# ============================================
# Step 9: Test Installation
# ============================================

echo ""
log_info "Testing Nexmon installation..."

# Reload driver
log_info "Reloading brcmfmac driver..."
rmmod brcmfmac 2>/dev/null || true
modprobe brcmfmac

sleep 3

# Check if nexutil works
if command -v nexutil &> /dev/null; then
    log_info "Running nexutil -v..."
    nexutil -v || true
fi

# Try to enable monitor mode
log_info "Testing monitor mode..."
if "$NEXMON_DIR/scripts/monstart.sh" wlan0 2>/dev/null; then
    sleep 2
    if iw dev wlan0mon info 2>/dev/null | grep -q "type monitor"; then
        log_success "Monitor mode works!"
        "$NEXMON_DIR/scripts/monstop.sh" wlan0 2>/dev/null || true
    else
        log_warn "Monitor interface created but may not be in monitor mode"
    fi
else
    log_warn "Could not test monitor mode (may need reboot)"
fi

# ============================================
# Done!
# ============================================

echo ""
echo "============================================"
echo -e "  ${GREEN}Nexmon Installation Complete!${NC}"
echo "============================================"
echo ""
echo "  Pi Model: $PI_MODEL"
echo "  WiFi Chip: $CHIP_NAME"
echo "  Firmware: $FW_VERSION"
echo ""
echo "  Helper scripts:"
echo "    monstart.sh [iface]  - Enable monitor mode"
echo "    monstop.sh [iface]   - Disable monitor mode"
echo "    rebuild-nexmon.sh    - Rebuild after kernel update"
echo "    restore-firmware.sh  - Restore original firmware"
echo ""
echo -e "  ${YELLOW}IMPORTANT: Reboot to ensure changes take effect${NC}"
echo "    sudo reboot"
echo ""
echo "  After reboot, test with:"
echo "    sudo monstart.sh"
echo "    iw dev"
echo ""
echo "============================================"
