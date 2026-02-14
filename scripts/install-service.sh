#!/bin/bash
# Install Kali Ink Bot as a systemd service
# Run with: sudo ./scripts/install-service.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SERVICE_NAME="kali-ink-bot"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

echo "=== Installing Kali Ink Bot Service ==="
echo ""

# Detect actual project path and user
ACTUAL_USER="${SUDO_USER:-pi}"
ACTUAL_HOME=$(eval echo ~$ACTUAL_USER)

echo "Project directory: $PROJECT_DIR"
echo "User: $ACTUAL_USER"
echo ""

# Update service file with correct paths
SERVICE_FILE="$SCRIPT_DIR/$SERVICE_NAME.service"
TEMP_SERVICE="/tmp/$SERVICE_NAME.service"

sed -e "s|/home/pi/kali-ink-bot|$PROJECT_DIR|g" \
    -e "s|User=root|User=root|g" \
    "$SERVICE_FILE" > "$TEMP_SERVICE"

# Make boot script executable
chmod +x "$SCRIPT_DIR/kali-ink-bot.sh"

# Copy service file
cp "$TEMP_SERVICE" "/etc/systemd/system/$SERVICE_NAME.service"
rm "$TEMP_SERVICE"

# Reload systemd
systemctl daemon-reload

echo "Service installed!"
echo ""
echo "=== Quick Start ==="
echo ""
echo "  Start:    sudo systemctl start $SERVICE_NAME"
echo "  Stop:     sudo systemctl stop $SERVICE_NAME"
echo "  Restart:  sudo systemctl restart $SERVICE_NAME"
echo "  Status:   sudo systemctl status $SERVICE_NAME"
echo "  Logs:     sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "  Enable on boot:   sudo systemctl enable $SERVICE_NAME"
echo "  Disable on boot:  sudo systemctl disable $SERVICE_NAME"
echo ""

# Ask about enabling on boot
read -p "Enable Kali Ink Bot to start on boot? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl enable "$SERVICE_NAME"
    echo "Service will start automatically on boot"
fi

echo ""
echo "=== Configuration ==="
echo ""
echo "Edit bettercap credentials in /etc/systemd/system/$SERVICE_NAME.service:"
echo "  Environment=BETTERCAP_PASS=your-secure-password"
echo ""
echo "Then reload: sudo systemctl daemon-reload"
echo ""
echo "Done!"
