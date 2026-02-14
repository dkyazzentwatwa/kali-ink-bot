"""
Project Inkling - WiFi Adapter Detection

Auto-detect WiFi adapters and capabilities for monitor mode and injection.
Identifies supported chipsets for WiFi hunting operations.
"""

import asyncio
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


# Known chipsets with good monitor mode / injection support
KNOWN_MONITOR_CHIPSETS = {
    # Atheros
    "ath9k_htc": {"name": "Atheros AR9271", "monitor": True, "injection": True},
    "ath9k": {"name": "Atheros AR9xxx", "monitor": True, "injection": True},
    "ath10k_pci": {"name": "Qualcomm Atheros", "monitor": True, "injection": True},

    # Realtek
    "rtl8812au": {"name": "Realtek RTL8812AU", "monitor": True, "injection": True},
    "88XXau": {"name": "Realtek RTL8812AU/21AU", "monitor": True, "injection": True},
    "rtl88xxau": {"name": "Realtek RTL88xxAU", "monitor": True, "injection": True},
    "rtl8821au": {"name": "Realtek RTL8821AU", "monitor": True, "injection": True},
    "rtl8814au": {"name": "Realtek RTL8814AU", "monitor": True, "injection": True},
    "rtl8187": {"name": "Realtek RTL8187", "monitor": True, "injection": True},
    "8192cu": {"name": "Realtek RTL8192CU", "monitor": True, "injection": False},
    "8188eu": {"name": "Realtek RTL8188EUS", "monitor": True, "injection": False},

    # Ralink/MediaTek
    "rt2800usb": {"name": "Ralink RT2800", "monitor": True, "injection": True},
    "rt73usb": {"name": "Ralink RT73", "monitor": True, "injection": True},
    "rt2500usb": {"name": "Ralink RT2500", "monitor": True, "injection": True},
    "mt76x2u": {"name": "MediaTek MT7612U", "monitor": True, "injection": True},
    "mt7601u": {"name": "MediaTek MT7601U", "monitor": True, "injection": True},

    # Intel (limited injection)
    "iwlwifi": {"name": "Intel Wireless", "monitor": True, "injection": False},

    # Broadcom
    "brcmfmac": {"name": "Broadcom FullMAC", "monitor": False, "injection": False},
    "brcmsmac": {"name": "Broadcom SoftMAC", "monitor": True, "injection": False},
}


@dataclass
class WiFiAdapter:
    """Represents a WiFi adapter with its capabilities."""

    interface: str  # wlan0, wlan1, wlan1mon
    driver: str  # ath9k_htc, rtl8812au
    chipset: str  # Human-readable chipset name
    mac_address: str
    monitor_capable: bool = False
    injection_capable: bool = False
    bands: List[str] = field(default_factory=list)  # ["2.4GHz", "5GHz"]
    connected: bool = False
    current_mode: str = "managed"  # managed, monitor
    phy: Optional[str] = None  # phy0, phy1

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "driver": self.driver,
            "chipset": self.chipset,
            "mac_address": self.mac_address,
            "monitor_capable": self.monitor_capable,
            "injection_capable": self.injection_capable,
            "bands": self.bands,
            "connected": self.connected,
            "current_mode": self.current_mode,
            "phy": self.phy,
        }


class AdapterManager:
    """
    Detect and manage WiFi adapters.

    Provides methods to:
    - Detect all wireless interfaces
    - Check monitor mode capability
    - Enable/disable monitor mode
    - Get the best adapter for hunting
    """

    def __init__(self):
        self._adapters: List[WiFiAdapter] = []
        self._last_scan = 0.0

    def detect_adapters(self, refresh: bool = False) -> List[WiFiAdapter]:
        """
        Detect all wireless adapters on the system.

        Uses multiple methods:
        1. /sys/class/net/*/wireless for interface list
        2. iw dev for detailed info
        3. /sys/class/net/*/device/uevent for driver info
        """
        if self._adapters and not refresh:
            return self._adapters

        adapters = []

        # Find all wireless interfaces
        sys_net = Path("/sys/class/net")
        if not sys_net.exists():
            logger.warning("Cannot access /sys/class/net")
            return adapters

        for iface_path in sys_net.iterdir():
            iface = iface_path.name
            wireless_path = iface_path / "wireless"

            # Check if this is a wireless interface
            if not wireless_path.exists():
                continue

            adapter = self._get_adapter_info(iface)
            if adapter:
                adapters.append(adapter)

        self._adapters = adapters
        return adapters

    def _get_adapter_info(self, interface: str) -> Optional[WiFiAdapter]:
        """Get detailed information about a wireless adapter."""
        sys_net = Path("/sys/class/net") / interface

        # Get MAC address
        mac_path = sys_net / "address"
        mac_address = ""
        if mac_path.exists():
            mac_address = mac_path.read_text().strip()

        # Get driver info from uevent
        driver = "unknown"
        uevent_path = sys_net / "device" / "uevent"
        if uevent_path.exists():
            uevent = uevent_path.read_text()
            for line in uevent.split("\n"):
                if line.startswith("DRIVER="):
                    driver = line.split("=", 1)[1].strip()
                    break

        # Get chipset info from driver
        chipset_info = KNOWN_MONITOR_CHIPSETS.get(driver, {})
        chipset = chipset_info.get("name", driver)
        monitor_capable = chipset_info.get("monitor", False)
        injection_capable = chipset_info.get("injection", False)

        # Use iw to check capabilities if driver unknown
        if not chipset_info:
            monitor_capable, injection_capable = self._check_iw_capabilities(interface)

        # Get phy and bands from iw
        phy, bands = self._get_iw_info(interface)

        # Check current mode
        current_mode = self._get_current_mode(interface)

        # Check if connected
        connected = self._check_connected(interface)

        return WiFiAdapter(
            interface=interface,
            driver=driver,
            chipset=chipset,
            mac_address=mac_address,
            monitor_capable=monitor_capable,
            injection_capable=injection_capable,
            bands=bands,
            connected=connected,
            current_mode=current_mode,
            phy=phy,
        )

    def _check_iw_capabilities(self, interface: str) -> Tuple[bool, bool]:
        """Check monitor and injection capability using iw."""
        monitor_capable = False
        injection_capable = False

        try:
            # Get phy for this interface
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return monitor_capable, injection_capable

            # Extract phy
            phy_match = re.search(r"wiphy (\d+)", result.stdout)
            if not phy_match:
                return monitor_capable, injection_capable

            phy = f"phy{phy_match.group(1)}"

            # Check phy capabilities
            result = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Check for monitor mode support
                if "monitor" in result.stdout.lower():
                    monitor_capable = True
                # Check for injection (look for supported interface modes)
                if "* monitor" in result.stdout:
                    injection_capable = True  # Simplified check
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"iw check failed for {interface}: {e}")

        return monitor_capable, injection_capable

    def _get_iw_info(self, interface: str) -> Tuple[Optional[str], List[str]]:
        """Get phy and supported bands from iw."""
        phy = None
        bands = []

        try:
            # Get device info
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                phy_match = re.search(r"wiphy (\d+)", result.stdout)
                if phy_match:
                    phy = f"phy{phy_match.group(1)}"

            # Get phy info for bands
            if phy:
                result = subprocess.run(
                    ["iw", "phy", phy, "info"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Check for 2.4GHz (channels 1-14)
                    if re.search(r"\*\s*24\d\d MHz", result.stdout):
                        bands.append("2.4GHz")
                    # Check for 5GHz (channels in 5xxx MHz range)
                    if re.search(r"\*\s*5\d\d\d MHz", result.stdout):
                        bands.append("5GHz")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"iw info failed for {interface}: {e}")

        return phy, bands

    def _get_current_mode(self, interface: str) -> str:
        """Get the current mode of the interface."""
        try:
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                if "type monitor" in result.stdout:
                    return "monitor"
                elif "type managed" in result.stdout:
                    return "managed"
                elif "type AP" in result.stdout:
                    return "ap"
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

        return "managed"

    def _check_connected(self, interface: str) -> bool:
        """Check if the interface is connected to a network."""
        try:
            result = subprocess.run(
                ["iw", "dev", interface, "link"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return "Connected to" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

        return False

    def get_monitor_adapter(self) -> Optional[WiFiAdapter]:
        """
        Get the best adapter for monitor mode.

        Priority:
        1. Already in monitor mode
        2. Injection capable + not connected
        3. Monitor capable + not connected
        4. Any monitor capable
        """
        adapters = self.detect_adapters()

        # First, check for already in monitor mode
        for adapter in adapters:
            if adapter.current_mode == "monitor":
                return adapter

        # Second, injection capable and not connected
        for adapter in adapters:
            if adapter.injection_capable and not adapter.connected:
                return adapter

        # Third, monitor capable and not connected
        for adapter in adapters:
            if adapter.monitor_capable and not adapter.connected:
                return adapter

        # Finally, any monitor capable
        for adapter in adapters:
            if adapter.monitor_capable:
                return adapter

        return None

    def get_managed_adapter(self) -> Optional[WiFiAdapter]:
        """Get adapter for normal network connections (not for hunting)."""
        adapters = self.detect_adapters()

        # Prefer connected adapter
        for adapter in adapters:
            if adapter.connected and adapter.current_mode == "managed":
                return adapter

        # Any managed adapter
        for adapter in adapters:
            if adapter.current_mode == "managed":
                return adapter

        return None

    async def enable_monitor_mode(self, interface: str) -> Tuple[bool, str]:
        """
        Enable monitor mode on an interface.

        Returns (success, new_interface_name_or_error)
        """
        # Check if adapter supports monitor mode
        adapter = None
        for a in self.detect_adapters():
            if a.interface == interface:
                adapter = a
                break

        if not adapter:
            return False, f"Interface not found: {interface}"

        if not adapter.monitor_capable:
            return False, f"Interface {interface} does not support monitor mode"

        if adapter.current_mode == "monitor":
            return True, interface  # Already in monitor mode

        try:
            # Method 1: Try airmon-ng (preferred)
            result = await asyncio.create_subprocess_exec(
                "airmon-ng", "start", interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=30)

            if result.returncode == 0:
                # Parse output for new interface name
                output = stdout.decode()
                mon_match = re.search(r"\(monitor mode vif enabled (?:for \[\w+\] )?on \[(\w+)\]", output)
                if mon_match:
                    new_iface = mon_match.group(1)
                else:
                    new_iface = f"{interface}mon"

                # Refresh adapter list
                self.detect_adapters(refresh=True)
                return True, new_iface
        except FileNotFoundError:
            pass  # airmon-ng not installed, try manual method
        except asyncio.TimeoutExpired:
            return False, "airmon-ng timed out"
        except Exception as e:
            logger.debug(f"airmon-ng failed: {e}")

        # Method 2: Manual using iw
        try:
            # Bring interface down
            await asyncio.create_subprocess_exec(
                "ip", "link", "set", interface, "down",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            # Set monitor mode
            result = await asyncio.create_subprocess_exec(
                "iw", interface, "set", "type", "monitor",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=10)

            if result.returncode != 0:
                # Bring back up in managed mode
                await asyncio.create_subprocess_exec(
                    "ip", "link", "set", interface, "up",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                return False, f"Failed to set monitor mode: {stderr.decode()}"

            # Bring interface up
            await asyncio.create_subprocess_exec(
                "ip", "link", "set", interface, "up",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            # Refresh adapter list
            self.detect_adapters(refresh=True)
            return True, interface
        except asyncio.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    async def disable_monitor_mode(self, interface: str) -> Tuple[bool, str]:
        """
        Disable monitor mode on an interface.

        Returns (success, interface_name_or_error)
        """
        try:
            # Method 1: Try airmon-ng
            result = await asyncio.create_subprocess_exec(
                "airmon-ng", "stop", interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=30)

            if result.returncode == 0:
                # Parse output for original interface name
                output = stdout.decode()
                iface_match = re.search(r"\(monitor mode disabled on \[\w+\]\)", output)
                if iface_match:
                    # Extract original interface (usually removes 'mon' suffix)
                    new_iface = interface.replace("mon", "")
                else:
                    new_iface = interface

                # Refresh adapter list
                self.detect_adapters(refresh=True)
                return True, new_iface
        except FileNotFoundError:
            pass  # airmon-ng not installed
        except asyncio.TimeoutExpired:
            return False, "airmon-ng timed out"
        except Exception as e:
            logger.debug(f"airmon-ng stop failed: {e}")

        # Method 2: Manual using iw
        try:
            # Bring interface down
            await asyncio.create_subprocess_exec(
                "ip", "link", "set", interface, "down",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            # Set managed mode
            result = await asyncio.create_subprocess_exec(
                "iw", interface, "set", "type", "managed",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=10)

            # Bring interface up
            await asyncio.create_subprocess_exec(
                "ip", "link", "set", interface, "up",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            # Refresh adapter list
            self.detect_adapters(refresh=True)
            return True, interface
        except asyncio.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def get_status(self) -> dict:
        """Get overall adapter status for display."""
        adapters = self.detect_adapters(refresh=True)
        monitor_adapter = self.get_monitor_adapter()
        managed_adapter = self.get_managed_adapter()

        return {
            "adapters": [a.to_dict() for a in adapters],
            "total": len(adapters),
            "monitor_capable": sum(1 for a in adapters if a.monitor_capable),
            "injection_capable": sum(1 for a in adapters if a.injection_capable),
            "in_monitor_mode": sum(1 for a in adapters if a.current_mode == "monitor"),
            "best_monitor_adapter": monitor_adapter.interface if monitor_adapter else None,
            "managed_adapter": managed_adapter.interface if managed_adapter else None,
        }
