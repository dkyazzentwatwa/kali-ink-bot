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

    # Broadcom - Pi Zero 2W built-in WiFi
    # With Nexmon patch, brcmfmac CAN do monitor mode!
    # We'll check dynamically if monitor mode is supported
    "brcmfmac": {"name": "Broadcom BCM43430/43455 (Pi WiFi)", "monitor": True, "injection": True},
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

        Tries methods in order:
        1. Nexmon monstart.sh script (if installed)
        2. Pwnagotchi-style iw commands
        3. airmon-ng fallback

        Returns (success, new_interface_name_or_error)
        """
        # Check if adapter exists
        adapter = None
        for a in self.detect_adapters():
            if a.interface == interface:
                adapter = a
                break

        if not adapter:
            return False, f"Interface not found: {interface}"

        # Check if already in monitor mode or monitor interface exists
        mon_interface = f"{interface}mon"
        for a in self._adapters:
            if a.interface == mon_interface and a.current_mode == "monitor":
                return True, mon_interface

        if adapter.current_mode == "monitor":
            return True, interface

        async def run_cmd(*args, timeout: int = 10) -> Tuple[int, str, str]:
            """Helper to run command and return (returncode, stdout, stderr)."""
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return proc.returncode, stdout.decode(), stderr.decode()
            except FileNotFoundError:
                return -1, "", f"Command not found: {args[0]}"
            except asyncio.TimeoutExpired:
                return -1, "", "Command timed out"

        # Method 1: Try Nexmon monstart.sh script if installed
        nexmon_script = Path("/opt/nexmon/scripts/monstart.sh")
        if nexmon_script.exists():
            logger.info("Using Nexmon monstart.sh script")
            ret, stdout, stderr = await run_cmd(str(nexmon_script), interface, timeout=30)
            if ret == 0:
                self.detect_adapters(refresh=True)
                # Check if monitor interface was created
                for a in self._adapters:
                    if a.interface == mon_interface and a.current_mode == "monitor":
                        logger.info(f"Nexmon enabled monitor mode: {mon_interface}")
                        return True, mon_interface
                # Maybe it used the same interface name
                for a in self._adapters:
                    if a.interface == interface and a.current_mode == "monitor":
                        return True, interface
            else:
                logger.warning(f"Nexmon script failed: {stderr}, falling back to manual method")

        try:
            # Step 1: Unblock rfkill
            await run_cmd("rfkill", "unblock", "all")

            # Step 2: Bring interface up
            ret, _, err = await run_cmd("ifconfig", interface, "up")
            if ret != 0:
                # Try ip link as fallback
                await run_cmd("ip", "link", "set", interface, "up")

            # Step 3: Disable power save
            await run_cmd("iw", "dev", interface, "set", "power_save", "off")

            # Step 4: Get phy name for this interface
            ret, stdout, _ = await run_cmd("iw", "dev", interface, "info")
            if ret != 0:
                return False, f"Failed to get interface info: {interface}"

            phy_match = re.search(r"wiphy (\d+)", stdout)
            if not phy_match:
                return False, "Could not determine phy for interface"

            phy = f"phy{phy_match.group(1)}"

            # Step 5: Create monitor interface (Pwnagotchi style)
            ret, _, err = await run_cmd(
                "iw", "phy", phy, "interface", "add", mon_interface, "type", "monitor"
            )
            if ret != 0:
                # Interface might already exist, try removing and recreating
                await run_cmd("iw", "dev", mon_interface, "del")
                ret, _, err = await run_cmd(
                    "iw", "phy", phy, "interface", "add", mon_interface, "type", "monitor"
                )
                if ret != 0:
                    # Fallback: try setting existing interface to monitor mode
                    await run_cmd("ip", "link", "set", interface, "down")
                    ret, _, err = await run_cmd("iw", interface, "set", "type", "monitor")
                    if ret != 0:
                        await run_cmd("ip", "link", "set", interface, "up")
                        return False, f"Failed to enable monitor mode: {err}"
                    await run_cmd("ip", "link", "set", interface, "up")
                    self.detect_adapters(refresh=True)
                    return True, interface

            # Step 6: Bring monitor interface up
            ret, _, err = await run_cmd("ifconfig", mon_interface, "up")
            if ret != 0:
                await run_cmd("ip", "link", "set", mon_interface, "up")

            # Refresh adapter list
            self.detect_adapters(refresh=True)
            logger.info(f"Monitor mode enabled: {mon_interface}")
            return True, mon_interface

        except Exception as e:
            logger.exception("Failed to enable monitor mode")
            return False, str(e)

    async def disable_monitor_mode(self, interface: str) -> Tuple[bool, str]:
        """
        Disable monitor mode on an interface.

        Tries methods in order:
        1. Nexmon monstop.sh script (if installed)
        2. Manual iw commands

        Returns (success, interface_name_or_error)
        """
        async def run_cmd(*args, timeout: int = 10) -> Tuple[int, str, str]:
            """Helper to run command."""
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return proc.returncode, stdout.decode(), stderr.decode()
            except FileNotFoundError:
                return -1, "", f"Command not found: {args[0]}"
            except asyncio.TimeoutExpired:
                return -1, "", "Command timed out"

        # Determine original interface name
        if interface.endswith("mon"):
            orig_interface = interface[:-3]  # Remove 'mon' suffix
        else:
            orig_interface = interface

        # Method 1: Try Nexmon monstop.sh script if installed
        nexmon_script = Path("/opt/nexmon/scripts/monstop.sh")
        if nexmon_script.exists():
            logger.info("Using Nexmon monstop.sh script")
            ret, _, stderr = await run_cmd(str(nexmon_script), orig_interface, timeout=30)
            if ret == 0:
                self.detect_adapters(refresh=True)
                logger.info(f"Nexmon disabled monitor mode: {orig_interface}")
                return True, orig_interface
            else:
                logger.warning(f"Nexmon script failed: {stderr}, falling back to manual method")

        try:
            # Step 1: Bring monitor interface down and delete it
            await run_cmd("ifconfig", interface, "down")
            await run_cmd("ip", "link", "set", interface, "down")

            # Step 2: Delete the monitor interface (if it's a separate vif)
            ret, _, _ = await run_cmd("iw", "dev", interface, "del")

            if ret != 0 and interface == orig_interface:
                # Interface wasn't a separate vif, set back to managed mode
                await run_cmd("iw", interface, "set", "type", "managed")
                await run_cmd("ip", "link", "set", interface, "up")

            # Step 3: Bring original interface back up
            await run_cmd("ifconfig", orig_interface, "up")
            await run_cmd("ip", "link", "set", orig_interface, "up")

            # Refresh adapter list
            self.detect_adapters(refresh=True)
            logger.info(f"Monitor mode disabled: {interface} -> {orig_interface}")
            return True, orig_interface

        except Exception as e:
            logger.exception("Failed to disable monitor mode")
            return False, str(e)

    async def _disable_monitor_mode_airmon(self, interface: str) -> Tuple[bool, str]:
        """Legacy airmon-ng method (kept for reference)."""
        try:
            result = await asyncio.create_subprocess_exec(
                "airmon-ng", "stop", interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=30)

            if result.returncode == 0:
                output = stdout.decode()
                iface_match = re.search(r"\(monitor mode disabled on \[\w+\]\)", output)
                if iface_match:
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
