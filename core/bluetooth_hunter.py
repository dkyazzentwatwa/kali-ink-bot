"""
Project Inkling - Bluetooth Hunter

Bluetooth Classic and BLE scanning/reconnaissance module.
Optimized for Raspberry Pi Zero 2W with Kali Linux.
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Bluetooth device class major codes (bits 12-8)
MAJOR_DEVICE_CLASSES = {
    0x00: "miscellaneous",
    0x01: "computer",
    0x02: "phone",
    0x03: "network",
    0x04: "audio_video",
    0x05: "peripheral",
    0x06: "imaging",
    0x07: "wearable",
    0x08: "toy",
    0x09: "health",
    0x1F: "uncategorized",
}

# Minor device classes for computers (major class 0x01)
COMPUTER_MINOR_CLASSES = {
    0x00: "uncategorized",
    0x01: "desktop",
    0x02: "server",
    0x03: "laptop",
    0x04: "handheld",
    0x05: "palm",
    0x06: "wearable",
    0x07: "tablet",
}

# Minor device classes for phones (major class 0x02)
PHONE_MINOR_CLASSES = {
    0x00: "uncategorized",
    0x01: "cellular",
    0x02: "cordless",
    0x03: "smartphone",
    0x04: "modem",
    0x05: "isdn",
}

# Minor device classes for audio/video (major class 0x04)
AUDIO_MINOR_CLASSES = {
    0x01: "headset",
    0x02: "handsfree",
    0x04: "microphone",
    0x05: "loudspeaker",
    0x06: "headphones",
    0x07: "portable_audio",
    0x08: "car_audio",
    0x09: "settop_box",
    0x0A: "hifi_audio",
    0x0B: "vcr",
    0x0C: "video_camera",
    0x0D: "camcorder",
    0x0E: "video_monitor",
    0x0F: "video_display",
    0x10: "video_conferencing",
    0x12: "gaming",
}

# Minor device classes for peripherals (major class 0x05)
PERIPHERAL_MINOR_CLASSES = {
    0x01: "keyboard",
    0x02: "mouse",
    0x03: "combo",
    0x04: "joystick",
    0x05: "gamepad",
    0x06: "remote",
    0x07: "sensing",
    0x08: "digitizer",
    0x09: "card_reader",
    0x0A: "pen",
    0x0B: "scanner",
    0x0C: "wand",
}


@dataclass
class BTDevice:
    """Bluetooth device information."""
    address: str
    name: Optional[str] = None
    device_class: str = "unknown"
    rssi: int = 0
    services: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    ble: bool = False
    manufacturer: Optional[str] = None
    raw_class: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "address": self.address,
            "name": self.name,
            "device_class": self.device_class,
            "rssi": self.rssi,
            "services": self.services,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "ble": self.ble,
            "manufacturer": self.manufacturer,
            "raw_class": self.raw_class,
        }


def _parse_device_class(class_int: int) -> str:
    """
    Convert Bluetooth device class integer to human-readable category.

    The device class is a 24-bit field:
    - Bits 12-8: Major device class
    - Bits 7-2: Minor device class
    - Bits 1-0: Format type

    Returns a simplified category string.
    """
    if class_int == 0:
        return "unknown"

    # Extract major class (bits 12-8)
    major_class = (class_int >> 8) & 0x1F
    # Extract minor class (bits 7-2)
    minor_class = (class_int >> 2) & 0x3F

    major_name = MAJOR_DEVICE_CLASSES.get(major_class, "unknown")

    # Refine based on minor class
    if major_class == 0x01:  # Computer
        minor_name = COMPUTER_MINOR_CLASSES.get(minor_class, major_name)
        if minor_name in ["laptop", "desktop", "server", "tablet"]:
            return minor_name
        return "computer"

    elif major_class == 0x02:  # Phone
        minor_name = PHONE_MINOR_CLASSES.get(minor_class, major_name)
        if minor_name == "smartphone":
            return "phone"
        return "phone"

    elif major_class == 0x04:  # Audio/Video
        minor_name = AUDIO_MINOR_CLASSES.get(minor_class, major_name)
        if minor_name in ["headset", "headphones", "handsfree"]:
            return "headset"
        if minor_name in ["loudspeaker", "portable_audio", "hifi_audio"]:
            return "speaker"
        return "audio"

    elif major_class == 0x05:  # Peripheral
        minor_name = PERIPHERAL_MINOR_CLASSES.get(minor_class, major_name)
        if minor_name in ["keyboard", "combo"]:
            return "keyboard"
        if minor_name in ["mouse"]:
            return "mouse"
        if minor_name in ["joystick", "gamepad"]:
            return "gamepad"
        return "peripheral"

    elif major_class == 0x07:  # Wearable
        return "wearable"

    elif major_class == 0x09:  # Health
        return "health"

    return major_name if major_name != "unknown" else "other"


async def _run_subprocess(
    *args: str,
    timeout: float = 30.0,
) -> tuple[int, str, str]:
    """
    Run a subprocess asynchronously with timeout.

    Returns (return_code, stdout, stderr).
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )

        return (
            process.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )

    except asyncio.TimeoutError:
        try:
            process.terminate()
            await asyncio.sleep(0.1)
            process.kill()
        except Exception:
            pass
        return (-1, "", "Command timed out")

    except FileNotFoundError as e:
        return (-1, "", f"Command not found: {e}")

    except Exception as e:
        return (-1, "", f"Error: {e}")


class BluetoothHunter:
    """
    Bluetooth scanner for Classic and BLE devices.

    Uses hcitool and optionally bleak for scanning.
    Caches discovered devices for later retrieval.
    """

    MAX_DEVICES = 500  # Maximum cached devices

    def __init__(self, data_dir: str = "~/.inkling/bluetooth"):
        """
        Initialize Bluetooth hunter.

        Args:
            data_dir: Directory for storing device cache
        """
        self.data_dir = Path(data_dir).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._devices: Dict[str, BTDevice] = {}
        self._bleak_available: Optional[bool] = None
        self._load_cache()

    def _get_cache_path(self) -> Path:
        """Get path to device cache file."""
        return self.data_dir / "devices.json"

    def _load_cache(self) -> None:
        """Load cached devices from disk."""
        cache_path = self._get_cache_path()
        if cache_path.exists():
            try:
                with open(cache_path, "r") as f:
                    data = json.load(f)
                    for addr, device_data in data.items():
                        self._devices[addr] = BTDevice(
                            address=device_data["address"],
                            name=device_data.get("name"),
                            device_class=device_data.get("device_class", "unknown"),
                            rssi=device_data.get("rssi", 0),
                            services=device_data.get("services", []),
                            first_seen=device_data.get("first_seen", time.time()),
                            last_seen=device_data.get("last_seen", time.time()),
                            ble=device_data.get("ble", False),
                            manufacturer=device_data.get("manufacturer"),
                            raw_class=device_data.get("raw_class", 0),
                        )
                logger.debug(f"Loaded {len(self._devices)} devices from cache")
            except Exception as e:
                logger.warning(f"Failed to load Bluetooth cache: {e}")

    def _save_cache(self) -> None:
        """Save device cache to disk."""
        # Prune old devices if over limit
        if len(self._devices) > self.MAX_DEVICES:
            sorted_devices = sorted(
                self._devices.items(),
                key=lambda x: x[1].last_seen,
                reverse=True,
            )
            self._devices = dict(sorted_devices[:self.MAX_DEVICES])

        try:
            cache_path = self._get_cache_path()
            data = {addr: dev.to_dict() for addr, dev in self._devices.items()}
            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved {len(self._devices)} devices to cache")
        except Exception as e:
            logger.warning(f"Failed to save Bluetooth cache: {e}")

    async def _check_bleak(self) -> bool:
        """Check if bleak library is available."""
        if self._bleak_available is not None:
            return self._bleak_available

        try:
            import bleak  # noqa: F401
            self._bleak_available = True
            logger.debug("Bleak library available for BLE scanning")
        except ImportError:
            self._bleak_available = False
            logger.debug("Bleak library not available, falling back to hcitool")

        return self._bleak_available

    async def _run_hcitool_scan(self, duration: int = 10) -> List[BTDevice]:
        """
        Run hcitool scan for Bluetooth Classic devices.

        Args:
            duration: Scan duration in seconds

        Returns:
            List of discovered devices
        """
        devices: List[BTDevice] = []

        # Run inquiry scan
        # hcitool scan output format: "XX:XX:XX:XX:XX:XX	Device Name"
        returncode, stdout, stderr = await _run_subprocess(
            "hcitool", "scan", "--flush",
            timeout=duration + 5,
        )

        if returncode != 0:
            if "not found" in stderr.lower():
                logger.warning("hcitool not installed")
                return []
            if "no such device" in stderr.lower():
                logger.warning("No Bluetooth adapter found")
                return []
            logger.debug(f"hcitool scan failed: {stderr}")
            return []

        # Parse scan results
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("Scanning"):
                continue

            # Match MAC address and optional name
            match = re.match(
                r"([0-9A-Fa-f:]{17})\s*(.*)",
                line,
            )
            if match:
                address = match.group(1).upper()
                name = match.group(2).strip() or None

                device = BTDevice(
                    address=address,
                    name=name,
                    ble=False,
                )
                devices.append(device)

        # Get device class information using hcitool inq
        returncode, stdout, stderr = await _run_subprocess(
            "hcitool", "inq",
            timeout=duration + 5,
        )

        if returncode == 0:
            # Parse inquiry results for class info
            # Format: "XX:XX:XX:XX:XX:XX	clock offset: 0x1234	class: 0x5a020c"
            for line in stdout.strip().split("\n"):
                match = re.search(
                    r"([0-9A-Fa-f:]{17}).*class:\s*(0x[0-9A-Fa-f]+)",
                    line,
                )
                if match:
                    address = match.group(1).upper()
                    class_hex = match.group(2)
                    try:
                        class_int = int(class_hex, 16)
                        device_class = _parse_device_class(class_int)

                        # Update existing device or add new one
                        found = False
                        for dev in devices:
                            if dev.address == address:
                                dev.device_class = device_class
                                dev.raw_class = class_int
                                found = True
                                break

                        if not found:
                            devices.append(BTDevice(
                                address=address,
                                device_class=device_class,
                                raw_class=class_int,
                                ble=False,
                            ))
                    except ValueError:
                        pass

        return devices

    async def _run_hcitool_lescan(self, duration: int = 10) -> List[BTDevice]:
        """
        Run hcitool lescan for BLE devices.

        Note: lescan requires root privileges.

        Args:
            duration: Scan duration in seconds

        Returns:
            List of discovered BLE devices
        """
        devices: List[BTDevice] = []
        seen_addresses: set = set()

        # lescan runs indefinitely, so we need to kill it after duration
        try:
            process = await asyncio.create_subprocess_exec(
                "sudo", "hcitool", "lescan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Read output for specified duration
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(),
                        timeout=1.0,
                    )
                    if not line:
                        break

                    line = line.decode("utf-8", errors="replace").strip()

                    # Skip header
                    if "LE Scan" in line:
                        continue

                    # Parse: "XX:XX:XX:XX:XX:XX Device Name" or just address
                    match = re.match(
                        r"([0-9A-Fa-f:]{17})\s*(.*)",
                        line,
                    )
                    if match:
                        address = match.group(1).upper()
                        name = match.group(2).strip() or None

                        if address not in seen_addresses:
                            seen_addresses.add(address)
                            devices.append(BTDevice(
                                address=address,
                                name=name,
                                ble=True,
                            ))

                except asyncio.TimeoutError:
                    continue

            # Terminate lescan
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                process.kill()

        except FileNotFoundError:
            logger.warning("hcitool not installed")
        except PermissionError:
            logger.warning("BLE scan requires root privileges")
        except Exception as e:
            logger.debug(f"BLE scan error: {e}")

        return devices

    async def _run_bleak_scan(self, duration: int = 10) -> List[BTDevice]:
        """
        Run BLE scan using bleak library.

        Args:
            duration: Scan duration in seconds

        Returns:
            List of discovered BLE devices
        """
        try:
            from bleak import BleakScanner

            devices: List[BTDevice] = []

            discovered = await BleakScanner.discover(timeout=duration)

            for d in discovered:
                # Get RSSI and manufacturer data
                rssi = d.rssi if hasattr(d, "rssi") else 0
                manufacturer = None

                # Extract manufacturer from advertisement data
                if hasattr(d, "metadata"):
                    mfr_data = d.metadata.get("manufacturer_data", {})
                    if mfr_data:
                        # First manufacturer ID found
                        mfr_id = next(iter(mfr_data.keys()), None)
                        if mfr_id:
                            manufacturer = self._lookup_manufacturer(mfr_id)

                device = BTDevice(
                    address=d.address.upper(),
                    name=d.name,
                    rssi=rssi,
                    ble=True,
                    manufacturer=manufacturer,
                )
                devices.append(device)

            return devices

        except ImportError:
            logger.debug("Bleak not available")
            return []
        except Exception as e:
            logger.debug(f"Bleak scan error: {e}")
            return []

    def _lookup_manufacturer(self, mfr_id: int) -> Optional[str]:
        """
        Look up manufacturer name from Bluetooth SIG company ID.

        Common IDs only - full list at bluetooth.com/specifications/assigned-numbers/
        """
        manufacturers = {
            0x004C: "Apple",
            0x0006: "Microsoft",
            0x000F: "Broadcom",
            0x00E0: "Google",
            0x0075: "Samsung",
            0x0087: "Garmin",
            0x00D2: "Huawei",
            0x0310: "Xiaomi",
            0x038F: "Amazfit",
            0x0171: "Amazon",
            0x0157: "Fitbit",
            0x02FF: "Tile",
            0x0059: "Nordic Semiconductor",
            0x0046: "Sony",
            0x002D: "Texas Instruments",
            0x000D: "Texas Instruments",
            0x001D: "Qualcomm",
            0x0131: "Bose",
            0x009E: "Bose",
            0x0080: "Logitech",
            0x00AA: "Beats",
        }
        return manufacturers.get(mfr_id)

    async def scan_classic(self, duration: int = 10) -> List[BTDevice]:
        """
        Scan for Bluetooth Classic devices.

        Args:
            duration: Scan duration in seconds (default 10)

        Returns:
            List of discovered BTDevice objects
        """
        logger.info(f"Starting Bluetooth Classic scan ({duration}s)...")

        devices = await self._run_hcitool_scan(duration)

        # Update cache
        now = time.time()
        for device in devices:
            if device.address in self._devices:
                # Update existing device
                existing = self._devices[device.address]
                existing.last_seen = now
                if device.name and not existing.name:
                    existing.name = device.name
                if device.device_class != "unknown":
                    existing.device_class = device.device_class
                if device.raw_class:
                    existing.raw_class = device.raw_class
            else:
                # Add new device
                device.first_seen = now
                device.last_seen = now
                self._devices[device.address] = device

        self._save_cache()

        logger.info(f"Classic scan complete: {len(devices)} devices found")
        return devices

    async def scan_ble(self, duration: int = 10) -> List[BTDevice]:
        """
        Scan for Bluetooth Low Energy devices.

        Uses bleak library if available, otherwise falls back to hcitool lescan.

        Args:
            duration: Scan duration in seconds (default 10)

        Returns:
            List of discovered BTDevice objects
        """
        logger.info(f"Starting BLE scan ({duration}s)...")

        # Try bleak first
        if await self._check_bleak():
            devices = await self._run_bleak_scan(duration)
        else:
            # Fallback to hcitool lescan
            devices = await self._run_hcitool_lescan(duration)

        # Update cache
        now = time.time()
        for device in devices:
            if device.address in self._devices:
                # Update existing device
                existing = self._devices[device.address]
                existing.last_seen = now
                existing.ble = True
                if device.name and not existing.name:
                    existing.name = device.name
                if device.rssi:
                    existing.rssi = device.rssi
                if device.manufacturer:
                    existing.manufacturer = device.manufacturer
            else:
                # Add new device
                device.first_seen = now
                device.last_seen = now
                self._devices[device.address] = device

        self._save_cache()

        logger.info(f"BLE scan complete: {len(devices)} devices found")
        return devices

    async def scan_all(self, duration: int = 10) -> List[BTDevice]:
        """
        Scan for both Classic and BLE devices.

        Args:
            duration: Duration for each scan type

        Returns:
            Combined list of discovered devices
        """
        logger.info(f"Starting combined Bluetooth scan ({duration}s each)...")

        # Run scans concurrently
        classic_task = asyncio.create_task(self.scan_classic(duration))
        ble_task = asyncio.create_task(self.scan_ble(duration))

        classic_devices = await classic_task
        ble_devices = await ble_task

        # Merge results (BLE devices may overlap with classic)
        all_addresses = set()
        all_devices = []

        for device in classic_devices:
            all_addresses.add(device.address)
            all_devices.append(device)

        for device in ble_devices:
            if device.address not in all_addresses:
                all_devices.append(device)

        return all_devices

    async def enumerate_services(self, address: str) -> List[str]:
        """
        Enumerate services on a Bluetooth Classic device.

        Uses sdptool browse for service discovery.

        Args:
            address: Bluetooth MAC address

        Returns:
            List of service names/descriptions
        """
        logger.info(f"Enumerating services for {address}...")

        services: List[str] = []

        returncode, stdout, stderr = await _run_subprocess(
            "sdptool", "browse", address,
            timeout=30.0,
        )

        if returncode != 0:
            if "not found" in stderr.lower():
                logger.warning("sdptool not installed")
                return []
            logger.debug(f"Service enumeration failed: {stderr}")
            return []

        # Parse sdptool output
        # Service Name: OBEX Object Push
        # Service RecHandle: 0x10002
        # Service Class ID List:
        #   "OBEX Object Push" (0x1105)
        current_service = None
        for line in stdout.split("\n"):
            line = line.strip()

            if line.startswith("Service Name:"):
                current_service = line.replace("Service Name:", "").strip()
                if current_service and current_service not in services:
                    services.append(current_service)

            elif '"' in line and "0x" in line:
                # Extract service class name from quotes
                match = re.search(r'"([^"]+)"', line)
                if match:
                    service_name = match.group(1)
                    if service_name not in services:
                        services.append(service_name)

        # Update cache
        if address in self._devices:
            self._devices[address].services = services
            self._save_cache()

        logger.info(f"Found {len(services)} services on {address}")
        return services

    async def enumerate_ble_services(self, address: str) -> List[str]:
        """
        Enumerate GATT services on a BLE device.

        Requires bleak library.

        Args:
            address: Bluetooth MAC address

        Returns:
            List of service UUIDs/names
        """
        if not await self._check_bleak():
            logger.warning("Bleak required for BLE service enumeration")
            return []

        try:
            from bleak import BleakClient

            services: List[str] = []

            async with BleakClient(address, timeout=10.0) as client:
                for service in client.services:
                    # Get service description or UUID
                    desc = service.description or str(service.uuid)
                    services.append(desc)

            # Update cache
            if address in self._devices:
                self._devices[address].services = services
                self._save_cache()

            logger.info(f"Found {len(services)} BLE services on {address}")
            return services

        except Exception as e:
            logger.debug(f"BLE service enumeration failed: {e}")
            return []

    def get_device(self, address: str) -> Optional[BTDevice]:
        """
        Get a cached device by MAC address.

        Args:
            address: Bluetooth MAC address (case-insensitive)

        Returns:
            BTDevice if found, None otherwise
        """
        return self._devices.get(address.upper())

    def list_devices(
        self,
        ble_only: bool = False,
        classic_only: bool = False,
        limit: int = 100,
    ) -> List[BTDevice]:
        """
        List all cached devices.

        Args:
            ble_only: Only return BLE devices
            classic_only: Only return Classic devices
            limit: Maximum number of devices to return

        Returns:
            List of BTDevice objects, sorted by last_seen (most recent first)
        """
        devices = list(self._devices.values())

        if ble_only:
            devices = [d for d in devices if d.ble]
        elif classic_only:
            devices = [d for d in devices if not d.ble]

        # Sort by last_seen descending
        devices.sort(key=lambda d: d.last_seen, reverse=True)

        return devices[:limit]

    def clear_cache(self) -> int:
        """
        Clear the device cache.

        Returns:
            Number of devices cleared
        """
        count = len(self._devices)
        self._devices.clear()
        self._save_cache()
        logger.info(f"Cleared {count} devices from cache")
        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about discovered devices."""
        devices = list(self._devices.values())

        # Count by type
        ble_count = sum(1 for d in devices if d.ble)
        classic_count = len(devices) - ble_count

        # Count by device class
        class_counts: Dict[str, int] = {}
        for d in devices:
            cls = d.device_class
            class_counts[cls] = class_counts.get(cls, 0) + 1

        # Recent devices (last 24 hours)
        day_ago = time.time() - 86400
        recent_count = sum(1 for d in devices if d.last_seen > day_ago)

        return {
            "total_devices": len(devices),
            "ble_devices": ble_count,
            "classic_devices": classic_count,
            "devices_last_24h": recent_count,
            "by_class": class_counts,
        }

    @staticmethod
    def format_device(device: BTDevice) -> str:
        """Format a device for display."""
        lines = []

        name = device.name or "(unnamed)"
        lines.append(f"  {device.address} - {name}")

        details = []
        if device.device_class != "unknown":
            details.append(device.device_class)
        if device.ble:
            details.append("BLE")
        else:
            details.append("Classic")
        if device.rssi:
            details.append(f"{device.rssi}dBm")
        if device.manufacturer:
            details.append(device.manufacturer)

        if details:
            lines.append(f"    [{', '.join(details)}]")

        if device.services:
            lines.append(f"    Services: {', '.join(device.services[:5])}")
            if len(device.services) > 5:
                lines.append(f"    ... and {len(device.services) - 5} more")

        return "\n".join(lines)

    @staticmethod
    def format_scan_summary(devices: List[BTDevice]) -> str:
        """Format scan results for display."""
        if not devices:
            return "No devices found"

        lines = [f"Found {len(devices)} device(s):"]
        for device in devices[:20]:
            name = device.name or "(unnamed)"
            device_type = "BLE" if device.ble else "Classic"
            rssi_str = f" ({device.rssi}dBm)" if device.rssi else ""
            lines.append(f"  {device.address} - {name} [{device_type}]{rssi_str}")

        if len(devices) > 20:
            lines.append(f"  ... and {len(devices) - 20} more")

        return "\n".join(lines)
