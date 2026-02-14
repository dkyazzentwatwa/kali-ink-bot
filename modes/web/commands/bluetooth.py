"""Bluetooth command handlers for web mode."""
import asyncio
import time
from typing import Any, Dict

from . import CommandHandler


class BluetoothCommands(CommandHandler):
    """Bluetooth hunting command handlers."""

    def _get_mode_manager(self):
        """Get or create mode manager instance."""
        if not hasattr(self.web_mode, '_mode_manager'):
            from core.mode_manager import ModeManager
            config = self._config
            modes_cfg = config.get("modes", {})
            from core.mode_manager import OperationMode
            default_mode = OperationMode(modes_cfg.get("default", "pentest"))
            auto_switch = modes_cfg.get("auto_switch_on_adapter", True)
            self.web_mode._mode_manager = ModeManager(
                default_mode=default_mode,
                auto_switch_on_adapter=auto_switch,
            )
        return self.web_mode._mode_manager

    def _get_bt_hunter(self):
        """Get or create Bluetooth hunter instance."""
        if not hasattr(self.web_mode, '_bt_hunter'):
            try:
                from core.bluetooth_hunter import BluetoothHunter
                self.web_mode._bt_hunter = BluetoothHunter()
            except ImportError:
                return None
        return self.web_mode._bt_hunter

    def bt_scan(self, args: str = "") -> Dict[str, Any]:
        """Scan for classic Bluetooth devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return {
                "response": "Bluetooth hunter not available. Check dependencies.",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

        # Parse duration
        duration = 10
        if args.strip():
            try:
                duration = int(args.strip())
            except ValueError:
                pass

        try:
            future = asyncio.run_coroutine_threadsafe(
                hunter.scan_classic(duration),
                self._loop
            )
            devices = future.result(timeout=duration + 10)

            if not devices:
                return {
                    "response": f"No Bluetooth devices found (scanned for {duration}s).",
                    "face": self._get_face_str(),
                    "status": "bluetooth",
                }

            lines = [f"Bluetooth Devices Found ({len(devices)}):"]
            lines.append("-" * 60)
            lines.append(f"{'Address':<18} {'Name':<20} {'Class':<12} {'RSSI'}")
            lines.append("-" * 60)

            for d in devices:
                name = (d.name or "Unknown")[:18]
                dev_class = d.device_class[:10]
                rssi = f"{d.rssi} dBm" if d.rssi else "N/A"
                lines.append(f"{d.address:<18} {name:<20} {dev_class:<12} {rssi}")

            return {
                "response": "\n".join(lines),
                "face": self._get_face_str(),
                "status": "bluetooth",
            }
        except asyncio.TimeoutError:
            return {
                "response": "Bluetooth scan timed out.",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }
        except Exception as e:
            return {
                "response": f"Scan error: {e}",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

    def ble_scan(self, args: str = "") -> Dict[str, Any]:
        """Scan for BLE devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return {
                "response": "Bluetooth hunter not available. Check dependencies.",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

        # Parse duration
        duration = 10
        if args.strip():
            try:
                duration = int(args.strip())
            except ValueError:
                pass

        try:
            future = asyncio.run_coroutine_threadsafe(
                hunter.scan_ble(duration),
                self._loop
            )
            devices = future.result(timeout=duration + 10)

            if not devices:
                return {
                    "response": f"No BLE devices found (scanned for {duration}s).",
                    "face": self._get_face_str(),
                    "status": "bluetooth",
                }

            lines = [f"BLE Devices Found ({len(devices)}):"]
            lines.append("-" * 60)
            lines.append(f"{'Address':<18} {'Name':<25} {'RSSI'}")
            lines.append("-" * 60)

            for d in devices:
                name = (d.name or "Unknown")[:23]
                rssi = f"{d.rssi} dBm" if d.rssi else "N/A"
                lines.append(f"{d.address:<18} {name:<25} {rssi}")

            return {
                "response": "\n".join(lines),
                "face": self._get_face_str(),
                "status": "bluetooth",
            }
        except asyncio.TimeoutError:
            return {
                "response": "BLE scan timed out.",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }
        except Exception as e:
            return {
                "response": f"BLE scan error: {e}",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

    def bt_devices(self, args: str = "") -> Dict[str, Any]:
        """List known Bluetooth devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return {
                "response": "Bluetooth hunter not available.",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

        devices = hunter.list_devices()

        if not devices:
            return {
                "response": "No Bluetooth devices in cache.\n\nRun /bt-scan or /ble-scan first.",
                "face": self._get_face_str(),
                "status": "bluetooth",
            }

        # Filter by type if specified
        ble_only = "ble" in args.lower()
        classic_only = "classic" in args.lower()

        if ble_only:
            devices = [d for d in devices if d.ble]
        elif classic_only:
            devices = [d for d in devices if not d.ble]

        lines = [f"Known Bluetooth Devices ({len(devices)}):"]
        lines.append("-" * 70)
        lines.append(f"{'Address':<18} {'Name':<20} {'Class':<12} {'Type':<6} {'RSSI'}")
        lines.append("-" * 70)

        for d in devices:
            name = (d.name or "Unknown")[:18]
            dev_class = d.device_class[:10]
            dev_type = "BLE" if d.ble else "Classic"
            rssi = f"{d.rssi}" if d.rssi else "N/A"
            lines.append(f"{d.address:<18} {name:<20} {dev_class:<12} {dev_type:<6} {rssi}")

        return {
            "response": "\n".join(lines),
            "face": self._get_face_str(),
            "status": "bluetooth",
        }
