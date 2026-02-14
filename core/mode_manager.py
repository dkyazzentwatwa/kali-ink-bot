"""
Project Inkling - Mode Manager

Manages operational modes for the Kali Ink Bot.
Handles transitions between pentest, WiFi hunting, Bluetooth, and idle modes.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class OperationMode(str, Enum):
    """Available operation modes."""
    PENTEST = "pentest"          # Default AI-assisted pentesting
    WIFI_PASSIVE = "wifi"        # Passive WiFi monitoring (recon only)
    WIFI_ACTIVE = "wifi_active"  # Active WiFi attacks (deauth enabled)
    BLUETOOTH = "bluetooth"      # BT/BLE hunting
    IDLE = "idle"                # Low-power display only


# Legal disclaimer shown when entering active mode
ACTIVE_MODE_WARNING = """
WARNING: Active WiFi mode enables packet injection and deauthentication attacks.

These capabilities are intended ONLY for:
- Authorized penetration testing engagements
- Security research on networks you own
- Educational purposes in controlled environments

Unauthorized use of these tools against networks you do not own or have
explicit written permission to test may violate laws in your jurisdiction.

By enabling active mode, you confirm you have proper authorization.
"""


@dataclass
class ModeState:
    """Current state of the mode manager."""
    mode: OperationMode
    since: float  # Timestamp when mode was entered
    interface: Optional[str] = None  # WiFi interface in use
    monitor_enabled: bool = False
    targets_found: int = 0
    captures_today: int = 0
    last_activity: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "since": self.since,
            "duration_seconds": time.time() - self.since,
            "interface": self.interface,
            "monitor_enabled": self.monitor_enabled,
            "targets_found": self.targets_found,
            "captures_today": self.captures_today,
            "last_activity": self.last_activity,
        }


class ModeManager:
    """
    Manages operational modes and transitions.

    Coordinates between different hunting modes (WiFi, Bluetooth)
    and the standard pentest mode. Handles resource allocation
    and ensures clean transitions.
    """

    def __init__(
        self,
        default_mode: OperationMode = OperationMode.PENTEST,
        auto_switch_on_adapter: bool = True,
    ):
        """
        Initialize the mode manager.

        Args:
            default_mode: Initial operation mode
            auto_switch_on_adapter: Auto-switch to wifi mode when monitor adapter detected
        """
        self._state = ModeState(
            mode=default_mode,
            since=time.time(),
        )
        self._auto_switch = auto_switch_on_adapter
        self._callbacks: Dict[str, List[Callable]] = {
            "mode_changed": [],
            "wifi_target": [],
            "handshake": [],
            "bt_device": [],
        }

        # Lazy-loaded components
        self._wifi_hunter = None
        self._bt_hunter = None
        self._adapter_manager = None
        self._wifi_db = None

        # Background task handles
        self._tick_task: Optional[asyncio.Task] = None
        self._running = False

    @property
    def mode(self) -> OperationMode:
        """Get current operation mode."""
        return self._state.mode

    @property
    def state(self) -> ModeState:
        """Get full mode state."""
        return self._state

    def _get_adapter_manager(self):
        """Lazy-load adapter manager."""
        if self._adapter_manager is None:
            from core.wifi_adapter import AdapterManager
            self._adapter_manager = AdapterManager()
        return self._adapter_manager

    def _get_wifi_hunter(self):
        """Lazy-load WiFi hunter."""
        if self._wifi_hunter is None:
            try:
                from core.wifi_hunter import WiFiHunter
                self._wifi_hunter = WiFiHunter()
            except ImportError:
                logger.warning("WiFiHunter not available")
        return self._wifi_hunter

    def _get_bt_hunter(self):
        """Lazy-load Bluetooth hunter."""
        if self._bt_hunter is None:
            try:
                from core.bluetooth_hunter import BluetoothHunter
                self._bt_hunter = BluetoothHunter()
            except ImportError:
                logger.warning("BluetoothHunter not available")
        return self._bt_hunter

    def _get_wifi_db(self):
        """Lazy-load WiFi database."""
        if self._wifi_db is None:
            from core.wifi_db import WiFiDB
            self._wifi_db = WiFiDB()
        return self._wifi_db

    async def switch_mode(
        self,
        mode: OperationMode,
        force: bool = False,
    ) -> Tuple[bool, str]:
        """
        Switch to a different operation mode.

        Args:
            mode: Target mode to switch to
            force: Skip confirmation for active modes

        Returns:
            (success, message)
        """
        current = self._state.mode

        # No-op if already in this mode
        if current == mode:
            return True, f"Already in {mode.value} mode"

        # Handle exit from current mode
        exit_success, exit_msg = await self._exit_mode(current)
        if not exit_success:
            logger.warning(f"Failed to cleanly exit {current.value}: {exit_msg}")
            # Continue anyway, best effort

        # Handle entry to new mode
        enter_success, enter_msg = await self._enter_mode(mode)
        if not enter_success:
            # Try to restore previous mode
            await self._enter_mode(current)
            return False, enter_msg

        # Update state
        self._state = ModeState(
            mode=mode,
            since=time.time(),
            interface=self._state.interface,
            monitor_enabled=self._state.monitor_enabled,
        )

        # Notify callbacks
        await self._notify("mode_changed", {"from": current.value, "to": mode.value})

        logger.info(f"Switched mode: {current.value} -> {mode.value}")
        return True, f"Switched to {mode.value} mode"

    async def _exit_mode(self, mode: OperationMode) -> Tuple[bool, str]:
        """Clean up when exiting a mode."""
        try:
            if mode in (OperationMode.WIFI_PASSIVE, OperationMode.WIFI_ACTIVE):
                hunter = self._get_wifi_hunter()
                if hunter:
                    await hunter.stop_capture()
                    if self._state.monitor_enabled:
                        await hunter.stop_monitor_mode()
                        self._state.monitor_enabled = False

            elif mode == OperationMode.BLUETOOTH:
                # Nothing special to clean up for BT
                pass

            return True, "OK"
        except Exception as e:
            logger.exception(f"Error exiting {mode.value} mode")
            return False, str(e)

    async def _enter_mode(self, mode: OperationMode) -> Tuple[bool, str]:
        """Initialize a new mode."""
        try:
            if mode == OperationMode.WIFI_PASSIVE:
                return await self._enter_wifi_mode(active=False)

            elif mode == OperationMode.WIFI_ACTIVE:
                return await self._enter_wifi_mode(active=True)

            elif mode == OperationMode.BLUETOOTH:
                return await self._enter_bluetooth_mode()

            elif mode == OperationMode.PENTEST:
                # No special initialization needed
                return True, "Pentest mode active"

            elif mode == OperationMode.IDLE:
                return True, "Idle mode active"

            return False, f"Unknown mode: {mode}"
        except Exception as e:
            logger.exception(f"Error entering {mode.value} mode")
            return False, str(e)

    async def _enter_wifi_mode(self, active: bool = False) -> Tuple[bool, str]:
        """Enter WiFi hunting mode."""
        adapter_mgr = self._get_adapter_manager()
        hunter = self._get_wifi_hunter()

        if not hunter:
            return False, "WiFi hunter not available"

        # Find a suitable adapter
        adapter = adapter_mgr.get_monitor_adapter()
        if not adapter:
            adapters = adapter_mgr.detect_adapters()
            if not adapters:
                return False, "No WiFi adapters found"
            return False, f"No monitor-capable adapter found. Available: {[a.interface for a in adapters]}"

        # Check if already in monitor mode
        if adapter.current_mode != "monitor":
            success, result = await adapter_mgr.enable_monitor_mode(adapter.interface)
            if not success:
                return False, f"Failed to enable monitor mode: {result}"
            self._state.interface = result
            self._state.monitor_enabled = True
        else:
            self._state.interface = adapter.interface
            self._state.monitor_enabled = True

        # Start passive capture
        try:
            await hunter.start_passive_capture()
        except Exception as e:
            return False, f"Failed to start capture: {e}"

        mode_name = "active WiFi" if active else "passive WiFi"
        return True, f"Entered {mode_name} mode on {self._state.interface}"

    async def _enter_bluetooth_mode(self) -> Tuple[bool, str]:
        """Enter Bluetooth hunting mode."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return False, "Bluetooth hunter not available"

        return True, "Bluetooth mode active"

    async def get_status(self) -> Dict[str, Any]:
        """Get comprehensive mode status."""
        status = self._state.to_dict()

        # Add adapter info if in WiFi mode
        if self._state.mode in (OperationMode.WIFI_PASSIVE, OperationMode.WIFI_ACTIVE):
            adapter_mgr = self._get_adapter_manager()
            status["adapters"] = adapter_mgr.get_status()

            wifi_db = self._get_wifi_db()
            db_stats = wifi_db.get_stats()
            status["wifi_stats"] = db_stats
            self._state.targets_found = db_stats["targets"]
            self._state.captures_today = db_stats["handshakes_today"]

        return status

    def is_active_mode(self) -> bool:
        """Check if currently in an active (attack-enabled) mode."""
        return self._state.mode == OperationMode.WIFI_ACTIVE

    def is_wifi_mode(self) -> bool:
        """Check if currently in any WiFi mode."""
        return self._state.mode in (OperationMode.WIFI_PASSIVE, OperationMode.WIFI_ACTIVE)

    def is_bluetooth_mode(self) -> bool:
        """Check if currently in Bluetooth mode."""
        return self._state.mode == OperationMode.BLUETOOTH

    # ========================================
    # Heartbeat Integration
    # ========================================

    async def start(self) -> None:
        """Start the mode manager background tasks."""
        if self._running:
            return

        self._running = True
        self._tick_task = asyncio.create_task(self._tick_loop())
        logger.info("Mode manager started")

    async def stop(self) -> None:
        """Stop the mode manager."""
        self._running = False

        if self._tick_task:
            self._tick_task.cancel()
            try:
                await self._tick_task
            except asyncio.CancelledError:
                pass

        # Clean exit from current mode
        await self._exit_mode(self._state.mode)
        logger.info("Mode manager stopped")

    async def _tick_loop(self) -> None:
        """Background tick loop for mode-specific behaviors."""
        while self._running:
            try:
                await self._tick()
                await asyncio.sleep(5)  # 5 second tick interval
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Mode manager tick error: {e}")
                await asyncio.sleep(5)

    async def _tick(self) -> None:
        """Perform mode-specific tick operations."""
        if self._state.mode in (OperationMode.WIFI_PASSIVE, OperationMode.WIFI_ACTIVE):
            await self._wifi_tick()
        elif self._state.mode == OperationMode.BLUETOOTH:
            await self._bluetooth_tick()

    async def _wifi_tick(self) -> None:
        """WiFi mode tick - update targets, check for captures."""
        hunter = self._get_wifi_hunter()
        if not hunter:
            return

        try:
            # Get current targets
            targets = await hunter.get_targets()
            self._state.targets_found = len(targets)
            self._state.last_activity = time.time()

            # Store targets in database
            wifi_db = self._get_wifi_db()
            for target in targets:
                from core.wifi_db import EncryptionType
                try:
                    enc = EncryptionType(target.encryption.lower())
                except (ValueError, AttributeError):
                    enc = EncryptionType.UNKNOWN

                wifi_db.upsert_target(
                    bssid=target.bssid,
                    ssid=target.ssid,
                    channel=target.channel,
                    encryption=enc,
                    signal=target.signal,
                )

                # Track clients
                for client_mac in target.clients:
                    wifi_db.upsert_client(
                        target_id=wifi_db.get_target_by_bssid(target.bssid).id,
                        mac_address=client_mac,
                    )

            # Check for evil twins
            evil_twins = await hunter.detect_evil_twin()
            for et in evil_twins:
                wifi_db.add_evil_twin_alert(
                    original_bssid=et["original_bssid"],
                    rogue_bssid=et["rogue_bssid"],
                    ssid=et["ssid"],
                )
                await self._notify("evil_twin", et)

        except Exception as e:
            logger.debug(f"WiFi tick error: {e}")

    async def _bluetooth_tick(self) -> None:
        """Bluetooth mode tick - passive device discovery."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return

        try:
            # Quick BLE scan
            devices = await hunter.scan_ble(duration=3)
            for device in devices:
                await self._notify("bt_device", device.to_dict())
        except Exception as e:
            logger.debug(f"Bluetooth tick error: {e}")

    # ========================================
    # Callbacks
    # ========================================

    def on(self, event: str, callback: Callable) -> None:
        """Register a callback for an event."""
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    def off(self, event: str, callback: Callable) -> None:
        """Unregister a callback."""
        if event in self._callbacks and callback in self._callbacks[event]:
            self._callbacks[event].remove(callback)

    async def _notify(self, event: str, data: Any) -> None:
        """Notify all callbacks for an event."""
        if event not in self._callbacks:
            return

        for callback in self._callbacks[event]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception as e:
                logger.exception(f"Callback error for {event}: {e}")

    # ========================================
    # Mode-specific Actions
    # ========================================

    async def wifi_deauth(
        self,
        bssid: str,
        client: Optional[str] = None,
        count: int = 3,
    ) -> Tuple[bool, str]:
        """Send deauth packets (requires active mode)."""
        if not self.is_active_mode():
            return False, "Deauth requires active WiFi mode. Use /mode wifi_active"

        hunter = self._get_wifi_hunter()
        if not hunter:
            return False, "WiFi hunter not available"

        success = await hunter.deauth_client(bssid, client or "FF:FF:FF:FF:FF:FF", count)

        # Log the attempt
        wifi_db = self._get_wifi_db()
        target = wifi_db.get_target_by_bssid(bssid)
        if target:
            wifi_db.log_deauth(
                target_id=target.id,
                bssid=bssid,
                client_mac=client,
                packets_sent=count,
                success=success,
            )

        return success, "Deauth sent" if success else "Deauth failed"

    async def wifi_capture_pmkid(self, bssid: str) -> Tuple[bool, str]:
        """Attempt PMKID capture."""
        if not self.is_wifi_mode():
            return False, "Not in WiFi mode"

        hunter = self._get_wifi_hunter()
        if not hunter:
            return False, "WiFi hunter not available"

        handshake = await hunter.capture_pmkid(bssid)
        if handshake:
            # Save to database
            wifi_db = self._get_wifi_db()
            target = wifi_db.get_target_by_bssid(bssid)
            if target:
                from core.wifi_db import CaptureType
                wifi_db.save_handshake(
                    target_id=target.id,
                    bssid=bssid,
                    capture_type=CaptureType.PMKID,
                    file_path=handshake.file_path,
                    ssid=handshake.ssid,
                )

            await self._notify("handshake", handshake)
            return True, f"PMKID captured: {handshake.file_path}"

        return False, "PMKID capture failed"

    async def wifi_survey(self) -> Dict[str, Any]:
        """Run WiFi channel survey."""
        if not self.is_wifi_mode():
            return {"error": "Not in WiFi mode"}

        hunter = self._get_wifi_hunter()
        if not hunter:
            return {"error": "WiFi hunter not available"}

        return await hunter.wifi_survey()

    async def bt_scan(self, ble: bool = False, duration: int = 10) -> List[Dict]:
        """Run Bluetooth scan."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return []

        if ble:
            devices = await hunter.scan_ble(duration)
        else:
            devices = await hunter.scan_classic(duration)

        return [d.to_dict() for d in devices]
