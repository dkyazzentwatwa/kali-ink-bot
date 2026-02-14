"""
Project Inkling - WiFi Hunter (Bettercap Wrapper)

Bettercap integration for WiFi hunting operations including passive capture,
deauthentication, PMKID capture, and evil twin detection.
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

import aiohttp

from core.wifi_adapter import AdapterManager
from core.wifi_db import CaptureType, EncryptionType, WiFiDB

logger = logging.getLogger(__name__)


# Bettercap REST API configuration
DEFAULT_BETTERCAP_HOST = "127.0.0.1"
DEFAULT_BETTERCAP_PORT = 8083
DEFAULT_BETTERCAP_USER = "inkling"
DEFAULT_BETTERCAP_PASS = "inkling"


@dataclass
class WiFiTarget:
    """WiFi access point discovered during hunting."""

    bssid: str
    ssid: Optional[str]
    channel: int
    encryption: str  # "WPA2", "WPA", "WEP", "OPEN"
    signal: int  # dBm (negative value)
    clients: List[str] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    handshake_captured: bool = False
    pmkid_captured: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "encryption": self.encryption,
            "signal": self.signal,
            "clients": self.clients,
            "last_seen": self.last_seen,
            "handshake_captured": self.handshake_captured,
            "pmkid_captured": self.pmkid_captured,
        }


@dataclass
class Handshake:
    """Captured WiFi handshake (for function returns, not DB storage)."""

    bssid: str
    ssid: Optional[str]
    file_path: str
    capture_type: Literal["4way", "pmkid"]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "file_path": self.file_path,
            "capture_type": self.capture_type,
            "timestamp": self.timestamp,
        }


class WiFiHunter:
    """
    Bettercap wrapper for WiFi hunting operations.

    Provides async methods for:
    - Monitor mode management (via AdapterManager)
    - Passive WiFi capture
    - Target discovery
    - Deauthentication attacks
    - PMKID capture
    - Evil twin detection
    - Channel/signal survey
    """

    def __init__(
        self,
        interface: str = "wlan1",
        data_dir: str = "~/.inkling/wifi",
        bettercap_host: str = DEFAULT_BETTERCAP_HOST,
        bettercap_port: int = DEFAULT_BETTERCAP_PORT,
        bettercap_user: str = DEFAULT_BETTERCAP_USER,
        bettercap_pass: str = DEFAULT_BETTERCAP_PASS,
    ):
        """
        Initialize WiFi Hunter.

        Args:
            interface: Wireless interface to use (e.g., wlan1, wlan1mon)
            data_dir: Directory for storing captures
            bettercap_host: Bettercap REST API host
            bettercap_port: Bettercap REST API port
            bettercap_user: Bettercap API username
            bettercap_pass: Bettercap API password
        """
        self.interface = interface
        self.data_dir = Path(data_dir).expanduser()
        self.handshake_dir = self.data_dir / "handshakes"
        self.pmkid_dir = self.data_dir / "pmkid"

        # Create directories
        self.handshake_dir.mkdir(parents=True, exist_ok=True)
        self.pmkid_dir.mkdir(parents=True, exist_ok=True)

        # Bettercap API configuration
        self._api_base = f"http://{bettercap_host}:{bettercap_port}"
        self._api_auth = aiohttp.BasicAuth(bettercap_user, bettercap_pass)

        # Adapter manager for monitor mode
        self._adapter_manager = AdapterManager()

        # Session state
        self._session: Optional[aiohttp.ClientSession] = None
        self._is_capturing = False
        self._monitor_interface: Optional[str] = None
        self._bettercap_proc: Optional[asyncio.subprocess.Process] = None

    async def is_bettercap_running(self) -> bool:
        """Check if bettercap API is responding."""
        try:
            session = await self._get_session()
            async with session.get(f"{self._api_base}/api/session", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                return resp.status == 200
        except Exception:
            return False

    async def start_bettercap(self, interface: str = None) -> Tuple[bool, str]:
        """
        Start bettercap if not already running.

        Args:
            interface: WiFi interface to use (defaults to self.interface)

        Returns:
            (success, message)
        """
        # Check if already running
        if await self.is_bettercap_running():
            return True, "Bettercap already running"

        iface = interface or self._monitor_interface or self.interface

        try:
            # Start bettercap with REST API enabled
            cmd = [
                "bettercap",
                "-iface", iface,
                "-api-rest-address", "127.0.0.1",
                "-api-rest-port", str(DEFAULT_BETTERCAP_PORT),
                "-api-rest-username", DEFAULT_BETTERCAP_USER,
                "-api-rest-password", DEFAULT_BETTERCAP_PASS,
                "-no-colors",
                "-silent",
            ]

            logger.info(f"Starting bettercap: {' '.join(cmd)}")

            self._bettercap_proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            # Wait for API to become available
            for _ in range(30):  # 30 second timeout
                await asyncio.sleep(1)
                if await self.is_bettercap_running():
                    logger.info("Bettercap started successfully")
                    return True, "Bettercap started"

            # Timeout
            await self.stop_bettercap()
            return False, "Bettercap failed to start (timeout)"

        except FileNotFoundError:
            return False, "Bettercap not installed. Install with: sudo apt install bettercap"
        except Exception as e:
            logger.exception("Failed to start bettercap")
            return False, f"Failed to start bettercap: {e}"

    async def stop_bettercap(self) -> None:
        """Stop bettercap if we started it."""
        if self._bettercap_proc:
            try:
                self._bettercap_proc.terminate()
                await asyncio.wait_for(self._bettercap_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._bettercap_proc.kill()
            except Exception as e:
                logger.warning(f"Error stopping bettercap: {e}")
            finally:
                self._bettercap_proc = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                auth=self._api_auth,
                timeout=timeout,
            )
        return self._session

    async def _api_get(self, endpoint: str) -> Dict[str, Any]:
        """
        Make GET request to bettercap API.

        Args:
            endpoint: API endpoint (e.g., "/api/session")

        Returns:
            JSON response as dict

        Raises:
            aiohttp.ClientError: On connection errors
            ValueError: On non-JSON response
        """
        session = await self._get_session()
        url = f"{self._api_base}{endpoint}"

        try:
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json()
        except aiohttp.ContentTypeError:
            text = await response.text()
            logger.error(f"Non-JSON response from {endpoint}: {text[:200]}")
            raise ValueError(f"Non-JSON response from bettercap API: {text[:200]}")

    async def _api_post(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make POST request to bettercap API.

        Args:
            endpoint: API endpoint
            data: JSON data to send

        Returns:
            JSON response as dict
        """
        session = await self._get_session()
        url = f"{self._api_base}{endpoint}"

        try:
            async with session.post(url, json=data or {}) as response:
                response.raise_for_status()
                try:
                    return await response.json()
                except aiohttp.ContentTypeError:
                    # Some commands return empty or text response
                    return {"success": True, "text": await response.text()}
        except aiohttp.ClientError as e:
            logger.error(f"Bettercap API POST failed: {e}")
            raise

    async def _run_command(self, cmd: str) -> Dict[str, Any]:
        """
        Execute a bettercap command.

        Args:
            cmd: Bettercap command (e.g., "wifi.recon on")

        Returns:
            Command response
        """
        logger.debug(f"Bettercap command: {cmd}")
        return await self._api_post("/api/session", {"cmd": cmd})

    async def close(self) -> None:
        """Close the aiohttp session and stop bettercap if we started it."""
        # Stop capture first
        await self.stop_capture(stop_bettercap=True)

        # Close HTTP session
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # ========================================
    # Monitor Mode Management
    # ========================================

    async def start_monitor_mode(self) -> Tuple[bool, str]:
        """
        Enable monitor mode on the interface.

        Uses AdapterManager to enable monitor mode, which tries
        airmon-ng first, then falls back to manual iw commands.

        Returns:
            Tuple of (success, new_interface_name_or_error_message)
        """
        success, result = await self._adapter_manager.enable_monitor_mode(self.interface)

        if success:
            self._monitor_interface = result
            logger.info(f"Monitor mode enabled on {result}")
        else:
            logger.error(f"Failed to enable monitor mode: {result}")

        return success, result

    async def stop_monitor_mode(self) -> None:
        """
        Disable monitor mode on the interface.

        Stops any active capture first, then disables monitor mode.
        """
        # Stop capture if running
        if self._is_capturing:
            await self.stop_capture()

        # Determine which interface to disable
        iface = self._monitor_interface or self.interface

        success, result = await self._adapter_manager.disable_monitor_mode(iface)

        if success:
            logger.info(f"Monitor mode disabled, interface: {result}")
            self._monitor_interface = None
        else:
            logger.warning(f"Failed to disable monitor mode: {result}")

    # ========================================
    # Passive Capture
    # ========================================

    async def start_passive_capture(self) -> None:
        """
        Start passive WiFi capture with bettercap.

        Enables wifi.recon module to passively discover access points
        and clients without sending any packets.

        Will auto-start bettercap if not running.

        Raises:
            RuntimeError: If bettercap API is not available
        """
        if self._is_capturing:
            logger.warning("Capture already running")
            return

        # Get interface
        iface = self._monitor_interface or self.interface

        # Check if bettercap is running, start if not
        if not await self.is_bettercap_running():
            logger.info("Bettercap not running, starting...")
            success, msg = await self.start_bettercap(iface)
            if not success:
                raise RuntimeError(msg)

        try:
            # Set interface if monitor mode changed it
            await self._run_command(f"set wifi.interface {iface}")

            # Set handshake capture directory
            await self._run_command(f"set wifi.handshakes.file {self.handshake_dir}/{{essid}}_{{bssid}}.pcap")

            # Enable recon
            await self._run_command("wifi.recon on")

            self._is_capturing = True
            logger.info(f"Started passive capture on {iface}")
        except aiohttp.ClientError as e:
            logger.error(f"Failed to start capture: {e}")
            raise RuntimeError(f"Bettercap API not available: {e}")

    async def stop_capture(self, stop_bettercap: bool = False) -> None:
        """
        Stop WiFi capture.

        Disables wifi.recon and clears captured data.

        Args:
            stop_bettercap: If True, also stop bettercap process
        """
        if not self._is_capturing and not stop_bettercap:
            return

        try:
            if await self.is_bettercap_running():
                await self._run_command("wifi.recon off")
                await self._run_command("wifi.clear")
            self._is_capturing = False
            logger.info("Stopped capture")
        except aiohttp.ClientError as e:
            logger.warning(f"Error stopping capture: {e}")
            self._is_capturing = False

        if stop_bettercap:
            await self.stop_bettercap()

    # ========================================
    # Target Discovery
    # ========================================

    async def get_targets(self) -> List[WiFiTarget]:
        """
        Get discovered access points from bettercap.

        Returns:
            List of WiFiTarget objects representing discovered APs
        """
        try:
            # Get access points
            aps_response = await self._api_get("/api/wifi/aps")
            aps = aps_response if isinstance(aps_response, list) else []

            # Get clients for client association
            clients_response = await self._api_get("/api/wifi/clients")
            clients = clients_response if isinstance(clients_response, list) else []

            # Build client map (bssid -> list of client MACs)
            client_map: Dict[str, List[str]] = {}
            for client in clients:
                ap_mac = client.get("ap_mac", "").upper()
                client_mac = client.get("mac", "").upper()
                if ap_mac and client_mac:
                    if ap_mac not in client_map:
                        client_map[ap_mac] = []
                    client_map[ap_mac].append(client_mac)

            # Convert to WiFiTarget objects
            targets = []
            for ap in aps:
                bssid = ap.get("mac", "").upper()
                if not bssid:
                    continue

                # Parse encryption
                encryption = self._parse_encryption(ap.get("encryption", ""))

                target = WiFiTarget(
                    bssid=bssid,
                    ssid=ap.get("hostname") or ap.get("essid"),
                    channel=ap.get("channel", 0),
                    encryption=encryption,
                    signal=ap.get("rssi", -100),
                    clients=client_map.get(bssid, []),
                    last_seen=ap.get("last_seen", time.time()),
                    handshake_captured=ap.get("handshake", False),
                    pmkid_captured=ap.get("pmkid", False),
                )
                targets.append(target)

            # Sort by signal strength (strongest first)
            targets.sort(key=lambda t: t.signal, reverse=True)
            return targets

        except aiohttp.ClientError as e:
            logger.error(f"Failed to get targets: {e}")
            return []

    def _parse_encryption(self, enc_str: str) -> str:
        """Parse bettercap encryption string to standard format."""
        enc_upper = enc_str.upper()

        if "WPA3" in enc_upper:
            return "WPA3"
        elif "WPA2" in enc_upper:
            return "WPA2"
        elif "WPA" in enc_upper:
            return "WPA"
        elif "WEP" in enc_upper:
            return "WEP"
        elif "OPEN" in enc_upper or not enc_str:
            return "OPEN"
        else:
            return enc_str.upper() or "UNKNOWN"

    # ========================================
    # Deauthentication
    # ========================================

    async def deauth_client(
        self,
        bssid: str,
        client: str,
        count: int = 3,
    ) -> bool:
        """
        Send deauthentication packets to disconnect a client.

        Args:
            bssid: Target AP BSSID
            client: Client MAC address to deauth
            count: Number of deauth packets to send

        Returns:
            True if deauth was sent successfully

        Note:
            This is an active attack - only use on authorized targets.
        """
        try:
            # Set target AP
            await self._run_command(f"wifi.deauth {bssid}")

            # Set client target (or use * for all clients)
            if client.upper() == "ALL" or client == "*":
                client_target = "*"
            else:
                client_target = client.upper()

            # Send deauth packets
            for _ in range(count):
                await self._run_command(f"wifi.deauth {bssid} {client_target}")
                await asyncio.sleep(0.1)

            logger.info(f"Sent {count} deauth packets to {client} via {bssid}")
            return True

        except aiohttp.ClientError as e:
            logger.error(f"Deauth failed: {e}")
            return False

    async def deauth_all_clients(self, bssid: str, count: int = 3) -> bool:
        """
        Deauth all clients from an AP.

        Args:
            bssid: Target AP BSSID
            count: Number of deauth rounds

        Returns:
            True if deauth was sent successfully
        """
        return await self.deauth_client(bssid, "*", count)

    # ========================================
    # PMKID Capture
    # ========================================

    async def capture_pmkid(self, bssid: str) -> Optional[Handshake]:
        """
        Attempt to capture PMKID from an access point.

        PMKID capture is a clientless attack that works by sending
        an association request to the AP. Not all APs are vulnerable.

        Args:
            bssid: Target AP BSSID

        Returns:
            Handshake object if PMKID captured, None otherwise
        """
        try:
            # Get target info for SSID
            targets = await self.get_targets()
            target = next((t for t in targets if t.bssid.upper() == bssid.upper()), None)
            ssid = target.ssid if target else None

            # Enable PMKID capture if not already
            await self._run_command("set wifi.assoc.silent true")
            await self._run_command(f"wifi.assoc {bssid}")

            # Wait for PMKID (bettercap will attempt capture)
            await asyncio.sleep(5)

            # Check if PMKID was captured
            targets = await self.get_targets()
            target = next((t for t in targets if t.bssid.upper() == bssid.upper()), None)

            if target and target.pmkid_captured:
                # Generate output filename
                timestamp = int(time.time())
                safe_ssid = re.sub(r'[^\w\-]', '_', ssid or 'unknown')
                filename = f"pmkid_{safe_ssid}_{bssid.replace(':', '')}_{timestamp}.pcap"
                file_path = str(self.pmkid_dir / filename)

                # Save PMKID capture
                await self._run_command(f"wifi.write {file_path} {bssid}")

                handshake = Handshake(
                    bssid=bssid.upper(),
                    ssid=ssid,
                    file_path=file_path,
                    capture_type="pmkid",
                    timestamp=time.time(),
                )

                logger.info(f"PMKID captured for {ssid or bssid}: {file_path}")
                return handshake

            logger.info(f"No PMKID captured for {bssid}")
            return None

        except aiohttp.ClientError as e:
            logger.error(f"PMKID capture failed: {e}")
            return None

    # ========================================
    # Evil Twin Detection
    # ========================================

    async def detect_evil_twin(self) -> List[Dict[str, Any]]:
        """
        Check for potential evil twin attacks.

        Detects when multiple access points advertise the same SSID
        but have different BSSIDs, which could indicate a rogue AP.

        Returns:
            List of potential evil twin alerts, each containing:
            - ssid: Network name
            - bssids: List of BSSIDs advertising this SSID
            - count: Number of APs with this SSID
        """
        targets = await self.get_targets()

        # Group by SSID
        ssid_map: Dict[str, List[WiFiTarget]] = {}
        for target in targets:
            if target.ssid:
                if target.ssid not in ssid_map:
                    ssid_map[target.ssid] = []
                ssid_map[target.ssid].append(target)

        # Find SSIDs with multiple BSSIDs
        alerts = []
        for ssid, aps in ssid_map.items():
            if len(aps) > 1:
                # Check if BSSIDs are from different vendors (first 3 octets)
                ouis = set()
                for ap in aps:
                    oui = ap.bssid[:8].upper()  # First 3 octets (AA:BB:CC)
                    ouis.add(oui)

                # Multiple OUIs for same SSID is suspicious
                if len(ouis) > 1:
                    alert = {
                        "ssid": ssid,
                        "bssids": [ap.bssid for ap in aps],
                        "ouis": list(ouis),
                        "count": len(aps),
                        "signals": {ap.bssid: ap.signal for ap in aps},
                        "suspicious": True,
                        "reason": "Multiple vendor OUIs for same SSID",
                    }
                    alerts.append(alert)
                    logger.warning(f"Potential evil twin detected: {ssid} ({len(aps)} BSSIDs)")
                else:
                    # Same OUI - could be mesh network or multiple APs
                    alert = {
                        "ssid": ssid,
                        "bssids": [ap.bssid for ap in aps],
                        "count": len(aps),
                        "suspicious": False,
                        "reason": "Same vendor OUI (likely legitimate multi-AP)",
                    }
                    alerts.append(alert)

        return alerts

    # ========================================
    # WiFi Survey
    # ========================================

    async def wifi_survey(self) -> List[Dict[str, Any]]:
        """
        Get channel and signal survey data.

        Returns information about WiFi channel utilization and
        signal strength distribution for site survey purposes.

        Returns:
            List of channel data, each containing:
            - channel: Channel number
            - frequency: Channel frequency in MHz
            - ap_count: Number of APs on this channel
            - avg_signal: Average signal strength
            - max_signal: Strongest signal
            - ssids: List of SSIDs on this channel
        """
        targets = await self.get_targets()

        # Group by channel
        channel_map: Dict[int, List[WiFiTarget]] = {}
        for target in targets:
            ch = target.channel
            if ch not in channel_map:
                channel_map[ch] = []
            channel_map[ch].append(target)

        # Build survey data
        survey = []
        for channel, aps in sorted(channel_map.items()):
            signals = [ap.signal for ap in aps]
            ssids = [ap.ssid for ap in aps if ap.ssid]

            # Calculate frequency
            if channel <= 14:
                # 2.4 GHz
                freq = 2407 + (channel * 5) if channel < 14 else 2484
            else:
                # 5 GHz
                freq = 5000 + (channel * 5)

            survey_entry = {
                "channel": channel,
                "frequency": freq,
                "band": "2.4GHz" if channel <= 14 else "5GHz",
                "ap_count": len(aps),
                "avg_signal": sum(signals) // len(signals) if signals else -100,
                "max_signal": max(signals) if signals else -100,
                "min_signal": min(signals) if signals else -100,
                "ssids": ssids,
                "congestion": self._get_congestion_level(len(aps)),
            }
            survey.append(survey_entry)

        return survey

    def _get_congestion_level(self, ap_count: int) -> str:
        """Get congestion level based on AP count."""
        if ap_count <= 2:
            return "low"
        elif ap_count <= 5:
            return "medium"
        elif ap_count <= 10:
            return "high"
        else:
            return "severe"

    # ========================================
    # Handshake Capture (4-way)
    # ========================================

    async def capture_handshake(
        self,
        bssid: str,
        client: Optional[str] = None,
        timeout: int = 60,
        deauth: bool = True,
    ) -> Optional[Handshake]:
        """
        Attempt to capture a 4-way WPA handshake.

        Args:
            bssid: Target AP BSSID
            client: Specific client to target (or None for any)
            timeout: Maximum time to wait for handshake (seconds)
            deauth: Whether to send deauth to speed up capture

        Returns:
            Handshake object if captured, None otherwise
        """
        try:
            # Get target info
            targets = await self.get_targets()
            target = next((t for t in targets if t.bssid.upper() == bssid.upper()), None)
            ssid = target.ssid if target else None

            # Start handshake capture
            await self._run_command(f"set wifi.handshakes.file {self.handshake_dir}")

            # Send deauth to trigger reconnection
            if deauth:
                if client:
                    await self.deauth_client(bssid, client, count=5)
                elif target and target.clients:
                    # Deauth first client
                    await self.deauth_client(bssid, target.clients[0], count=5)
                else:
                    # Deauth all
                    await self.deauth_all_clients(bssid, count=5)

            # Wait and check for handshake
            start_time = time.time()
            while time.time() - start_time < timeout:
                await asyncio.sleep(5)

                targets = await self.get_targets()
                target = next((t for t in targets if t.bssid.upper() == bssid.upper()), None)

                if target and target.handshake_captured:
                    # Generate filename
                    timestamp = int(time.time())
                    safe_ssid = re.sub(r'[^\w\-]', '_', ssid or 'unknown')
                    filename = f"handshake_{safe_ssid}_{bssid.replace(':', '')}_{timestamp}.cap"
                    file_path = str(self.handshake_dir / filename)

                    # Save handshake
                    await self._run_command(f"wifi.write {file_path} {bssid}")

                    handshake = Handshake(
                        bssid=bssid.upper(),
                        ssid=ssid,
                        file_path=file_path,
                        capture_type="4way",
                        timestamp=time.time(),
                    )

                    logger.info(f"Handshake captured for {ssid or bssid}: {file_path}")
                    return handshake

            logger.info(f"No handshake captured for {bssid} within {timeout}s")
            return None

        except aiohttp.ClientError as e:
            logger.error(f"Handshake capture failed: {e}")
            return None

    # ========================================
    # Session Info
    # ========================================

    async def get_session_info(self) -> Dict[str, Any]:
        """
        Get bettercap session information.

        Returns:
            Session info including active modules, interface, etc.
        """
        try:
            return await self._api_get("/api/session")
        except aiohttp.ClientError as e:
            logger.error(f"Failed to get session info: {e}")
            return {"error": str(e)}

    async def is_bettercap_running(self) -> bool:
        """
        Check if bettercap API is accessible.

        Returns:
            True if bettercap is running and API is accessible
        """
        try:
            await self._api_get("/api/session")
            return True
        except Exception:
            return False

    def get_status(self) -> Dict[str, Any]:
        """
        Get current hunter status.

        Returns:
            Status dict with interface, capture state, directories, etc.
        """
        return {
            "interface": self.interface,
            "monitor_interface": self._monitor_interface,
            "is_capturing": self._is_capturing,
            "data_dir": str(self.data_dir),
            "handshake_dir": str(self.handshake_dir),
            "pmkid_dir": str(self.pmkid_dir),
            "api_base": self._api_base,
        }
