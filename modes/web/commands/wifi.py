"""WiFi hunting command handlers for web mode."""
import asyncio
import time
from typing import Any, Dict, Optional

from . import CommandHandler


class WiFiCommands(CommandHandler):
    """WiFi hunting command handlers."""

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

    def _get_wifi_db(self):
        """Get or create WiFi database instance."""
        if not hasattr(self.web_mode, '_wifi_db'):
            from core.wifi_db import WiFiDB
            self.web_mode._wifi_db = WiFiDB()
        return self.web_mode._wifi_db

    def _get_adapter_manager(self):
        """Get or create adapter manager instance."""
        if not hasattr(self.web_mode, '_adapter_manager'):
            from core.wifi_adapter import AdapterManager
            self.web_mode._adapter_manager = AdapterManager()
        return self.web_mode._adapter_manager

    def mode(self, args: str = "") -> Dict[str, Any]:
        """Switch operation mode."""
        mode_mgr = self._get_mode_manager()

        if not args.strip():
            # Show current mode status
            try:
                future = asyncio.run_coroutine_threadsafe(
                    mode_mgr.get_status(),
                    self._loop
                )
                status = future.result(timeout=10)
            except Exception as e:
                status = {"mode": mode_mgr.mode.value, "error": str(e)}

            lines = [
                f"Current mode: {status.get('mode', 'unknown')}",
                "",
                "Available modes:",
                "  pentest     - AI-assisted penetration testing (default)",
                "  wifi        - Passive WiFi monitoring",
                "  wifi_active - Active WiFi attacks (deauth enabled)",
                "  bluetooth   - Bluetooth/BLE hunting",
                "  idle        - Low-power display only",
                "",
                f"Use: /mode <mode_name>",
            ]
            return {
                "response": "\n".join(lines),
                "face": self._get_face_str(),
                "status": "mode",
            }

        # Switch mode
        from core.mode_manager import OperationMode
        target_mode = args.strip().lower()

        try:
            mode = OperationMode(target_mode)
        except ValueError:
            return {
                "response": f"Unknown mode: {target_mode}\nValid modes: pentest, wifi, wifi_active, bluetooth, idle",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

        try:
            future = asyncio.run_coroutine_threadsafe(
                mode_mgr.switch_mode(mode),
                self._loop
            )
            success, message = future.result(timeout=60)

            if success:
                return {
                    "response": f"Mode switched to: {mode.value}\n{message}",
                    "face": self._get_face_str(),
                    "status": "mode",
                }
            else:
                return {
                    "response": f"Mode switch failed: {message}",
                    "face": self._get_face_str(),
                    "status": "error",
                    "error": True,
                }
        except Exception as e:
            return {
                "response": f"Error switching mode: {e}",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

    def wifi_hunt(self, args: str = "") -> Dict[str, Any]:
        """Start WiFi hunting mode."""
        mode_mgr = self._get_mode_manager()

        try:
            from core.mode_manager import OperationMode
            future = asyncio.run_coroutine_threadsafe(
                mode_mgr.switch_mode(OperationMode.WIFI_PASSIVE),
                self._loop
            )
            success, message = future.result(timeout=60)

            if success:
                return {
                    "response": f"WiFi hunting started!\n{message}\n\nUse /wifi-targets to see discovered networks.",
                    "face": self._get_face_str(),
                    "status": "wifi",
                }
            else:
                return {
                    "response": f"Failed to start WiFi hunting: {message}",
                    "face": self._get_face_str(),
                    "status": "error",
                    "error": True,
                }
        except Exception as e:
            return {
                "response": f"Error: {e}",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

    def wifi_targets(self, args: str = "") -> Dict[str, Any]:
        """List discovered WiFi networks."""
        wifi_db = self._get_wifi_db()

        # Check for filters
        has_handshake = None
        if "handshake" in args.lower():
            has_handshake = True

        targets = wifi_db.list_targets(has_handshake=has_handshake, limit=50)

        if not targets:
            return {
                "response": "No WiFi targets discovered yet.\n\nStart hunting with /wifi-hunt or /mode wifi",
                "face": self._get_face_str(),
                "status": "wifi",
            }

        lines = [f"WiFi Targets ({len(targets)} found):"]
        lines.append("-" * 60)
        lines.append(f"{'SSID':<20} {'BSSID':<18} {'Ch':>3} {'Sig':>5} {'Enc':<5} {'HS':>2}")
        lines.append("-" * 60)

        for t in targets[:30]:
            ssid = (t.ssid or "<hidden>")[:18]
            hs = "Y" if t.handshake_captured or t.pmkid_captured else "-"
            enc = t.encryption.value[:5] if t.encryption else "?"
            lines.append(f"{ssid:<20} {t.bssid:<18} {t.channel:>3} {t.signal_last:>5} {enc:<5} {hs:>2}")

        if len(targets) > 30:
            lines.append(f"\n... and {len(targets) - 30} more")

        return {
            "response": "\n".join(lines),
            "face": self._get_face_str(),
            "status": "wifi",
        }

    def wifi_deauth(self, args: str = "") -> Dict[str, Any]:
        """Deauth a client from an AP."""
        if not args.strip():
            return {
                "response": "Usage: /wifi-deauth <BSSID> [client_mac] [count]\n\n"
                           "Requires wifi_active mode. Enable with: /mode wifi_active",
                "face": self._get_face_str(),
                "status": "wifi",
            }

        parts = args.strip().split()
        bssid = parts[0]
        client = parts[1] if len(parts) > 1 else None
        count = int(parts[2]) if len(parts) > 2 else 3

        mode_mgr = self._get_mode_manager()

        if not mode_mgr.is_active_mode():
            return {
                "response": "Deauth requires active mode.\n\nEnable with: /mode wifi_active",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

        try:
            future = asyncio.run_coroutine_threadsafe(
                mode_mgr.wifi_deauth(bssid, client, count),
                self._loop
            )
            success, message = future.result(timeout=30)

            return {
                "response": f"Deauth {'sent' if success else 'failed'}: {message}",
                "face": self._get_face_str(),
                "status": "wifi" if success else "error",
                "error": not success,
            }
        except Exception as e:
            return {
                "response": f"Deauth error: {e}",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

    def wifi_capture(self, args: str = "") -> Dict[str, Any]:
        """Capture PMKID from a target."""
        if not args.strip():
            return {
                "response": "Usage: /wifi-capture <BSSID>\n\nAttempts to capture PMKID from target AP.",
                "face": self._get_face_str(),
                "status": "wifi",
            }

        bssid = args.strip().split()[0]
        mode_mgr = self._get_mode_manager()

        try:
            future = asyncio.run_coroutine_threadsafe(
                mode_mgr.wifi_capture_pmkid(bssid),
                self._loop
            )
            success, message = future.result(timeout=60)

            return {
                "response": message,
                "face": self._get_face_str(),
                "status": "wifi" if success else "error",
                "error": not success,
            }
        except Exception as e:
            return {
                "response": f"Capture error: {e}",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

    def wifi_survey(self, args: str = "") -> Dict[str, Any]:
        """Run WiFi channel survey."""
        mode_mgr = self._get_mode_manager()

        if not mode_mgr.is_wifi_mode():
            return {
                "response": "Survey requires WiFi mode.\n\nStart with: /mode wifi",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

        try:
            future = asyncio.run_coroutine_threadsafe(
                mode_mgr.wifi_survey(),
                self._loop
            )
            result = future.result(timeout=120)

            if "error" in result:
                return {
                    "response": f"Survey error: {result['error']}",
                    "face": self._get_face_str(),
                    "status": "error",
                    "error": True,
                }

            # Format survey results
            lines = ["WiFi Channel Survey:"]
            lines.append("-" * 40)

            survey = result.get("survey", [])
            for ch in sorted(survey, key=lambda x: x.get("channel", 0)):
                channel = ch.get("channel", "?")
                networks = ch.get("networks", 0)
                avg_signal = ch.get("avg_signal", 0)
                lines.append(f"Channel {channel:2}: {networks:2} networks, avg signal: {avg_signal} dBm")

            return {
                "response": "\n".join(lines),
                "face": self._get_face_str(),
                "status": "wifi",
            }
        except Exception as e:
            return {
                "response": f"Survey error: {e}",
                "face": self._get_face_str(),
                "status": "error",
                "error": True,
            }

    def handshakes(self, args: str = "") -> Dict[str, Any]:
        """List captured handshakes."""
        wifi_db = self._get_wifi_db()

        # Check for cracked filter
        cracked = None
        if "cracked" in args.lower():
            cracked = True

        handshakes = wifi_db.list_handshakes(cracked=cracked, limit=50)

        if not handshakes:
            msg = "No handshakes captured yet." if cracked is None else "No cracked handshakes."
            return {
                "response": msg,
                "face": self._get_face_str(),
                "status": "wifi",
            }

        lines = [f"Captured Handshakes ({len(handshakes)}):"]
        lines.append("-" * 70)
        lines.append(f"{'SSID':<20} {'BSSID':<18} {'Type':<6} {'Cracked':<8} {'File'}")
        lines.append("-" * 70)

        for h in handshakes:
            ssid = (h.ssid or "<hidden>")[:18]
            cracked_str = "YES" if h.cracked else "-"
            file_short = h.file_path.split("/")[-1][:20]
            lines.append(f"{ssid:<20} {h.bssid:<18} {h.capture_type.value:<6} {cracked_str:<8} {file_short}")

        return {
            "response": "\n".join(lines),
            "face": self._get_face_str(),
            "status": "wifi",
        }

    def adapters(self, args: str = "") -> Dict[str, Any]:
        """List WiFi adapters."""
        adapter_mgr = self._get_adapter_manager()
        status = adapter_mgr.get_status()

        adapters = status.get("adapters", [])

        if not adapters:
            return {
                "response": "No WiFi adapters detected.\n\nPlug in a monitor-mode capable adapter.",
                "face": self._get_face_str(),
                "status": "wifi",
            }

        lines = [f"WiFi Adapters ({len(adapters)} found):"]
        lines.append("-" * 60)

        for a in adapters:
            lines.append(f"\n{a['interface']}:")
            lines.append(f"  Driver:   {a['driver']}")
            lines.append(f"  Chipset:  {a['chipset']}")
            lines.append(f"  MAC:      {a['mac_address']}")
            lines.append(f"  Mode:     {a['current_mode']}")
            lines.append(f"  Monitor:  {'Yes' if a['monitor_capable'] else 'No'}")
            lines.append(f"  Inject:   {'Yes' if a['injection_capable'] else 'No'}")
            if a['bands']:
                lines.append(f"  Bands:    {', '.join(a['bands'])}")
            if a['connected']:
                lines.append(f"  Status:   Connected")

        lines.append("")
        lines.append(f"Monitor capable: {status.get('monitor_capable', 0)}")
        lines.append(f"Injection capable: {status.get('injection_capable', 0)}")
        if status.get('best_monitor_adapter'):
            lines.append(f"Best for hunting: {status['best_monitor_adapter']}")

        return {
            "response": "\n".join(lines),
            "face": self._get_face_str(),
            "status": "wifi",
        }
