#!/usr/bin/env python3
"""
Inkling WiFi MCP Server

Provides WiFi hunting tools to MCP clients for AI-assisted WiFi security testing.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.wifi_db import WiFiDB, EncryptionType, CaptureType
from core.wifi_adapter import AdapterManager


class WiFiMCPServer:
    """MCP server for WiFi hunting tools."""

    def __init__(self, data_dir: str = "~/.inkling/wifi"):
        self.data_dir = Path(data_dir).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.wifi_db = WiFiDB()
        self.adapter_manager = AdapterManager()

        # Lazy-loaded components
        self._wifi_hunter = None
        self._mode_manager = None

    def _get_wifi_hunter(self):
        """Lazy-load WiFi hunter."""
        if self._wifi_hunter is None:
            try:
                from core.wifi_hunter import WiFiHunter
                self._wifi_hunter = WiFiHunter(data_dir=str(self.data_dir))
            except ImportError:
                pass
        return self._wifi_hunter

    def _get_mode_manager(self):
        """Lazy-load mode manager."""
        if self._mode_manager is None:
            try:
                from core.mode_manager import ModeManager
                self._mode_manager = ModeManager()
            except ImportError:
                pass
        return self._mode_manager

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle one MCP JSON-RPC request."""
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")

        try:
            if method == "initialize":
                return self._initialize(request_id)
            if method == "tools/list":
                return self._list_tools(request_id)
            if method == "tools/call":
                return self._call_tool(request_id, params)
            return self._error(request_id, f"Unknown method: {method}")
        except Exception as exc:
            return self._error(request_id, str(exc))

    def _initialize(self, request_id: int) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "1.0",
                "serverInfo": {"name": "inkling-wifi", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        }

    def _list_tools(self, request_id: int) -> Dict[str, Any]:
        tools = [
            # Discovery tools
            {
                "name": "wifi_adapters",
                "description": "List WiFi adapters and their capabilities (monitor mode, injection support).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "wifi_scan",
                "description": "Get discovered WiFi networks from passive scanning. Must be in wifi mode.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Max results (default 50)"},
                        "encryption": {"type": "string", "description": "Filter by encryption: open, wep, wpa, wpa2, wpa3"},
                    },
                },
            },
            {
                "name": "wifi_targets",
                "description": "List all discovered WiFi targets from the database.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "has_handshake": {"type": "boolean", "description": "Filter by handshake captured status"},
                        "limit": {"type": "number", "description": "Max results (default 100)"},
                    },
                },
            },
            {
                "name": "wifi_target_details",
                "description": "Get detailed info about a specific WiFi target including clients.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "bssid": {"type": "string", "description": "Target BSSID"},
                    },
                    "required": ["bssid"],
                },
            },
            {
                "name": "wifi_clients",
                "description": "List WiFi clients associated with a target.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_id": {"type": "number", "description": "Target ID to list clients for"},
                        "limit": {"type": "number", "description": "Max results (default 100)"},
                    },
                },
            },
            {
                "name": "wifi_handshakes",
                "description": "List captured WiFi handshakes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cracked": {"type": "boolean", "description": "Filter by cracked status"},
                        "limit": {"type": "number", "description": "Max results (default 50)"},
                    },
                },
            },
            # Action tools
            {
                "name": "wifi_deauth",
                "description": "Send deauth packets to disconnect a client. REQUIRES wifi_active mode.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "bssid": {"type": "string", "description": "Target access point BSSID"},
                        "client": {"type": "string", "description": "Client MAC (default: broadcast)"},
                        "count": {"type": "number", "description": "Number of deauth packets (default 3)"},
                    },
                    "required": ["bssid"],
                },
            },
            {
                "name": "wifi_capture_pmkid",
                "description": "Attempt to capture PMKID from a target AP.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "bssid": {"type": "string", "description": "Target access point BSSID"},
                    },
                    "required": ["bssid"],
                },
            },
            {
                "name": "wifi_survey",
                "description": "Run a channel/signal survey to identify optimal channels.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            # Mode tools
            {
                "name": "wifi_mode_status",
                "description": "Get current WiFi hunting mode status and statistics.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "wifi_mode_switch",
                "description": "Switch WiFi hunting mode. Options: pentest, wifi, wifi_active, bluetooth, idle.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mode": {"type": "string", "description": "Target mode: pentest, wifi, wifi_active, bluetooth, idle"},
                    },
                    "required": ["mode"],
                },
            },
            # Analysis tools
            {
                "name": "wifi_evil_twins",
                "description": "List detected evil twin / rogue access points.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dismissed": {"type": "boolean", "description": "Include dismissed alerts"},
                    },
                },
            },
            {
                "name": "wifi_stats",
                "description": "Get WiFi hunting statistics.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}

    def _call_tool(self, request_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        tool_handlers = {
            "wifi_adapters": self._tool_adapters,
            "wifi_scan": self._tool_scan,
            "wifi_targets": self._tool_targets,
            "wifi_target_details": self._tool_target_details,
            "wifi_clients": self._tool_clients,
            "wifi_handshakes": self._tool_handshakes,
            "wifi_deauth": self._tool_deauth,
            "wifi_capture_pmkid": self._tool_capture_pmkid,
            "wifi_survey": self._tool_survey,
            "wifi_mode_status": self._tool_mode_status,
            "wifi_mode_switch": self._tool_mode_switch,
            "wifi_evil_twins": self._tool_evil_twins,
            "wifi_stats": self._tool_stats,
        }

        handler = tool_handlers.get(tool_name)
        if not handler:
            return self._error(request_id, f"Unknown tool: {tool_name}")

        result = handler(arguments)

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
        }

    # Tool implementations

    def _tool_adapters(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List WiFi adapters."""
        status = self.adapter_manager.get_status()
        return {
            "success": True,
            **status,
        }

    def _tool_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get WiFi scan results."""
        hunter = self._get_wifi_hunter()
        if not hunter:
            return {"success": False, "error": "WiFi hunter not available"}

        targets = self._run_async(hunter.get_targets())

        # Filter and limit
        limit = args.get("limit", 50)
        encryption_filter = args.get("encryption")

        results = []
        for target in targets[:limit]:
            if encryption_filter and target.encryption.lower() != encryption_filter.lower():
                continue
            results.append({
                "bssid": target.bssid,
                "ssid": target.ssid,
                "channel": target.channel,
                "encryption": target.encryption,
                "signal": target.signal,
                "clients": len(target.clients),
                "handshake_captured": target.handshake_captured,
                "pmkid_captured": target.pmkid_captured,
            })

        return {
            "success": True,
            "targets": results,
            "count": len(results),
        }

    def _tool_targets(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List WiFi targets from database."""
        has_handshake = args.get("has_handshake")
        limit = args.get("limit", 100)

        targets = self.wifi_db.list_targets(
            has_handshake=has_handshake,
            limit=limit,
        )

        return {
            "success": True,
            "targets": [t.to_dict() for t in targets],
            "count": len(targets),
        }

    def _tool_target_details(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get target details."""
        bssid = args.get("bssid")
        if not bssid:
            return {"success": False, "error": "bssid is required"}

        target = self.wifi_db.get_target_by_bssid(bssid)
        if not target:
            return {"success": False, "error": f"Target not found: {bssid}"}

        clients = self.wifi_db.list_clients(target_id=target.id)
        handshakes = self.wifi_db.list_handshakes(target_id=target.id)
        deauth_logs = self.wifi_db.list_deauth_logs(target_id=target.id, limit=20)

        return {
            "success": True,
            "target": target.to_dict(),
            "clients": [c.to_dict() for c in clients],
            "handshakes": [h.to_dict() for h in handshakes],
            "deauth_attempts": [d.to_dict() for d in deauth_logs],
        }

    def _tool_clients(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List WiFi clients."""
        target_id = args.get("target_id")
        limit = args.get("limit", 100)

        clients = self.wifi_db.list_clients(
            target_id=target_id,
            limit=limit,
        )

        return {
            "success": True,
            "clients": [c.to_dict() for c in clients],
            "count": len(clients),
        }

    def _tool_handshakes(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List handshakes."""
        cracked = args.get("cracked")
        limit = args.get("limit", 50)

        handshakes = self.wifi_db.list_handshakes(
            cracked=cracked,
            limit=limit,
        )

        return {
            "success": True,
            "handshakes": [h.to_dict() for h in handshakes],
            "count": len(handshakes),
        }

    def _tool_deauth(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Send deauth packets."""
        mode_mgr = self._get_mode_manager()
        if not mode_mgr:
            return {"success": False, "error": "Mode manager not available"}

        bssid = args.get("bssid")
        if not bssid:
            return {"success": False, "error": "bssid is required"}

        client = args.get("client")
        count = args.get("count", 3)

        success, message = self._run_async(
            mode_mgr.wifi_deauth(bssid, client, count)
        )

        return {
            "success": success,
            "message": message,
            "bssid": bssid,
            "client": client or "broadcast",
            "packets": count,
        }

    def _tool_capture_pmkid(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt PMKID capture."""
        mode_mgr = self._get_mode_manager()
        if not mode_mgr:
            return {"success": False, "error": "Mode manager not available"}

        bssid = args.get("bssid")
        if not bssid:
            return {"success": False, "error": "bssid is required"}

        success, message = self._run_async(
            mode_mgr.wifi_capture_pmkid(bssid)
        )

        return {
            "success": success,
            "message": message,
            "bssid": bssid,
        }

    def _tool_survey(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run WiFi survey."""
        mode_mgr = self._get_mode_manager()
        if not mode_mgr:
            return {"success": False, "error": "Mode manager not available"}

        result = self._run_async(mode_mgr.wifi_survey())
        return {"success": True, "survey": result}

    def _tool_mode_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get mode status."""
        mode_mgr = self._get_mode_manager()
        if not mode_mgr:
            # Return basic adapter status even without mode manager
            return {
                "success": True,
                "mode": "pentest",
                "adapters": self.adapter_manager.get_status(),
            }

        status = self._run_async(mode_mgr.get_status())
        return {"success": True, **status}

    def _tool_mode_switch(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Switch operation mode."""
        mode_mgr = self._get_mode_manager()
        if not mode_mgr:
            return {"success": False, "error": "Mode manager not available"}

        mode_str = args.get("mode")
        if not mode_str:
            return {"success": False, "error": "mode is required"}

        from core.mode_manager import OperationMode
        try:
            mode = OperationMode(mode_str)
        except ValueError:
            valid_modes = [m.value for m in OperationMode]
            return {"success": False, "error": f"Invalid mode: {mode_str}. Valid: {valid_modes}"}

        success, message = self._run_async(mode_mgr.switch_mode(mode))

        return {
            "success": success,
            "message": message,
            "mode": mode.value,
        }

    def _tool_evil_twins(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List evil twin alerts."""
        dismissed = args.get("dismissed", False)

        alerts = self.wifi_db.list_evil_twin_alerts(dismissed=dismissed)

        return {
            "success": True,
            "alerts": [a.to_dict() for a in alerts],
            "count": len(alerts),
        }

    def _tool_stats(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get WiFi stats."""
        stats = self.wifi_db.get_stats()
        adapter_status = self.adapter_manager.get_status()

        return {
            "success": True,
            "wifi_stats": stats,
            "adapter_status": adapter_status,
        }

    @staticmethod
    def _run_async(coro):
        """Run an async coroutine synchronously."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(coro)

    @staticmethod
    def _error(request_id: Optional[int], message: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32000, "message": message},
        }


def main() -> None:
    """Run stdio JSON-RPC loop for MCP."""
    server = WiFiMCPServer()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
            response = server.handle_request(request)
            print(json.dumps(response), flush=True)
        except json.JSONDecodeError:
            continue
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32000, "message": str(exc)},
                    }
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()
