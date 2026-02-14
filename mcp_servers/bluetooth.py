#!/usr/bin/env python3
"""
Inkling Bluetooth MCP Server

Provides Bluetooth/BLE hunting tools to MCP clients for AI-assisted security testing.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BluetoothMCPServer:
    """MCP server for Bluetooth hunting tools."""

    def __init__(self, data_dir: str = "~/.inkling/bluetooth"):
        self.data_dir = Path(data_dir).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Lazy-loaded components
        self._bt_hunter = None
        self._mode_manager = None

    def _get_bt_hunter(self):
        """Lazy-load Bluetooth hunter."""
        if self._bt_hunter is None:
            try:
                from core.bluetooth_hunter import BluetoothHunter
                self._bt_hunter = BluetoothHunter(data_dir=str(self.data_dir))
            except ImportError:
                pass
        return self._bt_hunter

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
                "serverInfo": {"name": "inkling-bluetooth", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        }

    def _list_tools(self, request_id: int) -> Dict[str, Any]:
        tools = [
            {
                "name": "bt_scan_classic",
                "description": "Scan for classic Bluetooth devices (phones, laptops, headsets).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "duration": {"type": "number", "description": "Scan duration in seconds (default 10)"},
                    },
                },
            },
            {
                "name": "bt_scan_ble",
                "description": "Scan for Bluetooth Low Energy devices (wearables, IoT, beacons).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "duration": {"type": "number", "description": "Scan duration in seconds (default 10)"},
                    },
                },
            },
            {
                "name": "bt_devices",
                "description": "List all discovered Bluetooth devices from cache.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ble_only": {"type": "boolean", "description": "Only show BLE devices"},
                        "classic_only": {"type": "boolean", "description": "Only show classic BT devices"},
                    },
                },
            },
            {
                "name": "bt_device_details",
                "description": "Get detailed info about a specific Bluetooth device.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Bluetooth MAC address"},
                    },
                    "required": ["address"],
                },
            },
            {
                "name": "bt_services",
                "description": "Enumerate services on a Bluetooth device.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Bluetooth MAC address"},
                    },
                    "required": ["address"],
                },
            },
            {
                "name": "bt_status",
                "description": "Get Bluetooth adapter status and capabilities.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}

    def _call_tool(self, request_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        tool_handlers = {
            "bt_scan_classic": self._tool_scan_classic,
            "bt_scan_ble": self._tool_scan_ble,
            "bt_devices": self._tool_devices,
            "bt_device_details": self._tool_device_details,
            "bt_services": self._tool_services,
            "bt_status": self._tool_status,
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

    def _tool_scan_classic(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan for classic Bluetooth devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return {"success": False, "error": "Bluetooth hunter not available"}

        duration = args.get("duration", 10)
        devices = self._run_async(hunter.scan_classic(duration))

        return {
            "success": True,
            "devices": [d.to_dict() for d in devices],
            "count": len(devices),
            "scan_type": "classic",
            "duration": duration,
        }

    def _tool_scan_ble(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan for BLE devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return {"success": False, "error": "Bluetooth hunter not available"}

        duration = args.get("duration", 10)
        devices = self._run_async(hunter.scan_ble(duration))

        return {
            "success": True,
            "devices": [d.to_dict() for d in devices],
            "count": len(devices),
            "scan_type": "ble",
            "duration": duration,
        }

    def _tool_devices(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List cached devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            return {"success": False, "error": "Bluetooth hunter not available"}

        devices = hunter.list_devices()

        # Apply filters
        ble_only = args.get("ble_only", False)
        classic_only = args.get("classic_only", False)

        if ble_only:
            devices = [d for d in devices if d.ble]
        elif classic_only:
            devices = [d for d in devices if not d.ble]

        return {
            "success": True,
            "devices": [d.to_dict() for d in devices],
            "count": len(devices),
        }

    def _tool_device_details(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get device details."""
        address = args.get("address")
        if not address:
            return {"success": False, "error": "address is required"}

        hunter = self._get_bt_hunter()
        if not hunter:
            return {"success": False, "error": "Bluetooth hunter not available"}

        device = hunter.get_device(address)
        if not device:
            return {"success": False, "error": f"Device not found: {address}"}

        return {
            "success": True,
            "device": device.to_dict(),
        }

    def _tool_services(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate services."""
        address = args.get("address")
        if not address:
            return {"success": False, "error": "address is required"}

        hunter = self._get_bt_hunter()
        if not hunter:
            return {"success": False, "error": "Bluetooth hunter not available"}

        services = self._run_async(hunter.enumerate_services(address))

        return {
            "success": True,
            "address": address,
            "services": services,
            "count": len(services),
        }

    def _tool_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get Bluetooth status."""
        hunter = self._get_bt_hunter()

        # Check if bluetooth tools are available
        import subprocess

        status = {
            "bluetooth_available": False,
            "hcitool_available": False,
            "bleak_available": False,
            "adapters": [],
        }

        # Check hcitool
        try:
            result = subprocess.run(
                ["hcitool", "dev"],
                capture_output=True,
                text=True,
                timeout=5
            )
            status["hcitool_available"] = result.returncode == 0

            # Parse adapters
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "\t" in line:
                        parts = line.strip().split("\t")
                        if len(parts) >= 2:
                            status["adapters"].append({
                                "interface": parts[0],
                                "address": parts[1],
                            })
                status["bluetooth_available"] = len(status["adapters"]) > 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check bleak
        try:
            import bleak
            status["bleak_available"] = True
        except ImportError:
            pass

        # Add cached device count
        if hunter:
            status["cached_devices"] = len(hunter.list_devices())

        return {"success": True, **status}

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
    server = BluetoothMCPServer()
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
