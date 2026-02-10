#!/usr/bin/env python3
"""
Inkling Kali MCP Server

Provides profile-aware Kali tooling to MCP clients.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Add parent directory to path for imports.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.kali_tools import KaliToolManager


class KaliMCPServer:
    """MCP server for Kali pentest tools."""

    def __init__(self, data_dir: str = "~/.inkling/pentest", pentest_config: Optional[Dict[str, Any]] = None):
        self.pentest_config = pentest_config or {}
        self.tool_manager = KaliToolManager(
            data_dir=data_dir,
            package_profile=self.pentest_config.get("package_profile", "pi-headless-curated"),
            required_tools=self.pentest_config.get("required_tools"),
            optional_tools=self.pentest_config.get("optional_tools"),
        )

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
                "serverInfo": {"name": "inkling-kali", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        }

    def _list_tools(self, request_id: int) -> Dict[str, Any]:
        tools = [
            {
                "name": "pentest_tools_status",
                "description": "Get profile-aware Kali tool install status and guidance.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "pentest_scan",
                "description": "Run nmap scan against a target.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "scan_type": {"type": "string"},
                        "ports": {"type": "string"},
                        "timing": {"type": "number"},
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "pentest_web_scan",
                "description": "Run Nikto web vulnerability scan.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "port": {"type": "number"},
                        "ssl": {"type": "boolean"},
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "pentest_exploit",
                "description": "Run exploit workflow (safe stub in MVP).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "exploit_module": {"type": "string"},
                        "options": {"type": "object"},
                    },
                    "required": ["target", "exploit_module"],
                },
            },
            {
                "name": "pentest_sessions_list",
                "description": "List active exploit sessions (safe stub in MVP).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "pentest_session_interact",
                "description": "Run a command in an active session (safe stub in MVP).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "number"},
                        "command": {"type": "string"},
                    },
                    "required": ["session_id", "command"],
                },
            },
        ]
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}

    def _call_tool(self, request_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "pentest_tools_status":
            result = self._tool_tools_status()
        elif tool_name == "pentest_scan":
            result = self._tool_scan(arguments)
        elif tool_name == "pentest_web_scan":
            result = self._tool_web_scan(arguments)
        elif tool_name == "pentest_exploit":
            result = self._tool_exploit(arguments)
        elif tool_name == "pentest_sessions_list":
            result = self._tool_sessions_list()
        elif tool_name == "pentest_session_interact":
            result = self._tool_session_interact(arguments)
        else:
            return self._error(request_id, f"Unknown tool: {tool_name}")

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
        }

    def _tool_tools_status(self) -> Dict[str, Any]:
        return self.tool_manager.get_tools_status(refresh=True)

    def _tool_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target = args.get("target")
        if not target:
            return {"success": False, "error": "target is required"}

        result = self._run_async(
            self.tool_manager.nmap_scan(
                target=target,
                scan_type=args.get("scan_type", "quick"),
                ports=args.get("ports"),
                timing=int(args.get("timing", 4)),
            )
        )
        if not result:
            status = self.tool_manager.get_tools_status(refresh=True)
            return {
                "success": False,
                "error": "Scan failed. Verify required tools and target reachability.",
                "tools_status": status,
            }

        return {"success": True, "scan": result.__dict__}

    def _tool_web_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target = args.get("target")
        if not target:
            return {"success": False, "error": "target is required"}
        result = self._run_async(
            self.tool_manager.nikto_scan(
                target=target,
                port=int(args.get("port", 80)),
                ssl=bool(args.get("ssl", False)),
            )
        )
        return result

    def _tool_exploit(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target = args.get("target")
        module = args.get("exploit_module")
        if not target or not module:
            return {"success": False, "error": "target and exploit_module are required"}
        return self._run_async(
            self.tool_manager.exploit_with_msfconsole(
                target=target,
                exploit_module=module,
                options=args.get("options"),
            )
        )

    def _tool_sessions_list(self) -> Dict[str, Any]:
        return self._run_async(self.tool_manager.list_sessions())

    def _tool_session_interact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if "session_id" not in args or "command" not in args:
            return {"success": False, "error": "session_id and command are required"}
        return self._run_async(
            self.tool_manager.session_interact(
                session_id=int(args["session_id"]),
                command=str(args["command"]),
            )
        )

    @staticmethod
    def _run_async(coro):
        return asyncio.run(coro)

    @staticmethod
    def _error(request_id: Optional[int], message: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32000, "message": message},
        }


def main() -> None:
    """Run stdio JSON-RPC loop for MCP."""
    server = KaliMCPServer()
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
