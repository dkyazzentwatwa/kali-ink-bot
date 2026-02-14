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
from core.pentest_db import PentestDB, Scope, Severity, ScanType
from core.recon import ReconEngine


class KaliMCPServer:
    """MCP server for Kali pentest tools."""

    def __init__(self, data_dir: str = "~/.inkling/pentest", pentest_config: Optional[Dict[str, Any]] = None):
        self.pentest_config = pentest_config or {}
        self.tool_manager = KaliToolManager(
            data_dir=data_dir,
            package_profile=self.pentest_config.get("package_profile", "pi-headless-curated"),
            required_tools=self.pentest_config.get("required_tools"),
            optional_tools=self.pentest_config.get("optional_tools"),
            enabled_profiles=self.pentest_config.get("enabled_profiles"),
        )
        self.pentest_db = PentestDB()
        self.recon_engine = ReconEngine()

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
                "name": "pentest_profiles_list",
                "description": "List modular Kali profile groups and metapackages.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "pentest_profile_status",
                "description": "Get installed/missing status for selected profile names.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "profile_names": {
                            "type": "array",
                            "items": {"type": "string"},
                        }
                    },
                },
            },
            {
                "name": "pentest_profile_install_command",
                "description": "Generate apt command for one or more profile names.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "profile_names": {
                            "type": "array",
                            "items": {"type": "string"},
                        }
                    },
                    "required": ["profile_names"],
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
            # New target/scan/vuln management tools
            {
                "name": "pentest_targets_list",
                "description": "List all targets in the pentest database.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scope": {"type": "string", "description": "Filter by scope: in_scope, out_of_scope, unknown"},
                    },
                },
            },
            {
                "name": "pentest_target_add",
                "description": "Add a target to the pentest database.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address or hostname"},
                        "hostname": {"type": "string", "description": "Optional hostname"},
                        "scope": {"type": "string", "description": "Scope: in_scope (default), out_of_scope, unknown"},
                        "notes": {"type": "string", "description": "Optional notes"},
                    },
                    "required": ["ip"],
                },
            },
            {
                "name": "pentest_target_remove",
                "description": "Remove a target from the pentest database.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_id": {"type": "number", "description": "Target ID to remove"},
                    },
                    "required": ["target_id"],
                },
            },
            {
                "name": "pentest_scans_list",
                "description": "List scan history from the database.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_id": {"type": "number", "description": "Filter by target ID"},
                        "scan_type": {"type": "string", "description": "Filter by type: nmap, nikto, recon, ports"},
                        "limit": {"type": "number", "description": "Max results (default 25)"},
                    },
                },
            },
            {
                "name": "pentest_scan_details",
                "description": "Get detailed results for a specific scan.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {"type": "number", "description": "Scan ID to retrieve"},
                    },
                    "required": ["scan_id"],
                },
            },
            {
                "name": "pentest_vulns_list",
                "description": "List discovered vulnerabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_id": {"type": "number", "description": "Filter by target ID"},
                        "severity": {"type": "string", "description": "Filter by severity: critical, high, medium, low, info"},
                        "limit": {"type": "number", "description": "Max results (default 50)"},
                    },
                },
            },
            {
                "name": "pentest_dns_enum",
                "description": "Perform DNS enumeration on a domain.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain to enumerate"},
                    },
                    "required": ["domain"],
                },
            },
            {
                "name": "pentest_report_generate",
                "description": "Generate a pentest report.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_ids": {"type": "array", "items": {"type": "number"}, "description": "Target IDs to include (empty for all in-scope)"},
                        "format": {"type": "string", "description": "Output format: markdown (default) or html"},
                    },
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
        elif tool_name == "pentest_profiles_list":
            result = self._tool_profiles_list()
        elif tool_name == "pentest_profile_status":
            result = self._tool_profile_status(arguments)
        elif tool_name == "pentest_profile_install_command":
            result = self._tool_profile_install_command(arguments)
        elif tool_name == "pentest_web_scan":
            result = self._tool_web_scan(arguments)
        elif tool_name == "pentest_exploit":
            result = self._tool_exploit(arguments)
        elif tool_name == "pentest_sessions_list":
            result = self._tool_sessions_list()
        elif tool_name == "pentest_session_interact":
            result = self._tool_session_interact(arguments)
        elif tool_name == "pentest_targets_list":
            result = self._tool_targets_list(arguments)
        elif tool_name == "pentest_target_add":
            result = self._tool_target_add(arguments)
        elif tool_name == "pentest_target_remove":
            result = self._tool_target_remove(arguments)
        elif tool_name == "pentest_scans_list":
            result = self._tool_scans_list(arguments)
        elif tool_name == "pentest_scan_details":
            result = self._tool_scan_details(arguments)
        elif tool_name == "pentest_vulns_list":
            result = self._tool_vulns_list(arguments)
        elif tool_name == "pentest_dns_enum":
            result = self._tool_dns_enum(arguments)
        elif tool_name == "pentest_report_generate":
            result = self._tool_report_generate(arguments)
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

    def _tool_profiles_list(self) -> Dict[str, Any]:
        return {"success": True, "profiles": self.tool_manager.get_profiles_catalog()}

    def _tool_profile_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        names = args.get("profile_names") or []
        return {"success": True, **self.tool_manager.get_profile_status(names, refresh=True)}

    def _tool_profile_install_command(self, args: Dict[str, Any]) -> Dict[str, Any]:
        names = args.get("profile_names")
        if not names:
            return {"success": False, "error": "profile_names is required"}
        return {
            "success": True,
            "install_command": self.tool_manager.get_profile_install_command(names),
        }

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

    # New target/scan/vuln management tools

    def _tool_targets_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        scope_str = args.get("scope")
        scope = None
        if scope_str:
            try:
                scope = Scope(scope_str)
            except ValueError:
                return {"success": False, "error": f"Invalid scope: {scope_str}"}

        targets = self.pentest_db.list_targets(scope=scope)
        return {
            "success": True,
            "targets": [t.to_dict() for t in targets],
            "count": len(targets),
        }

    def _tool_target_add(self, args: Dict[str, Any]) -> Dict[str, Any]:
        ip = args.get("ip")
        if not ip:
            return {"success": False, "error": "ip is required"}

        # Check if exists
        existing = self.pentest_db.get_target_by_ip(ip)
        if existing:
            return {
                "success": False,
                "error": f"Target already exists with ID {existing.id}",
                "target": existing.to_dict(),
            }

        scope_str = args.get("scope", "in_scope")
        try:
            scope = Scope(scope_str)
        except ValueError:
            scope = Scope.IN_SCOPE

        target = self.pentest_db.add_target(
            ip=ip,
            hostname=args.get("hostname"),
            scope=scope,
            notes=args.get("notes", ""),
        )
        return {"success": True, "target": target.to_dict()}

    def _tool_target_remove(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target_id = args.get("target_id")
        if target_id is None:
            return {"success": False, "error": "target_id is required"}

        target = self.pentest_db.get_target(int(target_id))
        if not target:
            return {"success": False, "error": f"Target not found: {target_id}"}

        self.pentest_db.remove_target(int(target_id))
        return {"success": True, "removed": target.to_dict()}

    def _tool_scans_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target_id = args.get("target_id")
        scan_type_str = args.get("scan_type")
        limit = args.get("limit", 25)

        scan_type = None
        if scan_type_str:
            try:
                scan_type = ScanType(scan_type_str)
            except ValueError:
                return {"success": False, "error": f"Invalid scan_type: {scan_type_str}"}

        scans = self.pentest_db.get_scans(
            target_id=int(target_id) if target_id else None,
            scan_type=scan_type,
            limit=int(limit),
        )
        return {
            "success": True,
            "scans": [s.to_dict() for s in scans],
            "count": len(scans),
        }

    def _tool_scan_details(self, args: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = args.get("scan_id")
        if scan_id is None:
            return {"success": False, "error": "scan_id is required"}

        scan = self.pentest_db.get_scan(int(scan_id))
        if not scan:
            return {"success": False, "error": f"Scan not found: {scan_id}"}

        # Also get vulnerabilities for this scan
        vulns = self.pentest_db.get_vulns(target_id=scan.target_id, limit=100)
        scan_vulns = [v for v in vulns if v.scan_id == scan.id]

        return {
            "success": True,
            "scan": scan.to_dict(),
            "vulnerabilities": [v.to_dict() for v in scan_vulns],
        }

    def _tool_vulns_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target_id = args.get("target_id")
        severity_str = args.get("severity")
        limit = args.get("limit", 50)

        severity = None
        if severity_str:
            try:
                severity = Severity(severity_str)
            except ValueError:
                return {"success": False, "error": f"Invalid severity: {severity_str}"}

        vulns = self.pentest_db.get_vulns(
            target_id=int(target_id) if target_id else None,
            severity=severity,
            limit=int(limit),
        )
        counts = self.pentest_db.get_vuln_counts(
            target_id=int(target_id) if target_id else None
        )

        return {
            "success": True,
            "vulnerabilities": [v.to_dict() for v in vulns],
            "counts": counts,
            "total": len(vulns),
        }

    def _tool_dns_enum(self, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = args.get("domain")
        if not domain:
            return {"success": False, "error": "domain is required"}

        result = self._run_async(self.recon_engine.full_recon(domain))
        return {
            "success": True,
            "target": domain,
            "recon": result.to_dict(),
        }

    def _tool_report_generate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target_ids = args.get("target_ids", [])
        report_format = args.get("format", "markdown")

        if not target_ids:
            # Use all in-scope targets
            targets = self.pentest_db.list_targets(scope=Scope.IN_SCOPE)
            target_ids = [t.id for t in targets]

        if not target_ids:
            return {"success": False, "error": "No targets for report"}

        try:
            from core.report_generator import ReportGenerator
            from pathlib import Path
            from datetime import datetime

            generator = ReportGenerator(self.pentest_db)
            report = generator.generate(target_ids=target_ids, format=report_format)

            reports_dir = Path("~/.inkling/reports").expanduser()
            reports_dir.mkdir(parents=True, exist_ok=True)

            ext = "md" if report_format == "markdown" else "html"
            filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
            report_path = reports_dir / filename

            with open(report_path, "w") as f:
                f.write(report)

            stats = self.pentest_db.get_stats()
            return {
                "success": True,
                "report_path": str(report_path),
                "targets": len(target_ids),
                "scans": stats["scans"],
                "vulnerabilities": stats["vulnerabilities"],
            }
        except ImportError:
            return {"success": False, "error": "Jinja2 not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

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
