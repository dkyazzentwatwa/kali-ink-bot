"""
Project Inkling - Shared Command Registry

Central definition of all commands available in both SSH and web modes.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class Command:
    """Definition of a command available in chat modes."""
    name: str
    description: str
    handler: str  # Method name to call (e.g., "cmd_help")
    category: str  # "info", "social", "system", "personality", "display", "session"
    requires_brain: bool = False
    requires_api: bool = False


# All available commands
COMMANDS: List[Command] = [
    # Info commands
    Command("help", "Show available commands", "cmd_help", "info"),
    Command("level", "Show XP and progression", "cmd_level", "info"),
    Command("prestige", "Reset level with XP bonus", "cmd_prestige", "info"),
    Command("stats", "Show token usage statistics", "cmd_stats", "info", requires_brain=True),
    Command("history", "Show recent messages", "cmd_history", "info", requires_brain=True),

    # Personality commands
    Command("mood", "Show current mood", "cmd_mood", "personality"),
    Command("energy", "Show energy level", "cmd_energy", "personality"),
    Command("traits", "Show personality traits", "cmd_traits", "personality"),

    # System commands
    Command("system", "Show system stats", "cmd_system", "system"),
    Command("config", "Show AI configuration", "cmd_config", "system", requires_brain=True),
    Command("bash", "Run a shell command", "cmd_bash", "system"),
    Command("tools", "Show Kali tool install status", "cmd_tools", "system"),

    # Pentest commands
    Command("scan", "Run nmap network scan on target", "cmd_scan", "pentest"),
    Command("web-scan", "Run nikto web vulnerability scan", "cmd_web_scan", "pentest"),
    Command("recon", "DNS/WHOIS enumeration on target", "cmd_recon", "pentest"),
    Command("ports", "Quick TCP port scan", "cmd_ports", "pentest"),
    Command("targets", "Manage target list", "cmd_targets", "pentest"),
    Command("vulns", "View discovered vulnerabilities", "cmd_vulns", "pentest"),
    Command("scans", "View scan history", "cmd_scans", "pentest"),
    Command("report", "Generate pentest report", "cmd_report", "pentest"),

    # Mode & WiFi hunting commands
    Command("mode", "Switch operation mode (pentest/wifi/bluetooth)", "cmd_mode", "wifi"),
    Command("wifi-hunt", "Start WiFi hunting (passive mode)", "cmd_wifi_hunt", "wifi"),
    Command("wifi-targets", "List discovered WiFi networks", "cmd_wifi_targets", "wifi"),
    Command("wifi-deauth", "Deauth client from AP (requires active mode)", "cmd_wifi_deauth", "wifi"),
    Command("wifi-capture", "Capture handshake/PMKID from target", "cmd_wifi_capture", "wifi"),
    Command("wifi-survey", "Run WiFi channel survey", "cmd_wifi_survey", "wifi"),
    Command("handshakes", "List captured WiFi handshakes", "cmd_handshakes", "wifi"),
    Command("adapters", "List WiFi adapters and capabilities", "cmd_adapters", "wifi"),

    # Bluetooth commands
    Command("bt-scan", "Scan for Bluetooth devices", "cmd_bt_scan", "bluetooth"),
    Command("bt-devices", "List known Bluetooth devices", "cmd_bt_devices", "bluetooth"),
    Command("ble-scan", "Scan for BLE devices", "cmd_ble_scan", "bluetooth"),

    # Display commands
    Command("face", "Test a face expression", "cmd_face", "display"),
    Command("faces", "List all available faces", "cmd_faces", "display"),
    Command("refresh", "Force display refresh", "cmd_refresh", "display"),
    Command("screensaver", "Toggle screen saver on/off", "cmd_screensaver", "display"),
    Command("darkmode", "Toggle dark mode (inverted display)", "cmd_darkmode", "display"),

    # Scheduler commands
    Command("schedule", "Manage scheduled price checks", "cmd_schedule", "scheduler"),

    # Utility commands
    Command("thoughts", "Show recent autonomous thoughts", "cmd_thoughts", "info"),
    Command("memory", "Show memory stats and entries", "cmd_memory", "info"),
    Command("settings", "Show current settings (SSH)", "cmd_settings", "system"),
    Command("backup", "Create backup of local data", "cmd_backup", "system"),

    # WiFi commands
    Command("wifi", "Show WiFi status and saved networks", "cmd_wifi", "system"),
    Command("btcfg", "Start BLE WiFi configuration (15 min)", "cmd_btcfg", "system"),
    Command("wifiscan", "Scan for nearby WiFi networks", "cmd_wifiscan", "system"),

    # Task commands
    Command("tasks", "List tasks with optional filters", "cmd_tasks", "tasks"),
    Command("task", "Create or show a task", "cmd_task", "tasks"),
    Command("done", "Mark a task as complete", "cmd_done", "tasks"),
    Command("cancel", "Cancel a task", "cmd_cancel", "tasks"),
    Command("delete", "Delete a task permanently", "cmd_delete", "tasks"),
    Command("taskstats", "Show task statistics", "cmd_taskstats", "tasks"),
    Command("find", "Search tasks by keyword", "cmd_find", "tasks"),
    Command("journal", "Show recent journal entries", "cmd_journal", "tasks"),

    # Session commands
    Command("rest", "Take a break (calms down +2 XP)", "cmd_rest", "session"),
    Command("focus", "Manage focus/pomodoro sessions", "cmd_focus", "session"),

    # Session commands (SSH only)
    Command("ask", "Explicit chat command", "cmd_ask", "session", requires_brain=True),
    Command("clear", "Clear conversation history", "cmd_clear", "session", requires_brain=True),
]


def get_commands_by_category() -> dict:
    """Group commands by category for display."""
    categories = {}
    for cmd in COMMANDS:
        if cmd.category not in categories:
            categories[cmd.category] = []
        categories[cmd.category].append(cmd)
    return categories


def get_command(name: str) -> Command | None:
    """Get a command by name (without leading /)."""
    name = name.lstrip("/").lower()
    for cmd in COMMANDS:
        if cmd.name == name:
            return cmd
    return None
