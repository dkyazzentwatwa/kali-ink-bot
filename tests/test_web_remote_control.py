"""Tests for web remote-control command/dashboard behavior."""

from types import SimpleNamespace

from core.commands import COMMANDS
from modes.web.commands.system import SystemCommands
from modes.web_chat import TEMPLATE_DIR, WebChatMode


class _DisplayStub:
    def set_mode(self, _mode):
        return None

    def increment_chat_count(self):
        return None

    async def update(self, **kwargs):
        del kwargs
        return None

    async def show_message_paginated(self, **kwargs):
        del kwargs
        return 1


class _BrainStub:
    available_providers = ["stub"]
    providers = []
    budget = SimpleNamespace(daily_limit=10000)
    config = {"budget": {"per_request_max": 5000}}

    def get_stats(self):
        return {
            "tokens_used_today": 0,
            "tokens_remaining": 10000,
            "providers": ["stub"],
            "daily_limit": 10000,
        }


def test_registry_commands_have_web_handlers():
    """Every command in the shared registry should resolve to a web handler."""
    missing = []
    for cmd in COMMANDS:
        if not hasattr(WebChatMode, f"_cmd_{cmd.name}"):
            missing.append(cmd.name)
    assert missing == []


def test_web_template_uses_dynamic_command_groups():
    """Web command palette should be generated from template data."""
    template_text = (TEMPLATE_DIR / "main.html").read_text()
    assert "% for group in command_groups:" in template_text
    assert "prefillCommand(" in template_text


def test_dashboard_snapshot_shape(personality):
    """Dashboard snapshot should expose the key remote-control sections."""
    mode = WebChatMode(brain=_BrainStub(), display=_DisplayStub(), personality=personality, config={})
    snapshot = mode._build_dashboard_snapshot()
    assert "system" in snapshot
    assert "wifi" in snapshot
    assert "tools" in snapshot
    assert "control" in snapshot
    assert "command_count" in snapshot["control"]


def test_web_bash_disabled_message():
    """When web bash is disabled, command returns actionable guidance."""
    mode = SimpleNamespace(
        personality=SimpleNamespace(face="happy"),
        display=None,
        brain=None,
        task_manager=None,
        memory_store=None,
        focus_manager=None,
        scheduler=None,
        _config={},
        _loop=None,
        _allow_web_bash=False,
        _bash_timeout_seconds=8,
        _bash_max_output_bytes=8192,
        _get_face_str=lambda: "happy",
    )
    handler = SystemCommands(mode)
    result = handler.bash("uname -a")
    assert result["error"] is True
    assert "allow_bash" in result["response"]


def test_web_bash_executes_with_limits(monkeypatch):
    """When enabled, web bash should execute via the shared safe helper."""
    mode = SimpleNamespace(
        personality=SimpleNamespace(face="happy"),
        display=None,
        brain=None,
        task_manager=None,
        memory_store=None,
        focus_manager=None,
        scheduler=None,
        _config={},
        _loop=None,
        _allow_web_bash=True,
        _bash_timeout_seconds=3,
        _bash_max_output_bytes=512,
        _get_face_str=lambda: "happy",
    )
    handler = SystemCommands(mode)

    captured = {}

    def fake_run(command, timeout_seconds, max_output_bytes):
        captured["command"] = command
        captured["timeout"] = timeout_seconds
        captured["max_output"] = max_output_bytes
        return 0, "ok output"

    monkeypatch.setattr("core.shell_utils.run_bash_command", fake_run)
    result = handler.bash("echo hi")

    assert captured["command"] == "echo hi"
    assert captured["timeout"] == 3
    assert captured["max_output"] == 512
    assert result["status"] == "bash"
    assert "[exit 0]" in result["response"]
