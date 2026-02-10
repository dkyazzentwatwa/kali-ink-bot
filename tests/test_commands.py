"""
Tests for the shared command registry.
"""

import pytest
from core.commands import COMMANDS, get_command, get_commands_by_category


def test_all_commands_have_required_fields():
    """Verify all commands have required fields."""
    for cmd in COMMANDS:
        assert cmd.name
        assert cmd.description
        assert cmd.handler
        assert cmd.category
        assert isinstance(cmd.requires_brain, bool)
        assert isinstance(cmd.requires_api, bool)


def test_get_command():
    """Test command lookup."""
    # Test with leading slash
    cmd = get_command("/help")
    assert cmd is not None
    assert cmd.name == "help"

    # Test without leading slash
    cmd = get_command("mood")
    assert cmd is not None
    assert cmd.name == "mood"

    # Test unknown command
    cmd = get_command("nonexistent")
    assert cmd is None


def test_get_commands_by_category():
    """Test category grouping."""
    categories = get_commands_by_category()

    # Check expected categories exist
    assert "info" in categories
    assert "personality" in categories
    assert "system" in categories
    assert "display" in categories
    assert "session" in categories
    assert "tasks" in categories
    assert "crypto" in categories

    # Verify some specific commands are in correct categories
    info_commands = [c.name for c in categories["info"]]
    assert "help" in info_commands
    assert "level" in info_commands
    assert "stats" in info_commands

    task_commands = [c.name for c in categories["tasks"]]
    assert "tasks" in task_commands
    assert "task" in task_commands
    assert "done" in task_commands


def test_command_count():
    """Verify we have all expected commands."""
    command_names = [c.name for c in COMMANDS]

    # Core commands
    assert "help" in command_names
    assert "mood" in command_names
    assert "stats" in command_names
    assert "level" in command_names
    assert "prestige" in command_names

    # System commands
    assert "system" in command_names
    assert "config" in command_names
    assert "tools" in command_names
    assert "wifi" in command_names
    assert "wifiscan" in command_names

    # Task commands
    assert "tasks" in command_names
    assert "task" in command_names
    assert "done" in command_names
    assert "cancel" in command_names
    assert "delete" in command_names

    # Display + utility commands
    assert "face" in command_names
    assert "faces" in command_names
    assert "refresh" in command_names
    assert "memory" in command_names

    # Registry should contain a broad command surface.
    assert len(COMMANDS) >= 35


def test_handler_naming_convention():
    """Verify all handlers follow naming convention."""
    for cmd in COMMANDS:
        # All handlers should start with "cmd_"
        assert cmd.handler.startswith("cmd_"), f"Handler {cmd.handler} doesn't follow convention"
        # Handler should match command name
        assert cmd.handler == f"cmd_{cmd.name}", f"Handler {cmd.handler} doesn't match command {cmd.name}"


def test_requirements():
    """Test command requirements are set correctly."""
    # Brain-dependent commands
    stats_cmd = get_command("stats")
    assert stats_cmd.requires_brain

    config_cmd = get_command("config")
    assert config_cmd.requires_brain

    # Commands that don't require special features
    mood_cmd = get_command("mood")
    assert not mood_cmd.requires_brain
    assert not mood_cmd.requires_api
