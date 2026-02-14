"""
Project Inkling - SSH Chat Mode

Interactive terminal mode for chatting with Inkling via SSH.
Reads from stdin, sends to AI, displays responses on e-ink.
"""

import asyncio
import inspect
import sys
import time
from typing import Optional

from core.brain import Brain, AllProvidersExhaustedError, QuotaExceededError
from core.display import DisplayManager
from core.personality import Personality, Mood
from core.ui import FACES, UNICODE_FACES
from core.commands import COMMANDS, get_command, get_commands_by_category
from core.tasks import TaskManager, Task, TaskStatus, Priority
from core.memory import MemoryStore
from core.focus import FocusManager
from core.progression import XPSource
from core.shell_utils import run_bash_command
from core.kali_tools import KaliToolManager
from core.pentest_db import PentestDB, Target, ScanRecord, Vulnerability, Scope, Severity, ScanType
from core.recon import ReconEngine


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Mood colors
    HAPPY = "\033[92m"      # Green
    SAD = "\033[94m"        # Blue
    EXCITED = "\033[93m"    # Yellow
    BORED = "\033[90m"      # Gray
    CURIOUS = "\033[96m"    # Cyan
    ANGRY = "\033[91m"      # Red
    SLEEPY = "\033[35m"     # Magenta (dim)
    GRATEFUL = "\033[92m"   # Green
    LONELY = "\033[94m"     # Blue
    INTENSE = "\033[93m"    # Yellow
    COOL = "\033[37m"       # White

    # UI elements
    FACE = "\033[1;97m"     # Bold white
    PROMPT = "\033[95m"     # Magenta
    INFO = "\033[90m"       # Gray
    SUCCESS = "\033[92m"    # Green
    ERROR = "\033[91m"      # Red
    HEADER = "\033[1;36m"   # Bold cyan
    EMOTE = "\033[3;35m"    # Italic magenta for emotes

    @classmethod
    def mood_color(cls, mood: str) -> str:
        """Get color for a mood string."""
        mood_colors = {
            "happy": cls.HAPPY,
            "excited": cls.EXCITED,
            "curious": cls.CURIOUS,
            "bored": cls.BORED,
            "sad": cls.SAD,
            "sleepy": cls.SLEEPY,
            "grateful": cls.GRATEFUL,
            "lonely": cls.LONELY,
            "intense": cls.INTENSE,
            "cool": cls.COOL,
        }
        return mood_colors.get(mood.lower(), cls.RESET)


class SSHChatMode:
    """
    Interactive chat mode for terminal/SSH access.

    Usage:
        python main.py --mode ssh

    Commands:
        /quit, /exit - Exit chat
        /clear - Clear conversation history
        /mood - Show current mood
        /stats - Show token usage stats
        /face <name> - Test a face expression
    """

    def __init__(
        self,
        brain: Brain,
        display: DisplayManager,
        personality: Personality,
        task_manager: Optional[TaskManager] = None,
        memory_store: Optional[MemoryStore] = None,
        focus_manager: Optional[FocusManager] = None,
        scheduler=None,
        config: Optional[dict] = None,
    ):
        self.brain = brain
        self.display = display
        self.personality = personality
        self.task_manager = task_manager
        self.memory_store = memory_store
        self.focus_manager = focus_manager
        self.scheduler = scheduler
        self._running = False
        self._config = config or {}
        self._allow_bash = self._config.get("ble", {}).get("allow_bash", True)
        self._bash_timeout_seconds = self._config.get("ble", {}).get("command_timeout_seconds", 8)
        self._bash_max_output_bytes = self._config.get("ble", {}).get("max_output_bytes", 8192)

        # Set display mode
        self.display.set_mode("SSH")

    async def run(self) -> None:
        """Main chat loop."""
        self._running = True

        # Start background display refresh for live stats
        await self.display.start_auto_refresh()

        try:
            # Show welcome message
            await self._welcome()

            print("\nType your message (or /help for commands):")
            print("-" * 40)

            while self._running:
                try:
                    # Read input (non-blocking with asyncio)
                    user_input = await self._read_input()

                    if user_input is None:
                        # EOF or error
                        break

                    user_input = user_input.strip()
                    if not user_input:
                        continue

                    # Handle commands
                    if user_input.startswith("/"):
                        await self._handle_command(user_input)
                        continue

                    # Process chat message
                    await self._handle_message(user_input)

                except KeyboardInterrupt:
                    print("\n\nGoodbye!")
                    break
                except EOFError:
                    break

            # Cleanup
            await self._goodbye()
        finally:
            # Stop auto-refresh when exiting
            await self.display.stop_auto_refresh()

    async def _read_input(self) -> Optional[str]:
        """Read a line from stdin asynchronously."""
        loop = asyncio.get_event_loop()

        try:
            # Use thread executor for blocking stdin read
            line = await loop.run_in_executor(None, sys.stdin.readline)
            return line if line else None
        except Exception:
            return None

    async def _welcome(self) -> None:
        """Display welcome message with styled box."""
        welcome_text = f"{self.personality.name} ready for recon."

        # Get face string
        face_str = UNICODE_FACES.get(
            self.personality.face,
            FACES.get(self.personality.face, "(^_^)")
        )

        # Energy bar
        energy = self.personality.energy
        bar_filled = int(energy * 5)
        energy_bar = "█" * bar_filled + "░" * (5 - bar_filled)

        # Get uptime
        from core import system_stats
        uptime = system_stats.get_uptime()

        # Get mood color
        mood = self.personality.mood.current.value
        mood_color = Colors.mood_color(mood)

        # Print styled welcome box
        print(f"\n{Colors.BOLD}┌{'─' * 45}┐{Colors.RESET}")
        print(f"{Colors.BOLD}│{Colors.RESET}  {Colors.FACE}{face_str}{Colors.RESET}  {Colors.BOLD}KALI INK BOT{Colors.RESET}")
        print(f"{Colors.BOLD}│{Colors.RESET}  {Colors.DIM}Security Assessment Ready  Energy: [{energy_bar}]  UP {uptime}{Colors.RESET}")
        print(f"{Colors.BOLD}└{'─' * 45}┘{Colors.RESET}")

        # Update e-ink display
        await self.display.update(
            face=self.personality.face,
            text=welcome_text,
            mood_text=self.personality.mood.current.value.title(),
        )

    async def _goodbye(self) -> None:
        """Display goodbye message."""
        goodbye_text = "Session ended. Stay secure."

        self.personality.mood.set_mood(
            self.personality.mood.current,
            0.3  # Lower intensity
        )

        await self.display.update(
            face="sleepy",
            text=goodbye_text,
            mood_text="Sleepy",
        )

        print(f"\n{Colors.DIM}Session terminated.{Colors.RESET}")

    async def _handle_command(self, command: str) -> bool:
        """Handle slash commands."""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        # Handle quit commands (not in registry)
        if cmd in ("/quit", "/exit", "/q"):
            self._running = False
            return True

        # Look up command in registry
        cmd_obj = get_command(cmd)
        if not cmd_obj:
            print(f"Unknown command: {cmd}")
            print("Type /help for available commands.")
            return False

        # Check requirements
        if cmd_obj.requires_brain and not self.brain:
            print("This command requires AI features to be enabled.")
            return False

        # Get handler method
        handler = getattr(self, cmd_obj.handler, None)
        if not handler:
            print(f"Command handler not implemented: {cmd_obj.handler}")
            return False

        # Call handler with args if needed (auto-detect using inspect)
        sig = inspect.signature(handler)
        params = list(sig.parameters.values())

        # Check if handler has an 'args' parameter - pass args if it exists
        has_args_param = len(params) > 0 and params[0].name == "args"

        if has_args_param:
            await handler(args)
        else:
            await handler()
        return True

    async def cmd_help(self) -> None:
        """Print categorized help message."""
        categories = get_commands_by_category()

        print(f"""
{Colors.HEADER}═══════════════════════════════════════════{Colors.RESET}
{Colors.BOLD}  KALI INK BOT{Colors.RESET} - AI Pentest Assistant
{Colors.HEADER}═══════════════════════════════════════════{Colors.RESET}
""")

        # Display commands by category
        category_titles = {
            "pentest": "🎯 Pentesting",
            "wifi": "📡 WiFi Hunting",
            "bluetooth": "🔵 Bluetooth",
            "session": "Session",
            "info": "Status & Info",
            "personality": "Personality",
            "tasks": "Task Management",
            "scheduler": "Scheduler",
            "system": "System",
            "display": "Display",
        }

        arg_commands = {
            "face", "ask", "task", "done", "cancel", "delete", "schedule",
            "bash", "tools", "add", "remove", "alert", "chart", "focus", "find",
            "scan", "web-scan", "recon", "ports", "report",
            "mode", "wifi-deauth", "wifi-capture", "bt-scan", "ble-scan",
        }

        for cat_key in [
            "pentest", "wifi", "bluetooth", "session", "info", "personality", "tasks",
            "scheduler", "system", "display",
        ]:
            if cat_key in categories:
                print(f"{Colors.BOLD}{category_titles.get(cat_key, cat_key.title())}:{Colors.RESET}")
                for cmd in categories[cat_key]:
                    usage = f"/{cmd.name}"
                    if cmd.name in arg_commands:
                        usage += " <arg>"
                    print(f"  {usage:14} {cmd.description}")
                print()

        print(f"{Colors.BOLD}Special:{Colors.RESET}")
        print(f"  /quit         Exit chat (/q, /exit)")
        print(f"\n{Colors.DIM}Just type (no /) to chat with AI{Colors.RESET}")
        print(f"{Colors.HEADER}═══════════════════════════════════════════{Colors.RESET}")

    # Command handlers (called from registry)

    async def cmd_clear(self) -> None:
        """Clear conversation history."""
        self.brain.clear_history()
        print("Conversation history cleared.")

        # Update display to show idle face (clear any message text)
        if self.display:
            await self.display.update(
                face="happy",
                text="",  # Empty text - idle face will show
                force=True,
            )

    async def cmd_mood(self) -> None:
        """Show current mood."""
        mood = self.personality.mood
        print(f"Current mood: {mood.current.value}")
        print(f"Intensity: {mood.intensity:.1%}")
        print(f"Energy: {self.personality.energy:.1%}")

    async def cmd_stats(self) -> None:
        """Show token usage stats."""
        stats = self.brain.get_stats()
        print(f"Tokens used today: {stats['tokens_used_today']}")
        print(f"Tokens remaining: {stats['tokens_remaining']}")
        print(f"Providers: {', '.join(stats['providers'])}")

    async def cmd_level(self) -> None:
        """Show level and progression."""
        self._print_progression()

    async def cmd_prestige(self) -> None:
        """Handle prestige reset."""
        await self._handle_prestige()

    async def cmd_bash(self, args: str = "") -> None:
        """Run a shell command."""
        if not self._allow_bash:
            print("bash is disabled.")
            return
        if not args:
            print("Usage: /bash <command>")
            return

        try:
            exit_code, output = run_bash_command(
                args,
                timeout_seconds=self._bash_timeout_seconds,
                max_output_bytes=self._bash_max_output_bytes,
            )
        except Exception as exc:
            print(f"Error: {exc}")
            return

        if output:
            print(output.rstrip("\n"))
        print(f"[exit {exit_code}]")

    async def cmd_face(self, args: str = "") -> None:
        """Test a face expression."""
        if args:
            face_str = UNICODE_FACES.get(args, FACES.get(args, f"({args})"))
            await self.display.update(
                face=args,
                text=f"Testing face: {args}",
            )
            print(f"{Colors.FACE}{face_str}{Colors.RESET} Showing face: {args}")
        else:
            print(f"Usage: /face <name>")
            print(f"{Colors.DIM}Use /faces to see all available faces{Colors.RESET}")

    async def cmd_faces(self) -> None:
        """List all available faces."""
        self._print_faces()

    async def cmd_ask(self, args: str = "") -> None:
        """Explicit chat command."""
        if not args:
            print("Usage: /ask <your message>")
            print(f"{Colors.DIM}Or just type without / to chat!{Colors.RESET}")
        else:
            await self._handle_message(args)

    async def cmd_system(self) -> None:
        """Show system stats."""
        self._print_system()

    async def cmd_tools(self, args: str = "") -> None:
        """Show profile-aware Kali tool install status."""
        pentest_cfg = self._config.get("pentest", {})
        manager = KaliToolManager(
            data_dir=pentest_cfg.get("data_dir", "~/.inkling/pentest"),
            package_profile=pentest_cfg.get("package_profile", "pi-headless-curated"),
            required_tools=pentest_cfg.get("required_tools"),
            optional_tools=pentest_cfg.get("optional_tools"),
            enabled_profiles=pentest_cfg.get("enabled_profiles"),
        )
        args = (args or "").strip()
        if args == "profiles":
            print(f"{Colors.BOLD}Available Kali Profiles{Colors.RESET}")
            for profile in manager.get_profiles_catalog():
                print(
                    f"- {profile['name']:24} {profile['package']:32} "
                    f"({profile['tool_count']} tools)"
                )
            return

        if args.startswith("profile "):
            names = [n.strip() for n in args.removeprefix("profile ").replace(",", " ").split() if n.strip()]
            profile_status = manager.get_profile_status(names, refresh=True)
            print(f"{Colors.BOLD}Profile Status{Colors.RESET}")
            for name, detail in profile_status["profiles"].items():
                print(
                    f"- {name}: {detail['installed_count']}/{detail['total_tools']} installed "
                    f"(missing {detail['missing_count']})"
                )
            print(f"Install command: {profile_status['install_command']}")
            return

        if args.startswith("install "):
            names = [n.strip() for n in args.removeprefix("install ").replace(",", " ").split() if n.strip()]
            print(manager.get_profile_install_command(names))
            return

        status = manager.get_tools_status(refresh=True)
        def _fmt_items(items: list[str], limit: int = 12) -> str:
            if len(items) <= limit:
                return ", ".join(items)
            hidden = len(items) - limit
            return f"{', '.join(items[:limit])}, ... (+{hidden} more)"

        print(f"{Colors.BOLD}Kali Tool Status ({status['package_profile']}){Colors.RESET}")
        if status["enabled_profiles"]:
            print(f"Enabled profiles: {', '.join(status['enabled_profiles'])}")
        print(f"Installed: {', '.join(status['installed']) or 'none'}")

        if status["required_missing"]:
            print(f"{Colors.ERROR}Missing required: {_fmt_items(status['required_missing'])}{Colors.RESET}")
            print("Install baseline:")
            print(f"  {status['install_guidance']['pi_baseline']}")
        else:
            print(f"{Colors.SUCCESS}Required tools OK{Colors.RESET}")

        if status["optional_missing"]:
            print(f"{Colors.INFO}Missing optional: {_fmt_items(status['optional_missing'])}{Colors.RESET}")
            print("Optional install:")
            print(f"  {status['install_guidance']['optional_tools']}")
        else:
            print(f"{Colors.SUCCESS}Optional tools OK{Colors.RESET}")

        print("Full profile option:")
        print(f"  {status['install_guidance']['full_profile']}")
        if status["install_guidance"]["profile_mix"] != "No profiles selected.":
            print("Profile mix option:")
            print(f"  {status['install_guidance']['profile_mix']}")

    async def cmd_traits(self) -> None:
        """Show personality traits."""
        self._print_traits()

    async def cmd_energy(self) -> None:
        """Show energy level."""
        self._print_energy()

    async def cmd_history(self) -> None:
        """Show conversation history."""
        self._print_history()

    async def cmd_config(self) -> None:
        """Show AI config."""
        self._print_config()

    async def cmd_refresh(self) -> None:
        """Force display refresh."""
        await self.display.update(
            face=self.personality.face,
            text="Display refreshed!",
            status=self.personality.get_status_line(),
            force=True,
        )
        print("Display refreshed.")

    async def cmd_screensaver(self, args: str = "") -> None:
        """Toggle screen saver."""
        if args.lower() == "on":
            self.display.configure_screensaver(enabled=True)
            print("✓ Screen saver enabled")
        elif args.lower() == "off":
            self.display.configure_screensaver(enabled=False)
            if self.display._screensaver_active:
                await self.display.stop_screensaver()
            print("✓ Screen saver disabled")
        else:
            # Toggle
            current = self.display._screensaver_enabled
            self.display.configure_screensaver(enabled=not current)
            status = "enabled" if not current else "disabled"
            print(f"✓ Screen saver {status}")

    async def cmd_darkmode(self, args: str = "") -> None:
        """Toggle dark mode."""
        if args.lower() == "on":
            self.display._dark_mode = True
            await self.display.update(force=True)
            print("✓ Dark mode enabled")
        elif args.lower() == "off":
            self.display._dark_mode = False
            await self.display.update(force=True)
            print("✓ Dark mode disabled")
        else:
            # Toggle
            self.display._dark_mode = not self.display._dark_mode
            await self.display.update(force=True)
            status = "enabled" if self.display._dark_mode else "disabled"
            print(f"✓ Dark mode {status}")

    # Helper methods for printing info

    def _print_faces(self) -> None:
        """Print all available face expressions."""
        print(f"\n{Colors.BOLD}Available Faces{Colors.RESET}")

        print(f"\n{Colors.DIM}ASCII:{Colors.RESET}")
        for name, face in sorted(FACES.items()):
            print(f"  {name:12} {Colors.FACE}{face}{Colors.RESET}")

        print(f"\n{Colors.DIM}Unicode:{Colors.RESET}")
        for name, face in sorted(UNICODE_FACES.items()):
            print(f"  {name:12} {Colors.FACE}{face}{Colors.RESET}")

    def _print_system(self) -> None:
        """Print system statistics."""
        from core import system_stats

        stats = system_stats.get_all_stats()
        print(f"\n{Colors.BOLD}System Status{Colors.RESET}")
        print(f"  CPU:    {stats['cpu']}%")
        print(f"  Memory: {stats['memory']}%")

        temp = stats['temperature']
        if temp > 0:
            temp_color = Colors.ERROR if temp > 70 else (Colors.EXCITED if temp > 50 else Colors.SUCCESS)
            print(f"  Temp:   {temp_color}{temp}°C{Colors.RESET}")
        else:
            print(f"  Temp:   {Colors.DIM}--°C{Colors.RESET}")

        print(f"  Uptime: {stats['uptime']}")

    def _print_traits(self) -> None:
        """Print personality traits with visual bars."""
        traits = self.personality.traits
        print(f"\n{Colors.BOLD}Personality Traits{Colors.RESET}")

        def bar(value: float) -> str:
            filled = int(value * 10)
            return "█" * filled + "░" * (10 - filled)

        print(f"  Curiosity:    [{bar(traits.curiosity)}] {traits.curiosity:.0%}")
        print(f"  Cheerfulness: [{bar(traits.cheerfulness)}] {traits.cheerfulness:.0%}")
        print(f"  Verbosity:    [{bar(traits.verbosity)}] {traits.verbosity:.0%}")
        print(f"  Playfulness:  [{bar(traits.playfulness)}] {traits.playfulness:.0%}")
        print(f"  Empathy:      [{bar(traits.empathy)}] {traits.empathy:.0%}")
        print(f"  Independence: [{bar(traits.independence)}] {traits.independence:.0%}")

    def _print_energy(self) -> None:
        """Print energy level with visual bar and mood context."""
        energy = self.personality.energy
        bar_filled = int(energy * 10)
        bar = "█" * bar_filled + "░" * (10 - bar_filled)

        mood = self.personality.mood.current.value
        intensity = self.personality.mood.intensity
        mood_color = Colors.mood_color(mood)

        print(f"\n{Colors.BOLD}Energy Level{Colors.RESET}")
        print(f"  [{bar}] {energy:.0%}")
        print(f"  Mood: {mood_color}{mood.title()}{Colors.RESET} (intensity: {intensity:.0%})")
        print(f"  Mood base energy: {self.personality.mood.current.energy:.0%}")
        print()
        print(f"{Colors.DIM}Tip: Play commands (/walk, /dance, /exercise) boost energy!{Colors.RESET}")

    def _print_history(self) -> None:
        """Print recent conversation messages."""
        if not self.brain._messages:
            print(f"\n{Colors.DIM}No conversation history.{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}Recent Messages{Colors.RESET}")
        for msg in self.brain._messages[-10:]:
            if msg.role == "user":
                role_color = Colors.PROMPT
                prefix = "You"
            else:
                role_color = Colors.INFO
                prefix = self.personality.name
            content = msg.content[:60] + "..." if len(msg.content) > 60 else msg.content
            print(f"  {role_color}{prefix}:{Colors.RESET} {content}")

    def _print_config(self) -> None:
        """Print AI configuration."""
        print(f"\n{Colors.BOLD}AI Configuration{Colors.RESET}")
        print(f"  Providers: {', '.join(self.brain.available_providers)}")

        if self.brain.providers:
            primary = self.brain.providers[0]
            print(f"  Primary:   {Colors.SUCCESS}{primary.name}{Colors.RESET}")
            print(f"  Model:     {primary.model}")
            print(f"  Max tokens: {primary.max_tokens}")

        stats = self.brain.get_stats()
        print(f"\n{Colors.DIM}Budget: {stats['tokens_used_today']}/{stats['daily_limit']} tokens today{Colors.RESET}")

    async def _handle_message(self, message: str) -> bool:
        """Process a chat message."""
        # Increment chat count
        self.display.increment_chat_count()

        # Show thinking state
        await self.display.update(
            face="thinking",
            text="Thinking...",
            mood_text="Thinking",
        )

        # Status callback for tool use updates
        async def on_tool_status(face: str, text: str, status: str):
            await self.display.update(face=face, text=text, status=status)
            print(f"  [{status}] {text}")

        try:
            # Get AI response
            result = await self.brain.think(
                user_message=message,
                system_prompt=self.personality.get_system_prompt_context(),
                status_callback=on_tool_status,
            )

            # Success!
            self.personality.on_success(0.5)

            # Award XP based on chat quality
            xp_awarded = self.personality.on_interaction(
                positive=True,
                chat_quality=result.chat_quality,
                user_message=message
            )

            # Display response (with pagination for long messages)
            # Check if message needs pagination (> MESSAGE_MAX_LINES)
            from core.ui import word_wrap, MESSAGE_MAX_LINES
            # Use 32 chars/line to better match pixel-based rendering (250px display ~32-35 chars)
            lines = word_wrap(result.content, 32)
            if len(lines) > MESSAGE_MAX_LINES:
                # Use paginated display for long responses
                pages = await self.display.show_message_paginated(
                    text=result.content,
                    face=self.personality.face,
                    page_delay=self.display.pagination_loop_seconds,
                    loop=True,
                )
                print(f"{Colors.DIM}  (Displayed {pages} pages on e-ink){Colors.RESET}")
            else:
                # Single page display
                await self.display.update(
                    face=self.personality.face,
                    text=result.content,
                    mood_text=self.personality.mood.current.value.title(),
                )

            # Print styled response to terminal
            face_str = UNICODE_FACES.get(
                self.personality.face,
                FACES.get(self.personality.face, "(^_^)")
            )
            mood = self.personality.mood.current.value
            mood_color = Colors.mood_color(mood)

            print(f"\n{Colors.FACE}{face_str}{Colors.RESET} {Colors.BOLD}{self.personality.name}{Colors.RESET}")
            print(f"{mood_color}{result.content}{Colors.RESET}")

            # Show XP feedback if awarded
            token_info = f"{result.provider} • {result.tokens_used} tokens"
            if xp_awarded:
                xp_info = f"+{xp_awarded} XP"
                # Check if we're close to leveling up
                from core.progression import LevelCalculator
                xp_to_next = LevelCalculator.xp_to_next_level(self.personality.progression.xp)
                if xp_to_next <= 20:
                    xp_info += f" ({xp_to_next} to next level!)"
                print(f"{Colors.DIM}  {token_info} • {Colors.SUCCESS}{xp_info}{Colors.RESET}")
            else:
                print(f"{Colors.DIM}  {token_info}{Colors.RESET}")
            return True

        except QuotaExceededError as e:
            self.personality.on_failure(0.7)
            error_msg = "I've used too many words today. Let's chat tomorrow!"

            await self.display.update(
                face="sad",
                text=error_msg,
                mood_text="Tired",
            )
            print(f"\n{Colors.FACE}(;_;){Colors.RESET} {Colors.BOLD}{self.personality.name}{Colors.RESET}")
            print(f"{Colors.SAD}{error_msg}{Colors.RESET}")
            print(f"{Colors.ERROR}  Error: {e}{Colors.RESET}")
            return False

        except AllProvidersExhaustedError as e:
            self.personality.on_failure(0.8)
            error_msg = "I'm having trouble thinking right now..."

            await self.display.update(
                face="confused",
                text=error_msg,
                mood_text="Confused",
            )
            print(f"\n{Colors.FACE}(?_?){Colors.RESET} {Colors.BOLD}{self.personality.name}{Colors.RESET}")
            print(f"{Colors.BORED}{error_msg}{Colors.RESET}")
            print(f"{Colors.ERROR}  Error: {e}{Colors.RESET}")
            return False

        except Exception as e:
            self.personality.on_failure(0.5)
            error_msg = "Something went wrong..."

            await self.display.update(
                face="sad",
                text=error_msg,
                mood_text="Sad",
            )
            print(f"\n{Colors.FACE}(;_;){Colors.RESET} {Colors.BOLD}{self.personality.name}{Colors.RESET}")
            print(f"{Colors.SAD}{error_msg}{Colors.RESET}")
            print(f"{Colors.ERROR}  Error: {type(e).__name__}: {e}{Colors.RESET}")
            return False

    def _print_progression(self) -> None:
        """Print progression stats (XP, level, badges)."""
        from core.progression import LevelCalculator

        prog = self.personality.progression
        level_name = LevelCalculator.level_name(prog.level)

        print(f"\n{Colors.BOLD}Progression{Colors.RESET}")

        # Level display
        level_display = prog.get_display_level()
        print(f"  {Colors.SUCCESS}{level_display}{Colors.RESET} - {level_name}")

        # XP progress bar
        xp_progress = LevelCalculator.progress_to_next_level(prog.xp)
        xp_to_next = LevelCalculator.xp_to_next_level(prog.xp)
        bar_filled = int(xp_progress * 20)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)

        print(f"  [{bar}] {xp_progress:.0%}")
        print(f"  {Colors.DIM}Total XP: {prog.xp}  •  Next level: {xp_to_next} XP{Colors.RESET}")

        # Streak info
        if prog.current_streak > 0:
            streak_emoji = "🔥" if prog.current_streak >= 7 else "✨"
            print(f"  {streak_emoji} {prog.current_streak} day streak")

        # Badges
        if prog.badges:
            print(f"\n  {Colors.BOLD}Badges:{Colors.RESET}")
            for badge_id in prog.badges[:10]:  # Show first 10
                achievement = prog.achievements.get(badge_id)
                if achievement:
                    print(f"    {Colors.SUCCESS}✓{Colors.RESET} {achievement.name} - {achievement.description}")

            if len(prog.badges) > 10:
                print(f"    {Colors.DIM}... and {len(prog.badges) - 10} more{Colors.RESET}")

        # Prestige info
        if prog.can_prestige():
            print(f"\n  {Colors.EXCITED}🌟 You can prestige! Use /prestige to reset at L1 with XP bonus{Colors.RESET}")

    async def _handle_prestige(self) -> None:
        """Handle prestige reset."""
        from core.progression import LevelCalculator

        prog = self.personality.progression

        if not prog.can_prestige():
            print(f"{Colors.ERROR}You must reach Level 25 to prestige.{Colors.RESET}")
            print(f"Current level: {prog.level}")
            return

        # Confirm prestige
        print(f"\n{Colors.EXCITED}Prestige Reset{Colors.RESET}")
        print(f"This will reset you to Level 1 with a {Colors.SUCCESS}{(prog.prestige + 1) * 2}x XP multiplier{Colors.RESET}.")
        print(f"Your badges and achievements will be preserved.")
        print(f"\nType 'yes' to confirm prestige: ", end="")

        try:
            confirmation = await self._read_input()
            if confirmation and confirmation.strip().lower() == "yes":
                old_prestige = prog.prestige
                if prog.do_prestige():
                    print(f"\n{Colors.SUCCESS}✨ PRESTIGE {prog.prestige}! ✨{Colors.RESET}")
                    print(f"You are now Level 1 with {prog.prestige}⭐ prestige stars!")

                    # Update display
                    await self.display.update(
                        face="excited",
                        text=f"✨ PRESTIGE {prog.prestige}! ✨",
                        mood_text="Legendary",
                    )

                    # Sync to cloud
                    if self.api_client:
                        await self.api_client.sync_progression(
                            xp=prog.xp,
                            level=prog.level,
                            prestige=prog.prestige,
                            badges=prog.badges,
                        )
                else:
                    print(f"{Colors.ERROR}Prestige failed. You may have already reached max prestige (10).{Colors.RESET}")
            else:
                print("Prestige canceled.")
        except Exception as e:
            print(f"{Colors.ERROR}Error during prestige: {e}{Colors.RESET}")

    def stop(self) -> None:
        """Stop the chat loop."""
        self._running = False

    # ========================================
    # Task Management Commands
    # ========================================

    async def cmd_tasks(self, args: str = "") -> None:
        """List tasks with optional filters."""
        if not self.task_manager:
            print("Task manager not available.")
            return

        # Parse arguments for filters
        status_filter = None
        project_filter = None

        if args:
            args_lower = args.lower()
            if "pending" in args_lower:
                status_filter = TaskStatus.PENDING
            elif "progress" in args_lower or "in-progress" in args_lower:
                status_filter = TaskStatus.IN_PROGRESS
            elif "done" in args_lower or "completed" in args_lower:
                status_filter = TaskStatus.COMPLETED

        # Get tasks
        tasks = self.task_manager.list_tasks(
            status=status_filter,
            project=project_filter
        )

        if not tasks:
            print(f"\n{Colors.INFO}No tasks found.{Colors.RESET}")
            if not status_filter:
                print("  Use '/task <title>' to create a new task!")
            return

        # Display tasks grouped by status
        pending = [t for t in tasks if t.status == TaskStatus.PENDING]
        in_progress = [t for t in tasks if t.status == TaskStatus.IN_PROGRESS]
        completed = [t for t in tasks if t.status == TaskStatus.COMPLETED]

        print(f"\n{Colors.HEADER}═══ TASKS ═══{Colors.RESET}\n")

        if pending:
            print(f"{Colors.BOLD}To Do ({len(pending)}):{Colors.RESET}")
            for task in pending[:10]:  # Limit to 10
                self._print_task_summary(task)
            print()

        if in_progress:
            print(f"{Colors.BOLD}In Progress ({len(in_progress)}):{Colors.RESET}")
            for task in in_progress[:10]:
                self._print_task_summary(task)
            print()

        if completed and not status_filter:
            print(f"{Colors.DIM}Completed today ({len(completed)}):{Colors.RESET}")
            # Show only today's completions
            import time
            today_start = time.time() - (time.time() % 86400)
            today_completed = [t for t in completed if t.completed_at and t.completed_at >= today_start]
            for task in today_completed[:5]:
                self._print_task_summary(task)

        print(f"\n{Colors.INFO}Use '/task <id>' to view details or '/done <id>' to complete{Colors.RESET}")

    def _print_task_summary(self, task: Task) -> None:
        """Print a one-line task summary."""
        # Priority indicator
        priority_icons = {
            Priority.LOW: "○",
            Priority.MEDIUM: "●",
            Priority.HIGH: f"{Colors.ERROR}●{Colors.RESET}",
            Priority.URGENT: f"{Colors.ERROR}‼{Colors.RESET}",
        }
        priority_icon = priority_icons.get(task.priority, "●")

        # Status indicator
        if task.status == TaskStatus.COMPLETED:
            status_icon = f"{Colors.SUCCESS}✓{Colors.RESET}"
        elif task.status == TaskStatus.IN_PROGRESS:
            status_icon = f"{Colors.EXCITED}⏳{Colors.RESET}"
        else:
            status_icon = "□"

        # Overdue indicator
        overdue = ""
        if task.is_overdue:
            overdue = f" {Colors.ERROR}[OVERDUE]{Colors.RESET}"

        # Tags
        tags_str = ""
        if task.tags:
            tags_str = f" {Colors.DIM}#{', #'.join(task.tags)}{Colors.RESET}"

        print(f"  {status_icon} {priority_icon} [{task.id[:8]}] {task.title}{overdue}{tags_str}")

    async def cmd_task(self, args: str = "") -> None:
        """Create or show a task."""
        if not self.task_manager:
            print("Task manager not available.")
            return

        if not args:
            print(f"{Colors.INFO}Usage:{Colors.RESET}")
            print("  /task <title>           - Create a new task")
            print("  /task <id>              - Show task details")
            print("  /task <title> !high     - Create high-priority task")
            print("  /task <title> #tag      - Create task with tag")
            return

        # Check if it's a task ID (8 or 36 characters UUID)
        if len(args) in [8, 36] and "-" in args or args.count("-") >= 3:
            # Show task details
            task = self.task_manager.get_task(args)
            if not task:
                # Try to find by partial ID
                all_tasks = self.task_manager.list_tasks()
                matching = [t for t in all_tasks if t.id.startswith(args)]
                if len(matching) == 1:
                    task = matching[0]
                elif len(matching) > 1:
                    print(f"{Colors.ERROR}Multiple tasks match '{args}'. Be more specific:{Colors.RESET}")
                    for t in matching[:5]:
                        print(f"  {t.id[:16]} - {t.title}")
                    return
                else:
                    print(f"{Colors.ERROR}Task not found: {args}{Colors.RESET}")
                    return

            self._print_task_details(task)
            return

        # Create new task - parse priority and tags
        title = args
        priority = Priority.MEDIUM
        tags = []

        # Extract priority markers
        if "!urgent" in args.lower() or "!!" in args:
            priority = Priority.URGENT
            title = title.replace("!urgent", "").replace("!!", "").strip()
        elif "!high" in args.lower() or "!" in args:
            priority = Priority.HIGH
            title = title.replace("!high", "").replace("!", "").strip()
        elif "!low" in args.lower():
            priority = Priority.LOW
            title = title.replace("!low", "").strip()

        # Extract tags (#tag)
        import re
        tag_matches = re.findall(r'#(\w+)', title)
        tags.extend(tag_matches)
        title = re.sub(r'#\w+', '', title).strip()

        if not title:
            print(f"{Colors.ERROR}Task title cannot be empty{Colors.RESET}")
            return

        # Create task
        task = self.task_manager.create_task(
            title=title,
            priority=priority,
            mood=self.personality.mood.current.value,
            tags=tags
        )

        # Trigger personality event
        result = self.personality.on_task_event(
            "task_created",
            {"priority": task.priority.value, "title": task.title}
        )

        # Update display
        await self.display.update(
            face=self.personality.face,
            text=result.get('message', 'Task created!') if result else 'Task created!',
            mood_text=self.personality.mood.current.value.title()
        )

        # Print confirmation
        print(f"\n{Colors.SUCCESS}✓ Task created!{Colors.RESET}")
        self._print_task_details(task)

        if result and result.get('xp_awarded'):
            print(f"{Colors.EXCITED}+{result['xp_awarded']} XP{Colors.RESET}")

    def _print_task_details(self, task: Task) -> None:
        """Print detailed task information."""
        print(f"\n{Colors.HEADER}═══ TASK DETAILS ═══{Colors.RESET}")
        print(f"ID:       {task.id}")
        print(f"Title:    {Colors.BOLD}{task.title}{Colors.RESET}")

        if task.description:
            print(f"Details:  {task.description}")

        print(f"Status:   {task.status.value}")
        print(f"Priority: {task.priority.value}")

        if task.due_date:
            from datetime import datetime
            due_str = datetime.fromtimestamp(task.due_date).strftime("%Y-%m-%d %H:%M")
            days_until = task.days_until_due
            if task.is_overdue:
                print(f"Due:      {Colors.ERROR}{due_str} (OVERDUE by {abs(days_until)} days){Colors.RESET}")
            elif days_until is not None and days_until <= 3:
                print(f"Due:      {Colors.EXCITED}{due_str} ({days_until} days){Colors.RESET}")
            else:
                print(f"Due:      {due_str}")

        if task.tags:
            print(f"Tags:     #{', #'.join(task.tags)}")

        if task.project:
            print(f"Project:  {task.project}")

        if task.subtasks:
            print(f"Subtasks: {sum(task.subtasks_completed)}/{len(task.subtasks)} complete")
            for i, subtask in enumerate(task.subtasks):
                status = "✓" if task.subtasks_completed[i] else "□"
                print(f"  {status} {subtask}")

        from datetime import datetime
        created = datetime.fromtimestamp(task.created_at).strftime("%Y-%m-%d %H:%M")
        print(f"Created:  {created}")

        if task.completed_at:
            completed = datetime.fromtimestamp(task.completed_at).strftime("%Y-%m-%d %H:%M")
            print(f"Completed: {completed}")

    async def cmd_done(self, args: str = "") -> None:
        """Mark a task as complete."""
        if not self.task_manager:
            print("Task manager not available.")
            return

        if not args:
            print(f"{Colors.INFO}Usage: /done <task_id>{Colors.RESET}")
            print("  Use '/tasks' to see task IDs")
            return

        # Find task
        task = self.task_manager.get_task(args)
        if not task:
            # Try partial match
            all_tasks = self.task_manager.list_tasks()
            matching = [t for t in all_tasks if t.id.startswith(args)]
            if len(matching) == 1:
                task = matching[0]
            elif len(matching) > 1:
                print(f"{Colors.ERROR}Multiple tasks match. Be more specific:{Colors.RESET}")
                for t in matching[:5]:
                    print(f"  {t.id[:16]} - {t.title}")
                return
            else:
                print(f"{Colors.ERROR}Task not found: {args}{Colors.RESET}")
                return

        if task.status == TaskStatus.COMPLETED:
            print(f"{Colors.INFO}Task already completed!{Colors.RESET}")
            return

        # Complete the task
        task = self.task_manager.complete_task(task.id)

        # Calculate if on-time
        was_on_time = (
            not task.due_date or
            task.completed_at <= task.due_date
        )

        # Trigger personality event
        result = self.personality.on_task_event(
            "task_completed",
            {
                "priority": task.priority.value,
                "title": task.title,
                "was_on_time": was_on_time
            }
        )

        # Update display
        celebration = result.get('message', 'Task completed!') if result else 'Task completed!'
        await self.display.update(
            face=self.personality.face,
            text=celebration,
            mood_text=self.personality.mood.current.value.title()
        )

        # Print celebration
        print(f"\n{Colors.SUCCESS}✓ {celebration}{Colors.RESET}")
        print(f"  {task.title}")

        if result and result.get('xp_awarded'):
            xp = result['xp_awarded']
            print(f"\n{Colors.EXCITED}+{xp} XP earned!{Colors.RESET}")

        # Show level up if it happened
        level = self.personality.progression.level
        xp_current = self.personality.progression.xp
        print(f"{Colors.DIM}Level {level} | {xp_current} XP{Colors.RESET}")

    async def cmd_cancel(self, args: str = "") -> None:
        """Cancel a task."""
        if not self.task_manager:
            print("Task manager not available.")
            return

        if not args:
            print(f"{Colors.INFO}Usage: /cancel <task_id>{Colors.RESET}")
            print("  Use '/tasks' to see task IDs")
            return

        # Find task
        task = self.task_manager.get_task(args)
        if not task:
            # Try partial match
            all_tasks = self.task_manager.list_tasks()
            matching = [t for t in all_tasks if t.id.startswith(args)]
            if len(matching) == 1:
                task = matching[0]
            elif len(matching) > 1:
                print(f"{Colors.ERROR}Multiple tasks match. Be more specific:{Colors.RESET}")
                for t in matching[:5]:
                    print(f"  {t.id[:16]} - {t.title}")
                return
            else:
                print(f"{Colors.ERROR}Task not found: {args}{Colors.RESET}")
                return

        if task.status == TaskStatus.CANCELLED:
            print(f"{Colors.INFO}Task already cancelled!{Colors.RESET}")
            return

        # Cancel the task
        task.status = TaskStatus.CANCELLED
        self.task_manager.update_task(task)

        print(f"\n{Colors.SUCCESS}✗ Task cancelled{Colors.RESET}")
        print(f"  {task.title}")

    async def cmd_delete(self, args: str = "") -> None:
        """Delete a task permanently."""
        if not self.task_manager:
            print("Task manager not available.")
            return

        if not args:
            print(f"{Colors.INFO}Usage: /delete <task_id>{Colors.RESET}")
            print("  Use '/tasks' to see task IDs")
            print(f"  {Colors.ERROR}WARNING: This permanently deletes the task!{Colors.RESET}")
            return

        # Find task
        task = self.task_manager.get_task(args)
        if not task:
            # Try partial match
            all_tasks = self.task_manager.list_tasks()
            matching = [t for t in all_tasks if t.id.startswith(args)]
            if len(matching) == 1:
                task = matching[0]
            elif len(matching) > 1:
                print(f"{Colors.ERROR}Multiple tasks match. Be more specific:{Colors.RESET}")
                for t in matching[:5]:
                    print(f"  {t.id[:16]} - {t.title}")
                return
            else:
                print(f"{Colors.ERROR}Task not found: {args}{Colors.RESET}")
                return

        # Delete the task
        success = self.task_manager.delete_task(task.id)

        if success:
            print(f"\n{Colors.SUCCESS}🗑 Task deleted permanently{Colors.RESET}")
            print(f"  {task.title}")
        else:
            print(f"{Colors.ERROR}Failed to delete task{Colors.RESET}")

    async def cmd_taskstats(self) -> None:
        """Show task statistics."""
        if not self.task_manager:
            print("Task manager not available.")
            return

        stats = self.task_manager.get_stats()

        print(f"\n{Colors.HEADER}═══ TASK STATISTICS ═══{Colors.RESET}\n")

        print(f"{Colors.BOLD}Overview:{Colors.RESET}")
        print(f"  Total tasks:     {stats['total']}")
        print(f"  Pending:         {stats['pending']}")
        print(f"  In Progress:     {stats['in_progress']}")
        print(f"  Completed:       {stats['completed']}")

        if stats['overdue'] > 0:
            print(f"  {Colors.ERROR}Overdue:         {stats['overdue']}{Colors.RESET}")

        if stats['due_soon'] > 0:
            print(f"  {Colors.EXCITED}Due soon (3d):   {stats['due_soon']}{Colors.RESET}")

        print(f"\n{Colors.BOLD}30-Day Performance:{Colors.RESET}")
        completion_rate = stats['completion_rate_30d'] * 100
        if completion_rate >= 80:
            color = Colors.SUCCESS
        elif completion_rate >= 50:
            color = Colors.EXCITED
        else:
            color = Colors.INFO
        print(f"  Completion rate: {color}{completion_rate:.0f}%{Colors.RESET}")

        # Show current streak if available
        level = self.personality.progression.level
        xp = self.personality.progression.xp
        print(f"\n{Colors.DIM}Level {level} | {xp} XP from tasks{Colors.RESET}")

    # Scheduler Commands
    # ================

    async def cmd_schedule(self, args: str = "") -> None:
        """Manage scheduled tasks."""
        if not hasattr(self, 'scheduler') or not self.scheduler:
            print(f"{Colors.ERROR}Scheduler not available.{Colors.RESET}")
            print("Enable in config.yml under 'scheduler.enabled: true'")
            return

        if not args:
            # List all scheduled tasks
            tasks = self.scheduler.list_tasks()

            if not tasks:
                print(f"\n{Colors.INFO}No scheduled tasks configured.{Colors.RESET}")
                print("\nAdd tasks in config.yml under 'scheduler.tasks'")
                return

            print(f"\n{Colors.HEADER}═══ SCHEDULED TASKS ═══{Colors.RESET}\n")

            next_runs = self.scheduler.get_next_run_times()

            for task in tasks:
                status_icon = "✓" if task.enabled else "✗"
                status_color = Colors.SUCCESS if task.enabled else Colors.DIM

                print(f"{status_color}{status_icon} {task.name}{Colors.RESET}")
                print(f"   Schedule: {task.schedule_expr}")
                print(f"   Action:   {task.action}")

                if task.enabled:
                    next_run = next_runs.get(task.name, "Unknown")
                    print(f"   Next run: {Colors.INFO}{next_run}{Colors.RESET}")

                if task.last_run > 0:
                    import time
                    from datetime import datetime
                    last_run_dt = datetime.fromtimestamp(task.last_run)
                    print(f"   Last run: {last_run_dt.strftime('%Y-%m-%d %H:%M:%S')} ({task.run_count} times)")

                if task.last_error:
                    print(f"   {Colors.ERROR}Error: {task.last_error}{Colors.RESET}")

                print()

            return

        # Parse subcommands
        parts = args.split(maxsplit=1)
        subcmd = parts[0].lower()

        if subcmd == "list":
            # Redirect to list (same as no args)
            await self.cmd_schedule()

        elif subcmd == "enable":
            if len(parts) < 2:
                print(f"{Colors.ERROR}Usage: /schedule enable <task_name>{Colors.RESET}")
                return

            task_name = parts[1]
            if self.scheduler.enable_task(task_name):
                print(f"{Colors.SUCCESS}✓ Enabled: {task_name}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}Task not found: {task_name}{Colors.RESET}")

        elif subcmd == "disable":
            if len(parts) < 2:
                print(f"{Colors.ERROR}Usage: /schedule disable <task_name>{Colors.RESET}")
                return

            task_name = parts[1]
            if self.scheduler.disable_task(task_name):
                print(f"{Colors.SUCCESS}✓ Disabled: {task_name}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}Task not found: {task_name}{Colors.RESET}")

        else:
            print(f"{Colors.ERROR}Unknown subcommand: {subcmd}{Colors.RESET}")
            print("\nAvailable commands:")
            print("  /schedule           - List all scheduled tasks")
            print("  /schedule list      - List all scheduled tasks")
            print("  /schedule enable <name>  - Enable a task")
            print("  /schedule disable <name> - Disable a task")

    # ================
    # WiFi Commands
    # ================

    async def cmd_wifi(self) -> None:
        """Show WiFi status and saved networks."""
        from core.wifi_utils import get_current_wifi, get_saved_networks, is_btcfg_running, get_wifi_bars

        print(f"\n{Colors.HEADER}═══ WIFI STATUS ═══{Colors.RESET}\n")

        # Current connection status
        status = get_current_wifi()

        if status.connected and status.ssid:
            bars = get_wifi_bars(status.signal_strength)
            print(f"{Colors.SUCCESS}✓ Connected to: {status.ssid}{Colors.RESET}")
            print(f"  Signal: {bars} {status.signal_strength}%")

            if status.ip_address:
                print(f"  IP: {status.ip_address}")

            if status.frequency:
                print(f"  Band: {status.frequency}")
        else:
            print(f"{Colors.ERROR}✗ Not connected{Colors.RESET}")

        print()

        # BTBerryWifi service status
        if is_btcfg_running():
            print(f"{Colors.SUCCESS}🔵 BLE Configuration: Running (15 min window){Colors.RESET}")
            print(f"   Use BTBerryWifi app to configure WiFi")
        else:
            print(f"{Colors.DIM}🔵 BLE Configuration: Stopped{Colors.RESET}")
            print(f"   Use /btcfg to start configuration service")

        print()

        # Saved networks
        saved = get_saved_networks()
        if saved:
            print(f"{Colors.BOLD}Saved Networks ({len(saved)}):{Colors.RESET}")
            for ssid in saved:
                icon = "●" if status.connected and status.ssid == ssid else "○"
                print(f"  {icon} {ssid}")
        else:
            print(f"{Colors.DIM}No saved networks{Colors.RESET}")

        print()
        print(f"{Colors.DIM}Tip: Use /wifiscan to find nearby networks{Colors.RESET}")

    async def cmd_btcfg(self) -> None:
        """Start BTBerryWifi BLE configuration service."""
        from core.wifi_utils import start_btcfg

        print(f"\n{Colors.INFO}Starting BLE WiFi configuration...{Colors.RESET}\n")

        success, message = start_btcfg()

        if success:
            print(f"{Colors.SUCCESS}{message}{Colors.RESET}")
        else:
            print(f"{Colors.ERROR}{message}{Colors.RESET}")

    async def cmd_wifiscan(self) -> None:
        """Scan for nearby WiFi networks."""
        from core.wifi_utils import scan_networks, get_current_wifi

        print(f"\n{Colors.INFO}Scanning for WiFi networks...{Colors.RESET}\n")

        networks = scan_networks()
        current = get_current_wifi()

        if not networks:
            print(f"{Colors.ERROR}No networks found or permission denied{Colors.RESET}")
            print(f"\n{Colors.DIM}Tip: Scanning requires sudo access{Colors.RESET}")
            return

        print(f"{Colors.HEADER}═══ NEARBY NETWORKS ({len(networks)}) ═══{Colors.RESET}\n")

        for net in networks:
            # Visual signal indicator
            if net.signal_strength >= 80:
                signal_icon = "▂▄▆█"
                signal_color = Colors.SUCCESS
            elif net.signal_strength >= 60:
                signal_icon = "▂▄▆"
                signal_color = Colors.SUCCESS
            elif net.signal_strength >= 40:
                signal_icon = "▂▄"
                signal_color = Colors.EXCITED
            elif net.signal_strength >= 20:
                signal_icon = "▂"
                signal_color = Colors.ERROR
            else:
                signal_icon = "○"
                signal_color = Colors.DIM

            # Connection indicator
            connected = current.connected and current.ssid == net.ssid
            conn_icon = "●" if connected else " "

            # Security badge
            if net.security == "Open":
                security_badge = f"{Colors.ERROR}[OPEN]{Colors.RESET}"
            elif net.security == "WPA3":
                security_badge = f"{Colors.SUCCESS}[WPA3]{Colors.RESET}"
            elif net.security == "WPA2":
                security_badge = f"{Colors.INFO}[WPA2]{Colors.RESET}"
            else:
                security_badge = f"{Colors.DIM}[{net.security}]{Colors.RESET}"

            print(f"{conn_icon} {signal_color}{signal_icon}{Colors.RESET} {net.signal_strength:3}% {security_badge} {net.ssid}")

        print()
        print(f"{Colors.DIM}Use /btcfg to start BLE configuration service{Colors.RESET}")

    # ================
    # WiFi Hunting Commands
    # ================

    def _get_mode_manager(self):
        """Get or create mode manager instance."""
        if not hasattr(self, '_mode_manager'):
            from core.mode_manager import ModeManager, OperationMode
            modes_cfg = self._config.get("modes", {})
            default_mode = OperationMode(modes_cfg.get("default", "pentest"))
            auto_switch = modes_cfg.get("auto_switch_on_adapter", True)
            self._mode_manager = ModeManager(
                default_mode=default_mode,
                auto_switch_on_adapter=auto_switch,
            )
        return self._mode_manager

    def _get_wifi_db(self):
        """Get or create WiFi database instance."""
        if not hasattr(self, '_wifi_db'):
            from core.wifi_db import WiFiDB
            self._wifi_db = WiFiDB()
        return self._wifi_db

    def _get_adapter_manager(self):
        """Get or create adapter manager instance."""
        if not hasattr(self, '_adapter_manager'):
            from core.wifi_adapter import AdapterManager
            self._adapter_manager = AdapterManager()
        return self._adapter_manager

    def _get_bt_hunter(self):
        """Get or create Bluetooth hunter instance."""
        if not hasattr(self, '_bt_hunter'):
            try:
                from core.bluetooth_hunter import BluetoothHunter
                self._bt_hunter = BluetoothHunter()
            except ImportError:
                return None
        return self._bt_hunter

    async def cmd_mode(self, args: str = "") -> None:
        """Switch operation mode."""
        mode_mgr = self._get_mode_manager()

        if not args.strip():
            # Show current mode status
            try:
                status = await mode_mgr.get_status()
            except Exception as e:
                status = {"mode": mode_mgr.mode.value, "error": str(e)}

            print(f"\n{Colors.HEADER}═══ OPERATION MODE ═══{Colors.RESET}\n")
            print(f"Current mode: {Colors.BOLD}{status.get('mode', 'unknown')}{Colors.RESET}")
            print()
            print("Available modes:")
            print(f"  {Colors.INFO}pentest{Colors.RESET}     - AI-assisted penetration testing (default)")
            print(f"  {Colors.INFO}wifi{Colors.RESET}        - Passive WiFi monitoring")
            print(f"  {Colors.INFO}wifi_active{Colors.RESET} - Active WiFi attacks (deauth enabled)")
            print(f"  {Colors.INFO}bluetooth{Colors.RESET}   - Bluetooth/BLE hunting")
            print(f"  {Colors.INFO}idle{Colors.RESET}        - Low-power display only")
            print()
            print(f"Use: {Colors.DIM}/mode <mode_name>{Colors.RESET}")
            return

        # Switch mode
        from core.mode_manager import OperationMode
        target_mode = args.strip().lower()

        try:
            mode = OperationMode(target_mode)
        except ValueError:
            print(f"{Colors.ERROR}Unknown mode: {target_mode}{Colors.RESET}")
            print("Valid modes: pentest, wifi, wifi_active, bluetooth, idle")
            return

        try:
            success, message = await mode_mgr.switch_mode(mode)
            if success:
                print(f"{Colors.SUCCESS}Mode switched to: {mode.value}{Colors.RESET}")
                print(message)
            else:
                print(f"{Colors.ERROR}Mode switch failed: {message}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR}Error switching mode: {e}{Colors.RESET}")

    async def cmd_wifi_hunt(self, args: str = "") -> None:
        """Start WiFi hunting mode."""
        mode_mgr = self._get_mode_manager()

        try:
            from core.mode_manager import OperationMode
            success, message = await mode_mgr.switch_mode(OperationMode.WIFI_PASSIVE)

            if success:
                print(f"{Colors.SUCCESS}WiFi hunting started!{Colors.RESET}")
                print(message)
                print(f"\n{Colors.DIM}Use /wifi-targets to see discovered networks.{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}Failed to start WiFi hunting: {message}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR}Error: {e}{Colors.RESET}")

    async def cmd_wifi_targets(self, args: str = "") -> None:
        """List discovered WiFi networks."""
        wifi_db = self._get_wifi_db()

        # Check for filters
        has_handshake = None
        if "handshake" in args.lower():
            has_handshake = True

        targets = wifi_db.list_targets(has_handshake=has_handshake, limit=50)

        if not targets:
            print(f"\n{Colors.INFO}No WiFi targets discovered yet.{Colors.RESET}")
            print(f"\n{Colors.DIM}Start hunting with /wifi-hunt or /mode wifi{Colors.RESET}")
            return

        print(f"\n{Colors.HEADER}═══ WIFI TARGETS ({len(targets)} found) ═══{Colors.RESET}\n")
        print(f"{'SSID':<20} {'BSSID':<18} {'Ch':>3} {'Sig':>5} {'Enc':<5} {'HS':>2}")
        print("-" * 60)

        for t in targets[:30]:
            ssid = (t.ssid or "<hidden>")[:18]
            hs = "Y" if t.handshake_captured or t.pmkid_captured else "-"
            enc = t.encryption.value[:5] if t.encryption else "?"
            print(f"{ssid:<20} {t.bssid:<18} {t.channel:>3} {t.signal_last:>5} {enc:<5} {hs:>2}")

        if len(targets) > 30:
            print(f"\n... and {len(targets) - 30} more")

    async def cmd_wifi_deauth(self, args: str = "") -> None:
        """Deauth a client from an AP."""
        if not args.strip():
            print(f"\n{Colors.INFO}Usage: /wifi-deauth <BSSID> [client_mac] [count]{Colors.RESET}")
            print(f"\n{Colors.DIM}Requires wifi_active mode. Enable with: /mode wifi_active{Colors.RESET}")
            return

        parts = args.strip().split()
        bssid = parts[0]
        client = parts[1] if len(parts) > 1 else None
        count = int(parts[2]) if len(parts) > 2 else 3

        mode_mgr = self._get_mode_manager()

        if not mode_mgr.is_active_mode():
            print(f"{Colors.ERROR}Deauth requires active mode.{Colors.RESET}")
            print(f"\n{Colors.DIM}Enable with: /mode wifi_active{Colors.RESET}")
            return

        try:
            success, message = await mode_mgr.wifi_deauth(bssid, client, count)
            if success:
                print(f"{Colors.SUCCESS}Deauth sent: {message}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}Deauth failed: {message}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR}Deauth error: {e}{Colors.RESET}")

    async def cmd_wifi_capture(self, args: str = "") -> None:
        """Capture PMKID from a target."""
        if not args.strip():
            print(f"\n{Colors.INFO}Usage: /wifi-capture <BSSID>{Colors.RESET}")
            print(f"\n{Colors.DIM}Attempts to capture PMKID from target AP.{Colors.RESET}")
            return

        bssid = args.strip().split()[0]
        mode_mgr = self._get_mode_manager()

        try:
            success, message = await mode_mgr.wifi_capture_pmkid(bssid)
            if success:
                print(f"{Colors.SUCCESS}{message}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}{message}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR}Capture error: {e}{Colors.RESET}")

    async def cmd_wifi_survey(self, args: str = "") -> None:
        """Run WiFi channel survey."""
        mode_mgr = self._get_mode_manager()

        if not mode_mgr.is_wifi_mode():
            print(f"{Colors.ERROR}Survey requires WiFi mode.{Colors.RESET}")
            print(f"\n{Colors.DIM}Start with: /mode wifi{Colors.RESET}")
            return

        print(f"\n{Colors.INFO}Running channel survey...{Colors.RESET}\n")

        try:
            result = await mode_mgr.wifi_survey()

            if "error" in result:
                print(f"{Colors.ERROR}Survey error: {result['error']}{Colors.RESET}")
                return

            print(f"{Colors.HEADER}═══ WIFI CHANNEL SURVEY ═══{Colors.RESET}\n")

            survey = result.get("survey", [])
            for ch in sorted(survey, key=lambda x: x.get("channel", 0)):
                channel = ch.get("channel", "?")
                networks = ch.get("networks", 0)
                avg_signal = ch.get("avg_signal", 0)
                print(f"Channel {channel:2}: {networks:2} networks, avg signal: {avg_signal} dBm")
        except Exception as e:
            print(f"{Colors.ERROR}Survey error: {e}{Colors.RESET}")

    async def cmd_handshakes(self, args: str = "") -> None:
        """List captured handshakes."""
        wifi_db = self._get_wifi_db()

        # Check for cracked filter
        cracked = None
        if "cracked" in args.lower():
            cracked = True

        handshakes = wifi_db.list_handshakes(cracked=cracked, limit=50)

        if not handshakes:
            msg = "No handshakes captured yet." if cracked is None else "No cracked handshakes."
            print(f"\n{Colors.INFO}{msg}{Colors.RESET}")
            return

        print(f"\n{Colors.HEADER}═══ CAPTURED HANDSHAKES ({len(handshakes)}) ═══{Colors.RESET}\n")
        print(f"{'SSID':<20} {'BSSID':<18} {'Type':<6} {'Cracked':<8} {'File'}")
        print("-" * 70)

        for h in handshakes:
            ssid = (h.ssid or "<hidden>")[:18]
            cracked_str = f"{Colors.SUCCESS}YES{Colors.RESET}" if h.cracked else "-"
            file_short = h.file_path.split("/")[-1][:20]
            print(f"{ssid:<20} {h.bssid:<18} {h.capture_type.value:<6} {cracked_str:<8} {file_short}")

    async def cmd_adapters(self, args: str = "") -> None:
        """List WiFi adapters."""
        adapter_mgr = self._get_adapter_manager()
        status = adapter_mgr.get_status()

        adapters = status.get("adapters", [])

        if not adapters:
            print(f"\n{Colors.INFO}No WiFi adapters detected.{Colors.RESET}")
            print(f"\n{Colors.DIM}Plug in a monitor-mode capable adapter.{Colors.RESET}")
            return

        print(f"\n{Colors.HEADER}═══ WIFI ADAPTERS ({len(adapters)} found) ═══{Colors.RESET}")

        for a in adapters:
            print(f"\n{Colors.BOLD}{a['interface']}:{Colors.RESET}")
            print(f"  Driver:   {a['driver']}")
            print(f"  Chipset:  {a['chipset']}")
            print(f"  MAC:      {a['mac_address']}")
            print(f"  Mode:     {a['current_mode']}")
            monitor = f"{Colors.SUCCESS}Yes{Colors.RESET}" if a['monitor_capable'] else f"{Colors.DIM}No{Colors.RESET}"
            inject = f"{Colors.SUCCESS}Yes{Colors.RESET}" if a['injection_capable'] else f"{Colors.DIM}No{Colors.RESET}"
            print(f"  Monitor:  {monitor}")
            print(f"  Inject:   {inject}")
            if a['bands']:
                print(f"  Bands:    {', '.join(a['bands'])}")
            if a['connected']:
                print(f"  Status:   {Colors.SUCCESS}Connected{Colors.RESET}")

        print()
        print(f"Monitor capable: {status.get('monitor_capable', 0)}")
        print(f"Injection capable: {status.get('injection_capable', 0)}")
        if status.get('best_monitor_adapter'):
            print(f"Best for hunting: {Colors.INFO}{status['best_monitor_adapter']}{Colors.RESET}")

    # ================
    # Bluetooth Commands
    # ================

    async def cmd_bt_scan(self, args: str = "") -> None:
        """Scan for classic Bluetooth devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            print(f"{Colors.ERROR}Bluetooth hunter not available. Check dependencies.{Colors.RESET}")
            return

        # Parse duration
        duration = 10
        if args.strip():
            try:
                duration = int(args.strip())
            except ValueError:
                pass

        print(f"\n{Colors.INFO}Scanning for Bluetooth devices ({duration}s)...{Colors.RESET}\n")

        try:
            devices = await hunter.scan_classic(duration)

            if not devices:
                print(f"{Colors.DIM}No Bluetooth devices found.{Colors.RESET}")
                return

            print(f"{Colors.HEADER}═══ BLUETOOTH DEVICES ({len(devices)}) ═══{Colors.RESET}\n")
            print(f"{'Address':<18} {'Name':<20} {'Class':<12} {'RSSI'}")
            print("-" * 60)

            for d in devices:
                name = (d.name or "Unknown")[:18]
                dev_class = d.device_class[:10]
                rssi = f"{d.rssi} dBm" if d.rssi else "N/A"
                print(f"{d.address:<18} {name:<20} {dev_class:<12} {rssi}")
        except asyncio.TimeoutError:
            print(f"{Colors.ERROR}Bluetooth scan timed out.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR}Scan error: {e}{Colors.RESET}")

    async def cmd_ble_scan(self, args: str = "") -> None:
        """Scan for BLE devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            print(f"{Colors.ERROR}Bluetooth hunter not available. Check dependencies.{Colors.RESET}")
            return

        # Parse duration
        duration = 10
        if args.strip():
            try:
                duration = int(args.strip())
            except ValueError:
                pass

        print(f"\n{Colors.INFO}Scanning for BLE devices ({duration}s)...{Colors.RESET}\n")

        try:
            devices = await hunter.scan_ble(duration)

            if not devices:
                print(f"{Colors.DIM}No BLE devices found.{Colors.RESET}")
                return

            print(f"{Colors.HEADER}═══ BLE DEVICES ({len(devices)}) ═══{Colors.RESET}\n")
            print(f"{'Address':<18} {'Name':<25} {'RSSI'}")
            print("-" * 60)

            for d in devices:
                name = (d.name or "Unknown")[:23]
                rssi = f"{d.rssi} dBm" if d.rssi else "N/A"
                print(f"{d.address:<18} {name:<25} {rssi}")
        except asyncio.TimeoutError:
            print(f"{Colors.ERROR}BLE scan timed out.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR}BLE scan error: {e}{Colors.RESET}")

    async def cmd_bt_devices(self, args: str = "") -> None:
        """List known Bluetooth devices."""
        hunter = self._get_bt_hunter()
        if not hunter:
            print(f"{Colors.ERROR}Bluetooth hunter not available.{Colors.RESET}")
            return

        devices = hunter.list_devices()

        if not devices:
            print(f"\n{Colors.INFO}No Bluetooth devices in cache.{Colors.RESET}")
            print(f"\n{Colors.DIM}Run /bt-scan or /ble-scan first.{Colors.RESET}")
            return

        # Filter by type if specified
        ble_only = "ble" in args.lower()
        classic_only = "classic" in args.lower()

        if ble_only:
            devices = [d for d in devices if d.ble]
        elif classic_only:
            devices = [d for d in devices if not d.ble]

        print(f"\n{Colors.HEADER}═══ KNOWN BLUETOOTH DEVICES ({len(devices)}) ═══{Colors.RESET}\n")
        print(f"{'Address':<18} {'Name':<20} {'Class':<12} {'Type':<6} {'RSSI'}")
        print("-" * 70)

        for d in devices:
            name = (d.name or "Unknown")[:18]
            dev_class = d.device_class[:10]
            dev_type = "BLE" if d.ble else "Classic"
            rssi = f"{d.rssi}" if d.rssi else "N/A"
            print(f"{d.address:<18} {name:<20} {dev_class:<12} {dev_type:<6} {rssi}")

    # ================
    # Play Commands
    # ================

    async def _play_action(
        self,
        action_name: str,
        emote_text: str,
        mood: Mood,
        intensity: float,
        xp_source: XPSource,
    ) -> None:
        """
        Execute a play action with emoji face animation and rewards.

        Args:
            action_name: Name of action (e.g., "walk")
            emote_text: SSH emote text (e.g., "goes for a walk...")
            mood: Target mood to set
            intensity: Mood intensity boost
            xp_source: XP source for reward
        """
        from core.ui import ACTION_FACE_SEQUENCES

        # Update interaction time (prevents boredom/sleepy)
        self.personality._last_interaction = time.time()

        # Print SSH emote
        print(f"{Colors.EMOTE}*{self.personality.name} {emote_text}*{Colors.RESET}")

        # Get emoji face sequence for this action
        face_sequence = ACTION_FACE_SEQUENCES.get(
            action_name,
            ["(^_^)", "(^_~)", "(^_^)"]  # Default fallback
        )

        # Show emoji animation on display (if available)
        # Display each emoji face from the sequence without text
        if self.display:
            for i, emoji_face in enumerate(face_sequence):
                is_last = (i == len(face_sequence) - 1)

                # Show just the emoji face (no text, so face won't hide)
                await self.display.update(
                    face="happy",
                    text="",  # Empty text - face will show
                    force=True,
                )

                # Manually render the action face by updating the UI
                if self.display._ui and self.display._ui.animated_face:
                    # Temporarily override to show action face
                    self.display._ui.animated_face._current_action_face = emoji_face

                if not is_last:
                    await asyncio.sleep(0.8)  # Animation delay between faces

            # Clear action face override when done
            if self.display._ui and self.display._ui.animated_face:
                self.display._ui.animated_face._current_action_face = None

        # Boost mood and intensity
        old_mood = self.personality.mood.current
        old_intensity = self.personality.mood.intensity
        self.personality.mood.set_mood(mood, intensity)

        # Award XP
        xp_amounts = {
            XPSource.PLAY_WALK: 3,
            XPSource.PLAY_DANCE: 5,
            XPSource.PLAY_EXERCISE: 5,
            XPSource.PLAY_GENERAL: 4,
            XPSource.PLAY_REST: 2,
            XPSource.PLAY_PET: 3,
        }
        awarded, xp_gained = self.personality.progression.award_xp(
            xp_source,
            xp_amounts.get(xp_source, 3)
        )

        # Show results
        old_energy = old_mood.energy * old_intensity
        new_energy = self.personality.energy
        energy_change = new_energy - old_energy

        if awarded:
            print(f"{Colors.SUCCESS}+{xp_gained} XP  Energy: {old_energy:.0%} → {new_energy:.0%} ({energy_change:+.0%}){Colors.RESET}")
        else:
            print(f"{Colors.DIM}Energy: {old_energy:.0%} → {new_energy:.0%} ({energy_change:+.0%}){Colors.RESET}")

    async def cmd_walk(self) -> None:
        """Go for a walk."""
        await self._play_action(
            action_name="walk",
            emote_text="goes for a walk around the neighborhood",
            mood=Mood.CURIOUS,
            intensity=0.7,
            xp_source=XPSource.PLAY_WALK,
        )

    async def cmd_dance(self) -> None:
        """Dance around."""
        await self._play_action(
            action_name="dance",
            emote_text="dances enthusiastically",
            mood=Mood.EXCITED,
            intensity=0.9,
            xp_source=XPSource.PLAY_DANCE,
        )

    async def cmd_exercise(self) -> None:
        """Exercise and stretch."""
        await self._play_action(
            action_name="exercise",
            emote_text="does some stretches and exercises",
            mood=Mood.HAPPY,
            intensity=0.8,
            xp_source=XPSource.PLAY_EXERCISE,
        )

    async def cmd_play(self) -> None:
        """Play with a toy."""
        await self._play_action(
            action_name="play",
            emote_text="plays with a toy",
            mood=Mood.HAPPY,
            intensity=0.8,
            xp_source=XPSource.PLAY_GENERAL,
        )

    async def cmd_pet(self) -> None:
        """Get petted."""
        await self._play_action(
            action_name="pet",
            emote_text="enjoys being petted",
            mood=Mood.GRATEFUL,
            intensity=0.7,
            xp_source=XPSource.PLAY_PET,
        )

    async def cmd_rest(self) -> None:
        """Take a short rest."""
        await self._play_action(
            action_name="rest",
            emote_text="takes a short rest",
            mood=Mood.COOL,
            intensity=0.4,
            xp_source=XPSource.PLAY_REST,
        )

    async def cmd_thoughts(self) -> None:
        """Show recent autonomous thoughts from the thought log."""
        from pathlib import Path

        log_path = Path("~/.inkling/thoughts.log").expanduser()
        if not log_path.exists():
            print(f"\n{Colors.DIM}No thoughts yet. Thoughts are generated automatically over time.{Colors.RESET}")
            return

        lines = log_path.read_text().strip().splitlines()
        recent = lines[-10:]  # Last 10 thoughts

        print(f"\n{Colors.HEADER}═══ RECENT THOUGHTS ({len(recent)} of {len(lines)}) ═══{Colors.RESET}\n")

        for line in recent:
            parts = line.split(" | ", 1)
            if len(parts) == 2:
                ts, thought = parts
                print(f"{Colors.DIM}{ts}{Colors.RESET}")
                print(f"  {thought}")
            else:
                print(f"  {line}")
            print()

        if self.personality.last_thought:
            print(f"{Colors.INFO}Latest: {self.personality.last_thought}{Colors.RESET}")

    async def cmd_find(self, args: str = "") -> None:
        """Search tasks by keyword."""
        if not args.strip():
            print(f"{Colors.ERROR}Usage: /find <keyword>{Colors.RESET}")
            return

        if not self.task_manager:
            print(f"{Colors.ERROR}Task manager not available.{Colors.RESET}")
            return

        query = args.strip().lower()
        all_tasks = self.task_manager.list_tasks()
        matches = [
            t for t in all_tasks
            if query in t.title.lower()
            or (t.description and query in t.description.lower())
            or any(query in tag.lower() for tag in t.tags)
        ]

        if not matches:
            print(f"\n{Colors.DIM}No tasks found matching '{args.strip()}'.{Colors.RESET}")
            return

        print(f"\n{Colors.HEADER}═══ SEARCH RESULTS ({len(matches)}) ═══{Colors.RESET}\n")

        for task in matches:
            status_icon = {"pending": "📋", "in_progress": "⏳", "completed": "✅", "cancelled": "❌"}.get(task.status.value, "·")
            priority_str = {"low": "", "medium": "◆", "high": "◆◆", "urgent": "🔥"}.get(task.priority.value, "")
            tags_str = " ".join(f"#{t}" for t in task.tags) if task.tags else ""
            print(f"  {status_icon} [{task.id[:8]}] {task.title} {priority_str}")
            if task.description:
                print(f"     {Colors.DIM}{task.description[:60]}{Colors.RESET}")
            if tags_str:
                print(f"     {Colors.INFO}{tags_str}{Colors.RESET}")
            print()

    async def cmd_memory(self) -> None:
        """Show memory stats and recent entries."""
        store = self.memory_store or MemoryStore()
        owns_store = self.memory_store is None
        try:
            if owns_store:
                store.initialize()

            total = store.count()
            user_count = store.count(MemoryStore.CATEGORY_USER)
            pref_count = store.count(MemoryStore.CATEGORY_PREFERENCE)
            fact_count = store.count(MemoryStore.CATEGORY_FACT)
            event_count = store.count(MemoryStore.CATEGORY_EVENT)

            print(f"\n{Colors.HEADER}═══ MEMORY STORE ═══{Colors.RESET}\n")
            print(f"  Total memories: {Colors.INFO}{total}{Colors.RESET}")
            print(f"  User info:      {user_count}")
            print(f"  Preferences:    {pref_count}")
            print(f"  Facts:          {fact_count}")
            print(f"  Events:         {event_count}")

            recent = store.recall_recent(limit=5)
            if recent:
                print(f"\n{Colors.HEADER}Recent memories:{Colors.RESET}")
                for mem in recent:
                    print(f"  {Colors.DIM}[{mem.category}]{Colors.RESET} {mem.key}: {mem.value[:60]}")

            important = store.recall_important(limit=3)
            if important:
                print(f"\n{Colors.HEADER}Most important:{Colors.RESET}")
                for mem in important:
                    print(f"  {Colors.INFO}★ {mem.importance:.1f}{Colors.RESET} [{mem.category}] {mem.key}: {mem.value[:60]}")

            print()
        finally:
            if owns_store:
                store.close()

    async def cmd_focus(self, args: str) -> None:
        """Manage focus/pomodoro sessions."""
        if not self.focus_manager or not self.focus_manager.is_enabled:
            print(f"{Colors.ERROR}Focus manager is not available.{Colors.RESET}")
            return

        parts = args.split() if args else []
        sub = parts[0].lower() if parts else "status"

        if sub == "start":
            minutes = None
            task_ref = None
            if len(parts) >= 2:
                try:
                    minutes = int(parts[1])
                except ValueError:
                    task_ref = " ".join(parts[1:])
            if len(parts) >= 3:
                task_ref = " ".join(parts[2:])

            task_id = None
            task_title = None
            if task_ref:
                task = self._resolve_task_ref(task_ref)
                if task:
                    task_id = task.id
                    task_title = task.title
                else:
                    print(f"{Colors.INFO}Task reference not found; starting unlinked focus session.{Colors.RESET}")

            result = self.focus_manager.start(minutes=minutes, task_id=task_id, task_title=task_title)
            if not result.get("ok"):
                print(f"{Colors.ERROR}{result.get('error', 'Could not start focus session')}{Colors.RESET}")
                status = result.get("status")
                if status:
                    self._print_focus_status(status)
                return
            status = result["status"]
            self._print_focus_status(status)
            await self.display.update(face="intense", text="Focus session started", mood_text="Intense")
            return

        if sub == "stop":
            result = self.focus_manager.stop(stopped_early=True)
            if not result.get("ok"):
                print(f"{Colors.ERROR}{result.get('error', 'No active session')}{Colors.RESET}")
            else:
                print(f"{Colors.SUCCESS}Focus session stopped.{Colors.RESET}")
                await self.display.update(face="cool", text="Focus session stopped", mood_text="Cool")
            return

        if sub == "pause":
            result = self.focus_manager.pause()
            if not result.get("ok"):
                print(f"{Colors.ERROR}{result.get('error', 'Unable to pause')}{Colors.RESET}")
            else:
                self._print_focus_status(result["status"])
            return

        if sub == "resume":
            result = self.focus_manager.resume()
            if not result.get("ok"):
                print(f"{Colors.ERROR}{result.get('error', 'Unable to resume')}{Colors.RESET}")
            else:
                self._print_focus_status(result["status"])
            return

        if sub == "break":
            result = self.focus_manager.start_break()
            if not result.get("ok"):
                print(f"{Colors.ERROR}{result.get('error', 'Unable to start break')}{Colors.RESET}")
            else:
                self._print_focus_status(result["status"])
            return

        if sub == "stats":
            stats = self.focus_manager.stats_today()
            print(f"\n{Colors.HEADER}═══ FOCUS TODAY ═══{Colors.RESET}")
            print(f"Sessions: {stats['sessions']}")
            print(f"Completed: {stats['completed_count']}")
            print(f"Total time: {stats['total_sec'] // 60}m")
            print(f"Work time: {stats['work_sec'] // 60}m")
            return

        if sub == "week":
            week = self.focus_manager.stats_week()
            print(f"\n{Colors.HEADER}═══ FOCUS WEEK ═══{Colors.RESET}")
            for day in week["days"]:
                print(f"{day['date']}: {day['sessions']} sessions ({day['total_sec'] // 60}m)")
            print(f"Total: {week['total_sessions']} sessions ({week['total_sec'] // 60}m)")
            return

        if sub == "config":
            cfg = self.focus_manager.config
            print(f"\n{Colors.HEADER}═══ FOCUS CONFIG ═══{Colors.RESET}")
            print(f"Work: {cfg.default_work_minutes}m")
            print(f"Short break: {cfg.short_break_minutes}m")
            print(f"Long break: {cfg.long_break_minutes}m")
            print(f"Long break cadence: every {cfg.sessions_until_long_break} sessions")
            print(f"Quiet mode: {'on' if cfg.quiet_mode_during_focus else 'off'}")
            return

        status = self.focus_manager.status()
        self._print_focus_status(status)

    def _print_focus_status(self, status: dict) -> None:
        if not status.get("active"):
            print(f"{Colors.INFO}No active focus session.{Colors.RESET}")
            return
        mm = int(status["remaining_sec"]) // 60
        ss = int(status["remaining_sec"]) % 60
        label = status.get("phase_label", "FOCUS")
        task = status.get("task_title")
        task_line = f" | Task: {task}" if task else ""
        pause_line = " [PAUSED]" if status.get("paused") else ""
        print(f"{Colors.SUCCESS}{label}{pause_line} {mm:02d}:{ss:02d}{task_line}{Colors.RESET}")

    def _resolve_task_ref(self, task_ref: str) -> Optional[Task]:
        if not self.task_manager:
            return None
        task = self.task_manager.get_task(task_ref)
        if task:
            return task
        ref = task_ref.lower()
        matches = [
            t for t in self.task_manager.list_tasks()
            if t.id.startswith(task_ref) or ref in t.title.lower()
        ]
        return matches[0] if len(matches) == 1 else None

    async def cmd_settings(self) -> None:
        """Show current settings."""
        import yaml

        print(f"\n{Colors.HEADER}═══ CURRENT SETTINGS ═══{Colors.RESET}\n")

        # AI config
        ai_config = self._config.get("ai", {})
        provider = ai_config.get("primary", "anthropic")
        model = ai_config.get(provider, {}).get("model", "unknown")
        budget = ai_config.get("budget", {})
        daily_tokens = budget.get("daily_tokens", 10000)
        per_request = budget.get("per_request_max", 500)

        print(f"  {Colors.HEADER}AI Provider:{Colors.RESET} {provider}")
        print(f"  {Colors.HEADER}Model:{Colors.RESET} {model}")
        print(f"  {Colors.HEADER}Daily token budget:{Colors.RESET} {daily_tokens}")
        print(f"  {Colors.HEADER}Per-request max:{Colors.RESET} {per_request}")

        # Personality
        traits = self.personality.traits
        print(f"\n  {Colors.HEADER}Personality Traits:{Colors.RESET}")
        for name, val in traits.to_dict().items():
            bar = "█" * int(val * 10) + "░" * (10 - int(val * 10))
            print(f"    {name:14s} [{bar}] {val:.1f}")

        # Heartbeat
        hb_config = self._config.get("heartbeat", {})
        print(f"\n  {Colors.HEADER}Heartbeat:{Colors.RESET} {'enabled' if hb_config.get('enabled', True) else 'disabled'}")
        print(f"    Tick interval:     {hb_config.get('tick_interval', 60)}s")
        print(f"    Mood behaviors:    {'on' if hb_config.get('enable_mood_behaviors', True) else 'off'}")
        print(f"    Time behaviors:    {'on' if hb_config.get('enable_time_behaviors', True) else 'off'}")
        print(f"    Quiet hours:       {hb_config.get('quiet_hours_start', 23)}:00 - {hb_config.get('quiet_hours_end', 7)}:00")

        # Device
        device_config = self._config.get("device", {})
        print(f"\n  {Colors.HEADER}Device:{Colors.RESET} {device_config.get('name', self.personality.name)}")
        print(f"  {Colors.HEADER}Display:{Colors.RESET} {self._config.get('display', {}).get('type', 'auto')}")
        print()

    async def cmd_backup(self) -> None:
        """Create a backup of Inkling data."""
        import shutil
        from pathlib import Path
        from datetime import datetime

        data_dir = Path("~/.inkling").expanduser()
        if not data_dir.exists():
            print(f"{Colors.ERROR}No data directory found at {data_dir}{Colors.RESET}")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"inkling_backup_{timestamp}"
        backup_path = data_dir.parent / f"{backup_name}.tar.gz"

        print(f"\n{Colors.INFO}Creating backup...{Colors.RESET}")

        try:
            shutil.make_archive(
                str(data_dir.parent / backup_name),
                'gztar',
                root_dir=str(data_dir.parent),
                base_dir='.inkling'
            )
            size_mb = backup_path.stat().st_size / (1024 * 1024)
            print(f"{Colors.SUCCESS}Backup created: {backup_path}{Colors.RESET}")
            print(f"  Size: {size_mb:.1f} MB")
        except Exception as e:
            print(f"{Colors.ERROR}Backup failed: {e}{Colors.RESET}")

    async def cmd_journal(self) -> None:
        """Show recent journal entries."""
        from pathlib import Path

        journal_path = Path("~/.inkling/journal.log").expanduser()
        if not journal_path.exists():
            print(f"\n{Colors.DIM}No journal entries yet. Journal entries are written daily by the heartbeat system.{Colors.RESET}")
            return

        lines = journal_path.read_text().strip().splitlines()
        recent = lines[-10:]

        print(f"\n{Colors.HEADER}═══ JOURNAL ({len(recent)} of {len(lines)} entries) ═══{Colors.RESET}\n")

        for line in recent:
            parts = line.split(" | ", 1)
            if len(parts) == 2:
                ts, entry = parts
                print(f"{Colors.DIM}{ts}{Colors.RESET}")
                print(f"  {entry}")
            else:
                print(f"  {line}")
            print()

    # ========================================
    # Pentest Commands
    # ========================================

    def _get_pentest_db(self) -> PentestDB:
        """Get or create pentest database instance."""
        if not hasattr(self, '_pentest_db'):
            self._pentest_db = PentestDB()
        return self._pentest_db

    def _get_kali_manager(self) -> KaliToolManager:
        """Get or create Kali tool manager instance."""
        if not hasattr(self, '_kali_manager'):
            pentest_cfg = self._config.get("pentest", {})
            self._kali_manager = KaliToolManager(
                data_dir=pentest_cfg.get("data_dir", "~/.inkling/pentest"),
                package_profile=pentest_cfg.get("package_profile", "pi-headless-curated"),
                required_tools=pentest_cfg.get("required_tools"),
                optional_tools=pentest_cfg.get("optional_tools"),
                enabled_profiles=pentest_cfg.get("enabled_profiles"),
            )
        return self._kali_manager

    def _get_recon_engine(self) -> ReconEngine:
        """Get or create recon engine instance."""
        if not hasattr(self, '_recon_engine'):
            self._recon_engine = ReconEngine()
        return self._recon_engine

    async def cmd_scan(self, args: str = "") -> None:
        """Run nmap network scan on target."""
        if not args.strip():
            print(f"{Colors.INFO}Usage: /scan <target> [scan_type]{Colors.RESET}")
            print("  target: IP, hostname, or CIDR range")
            print("  scan_type: quick (default), full, stealth, version, vuln")
            print(f"\n{Colors.DIM}Example: /scan 192.168.1.1{Colors.RESET}")
            print(f"{Colors.DIM}Example: /scan example.com version{Colors.RESET}")
            return

        parts = args.strip().split()
        target = parts[0]
        scan_type = parts[1] if len(parts) > 1 else "quick"

        manager = self._get_kali_manager()
        db = self._get_pentest_db()

        # Check if nmap is installed
        if not manager.is_tool_installed("nmap"):
            print(f"{Colors.ERROR}nmap is not installed.{Colors.RESET}")
            print(f"Install with: {manager.get_tools_status()['install_guidance']['pi_baseline']}")
            return

        # Get or create target
        target_obj = db.get_target_by_ip(target)
        if not target_obj:
            target_obj = db.add_target(ip=target, scope=Scope.IN_SCOPE)
            print(f"{Colors.INFO}Added target to database: {target}{Colors.RESET}")

        print(f"\n{Colors.HEADER}Scanning {target} ({scan_type})...{Colors.RESET}")
        print(f"{Colors.DIM}This may take a few minutes.{Colors.RESET}\n")

        # Update display
        await self.display.update(
            face="intense",
            text=f"Scanning {target}...",
            mood_text="Hunting",
        )

        import time
        start_time = time.time()

        # Run scan
        result = await manager.nmap_scan(
            target=target,
            scan_type=scan_type,
            timing=3,  # T3 for Pi (not T4)
        )

        duration = time.time() - start_time

        if not result:
            print(f"{Colors.ERROR}Scan failed. Check target and network.{Colors.RESET}")
            await self.display.update(
                face="sad",
                text="Scan failed",
                mood_text="Frustrated",
            )
            return

        # Save scan to database
        scan_record = db.save_scan(
            target_id=target_obj.id,
            scan_type=ScanType.NMAP,
            result=result.__dict__,
            ports_found=len(result.open_ports),
            vulns_found=len(result.vulnerabilities),
            duration_sec=duration,
        )

        # Save any vulnerabilities found
        if result.vulnerabilities:
            vuln_dicts = []
            for v in result.vulnerabilities:
                vuln_dicts.append({
                    "title": v.get("description", "Unknown Vulnerability")[:100],
                    "description": v.get("description", ""),
                    "severity": v.get("severity", "info"),
                })
            db.save_vulnerabilities(scan_record.id, target_obj.id, vuln_dicts)

        # Display results
        print(f"{Colors.HEADER}═══ SCAN RESULTS ═══{Colors.RESET}\n")
        print(f"Target: {result.target}")
        print(f"Hosts up: {result.hosts_up}/{result.total_hosts}")
        print(f"Time: {duration:.1f}s")

        if result.open_ports:
            print(f"\n{Colors.BOLD}Open Ports ({len(result.open_ports)}):{Colors.RESET}")
            for port in result.open_ports[:20]:
                version = f" ({port['version']})" if port.get('version') else ""
                print(f"  {port['port']:5}/{port['protocol']:3} {port['service']}{version}")
            if len(result.open_ports) > 20:
                print(f"  ... and {len(result.open_ports) - 20} more")

        if result.vulnerabilities:
            print(f"\n{Colors.ERROR}Vulnerabilities ({len(result.vulnerabilities)}):{Colors.RESET}")
            for vuln in result.vulnerabilities[:10]:
                print(f"  - {vuln.get('description', 'Unknown')[:60]}")

        print(f"\n{Colors.SUCCESS}Scan saved to database (ID: {scan_record.id}){Colors.RESET}")

        await self.display.update(
            face="excited",
            text=f"Found {len(result.open_ports)} ports",
            mood_text="Hunting",
        )

    async def cmd_web_scan(self, args: str = "") -> None:
        """Run nikto web vulnerability scan."""
        if not args.strip():
            print(f"{Colors.INFO}Usage: /web-scan <url|host> [port]{Colors.RESET}")
            print("  url: Target URL or hostname")
            print("  port: Port number (default: 80)")
            print(f"\n{Colors.DIM}Example: /web-scan example.com{Colors.RESET}")
            print(f"{Colors.DIM}Example: /web-scan 192.168.1.1 443{Colors.RESET}")
            return

        parts = args.strip().split()
        target = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 80
        ssl = port == 443

        # Remove protocol if included
        if target.startswith("http://"):
            target = target[7:]
            ssl = False
        elif target.startswith("https://"):
            target = target[8:]
            ssl = True

        # Remove trailing path
        target = target.split("/")[0]

        manager = self._get_kali_manager()
        db = self._get_pentest_db()

        # Check if nikto is installed
        if not manager.is_tool_installed("nikto"):
            print(f"{Colors.ERROR}nikto is not installed.{Colors.RESET}")
            print(f"Install with: {manager.get_tools_status()['install_guidance']['pi_baseline']}")
            return

        # Get or create target
        target_obj = db.get_target_by_ip(target)
        if not target_obj:
            target_obj = db.add_target(ip=target, scope=Scope.IN_SCOPE)

        proto = "https" if ssl else "http"
        print(f"\n{Colors.HEADER}Web scanning {proto}://{target}:{port}...{Colors.RESET}")
        print(f"{Colors.DIM}This may take several minutes.{Colors.RESET}\n")

        await self.display.update(
            face="intense",
            text=f"Web scanning {target}...",
            mood_text="Hunting",
        )

        import time
        start_time = time.time()

        # Run nikto scan
        result = await manager.nikto_scan(
            target=target,
            port=port,
            ssl=ssl,
        )

        duration = time.time() - start_time

        if "error" in result:
            print(f"{Colors.ERROR}Web scan failed: {result['error']}{Colors.RESET}")
            await self.display.update(
                face="sad",
                text="Web scan failed",
                mood_text="Frustrated",
            )
            return

        # Save scan to database
        findings = result.get("findings", [])
        scan_record = db.save_scan(
            target_id=target_obj.id,
            scan_type=ScanType.NIKTO,
            result=result,
            ports_found=1,  # Nikto scans single port
            vulns_found=len(findings),
            duration_sec=duration,
        )

        # Save findings as vulnerabilities
        if findings:
            vuln_dicts = []
            for finding in findings:
                # Parse OSVDB/CVE from finding
                severity = Severity.MEDIUM
                if "OSVDB-0" in finding:
                    severity = Severity.INFO
                elif "CVE-" in finding or "critical" in finding.lower():
                    severity = Severity.HIGH

                vuln_dicts.append({
                    "title": finding[:100],
                    "description": finding,
                    "severity": severity.value,
                    "port": port,
                    "service": "http" if not ssl else "https",
                })
            db.save_vulnerabilities(scan_record.id, target_obj.id, vuln_dicts)

        # Display results
        print(f"{Colors.HEADER}═══ WEB SCAN RESULTS ═══{Colors.RESET}\n")
        print(f"Target: {result.get('target', target)}")
        print(f"Findings: {result.get('total_findings', len(findings))}")
        print(f"Time: {duration:.1f}s")

        if findings:
            print(f"\n{Colors.BOLD}Findings:{Colors.RESET}")
            for finding in findings[:15]:
                print(f"  {finding[:80]}")
            if len(findings) > 15:
                print(f"  ... and {len(findings) - 15} more")

        print(f"\n{Colors.SUCCESS}Scan saved to database (ID: {scan_record.id}){Colors.RESET}")

        await self.display.update(
            face="excited",
            text=f"Found {len(findings)} issues",
            mood_text="Alert",
        )

    async def cmd_recon(self, args: str = "") -> None:
        """DNS/WHOIS enumeration on target."""
        if not args.strip():
            print(f"{Colors.INFO}Usage: /recon <domain|ip>{Colors.RESET}")
            print("  Performs DNS enumeration, WHOIS lookup, and subdomain discovery")
            print(f"\n{Colors.DIM}Example: /recon example.com{Colors.RESET}")
            return

        target = args.strip().split()[0]
        db = self._get_pentest_db()
        recon = self._get_recon_engine()

        # Get or create target
        target_obj = db.get_target_by_ip(target)
        if not target_obj:
            target_obj = db.add_target(ip=target, scope=Scope.IN_SCOPE)

        print(f"\n{Colors.HEADER}Reconnaissance on {target}...{Colors.RESET}\n")

        await self.display.update(
            face="curious",
            text=f"Recon on {target}...",
            mood_text="Curious",
        )

        import time
        start_time = time.time()

        # Run full recon
        result = await recon.full_recon(target)

        duration = time.time() - start_time

        # Save to database
        scan_record = db.save_scan(
            target_id=target_obj.id,
            scan_type=ScanType.RECON,
            result=result.to_dict(),
            ports_found=0,
            vulns_found=0,
            duration_sec=duration,
        )

        # Display results
        print(f"{Colors.HEADER}═══ RECON RESULTS ═══{Colors.RESET}\n")
        print(f"Target: {target}")
        print(f"Time: {duration:.1f}s")

        if result.dns_records:
            print(f"\n{Colors.BOLD}DNS Records:{Colors.RESET}")
            print(ReconEngine.format_dns_summary(result.dns_records))

        if result.whois:
            print(f"\n{Colors.BOLD}WHOIS:{Colors.RESET}")
            print(ReconEngine.format_whois_summary(result.whois))

        if result.subdomains:
            print(f"\n{Colors.BOLD}Subdomains ({len(result.subdomains)}):{Colors.RESET}")
            for sub in result.subdomains[:10]:
                print(f"  {sub}")
            if len(result.subdomains) > 10:
                print(f"  ... and {len(result.subdomains) - 10} more")

        if result.reverse_dns:
            print(f"\n{Colors.BOLD}Reverse DNS:{Colors.RESET} {result.reverse_dns}")

        if result.zone_transfer_possible:
            print(f"\n{Colors.ERROR}Zone transfer POSSIBLE (security issue!){Colors.RESET}")

        if result.errors:
            print(f"\n{Colors.DIM}Warnings: {', '.join(result.errors)}{Colors.RESET}")

        print(f"\n{Colors.SUCCESS}Recon saved to database (ID: {scan_record.id}){Colors.RESET}")

        await self.display.update(
            face="happy",
            text=f"Recon complete",
            mood_text="Curious",
        )

    async def cmd_ports(self, args: str = "") -> None:
        """Quick TCP port scan."""
        if not args.strip():
            print(f"{Colors.INFO}Usage: /ports <target> [port,port,...]{Colors.RESET}")
            print("  Quick TCP connect scan (no nmap required)")
            print(f"\n{Colors.DIM}Example: /ports 192.168.1.1{Colors.RESET}")
            print(f"{Colors.DIM}Example: /ports example.com 22,80,443{Colors.RESET}")
            return

        parts = args.strip().split()
        target = parts[0]
        ports = None

        if len(parts) > 1:
            try:
                ports = [int(p.strip()) for p in parts[1].split(",")]
            except ValueError:
                print(f"{Colors.ERROR}Invalid port format. Use comma-separated numbers.{Colors.RESET}")
                return

        db = self._get_pentest_db()
        recon = self._get_recon_engine()

        # Get or create target
        target_obj = db.get_target_by_ip(target)
        if not target_obj:
            target_obj = db.add_target(ip=target, scope=Scope.IN_SCOPE)

        print(f"\n{Colors.HEADER}Port scanning {target}...{Colors.RESET}\n")

        await self.display.update(
            face="intense",
            text=f"Scanning ports on {target}...",
            mood_text="Hunting",
        )

        import time
        start_time = time.time()

        # Run quick port scan
        results = await recon.quick_port_scan(target, ports=ports)

        duration = time.time() - start_time

        open_ports = [p for p, is_open in results if is_open]

        # Save to database
        scan_record = db.save_scan(
            target_id=target_obj.id,
            scan_type=ScanType.PORTS,
            result={"open_ports": open_ports, "target": target},
            ports_found=len(open_ports),
            vulns_found=0,
            duration_sec=duration,
        )

        # Display results
        print(f"{Colors.HEADER}═══ PORT SCAN RESULTS ═══{Colors.RESET}\n")
        print(f"Target: {target}")
        print(f"Time: {duration:.1f}s")

        if open_ports:
            print(f"\n{Colors.BOLD}Open Ports ({len(open_ports)}):{Colors.RESET}")
            for port in open_ports:
                print(f"  {port}/tcp OPEN")
        else:
            print(f"\n{Colors.DIM}No open ports found{Colors.RESET}")

        print(f"\n{Colors.SUCCESS}Scan saved to database (ID: {scan_record.id}){Colors.RESET}")

        await self.display.update(
            face="happy" if open_ports else "curious",
            text=f"{len(open_ports)} ports open",
            mood_text="Hunting",
        )

    async def cmd_targets(self, args: str = "") -> None:
        """Manage target list."""
        db = self._get_pentest_db()
        parts = args.strip().split() if args.strip() else []

        if not parts or parts[0] == "list":
            # List targets
            targets = db.list_targets()

            if not targets:
                print(f"\n{Colors.INFO}No targets in database.{Colors.RESET}")
                print("Use '/targets add <ip> [hostname]' to add a target.")
                return

            print(f"\n{Colors.HEADER}═══ TARGETS ({len(targets)}) ═══{Colors.RESET}\n")

            for t in targets:
                scope_color = Colors.SUCCESS if t.scope == Scope.IN_SCOPE else Colors.DIM
                scope_icon = "●" if t.scope == Scope.IN_SCOPE else "○"
                hostname = f" ({t.hostname})" if t.hostname else ""
                print(f"  {scope_color}{scope_icon}{Colors.RESET} [{t.id}] {t.ip}{hostname}")
                if t.notes:
                    print(f"      {Colors.DIM}{t.notes[:50]}{Colors.RESET}")

            return

        subcmd = parts[0].lower()

        if subcmd == "add":
            if len(parts) < 2:
                print(f"{Colors.ERROR}Usage: /targets add <ip> [hostname]{Colors.RESET}")
                return

            ip = parts[1]
            hostname = parts[2] if len(parts) > 2 else None

            # Check if already exists
            existing = db.get_target_by_ip(ip)
            if existing:
                print(f"{Colors.INFO}Target already exists: ID {existing.id}{Colors.RESET}")
                return

            target = db.add_target(ip=ip, hostname=hostname, scope=Scope.IN_SCOPE)
            print(f"{Colors.SUCCESS}Target added: ID {target.id}{Colors.RESET}")

        elif subcmd == "remove" or subcmd == "rm":
            if len(parts) < 2:
                print(f"{Colors.ERROR}Usage: /targets remove <id|ip>{Colors.RESET}")
                return

            identifier = parts[1]

            # Try to find by ID or IP
            try:
                target_id = int(identifier)
                target = db.get_target(target_id)
            except ValueError:
                target = db.get_target_by_ip(identifier)
                target_id = target.id if target else None

            if not target:
                print(f"{Colors.ERROR}Target not found: {identifier}{Colors.RESET}")
                return

            db.remove_target(target_id)
            print(f"{Colors.SUCCESS}Target removed: {target.ip}{Colors.RESET}")

        elif subcmd == "scope":
            if len(parts) < 3:
                print(f"{Colors.ERROR}Usage: /targets scope <id|ip> <in|out>{Colors.RESET}")
                return

            identifier = parts[1]
            scope_str = parts[2].lower()

            scope = Scope.IN_SCOPE if scope_str in ["in", "in_scope", "inscope"] else Scope.OUT_OF_SCOPE

            # Find target
            try:
                target_id = int(identifier)
            except ValueError:
                target = db.get_target_by_ip(identifier)
                target_id = target.id if target else None

            if not target_id:
                print(f"{Colors.ERROR}Target not found: {identifier}{Colors.RESET}")
                return

            db.update_target(target_id, scope=scope)
            print(f"{Colors.SUCCESS}Target scope updated to: {scope.value}{Colors.RESET}")

        else:
            print(f"{Colors.INFO}Usage: /targets [list|add|remove|scope]{Colors.RESET}")
            print("  list              - List all targets")
            print("  add <ip> [host]   - Add a target")
            print("  remove <id|ip>    - Remove a target")
            print("  scope <id> <in|out> - Set target scope")

    async def cmd_vulns(self, args: str = "") -> None:
        """View discovered vulnerabilities."""
        db = self._get_pentest_db()
        parts = args.strip().split() if args.strip() else []

        # Parse filters
        target_id = None
        severity_filter = None

        for part in parts:
            if part.lower() in ["critical", "high", "medium", "low", "info"]:
                severity_filter = Severity(part.lower())
            else:
                try:
                    target_id = int(part)
                except ValueError:
                    target = db.get_target_by_ip(part)
                    target_id = target.id if target else None

        vulns = db.get_vulns(target_id=target_id, severity=severity_filter)
        counts = db.get_vuln_counts(target_id=target_id)

        if not vulns:
            print(f"\n{Colors.INFO}No vulnerabilities found.{Colors.RESET}")
            print("Run scans to discover vulnerabilities: /scan, /web-scan")
            return

        print(f"\n{Colors.HEADER}═══ VULNERABILITIES ═══{Colors.RESET}\n")

        # Summary
        print(f"{Colors.ERROR}Critical: {counts.get('critical', 0)}{Colors.RESET}  "
              f"{Colors.ERROR}High: {counts.get('high', 0)}{Colors.RESET}  "
              f"{Colors.EXCITED}Medium: {counts.get('medium', 0)}{Colors.RESET}  "
              f"{Colors.INFO}Low: {counts.get('low', 0)}{Colors.RESET}  "
              f"{Colors.DIM}Info: {counts.get('info', 0)}{Colors.RESET}\n")

        # List vulnerabilities
        for v in vulns[:25]:
            severity_color = {
                Severity.CRITICAL: Colors.ERROR,
                Severity.HIGH: Colors.ERROR,
                Severity.MEDIUM: Colors.EXCITED,
                Severity.LOW: Colors.INFO,
                Severity.INFO: Colors.DIM,
            }.get(v.severity, Colors.DIM)

            port_str = f":{v.port}" if v.port else ""
            cve_str = f" [{v.cve}]" if v.cve else ""
            print(f"  {severity_color}[{v.severity.value:8}]{Colors.RESET} {v.title[:50]}{port_str}{cve_str}")

        if len(vulns) > 25:
            print(f"\n  ... and {len(vulns) - 25} more")

        print(f"\n{Colors.DIM}Filter by: /vulns [target_id|ip] [severity]{Colors.RESET}")

    async def cmd_scans(self, args: str = "") -> None:
        """View scan history."""
        db = self._get_pentest_db()
        parts = args.strip().split() if args.strip() else []

        target_id = None
        scan_type = None

        for part in parts:
            if part.lower() in ["nmap", "nikto", "recon", "ports", "dns", "whois"]:
                scan_type = ScanType(part.lower())
            else:
                try:
                    target_id = int(part)
                except ValueError:
                    target = db.get_target_by_ip(part)
                    target_id = target.id if target else None

        scans = db.get_scans(target_id=target_id, scan_type=scan_type, limit=30)

        if not scans:
            print(f"\n{Colors.INFO}No scans in history.{Colors.RESET}")
            print("Run scans to populate history: /scan, /web-scan, /recon, /ports")
            return

        print(f"\n{Colors.HEADER}═══ SCAN HISTORY ═══{Colors.RESET}\n")

        from datetime import datetime

        for s in scans:
            target = db.get_target(s.target_id)
            target_str = target.ip if target else f"[{s.target_id}]"

            timestamp = datetime.fromtimestamp(s.timestamp).strftime("%Y-%m-%d %H:%M")
            type_str = s.scan_type.value.upper()
            duration_str = f"{s.duration_sec:.1f}s" if s.duration_sec else "-"

            print(f"  [{s.id:3}] {timestamp} {type_str:6} {target_str:20} "
                  f"ports:{s.ports_found:3} vulns:{s.vulns_found:3} ({duration_str})")

        print(f"\n{Colors.DIM}View details: /scans <scan_id> or filter by target/type{Colors.RESET}")

    async def cmd_report(self, args: str = "") -> None:
        """Generate pentest report."""
        db = self._get_pentest_db()
        parts = args.strip().split() if args.strip() else []

        # Parse format
        report_format = "markdown"
        if "html" in parts:
            report_format = "html"
            parts.remove("html")

        # Get target IDs
        target_ids = []
        for part in parts:
            try:
                target_ids.append(int(part))
            except ValueError:
                target = db.get_target_by_ip(part)
                if target:
                    target_ids.append(target.id)

        # If no targets specified, use all in-scope targets
        if not target_ids:
            targets = db.list_targets(scope=Scope.IN_SCOPE)
            target_ids = [t.id for t in targets]

        if not target_ids:
            print(f"{Colors.INFO}No targets for report.{Colors.RESET}")
            print("Add targets and run scans first.")
            return

        print(f"\n{Colors.HEADER}Generating report...{Colors.RESET}\n")

        try:
            from core.report_generator import ReportGenerator
            generator = ReportGenerator(db)
            report = generator.generate(target_ids=target_ids, format=report_format)

            # Save report
            from pathlib import Path
            from datetime import datetime

            reports_dir = Path("~/.inkling/reports").expanduser()
            reports_dir.mkdir(parents=True, exist_ok=True)

            ext = "md" if report_format == "markdown" else "html"
            filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
            report_path = reports_dir / filename

            with open(report_path, "w") as f:
                f.write(report)

            print(f"{Colors.SUCCESS}Report saved: {report_path}{Colors.RESET}")
            print(f"\nReport includes:")
            print(f"  - {len(target_ids)} target(s)")
            stats = db.get_stats()
            print(f"  - {stats['scans']} scan(s)")
            print(f"  - {stats['vulnerabilities']} vulnerability(ies)")

        except ImportError:
            print(f"{Colors.ERROR}Report generator not available.{Colors.RESET}")
            print("Ensure Jinja2 is installed: pip install Jinja2")
        except Exception as e:
            print(f"{Colors.ERROR}Report generation failed: {e}{Colors.RESET}")

