<div align="center">

# 🛡️ Kali Ink Bot

### *Your AI-Powered Penetration Testing Companion*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

*A Pwnagotchi-inspired AI security assistant for Kali Linux on Raspberry Pi with e-ink display*

[Features](#-features) • [Quick Start](#-quick-start) • [Usage](#-usage) • [Documentation](#-documentation) • [Legal](#%EF%B8%8F-legal-warning)

---

<p align="center">
  <img src="img/inky1.jpeg" alt="Kali Ink Bot Device 1" width="45%">
  <img src="img/inky6.jpeg" alt="Kali Ink Bot Device 2" width="45%">
</p>

---

</div>

## ⚠️ LEGAL WARNING

**This tool is for AUTHORIZED SECURITY TESTING ONLY**

- ✅ Only use on systems you **own** or have **written authorization** to test
- ✅ Designed for penetration testers, security researchers, and CTF players
- ✅ Educational use on isolated test environments
- ❌ **NEVER** use on systems without explicit permission
- ❌ Unauthorized access to computer systems is **illegal**

**You are solely responsible for your use of this tool. The authors assume no liability for misuse.**

---

## ✨ What is Kali Ink Bot?

Kali Ink Bot is an **AI-powered penetration testing assistant** that combines Kali Linux security tools with an intelligent AI companion. Built for Raspberry Pi Zero 2W with an e-ink display, it provides:

- 🤖 **AI-Assisted Pentesting**: Claude/GPT/Gemini helps plan and execute security assessments
- 🛠️ **Kali Tool Integration**: Nmap, Metasploit, Hydra, Nikto, SQLMap, Aircrack-ng
- 📊 **Profile Management**: Optimized tool packages for Pi (headless-curated) or full Kali
- 🖥️ **E-ink Display**: Pwnagotchi-style interface showing scan status and results
- 💬 **Multi-Mode Interface**: SSH terminal or web UI (http://localhost:8081)
- 🎭 **Personality System**: Evolving AI personality with moods and XP progression

Think Pwnagotchi meets Metasploit meets your favorite AI assistant—designed for ethical hackers.

---

## 🎯 Key Features

<table>
<tr>
<td width="50%">

#### 🛡️ **Security Testing Tools**
- **Network Scanning**: Nmap integration with XML parsing
- **Web Scanning**: Nikto vulnerability detection
- **Password Attacks**: Hydra brute-forcing
- **Exploitation**: Metasploit framework support
- **SQL Injection**: SQLMap integration
- **WiFi Attacks**: Aircrack-ng support
- **Profile System**: Modular tool packages

</td>
<td width="50%">

#### 🧠 **AI Assistance**
- **Multi-Provider**: Anthropic Claude, OpenAI GPT, Google Gemini, Ollama
- **Tool Guidance**: AI helps select and configure tools
- **Report Generation**: Automated scan analysis
- **Task Planning**: Break down complex assessments
- **Conversation Memory**: Persistent context across sessions
- **MCP Integration**: 8 pentest tools exposed to AI

</td>
</tr>
<tr>
<td width="50%">

#### 🖥️ **E-ink Display**
- Pwnagotchi-style UI layout
- Scan status and results
- WiFi signal strength indicator
- Battery status (PiSugar support)
- Screen saver mode
- Dark mode for night operations
- Waveshare V3/V4 support

</td>
<td width="50%">

#### 💬 **Multi-Mode Interface**
- **SSH Mode**: Terminal interface for quick commands
- **Web UI**: Browser interface at http://localhost:8081
- **Remote Access**: Ngrok tunnel for remote operations
- **File Browser**: Edit scripts and reports in-browser
- **13 Themes**: Pastel and dark themes
- **20+ Commands**: `/tools`, `/scan`, `/help`, etc.

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

- **Raspberry Pi Zero 2W** (or any Linux device for development)
- **Kali Linux** or Debian/Ubuntu-based system
- **Waveshare 2.13" e-ink display** (V3 or V4) - *optional, works with mock display*
- **Python 3.11+**
- **API Key** from [Anthropic](https://console.anthropic.com), [OpenAI](https://platform.openai.com), or [Google AI](https://ai.google.dev/)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/kali-ink-bot.git
cd kali-ink-bot

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Copy config template
cp config.yml config.local.yml
```

### Install Kali Tools

**Baseline (Recommended for Raspberry Pi)**:
```bash
sudo apt update
sudo apt install -y kali-linux-headless nmap hydra nikto
```

**Optional Advanced Tools**:
```bash
sudo apt install -y metasploit-framework sqlmap aircrack-ng
```

**Full Kali Package** (larger footprint):
```bash
sudo apt install -y kali-linux-default
```

### Configuration

Edit `config.local.yml`:

```yaml
# Set your device name
device:
  name: "Kali-Bot"

# Configure AI provider (get keys from provider websites)
ai:
  primary: "anthropic"  # or "openai" or "gemini"
  anthropic:
    api_key: "sk-ant-..."
    model: "claude-haiku-4-5"  # Fast and cheap!

# Configure Kali tool profile
pentest:
  package_profile: "pi-headless-curated"  # or "kali-linux-default"
  required_tools: ["nmap", "hydra", "nikto"]
  optional_tools: ["msfconsole", "sqlmap", "aircrack-ng"]

# Enable Kali MCP server
mcp:
  enabled: true
  servers:
    kali:
      command: "python"
      args: ["mcp_servers/kali.py"]
```

Or use environment variables:

```bash
# Create .env file
cp .env.example .env

# Add your API key
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
```

### Running

```bash
# Activate virtual environment
source .venv/bin/activate

# SSH/Terminal mode (best for development)
python main.py --mode ssh

# Web UI mode (browser at http://localhost:8081)
python main.py --mode web

# Demo mode (cycles through all face expressions)
python main.py --mode demo
```

### Verify Tool Installation

From SSH mode:
```bash
/tools                    # Show tool installation status
/tools profiles           # List available tool profiles
/tools profile web        # Check web testing tools
```

---

## 🎮 Usage

### Available Modes

| Mode | Command | Description |
|------|---------|-------------|
| 🖥️ **SSH** | `python main.py --mode ssh` | Terminal chat interface |
| 🌐 **Web** | `python main.py --mode web` | Browser UI at http://localhost:8081 |
| 🎨 **Demo** | `python main.py --mode demo` | Display test (all faces) |

### Slash Commands

<details>
<summary><b>🛡️ Pentest Commands</b></summary>

- `/tools` - Show Kali tool installation status
- `/tools profiles` - List available tool profiles
- `/tools profile <name>` - Show specific profile status
- `/tools install <profiles>` - Generate install command

</details>

<details>
<summary><b>📊 Info Commands</b></summary>

- `/help` - Show all available commands
- `/level` - View XP, level, and progression
- `/stats` - Token usage and remaining budget
- `/history` - Recent conversation messages

</details>

<details>
<summary><b>🎭 Personality Commands</b></summary>

- `/mood` - Current mood and intensity
- `/energy` - Energy level with visual bar
- `/traits` - View all personality traits

</details>

<details>
<summary><b>⚙️ System Commands</b></summary>

- `/system` - CPU, memory, temperature stats
- `/config` - AI provider and model info
- `/bash <command>` - Run shell command
- `/face <name>` - Test a face expression
- `/faces` - List all available faces
- `/refresh` - Force display update
- `/screensaver` - Toggle screen saver on/off
- `/darkmode` - Toggle dark mode

</details>

<details>
<summary><b>📡 WiFi Commands</b></summary>

- `/wifi` - Show WiFi status and saved networks
- `/btcfg` - Start BLE configuration service (15 min)
- `/wifiscan` - Scan for nearby WiFi networks

</details>

<details>
<summary><b>💬 Session Commands</b></summary>

- `/clear` - Clear conversation history
- `/ask <message>` - Explicit chat
- `/quit` or `/exit` - Exit (SSH mode only)

</details>

### Example Workflow

```bash
# Start SSH mode
python main.py --mode ssh

# Check tool status
/tools

# Ask AI for help
What tools should I use to scan a web application for vulnerabilities?

# AI will suggest tools and can run them via MCP:
# - pentest_scan: Run nmap against target
# - pentest_web_scan: Run Nikto web scan
# - pentest_tools_status: Check what's installed
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Raspberry Pi Zero 2W                    │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │
│  │  Display   │  │ Personality│  │  Brain (Multi-AI)    │  │
│  │  Manager   │◀─│   System   │◀─│  • Anthropic/Claude  │  │
│  │            │  │            │  │  • OpenAI/GPT        │  │
│  │  E-ink V3/4│  │ Mood, XP,  │  │  • Google/Gemini     │  │
│  │  or Mock   │  │ Traits     │  │  • Ollama           │  │
│  └────────────┘  └────────────┘  └──────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Kali Tool Manager (Profile-Aware)            │  │
│  │  • Nmap  • Metasploit  • Hydra  • Nikto            │  │
│  │  • SQLMap  • Aircrack-ng  • Tool Status Tracking    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         MCP Servers (Model Context Protocol)         │  │
│  │  • Pentest tools  • System tools  • File browser    │  │
│  │  • 8 pentest operations exposed to AI               │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| 🧠 **Brain** | `core/brain.py` | Multi-provider AI with automatic fallback |
| 🎭 **Personality** | `core/personality.py` | Mood state machine, traits, progression |
| 🛡️ **Kali Tools** | `core/kali_tools.py` | Tool manager, scan results, exploit handling |
| 📊 **Profiles** | `core/kali_profiles.py` | Package profiles and metapackage management |
| 🖥️ **Display** | `core/display.py` | E-ink driver abstraction (V3/V4/Mock) |
| 🎨 **UI** | `core/ui.py` | Pwnagotchi-style display layout |
| 🔧 **MCP Client** | `core/mcp_client.py` | Tool integration for AI |
| 🛠️ **Kali MCP** | `mcp_servers/kali.py` | Pentest tools exposed via MCP |

---

## 📚 Documentation

- 📖 **[Kali Bot Guide](KALI_BOT.md)** - Complete package profile strategy
- ⚡ **[Quick Start Guide](KALI_QUICK_START.md)** - 5-minute setup
- 🎮 **[Usage Guide](docs/guides/USAGE.md)** - Feature walkthrough
- 🌐 **[Web UI Guide](docs/guides/WEB_UI.md)** - Browser interface
- 🔌 **[Remote Access](docs/guides/REMOTE_CLAUDE_CODE.md)** - Ngrok setup
- 🔧 **[Troubleshooting](docs/guides/TROUBLESHOOTING.md)** - Common issues
- 🤖 **[CLAUDE.md](CLAUDE.md)** - Technical docs for AI assistants

---

## 🛠️ MCP Pentest Tools

The AI can use these tools via Model Context Protocol:

1. **pentest_tools_status** - Check installed tools and get guidance
2. **pentest_scan** - Run nmap network scans
3. **pentest_web_scan** - Run Nikto web vulnerability scans
4. **pentest_profiles_list** - List available tool profiles
5. **pentest_profile_status** - Check profile installation status
6. **pentest_profile_install_command** - Generate apt install commands
7. **pentest_exploit** - Exploit workflows (MVP stub)
8. **pentest_sessions_list** - List active sessions (MVP stub)

Enable in `config.yml`:
```yaml
mcp:
  enabled: true
  servers:
    kali:
      command: "python"
      args: ["mcp_servers/kali.py"]
```

---

## 🎨 Tool Profiles

### Pi-Headless-Curated (Recommended)

Optimized for Raspberry Pi with limited resources:
```bash
sudo apt install -y kali-linux-headless nmap hydra nikto
```

### Modular Profiles

Install specific tool categories:
```bash
# Information gathering
sudo apt install -y kali-tools-information-gathering

# Web testing
sudo apt install -y kali-tools-web

# Vulnerability assessment
sudo apt install -y kali-tools-vulnerability

# Password cracking
sudo apt install -y kali-tools-passwords
```

### Full Kali Default

Complete tool suite:
```bash
sudo apt install -y kali-linux-default
```

---

## 📡 WiFi Configuration (Portable Use)

For field testing, configure WiFi via Bluetooth using BTBerryWifi:

```bash
# Install on Raspberry Pi
curl -L https://raw.githubusercontent.com/nksan/Rpi-SetWiFi-viaBluetooth/main/btwifisetInstall.sh | bash
```

**Mobile Apps**:
- iOS: [App Store](https://apps.apple.com/app/btberrywifi/id6479825660)
- Android: [Google Play](https://play.google.com/store/apps/details?id=com.bluetoothwifisetup)

**Commands**:
- `/wifi` - Show WiFi status
- `/btcfg` - Start BLE configuration (15 min)
- `/wifiscan` - Scan networks

---

## 🔋 PiSugar Battery Support

For portable pentesting with battery status on display:

```bash
# Install PiSugar Power Manager
wget https://cdn.pisugar.com/release/pisugar-power-manager.sh
sudo bash pisugar-power-manager.sh -c release

# Enable service
sudo systemctl enable --now pisugar-server
```

Configure in `config.local.yml`:
```yaml
battery:
  enabled: true
  host: "127.0.0.1"
  port: 8423
```

---

## 🛠️ Development

### Running Tests

```bash
source .venv/bin/activate

# All tests
pytest

# Kali-specific tests
pytest tests/test_kali_tools.py -xvs
pytest tests/test_mcp_kali.py -xvs

# Coverage
pytest --cov=core --cov-report=html
```

### Debug Mode

```bash
# Enable detailed logging
INKLING_DEBUG=1 python main.py --mode ssh

# Disable display echo
INKLING_NO_DISPLAY_ECHO=1 python main.py --mode ssh
```

### Project Structure

```
kali-ink-bot/
├── core/
│   ├── brain.py           # Multi-AI provider
│   ├── personality.py     # Mood & traits
│   ├── kali_tools.py      # Tool manager
│   ├── kali_profiles.py   # Package profiles
│   └── display.py         # E-ink driver
├── mcp_servers/
│   ├── kali.py            # Pentest MCP server
│   ├── system.py          # System utilities
│   └── filesystem.py      # File operations
├── modes/
│   ├── ssh_chat.py        # Terminal interface
│   └── web_chat.py        # Browser interface
├── docs/                  # Documentation
├── tests/                 # Test suite
├── config.yml             # Default config
└── main.py                # Entry point
```

---

## 🤝 Contributing

Contributions welcome! Whether it's:

- 🐛 Bug reports
- 💡 New tool integrations
- 📝 Documentation improvements
- 🔧 Code contributions

Please open an issue or pull request on GitHub.

---

## 🙏 Acknowledgments

- **Pwnagotchi** - Inspiration for personality system and e-ink UI
- **Kali Linux** - Industry-standard pentest distribution
- **Offensive Security** - Security training and tools
- **Anthropic** - Claude API for AI assistance
- **Waveshare** - E-ink display hardware
- **Raspberry Pi Foundation** - Perfect portable platform

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

**Use responsibly and ethically. Always obtain proper authorization.**

---

## ⚖️ Responsible Disclosure

If you discover security vulnerabilities in this tool, please:

1. Do NOT exploit them
2. Report responsibly via GitHub issues or email
3. Give maintainers time to patch before public disclosure

---

<div align="center">

**Made with ❤️ for ethical hackers and security professionals**

*Hack responsibly. Test legally. Stay curious.*

</div>
