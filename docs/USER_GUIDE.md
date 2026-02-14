# Kali Ink Bot User Guide

Your AI-powered pentesting companion for Raspberry Pi Zero 2W.

---

## What Is This?

Kali Ink Bot is an AI assistant that helps you run penetration tests. It combines:

- **Kali Linux tools** (nmap, nikto, hydra, etc.)
- **AI brains** (Claude, GPT, Gemini, or Ollama)
- **A cute personality** that levels up as you work
- **Web & SSH interfaces** for flexible access

Think of it as a hacker buddy that lives on your Pi.

---

## Quick Start

### 1. Setup

```bash
# Clone and enter the project
cd kali-ink-bot

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy config and add your API key
cp config.yml config.local.yml
nano config.local.yml
```

Add your AI provider key:
```yaml
ai:
  primary: anthropic  # or openai, gemini, ollama
  anthropic:
    api_key: "sk-ant-your-key-here"
```

### 2. Run It

**Web Mode** (recommended for most users):
```bash
python main.py --mode web
```
Then open http://localhost:8081 in your browser.

**SSH Mode** (terminal interface):
```bash
python main.py --mode ssh
```

---

## The Interface

### Web UI Pages

| Page | URL | What It Does |
|------|-----|--------------|
| **Chat** | `/` | Talk to your AI, run commands |
| **Scans** | `/scans` | Dashboard for targets & scan history |
| **Vulns** | `/vulns` | View discovered vulnerabilities |
| **Tasks** | `/tasks` | Kanban board for pentest objectives |
| **Files** | `/files` | Browse saved reports & data |
| **Settings** | `/settings` | Configure personality & AI |

### Chat Commands

Type these in the chat input (web) or terminal (SSH):

#### Pentesting Commands

| Command | What It Does |
|---------|--------------|
| `/scan <target>` | Run nmap network scan |
| `/web-scan <url>` | Run nikto web vulnerability scan |
| `/recon <domain>` | DNS enumeration + WHOIS lookup |
| `/ports <target>` | Quick TCP port scan (no nmap needed) |
| `/targets` | List/manage your target list |
| `/vulns` | Show discovered vulnerabilities |
| `/scans` | Show scan history |
| `/report` | Generate a pentest report |
| `/tools` | Check which Kali tools are installed |

#### General Commands

| Command | What It Does |
|---------|--------------|
| `/help` | Show all commands |
| `/tasks` | List your tasks |
| `/task <title>` | Create a new task |
| `/done <id>` | Mark task complete (+XP!) |
| `/mood` | Check the bot's mood |
| `/level` | See XP and progression |
| `/system` | Show CPU, memory, temp |
| `/clear` | Clear chat history |

---

## Pentesting Workflow

### Step 1: Add a Target

```
/targets add 192.168.1.100
```

Or use the Scans page and click "Add Target".

### Step 2: Reconnaissance

Get DNS records and WHOIS info:
```
/recon example.com
```

Quick port check:
```
/ports 192.168.1.100
```

### Step 3: Scan

Network scan with nmap:
```
/scan 192.168.1.100
```

Web vulnerability scan:
```
/web-scan http://192.168.1.100
```

### Step 4: Review Findings

Check what was found:
```
/vulns
```

Or visit the Vulns page (`/vulns`) for a visual dashboard.

### Step 5: Generate Report

Create a markdown report:
```
/report
```

Reports are saved to `~/.inkling/pentest/reports/`.

---

## Talking to the AI

Just type normally and the AI will help you:

```
> What should I scan first on this network?

> Can you explain what this nmap output means?

> How do I exploit CVE-2024-1234?

> Write me a Python script to test for SQL injection
```

The AI has access to your scan results and can help interpret them.

---

## The Scans Dashboard

Visit `/scans` in your browser for:

### Stats Overview
- Total targets in scope
- Number of scans run
- Vulnerabilities found (by severity)

### Quick Scan
1. Enter target IP/hostname
2. Select scan type (nmap, nikto, or quick ports)
3. Click "Scan"

### Target Management
- Add new targets with scope (in-scope, out-of-scope)
- Remove targets when done
- One-click scan any target

### Scan History
- See all past scans
- Click any scan to view full results
- Filter by target or scan type

---

## The Vulns Dashboard

Visit `/vulns` for:

### Severity Summary
Click any severity level to filter:
- **Critical** (red) - Immediate action needed
- **High** (orange) - Serious issues
- **Medium** (yellow) - Should fix
- **Low** (blue) - Minor issues
- **Info** (gray) - Informational

### Vulnerability Cards
Each card shows:
- Title and severity badge
- CVE number (if known)
- CVSS score
- Description

Click any card for full details.

### Export
Download all vulns as CSV for reporting.

---

## Configuration

Edit `config.local.yml`:

### AI Provider
```yaml
ai:
  primary: anthropic  # anthropic, openai, gemini, ollama

  anthropic:
    api_key: "sk-ant-..."
    model: claude-sonnet-4-5-20250929

  openai:
    api_key: "sk-..."
    model: gpt-4o-mini

  ollama:
    base_url: "http://localhost:11434/api"
    model: llama3
```

### Token Budget
```yaml
ai:
  budget:
    daily_tokens: 50000      # Daily limit
    per_request_max: 500     # Max per response
```

### Pentest Settings
```yaml
pentest:
  data_dir: "~/.inkling/pentest"
  package_profile: "pi-headless-curated"
  enabled_profiles:
    - web
    - passwords
    - information-gathering
```

### Remote Access (Ngrok)
```yaml
network:
  ngrok:
    enabled: true
    auth_token: "your-ngrok-token"
```

Set a password:
```bash
export SERVER_PW="your-secure-password"
```

---

## Installing Kali Tools

The bot checks which tools you have installed:

```
/tools
```

To see available tool profiles:
```
/tools profiles
```

Install a profile mix:
```
/tools install web,passwords,information-gathering
```

This generates an apt command you can run:
```bash
sudo apt install nmap nikto hydra dirb gobuster ...
```

---

## Personality & Leveling

Your bot has a personality that evolves:

### Moods
- Happy, Excited, Curious (positive interactions)
- Bored, Sad (inactivity)
- Hunting, Focused, Alert (during pentests)

### XP System
Earn XP by:
- Completing tasks
- Running scans
- Finding vulnerabilities
- Chatting productively

Level up for new titles: NEWB → SCRIPT_KIDDIE → HACKER → ELITE → ...

### Traits
Adjust personality in Settings:
- **Curiosity** - How much it explores
- **Cheerfulness** - Response positivity
- **Verbosity** - Response length
- **Playfulness** - Humor level
- **Empathy** - Understanding tone
- **Independence** - Proactive suggestions

---

## Tips & Tricks

### 1. Use the AI to Plan
```
> I have access to 192.168.1.0/24. Help me plan a pentest.
```

### 2. Ask for Explanations
```
> What does this nmap script output mean?
> [paste output]
```

### 3. Generate Custom Scripts
```
> Write a Python script to brute force FTP login
```

### 4. Track Your Work
Use tasks to stay organized:
```
/task Enumerate all web services on target
/task Test for SQL injection on login form
/task Document findings for client report
```

### 5. Keyboard Shortcuts (Web)
- `Ctrl+Enter` - Send message
- `Ctrl+K` - Command palette
- `Escape` - Close modals

---

## File Locations

| What | Where |
|------|-------|
| Config | `./config.local.yml` |
| Database | `~/.inkling/pentest/pentest.db` |
| Reports | `~/.inkling/pentest/reports/` |
| Conversation | `~/.inkling/conversation.json` |
| Tasks | `~/.inkling/tasks.db` |

---

## Troubleshooting

### "No API key configured"
Add your key to `config.local.yml` or set environment variable:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### "nmap not found"
Install Kali tools:
```bash
sudo apt install nmap
```

### Web UI not loading
Check the port isn't in use:
```bash
lsof -i :8081
```

### Scans timing out
On Pi Zero 2W, use conservative timing:
```
/scan 192.168.1.1 -T3
```

### Out of memory
Limit concurrent operations. The bot auto-manages this, but avoid running multiple heavy scans simultaneously.

---

## Legal Notice

**Only use on systems you own or have written permission to test.**

Unauthorized access to computer systems is illegal. This tool is for:
- Authorized penetration testing
- Security research
- CTF competitions
- Learning in lab environments

Stay legal. Stay ethical. Happy hacking.

---

## Getting Help

- Check `/help` for all commands
- Ask the AI for guidance
- Read `CLAUDE.md` for developer docs
- File issues at the project repo

---

*Built with love for the security community.*
