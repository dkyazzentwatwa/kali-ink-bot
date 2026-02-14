# Kali Ink Bot Quick Reference

## Starting Up

```bash
source .venv/bin/activate
python main.py --mode web    # Browser at http://localhost:8081
python main.py --mode ssh    # Terminal interface
```

---

## Pentest Commands

| Command | Example | Description |
|---------|---------|-------------|
| `/scan` | `/scan 192.168.1.1` | Nmap network scan |
| `/web-scan` | `/web-scan http://target.com` | Nikto web scan |
| `/recon` | `/recon example.com` | DNS + WHOIS lookup |
| `/ports` | `/ports 10.0.0.1` | Quick TCP port scan |
| `/targets` | `/targets add 192.168.1.1` | Manage target list |
| `/vulns` | `/vulns` | List vulnerabilities |
| `/scans` | `/scans` | View scan history |
| `/report` | `/report` | Generate report |
| `/tools` | `/tools profiles` | Check installed tools |

---

## Task Commands

| Command | Example | Description |
|---------|---------|-------------|
| `/tasks` | `/tasks` | List all tasks |
| `/task` | `/task Test login form` | Create new task |
| `/done` | `/done abc123` | Complete task (+XP) |
| `/cancel` | `/cancel abc123` | Cancel task |
| `/delete` | `/delete abc123` | Delete permanently |

---

## Info Commands

| Command | Description |
|---------|-------------|
| `/help` | Show all commands |
| `/mood` | Current mood |
| `/level` | XP and progression |
| `/stats` | Token usage |
| `/system` | CPU, memory, temp |
| `/config` | AI configuration |

---

## Web Pages

| Page | URL |
|------|-----|
| Chat | `http://localhost:8081/` |
| Scans | `http://localhost:8081/scans` |
| Vulns | `http://localhost:8081/vulns` |
| Tasks | `http://localhost:8081/tasks` |
| Files | `http://localhost:8081/files` |
| Settings | `http://localhost:8081/settings` |

---

## Common Workflows

### Quick Network Assessment
```
/targets add 192.168.1.0/24
/ports 192.168.1.1
/scan 192.168.1.1
/vulns
```

### Web App Test
```
/recon target.com
/web-scan http://target.com
/vulns
/report
```

### Check Tool Readiness
```
/tools
/tools profiles
/tools install web,passwords
```

---

## Environment Variables

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude
export OPENAI_API_KEY="sk-..."          # GPT
export GOOGLE_API_KEY="..."             # Gemini
export SERVER_PW="password"             # Web auth
export INKLING_DEBUG=1                  # Debug logs
```

---

## File Locations

```
~/.inkling/
├── pentest/
│   ├── pentest.db          # Targets, scans, vulns
│   └── reports/            # Generated reports
├── conversation.json       # Chat history
├── tasks.db               # Task database
└── personality.json       # Bot state
```

---

## Keyboard Shortcuts (Web)

| Key | Action |
|-----|--------|
| `Ctrl+Enter` | Send message |
| `Ctrl+K` | Command palette |
| `Escape` | Close modal |

---

## Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| Critical | Red | Immediate action |
| High | Orange | Serious issue |
| Medium | Yellow | Should fix |
| Low | Blue | Minor issue |
| Info | Gray | Informational |

---

*Full guide: `docs/USER_GUIDE.md`*
