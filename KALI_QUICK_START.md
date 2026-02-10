# Kali Bot Quick Start

This guide configures Inkling for a Raspberry Pi friendly Kali tool baseline.

## 1. Install baseline packages (recommended on Pi)

```bash
sudo apt update
sudo apt install -y kali-linux-headless nmap hydra nikto
```

Optional advanced tools:

```bash
sudo apt install -y metasploit-framework sqlmap aircrack-ng
```

Full Kali superset (supported, larger footprint):

```bash
sudo apt install -y kali-linux-default
```

## 2. Configure Inkling

`config.yml` now includes a Pi-first pentest profile:

- `pentest.package_profile: pi-headless-curated`
- `pentest.required_tools: [nmap, hydra, nikto]`
- `pentest.optional_tools: [msfconsole, sqlmap, aircrack-ng]`

## 3. Verify tool status

From SSH mode:

```text
/tools
/tools profiles
/tools profile web,passwords
/tools install web,vulnerability,passwords,information-gathering
```

Expected behavior:

- Missing required tools are reported as blocking.
- Missing optional tools are warnings.
- Install guidance is shown for both baseline and full profile.
- Profile commands let you inspect/install modular groups from Kali metapackages.

## 4. Validate MCP status

The Kali MCP server exposes `pentest_tools_status`.

If MCP is enabled in `config.yml`, the AI can call it to inspect tool readiness.

## 5. Notes

- Exploit/session workflows are MVP-safe stubs.
- If `msfconsole` is missing, exploit/session calls return explicit optional-tool guidance.
- Engagement and scope checks remain unchanged and should still gate active testing behavior.
