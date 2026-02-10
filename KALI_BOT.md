# Kali Bot Runtime and Tooling Notes

This document defines the current Kali package profile strategy and runtime behavior for Inkling.

## Package profile strategy

### Default profile: `pi-headless-curated`

Optimized for Raspberry Pi deployments with constrained CPU, RAM, and storage.

Baseline install:

```bash
sudo apt update
sudo apt install -y kali-linux-headless nmap hydra nikto
```

Optional advanced install:

```bash
sudo apt install -y metasploit-framework sqlmap aircrack-ng
```

### Supported superset profile: `kali-linux-default`

Supported when users want the broad official Kali package set.

```bash
sudo apt install -y kali-linux-default
```

### Modular metapackage groups (new)

These profile groups can be mixed as needed:

- `information-gathering` -> `kali-tools-information-gathering`
- `web` -> `kali-tools-web`
- `vulnerability` -> `kali-tools-vulnerability`
- `passwords` -> `kali-tools-passwords`

Combined install example:

```bash
sudo apt install -y kali-tools-information-gathering kali-tools-web kali-tools-vulnerability kali-tools-passwords
```

## Runtime tool status model

Tool availability is categorized into:

- `required_tools`: blocking if missing.
- `optional_tools`: warnings only; advanced workflows degrade gracefully.

Status sources:

- `core/kali_tools.py`: `get_tools_status()`
- `core/kali_tools.py`: `get_profiles_catalog()`, `get_profile_status()`, `get_profile_install_command()`
- MCP: `pentest_tools_status`
- Chat command: `/tools` in SSH and web modes

## Expected `/tools` behavior

`/tools` shows:

1. Active package profile
2. Installed tools
3. Missing required tools (blocking)
4. Missing optional tools (warning)
5. Install guidance for:
   - Pi baseline
   - Optional advanced tools
   - Full profile

Subcommands:

- `/tools profiles` -> list available modular groups
- `/tools profile web,passwords` -> profile-specific install/missing status
- `/tools install web,vulnerability,passwords,information-gathering` -> apt command generator

## MCP behaviors

`mcp_servers/kali.py` includes:

- `pentest_tools_status`
- `pentest_profiles_list`
- `pentest_profile_status`
- `pentest_profile_install_command`
- `pentest_scan`
- `pentest_web_scan`
- `pentest_exploit` (MVP safe stub)
- `pentest_sessions_list` (MVP safe stub)
- `pentest_session_interact` (MVP safe stub)

### Degradation rules

- If required tools are missing, scan actions return status/guidance errors.
- If optional tool `msfconsole` is missing:
  - exploit/session tools return explicit optional-tool errors
  - response includes install hints

## Validation checklist

Use this checklist after provisioning:

1. Run `/tools` and verify:
   - no required missing tools for your intended workflows
   - optional missing list matches installed packages
2. If using MCP, verify `pentest_tools_status` is available.
3. Confirm config values:
   - `pentest.package_profile`
   - `pentest.required_tools`
   - `pentest.optional_tools`
4. If planning exploit/session work, install `metasploit-framework`.

## Security and scope

These changes do not alter engagement/scope authorization logic.

Tool readiness checks happen before execution, but target authorization and in-scope validation must still be enforced by engagement logic.
