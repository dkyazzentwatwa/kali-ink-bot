# Web Mode Commands and Remote Control

The web UI is now a remote control surface for the Pi:
- Live dashboard for system/network/Kali readiness
- Dynamic command palette built from the shared command registry
- Chat + command execution from the same page

## Access

By default, web mode runs at:

```bash
http://<pi-hostname-or-ip>:8081
```

## Dashboard (live)

The dashboard updates continuously and shows:
- **System**: CPU, memory, temperature, uptime
- **Network**: WiFi connection + signal + BLE WiFi config status
- **Kali Readiness**: installed tools, required missing, optional missing
- **Control Plane**: command count and `/bash` enablement

Backend endpoint:

```bash
GET /api/dashboard
```

## Command Palette

The command palette is generated from `core/commands.py`, so it matches what the backend can execute.

- Commands that require parameters are prefilled into the input box for editing.
- Commands without arguments execute immediately.
- Kali profile helpers are included as quick actions:
  - `/tools`
  - `/tools profiles`
  - `/tools profile web,passwords`
  - `/tools install web,vulnerability,passwords,information-gathering`

## Running Commands

Two API paths are available:

```bash
POST /api/chat
POST /api/command
```

Example:

```bash
curl -X POST http://localhost:8081/api/command \
  -H "Content-Type: application/json" \
  -d '{"command": "/system"}'
```

## `/bash` in Web Mode

Web mode supports remote shell execution with limits:
- timeout cap
- output-size cap

Configuration keys:

```yaml
web:
  allow_bash: true
  command_timeout_seconds: 8
  max_output_bytes: 8192
```

`web.*` falls back to `ble.*` values if not specified.

## Notes

- `/help` reflects command categories currently registered and available.
- If a command requires unavailable features, the API returns a clear error.
- Web authentication still applies before API access.
