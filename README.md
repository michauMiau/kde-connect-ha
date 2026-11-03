# KDE Connect integration for Home Assistant

Custom integration implementing the KDE Connect wire protocol from scratch: UDP discovery, TCP sessions with the KDE TLS model (plaintext packet, then TLS, roles inverted vs TCP direction), pairing trust-on-first-use, battery sensors, ping, notifications, SMS and runcommand services, payload transfer, events and repair flow.

## Install (manual)

Copy `custom_components/kde_connect/` into your HA config's `custom_components/` directory, restart HA, then add the integration from Settings → Devices & Services (discovery works when a KDE Connect device broadcasts on the LAN). Pair the device from KDE Connect on the peer and accept the pairing prompt in HA.

## Entities and services

- Battery sensor (charge, charging, quantity), device availability
- `kde_connect.ping`, `kde_connect.send_notification`, `kde_connect.send_sms`, `kde_connect.phone_send_notification`, `kde_connect.runcommand` (per-device commands)
- Events: discovery, pair request, battery change, ping, notifications, SMS, command output

## Development

Tests run against a Home Assistant core checkout: set `HA_CORE_PATH` to the core repo dir, then `pytest` in this repo root. Lint gates use the core repo's ruff/pylint config and `script.hassfest` (see CI).
