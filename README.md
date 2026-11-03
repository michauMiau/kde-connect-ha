<div align=center>
   <h2>
KDE Connect integration for Home Assistant.
   </h2>
</div>

Also check out [KOSPEL PPE4 for Home Assistant](https://github.com/michauMiau/ppe4-ha), the sibling integration in this family.

## Features

- Full KDE Connect protocol v8: UDP discovery, TCP sessions, plaintext packet + TLS (KDE's inverted TLS roles), encrypted identity, pairing trust-on-first-use
- **Sensors**: battery charge, charging state, battery quantity; device availability
- **Services**: ping, send notification, cancel notification, request notifications, notification reply, SMS, phone notification, find-my-phone, runcommand
- **Events**: discovery, pair request, battery change, ping, notifications, SMS, command output

## Installation

### Marketplace (recommended)

[![Open your Home Assistant instance and add the repository](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=michauMiau&repository=kde-connect-ha&category=integration)

1. Click the badge above (or **Marketplace → ⋮ → Custom repositories**)
2. Repository: `michauMiau/kde-connect-ha`, category: **Integration**
3. Click **Download** on *KDE Connect*.
4. Restart Home Assistant.

### Manual

1. Copy `custom_components/kde_connect/` into your HA `config/custom_components/` directory.
2. Restart Home Assistant.

### Add the device

[![Open your Home Assistant instance and start setting up.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=kde_connect)

Or: *Settings → Devices & Services → Add Integration → **KDE Connect***.
Devices broadcasting on the LAN are announced as discovery flows; a KDE Connect peer
sent to the integration appears as an unknown-device flow. Pair the device from KDE
Connect on the peer and accept the pairing prompt in Home Assistant.

## Development

Tests run against a Home Assistant core checkout: set `HA_CORE_PATH` to the core repo
dir, then `pytest` in this repo root. CI runs hassfest, HACS validation, functional
pytest and ruff/pylint gates.
