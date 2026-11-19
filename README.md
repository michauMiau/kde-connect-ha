<div align=center>
   <h2>
KDE Connect integration for Home Assistant.
   </h2>
</div>

Also check out [KOSPEL PPE4 for Home Assistant](https://github.com/michauMiau/ppe4-ha), the sibling integration in this family.

## Features

- Full KDE Connect protocol v8: UDP listen/probe, TCP sessions, plaintext packet + TLS (KDE's inverted TLS roles), encrypted identity, pairing trust-on-first-use
- **Sensors**: battery charge, charging state, battery quantity; device availability
- **Media player**: MPRIS remote control of the device's active player (play/pause/next/previous/seek/volume/source)
- **Run commands**: HA acts as the desktop side — define `key=command` lines in the entry options, enable execution, and trigger them from KDE Connect on the device. Each configured command also gets a HA **button** that runs it locally (output is emitted as a `kdeconnect_command_output` event).
- **Services**: send notification, cancel notification, request notifications, notification reply, SMS, find-my-phone, ping, pair, accept_pair, unpair
- **Events**: device discovered, pair request, battery change, ping, notifications, SMS, command output

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

The wizard offers a **one-time local network scan** (no background broadcasting or
sweeping) that lists discovered devices by name, id and IP, or manual host entry.
Pairing is only sent after you confirm it in the pairing step; accept it in KDE
Connect on the device.

To run commands on the Home Assistant host from the device, open the entry's
**Options**, add `key=command` lines and enable *Allow the device to run local
commands*. Each line also creates a `button.<key>` entity in HA that runs the
command locally; its stdout/stderr/exit code are emitted as
`kdeconnect_command_output` events for automations.

If a device shows as unavailable, pairing is not confirmed. Call the
`kde_connect.pair` service (target the device) and accept the request in KDE
Connect on the device; `kde_connect.unpair` tears it down. Pairing state is
stored on the entry, so reloads keep entities available.

Device-initiated pairing requests are auto-accepted by default. Disable
*Automatically accept pairing requests from the device* in the entry options to
require approval through `kde_connect.accept_pair` (a repair issue names the
requesting device).

## Development

Tests run against a Home Assistant core checkout: set `HA_CORE_PATH` to the core repo
dir, then `pytest` in this repo root. CI runs hassfest, HACS validation, functional
pytest and ruff/pylint gates.
