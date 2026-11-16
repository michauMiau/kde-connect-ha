"""Config flow for the KDE Connect integration.

Flow steps:
  user       -> ask host/port, UDP identity probe (discovery.py), TCP+TLS
               handshake (peer.py KdePeer.connect)
  discovery  -> accept a UDP-announce found device, handshake, pair
  pair       -> send pairing request; device prompts user; retry form on
               timeout (peer.py request_pair waits PAIRING_TIMEOUT itself)
  create     -> store peer identity + pinned certificate as the config entry

The flow owns a throwaway ``KdePeer`` for handshake/pairing; once the entry is
created the integration builds a new peer from the stored entry data.
Trust model (peer.py): peer certificate CN must equal deviceId; a pinned cert
(from the entry) must match byte-for-byte on reconnect.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.data_entry_flow import AbortFlow
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig
from homeassistant.setup import async_setup_component

from .const import (
    CONF_ALLOW_REMOTE_COMMANDS,
    CONF_ANNOUNCE,
    CONF_CAPABILITIES,
    CONF_DEVICE_ID,
    CONF_DEVICE_NAME,
    CONF_DEVICE_TYPE,
    CONF_HOST,
    CONF_INBOUND_PORT,
    CONF_LOCAL_COMMANDS,
    CONF_PEER_CERT,
    CONF_TCP_PORT,
    DOMAIN,
    HANDSHAKE_TIMEOUT,
    MAX_TCP_PORT,
    MIN_TCP_PORT,
    UDP_PORT,
)
from .peer import KdePeer
from .protocol import ProtocolError, valid_device_id

_LOGGER = logging.getLogger(__name__)

# Keys of hass.data[DOMAIN] owned by __init__.py (mirrored here to avoid a
# circular import at module load).
_DATA_MANAGER = "manager"

# User-facing form schema reused for the user step.
_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_TCP_PORT, default=UDP_PORT): int,
    }
)

# Pairing retry form: "Continue" re-checks pair state; unchecked -> abort.
_RETRY_SCHEMA = vol.Schema({vol.Optional("retry_again", default=True): bool})


class KdeConnectConfigFlow(ConfigFlow, domain=DOMAIN):
    """Set up one KDE Connect peer (protocol version 8)."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize flow state."""
        self._host: str | None = None
        self._tcp_port: int = UDP_PORT
        self._device_id: str | None = None
        self._device_name: str | None = None
        self._device_type: str | None = None
        self._peer_cert: str | None = None
        self._capabilities: list[str] = []
        self._peer: KdePeer | None = None

    def _manager(self) -> Any | None:
        """Return the integration manager singleton (set by async_setup)."""
        return self.hass.data.get(DOMAIN, {}).get(_DATA_MANAGER)

    @staticmethod
    async def _close_peer(peer: KdePeer) -> None:
        """Close a throwaway peer, best effort."""
        try:
            await peer.close()
        except Exception:
            _LOGGER.debug("peer shutdown failed", exc_info=True)

    async def _async_handshake(
        self, host: str, port: int, device_id: str | None = None, device_name: str | None = None
    ) -> bool:
        """UDP identity probe (if device id not known), then TCP/TLS handshake.

        Returns True on success. peer.py requires the deviceId before the TCP
        connect (v8 connection packet selects the target device), so the UDP
        probe is mandatory when the id is unknown; it also tells us the
        device's TCP port.
        """
        manager = self._manager()
        if manager is None:
            # Config flow may start before async_setup or with a first entry.
            # Load the component so manager/discovery exist for the probe.
            with contextlib.suppress(Exception):
                await async_setup_component(self.hass, DOMAIN, {})
            manager = self._manager()
        if manager is None:
            _LOGGER.info("KDE Connect manager is not loaded")
            return False
        identity = getattr(manager, "identity", None)
        if identity is None and hasattr(manager, "async_ensure_local_identity"):
            await manager.async_ensure_local_identity()
            identity = getattr(manager, "identity", None)
        if identity is None:
            _LOGGER.info("KDE Connect local identity is not ready")
            return False

        if device_id is None:
            discovery = getattr(manager, "discovery", None)
            if discovery is not None:
                probe = await discovery.async_probe(host, timeout=HANDSHAKE_TIMEOUT)
            else:
                probe = None
                _LOGGER.info("KDE Connect discovery is not loaded; trying TCP handshake")
            if probe and probe.get("device_id") and valid_device_id(str(probe["device_id"])):
                device_id = str(probe["device_id"])
                if probe.get("device_name"):
                    device_name = str(probe["device_name"])
                try:
                    probe_port = int(probe.get("tcp_port") or UDP_PORT)
                except (TypeError, ValueError):
                    probe_port = UDP_PORT
                # The probe announces the device's live TCP port; a user-entered
                # port other than the default wins over the announced one.
                if port == UDP_PORT and probe_port != UDP_PORT:
                    port = probe_port
            elif device_id is None:
                _LOGGER.info(
                    "KDE Connect UDP probe to %s got no identity; trying TCP handshake",
                    host,
                )

        peer = KdePeer(
            self.hass,
            identity=identity,
            peer_device_id=device_id,
            peer_device_name=device_name,
            peer_device_type=self._device_type,
            peer_cert_pem=self._peer_cert,
            peer_capabilities=self._capabilities or None,
            host=host,
            tcp_port=port,
        )
        try:
            await peer.connect(host, port)
        except (ProtocolError, OSError, TimeoutError) as err:
            _LOGGER.info("KDE Connect handshake to %s:%s failed: %s", host, port, err)
            await self._close_peer(peer)
            self._peer = None
            return False

        self._peer = peer
        self._host = host
        self._tcp_port = port
        self._device_id = peer.device_id
        self._device_name = peer.device_name or device_name
        self._device_type = peer.device_type or self._device_type
        self._peer_cert = peer.peer_cert_pem
        self._capabilities = sorted(peer.capabilities)
        return True

    async def _async_abort_progress_for_device(self, device_id: str) -> None:
        """Abort other in-progress flows for the same device."""
        try:
            flows = self.hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        except AttributeError:
            flows = [
                f
                for f in self.hass.config_entries.flow.async_progress()
                if f.get("handler") == DOMAIN
            ]
        for flow in flows:
            if flow.get("flow_id") == self.flow_id:
                continue
            if flow.get("context", {}).get("unique_id") == device_id:
                self.hass.config_entries.flow.async_abort(flow["flow_id"])

    async def _async_set_unique_id_or_close(self) -> None:
        """Register the deviceId as unique id; close the peer on abort."""
        try:
            if self._device_id:
                await self._async_abort_progress_for_device(self._device_id)
            await self.async_set_unique_id(self._device_id)
        except AbortFlow:
            if self._peer is not None:
                await self._close_peer(self._peer)
                self._peer = None
            raise

    async def _async_finish_or_pair(self) -> ConfigFlowResult:
        """Store unique id; if already paired create entry else pair step."""
        if not self._device_id or self._peer is None:
            return self.async_abort(reason="cannot_connect")
        try:
            await self._async_set_unique_id_or_close()
            self._abort_if_unique_id_configured(
                updates={CONF_HOST: self._host, CONF_TCP_PORT: self._tcp_port}
            )
        except AbortFlow:
            if self._peer is not None:
                await self._close_peer(self._peer)
                self._peer = None
            raise
        # Abort duplicate in-progress discovery flows for the same device so
        # a manual/user flow is not rejected as "already in progress".
        await self._async_abort_progress_for_device(self._device_id)
        if self._peer.paired:
            return await self._async_create_entry()
        return await self.async_step_pair()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manual setup: scan the local /24 (once) or enter host manually."""
        manager = self._manager()
        if manager is None:
            with contextlib.suppress(Exception):
                await async_setup_component(self.hass, DOMAIN, {})
            manager = self._manager()
        if manager is None:
            return self.async_abort(reason="cannot_connect")

        errors: dict[str, str] = {}
        description_placeholders: dict[str, str] = {}
        discovery = getattr(manager, "discovery", None)
        found = getattr(self, "_scan_results", None)
        if found is None:
            self._scan_results = []
            found = self._scan_results

        if user_input is not None:
            action = str(user_input.get("action") or "manual")
            if action == "scan":
                if discovery is None:
                    errors["base"] = "cannot_connect"
                else:
                    found.clear()
                    try:
                        results = await discovery.async_probe_subnet(timeout=3.0)
                    except Exception:
                        _LOGGER.exception("KDE Connect subnet scan failed")
                        results = []
                    # dedupe by device_id
                    seen: set[str] = set()
                    for r in results:
                        did = str(r.get("device_id") or "")
                        if not did or did in seen:
                            continue
                        seen.add(did)
                        found.append(r)
                    if not found:
                        errors["base"] = "no_devices_found"
                    else:
                        description_placeholders["found"] = "\n".join(
                            f"- {r.get('device_name') or '(unnamed)'} ({r.get('device_id')}) @ {r.get('host')}:{r.get('tcp_port')}"
                            for r in found
                        )
            elif action == "manual":
                host = str(user_input.get("host") or "").strip()
                port = int(user_input.get("tcp_port") or UDP_PORT)
                if not host:
                    errors["host"] = "cannot_connect"
                elif not MIN_TCP_PORT <= port <= MAX_TCP_PORT:
                    errors["tcp_port"] = "invalid_port"
                else:
                    if not await self._async_handshake(host, port):
                        errors["host"] = "cannot_connect"
                    else:
                        return await self._async_finish_or_pair()
            elif action == "select":
                selected = str(user_input.get("device") or "")
                match = next((r for r in found if r.get("device_id") == selected), None)
                if not match:
                    errors["device"] = "cannot_connect"
                else:
                    host = str(match.get("host") or "")
                    port = int(match.get("tcp_port") or UDP_PORT)
                    device_name = str(match.get("device_name") or "") or None
                    device_id = str(match.get("device_id") or "") or None
                    if not await self._async_handshake(host, port, device_id, device_name):
                        errors["base"] = "cannot_connect"
                    else:
                        return await self._async_finish_or_pair()

        if found:
            device_options = [
                f"{r.get('device_name') or '(unnamed)'} @ {r.get('host')} — {r.get('device_id')}"
                for r in found
            ]
            # store mapping separately
            self._scan_device_ids = [str(r.get("device_id")) for r in found]
            schema = vol.Schema(
                {
                    vol.Required("action", default="select"): vol.In(
                        {"select": "Use a discovered device", "scan": "Scan again", "manual": "Enter host manually"}
                    ),
                    vol.Optional("device"): vol.In(dict(zip(self._scan_device_ids, device_options))),
                    vol.Optional(CONF_HOST): str,
                    vol.Optional(CONF_TCP_PORT, default=UDP_PORT): int,
                }
            )
            description_placeholders["found"] = "\n".join(
                f"- {r.get('device_name') or '(unnamed)'} ({r.get('device_id')}) @ {r.get('host')}:{r.get('tcp_port')}"
                for r in found
            )
        else:
            schema = vol.Schema(
                {
                    vol.Required("action", default="scan"): vol.In(
                        {"scan": "Scan local network (one-time)", "manual": "Enter host manually"}
                    ),
                    vol.Optional(CONF_HOST): str,
                    vol.Optional(CONF_TCP_PORT, default=UDP_PORT): int,
                }
            )
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders=description_placeholders,
        )

    async def async_step_discovery(
        self, discovery_info: dict[str, Any]
    ) -> ConfigFlowResult:
        """Handle a device discovered via UDP (informational only).

        We never auto-start flows from background sweeps; discovery events are
        shown to the user in the manual scan step instead.
        """
        return self.async_abort(reason="not_implemented")

    async def async_step_pair(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pairing step: send the request only on explicit user action."""
        if self._peer is None:
            return self.async_abort(reason="cannot_connect")

        if self._peer.paired:
            return await self._async_create_entry()

        if user_input is None:
            return self.async_show_form(step_id="pair", data_schema=_RETRY_SCHEMA)

        if not user_input.get("retry_again", True):
            await self._close_peer(self._peer)
            self._peer = None
            return self.async_abort(reason="pairing_cancelled")

        try:
            paired = await self._peer.request_pair()
        except ProtocolError as err:
            _LOGGER.debug("KDE Connect pair request failed: %s", err)
            await self._close_peer(self._peer)
            self._peer = None
            return self.async_show_form(
                step_id="pair", data_schema=_RETRY_SCHEMA, errors={"base": "cannot_connect"}
            )

        if paired:
            return await self._async_create_entry()
        return self.async_show_form(
            step_id="pair", data_schema=_RETRY_SCHEMA, errors={"base": "pairing_timeout"}
        )

    async def _async_create_entry(self) -> ConfigFlowResult:
        """Persist the paired peer identity and finish the flow."""
        peer = self._peer
        if peer is None:
            return self.async_abort(reason="cannot_connect")

        device_id = self._device_id or peer.device_id
        if not device_id:
            return self.async_abort(reason="cannot_connect")

        capabilities = sorted(peer.capabilities) or self._capabilities

        manager = self._manager()
        inbound_port = getattr(manager, "inbound_port", None) or UDP_PORT

        data: dict[str, Any] = {
            CONF_HOST: self._host,
            CONF_TCP_PORT: self._tcp_port,
            CONF_DEVICE_ID: device_id,
            CONF_DEVICE_NAME: peer.device_name or self._device_name or device_id,
            CONF_DEVICE_TYPE: peer.device_type or self._device_type or "",
            CONF_PEER_CERT: peer.peer_cert_pem or self._peer_cert,
            CONF_CAPABILITIES: capabilities,
            CONF_INBOUND_PORT: inbound_port,
            CONF_ANNOUNCE: True,
        }

        await self._close_peer(peer)
        self._peer = None
        return self.async_create_entry(title=data[CONF_DEVICE_NAME], data=data)

    @classmethod
    def async_get_options_flow(cls, config_entry: ConfigEntry) -> OptionsFlow:
        """Options flow: default SMS recipients."""
        return KdeConnectOptionsFlow(config_entry)


class KdeConnectOptionsFlow(OptionsFlow):
    """Manage default SMS recipients per config entry."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Save entry for the options step."""
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage options: SMS defaults and local run-commands."""
        errors: dict[str, str] = {}
        if user_input is not None:
            targets = user_input.get("sms_targets") or []
            if isinstance(targets, str):
                targets = [targets]
            commands = user_input.get(CONF_LOCAL_COMMANDS) or []
            if isinstance(commands, str):
                commands = [commands]
            commands = [str(line) for line in commands if str(line).strip()]
            return self.async_create_entry(
                title="",
                data={
                    "sms_targets": [str(t) for t in targets],
                    CONF_ALLOW_REMOTE_COMMANDS: bool(
                        user_input.get(CONF_ALLOW_REMOTE_COMMANDS, False)
                    ),
                    CONF_LOCAL_COMMANDS: commands,
                },
            )

        options = self._config_entry.options
        current_targets = options.get("sms_targets", [])
        current_commands = options.get(CONF_LOCAL_COMMANDS, [])
        if isinstance(current_commands, str):
            current_commands = [current_commands]
        schema = {
            vol.Optional("sms_targets", default=current_targets): TextSelector(
                TextSelectorConfig(multiple=True, multiline=True)
            ),
            vol.Optional(CONF_ALLOW_REMOTE_COMMANDS, default=bool(options.get(CONF_ALLOW_REMOTE_COMMANDS, False))): bool,
            vol.Optional(CONF_LOCAL_COMMANDS, default=current_commands): TextSelector(
                TextSelectorConfig(multiple=True, multiline=True)
            ),
        }
        return self.async_show_form(step_id="init", data_schema=vol.Schema(schema), errors=errors)
