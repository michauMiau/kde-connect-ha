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

from .const import (
    CONF_ANNOUNCE,
    CONF_CAPABILITIES,
    CONF_DEVICE_ID,
    CONF_DEVICE_NAME,
    CONF_DEVICE_TYPE,
    CONF_HOST,
    CONF_INBOUND_PORT,
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
            return False
        identity = getattr(manager, "identity", None)
        if identity is None:
            _LOGGER.debug("KDE Connect local identity is not ready")
            return False

        if device_id is None:
            discovery = getattr(manager, "discovery", None)
            if discovery is None:
                return False
            probe = await discovery.async_probe(host, timeout=HANDSHAKE_TIMEOUT)
            if probe is None or not probe.get("device_id"):
                _LOGGER.debug("KDE Connect UDP probe to %s got no identity", host)
                return False
            device_id = str(probe["device_id"])
            if not valid_device_id(device_id):
                _LOGGER.debug("Peer advertised invalid deviceId %r", device_id)
                return False
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
        except ProtocolError as err:
            _LOGGER.debug("KDE Connect handshake to %s:%s failed: %s", host, port, err)
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

    async def _async_set_unique_id_or_close(self) -> None:
        """Register the deviceId as unique id; close the peer on abort."""
        try:
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
        if not self._peer.paired:
            try:
                await self._peer.request_pair()
            except ProtocolError:
                _LOGGER.debug("KDE Connect pairing request failed", exc_info=True)
        if self._peer.paired:
            return await self._async_create_entry()
        return await self.async_step_pair()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask host (+ optional TCP port), then handshake."""
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=_USER_SCHEMA)

        host = str(user_input[CONF_HOST]).strip()
        port = int(user_input.get(CONF_TCP_PORT) or UDP_PORT)
        if not MIN_TCP_PORT <= port <= MAX_TCP_PORT:
            return self.async_show_form(
                step_id="user",
                data_schema=_USER_SCHEMA,
                errors={CONF_TCP_PORT: "invalid_port"},
            )

        if not await self._async_handshake(host, port):
            return self.async_show_form(
                step_id="user",
                data_schema=_USER_SCHEMA,
                errors={CONF_HOST: "cannot_connect"},
            )
        return await self._async_finish_or_pair()

    async def async_step_discovery(
        self, discovery_info: dict[str, Any]
    ) -> ConfigFlowResult:
        """Handle a device found by the UDP discovery listener (discovery.py).

        discovery.py hands us its event payload keys: device_id, host,
        device_name, tcp_port, protocol_version.
        """
        device_id = str(discovery_info.get(CONF_DEVICE_ID) or "")
        host = str(discovery_info.get(CONF_HOST) or "")
        if not device_id or not host or not valid_device_id(device_id):
            return self.async_abort(reason="cannot_connect")

        self._device_id = device_id
        self._host = host
        try:
            self._tcp_port = int(discovery_info.get(CONF_TCP_PORT) or UDP_PORT)
        except (TypeError, ValueError):
            self._tcp_port = UDP_PORT
        self._device_name = str(discovery_info.get(CONF_DEVICE_NAME) or "") or None

        try:
            await self.async_set_unique_id(device_id)
            self._abort_if_unique_id_configured(
                updates={CONF_HOST: host, CONF_TCP_PORT: self._tcp_port}
            )
        except AbortFlow:
            if self._peer is not None:
                await self._close_peer(self._peer)
                self._peer = None
            raise

        if not await self._async_handshake(host, self._tcp_port, device_id, self._device_name):
            return self.async_abort(reason="cannot_connect")
        return await self._async_finish_or_pair()

    async def async_step_pair(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pairing step: send the request, wait for the device-side prompt."""
        if self._peer is None:
            return self.async_abort(reason="cannot_connect")

        if user_input is not None:
            if not user_input.get("retry_again", True):
                await self._close_peer(self._peer)
                self._peer = None
                return self.async_abort(reason="pairing_cancelled")

        if self._peer.paired:
            return await self._async_create_entry()

        # request_pair() waits PAIRING_TIMEOUT internally; the device shows a
        # prompt on its side and answers the pair packet.
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
        """Manage options."""
        if user_input is not None:
            targets = user_input.get("sms_targets") or []
            if isinstance(targets, str):
                targets = [targets]
            return self.async_create_entry(
                title="", data={"sms_targets": [str(t) for t in targets]}
            )

        current = self._config_entry.options.get("sms_targets", [])
        schema = {
            vol.Optional("sms_targets", default=current): TextSelector(
                # HA 2026.2: free_selection was removed from the text selector;
                # multiple + multiline render a repeatable text input list.
                TextSelectorConfig(multiple=True, multiline=True)
            )
        }
        return self.async_show_form(step_id="init", data_schema=vol.Schema(schema))
