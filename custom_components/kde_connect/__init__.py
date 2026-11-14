"""The KDE Connect integration.

Owns a singleton manager (``hass.data[DOMAIN]["manager"]``) holding one
:class:`KdePeer` (peer.py, protocol v8 TLS sessions) per config entry, plus
the UDP discovery service (discovery.py) and the shared inbound TCP server.
Reconnection and pairing-repair bookkeeping live here — peer.py keeps no
reconnect logic by design.

Entity runtime layout (consumed by sensor.py / binary_sensor.py /
device_tracker.py and notify.py):

``hass.data[DOMAIN][entry.entry_id] = {"peers": {device_id: peer}, "states":
{device_id: DeviceState}}``

Values in ``peers`` are ``_PeerAdapter`` wrappers: they delegate the entity
duck type (device_id/device_name/connected/paired/capabilities) to the real
KdePeer and add ``send_packet()`` compatibility used by notify.py.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ConfigEntryNotReady, ServiceValidationError
from homeassistant.helpers import (
    config_validation as cv,
)
from homeassistant.helpers import (
    device_registry as dr,
)
from homeassistant.helpers import (
    entity_registry as er,
)
from homeassistant.helpers import (
    issue_registry as ir,
)
from homeassistant.helpers.storage import Store

from . import protocol
from .const import (
    CONF_CAPABILITIES,
    CONF_DEVICE_ID,
    CONF_DEVICE_NAME,
    CONF_DEVICE_TYPE,
    CONF_HOST,
    CONF_INBOUND_PORT,
    CONF_PEER_CERT,
    CONF_TCP_PORT,
    DOMAIN,
    EVENT_DEVICE_DISCOVERED,
    EVENT_PAIR_CHANGED,
    MAX_TCP_PORT,
    MIN_TCP_PORT,
    PACKET_TYPE_NOTIFICATION,
    PACKET_TYPE_SMS_REQUEST,
    PLATFORMS,
    RECONNECT_MAX_DELAY,
    RECONNECT_MIN_DELAY,
    SERVICE_CANCEL_NOTIFICATION,
    SERVICE_FIND_MY_PHONE,
    SERVICE_NOTIFICATION_REPLY,
    SERVICE_REQUEST_NOTIFICATIONS,
    SERVICE_RUN_COMMAND,
    SERVICE_SEND_NOTIFICATION,
    SERVICE_SEND_SMS,
    UDP_PORT,
)
from .discovery import KdeConnectDiscovery
from .notify import APP_NAME
from .peer import KdePeer

_LOGGER = logging.getLogger(__name__)

DATA_MANAGER = "manager"
DATA_DISCOVERY = "discovery"

STORAGE_VERSION = 1
STORAGE_KEY = "kde_connect.local_identity"

LOCAL_DEVICE_TYPE = "desktop"
LOCAL_DEVICE_NAME = "Home Assistant"

# Integration is config-entry only; YAML config is not supported (hassfest
# requires this schema since async_setup is implemented).
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

# Service name -> wire capability string that must be present in
# peer.capabilities (the peer's incoming packet-type names) to allow the call.
SERVICE_CAPABILITIES: dict[str, str] = {
    SERVICE_SEND_SMS: protocol.CAPABILITY_SMS,
    SERVICE_SEND_NOTIFICATION: protocol.CAPABILITY_NOTIFICATION,
    SERVICE_REQUEST_NOTIFICATIONS: protocol.CAPABILITY_NOTIFICATION,
    SERVICE_CANCEL_NOTIFICATION: protocol.CAPABILITY_NOTIFICATION,
    SERVICE_NOTIFICATION_REPLY: protocol.CAPABILITY_NOTIFICATION,
    SERVICE_FIND_MY_PHONE: protocol.CAPABILITY_FIND_MY_PHONE,
    SERVICE_RUN_COMMAND: protocol.CAPABILITY_RUNCOMMAND,
}


def _target_list(call: ServiceCall, key: str) -> list[str]:
    raw = call.data.get(key)
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple)):
        return [str(item) for item in raw]
    return []


def _schema(fields: dict[Any, Any]) -> vol.Schema:
    """Build a service schema: device/entity target plus optional device id."""
    fields[vol.Optional("target")] = vol.Any(list, str, None)
    fields[vol.Optional("device")] = vol.Any(list, str, None)
    fields[vol.Optional("entity_id")] = vol.Any(list, str, None)
    fields[vol.Optional(CONF_DEVICE_ID)] = vol.Any(str, None)
    return vol.Schema(fields)


class _FirstLineReader:
    """asyncio.StreamReader shim that replays an already-consumed first line.

    The inbound dispatch in :meth:`KdeConnectManager._handle_inbound` consumes
    the identity line before routing, so ``KdePeer.serve`` needs to see it
    again; ``read_packet`` only calls ``readline()``.
    """

    def __init__(self, reader: asyncio.StreamReader, first_line: bytes) -> None:
        self._reader = reader
        self._first_line = first_line

    async def readline(self) -> bytes:
        if self._first_line is not None:
            line = self._first_line
            self._first_line = None
            return line
        return await self._reader.readline()


class _PeerAdapter:
    """Entity-facing duck type for notify.py: delegates to KdePeer, adds send_packet.

    notify.py's entities call ``await peer.send_packet(packet_type, body)``;
    KdePeer exposes typed service methods instead (send_notification,
    send_sms, ...), so this adapter maps the two notification/SMS wire
    packet types notify.py uses onto those methods and forwards everything
    else (device_id, device_name, capabilities, connected, paired, ...)
    through ``__getattr__``.
    """

    def __init__(self, peer: KdePeer) -> None:
        self.__dict__["_peer"] = peer

    async def send_packet(self, packet_type: str, body: dict[str, Any]) -> None:
        peer = self._peer
        if packet_type == PACKET_TYPE_NOTIFICATION:
            await peer.send_notification(
                str(body.get("title") or ""),
                str(body.get("content") or ""),
                notification_id=body.get("id") or body.get("notificationId"),
                reply_id=body.get("replyId"),
                app_name=str(body.get("appName") or APP_NAME),
            )
        elif packet_type == PACKET_TYPE_SMS_REQUEST:
            addresses = body.get("addresses") or []
            phone = str(
                body.get("phoneNumber")
                or (
                    addresses[0].get("address")
                    if addresses and isinstance(addresses[0], dict)
                    else ""
                )
                or ""
            )
            message = str(body.get("messageBody") or body.get("message") or "")
            await peer.send_sms(phone, message)
        else:
            raise protocol.ProtocolError(f"unsupported notify packet type {packet_type!r}")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__dict__["_peer"], name)


class KdeConnectManager:
    """Singleton holding one peer per config entry, plus discovery and inbound."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the manager."""
        self.hass = hass
        self.identity: protocol.LocalIdentity | None = None
        self.discovery: KdeConnectDiscovery | None = None
        self.inbound_port: int | None = None
        self.peers: dict[str, KdePeer] = {}
        self.device_entries: dict[str, str] = {}  # device_id -> entry_id
        self._reconnect: dict[str, asyncio.Task[None]] = {}
        self._server: asyncio.Server | None = None
        self._stopped = False

    # ------------------------------------------------------------- duck type
    # Attributes read by discovery.py (KdeConnectDiscovery).
    @property
    def local_device_id(self) -> str | None:
        """Return the local device id, or None before identity is stored."""
        return self.identity.device_id if self.identity else None

    @property
    def local_device_name(self) -> str:
        """Return the local device name used in discovery packets."""
        return self.identity.device_name if self.identity else LOCAL_DEVICE_NAME

    async def start(self) -> None:
        """Set up local identity, inbound port and inbound server, once."""
        if self._stopped:
            return
        await self._ensure_local_identity()
        if self.inbound_port is None:
            self.inbound_port = self._pick_inbound_port()
        if self._server is None:
            try:
                self._server = await asyncio.start_server(
                    self._handle_inbound, "0.0.0.0", self.inbound_port
                )
            except OSError:
                _LOGGER.warning(
                    "KDE Connect inbound server on port %s could not start",
                    self.inbound_port,
                    exc_info=True,
                )

    async def stop(self) -> None:
        """Shut down reconnect loops, peers and the inbound server."""
        self._stopped = True
        for task in self._reconnect.values():
            task.cancel()
        self._reconnect.clear()
        for peer in list(self.peers.values()):
            await self._shutdown_peer(peer)
        self.peers.clear()
        self.device_entries.clear()
        if self._server is not None:
            server, self._server = self._server, None
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                _LOGGER.debug("inbound server shutdown failed", exc_info=True)

    async def setup_entry(self, entry: ConfigEntry) -> None:
        """Create and connect the peer for an entry."""
        device_id = entry.data.get(CONF_DEVICE_ID)
        if not device_id or not protocol.valid_device_id(str(device_id)):
            raise ConfigEntryNotReady("Config entry is missing a valid device id")

        if self.identity is None:
            await self._ensure_local_identity()

        peer = self._build_peer(entry)
        try:
            await peer.connect()
        except protocol.ProtocolError as exc:
            await self._shutdown_peer(peer)
            raise ConfigEntryNotReady(
                f"Could not connect to KDE Connect device {device_id}: {exc}"
            ) from exc

        self.peers[str(device_id)] = peer
        self.device_entries[str(device_id)] = entry.entry_id
        self.hass.data[DOMAIN][entry.entry_id] = {
            "peers": {str(device_id): _PeerAdapter(peer)},
            "states": {str(device_id): peer.state},
        }
        self._persist_identity(entry, peer)
        self._reconnect[entry.entry_id] = self.hass.async_create_background_task(
            self._async_reconnect_loop(entry.entry_id, peer),
            f"kde_connect_reconnect_{device_id}",
            eager_start=True,
        )
        self._sync_pairing_issue(str(device_id))

    async def remove_entry(self, entry: ConfigEntry) -> None:
        """Drop the peer belonging to an entry."""
        device_id = entry.data.get(CONF_DEVICE_ID)
        if not device_id:
            return
        task = self._reconnect.pop(entry.entry_id, None)
        if task is not None:
            task.cancel()
        peer = self.peers.pop(str(device_id), None)
        self.device_entries.pop(str(device_id), None)
        self.hass.data[DOMAIN].pop(entry.entry_id, None)
        self._clear_pairing_issue(str(device_id))
        if peer is not None:
            await self._shutdown_peer(peer)

    def _build_peer(self, entry: ConfigEntry) -> KdePeer:
        """Instantiate KdePeer for an entry (verified peer.py signature)."""
        assert self.identity is not None
        return KdePeer(
            self.hass,
            identity=self.identity,
            peer_device_id=str(entry.data[CONF_DEVICE_ID]),
            peer_device_name=entry.data.get(CONF_DEVICE_NAME),
            peer_device_type=entry.data.get(CONF_DEVICE_TYPE),
            peer_cert_pem=entry.data.get(CONF_PEER_CERT),
            peer_capabilities=entry.data.get(CONF_CAPABILITIES) or None,
            host=entry.data.get(CONF_HOST),
            tcp_port=entry.data.get(CONF_TCP_PORT, UDP_PORT),
            inbound_port=entry.data.get(CONF_INBOUND_PORT, self.inbound_port),
        )

    @staticmethod
    async def _shutdown_peer(peer: KdePeer) -> None:
        try:
            await peer.close()
        except Exception:
            _LOGGER.debug("KDE Connect peer shutdown failed", exc_info=True)

    async def async_ensure_local_identity(self) -> None:
        """Generate the local identity for announce broadcasts right at setup.

        Without peers configured yet, discovery still needs a stable deviceId to
        broadcast. The identity is generated once and persisted across reloads.
        """
        await self._ensure_local_identity()

    async def _ensure_local_identity(self) -> None:
        """Load or generate our stable local identity (device id + cert)."""
        if self.identity is not None:
            return
        store = Store(self.hass, STORAGE_VERSION, STORAGE_KEY, private=True)
        data = await store.async_load()
        if (
            isinstance(data, dict)
            and data.get("device_id")
            and data.get("cert_pem")
            and data.get("key_pem")
        ):
            try:
                self.identity = protocol.LocalIdentity.from_config_dict(data)
            except KeyError:
                _LOGGER.debug("stored KDE Connect identity incomplete; regenerating")
            else:
                return

        self.identity = protocol.create_local_identity(
            LOCAL_DEVICE_NAME, device_type=LOCAL_DEVICE_TYPE
        )
        await store.async_save(self.identity.to_config_dict())

    @staticmethod
    def _pick_inbound_port() -> int:
        """First free TCP port in the KDE Connect port range."""
        for port in range(MIN_TCP_PORT, MAX_TCP_PORT + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.bind(("0.0.0.0", port))
                except OSError:
                    continue
                return port
        _LOGGER.warning(
            "No free KDE Connect inbound port in %s-%s; using %s",
            MIN_TCP_PORT,
            MAX_TCP_PORT,
            UDP_PORT,
        )
        return UDP_PORT

    # ---------------------------------------------------------------- inbound
    async def _handle_inbound(self, reader, writer) -> None:
        """Route an inbound TCP identity session to the matching peer.

        The peer's plaintext connection packet carries its ``deviceId`` plus
        ``targetDeviceId``; we consume it here (peer.py's ``serve()`` would
        read it itself) and replay it via ``_FirstLineReader``.
        """
        line = await reader.readline()
        if not line:
            await self._close_writer(writer)
            return
        try:
            packet = protocol.decode_packet(line)
        except protocol.ProtocolError:
            _LOGGER.debug("malformed inbound identity packet: %r", line[:120])
            await self._close_writer(writer)
            return
        if packet.get("type") != "kdeconnect.identity":
            await self._close_writer(writer)
            return
        body = packet.get("body") or {}
        device_id = str(body.get("deviceId") or "")
        target = str(body.get("targetDeviceId") or "")
        peer = self.peers.get(device_id) or self.peers.get(target)
        if peer is None:
            host = writer.transport.get_extra_info("peername")
            peer_host = host[0] if host else None
            if (
                protocol.valid_device_id(device_id)
                and self.identity is not None
                and device_id != self.identity.device_id
            ):
                self._announce_unknown_device(device_id, peer_host, body)
            await self._close_writer(writer)
            return
        try:
            await peer.serve(_FirstLineReader(reader, line), writer, self.inbound_port)
        except protocol.ProtocolError as err:
            _LOGGER.debug("inbound session with %s refused: %s", peer.device_id, err)
            await self._close_writer(writer)
        except Exception:
            _LOGGER.warning("Inbound session with %s failed", peer.device_id, exc_info=True)
            await self._close_writer(writer)

    @staticmethod
    async def _close_writer(writer) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            _LOGGER.debug("inbound writer shutdown failed", exc_info=True)

    def _announce_unknown_device(
        self, device_id: str, host: str | None, body: dict[str, Any]
    ) -> None:
        """A TCP identity from an unconfigured device: announce + discovery flow."""
        try:
            tcp_port = int(body.get("tcpPort") or UDP_PORT)
        except (TypeError, ValueError):
            tcp_port = UDP_PORT
        data = {
            "device_id": device_id,
            "host": host,
            "device_name": str(body.get("deviceName") or ""),
            "tcp_port": tcp_port,
            "protocol_version": int(body.get("protocolVersion") or protocol.PROTOCOL_VERSION),
        }
        self.hass.bus.async_fire(EVENT_DEVICE_DISCOVERED, data)
        if not host:
            return
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            if entry.unique_id == device_id or entry.data.get(CONF_DEVICE_ID) == device_id:
                return
        try:
            flows = self.hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        except AttributeError:
            flows = [
                f
                for f in self.hass.config_entries.flow.async_progress()
                if f.get("handler") == DOMAIN
            ]
        if any(f.get("context", {}).get("unique_id") == device_id for f in flows):
            return
        try:
            self.hass.async_create_background_task(
                self.hass.config_entries.flow.async_init(
                    DOMAIN,
                    context={"source": "discovery", "unique_id": device_id},
                    data=data,
                ),
                f"kde_connect_discovery_{device_id}",
                eager_start=True,
            )
        except Exception:
            _LOGGER.debug("KDE Connect discovery flow init failed", exc_info=True)

    # -------------------------------------------------------------- reconnect
    async def _async_reconnect_loop(self, entry_id: str, peer: KdePeer) -> None:
        """Reconnect a lost peer session with exponential backoff.

        peer.py flips ``connected`` and calls ``state.notify_changed()`` when a
        session drops; the listener wakes us immediately instead of polling.
        """
        wake = asyncio.Event()
        wake.set()

        def _watch() -> None:
            if not peer.connected:
                wake.set()

        peer.state.add_listener(_watch)
        delay = RECONNECT_MIN_DELAY
        while not self._stopped and entry_id in self.device_entries:
            if peer.connected:
                delay = RECONNECT_MIN_DELAY
                entry = self.hass.config_entries.async_get_entry(entry_id)
                if entry is not None:
                    self._persist_identity(entry, peer)
                self._sync_pairing_issue(peer.device_id)
                wake.clear()
                await wake.wait()
                continue
            await asyncio.sleep(delay)
            if peer.connected or self._stopped or entry_id not in self.device_entries:
                continue
            try:
                await peer.connect()
            except protocol.ProtocolError:
                _LOGGER.debug("KDE Connect reconnect to %s failed", peer.device_id)
                delay = min(delay * 2, RECONNECT_MAX_DELAY)
                self._sync_pairing_issue(peer.device_id)
                continue
            delay = RECONNECT_MIN_DELAY

    @callback
    def _on_pair_changed(self, event: Event) -> None:
        """Mirror live pair state into the repairs issue registry."""
        data = event.data if isinstance(event.data, dict) else {}
        device_id = data.get("device_id")
        if device_id:
            self._sync_pairing_issue(str(device_id))

    # ---------------------------------------------------------------- repairs
    def _sync_pairing_issue(self, device_id: str) -> None:
        entry_id = self.device_entries.get(device_id)
        if entry_id is None:
            return
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if entry is None:
            return
        peer = self.peers.get(device_id)
        if peer is not None and peer.paired:
            self._clear_pairing_issue(device_id)
            return
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            f"pairing_pending_{device_id}",
            is_fixable=False,
            is_persistent=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="pairing_pending",
            translation_placeholders={
                "device_name": entry.data.get(CONF_DEVICE_NAME, entry.title)
            },
            data={"device_id": device_id},
        )

    def _clear_pairing_issue(self, device_id: str) -> None:
        ir.async_delete_issue(self.hass, DOMAIN, f"pairing_pending_{device_id}")

    # ------------------------------------------------- post-handshake updates
    def _persist_identity(self, entry: ConfigEntry, peer: KdePeer) -> None:
        """Persist TOFU cert / identity changes discovered during a handshake."""
        updates: dict[str, Any] = {}
        if peer.peer_cert_pem and entry.data.get(CONF_PEER_CERT) != peer.peer_cert_pem:
            updates[CONF_PEER_CERT] = peer.peer_cert_pem
        if entry.data.get(CONF_DEVICE_NAME) != peer.device_name:
            updates[CONF_DEVICE_NAME] = peer.device_name
        if peer.device_type and entry.data.get(CONF_DEVICE_TYPE) != peer.device_type:
            updates[CONF_DEVICE_TYPE] = peer.device_type
        capabilities = sorted(peer.capabilities)
        if capabilities and entry.data.get(CONF_CAPABILITIES) != capabilities:
            updates[CONF_CAPABILITIES] = capabilities
        if updates:
            try:
                self.hass.config_entries.async_update_entry(
                    entry, data={**entry.data, **updates}
                )
            except Exception:
                _LOGGER.debug("could not persist KDE Connect entry updates", exc_info=True)

    def peer_for_device(self, dev_id: str) -> KdePeer | None:
        """Peer belonging to a device registry entry, if any."""
        device = dr.async_get(self.hass).async_get(dev_id)
        if device is None:
            return None
        for identifier in device.identifiers:
            if identifier[0] == DOMAIN:
                peer = self.peers.get(identifier[1])
                if peer is not None:
                    return peer
        for mapped_id, mapped_entry in self.device_entries.items():
            if mapped_entry in device.entries:
                peer = self.peers.get(mapped_id)
                if peer is not None:
                    return peer
        return None

    def peer_for_entity(self, entity_id: str) -> KdePeer | None:
        """Peer belonging to an entity registry entry, if any."""
        entity_entry = er.async_get(self.hass).async_get(entity_id)
        if entity_entry is None or entity_entry.entry_id is None:
            return None
        entry = self.hass.config_entries.async_get_entry(entity_entry.entry_id)
        if entry is None or entry.domain != DOMAIN:
            return None
        return self.peers.get(str(entry.data.get(CONF_DEVICE_ID, "")))

    # ------------------------------------------------------- service targets
    def peer_for_call(self, call: ServiceCall) -> KdePeer:
        """Resolve the targeted peer from device/entity ids in a service call."""
        for dev_id in _target_list(call, "device") + _target_list(call, "target"):
            peer = self.peer_for_device(dev_id)
            if peer is not None:
                return peer

        for entity_id in _target_list(call, "entity_id"):
            peer = self.peer_for_entity(entity_id)
            if peer is not None:
                return peer

        for device_id in _target_list(call, CONF_DEVICE_ID):
            peer = self.peers.get(device_id)
            if peer is not None:
                return peer

        if len(self.peers) == 1 and not _target_list(call, "device"):
            return next(iter(self.peers.values()))

        raise ServiceValidationError(
            "No paired KDE Connect device targeted for this service call"
        )

    def sms_targets(self, peer: KdePeer, call: ServiceCall) -> list[str]:
        """SMS recipients: explicit phone_number, else entry options sms_targets."""
        phone = call.data.get("phone_number")
        if phone:
            return [str(phone)]
        entry_id = self.device_entries.get(peer.device_id)
        entry = (
            self.hass.config_entries.async_get_entry(entry_id)
            if entry_id is not None
            else None
        )
        raw = entry.options.get("sms_targets") if entry is not None else None
        targets = raw if isinstance(raw, list) else ([raw] if raw else [])
        targets = [str(t) for t in targets if str(t)]
        if not targets:
            raise ServiceValidationError(
                "SMS recipient required: pass phone_number or configure default "
                "SMS recipients in the KDE Connect entry options"
            )
        return targets


@callback
def _require_ready(manager: KdeConnectManager, peer: KdePeer, service: str) -> None:
    """Gate a service call on connection, pairing and peer capability."""
    if not peer.connected:
        raise ServiceValidationError(
            f"KDE Connect device {peer.device_name} is not connected"
        )
    if not peer.paired:
        raise ServiceValidationError(
            f"KDE Connect pairing is not confirmed for {peer.device_name}; open "
            "the KDE Connect app on the device to accept the pairing request"
        )
    capability = SERVICE_CAPABILITIES.get(service)
    if capability is not None and capability not in peer.capabilities:
        raise ServiceValidationError(
            f"KDE Connect device {peer.device_name} does not support "
            f"'{capability}' (required for service kde_connect.{service})"
        )


async def _await_peer(coro: Any, peer: KdePeer) -> Any:
    """Run a peer method and translate wire errors into service errors."""
    try:
        return await coro
    except protocol.ProtocolError as err:
        raise ServiceValidationError(
            f"kde_connect call failed for {peer.device_name}: {err}"
        ) from err


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up the KDE Connect integration: manager, discovery, services."""
    if DOMAIN in hass.data:
        return True

    manager = KdeConnectManager(hass)
    discovery = KdeConnectDiscovery(hass, manager)
    manager.discovery = discovery
    hass.data[DOMAIN] = {DATA_MANAGER: manager, DATA_DISCOVERY: discovery}

    await manager.start()
    await manager.async_ensure_local_identity()
    await discovery.async_start()

    async def _on_ha_stop(event: Event) -> None:
        await discovery.async_stop()
        await manager.stop()

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _on_ha_stop)
    hass.bus.async_listen(EVENT_PAIR_CHANGED, manager._on_pair_changed)

    _register_services(hass, manager)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a KDE Connect peer from a config entry."""
    data = hass.data.get(DOMAIN)
    if not data or DATA_MANAGER not in data:
        raise ConfigEntryNotReady("KDE Connect integration setup has not run")
    manager: KdeConnectManager = data[DATA_MANAGER]
    await manager.setup_entry(entry)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a KDE Connect peer config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        manager: KdeConnectManager = hass.data[DOMAIN][DATA_MANAGER]
        await manager.remove_entry(entry)
    return unload_ok


@callback
def _register_services(hass: HomeAssistant, manager: KdeConnectManager) -> None:
    """Register device-targeted KDE Connect services (gated per call)."""

    async def send_sms(call: ServiceCall) -> None:
        peer = manager.peer_for_call(call)
        _require_ready(manager, peer, SERVICE_SEND_SMS)
        message = str(call.data["message"])
        for target in manager.sms_targets(peer, call):
            await _await_peer(peer.send_sms(target, message), peer)

    async def send_notification(call: ServiceCall) -> None:
        peer = manager.peer_for_call(call)
        _require_ready(manager, peer, SERVICE_SEND_NOTIFICATION)
        title = str(call.data.get("title") or APP_NAME)
        content = str(call.data["message"])
        await _await_peer(peer.send_notification(title, content, app_name=APP_NAME), peer)

    async def find_my_phone(call: ServiceCall) -> None:
        peer = manager.peer_for_call(call)
        _require_ready(manager, peer, SERVICE_FIND_MY_PHONE)
        await _await_peer(
            peer.find_my_phone(
                ring=bool(call.data.get("ring", True)),
                vibrate=bool(call.data.get("vibrate", True)),
            ),
            peer,
        )

    async def request_notifications(call: ServiceCall) -> None:
        peer = manager.peer_for_call(call)
        _require_ready(manager, peer, SERVICE_REQUEST_NOTIFICATIONS)
        await _await_peer(peer.request_notifications(), peer)

    async def cancel_notification(call: ServiceCall) -> None:
        peer = manager.peer_for_call(call)
        _require_ready(manager, peer, SERVICE_CANCEL_NOTIFICATION)
        await _await_peer(
            peer.cancel_notification(str(call.data["notification_id"])), peer
        )

    async def notification_reply(call: ServiceCall) -> None:
        peer = manager.peer_for_call(call)
        _require_ready(manager, peer, SERVICE_NOTIFICATION_REPLY)
        await _await_peer(
            peer.reply_notification(str(call.data["reply_id"]), str(call.data["message"])),
            peer,
        )

    async def run_command(call: ServiceCall) -> None:
        peer = manager.peer_for_call(call)
        _require_ready(manager, peer, SERVICE_RUN_COMMAND)
        await _await_peer(peer.run_command(str(call.data["command"])), peer)

    hass.services.async_register(
        DOMAIN,
        SERVICE_SEND_NOTIFICATION,
        send_notification,
        schema=_schema(
            {
                vol.Required("message"): str,
                vol.Optional("title"): str,
            }
        ),
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_SEND_SMS,
        send_sms,
        schema=_schema({vol.Required("message"): str, vol.Optional("phone_number"): str}),
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_FIND_MY_PHONE,
        find_my_phone,
        schema=_schema(
            {
                vol.Optional("ring", default=True): bool,
                vol.Optional("vibrate", default=True): bool,
            }
        ),
    )
    hass.services.async_register(
        DOMAIN, SERVICE_REQUEST_NOTIFICATIONS, request_notifications, schema=_schema({})
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_CANCEL_NOTIFICATION,
        cancel_notification,
        schema=_schema({vol.Required("notification_id"): str}),
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_NOTIFICATION_REPLY,
        notification_reply,
        schema=_schema(
            {vol.Required("reply_id"): str, vol.Required("message"): str}
        ),
    )
    hass.services.async_register(
        DOMAIN, SERVICE_RUN_COMMAND, run_command, schema=_schema({vol.Required("command"): str})
    )
