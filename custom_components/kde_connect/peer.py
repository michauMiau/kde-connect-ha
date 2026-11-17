"""KDE Connect peer transport — protocol version 8, TLS-only sessions.

A ``KdePeer`` owns exactly one TCP session with one remote KDE Connect
device and performs the protocol v8 handshake:

Outbound (HA connects to the peer's announced ``tcpPort``):

1. TCP connect (peer ports 1716-1764).
2. Send the *plaintext connection packet*
   ``{"type": "kdeconnect.identity", "body": {deviceId, deviceName,
   protocolVersion, targetDeviceId, targetProtocolVersion}}``.
3. Upgrade the socket to TLS (TCP client acts as TLS server).
4. Inside TLS exchange encrypted identity packets
   ``{deviceId, deviceName, deviceType, protocolVersion,
   incomingCapabilities, outgoingCapabilities}``.

Inbound (started by ``asyncio.start_server`` in ``__init__.py``):

1. Read the peer's plaintext connection packet (carries ``targetDeviceId``).
2. Upgrade TLS (TCP server acts as TLS client).
3. Exchange encrypted identity packets inside TLS.

Peer certificates are self-signed RSA/EC with ``CN == deviceId``. OpenSSL
cannot build a trust chain from a bare self-signed leaf, so trust is
enforced explicitly: certificate equality against the pinned PEM plus the
CN check — see ``protocol.client_tls_context`` / ``peer_certificate``.

Entity-facing duck type (consumed by ``entities.py``): ``device_id`` /
``device_name`` / ``device_type`` describe the *remote peer*,
``capabilities`` is the union of advertised packet types, and
``connected`` / ``paired`` drive entity availability. Push packets update
``self.state`` (``DeviceState``) and call ``notify_changed()``, so sensor
entities refresh immediately.

This module keeps no UDP discovery/announce loops and no reconnect
logic — ``__init__.py`` owns discovery, pairing UI and reconnection.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import os
import signal
import time
from datetime import UTC, datetime
from typing import Any

from homeassistant.core import HomeAssistant

from .const import (
    EVENT_COMMAND_OUTPUT,
    EVENT_NOTIFICATION_ACTION,
    EVENT_NOTIFICATION_RECEIVED,
    EVENT_NOTIFICATION_REPLY,
    EVENT_NOTIFICATION_REQUEST,
    EVENT_PAIR_CHANGED,
    EVENT_PAIR_REQUEST,
    EVENT_SMS_RECEIVED,
    HANDSHAKE_TIMEOUT,
    PACKET_TYPE_BATTERY,
    PACKET_TYPE_FIND_MY_PHONE_REQUEST,
    PACKET_TYPE_IDENTITY,
    PACKET_TYPE_MPRIS,
    PACKET_TYPE_MPRIS_REQUEST,
    PACKET_TYPE_NOTIFICATION,
    PACKET_TYPE_NOTIFICATION_ACTION,
    PACKET_TYPE_NOTIFICATION_REPLY,
    PACKET_TYPE_NOTIFICATION_REQUEST,
    PACKET_TYPE_PAIR,
    PACKET_TYPE_PING,
    PACKET_TYPE_RUNCOMMAND,
    PACKET_TYPE_RUNCOMMAND_OUTPUT,
    PACKET_TYPE_RUNCOMMAND_REQUEST,
    PACKET_TYPE_SMS_MESSAGES,
    PACKET_TYPE_SMS_REQUEST,
    PAIRING_TIMEOUT,
    PROTOCOL_VERSION,
    SMS_REQUEST_PACKET_VERSION,
    TCP_KEEPALIVE_COUNT,
    TCP_KEEPALIVE_IDLE,
    TCP_KEEPALIVE_INTERVAL,
    TCP_USER_TIMEOUT_MS,
    UDP_PORT,
)
from .entities import DeviceState
from .protocol import (
    DEFAULT_INCOMING_CAPABILITIES,
    HandshakeError,
    LocalIdentity,
    PeerIdentityMismatch,
    ProtocolError,
    apply_tcp_keepalive,
    build_packet,
    certificate_cn,
    client_tls_context,
    decode_packet,
    encode_packet,
    load_certificate,
    make_command_list_packet,
    make_command_output_packet,
    make_command_request_packet,
    make_connection_packet,
    make_encrypted_identity,
    make_find_my_phone_packet,
    make_notification_packet,
    make_notification_request_packet,
    make_pair_accept,
    make_pair_request,
    make_pair_unpair,
    make_ping_packet,
    parse_battery,
    parse_notification,
    parse_runcommand,
    parse_sms_messages,
    peer_certificate,
    read_packet,
    sanitize_device_name,
    server_tls_context,
    upgrade_tls,
    valid_device_id,
)

_LOGGER = logging.getLogger(__name__)

# KDE Core waits ~1 s for the encrypted identity packet after TLS is up.
ENCRYPTED_IDENTITY_TIMEOUT = 1.0

# Largest single framed packet line (identity payloads stay far below).
MAX_LINE_BYTES = 512 * 1024

# Payload downloads are bounded by this size (SMS/notifications included).
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024

_NOTIFICATION_KEEP = 20


def _coerce_int(value: Any) -> int | None:
    """Coerce an MPRIS numeric field, rejecting NaN/inf and bad types."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class KdePeer:
    """Live protocol v8 TLS session with a single remote peer device."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        identity: LocalIdentity,
        peer_device_id: str | None = None,
        peer_device_name: str | None = None,
        peer_device_type: str | None = None,
        peer_cert_pem: str | None = None,
        peer_capabilities: list[str] | None = None,
        host: str | None = None,
        tcp_port: int | None = None,
        incoming_capabilities: list[str] | None = None,
        allow_remote_commands: bool = False,
        local_commands: dict[str, str] | None = None,
        inbound_port: int | None = None,
        peer_paired: bool | None = None,
        auto_accept_pairing: bool = True,
    ) -> None:
        """Initialize a live session with one remote peer device."""
        self._hass = hass
        self._identity = identity
        self._device_id = peer_device_id
        self._device_name = peer_device_name or (peer_device_id or "")
        self._device_type = peer_device_type
        self._peer_cert_pem = peer_cert_pem
        self._capabilities = {str(name) for name in peer_capabilities or ()}
        self._send_capabilities: set[str] = set()
        self._receive_capabilities: set[str] = set()
        self._incoming = list(incoming_capabilities or DEFAULT_INCOMING_CAPABILITIES)
        self._allow_remote_commands = allow_remote_commands
        self._local_commands = dict(local_commands or {})
        self._inbound_port = inbound_port
        self._host = host
        self._tcp_port = tcp_port
        self._auto_accept_pairing = auto_accept_pairing

        self.state = DeviceState()
        self._command_counter = 0

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._loop_task: asyncio.Task[None] | None = None
        self._closing = False
        self._connected = False
        self._paired = bool(peer_paired)
        self._paired_known = peer_paired is not None
        self._pair_rejected = False
        self._peer_addr: str | None = None
        self._session_lock = asyncio.Lock()
        self._command_tasks: set[asyncio.Task[None]] = set()
        self._command_procs: set[asyncio.subprocess.Process] = set()

        self._pair_event = asyncio.Event()
        self._pair_probe_event = asyncio.Event()
        self._pending_pair_request: dict[str, Any] | None = None

    # ------------------------------------------------------------------ entity view

    @property
    def device_id(self) -> str:
        """Remote peer deviceId (HA device identifier / entity unique id)."""
        return self._device_id or ""

    @property
    def device_name(self) -> str:
        """Remote peer display name."""
        return self._device_name

    @property
    def device_type(self) -> str | None:
        """Remote peer deviceType, e.g. android/desktop."""
        return self._device_type

    @property
    def capabilities(self) -> set[str]:
        """Union of packet types the peer advertises (both directions)."""
        if self._send_capabilities or self._receive_capabilities:
            return self._send_capabilities | self._receive_capabilities
        return self._capabilities

    @property
    def send_capabilities(self) -> set[str]:
        """Packet types the peer can receive (HA -> peer direction)."""
        return self._send_capabilities

    @property
    def receive_capabilities(self) -> set[str]:
        """Packet types the peer can send (peer -> HA direction)."""
        return self._receive_capabilities

    @property
    def connected(self) -> bool:
        """TLS identity exchange finished and session open."""
        return self._connected

    @property
    def paired(self) -> bool:
        """Pairing established per kdeconnect.pair state."""
        return self._paired

    @property
    def peer_cert_pem(self) -> str | None:
        """Pinned (or TOFU-captured) peer certificate PEM."""
        return self._peer_cert_pem

    # ------------------------------------------------------------------ sessions

    async def connect(self, host: str | None = None, tcp_port: int | None = None) -> None:
        """Open an outbound session and complete the protocol v8 handshake."""
        host = host or self._host
        port = tcp_port or self._tcp_port or UDP_PORT
        if not host:
            raise HandshakeError("peer host is not configured")
        async with self._session_lock:
            await self._close_transport()
            self._peer_addr = host
            await self._connect_locked(host, port)

    async def _connect_locked(self, host: str, port: int) -> None:
        """Establish the outbound session (caller holds ``_session_lock``)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, limit=MAX_LINE_BYTES),
                timeout=HANDSHAKE_TIMEOUT,
            )
        except TimeoutError as err:
            raise HandshakeError(f"TCP connect to {host}:{port} timed out") from err
        except OSError as err:
            raise HandshakeError(f"TCP connect to {host}:{port} failed: {err}") from err

        self._reader = reader
        self._writer = writer
        self._closing = False
        apply_tcp_keepalive(
            writer.transport.get_extra_info("socket"),
            idle=TCP_KEEPALIVE_IDLE,
            interval=TCP_KEEPALIVE_INTERVAL,
            count=TCP_KEEPALIVE_COUNT,
            user_timeout_ms=TCP_USER_TIMEOUT_MS,
        )

        # KDE: TCP client sends plaintext connection packet, then immediately
        # starts TLS (as TLS server). No plaintext reply in between.
        await self._send(
            make_connection_packet(
                self._identity.device_id,
                self._identity.device_name,
                target_device_id=self._device_id,
            )
        )

        try:
            await upgrade_tls(
                reader,
                writer,
                await server_tls_context(
                    self._identity.cert_pem,
                    self._identity.key_pem,
                    peer_cert_pem=self._peer_cert_pem,
                ),
                HANDSHAKE_TIMEOUT,
                server_side=True,
            )
        except TimeoutError as err:
            raise HandshakeError(f"TLS handshake with {host}:{port} timed out") from err
        except OSError as err:
            raise HandshakeError(f"TLS handshake with {host}:{port} failed: {err}") from err

        self._verify_peer_certificate(writer)
        await self._send(self._encrypted_identity_packet())

        try:
            peer_identity = await read_packet(reader, timeout=ENCRYPTED_IDENTITY_TIMEOUT)
        except TimeoutError as err:
            raise HandshakeError(
                f"peer {host}:{port} did not send an encrypted identity packet"
            ) from err
        except OSError as err:
            raise HandshakeError(f"peer {host}:{port} disconnected before encrypted identity") from err
        self._consume_peer_identity(peer_identity)

        self._connected = True
        self.state.last_seen = datetime.now(UTC)
        self.state.notify_changed()
        self._loop_task = self._hass.async_create_background_task(
            self._read_loop(reader), "kde_connect_session", eager_start=True
        )
        if self._paired and PACKET_TYPE_MPRIS_REQUEST in self.send_capabilities:
            with contextlib.suppress(HandshakeError, ProtocolError, TimeoutError, OSError):
                await self.mpris_request_player_list()
        if self._paired and PACKET_TYPE_RUNCOMMAND in self.send_capabilities:
            with contextlib.suppress(HandshakeError, ProtocolError, TimeoutError, OSError):
                await self.send_command_list()
        if not self._paired_known:
            scheduler = getattr(self._hass, "async_create_task", None)
            if scheduler is not None:
                scheduler(self._detect_paired())

    async def _detect_paired(self) -> None:
        """Legacy entries: infer pairing from a paired-only probe.

        Send a ``kdeconnect.runcommand.request``; an unpaired peer answers with
        ``kdeconnect.pair {pair: false}`` (or ignores it and stays silent), a
        paired peer answers with plugin data. Mark paired only on a positive
        response, otherwise leave the peer unpaired.
        """
        if self._paired or not self._connected or self._pending_pair_request:
            return
        self._pair_probe_event.clear()
        probes: list[dict[str, Any]] = []
        if PACKET_TYPE_RUNCOMMAND_REQUEST in self.capabilities:
            probes.append(make_command_request_packet({"requestCommandList": True}))
        if PACKET_TYPE_MPRIS_REQUEST in self.send_capabilities:
            probes.append(
                build_packet(PACKET_TYPE_MPRIS_REQUEST, {"requestPlayerList": True})
            )
        if not probes:
            return
        try:
            for probe in probes:
                await self._send(probe)
        except (HandshakeError, ProtocolError, TimeoutError, OSError) as err:
            _LOGGER.debug("pairing probe to %s failed: %s", self._device_id, err)
            return
        try:
            await asyncio.wait_for(self._pair_probe_event.wait(), timeout=2.5)
        except TimeoutError:
            _LOGGER.debug(
                "KDE Connect peer %s did not confirm pairing", self._device_id
            )
            return
        if self._pair_rejected or not self._connected:
            return
        self._paired = True
        self._paired_known = True
        self.state.notify_changed()
        _LOGGER.info("KDE Connect peer %s confirmed as paired", self._device_id)
        self._fire(EVENT_PAIR_CHANGED, {"device_id": self._device_id, "paired": True})
        await self._refresh_plugin_state()

    async def _refresh_plugin_state(self) -> None:
        """Ask the peer for run-command list and MPRIS player list."""
        if not self._paired:
            return
        if PACKET_TYPE_RUNCOMMAND in self.send_capabilities:
            with contextlib.suppress(HandshakeError, ProtocolError, TimeoutError, OSError):
                await self.send_command_list()
        if PACKET_TYPE_MPRIS_REQUEST in self.send_capabilities:
            with contextlib.suppress(HandshakeError, ProtocolError, TimeoutError, OSError):
                await self.mpris_request_player_list()

    async def serve(self, reader, writer, tcp_port: int | None = None) -> None:
        """Accept an inbound session started by asyncio.start_server."""
        async with self._session_lock:
            await self._close_transport()
            peername = writer.transport.get_extra_info("peername")
            self._peer_addr = peername[0] if peername else None
            await self._serve_locked(reader, writer, tcp_port)

    async def _serve_locked(self, reader, writer, tcp_port: int | None) -> None:
        """Run the inbound handshake (caller holds ``_session_lock``)."""
        self._reader = reader
        self._writer = writer
        self._closing = False
        port = tcp_port or self._inbound_port
        if port is None:
            sockname = writer.transport.get_extra_info("sockname")
            port = sockname[1] if sockname else UDP_PORT
        apply_tcp_keepalive(
            writer.transport.get_extra_info("socket"),
            idle=TCP_KEEPALIVE_IDLE,
            interval=TCP_KEEPALIVE_INTERVAL,
            count=TCP_KEEPALIVE_COUNT,
            user_timeout_ms=TCP_USER_TIMEOUT_MS,
        )

        connection = await read_packet(reader, timeout=HANDSHAKE_TIMEOUT)
        if connection is None or connection.get("type") != PACKET_TYPE_IDENTITY:
            raise HandshakeError("inbound session did not start with an identity packet")
        body = connection.get("body") or {}
        peer_id = body.get("deviceId")
        if not valid_device_id(peer_id):
            raise PeerIdentityMismatch(f"invalid inbound deviceId: {peer_id!r}")
        if peer_id != self._device_id:
            raise PeerIdentityMismatch(f"unexpected inbound deviceId {peer_id!r}")
        target = body.get("targetDeviceId")
        if target is not None and target != self._identity.device_id:
            raise PeerIdentityMismatch(
                f"inbound targetDeviceId {target!r} does not match our deviceId"
            )
        version = body.get("protocolVersion")
        if not isinstance(version, int) or version < PROTOCOL_VERSION:
            raise HandshakeError(
                f"peer {peer_id!r} speaks protocol version {version!r}, v8 required"
            )

        # KDE: TCP server reads plaintext connection packet, then immediately
        # starts TLS (as TLS client). No plaintext reply in between.
        try:
            await upgrade_tls(
                reader,
                writer,
                await client_tls_context(
                    self._peer_cert_pem,
                    self._identity.cert_pem,
                    self._identity.key_pem,
                ),
                HANDSHAKE_TIMEOUT,
                server_side=False,
            )
        except TimeoutError as err:
            raise HandshakeError("inbound TLS handshake timed out") from err
        except OSError as err:
            raise HandshakeError(f"inbound TLS handshake failed: {err}") from err

        self._verify_peer_certificate(writer)
        await self._send(self._encrypted_identity_packet())

        try:
            peer_identity = await read_packet(reader, timeout=ENCRYPTED_IDENTITY_TIMEOUT)
        except TimeoutError as err:
            raise HandshakeError("peer did not send an encrypted identity packet") from err
        except OSError as err:
            raise HandshakeError(f"peer disconnected before encrypted identity: {err}") from err
        self._consume_peer_identity(peer_identity)

        self._connected = True
        self.state.last_seen = datetime.now(UTC)
        self.state.notify_changed()
        self._loop_task = self._hass.async_create_background_task(
            self._read_loop(reader), "kde_connect_session", eager_start=True
        )
        if self._paired and PACKET_TYPE_MPRIS_REQUEST in self.send_capabilities:
            with contextlib.suppress(HandshakeError, ProtocolError, TimeoutError, OSError):
                await self.mpris_request_player_list()
        if self._paired and PACKET_TYPE_RUNCOMMAND in self.send_capabilities:
            with contextlib.suppress(HandshakeError, ProtocolError, TimeoutError, OSError):
                await self.send_command_list()
        if not self._paired_known:
            scheduler = getattr(self._hass, "async_create_task", None)
            if scheduler is not None:
                scheduler(self._detect_paired())

    async def close(self) -> None:
        """Close the session; idempotent. Pairing state is preserved."""
        async with self._session_lock:
            await self._close_transport()

    stop = close

    async def _close_transport(self) -> None:
        """Tear down the transport and child processes (lock held)."""
        self._closing = True
        task, self._loop_task = self._loop_task, None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        writer, self._writer = self._writer, None
        self._reader = None
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError, asyncio.InvalidStateError):
                await writer.wait_closed()
        for proc in list(self._command_procs):
            self._terminate_process(proc)
        for task in list(self._command_tasks):
            if not task.done():
                task.cancel()
        if self._command_tasks:
            await asyncio.gather(*self._command_tasks, return_exceptions=True)
        self._command_tasks.clear()
        self._command_procs.clear()
        if self._connected:
            self._connected = False
            self.state.notify_changed()

    # ------------------------------------------------------------------ identity

    def _encrypted_identity_packet(self) -> dict[str, Any]:
        return make_encrypted_identity(
            device_id=self._identity.device_id,
            device_name=self._identity.device_name,
            device_type=self._identity.device_type,
            incoming_capabilities=self._incoming,
            outgoing_capabilities=self._identity.outgoing_capabilities,
        )

    def _consume_peer_identity(self, packet: dict[str, Any]) -> None:
        """Validate and absorb the peer's encrypted identity packet."""
        if packet.get("type") != PACKET_TYPE_IDENTITY:
            raise HandshakeError(f"expected identity packet, got {packet.get('type')!r}")
        body = packet.get("body") or {}
        peer_id = body.get("deviceId")
        if not isinstance(peer_id, str) or not valid_device_id(peer_id):
            raise PeerIdentityMismatch(f"invalid peer deviceId: {peer_id!r}")
        if self._device_id is None:
            self._device_id = peer_id
            if not self._device_name:
                self._device_name = peer_id
        elif peer_id != self._device_id:
            raise PeerIdentityMismatch(
                f"peer identity deviceId {peer_id!r} != expected {self._device_id!r}"
            )
        version = body.get("protocolVersion")
        if not isinstance(version, int) or version < PROTOCOL_VERSION:
            raise HandshakeError(
                f"peer {peer_id!r} identity protocolVersion {version!r}, v8 required"
            )

        name = body.get("deviceName") or self._device_id
        self._device_name = sanitize_device_name(name) or self._device_id or peer_id
        self._device_type = body.get("deviceType") or self._device_type

        outgoing = body.get("outgoingCapabilities") or []
        incoming = body.get("incomingCapabilities") or []
        if isinstance(outgoing, list):
            self._receive_capabilities = {str(item) for item in outgoing}
        if isinstance(incoming, list):
            self._send_capabilities = {str(item) for item in incoming}
        if self._send_capabilities or self._receive_capabilities:
            self._capabilities = self._send_capabilities | self._receive_capabilities

    def _verify_peer_certificate(self, writer: asyncio.StreamWriter) -> None:
        """Verify the peer certificate against the pinned/known device id.

        CN == deviceId; for trusted peers the TLS context already demands
        the pinned cert (CERT_REQUIRED against the pinned CA PEM).
        """
        captured = peer_certificate(writer, self._device_id)
        if captured is not None and self._device_id is None:
            # Learn device id from certificate CN when probing an unknown peer.
            cert = load_certificate(captured)
            cn = certificate_cn(cert)
            if cn and valid_device_id(cn):
                self._device_id = cn
                if not self._device_name:
                    self._device_name = cn
        if captured is not None and not self._peer_cert_pem:
            # Trust-on-first-use: remember what we saw so future sessions pin it.
            self._peer_cert_pem = captured

    # ------------------------------------------------------------------ outbound

    async def _send(self, packet: dict[str, Any]) -> None:
        if self._writer is None:
            raise HandshakeError("session is not open")
        self._writer.write(encode_packet(packet))
        await self._writer.drain()

    async def _send_plugin(self, packet: dict[str, Any]) -> None:
        """Plugin packets need identity exchange and pairing."""
        if not self._connected:
            raise HandshakeError("peer session is not connected")
        if not self._paired:
            raise ProtocolError(f"peer {self._device_id} is not paired")
        await self._send(packet)

    @staticmethod
    def _terminate_process(proc: asyncio.subprocess.Process) -> None:
        """Terminate a command process group (best effort)."""
        if proc.returncode is not None:
            return
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            return
        with contextlib.suppress(OSError, ProcessLookupError):
            proc.terminate()

    async def _fetch_payload(self, packet: dict[str, Any]) -> bytes | None:
        """Download payload bytes from the announced payloadTransferInfo."""
        info = packet.get("payloadTransferInfo")
        size = packet.get("payloadSize")
        if not info or not size:
            return None
        ip = str(info.get("ip"))
        port = info.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ProtocolError("payloadTransferInfo has an invalid port")
        # Only accept the established peer's address (prevents SSRF to other
        # hosts on the LAN); loopback is allowed when the peer itself is local.
        local_peer = self._peer_addr in ("127.0.0.1", "::1")
        if self._peer_addr and ip != self._peer_addr and not (local_peer and ip in ("127.0.0.1", "::1")):
            raise ProtocolError(
                f"payload transfer host {ip!r} does not match peer {self._peer_addr!r}"
            )
        if size > MAX_PAYLOAD_BYTES:
            raise ProtocolError("payload exceeds size limit")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, limit=MAX_LINE_BYTES),
            timeout=HANDSHAKE_TIMEOUT,
        )
        try:
            # KDE inverts the TLS role relative to the TCP direction: we are
            # the TCP client here, so we run the TLS server handshake.
            await upgrade_tls(
                reader,
                writer,
                await server_tls_context(
                    self._identity.cert_pem,
                    self._identity.key_pem,
                    peer_cert_pem=self._peer_cert_pem,
                ),
                HANDSHAKE_TIMEOUT,
                server_side=True,
            )
            peer_certificate(writer, self._device_id)
            data = await asyncio.wait_for(
                reader.readexactly(size), timeout=HANDSHAKE_TIMEOUT
            )
        except asyncio.IncompleteReadError as err:
            raise ProtocolError("payload transfer truncated") from err
        finally:
            writer.close()
            with contextlib.suppress(OSError, asyncio.InvalidStateError):
                await writer.wait_closed()
        return data

    async def _send_payload_packet(
        self, packet_type: str, body: dict[str, Any], payload: bytes
    ) -> None:
        """Announce payloadTransferInfo pointing a temporary TLS server at us."""
        if self._writer is None:
            raise HandshakeError("session is not open")
        sockname = self._writer.transport.get_extra_info("sockname")
        if sockname is None:
            raise HandshakeError("cannot determine local socket address")
        ready = asyncio.Event()

        async def deliver(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            # The peer opens this as a TCP client, so it runs the TLS server
            # handshake and we run the TLS client handshake (inverted roles).
            await upgrade_tls(
                reader,
                writer,
                await client_tls_context(
                    self._peer_cert_pem,
                    self._identity.cert_pem,
                    self._identity.key_pem,
                ),
                HANDSHAKE_TIMEOUT,
                server_side=False,
            )
            peer_certificate(writer, self._device_id)
            writer.write(payload)
            await writer.drain()
            writer.close()
            ready.set()

        server = await asyncio.start_server(deliver, "0.0.0.0", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            await self._send_plugin(
                build_packet(
                    packet_type,
                    body,
                    payload_size=len(payload),
                    payload_transfer_info={"ip": sockname[0], "port": port},
                )
            )
            await asyncio.wait_for(ready.wait(), timeout=HANDSHAKE_TIMEOUT)
        finally:
            server.close()
            await server.wait_closed()

    # ------------------------------------------------------------------ services

    async def send_pair_request(self) -> None:
        """Send a pair request without waiting for the peer to accept."""
        if not self._connected:
            raise HandshakeError("peer session is not connected")
        self._pair_event.clear()
        self.state.notify_changed()
        await self._send(make_pair_request(int(time.time())))

    async def request_pair(self) -> bool:
        """Send a pair request; wait for the peer/owner acceptance."""
        await self.send_pair_request()
        try:
            await asyncio.wait_for(self._pair_event.wait(), timeout=PAIRING_TIMEOUT)
        except TimeoutError:
            return False
        return self._paired

    async def unpair(self) -> None:
        """Cancel a pending request or tear down the established pair."""
        if not self._connected:
            raise HandshakeError("peer session is not connected")
        await self._send(make_pair_unpair())
        self._paired = False
        self.state.notify_changed()
        self._fire(EVENT_PAIR_CHANGED, {"device_id": self._device_id, "paired": False})

    async def ping(self) -> None:
        """Send a ping packet to the device (one-way; no round-trip reply)."""
        if not self._connected:
            raise HandshakeError("peer session is not connected")
        await self._send(make_ping_packet())

    async def send_notification(
        self,
        title: str,
        content: str,
        *,
        notification_id: str | None = None,
        reply_id: str | None = None,
        app_name: str | None = None,
    ) -> None:
        """Send a notification to the paired device."""
        await self._send_plugin(
            make_notification_packet(
                title,
                content,
                notification_id=notification_id,
                reply_id=reply_id,
                app_name=app_name,
            )
        )

    async def request_notifications(self) -> None:
        """Ask the device for active notification updates (display plugin)."""
        await self._send_plugin(make_notification_request_packet())

    async def cancel_notification(self, notification_id: str) -> None:
        """Cancel an active notification on the paired device."""
        await self._send_plugin(
            build_packet(PACKET_TYPE_NOTIFICATION_REQUEST, {"cancel": notification_id})
        )

    async def reply_notification(self, request_reply_id: str, reply: str) -> None:
        """Send a reply to an active notification on the device."""
        await self._send_plugin(
            build_packet(
                PACKET_TYPE_NOTIFICATION_REPLY,
                {"requestReplyId": request_reply_id, "reply": reply},
            )
        )

    async def send_sms(self, phone_number: str, message: str) -> None:
        """Send an SMS to a phone number through the paired device."""
        payload = json.dumps(
            {
                "requestType": "message",
                "phoneNumber": phone_number,
                "message": message,
                "version": SMS_REQUEST_PACKET_VERSION,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        await self._send_payload_packet(
            PACKET_TYPE_SMS_REQUEST,
            {"phoneNumber": phone_number, "message": message},
            payload,
        )

    async def find_my_phone(self, *, ring: bool = True, vibrate: bool = True) -> None:
        """Ask the device to ring and/or vibrate (find my phone)."""
        await self._send_plugin(make_find_my_phone_packet(ring=ring, vibrate=vibrate))

    async def send_command_list(self) -> None:
        """Advertise this HA instance's run-command list to the peer."""
        if not self._connected or not self._paired:
            return
        commands = {
            key: {"name": key, "command": command}
            for key, command in self._local_commands.items()
        }
        await self._send(make_command_list_packet(commands, can_add_command=True))

    # ------------------------------------------------------------------ inbound

    async def _read_loop(self, reader: asyncio.StreamReader) -> None:
        """Read framed packets until the peer closes the session."""
        try:
            while True:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError, OSError):
                    _LOGGER.debug("session read error with peer %s", self._device_id)
                    break
                if not line:
                    break
                try:
                    packet = decode_packet(line)
                except ProtocolError:
                    _LOGGER.debug("malformed packet from %s: %r", self._device_id, line[:120])
                    continue
                try:
                    await self._dispatch(packet)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # One bad plugin packet must not tear down the session.
                    _LOGGER.debug(
                        "error handling %r from %s",
                        packet.get("type"),
                        self._device_id,
                        exc_info=True,
                    )
        except asyncio.CancelledError:
            return
        except (OSError, ConnectionResetError):
            _LOGGER.debug("session error with peer %s", self._device_id)
        finally:
            if not self._closing:
                self._closing = True
                self._connected = False
                self.state.notify_changed()
                _LOGGER.info("Peer %s disconnected", self._device_id)

    async def _dispatch(self, packet: dict[str, Any]) -> None:
        pkt_type = packet.get("type")
        body = packet.get("body") or {}

        if packet.get("payloadSize") and packet.get("payloadTransferInfo"):
            payload = await self._fetch_payload(packet)
            if payload is not None:
                try:
                    extra = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    extra = None
                if isinstance(extra, dict):
                    body.update(extra)

        self.state.last_seen = datetime.now(UTC)
        if pkt_type in (PACKET_TYPE_RUNCOMMAND, PACKET_TYPE_MPRIS):
            # Correlated answer to the legacy pairing probe (command list or
            # MPRIS player list); unrelated packets do not prove pairing.
            self._pair_probe_event.set()

        if pkt_type == PACKET_TYPE_IDENTITY:
            self._consume_peer_identity(packet)
            self.state.notify_changed()
        elif pkt_type == PACKET_TYPE_PAIR:
            await self._handle_pair(body)
        elif pkt_type == PACKET_TYPE_BATTERY:
            self._handle_battery(body)
        elif pkt_type == PACKET_TYPE_PING:
            await self._handle_ping()
        elif pkt_type == PACKET_TYPE_NOTIFICATION:
            self._handle_notification(body)
        elif pkt_type == PACKET_TYPE_NOTIFICATION_REQUEST:
            self._handle_notification_request(body)
        elif pkt_type == PACKET_TYPE_NOTIFICATION_REPLY:
            self._fire(
                EVENT_NOTIFICATION_REPLY,
                {
                    "device_id": self._device_id,
                    "request_reply_id": body.get("requestReplyId") or body.get("replyId"),
                    "reply": body.get("reply"),
                },
            )
        elif pkt_type == PACKET_TYPE_NOTIFICATION_ACTION:
            self._fire(
                EVENT_NOTIFICATION_ACTION,
                {
                    "device_id": self._device_id,
                    "action_id": body.get("actionId"),
                    "key": body.get("key"),
                },
            )
        elif pkt_type == PACKET_TYPE_SMS_MESSAGES:
            self._handle_sms(body)
        elif pkt_type == PACKET_TYPE_RUNCOMMAND_REQUEST:
            await self._handle_runcommand_request(body)
        elif pkt_type == PACKET_TYPE_RUNCOMMAND:
            # Desktop peers (kdeconnect-kde) request execution on the base
            # packet type; Android uses kdeconnect.runcommand.request.
            if body.get("key"):
                await self._handle_runcommand_request(body)
        elif pkt_type == PACKET_TYPE_RUNCOMMAND_OUTPUT:
            parsed = parse_runcommand(body)
            self._fire(
                EVENT_COMMAND_OUTPUT,
                {
                    "device_id": self._device_id,
                    "kind": parsed["kind"],
                    "id": parsed.get("id", ""),
                    "stdout": parsed.get("stdout", ""),
                    "stderr": parsed.get("stderr", ""),
                    "command": parsed.get("command", ""),
                    "success": parsed.get("success"),
                    "exit_code": parsed.get("exit_code"),
                },
            )
        elif pkt_type == PACKET_TYPE_MPRIS:
            self._handle_mpris(body)
        elif pkt_type == PACKET_TYPE_FIND_MY_PHONE_REQUEST:
            _LOGGER.debug("find-my-phone request from %s ignored", self._device_id)
        else:
            _LOGGER.debug("ignoring packet %r from %s", pkt_type, self._device_id)

    def _fire(self, event: str, data: dict[str, Any]) -> None:
        self._hass.bus.async_fire(event, data)

    async def _handle_pair(self, body: dict[str, Any]) -> None:
        pair = bool(body.get("pair"))
        if not pair:
            self._pair_rejected = True
        requested = pair and body.get("timestamp") is not None
        if requested:
            self._pending_pair_request = dict(body)
            self._fire(EVENT_PAIR_REQUEST, {"device_id": self._device_id})
            if not self._auto_accept_pairing:
                _LOGGER.info(
                    "KDE Connect pairing request from %s awaits approval",
                    self._device_id,
                )
                return
            await self._send(make_pair_accept())
            self._paired = True
        elif pair:
            self._paired = True  # our request was accepted
        else:
            self._paired = False  # accepted/cancelled/unpaired
        self._pair_event.set()
        self.state.notify_changed()
        self._fire(EVENT_PAIR_CHANGED, {"device_id": self._device_id, "paired": self._paired})
        if self._paired:
            await self._refresh_plugin_state()

    async def accept_pair(self) -> bool:
        """Approve the pending peer-initiated pairing request."""
        if not self._connected:
            raise HandshakeError("peer session is not connected")
        if self._paired:
            return True
        await self._send(make_pair_accept())
        self._paired = True
        self._paired_known = True
        self._pending_pair_request = None
        self._pair_event.set()
        self.state.notify_changed()
        self._fire(EVENT_PAIR_CHANGED, {"device_id": self._device_id, "paired": True})
        await self._refresh_plugin_state()
        return True

    def _handle_battery(self, body: dict[str, Any]) -> None:
        parsed = parse_battery(body)
        self.state.battery_charge = parsed["current_charge"]
        self.state.battery_charging = parsed["is_charging"]
        self.state.battery_quantity = parsed["battery_quantity"]
        self.state.notify_changed()

    async def _handle_ping(self) -> None:
        # KDE Connect pings are one-way: the receiver shows a notification and
        # does not echo. Do not answer, just record activity.
        self.state.notify_changed()

    def _handle_notification(self, body: dict[str, Any]) -> None:
        parsed = parse_notification(body)
        self.state.notifications.append(parsed)
        del self.state.notifications[_NOTIFICATION_KEEP:]
        self.state.notification_count += 1
        self.state.notify_changed()
        self._fire(
            EVENT_NOTIFICATION_RECEIVED,
            {
                "device_id": self._device_id,
                "title": parsed["title"],
                "content": parsed["content"],
                "app_name": parsed["app_name"],
                "notification_id": parsed["notification_id"],
                "reply_id": parsed["reply_id"],
                "urgent": parsed["urgent"],
            },
        )

    def _handle_notification_request(self, body: dict[str, Any]) -> None:
        """Device-side display plugin asks the desktop to show a notification."""
        self.state.notification_count += 1
        self.state.notify_changed()
        self._fire(
            EVENT_NOTIFICATION_REQUEST,
            {
                "device_id": self._device_id,
                "id": body.get("id"),
                "title": body.get("title"),
                "content": body.get("content"),
                "reply_id": body.get("replyId"),
                "type": body.get("type"),
            },
        )

    def _handle_sms(self, body: dict[str, Any]) -> None:
        parsed = parse_sms_messages(body)
        unread = 0
        for conversation in parsed["conversations"]:
            messages = conversation.get("messages") or []
            for message in messages:
                if message.get("unread") or message.get("unreadCount"):
                    unread += 1
        self.state.sms_unread_count = unread
        self.state.notify_changed()
        self._fire(
            EVENT_SMS_RECEIVED,
            {
                "device_id": self._device_id,
                "addresses": parsed["addresses"],
                "messages": parsed["messages"],
            },
        )

    async def _handle_runcommand_request(self, body: dict[str, Any]) -> None:
        """Peer asks HA to re-send its command list or to run a local command."""
        if not self._paired:
            _LOGGER.debug("refusing runcommand from unpaired peer %s", self._device_id)
            return
        if PACKET_TYPE_RUNCOMMAND_REQUEST not in self.capabilities:
            return
        if body.get("requestCommandList"):
            await self.send_command_list()
            return
        if body.get("setup") or body.get("stop"):
            _LOGGER.debug("runcommand %r from %s ignored", body, self._device_id)
            return

        key = body.get("key")
        key_str = key if isinstance(key, str) else None
        command = self._local_commands.get(key_str) if key_str is not None else None
        if not self._allow_remote_commands or command is None:
            _LOGGER.debug("remote command %r refused (peer %s)", key, self._device_id)
            return

        self._command_counter = (self._command_counter + 1) % 2**31
        command_id = self._command_counter
        scheduler = getattr(self._hass, "async_create_task", None)
        if scheduler is None:
            await self._execute_local_command(command_id, key_str, command)
            return
        task = scheduler(self._execute_local_command(command_id, key_str, command))
        self._command_tasks.add(task)
        task.add_done_callback(self._command_tasks.discard)

    async def _execute_local_command(self, command_id: int, key: str, command: str) -> None:
        """Run one local command and stream KDE runcommand output packets."""
        try:
            await self._send(
                make_command_output_packet(
                    command_id=command_id, command=command, started=True
                )
            )
        except (HandshakeError, ProtocolError, TimeoutError, OSError):
            _LOGGER.debug("could not announce command start to %s", self._device_id)
            return

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except (OSError, ValueError) as err:
            _LOGGER.warning("remote command %r failed to start: %s", key, err)
            await self._send(
                make_command_output_packet(
                    command_id=command_id, success=False, exit_code=1, finished=True
                )
            )
            return

        self._command_procs.add(proc)
        try:
            stdout, stderr = await proc.communicate()
        except asyncio.CancelledError:
            self._terminate_process(proc)
            with contextlib.suppress(asyncio.CancelledError):
                await proc.wait()
            raise
        finally:
            self._command_procs.discard(proc)

        try:
            await self._send(
                make_command_output_packet(
                    command_id=command_id,
                    stdout=stdout.decode("utf-8", "replace").splitlines(),
                    stderr=stderr.decode("utf-8", "replace").splitlines(),
                    output=True,
                )
            )
            await self._send(
                make_command_output_packet(
                    command_id=command_id,
                    success=proc.returncode == 0,
                    exit_code=int(proc.returncode or 0),
                    finished=True,
                )
            )
        except (HandshakeError, ProtocolError, TimeoutError, OSError):
            _LOGGER.warning("Could not deliver command output to %s", self._device_id)

    # ------------------------------------------------------------------ mpris

    def _handle_mpris(self, body: dict[str, Any]) -> None:
        if body.get("transferringAlbumArt"):
            return
        if "playerList" in body:
            players = body.get("playerList") or []
            if not isinstance(players, list):
                players = []
            new_players: dict[str, dict[str, Any]] = {}
            for name in players:
                if not isinstance(name, str):
                    continue
                new_players[name] = dict(self.state.mpris_players.get(name, {}))
            self.state.mpris_players = new_players
            if not new_players:
                self.state.mpris_current_player = None
            elif self.state.mpris_current_player not in new_players:
                self.state.mpris_current_player = next(iter(new_players.keys()))
            if self.state.mpris_current_player and self._connected and self._paired:
                scheduler = getattr(self._hass, "async_create_task", None)
                if scheduler is not None:
                    scheduler(self.mpris_request_player_status(self.state.mpris_current_player))

        player = body.get("player")
        if isinstance(player, str) and player:
            info = dict(self.state.mpris_players.get(player, {}))
            for key in (
                "title",
                "artist",
                "album",
                "albumArtUrl",
                "url",
                "loopStatus",
            ):
                if key in body:
                    info[key] = body.get(key)
            for key in (
                "isPlaying",
                "canPause",
                "canPlay",
                "canGoNext",
                "canGoPrevious",
                "canSeek",
                "shuffle",
            ):
                if key in body:
                    info[key] = bool(body.get(key))
            for key in ("volume", "length", "pos"):
                if key in body:
                    info[key] = _coerce_int(body.get(key))
            self.state.mpris_players[player] = info
            if self.state.mpris_current_player is None:
                self.state.mpris_current_player = player

        self.state.notify_changed()

    async def mpris_request_player_list(self) -> None:
        if not self._connected or not self._paired:
            return
        if PACKET_TYPE_MPRIS_REQUEST not in self.send_capabilities:
            return
        await self._send(build_packet(PACKET_TYPE_MPRIS_REQUEST, {"requestPlayerList": True}))

    async def mpris_request_player_status(self, player: str | None = None) -> None:
        player = player or self.state.mpris_current_player
        if not player:
            return
        await self._send_plugin(
            build_packet(
                PACKET_TYPE_MPRIS_REQUEST,
                {"player": player, "requestNowPlaying": True, "requestVolume": True},
            )
        )

    async def mpris_set_player(self, player: str) -> None:
        if player in self.state.mpris_players:
            self.state.mpris_current_player = player
            self.state.notify_changed()
        await self.mpris_request_player_status(player)

    async def mpris_action(self, action: str) -> None:
        player = self.state.mpris_current_player
        if not player and self.state.mpris_players:
            player = next(iter(self.state.mpris_players.keys()))
        if not player:
            raise ProtocolError("No MPRIS player available")
        await self._send_plugin(
            build_packet(PACKET_TYPE_MPRIS_REQUEST, {"player": player, "action": action})
        )

    async def mpris_set_volume(self, volume: int) -> None:
        player = self.state.mpris_current_player
        if not player and self.state.mpris_players:
            player = next(iter(self.state.mpris_players.keys()))
        if not player:
            raise ProtocolError("No MPRIS player available")
        await self._send_plugin(
            build_packet(
                PACKET_TYPE_MPRIS_REQUEST,
                {"player": player, "setVolume": max(0, min(100, int(volume)))},
            )
        )

    async def mpris_set_position(self, position_ms: int) -> None:
        player = self.state.mpris_current_player
        if not player and self.state.mpris_players:
            player = next(iter(self.state.mpris_players.keys()))
        if not player:
            raise ProtocolError("No MPRIS player available")
        await self._send_plugin(
            build_packet(
                PACKET_TYPE_MPRIS_REQUEST,
                {"player": player, "SetPosition": int(position_ms)},
            )
        )


Peer = KdePeer  # compatibility alias for earlier worker drafts
