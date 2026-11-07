"""KDE Connect peer transport — protocol version 8, TLS-only sessions.

A ``KdePeer`` owns exactly one TCP session with one remote KDE Connect
device and performs the protocol v8 handshake:

Outbound (HA connects to the peer's announced ``tcpPort``):

1. TCP connect (peer ports 1716-1764).
2. Send the *plaintext connection packet*
   ``{"type": "kdeconnect.identity", "body": {deviceId, deviceName,
   protocolVersion, targetDeviceId, targetProtocolVersion}}``.
3. Upgrade the socket with ``writer.start_tls`` (connecting side initiates).
4. Inside TLS send our encrypted identity packet
   ``{deviceId, deviceName, deviceType, protocolVersion,
   incomingCapabilities, outgoingCapabilities}`` and read the peer's
   encrypted identity answer (KDE Core replies within ~1 s).
5. Verify the peer certificate: ``CN == deviceId``, and for trusted peers
   the presented certificate must equal the pinned ``peer_cert_pem``.

Inbound (started by ``asyncio.start_server`` in ``__init__.py``):

1. Read the peer's plaintext connection packet (carries ``targetDeviceId``).
2. Reply with our plaintext identity packet carrying ``tcpPort``.
3. Upgrade TLS (server side).
4. Exchange encrypted identity packets inside TLS.

Peer certificates are self-signed RSA/EC with ``CN == deviceId``. OpenSSL
cannot build a trust chain from a bare self-signed leaf, so trust is
enforced explicitly: certificate equality against the pinned PEM plus the
CN check — see ``protocol.client_tls_context`` / ``peer_certificate``.

Entity-facing duck type (consumed by ``entities.py``): ``device_id`` /
``device_name`` / ``device_type`` describe the *remote peer*,
``capabilities`` is the set of packet types the peer can push to us, and
``connected`` / ``paired`` drive entity availability. Push packets update
``self.state`` (``DeviceState``) and call ``notify_changed()``, so sensor
entities refresh immediately.

This module keeps no UDP discovery/announce loops and no reconnect
logic — ``__init__.py`` owns discovery, pairing UI and reconnection.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
import json
import logging
import time
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
    PACKET_TYPE_NOTIFICATION,
    PACKET_TYPE_NOTIFICATION_ACTION,
    PACKET_TYPE_NOTIFICATION_REPLY,
    PACKET_TYPE_NOTIFICATION_REQUEST,
    PACKET_TYPE_PAIR,
    PACKET_TYPE_PING,
    PACKET_TYPE_RUNCOMMAND,
    PACKET_TYPE_RUNCOMMAND_OUTPUT,
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
    client_tls_context,
    decode_packet,
    encode_packet,
    make_connection_packet,
    make_encrypted_identity,
    make_find_my_phone_packet,
    make_notification_packet,
    make_notification_request_packet,
    make_pair_accept,
    make_pair_request,
    make_pair_unpair,
    make_ping_packet,
    make_run_command_packet,
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


class KdePeer:
    """Live protocol v8 TLS session with a single remote peer device."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        identity: LocalIdentity,
        peer_device_id: str,
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
    ) -> None:
        """Initialize a live session with one remote peer device."""
        self._hass = hass
        self._identity = identity
        self._device_id = peer_device_id
        self._device_name = peer_device_name or peer_device_id
        self._device_type = peer_device_type
        self._peer_cert_pem = peer_cert_pem
        self._capabilities = {str(name) for name in peer_capabilities or ()}
        self._incoming = list(incoming_capabilities or DEFAULT_INCOMING_CAPABILITIES)
        self._allow_remote_commands = allow_remote_commands
        self._local_commands = dict(local_commands or {})
        self._inbound_port = inbound_port
        self._host = host
        self._tcp_port = tcp_port

        self.state = DeviceState()
        self.commands: dict[str, dict[str, str]] = {}

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._loop_task: asyncio.Task[None] | None = None
        self._closing = False
        self._connected = False
        self._paired = False

        self._pair_event = asyncio.Event()
        self._ping_event = asyncio.Event()
        self._ping_started: float | None = None

    # ------------------------------------------------------------------ entity view

    @property
    def device_id(self) -> str:
        """Remote peer deviceId (HA device identifier / entity unique id)."""
        return self._device_id

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
        """Packet types the peer can push to us (wire string list names)."""
        return self._capabilities

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
        await self.close()

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

        # Plaintext connection packet; the peer initiates TLS right after it.
        await self._send(
            make_connection_packet(
                self._identity.device_id,
                self._identity.device_name,
                target_device_id=self._device_id,
            )
        )

        # The peer answers our connection packet in plaintext before TLS starts
        # (Qt reads the packet first, then upgrades); consume it so buffered
        # bytes only carry the TLS handshake.
        try:
            reply = await read_packet(reader, timeout=HANDSHAKE_TIMEOUT)
        except TimeoutError as err:
            raise HandshakeError(f"peer {host}:{port} did not answer the connection packet") from err
        except OSError as err:
            raise HandshakeError(f"peer {host}:{port} disconnected before identity packet") from err
        if reply is None or reply.get("type") != PACKET_TYPE_IDENTITY:
            raise HandshakeError(
                f"peer {host}:{port} did not answer the connection packet"
            )
        reply_body = reply.get("body") or {}
        if reply_body.get("deviceId") != self._device_id:
            raise PeerIdentityMismatch(
                f"peer {host}:{port} answered with deviceId "
                f"{reply_body.get('deviceId')!r}, expected {self._device_id!r}"
            )

        try:
            await upgrade_tls(
                reader,
                writer,
                server_tls_context(
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

    async def serve(self, reader, writer, tcp_port: int | None = None) -> None:
        """Accept an inbound session started by asyncio.start_server."""
        await self.close()
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

        # Plaintext reply carrying tcpPort; peer upgrades TLS after reading it.
        await self._send(
            make_connection_packet(
                self._identity.device_id,
                self._identity.device_name,
                tcp_port=port,
            )
        )

        try:
            await upgrade_tls(
                reader,
                writer,
                client_tls_context(
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
        self._consume_peer_identity(peer_identity)

        self._connected = True
        self.state.last_seen = datetime.now(UTC)
        self.state.notify_changed()
        self._loop_task = self._hass.async_create_background_task(
            self._read_loop(reader), "kde_connect_session", eager_start=True
        )

    async def close(self) -> None:
        """Close the session; idempotent."""
        self._closing = True
        task, self._loop_task = self._loop_task, None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
        writer, self._writer = self._writer, None
        self._reader = None
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError, asyncio.InvalidStateError):
                await writer.wait_closed()
        if self._connected:
            self._connected = False
            self._paired = False
            self.state.notify_changed()

    stop = close

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
        if peer_id != self._device_id:
            raise PeerIdentityMismatch(
                f"peer identity deviceId {peer_id!r} != expected {self._device_id!r}"
            )
        if not valid_device_id(peer_id):
            raise PeerIdentityMismatch(f"invalid peer deviceId: {peer_id!r}")
        version = body.get("protocolVersion")
        if not isinstance(version, int) or version < PROTOCOL_VERSION:
            raise HandshakeError(
                f"peer {peer_id!r} identity protocolVersion {version!r}, v8 required"
            )

        name = body.get("deviceName") or self._device_id
        self._device_name = sanitize_device_name(name) or self._device_id
        self._device_type = body.get("deviceType") or self._device_type

        outgoing = body.get("outgoingCapabilities") or []
        if isinstance(outgoing, list):
            advertised = {str(item) for item in outgoing}
            known = set(self._incoming)
            self._capabilities = advertised & known if advertised else set(self._incoming)
        elif not self._capabilities:
            self._capabilities = set(self._incoming)

    def _verify_peer_certificate(self, writer: asyncio.StreamWriter) -> None:
        """Verify the peer certificate against the pinned device id.

        CN == deviceId; for trusted peers the TLS context already demands
        the pinned cert (CERT_REQUIRED against the pinned CA PEM).
        """
        captured = peer_certificate(writer, self._device_id)
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

    async def _fetch_payload(self, packet: dict[str, Any]) -> bytes | None:
        """Download payload bytes from the announced payloadTransferInfo."""
        info = packet.get("payloadTransferInfo")
        size = packet.get("payloadSize")
        if not info or not size:
            return None
        ip = info.get("ip")
        port = info.get("port")
        if not ip or port is None:
            raise ProtocolError("payloadTransferInfo missing ip/port")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(ip), int(port), limit=MAX_LINE_BYTES),
            timeout=HANDSHAKE_TIMEOUT,
        )
        try:
            # KDE inverts the TLS role relative to the TCP direction: we are
            # the TCP client here, so we run the TLS server handshake.
            await upgrade_tls(
                reader,
                writer,
                server_tls_context(
                    self._identity.cert_pem,
                    self._identity.key_pem,
                    peer_cert_pem=self._peer_cert_pem,
                ),
                HANDSHAKE_TIMEOUT,
                server_side=True,
            )
            peer_certificate(writer, self._device_id)
            data = await asyncio.wait_for(reader.read(MAX_PAYLOAD_BYTES + 1), timeout=HANDSHAKE_TIMEOUT)
        finally:
            writer.close()
            with contextlib.suppress(OSError, asyncio.InvalidStateError):
                await writer.wait_closed()
        if len(data) > MAX_PAYLOAD_BYTES:
            raise ProtocolError("payload exceeds size limit")
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
                client_tls_context(
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

    async def request_pair(self) -> bool:
        """Send a pair request; wait for the peer/owner acceptance."""
        if not self._connected:
            raise HandshakeError("peer session is not connected")
        self._pair_event.clear()
        await self._send(make_pair_request(int(time.time())))
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

    async def ping(self) -> float | None:
        """Send a ping packet and return round-trip latency in ms, or None."""
        if not self._connected:
            raise HandshakeError("peer session is not connected")
        self._ping_event.clear()
        self._ping_started = time.monotonic()
        await self._send(make_ping_packet())
        try:
            await asyncio.wait_for(self._ping_event.wait(), timeout=HANDSHAKE_TIMEOUT)
        except TimeoutError:
            return None
        return self.state.ping_latency_ms

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

    async def run_command(self, key: str) -> None:
        """Run a command the peer advertised in its ``commandList`` (wire key)."""
        await self._send_plugin(make_run_command_packet(key))

    # ------------------------------------------------------------------ inbound

    async def _read_loop(self, reader: asyncio.StreamReader) -> None:
        """Read framed packets until the peer closes the session."""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    packet = decode_packet(line)
                except ProtocolError:
                    _LOGGER.debug("malformed packet from %s: %r", self._device_id, line[:120])
                    continue
                await self._dispatch(packet)
        except asyncio.CancelledError:
            return
        except (OSError, ConnectionResetError):
            _LOGGER.debug("session error with peer %s", self._device_id)
        finally:
            if not self._closing:
                self._closing = True
                self._connected = False
                self._paired = False
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
        elif pkt_type == PACKET_TYPE_RUNCOMMAND:
            await self._handle_runcommand(body)
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
        elif pkt_type == PACKET_TYPE_FIND_MY_PHONE_REQUEST:
            _LOGGER.debug("find-my-phone request from %s ignored", self._device_id)
        else:
            _LOGGER.debug("ignoring packet %r from %s", pkt_type, self._device_id)

    def _fire(self, event: str, data: dict[str, Any]) -> None:
        self._hass.bus.async_fire(event, data)

    async def _handle_pair(self, body: dict[str, Any]) -> None:
        pair = bool(body.get("pair"))
        requested = pair and body.get("timestamp") is not None
        if requested:
            # Peer initiated a pairing request — accept (config flow gates it).
            self._fire(EVENT_PAIR_REQUEST, {"device_id": self._device_id})
            await self._send(make_pair_accept())
            self._paired = True
        elif pair:
            self._paired = True  # our request was accepted
        else:
            self._paired = False  # accepted/cancelled/unpaired
        self._pair_event.set()
        self._fire(EVENT_PAIR_CHANGED, {"device_id": self._device_id, "paired": self._paired})
        self.state.notify_changed()

    def _handle_battery(self, body: dict[str, Any]) -> None:
        parsed = parse_battery(body)
        self.state.battery_charge = parsed["current_charge"]
        self.state.battery_charging = parsed["is_charging"]
        self.state.battery_quantity = parsed["battery_quantity"]
        self.state.notify_changed()

    async def _handle_ping(self) -> None:
        # KDE Connect pings are echoed back verbatim.
        await self._send(make_ping_packet())
        if self._ping_started is not None:
            self.state.ping_latency_ms = round(
                (time.monotonic() - self._ping_started) * 1000, 1
            )
            self._ping_started = None
            self._ping_event.set()
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

    async def _handle_runcommand(self, body: dict[str, Any]) -> None:
        command_list = body.get("commandList")
        if isinstance(command_list, dict):
            # Peer announces its runnable commands (device side).
            self.commands = {
                str(key): {"name": value.get("name"), "command": value.get("command")}
                for key, value in command_list.items()
                if isinstance(value, dict)
            }
            self.state.notify_changed()
            return

        # Device asks the desktop to run one of our configured commands.
        key = body.get("key")
        command = self._local_commands.get(key) if isinstance(key, str) else None
        command_id = body.get("commandId")
        if not self._allow_remote_commands or command is None:
            _LOGGER.debug("remote command %r refused (peer %s)", key, self._device_id)
            return
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        payload = json.dumps(
            {
                "id": command_id,
                "stdout": stdout.decode("utf-8", "replace").splitlines(),
                "stderr": stderr.decode("utf-8", "replace").splitlines(),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            await self._send_payload_packet(
                PACKET_TYPE_RUNCOMMAND_OUTPUT, {"id": command_id}, payload
            )
        except (HandshakeError, ProtocolError, TimeoutError):
            _LOGGER.warning("Could not deliver command output to %s", self._device_id)


Peer = KdePeer  # compatibility alias for earlier worker drafts
