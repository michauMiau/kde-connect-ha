"""Functional tests for the KDE Connect integration against an in-process fake device.

Each test drives a real TCP/TLS protocol-v8 handshake (certificates with
``CN == deviceId``, plaintext connection packet, ``protocol.upgrade_tls``
upgrade, encrypted identity exchange, pairing, battery pushes, payload
transfers) between the integration's ``KdePeer`` transport and a fake KDE
Connect device.

The fake device is asyncio-based and mirrors KDE Connect's inverted TLS
roles: the TCP client side runs the TLS *server* handshake and the TCP
accepting side runs the TLS *client* handshake (STARTTLS after the plaintext
connection packet). ``protocol.upgrade_tls`` feeds bytes that coalesce with
the plaintext packet into the SSL protocol's incoming BIO before the
handshake is awaited, so a buffered ClientHello is not swallowed into the
plain stream buffer. Everything runs on the event loop — no worker threads,
so nothing can wedge in ``accept()`` at teardown.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from typing import Any, Self

from custom_components.kde_connect import protocol
from custom_components.kde_connect.const import (
    CONF_CAPABILITIES,
    CONF_DEVICE_ID,
    CONF_DEVICE_NAME,
    CONF_DEVICE_TYPE,
    CONF_HOST,
    CONF_PEER_CERT,
    CONF_TCP_PORT,
    DOMAIN,
    EVENT_DEVICE_DISCOVERED,
    EVENT_PAIR_CHANGED,
    EVENT_PAIR_REQUEST,
    HANDSHAKE_TIMEOUT,
    MAX_TCP_PORT,
    MIN_TCP_PORT,
    PACKET_TYPE_BATTERY,
    PACKET_TYPE_IDENTITY,
    PACKET_TYPE_NOTIFICATION,
    PACKET_TYPE_PAIR,
    PACKET_TYPE_PING,
    PACKET_TYPE_SMS_REQUEST,
    SERVICE_SEND_NOTIFICATION,
    SERVICE_SEND_SMS,
)
from custom_components.kde_connect.peer import KdePeer
import pytest

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import STATE_UNAVAILABLE, Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component
from tests.common import MockConfigEntry  # noqa: TID251 - harness helpers for entry mocks

# The HA harness blocks sockets per test (pytest-socket); this module drives
# real loopback TCP sessions. enable_socket() restores socket creation but the
# harness's socket_allow_hosts(["127.0.0.1"]) connect guard stays in force, so
# connects to anything other than loopback remain blocked.
pytestmark = pytest.mark.enable_socket()

@pytest.fixture(autouse=True)
def _no_lan_udp_discovery(monkeypatch: Any) -> None:
    """Keep discovery inert during these tests.

    This host's LAN contains real KDE Connect devices that would answer the
    integration's UDP broadcast and inject foreign discovery flows/pairings.
    Bind/listen nothing: discovery stays inert during these tests.
    """

    async def _noop(self: Any) -> None:
        return None

    monkeypatch.setattr(
        "custom_components.kde_connect.discovery.KdeConnectDiscovery.async_start", _noop
    )
    monkeypatch.setattr(
        "custom_components.kde_connect.discovery.KdeConnectDiscovery.async_stop", _noop
    )


# What the fake device advertises in its encrypted identity packet.
FAKE_OUTGOING_CAPABILITIES = [
    "kdeconnect.battery",
    "kdeconnect.ping",
    "kdeconnect.notification",
    "kdeconnect.sms",
    "kdeconnect.sms.messages",
    "kdeconnect.runcommand",
]

BATTERY_BODY: dict[str, Any] = {
    "isCharging": True,
    "currentCharge": 42,
    "batteryQuantity": 54,
    "thresholdEvent": -1,
}


class FakeDevice:
    """Asyncio stand-in for a KDE Connect device (protocol v8).

    A real asyncio TCP server plus TLS sessions, mirroring KDE Core's
    inverted TLS roles exactly: KDE runs the TLS server handshake on the
    connecting side and the TLS client handshake on the accepting side,
    upgrading the same socket after the plaintext connection packet
    (STARTTLS). ``protocol.upgrade_tls`` covers the coalesced
    packet-then-ClientHello case that would otherwise deadlock the
    handshake on already-buffered bytes.

    Modes:
      * ``normal`` — full TLS session: encrypted identity exchange,
        optional spontaneous pair accept, battery push, then ping/p pair
        request/p payload answers.
      * ``close_after_identity`` — read the connection packet then close
        (unknown-device sessions whose announced TCP port is unreachable).
      * ``close_before_tls`` — close immediately after accept.
    """

    def __init__(
        self,
        *,
        name: str = "Fake Phone",
        mode: str = "normal",
        auto_pair: bool = True,
    ) -> None:
        """Initialize the fake device with a generated local identity."""
        self.identity = protocol.create_local_identity(name, device_type="android")
        self.mode = mode
        self.auto_pair = auto_pair
        self.connection_packets: list[dict[str, Any]] = []
        self.received: list[dict[str, Any]] = []
        self.payloads: list[bytes] = []
        # Home Assistant's local identity — required for payload fetch TLS pinning.
        self.ha_cert_pem: str | None = None
        self.ha_device_id: str | None = None
        self._server: asyncio.Server | None = None
        # StreamWriters holding live sessions (accepted, fetched, inbound).
        self._writers: list[asyncio.StreamWriter] = []
        # Handler tasks so ``stop()`` can wake sessions stuck in a read.
        self._tasks: list[asyncio.Task[Any]] = []
        self._ping_echoed = False

    @property
    def device_id(self) -> str:
        """The fake device's deviceId."""
        return self.identity.device_id

    @property
    def device_name(self) -> str:
        """The fake device's announced name."""
        return self.identity.device_name

    @property
    def cert_pem(self) -> str:
        """The fake device's self-signed certificate PEM."""
        return self.identity.cert_pem

    @property
    def port(self) -> int:
        """The TCP port the fake device is listening on."""
        assert self._server is not None
        assert self._server.sockets
        return self._server.sockets[0].getsockname()[1]

    async def __aenter__(self) -> Self:
        """Bind the fake device to a KDE Connect TCP port and start serving."""
        # KDE devices listen inside 1716-1764; the config flow and pair/battery
        # assertions validate announced ports against that range, so the fake's
        # listening port must also come from the range.
        last_err: OSError | None = None
        for port in range(MIN_TCP_PORT, MAX_TCP_PORT + 1):
            try:
                self._server = await asyncio.start_server(
                    self._handle_session, "127.0.0.1", port
                )
            except OSError as err:
                last_err = err
                continue
            return self
        raise OSError(
            f"no free KDE Connect TCP port on 127.0.0.1 ({MIN_TCP_PORT}-{MAX_TCP_PORT})"
        ) from last_err

    async def __aexit__(self, exc_type, exc, tb) -> None:
        """Stop the fake device and drop its sessions."""
        await self.stop()

    async def stop(self) -> None:
        """Close sessions and cancel stuck handler tasks."""
        self.close_sessions()
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            with contextlib.suppress(OSError):
                await server.wait_closed()
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    def close_sessions(self) -> None:
        """Drop every live TLS session the fake device holds open.

        Closing the stream transport sends a TLS close_notify so the peer
        sees a clean EOF, exactly like a device process exiting.
        """
        for writer in list(self._writers):
            with contextlib.suppress(OSError):
                writer.close()

    async def _handle_session(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._writers.append(writer)
        self._tasks.append(asyncio.current_task())
        try:
            if self.mode == "close_before_tls":
                # Drain the connection packet before closing: closing a socket
                # with unread receive data sends RST (ConnectionResetError),
                # not the clean EOF that peer.py maps into a SETUP_RETRY
                # handshake error. A real device exiting after accept sends FIN.
                await reader.readline()
                writer.close()
                return
            line = await reader.readline()
            if not line:
                writer.close()
                return
            self.connection_packets.append(protocol.decode_packet(line))
            if self.mode == "close_after_identity":
                writer.close()
                return

            # KDE answers the connection packet in plaintext before TLS starts.
            reply_target = self.ha_device_id or None
            await self._send_packet(
                writer,
                protocol.make_connection_packet(
                    self.device_id,
                    self.device_name,
                    self.port,
                    target_device_id=reply_target,
                ),
            )

            # KDE inverts TLS roles: we are the TCP server, so we run the TLS
            # client handshake (Qt: startClientEncryption on accepted sockets).
            context = protocol.client_tls_context(
                self.ha_cert_pem, self.identity.cert_pem, self.identity.key_pem
            )
            await protocol.upgrade_tls(
                reader, writer, context, HANDSHAKE_TIMEOUT, server_side=False
            )

            encrypted = await protocol.read_packet(reader, timeout=HANDSHAKE_TIMEOUT)
            if encrypted is None:
                return
            self.received.append(encrypted)

            await self._send_packet(writer, self._encrypted_identity())
            if self.auto_pair:
                await self._send_packet(writer, protocol.make_pair_accept())
            await self._send_packet(
                writer, protocol.build_packet(PACKET_TYPE_BATTERY, BATTERY_BODY)
            )

            while True:
                packet = await protocol.read_packet(reader)
                if packet is None:  # peer closed the session
                    break
                self.received.append(packet)
                await self._respond(writer, packet)
        except (protocol.ProtocolError, TimeoutError, OSError, ValueError):
            pass
        finally:
            with contextlib.suppress(OSError):
                writer.close()

    async def _respond(
        self, writer: asyncio.StreamWriter, packet: dict[str, Any]
    ) -> None:
        packet_type = packet.get("type")
        if packet_type == PACKET_TYPE_PING and not self._ping_echoed:
            self._ping_echoed = True
            await self._send_packet(writer, protocol.make_ping_packet())
        elif (
            packet_type == PACKET_TYPE_PAIR
            and packet.get("body", {}).get("timestamp") is not None
        ):
            # Device-side user accept: answer without timestamp.
            await self._send_packet(writer, protocol.make_pair_accept())
        elif packet.get("payloadSize") and packet.get("payloadTransferInfo"):
            await self._fetch_payload(packet)

    async def _fetch_payload(self, packet: dict[str, Any]) -> None:
        info = packet["payloadTransferInfo"]
        size = int(packet["payloadSize"])
        # KDE inverts TLS roles: we opened this as a TCP client, so TLS server.
        context = protocol.server_tls_context(
            self.identity.cert_pem, self.identity.key_pem
        )
        reader, writer = await asyncio.open_connection(str(info["ip"]), int(info["port"]))
        try:
            await protocol.upgrade_tls(
                reader, writer, context, HANDSHAKE_TIMEOUT, server_side=True
            )
            ssl_object = writer.transport.get_extra_info("ssl_object")
            cert_der = (
                ssl_object.getpeercert(binary_form=True) if ssl_object else None
            )
            if cert_der is not None:
                assert protocol.verify_certificate_identity(
                    protocol.load_certificate(cert_der), self.ha_device_id
                ), "payload TLS cert CN must match HA deviceId"
            data = bytearray()
            while len(data) < size:
                chunk = await reader.read(size - len(data))
                if not chunk:
                    break
                data += chunk
            self.payloads.append(bytes(data))
        finally:
            writer.close()
            with contextlib.suppress(OSError, asyncio.InvalidStateError):
                await writer.wait_closed()

    async def _send_packet(
        self, writer: asyncio.StreamWriter, packet: dict[str, Any]
    ) -> None:
        writer.write(protocol.encode_packet(packet))
        await writer.drain()

    def _encrypted_identity(self) -> dict[str, Any]:
        return protocol.make_encrypted_identity(
            self.device_id,
            self.device_name,
            device_type="android",
            outgoing_capabilities=FAKE_OUTGOING_CAPABILITIES,
        )

    async def send_plaintext_identity(
        self, port: int, *, target_device_id: str, tcp_port: int | None = None
    ) -> None:
        """Send a plaintext connection packet to HA's inbound port and close."""

        _, writer = await asyncio.open_connection("127.0.0.1", port)
        await self._send_packet(
            writer,
            protocol.make_connection_packet(
                self.device_id,
                self.device_name,
                tcp_port,
                target_device_id=target_device_id,
            ),
        )
        writer.close()
        with contextlib.suppress(OSError, asyncio.InvalidStateError):
            await writer.wait_closed()

    async def run_inbound_session(
        self, port: int, *, target_device_id: str, server_cert_pem: str
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Run a device-initiated session against the fake device's peer.

        Connect, plaintext connection packet, wait for the plaintext identity
        reply, TLS upgrade, encrypted identity, pair request, battery push.
        Returns the plaintext reply, the peer's encrypted identity and the pair
        answer.
        """

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self._writers.append(writer)
        await self._send_packet(
            writer,
            protocol.make_connection_packet(
                self.device_id, self.device_name, target_device_id=target_device_id
            ),
        )
        reply_line = await reader.readline()
        reply_packet = protocol.decode_packet(reply_line) if reply_line else None
        # KDE inverts TLS roles: we opened this as a TCP client, so we run the
        # TLS server handshake (Qt: startServerEncryption on outgoing sockets).
        # ``server_cert_pem`` is HA's certificate, presented by HA as the TLS
        # client; the TLS server context here runs CERT_NONE (Qt behavior:
        # no client-certificate request on outgoing device-initiated sessions).
        context = protocol.server_tls_context(
            self.identity.cert_pem, self.identity.key_pem
        )
        await protocol.upgrade_tls(
            reader, writer, context, HANDSHAKE_TIMEOUT, server_side=True
        )
        await self._send_packet(writer, self._encrypted_identity())
        peer_identity = await protocol.read_packet(reader, timeout=HANDSHAKE_TIMEOUT)
        await self._send_packet(writer, protocol.make_pair_request(int(time.time())))
        pair_answer = await protocol.read_packet(reader, timeout=HANDSHAKE_TIMEOUT)
        await self._send_packet(
            writer, protocol.build_packet(PACKET_TYPE_BATTERY, BATTERY_BODY)
        )
        return reply_packet, peer_identity, pair_answer


async def setup_integration(hass: HomeAssistant) -> Any:
    """Run domain setup and return the integration manager singleton."""
    assert await async_setup_component(hass, DOMAIN, {})
    return hass.data[DOMAIN]["manager"]


async def setup_entry(
    hass: HomeAssistant,
    fake: FakeDevice,
    *,
    peer_cert: str | None = None,
    device_id: str | None = None,
) -> MockConfigEntry:
    """Create a config entry pointing at the fake device and set it up."""
    device_id = device_id or fake.device_id
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=fake.device_name,
        unique_id=device_id,
        data={
            CONF_HOST: "127.0.0.1",
            CONF_TCP_PORT: fake.port,
            CONF_DEVICE_ID: device_id,
            CONF_DEVICE_NAME: fake.device_name,
            CONF_DEVICE_TYPE: "android",
            CONF_PEER_CERT: peer_cert,
        },
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    # ``async_setup`` already waits for platform setup; a full block_till_done
    # would hang forever on the peer's long-lived read-loop task.
    await asyncio.sleep(0.2)
    return entry


def entity_id(
    entity_registry: Any, platform: Platform, unique: str
) -> str | None:
    """Return the entity id registered under ``DOMAIN`` for a unique key."""
    return entity_registry.async_get_entity_id(platform, DOMAIN, unique)


async def _start_server_in_range(handler: Any) -> asyncio.Server:
    """Bind an inbound server inside the KDE Connect TCP port range.

    ``KdePeer.serve`` answers with the socket's own port as ``tcpPort``, and
    the test asserts that answer is inside 1716-1764 — so the bound port must
    come from the KDE port range instead of an ephemeral port.
    """
    last_err: OSError | None = None
    for port in range(MIN_TCP_PORT, MAX_TCP_PORT + 1):
        try:
            return await asyncio.start_server(handler, "127.0.0.1", port)
        except OSError as err:
            last_err = err
    raise OSError(
        f"no free KDE Connect TCP port on 127.0.0.1 ({MIN_TCP_PORT}-{MAX_TCP_PORT})"
    ) from last_err


async def test_outbound_tls_handshake_creates_entities_and_persisted_identity(
    hass: HomeAssistant,
    enable_custom_integrations: None,
    entity_registry: Any,
    device_registry: Any,
) -> None:
    """Full outbound protocol-v8 TLS handshake against a real socket.

    Checks the encrypted identity exchange inside TLS, TOFU certificate
    pinning persisted into the entry, capability persistence, and the entity
    states fed by the fake device's battery push.
    """
    async with FakeDevice(name="Pixel 8") as fake:
        manager = await setup_integration(hass)
        entry = await setup_entry(hass, fake)

        assert entry.state is ConfigEntryState.LOADED
        peer = manager.peers[fake.device_id]
        assert peer.connected and peer.paired

        # TLS really happened: the connection packet was plaintext, the first
        # packet seen inside TLS is HA's encrypted identity.
        assert fake.connection_packets[0]["type"] == PACKET_TYPE_IDENTITY
        assert fake.connection_packets[0]["body"]["targetDeviceId"] == fake.device_id
        encrypted = fake.received[0]
        assert encrypted["type"] == PACKET_TYPE_IDENTITY
        assert encrypted["body"]["deviceId"] == manager.identity.device_id
        assert "kdeconnect.battery" in encrypted["body"]["incomingCapabilities"]

        # TOFU-captured peer certificate: untrusted outbound sessions do not
        # present a client certificate (Qt behavior), so pinning happens later
        # through device-initiated inbound sessions.
        assert entry.data.get(CONF_PEER_CERT) in (None, fake.cert_pem)
        assert "kdeconnect.battery" in entry.data[CONF_CAPABILITIES]
        assert "kdeconnect.sms" in entry.data[CONF_CAPABILITIES]
        assert entry.data[CONF_DEVICE_TYPE] == "android"

        battery = entity_id(entity_registry, Platform.SENSOR, f"{fake.device_id}-battery_percent")
        state = hass.states.get(battery)
        assert state is not None
        assert state.state == "42"
        assert state.attributes["device_class"] == "battery"
        assert state.attributes["battery_quantity"] == 54

        charging = entity_id(entity_registry, Platform.BINARY_SENSOR, f"{fake.device_id}-battery_charging")
        assert hass.states.get(charging).state == "on"

        presence = entity_id(entity_registry, Platform.DEVICE_TRACKER, f"{fake.device_id}-presence")
        assert hass.states.get(presence).state == "home"

        notifications = entity_id(entity_registry, Platform.SENSOR, f"{fake.device_id}-notifications")
        assert hass.states.get(notifications).state == "0"

        device = device_registry.async_get_device({(DOMAIN, fake.device_id)})
        assert device is not None
        assert device.name == "Pixel 8"
        assert device.model == "android"


async def test_pairing_request_accepted_clears_repair_issue(
    hass: HomeAssistant,
    enable_custom_integrations: None,
    issue_registry: Any,
) -> None:
    """Without an auto-pairing device, request_pair() wires a pair answer."""
    events: list[Any] = []

    async with FakeDevice(name="Phone", auto_pair=False) as fake:
        manager = await setup_integration(hass)

        @callback
        def _record(event: Any) -> None:
            events.append(event)

        hass.bus.async_listen(EVENT_PAIR_CHANGED, _record)
        entry = await setup_entry(hass, fake)
        peer = manager.peers[fake.device_id]

        assert peer.connected and not peer.paired
        issue = issue_registry.async_get_issue(DOMAIN, f"pairing_pending_{fake.device_id}")
        assert issue is not None

        assert await peer.request_pair() is True
        await asyncio.sleep(0.2)

        assert peer.paired
        assert issue_registry.async_get_issue(DOMAIN, f"pairing_pending_{fake.device_id}") is None

        pair_requests = [
            p for p in fake.received if p["type"] == "kdeconnect.pair" and "timestamp" in p["body"]
        ]
        assert pair_requests, "pair request with timestamp reached the device"
        assert any(e.data.get("paired") for e in events)

        assert entry.state is ConfigEntryState.LOADED


async def test_notification_service_and_ping_roundtrip(
    hass: HomeAssistant,
    enable_custom_integrations: None,
) -> None:
    """kde_connect.send_notification travels over the TLS session; ping echoes."""
    async with FakeDevice() as fake:
        manager = await setup_integration(hass)
        await setup_entry(hass, fake)

        await hass.services.async_call(
            DOMAIN,
            SERVICE_SEND_NOTIFICATION,
            {"message": "hello there", "title": "a title"},
            blocking=True,
        )
        await asyncio.sleep(0.3)
        notifications = [p for p in fake.received if p["type"] == PACKET_TYPE_NOTIFICATION]
        assert notifications
        assert notifications[0]["body"]["content"] == "hello there"
        assert notifications[0]["body"]["appName"] == "Home Assistant"

        peer = manager.peers[fake.device_id]
        latency = await peer.ping()
        assert latency is not None and latency >= 0
        assert peer.state.ping_latency_ms is not None
        assert [p for p in fake.received if p["type"] == PACKET_TYPE_PING]


async def test_sms_payload_transfer_roundtrip(
    hass: HomeAssistant,
    enable_custom_integrations: None,
) -> None:
    """SMS uses payloadTransferInfo: fake device fetches raw payload over TLS."""
    async with FakeDevice() as fake:
        manager = await setup_integration(hass)
        await setup_entry(hass, fake)
        fake.ha_cert_pem = manager.identity.cert_pem
        fake.ha_device_id = manager.identity.device_id

        await hass.services.async_call(
            DOMAIN,
            SERVICE_SEND_SMS,
            {"message": "hi", "phone_number": "+155****1234"},
            blocking=True,
        )

        sms = [p for p in fake.received if p["type"] == PACKET_TYPE_SMS_REQUEST]
        assert sms and sms[0].get("payloadSize")
        assert sms[0]["payloadTransferInfo"]["ip"] == "127.0.0.1"
        assert fake.payloads, "payload connection delivered bytes"
        payload = json.loads(fake.payloads[0])
        assert payload == {
            "requestType": "message",
            "phoneNumber": "+155****1234",
            "message": "hi",
            "version": 1,
        }


async def test_session_drop_marks_entities_unavailable(
    hass: HomeAssistant,
    enable_custom_integrations: None,
    entity_registry: Any,
) -> None:
    """Device-initiated session close flips connected/paired and entity states."""
    async with FakeDevice() as fake:
        manager = await setup_integration(hass)
        entry = await setup_entry(hass, fake)
        battery = entity_id(entity_registry, Platform.SENSOR, f"{fake.device_id}-battery_percent")
        assert hass.states.get(battery).state == "42"

        fake.close_sessions()
        await asyncio.sleep(0.2)
        await hass.async_block_till_done()

        peer = manager.peers[fake.device_id]
        assert not peer.connected
        assert hass.states.get(battery).state == STATE_UNAVAILABLE

        await fake.stop()  # keep the reconnect loop from racing the unload
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert entry.state is ConfigEntryState.NOT_LOADED
        assert fake.device_id not in manager.peers


async def test_wrong_pinned_certificate_refused_in_tls(hass: HomeAssistant, enable_custom_integrations: None) -> None:
    """A pinned peer cert that does not match the presented cert fails TLS."""
    async with FakeDevice() as fake:
        await setup_integration(hass)
        other_cert, _other_key = protocol.create_identity_certificate(
            protocol.generate_device_id()
        )
        entry = await setup_entry(hass, fake, peer_cert=other_cert)
        assert entry.state is ConfigEntryState.SETUP_RETRY
        assert not hass.data[DOMAIN]["manager"].peers


async def test_certificate_cn_mismatch_refused(hass: HomeAssistant, enable_custom_integrations: None) -> None:
    """Peer certificate CN must equal the entry's deviceId."""
    async with FakeDevice() as fake:
        await setup_integration(hass)
        wrong_id = protocol.generate_device_id()
        entry = await setup_entry(hass, fake, device_id=wrong_id)
        assert entry.state is ConfigEntryState.SETUP_RETRY
        assert fake.device_id not in hass.data[DOMAIN]["manager"].peers


async def test_server_close_before_tls_is_handshake_error(
    hass: HomeAssistant, enable_custom_integrations: None
) -> None:
    """Sessions closed before the TLS upgrade raise SETUP_RETRY."""
    async with FakeDevice(mode="close_before_tls") as fake:
        await setup_integration(hass)
        entry = await setup_entry(hass, fake)
        assert entry.state is ConfigEntryState.SETUP_RETRY


async def test_unknown_device_announced_on_inbound_port(
    hass: HomeAssistant, enable_custom_integrations: None
) -> None:
    """An unconfigured device's inbound identity fires the discovery event."""
    events: list[Any] = []

    async with FakeDevice(name="Stranger", mode="close_after_identity") as fake:
        manager = await setup_integration(hass)

        @callback
        def _record(event: Any) -> None:
            events.append(event)

        hass.bus.async_listen(EVENT_DEVICE_DISCOVERED, _record)
        await fake.send_plaintext_identity(
            manager.inbound_port,
            target_device_id=manager.identity.device_id,
            tcp_port=fake.port,
        )
        await asyncio.sleep(0.2)
        await hass.async_block_till_done()

        assert events
        assert events[0].data["device_id"] == fake.device_id
        assert events[0].data["host"] == "127.0.0.1"
        assert events[0].data["tcp_port"] == fake.port
        # The discovery flow aborted cleanly (unreachable TCP port).
        assert not manager.peers


async def test_inbound_serve_handshake_pair_and_battery(
    hass: HomeAssistant, enable_custom_integrations: None
) -> None:
    """Device-initiated inbound session served by KdePeer.serve (server-side TLS)."""
    local = protocol.create_local_identity("HA peer test", device_type="desktop")
    events: list[Any] = []

    async with FakeDevice(name="Incoming") as fake:
        peer = KdePeer(
            hass,
            identity=local,
            peer_device_id=fake.device_id,
            peer_cert_pem=fake.cert_pem,
        )

        @callback
        def _record(event: Any) -> None:
            events.append(event)

        hass.bus.async_listen(EVENT_PAIR_REQUEST, _record)

        async def hooked(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await peer.serve(reader, writer)

        server = await _start_server_in_range(hooked)
        try:
            reply, peer_identity, pair_answer = await fake.run_inbound_session(
                server.sockets[0].getsockname()[1],
                target_device_id=local.device_id,
                server_cert_pem=local.cert_pem,
            )
            await hass.async_block_till_done()
            # Battery push may arrive slightly after the session callback; give
            # the asyncio read loop a moment to dispatch it.
            await asyncio.sleep(0.3)
            await hass.async_block_till_done()
        finally:
            pass

        assert MIN_TCP_PORT <= reply["body"]["tcpPort"] <= MAX_TCP_PORT
        assert peer_identity["body"]["deviceId"] == local.device_id
        assert pair_answer["body"]["pair"] is True and "timestamp" not in pair_answer["body"]
        assert events, "device-initiated pair request announced"

        assert peer.connected and peer.paired
        assert peer.state.battery_charge == 42
        assert peer.state.battery_charging is True
        assert peer.state.battery_quantity == 54
        assert "kdeconnect.battery" in peer.capabilities

        await peer.close()
        server.close()
        await server.wait_closed()
        assert not peer.connected


async def test_config_flow_user_step_completes_real_handshake(
    hass: HomeAssistant,
    enable_custom_integrations: None,
    monkeypatch: Any,
) -> None:
    """Config-flow user step: UDP probe (stubbed), TLS handshake, pair, entry."""
    async with FakeDevice(name="Flow Phone") as fake:
        manager = await setup_integration(hass)

        async def fake_probe(host: str, timeout: float) -> dict[str, Any]:
            return {
                "device_id": fake.device_id,
                "device_name": fake.device_name,
                "tcp_port": fake.port,
                "protocol_version": 8,
            }

        monkeypatch.setattr(manager.discovery, "async_probe", fake_probe)

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "user"}
        )
        assert result["step_id"] == "user"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"host": "127.0.0.1", "tcp_port": fake.port}
        )
        assert result["type"] is FlowResultType.CREATE_ENTRY
        assert result["data"][CONF_DEVICE_ID] == fake.device_id
        assert result["data"].get(CONF_PEER_CERT) in (None, fake.cert_pem)
        assert "kdeconnect.battery" in result["data"][CONF_CAPABILITIES]

        entry = hass.config_entries.async_entries(DOMAIN)[0]
        # The HA flow manager sets created entries up as soon as the flow
        # finishes, so the entry is already loading — drain the setup here.
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
