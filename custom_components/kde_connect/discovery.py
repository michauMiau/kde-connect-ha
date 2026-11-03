"""UDP discovery (announce) for KDE Connect peers.

KDE Connect devices announce themselves over UDP port 1716: every device on
the LAN periodically broadcasts a ``kdeconnect.identity`` packet and replies
to our own broadcast with its identity. This module:

- broadcasts our HA identity (stable local deviceId) every
  ``DISCOVERY_INTERVAL`` seconds, so devices can discover Home Assistant;
- listens on UDP 1716 for device identity packets;
- fires ``EVENT_DEVICE_DISCOVERED`` and starts a discovery config flow for
  devices we have not configured yet (per-device rate limit);
- offers ``async_probe`` for the config flow: send an identity packet to a
  specific host and wait for its reply (device id + tcp port).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.core import HomeAssistant, callback

from .const import (
    DISCOVERY_INTERVAL,
    DOMAIN,
    EVENT_DEVICE_DISCOVERED,
    PACKET_TYPE_IDENTITY,
    PROTOCOL_VERSION,
    UDP_PORT,
)
from .protocol import (
    decode_packet,
    encode_packet,
    make_udp_discovery_packet,
    valid_device_id,
)

_LOGGER = logging.getLogger(__name__)

# Minimum seconds between discovery events / flow starts for the same device.
_RATE_LIMIT = 15.0


class KdeConnectDiscovery:
    """UDP announce broadcaster + identity listener."""

    def __init__(self, hass: HomeAssistant, manager: Any) -> None:
        """Store the manager (identity source) and initialize state."""
        self._hass = hass
        self._manager = manager
        self._transport: asyncio.DatagramTransport | None = None
        self._broadcast_task: asyncio.Task[None] | None = None
        self._last_seen: dict[str, float] = {}
        self._pending_probes: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._started = False

    async def async_start(self) -> None:
        """Bind the UDP listener and start the announce broadcast loop."""
        if self._started:
            return
        self._started = True

        def factory() -> KdeConnectDiscovery:
            return self

        try:
            transport, _protocol = await self._hass.loop.create_datagram_endpoint(
                factory,
                local_addr=("0.0.0.0", UDP_PORT),
                allow_broadcast=True,
                reuse_port=True,
            )
        except OSError:
            _LOGGER.warning("Could not bind KDE Connect UDP discovery port %s", UDP_PORT)
            self._started = False
            return

        self._transport = transport
        self._broadcast_task = self._hass.async_create_background_task(
            self._async_broadcast_loop(), "kde_connect_announce", eager_start=True
        )

    async def async_stop(self) -> None:
        """Stop broadcasting and close the UDP socket."""
        self._started = False
        if self._broadcast_task is not None:
            self._broadcast_task.cancel()
            self._broadcast_task = None
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        for future in self._pending_probes.values():
            if not future.done():
                future.cancel()
        self._pending_probes.clear()

    def _announce_packet(self) -> bytes | None:
        """Serialized identity packet for our local identity."""
        device_id = self._manager.local_device_id
        if not device_id:
            return None
        packet = make_udp_discovery_packet(
            str(device_id),
            str(self._manager.local_device_name),
            int(self._manager.inbound_port or UDP_PORT),
        )
        return encode_packet(packet)

    async def _async_broadcast_loop(self) -> None:
        """Broadcast our identity periodically until stopped."""
        while self._started and self._transport is not None:
            packet = self._announce_packet()
            if packet is not None:
                try:
                    self._transport.sendto(packet, ("255.255.255.255", UDP_PORT))
                except OSError:
                    _LOGGER.debug("KDE Connect UDP broadcast failed", exc_info=True)
            await asyncio.sleep(DISCOVERY_INTERVAL)

    # ------------------------------------------------------------------ socket
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        """Asyncio protocol hook: socket bound."""
        self._transport = transport

    def connection_lost(self, exc: Exception | None) -> None:
        """Asyncio protocol hook: socket closed."""

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Asyncio protocol hook: dispatch identity packets."""
        try:
            packet = decode_packet(data)
        except Exception:  # noqa: BLE001 - ignore malformed UDP frames
            return
        if packet.get("type") != PACKET_TYPE_IDENTITY:
            return
        body = packet.get("body") or {}
        device_id = body.get("deviceId")
        if not valid_device_id(device_id):
            return
        if self._manager.local_device_id and device_id == self._manager.local_device_id:
            return
        self._async_handle_identity(str(device_id), str(addr[0]), body)

    @callback
    def _async_handle_identity(
        self, device_id: str, host: str, body: dict[str, Any]
    ) -> None:
        """A device identity arrived: answer pending probes or announce."""
        future = self._pending_probes.pop(host, None)
        if future is not None and not future.done():
            future.set_result(
                {
                    "device_id": device_id,
                    "device_name": str(body.get("deviceName", "")),
                    "tcp_port": _tcp_port(body.get("tcpPort")),
                    "protocol_version": int(body.get("protocolVersion", PROTOCOL_VERSION)),
                }
            )
            return

        now = self._hass.loop.time()
        if device_id in self._last_seen and now - self._last_seen[device_id] < _RATE_LIMIT:
            return
        self._last_seen[device_id] = now

        data: dict[str, Any] = {
            "device_id": device_id,
            "host": host,
            "device_name": str(body.get("deviceName", "")),
            "tcp_port": _tcp_port(body.get("tcpPort")),
            "protocol_version": int(body.get("protocolVersion", PROTOCOL_VERSION)),
        }
        self._hass.bus.async_fire(EVENT_DEVICE_DISCOVERED, data)

        # A UDP reply from a device we have not configured -> discovery flow.
        self._hass.async_create_background_task(
            self._async_start_discovery_flow(data),
            f"kde_connect_discovery_{device_id}",
            eager_start=True,
        )

    async def _async_start_discovery_flow(self, data: dict[str, Any]) -> None:
        """Kick off a discovery config flow for an unknown device."""
        try:
            await self._hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": "discovery", "unique_id": data["device_id"]},
                data=data,
            )
        except Exception:  # noqa: BLE001 - discovery flow may race with entry setup
            _LOGGER.debug("KDE Connect discovery flow init failed", exc_info=True)

    async def async_probe(self, host: str, timeout: float) -> dict[str, Any] | None:
        """Send an identity packet to ``host`` and wait for its identity reply."""
        if self._transport is None:
            return None
        packet = self._announce_packet()
        if packet is None:
            return None
        future: asyncio.Future[dict[str, Any]] = self._hass.loop.create_future()
        self._pending_probes[host] = future
        try:
            self._transport.sendto(packet, (host, UDP_PORT))
            return await asyncio.wait_for(future, timeout=timeout)
        except (TimeoutError, asyncio.CancelledError, OSError):
            return None
        finally:
            self._pending_probes.pop(host, None)


def _tcp_port(value: Any) -> int:
    """UDP ``tcpPort`` is a string on the wire; tolerate ints."""
    try:
        return int(value) if value is not None else UDP_PORT
    except (TypeError, ValueError):
        return UDP_PORT
