"""UDP discovery (announce) for KDE Connect peers.

By default this integration does NOT broadcast or sweep the network. The UDP
listener binds port 1716 so manual probes from config flow can discover devices.
Identity packets heard passively fire ``EVENT_DEVICE_DISCOVERED`` (informational)
but never auto-start config flows.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.core import HomeAssistant, callback

from .const import (
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

_RATE_LIMIT = 15.0


class KdeConnectDiscovery:
    """UDP listener (+ optional manual probe helpers)."""

    def __init__(self, hass: HomeAssistant, manager: Any) -> None:
        self._hass = hass
        self._manager = manager
        self._transport: asyncio.DatagramTransport | None = None
        self._last_seen: dict[str, float] = {}
        self._pending_probes: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._started = False

    async def async_start(self) -> None:
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
        _LOGGER.info("KDE Connect UDP discovery listener bound on port %s", UDP_PORT)

    async def async_stop(self) -> None:
        self._started = False
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        for future in self._pending_probes.values():
            if not future.done():
                future.cancel()
        self._pending_probes.clear()

    def _announce_packet(self) -> bytes | None:
        device_id = self._manager.local_device_id
        if not device_id:
            return None
        packet = make_udp_discovery_packet(
            str(device_id),
            str(self._manager.local_device_name),
            int(self._manager.inbound_port or UDP_PORT),
        )
        return encode_packet(packet)

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def connection_lost(self, exc: Exception | None) -> None:
        pass

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            packet = decode_packet(data)
        except Exception:  # noqa: BLE001
            return
        if packet.get("type") != PACKET_TYPE_IDENTITY:
            return
        body = packet.get("body") or {}
        device_id = body.get("deviceId")
        if not valid_device_id(device_id):
            return
        if self._manager.local_device_id and device_id == self._manager.local_device_id:
            return
        _LOGGER.info("KDE Connect identity packet from %s: %s", addr[0], device_id)
        self._async_handle_identity(str(device_id), str(addr[0]), body)

    @callback
    def _async_handle_identity(self, device_id: str, host: str, body: dict[str, Any]) -> None:
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

    async def async_probe(self, host: str, timeout: float) -> dict[str, Any] | None:
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

    async def async_probe_subnet(self, timeout: float = 3.0) -> list[dict[str, Any]]:
        """One-shot unicast probe of local /24 (manual scan). Returns discovered devices."""
        if self._transport is None:
            return []
        packet = self._announce_packet()
        if packet is None:
            return []
        from .protocol import local_ipv4

        local = local_ipv4()
        if local.count(".") != 3:
            return []
        prefix = local.rsplit(".", 1)[0]
        results: dict[str, dict[str, Any]] = {}

        async def _wait_for(host: str) -> None:
            if host in self._pending_probes:
                return
            fut: asyncio.Future[dict[str, Any]] = self._hass.loop.create_future()
            self._pending_probes[host] = fut
            try:
                res = await asyncio.wait_for(fut, timeout=timeout)
                results[str(res["device_id"])] = {
                    "device_id": res["device_id"],
                    "device_name": res.get("device_name") or "",
                    "host": host,
                    "tcp_port": int(res.get("tcp_port") or UDP_PORT),
                    "protocol_version": int(res.get("protocol_version") or PROTOCOL_VERSION),
                }
            except (TimeoutError, asyncio.CancelledError, OSError):
                pass
            finally:
                self._pending_probes.pop(host, None)

        waiters = [asyncio.create_task(_wait_for(f"{prefix}.{i}")) for i in range(1, 255) if f"{prefix}.{i}" != local]
        await asyncio.sleep(0.1)
        for i in range(1, 255):
            target = f"{prefix}.{i}"
            if target == local:
                continue
            try:
                self._transport.sendto(packet, (target, UDP_PORT))
            except OSError:
                continue
        for w in waiters:
            try:
                await w
            except (asyncio.CancelledError, Exception):
                _LOGGER.debug("KDE Connect probe waiter ended", exc_info=True)
        return list(results.values())


def _tcp_port(value: Any) -> int:
    try:
        return int(value) if value is not None else UDP_PORT
    except (TypeError, ValueError):
        return UDP_PORT
