"""Sensor platform for KDE Connect peers."""

from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN
from .entities import (
    KdeBatteryPercentEntity,
    peer_has_battery_capability,
    sensor_entities_for_peer,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: Callable[[list[SensorEntity]], None],
) -> bool:
    """Add capability-gated sensor entities for one peer config entry."""
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime is None:
        return False

    entities: list[SensorEntity] = []
    for device_id, peer in runtime["peers"].items():
        state = runtime["states"][device_id]
        entities.extend(sensor_entities_for_peer(peer, state))
        if peer_has_battery_capability(peer) and state.battery_charge is not None:
            entities.append(KdeBatteryPercentEntity(peer, state))
        elif peer_has_battery_capability(peer):
            added = False

            @callback
            def _maybe_add_battery(_state=state, _peer=peer) -> None:
                nonlocal added
                if added or _state.battery_charge is None:
                    return
                added = True
                async_add_entities([KdeBatteryPercentEntity(_peer, _state)])

            state.add_listener(_maybe_add_battery)
            entry.async_on_unload(
                lambda _s=state, _cb=_maybe_add_battery: _s.remove_listener(_cb)
            )

    async_add_entities(entities)
    return True
