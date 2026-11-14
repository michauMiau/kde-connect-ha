"""Binary sensor platform for KDE Connect peers."""

from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN
from .entities import KdeBatteryChargingEntity, peer_has_battery_capability


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: Callable[[list[BinarySensorEntity]], None],
) -> bool:
    """Add battery charging entity when the peer reports battery data."""
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime is None:
        return False

    for device_id, peer in runtime["peers"].items():
        if not peer_has_battery_capability(peer):
            continue
        state = runtime["states"][device_id]
        if state.battery_charge is not None or state.battery_charging is not None:
            async_add_entities([KdeBatteryChargingEntity(peer, state)])
            continue
        added = False

        @callback
        def _maybe_add(_state=state, _peer=peer) -> None:
            nonlocal added
            if added or (
                _state.battery_charge is None and _state.battery_charging is None
            ):
                return
            added = True
            async_add_entities([KdeBatteryChargingEntity(_peer, _state)])

        state.add_listener(_maybe_add)

    return True
