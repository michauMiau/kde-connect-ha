"""Device tracker platform for KDE Connect peers (delegates to entities.py)."""

from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.device_tracker import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .entities import device_tracker_entities_for_peer


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: Callable[[list[ScannerEntity]], None],
) -> bool:
    """Add presence entities for one peer config entry."""
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime is None:
        return False

    entities: list[ScannerEntity] = []
    for device_id, peer in runtime["peers"].items():
        entities.extend(device_tracker_entities_for_peer(peer, runtime["states"][device_id]))

    async_add_entities(entities)
    return True
