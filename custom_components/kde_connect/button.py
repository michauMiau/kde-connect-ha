"""Button platform for KDE Connect remote commands."""

from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN, PACKET_TYPE_RUNCOMMAND
from .entities import DeviceState, KdeEntityBase


class KdeRunCommandButton(KdeEntityBase, ButtonEntity):
    """Button to trigger a remote runcommand on the peer device."""

    _attr_has_entity_name = True

    def __init__(self, peer, state: DeviceState, key: str, name: str) -> None:
        super().__init__(peer, state)
        self._key = key
        self._attr_name = name or key
        self._attr_unique_id = f"{peer.device_id}-runcommand-{key}"

    async def async_press(self) -> None:
        await self._peer.run_command(self._key)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: Callable[[list[ButtonEntity]], None],
) -> bool:
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime is None:
        return False

    for device_id, peer in runtime["peers"].items():
        if PACKET_TYPE_RUNCOMMAND not in peer.capabilities:
            continue
        state = runtime["states"][device_id]
        known: set[str] = set()

        @callback
        def _sync_commands(_peer=peer, _state=state, _known=known) -> None:
            commands = getattr(_peer, "commands", {}) or {}
            new = []
            for key, info in commands.items():
                if key in _known:
                    continue
                _known.add(key)
                name = (info or {}).get("name") or key
                new.append(KdeRunCommandButton(_peer, _state, key, name))
            if new:
                async_add_entities(new)

        _sync_commands()
        state.add_listener(_sync_commands)

    return True
