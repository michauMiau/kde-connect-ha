"""Button platform: one button per local run-command configured in options."""

from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from . import _parse_local_commands
from .const import CONF_LOCAL_COMMANDS, DOMAIN
from .entities import DeviceState, KdeEntityBase


class KdeRunCommandButton(KdeEntityBase, ButtonEntity):
    """Press to run one of this HA instance's local commands."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:console"

    def __init__(
        self, peer, state: DeviceState, key: str, command: str
    ) -> None:
        super().__init__(peer, state)
        self._key = key
        self._command = command
        self._attr_name = key
        self._attr_unique_id = f"{peer.device_id}-runcommand-{key}"

    async def async_press(self) -> None:
        """Run the configured command locally."""
        await self._peer.run_local_command(self._key)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: Callable[[list[ButtonEntity]], None],
) -> bool:
    """Add one button per configured local command for every peer."""
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime is None:
        return False
    commands = _parse_local_commands((entry.options or {}).get(CONF_LOCAL_COMMANDS))
    entities: list[ButtonEntity] = []
    for device_id, peer in runtime["peers"].items():
        for key, command in commands.items():
            entities.append(
                KdeRunCommandButton(peer, runtime["states"][device_id], key, command)
            )
    if entities:
        async_add_entities(entities)
    return True
