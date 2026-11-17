"""Media player platform for KDE Connect MPRIS remote control."""

from __future__ import annotations

import math
from collections.abc import Callable
from typing import Any

from homeassistant.components.media_player import (
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaPlayerState,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PACKET_TYPE_MPRIS_REQUEST
from .entities import DeviceState, KdeEntityBase


class KdeMprisMediaPlayer(KdeEntityBase, MediaPlayerEntity):
    """Control the active media player on the remote KDE Connect device."""

    _attr_has_entity_name = True
    _attr_name = "Media player"

    def __init__(self, peer, state: DeviceState) -> None:
        super().__init__(peer, state)
        self._attr_unique_id = f"{peer.device_id}-mpris"

    @property
    def available(self) -> bool:
        return bool(
            self._peer.connected
            and self._peer.paired
            and PACKET_TYPE_MPRIS_REQUEST in self._peer.send_capabilities
        )

    @property
    def _player(self) -> dict[str, Any]:
        players = self._state.mpris_players or {}
        current = self._state.mpris_current_player
        if current and current in players:
            return players[current]
        if players:
            return next(iter(players.values()))
        return {}

    @property
    def state(self) -> MediaPlayerState | None:
        if not self._state.mpris_players:
            return MediaPlayerState.IDLE
        player = self._player
        if player.get("isPlaying"):
            return MediaPlayerState.PLAYING
        if player.get("pos", -1) >= 0 or player.get("title") or player.get("artist"):
            return MediaPlayerState.PAUSED
        return MediaPlayerState.IDLE

    @property
    def supported_features(self) -> MediaPlayerEntityFeature:
        features = MediaPlayerEntityFeature(0)
        player = self._player
        if player.get("canPlay") or player.get("canPause") or self._state.mpris_players:
            features |= MediaPlayerEntityFeature.PLAY | MediaPlayerEntityFeature.PAUSE
        if player.get("canGoNext", True) and self._state.mpris_players:
            features |= MediaPlayerEntityFeature.NEXT_TRACK
        if player.get("canGoPrevious", True) and self._state.mpris_players:
            features |= MediaPlayerEntityFeature.PREVIOUS_TRACK
        if player.get("canSeek"):
            features |= MediaPlayerEntityFeature.SEEK
        if "volume" in player:
            features |= MediaPlayerEntityFeature.VOLUME_SET
        if len(self._state.mpris_players) > 1:
            features |= MediaPlayerEntityFeature.SELECT_SOURCE
        return features

    @property
    def media_title(self) -> str | None:
        return self._player.get("title") or None

    @property
    def media_artist(self) -> str | None:
        return self._player.get("artist") or None

    @property
    def media_album_name(self) -> str | None:
        return self._player.get("album") or None

    @property
    def media_duration(self) -> int | None:
        length = self._player.get("length")
        if length is None or length <= 0:
            return None
        return int(length // 1000)

    @property
    def media_position(self) -> int | None:
        pos = self._player.get("pos")
        if pos is None or pos < 0:
            return None
        return int(pos // 1000)

    @property
    def volume_level(self) -> float | None:
        vol = self._player.get("volume")
        if vol is None:
            return None
        try:
            level = max(0.0, min(1.0, float(vol) / 100.0))
        except (TypeError, ValueError):
            return None
        return level if math.isfinite(level) else None

    @property
    def source(self) -> str | None:
        return self._state.mpris_current_player

    @property
    def source_list(self) -> list[str]:
        return list(self._state.mpris_players.keys())

    async def async_media_play(self) -> None:
        await self._peer.mpris_action("Play")

    async def async_media_pause(self) -> None:
        await self._peer.mpris_action("Pause")

    async def async_media_play_pause(self) -> None:
        await self._peer.mpris_action("PlayPause")

    async def async_media_next_track(self) -> None:
        await self._peer.mpris_action("Next")

    async def async_media_previous_track(self) -> None:
        await self._peer.mpris_action("Previous")

    async def async_media_seek(self, position: float) -> None:
        await self._peer.mpris_set_position(int(position * 1000))

    async def async_set_volume_level(self, volume: float) -> None:
        await self._peer.mpris_set_volume(int(volume * 100))

    async def async_select_source(self, source: str) -> None:
        await self._peer.mpris_set_player(source)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: Callable[[list[MediaPlayerEntity]], None],
) -> bool:
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime is None:
        return False
    entities: list[MediaPlayerEntity] = []
    for device_id, peer in runtime["peers"].items():
        if PACKET_TYPE_MPRIS_REQUEST in peer.send_capabilities:
            entities.append(KdeMprisMediaPlayer(peer, runtime["states"][device_id]))
    if entities:
        async_add_entities(entities)
    return True
