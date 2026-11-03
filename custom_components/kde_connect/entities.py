"""Push-driven entities for KDE Connect peers (no polling).

Entity state is read live from the shared ``DeviceState`` of one peer: the
transport pushes packets into ``DeviceState`` and calls ``notify_changed()``,
which triggers ``async_write_ha_state()`` on the registered entities. The peer
object (peer.py, class KdePeer) is duck-typed here: it must expose
``device_id``, ``device_name``, ``device_type``, ``capabilities`` (set of
incoming packet type strings), and boolean properties ``connected`` (TCP TLS
link open) and ``paired``. Availability is ``connected and paired``.

NOTE: HA core (verified against 2026.2.3) has no ``DeviceTrackerEntity`` base
class and no ``SourceType.COMPUTER``; the presence entity base is
``ScannerEntity`` (state ``home``/``not_home`` from ``is_connected``), so this
integration uses ``ScannerEntity`` with ``SourceType.ROUTER`` as the closest
supported presence source.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.components.device_tracker import (
    ScannerEntity,
    ScannerEntityDescription,
    SourceType,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTime
from homeassistant.core import callback
from homeassistant.helpers.entity import DeviceInfo, Entity

from .const import (
    DOMAIN,
    PACKET_TYPE_BATTERY,
    PACKET_TYPE_NOTIFICATION,
    PACKET_TYPE_PING,
    PACKET_TYPE_SMS_MESSAGES,
)

if TYPE_CHECKING:
    from .peer import KdePeer


@dataclass
class DeviceState:
    """Live per-peer state mutated by push packet handlers.

    The transport (peer.py / __init__.py) updates the fields when push packets
    arrive and then calls ``notify_changed()``; entities registered against
    this state re-write their HA state immediately.
    """

    battery_charge: int | None = None
    battery_charging: bool | None = None
    battery_quantity: int | None = None
    last_seen: datetime | None = None
    ping_latency_ms: float | None = None
    notification_count: int = 0
    sms_unread_count: int = 0
    notifications: list[dict[str, Any]] = field(default_factory=list)

    _listeners: list[Callable[[], None]] = field(default_factory=list, repr=False)

    def add_listener(self, listener: Callable[[], None]) -> None:
        """Register a callable invoked whenever state changes."""
        self._listeners.append(listener)

    def notify_changed(self) -> None:
        """Tell all registered entities to re-read state and write it."""
        for listener in self._listeners:
            listener()


class KdeEntityBase(Entity):
    """Shared base: device info, availability, push-driven updates."""

    _attr_has_entity_name = True

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the entity with live references (never copies)."""
        self._peer = peer
        self._state = state

    @property
    def available(self) -> bool:
        """Peer is available while the TLS link is open and paired."""
        return bool(self._peer.connected and self._peer.paired)

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry info for the KDE Connect peer."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._peer.device_id)},
            name=self._peer.device_name,
            model=self._peer.device_type,
        )

    async def async_added_to_hass(self) -> None:
        """Re-write state whenever push handlers change the shared state."""
        await super().async_added_to_hass()
        self._state.add_listener(self._handle_state_change)

    @callback
    def _handle_state_change(self) -> None:
        self.async_write_ha_state()


class KdeBatteryPercentEntity(KdeEntityBase, SensorEntity):
    """Battery percent sensor fed by kdeconnect.battery pushes."""

    entity_description: SensorEntityDescription

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the battery percent sensor."""
        super().__init__(peer, state)
        self.entity_description = BATTERY_PERCENT_DESCRIPTION
        self._attr_unique_id = f"{peer.device_id}-{BATTERY_PERCENT_DESCRIPTION.key}"

    @property
    def native_value(self) -> int | None:
        """Return the current battery charge percent, or None if unknown."""
        return self._state.battery_charge

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the battery quantity attribute when the peer reports it."""
        attr: dict[str, Any] = {}
        if self._state.battery_quantity is not None:
            attr["battery_quantity"] = self._state.battery_quantity
        return attr


class KdeBatteryChargingEntity(KdeEntityBase, BinarySensorEntity):
    """Charging binary sensor fed by kdeconnect.battery pushes."""

    entity_description: BinarySensorEntityDescription

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the battery charging binary sensor."""
        super().__init__(peer, state)
        self.entity_description = BATTERY_CHARGING_DESCRIPTION
        self._attr_unique_id = f"{peer.device_id}-{BATTERY_CHARGING_DESCRIPTION.key}"

    @property
    def is_on(self) -> bool | None:
        """Return True while the device is charging."""
        return self._state.battery_charging


class KdePingLatencyEntity(KdeEntityBase, SensorEntity):
    """Ping latency (ms) sensor updated by kdeconnect.ping round trips."""

    entity_description: SensorEntityDescription

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the ping latency sensor."""
        super().__init__(peer, state)
        self.entity_description = PING_LATENCY_DESCRIPTION
        self._attr_unique_id = f"{peer.device_id}-{PING_LATENCY_DESCRIPTION.key}"

    @property
    def native_value(self) -> float | None:
        """Return the last ping round-trip in ms, or None if unmeasured."""
        return self._state.ping_latency_ms


class KdeNotificationsReceivedEntity(KdeEntityBase, SensorEntity):
    """Counter of notifications received via kdeconnect.notification pushes."""

    entity_description: SensorEntityDescription

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the received-notification counter."""
        super().__init__(peer, state)
        self.entity_description = NOTIFICATIONS_DESCRIPTION
        self._attr_unique_id = f"{peer.device_id}-{NOTIFICATIONS_DESCRIPTION.key}"

    @property
    def native_value(self) -> int:
        """Return the count of notifications received."""
        return self._state.notification_count

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the notification list and the last-seen timestamp."""
        attr: dict[str, Any] = {"notifications": self._state.notifications}
        if self._state.last_seen is not None:
            attr["last_seen"] = self._state.last_seen
        return attr


class KdeSmsUnreadEntity(KdeEntityBase, SensorEntity):
    """Unread SMS counter fed by kdeconnect.sms.messages pushes."""

    entity_description: SensorEntityDescription

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the unread SMS counter."""
        super().__init__(peer, state)
        self.entity_description = SMS_UNREAD_DESCRIPTION
        self._attr_unique_id = f"{peer.device_id}-{SMS_UNREAD_DESCRIPTION.key}"

    @property
    def native_value(self) -> int:
        """Return the count of unread SMS messages."""
        return self._state.sms_unread_count


class KdePresenceEntity(KdeEntityBase, ScannerEntity):
    """Presence entity: home while the TLS link is open and paired.

    HA core has no ``SourceType.COMPUTER`` (verified 2026.2.3); ``ROUTER`` is
    the closest presence source for a TCP peer connection.
    """

    entity_description: ScannerEntityDescription

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the peer presence scanner."""
        super().__init__(peer, state)
        self.entity_description = PRESENCE_DESCRIPTION
        self._attr_source_type = SourceType.ROUTER

    @property
    def unique_id(self) -> str:
        """Stable unique id from the peer device id."""
        return f"{self._peer.device_id}-{PRESENCE_DESCRIPTION.key}"

    @property
    def hostname(self) -> str | None:
        """Return the peer device name."""
        return self._peer.device_name

    @property
    def is_connected(self) -> bool:
        """Home when the TLS link is open and pairing is established."""
        return bool(self._peer.connected and self._peer.paired)


BATTERY_PERCENT_DESCRIPTION = SensorEntityDescription(
    key="battery_percent",
    native_unit_of_measurement=PERCENTAGE,
    device_class=SensorDeviceClass.BATTERY,
    state_class=SensorStateClass.MEASUREMENT,
)

BATTERY_CHARGING_DESCRIPTION = BinarySensorEntityDescription(
    key="battery_charging",
    device_class=BinarySensorDeviceClass.BATTERY_CHARGING,
    entity_category=EntityCategory.DIAGNOSTIC,
)

PING_LATENCY_DESCRIPTION = SensorEntityDescription(
    key="ping_latency",
    native_unit_of_measurement=UnitOfTime.MILLISECONDS,
    device_class=SensorDeviceClass.DURATION,
    state_class=SensorStateClass.MEASUREMENT,
    entity_category=EntityCategory.DIAGNOSTIC,
)

NOTIFICATIONS_DESCRIPTION = SensorEntityDescription(
    key="notifications",
    state_class=SensorStateClass.TOTAL_INCREASING,
    entity_category=EntityCategory.DIAGNOSTIC,
)

SMS_UNREAD_DESCRIPTION = SensorEntityDescription(
    key="sms_unread",
    state_class=SensorStateClass.TOTAL,
    entity_category=EntityCategory.DIAGNOSTIC,
)

PRESENCE_DESCRIPTION = ScannerEntityDescription(
    key="presence",
    entity_category=EntityCategory.DIAGNOSTIC,
)


def entity_descriptions_for_peer(peer: KdePeer) -> list[str]:
    """Capability-gated entity keys the peer can support (informational)."""
    caps = peer.capabilities
    keys: list[str] = []
    if PACKET_TYPE_BATTERY in caps:
        keys.append(BATTERY_PERCENT_DESCRIPTION.key)
    if PACKET_TYPE_PING in caps:
        keys.append(PING_LATENCY_DESCRIPTION.key)
    if PACKET_TYPE_NOTIFICATION in caps:
        keys.append(NOTIFICATIONS_DESCRIPTION.key)
    if PACKET_TYPE_SMS_MESSAGES in caps:
        keys.append(SMS_UNREAD_DESCRIPTION.key)
    keys.append(PRESENCE_DESCRIPTION.key)
    return keys


def sensor_entities_for_peer(peer: KdePeer, state: DeviceState) -> list[SensorEntity]:
    """Sensor entities gated on the peer's advertised capabilities."""
    entities: list[SensorEntity] = []
    caps = peer.capabilities
    if PACKET_TYPE_BATTERY in caps:
        entities.append(KdeBatteryPercentEntity(peer, state))
    if PACKET_TYPE_PING in caps:
        entities.append(KdePingLatencyEntity(peer, state))
    if PACKET_TYPE_NOTIFICATION in caps:
        entities.append(KdeNotificationsReceivedEntity(peer, state))
    if PACKET_TYPE_SMS_MESSAGES in caps:
        entities.append(KdeSmsUnreadEntity(peer, state))
    return entities


def binary_sensor_entities_for_peer(peer: KdePeer, state: DeviceState) -> list[BinarySensorEntity]:
    """Binary sensor entities gated on the peer's advertised capabilities."""
    if PACKET_TYPE_BATTERY in peer.capabilities:
        return [KdeBatteryChargingEntity(peer, state)]
    return []


def device_tracker_entities_for_peer(peer: KdePeer, state: DeviceState) -> list[ScannerEntity]:
    """Presence entity for every peer (link state is always meaningful)."""
    return [KdePresenceEntity(peer, state)]
