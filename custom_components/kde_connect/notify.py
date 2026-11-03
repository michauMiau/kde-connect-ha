"""Notify entities for KDE Connect peers: device notifications and SMS.

Peer contract (peer.py, class KdePeer): ``await peer.send_packet(packet_type, body)``
plus properties ``connected``, ``paired`` and ``capabilities`` (outgoing-capability
strings such as ``"kdeconnect.notification"`` / ``"kdeconnect.sms.request"``).
Entities reuse ``KdeEntityBase`` from entities.py for device info, availability
(``connected and paired``) and push-driven state updates.

KDE Connect wire semantics (protocol v8):
- Notification TO the device: packet type ``kdeconnect.notification`` with body
  ``id``, ``title``, ``content``, ``appName``, ``isNotification`` (true to display).
- SMS request: packet type ``kdeconnect.sms.request`` with body
  ``{"version": 1, "addresses": [{"address": ...}], "messageBody": ...}``.

HA core (verified against 2026.2.3) has no ``NotifyEntityFeature.TARGET``; SMS
recipients are therefore passed as a ``target`` keyword argument to
``async_send_message``. Entity names come from ``has_entity_name`` + the
``entity_description`` keys ``notification`` / ``sms`` (strings.json).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
import uuid

from homeassistant.components.notify import (
    NotifyEntity,
    NotifyEntityDescription,
    NotifyEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError

from .const import (
    DOMAIN,
    PACKET_TYPE_NOTIFICATION,
    PACKET_TYPE_SMS_REQUEST,
    SMS_REQUEST_PACKET_VERSION,
)
from .entities import DeviceState, KdeEntityBase

if TYPE_CHECKING:
    from collections.abc import Callable

    from .peer import KdePeer

APP_NAME: str = "Home Assistant"


class KdeNotificationNotifyEntity(KdeEntityBase, NotifyEntity):
    """Notify entity that displays a notification on the paired device."""

    entity_description: NotifyEntityDescription
    _attr_supported_features = NotifyEntityFeature.TITLE

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the device notification entity."""
        super().__init__(peer, state)
        self.entity_description = DEVICE_NOTIFICATION_DESCRIPTION
        self._attr_unique_id = f"{peer.device_id}-notify"

    async def async_send_message(self, message: str, title: str | None = None) -> None:
        """Push a notification to the device (kdeconnect.notification packet)."""
        if not self._peer.connected or not self._peer.paired:
            raise ServiceValidationError("KDE Connect peer is not connected or paired")

        notification_id = str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": notification_id,
            "title": title or "",
            "content": message,
            "appName": APP_NAME,
            "isNotification": True,
            "notificationId": notification_id,
            "openBrowser": False,
        }
        await self._peer.send_packet(PACKET_TYPE_NOTIFICATION, body)


class KdeSmsNotifyEntity(KdeEntityBase, NotifyEntity):
    """Notify entity that sends an SMS through the paired device.

    Recipients (``target``): a phone number string or a list of phone number
    strings. ``title`` is accepted for the notify entity service signature but
    ignored — SMS messages have no title on the wire.
    """

    entity_description: NotifyEntityDescription

    def __init__(self, peer: KdePeer, state: DeviceState) -> None:
        """Initialize the SMS notify entity."""
        super().__init__(peer, state)
        self.entity_description = SMS_DESCRIPTION
        self._attr_unique_id = f"{peer.device_id}-sms"

    async def async_send_message(
        self,
        message: str,
        title: str | None = None,
        *,
        target: Any = None,
    ) -> None:
        """Send SMS to recipient(s) (kdeconnect.sms.request packet)."""
        if not self._peer.connected or not self._peer.paired:
            raise ServiceValidationError("KDE Connect peer is not connected or paired")

        recipients: list[str]
        if isinstance(target, str):
            recipients = [target]
        elif isinstance(target, list):
            recipients = [str(addr) for addr in target]
        elif target is None:
            raise ServiceValidationError(
                "SMS target required: pass a phone number or list of phone numbers"
            )
        else:
            raise ServiceValidationError(f"Unsupported SMS target: {target!r}")

        if not recipients:
            raise ServiceValidationError(
                "SMS target required: pass a phone number or list of phone numbers"
            )

        body: dict[str, Any] = {
            "version": SMS_REQUEST_PACKET_VERSION,
            "addresses": [{"address": addr} for addr in recipients],
            "messageBody": message,
        }
        await self._peer.send_packet(PACKET_TYPE_SMS_REQUEST, body)


DEVICE_NOTIFICATION_DESCRIPTION = NotifyEntityDescription(
    key="notification",
    icon="mdi:bell",
)

SMS_DESCRIPTION = NotifyEntityDescription(
    key="sms",
    icon="mdi:message",
    entity_category=EntityCategory.DIAGNOSTIC,
)


def notify_entities_for_peer(peer: KdePeer, state: DeviceState) -> list[NotifyEntity]:
    """Notify entities this peer supports, gated on outgoing capabilities."""
    entities: list[NotifyEntity] = []
    if PACKET_TYPE_NOTIFICATION in peer.capabilities:
        entities.append(KdeNotificationNotifyEntity(peer, state))
    if PACKET_TYPE_SMS_REQUEST in peer.capabilities:
        entities.append(KdeSmsNotifyEntity(peer, state))
    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: Callable[[list[NotifyEntity]], None],
) -> bool:
    """Set up notify entities for one config entry (NOTIFY platform module).

    Expects ``hass.data[DOMAIN][entry.entry_id]`` with ``peers`` and ``states``
    dicts keyed by device id, wired up by the integration's __init__.py.
    """
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime is None:
        return False

    peers: dict[str, KdePeer] = runtime["peers"]
    states: dict[str, DeviceState] = runtime["states"]

    entities: list[NotifyEntity] = []
    for device_id, peer in peers.items():
        entities.extend(notify_entities_for_peer(peer, states[device_id]))

    async_add_entities(entities)
    return True
