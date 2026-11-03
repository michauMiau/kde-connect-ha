"""Constants for the KDE Connect integration."""

from __future__ import annotations

from typing import Final

from homeassistant.const import Platform

DOMAIN: Final = "kde_connect"
PLATFORMS: Final[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.DEVICE_TRACKER,
    Platform.NOTIFY,
    Platform.SENSOR,
]

UDP_PORT: Final = 1716
MIN_TCP_PORT: Final = 1716
MAX_TCP_PORT: Final = 1764

PROTOCOL_VERSION: Final = 8

CONF_PROTOCOL_VERSION: Final = "protocol_version"

PACKET_TYPE_IDENTITY: Final = "kdeconnect.identity"
PACKET_TYPE_PAIR: Final = "kdeconnect.pair"
PACKET_TYPE_BATTERY: Final = "kdeconnect.battery"
PACKET_TYPE_PING: Final = "kdeconnect.ping"
PACKET_TYPE_NOTIFICATION: Final = "kdeconnect.notification"
PACKET_TYPE_NOTIFICATION_REQUEST: Final = "kdeconnect.notification.request"
PACKET_TYPE_NOTIFICATION_REPLY: Final = "kdeconnect.notification.reply"
PACKET_TYPE_NOTIFICATION_ACTION: Final = "kdeconnect.notification.action"
PACKET_TYPE_SMS_REQUEST: Final = "kdeconnect.sms.request"
PACKET_TYPE_SMS_MESSAGES: Final = "kdeconnect.sms.messages"
PACKET_TYPE_RUNCOMMAND: Final = "kdeconnect.runcommand"
PACKET_TYPE_RUNCOMMAND_OUTPUT: Final = "kdeconnect.runcommand.output"
PACKET_TYPE_FIND_MY_PHONE_REQUEST: Final = "kdeconnect.findmyphone.request"

SMS_REQUEST_PACKET_VERSION: Final = 1

CONF_HOST: Final = "host"
CONF_TCP_PORT: Final = "tcp_port"
CONF_DEVICE_ID: Final = "device_id"
CONF_DEVICE_NAME: Final = "device_name"
CONF_DEVICE_TYPE: Final = "device_type"
CONF_PEER_CERT: Final = "peer_cert"
CONF_CAPABILITIES: Final = "capabilities"
CONF_INBOUND_PORT: Final = "inbound_port"
CONF_ANNOUNCE: Final = "announce"

EVENT_NOTIFICATION_RECEIVED: Final = "kdeconnect_notification_received"
EVENT_NOTIFICATION_REQUEST: Final = "kdeconnect_notification_request"
EVENT_NOTIFICATION_REPLY: Final = "kdeconnect_notification_reply"
EVENT_NOTIFICATION_ACTION: Final = "kdeconnect_notification_action"
EVENT_SMS_RECEIVED: Final = "kdeconnect_sms_received"
EVENT_COMMAND_OUTPUT: Final = "kdeconnect_command_output"
EVENT_PAIR_REQUEST: Final = "kdeconnect_pair_request"
EVENT_PAIR_CHANGED: Final = "kdeconnect_pair_changed"
EVENT_DEVICE_DISCOVERED: Final = "kdeconnect_device_discovered"

SERVICE_SEND_SMS: Final = "send_sms"
SERVICE_SEND_NOTIFICATION: Final = "send_notification"
SERVICE_FIND_MY_PHONE: Final = "find_my_phone"
SERVICE_REQUEST_NOTIFICATIONS: Final = "request_notifications"
SERVICE_CANCEL_NOTIFICATION: Final = "cancel_notification"
SERVICE_NOTIFICATION_REPLY: Final = "notification_reply"
SERVICE_RUN_COMMAND: Final = "run_command"

DISCOVERY_KEY: Final = "device_id"

DISCOVERY_INTERVAL: Final = 20.0
RECONNECT_MIN_DELAY: Final = 1.0
RECONNECT_MAX_DELAY: Final = 60.0
PAIRING_TIMEOUT: Final = 45.0
HANDSHAKE_TIMEOUT: Final = 10.0
MAX_IDENTITY_PACKET_SIZE: Final = 8192
TCP_KEEPALIVE_IDLE: Final = 30
TCP_KEEPALIVE_INTERVAL: Final = 10
TCP_KEEPALIVE_COUNT: Final = 3
TCP_USER_TIMEOUT_MS: Final = 60000
