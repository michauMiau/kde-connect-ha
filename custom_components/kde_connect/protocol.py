r"""KDE Connect wire protocol helpers (protocol version 8).

Verified against KDE/kdeconnect-kde master:

- Framing: one compact JSON object per line, terminated by ``\n``:
  ``{"id": <ms epoch int>, "type": "kdeconnect.<plugin>", "body": {...}}``.
  Optional ``payloadSize`` (int) plus ``payloadTransferInfo`` (``{"ip",
  "port"}``) point at a separate TLS TCP connection carrying raw payload bytes.
- TLS is mandatory since protocol version 8. The connecting side sends a
  plaintext *connection packet* (identity body plus ``targetDeviceId`` /
  ``targetProtocolVersion``), reads the peer's plaintext identity answer, then
  upgrades the same socket via ``start_tls()``, and both sides exchange
  encrypted identity packets inside the TLS tunnel: ``{deviceId, deviceName,
  deviceType, protocolVersion, incomingCapabilities, outgoingCapabilities}``.
  The peer answers its encrypted identity packet within ~1 second and the
  ``deviceId`` must match throughout the session.
- Peer certificates are self-signed RSA/EC with ``CN == deviceId``. Trusted
  peers pin the peer certificate PEM as TLS CA and verify the presented CN
  equals the deviceId. Untrusted connections ignore the self-signed TLS error
  (``CERT_NONE``) and still verify the certificate CN equals the deviceId.
- Pairing: ``kdeconnect.pair`` body ``{"pair": true, "timestamp": <unix secs>}``
  when requesting; the peer answers ``{"pair": true}`` (no timestamp) on user
  accept; ``{"pair": false}`` cancels/unpairs.
- ``deviceId`` matches ``^[a-zA-Z0-9_-]{32,38}$``; ``deviceName`` must strip
  the characters ``["',;:.!?()[]<>]`` and is capped at 32 characters.
- UDP discovery broadcasts an identity packet body ``{deviceId, deviceName,
  protocolVersion, tcpPort}`` on port 1716; TCP ports are 1716-1764.
"""

from __future__ import annotations

import asyncio
from asyncio import sslproto
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import tempfile
import time
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import psutil

from .const import (
    MAX_IDENTITY_PACKET_SIZE,
    PACKET_TYPE_BATTERY,
    PACKET_TYPE_FIND_MY_PHONE_REQUEST,
    PACKET_TYPE_IDENTITY,
    PACKET_TYPE_NOTIFICATION,
    PACKET_TYPE_NOTIFICATION_ACTION,
    PACKET_TYPE_NOTIFICATION_REPLY,
    PACKET_TYPE_NOTIFICATION_REQUEST,
    PACKET_TYPE_PAIR,
    PACKET_TYPE_PING,
    PACKET_TYPE_RUNCOMMAND,
    PACKET_TYPE_RUNCOMMAND_OUTPUT,
    PACKET_TYPE_SMS_MESSAGES,
    PACKET_TYPE_SMS_REQUEST,
    PROTOCOL_VERSION,
    SMS_REQUEST_PACKET_VERSION,
)

DEVICE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{32,38}$")
_DEVICE_NAME_STRIP_PATTERN = re.compile("""["',;:.!?()\\[\\]<>]""")
MAX_DEVICE_NAME_LENGTH = 32

# Safety cap for one framed packet line; raw payload bodies are delivered on
# the payload connection, not inside the frame.
MAX_PACKET_BYTES = 16 * 1024 * 1024


class ProtocolError(Exception):
    """Raised on malformed frames or protocol violations."""


class HandshakeError(ProtocolError):
    """Raised when a protocol v8 TLS handshake cannot be completed."""


class PeerIdentityMismatch(HandshakeError):
    """Raised when peer identity or certificate does not match expectations."""


def valid_device_id(device_id: str) -> bool:
    """KDE Connect device ids are 32-38 characters of ``[A-Za-z0-9_-]``."""
    return bool(DEVICE_ID_PATTERN.match(device_id))


def generate_device_id() -> str:
    """A fresh random device id matching ``DEVICE_ID_PATTERN``."""
    return secrets.token_hex(16)


def sanitize_device_name(name: str) -> str:
    """Strip forbidden punctuation and truncate to <= 32 characters."""
    cleaned = _DEVICE_NAME_STRIP_PATTERN.sub("", name).strip()
    return cleaned[:MAX_DEVICE_NAME_LENGTH]


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def packet_id() -> int:
    """Packet ``id`` field: milliseconds epoch."""
    return int(time.time() * 1000)


def build_packet(
    packet_type: str,
    body: dict[str, Any] | None = None,
    *,
    payload_size: int | None = None,
    payload_transfer_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap a body into a framed packet dict.

    ``payload_size``/``payload_transfer_info`` announce raw payload bytes to
    be delivered on the separate TLS TCP connection they point at.
    """
    packet: dict[str, Any] = {
        "id": packet_id(),
        "type": packet_type,
        "body": dict(body or {}),
    }
    if payload_size is not None:
        packet["payloadSize"] = int(payload_size)
    if payload_transfer_info is not None:
        packet["payloadTransferInfo"] = dict(payload_transfer_info)
    return packet


def encode_packet(packet: dict[str, Any]) -> bytes:
    """Compact single-line JSON terminated by a newline."""
    return (
        json.dumps(packet, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def decode_packet(line: bytes | str) -> dict[str, Any]:
    """Parse one framed packet line; raise ``ProtocolError`` if malformed.

    Returns the packet dict with normalized ``id``/``type``/``body`` keys and
    any ``payloadSize``/``payloadTransferInfo`` fields preserved as-is.
    """
    raw = (
        line.decode("utf-8", "replace")
        if isinstance(line, (bytes, bytearray))
        else line
    )
    if len(raw.encode("utf-8", "replace")) > MAX_PACKET_BYTES:
        raise ProtocolError("packet exceeds size limit")
    raw = raw.strip()
    if not raw:
        raise ProtocolError("empty packet line")
    try:
        obj = json.loads(raw)
    except ValueError as err:
        raise ProtocolError(f"invalid JSON: {err}") from err
    if not isinstance(obj, dict):
        raise ProtocolError("packet is not a JSON object")
    packet_type = obj.get("type")
    if not isinstance(packet_type, str) or not packet_type:
        raise ProtocolError("packet has no string 'type'")
    body = obj.get("body", {})
    if not isinstance(body, dict):
        raise ProtocolError("packet body is not a JSON object")
    ident = obj.get("id", packet_id())
    if isinstance(ident, bool) or not isinstance(ident, int):
        raise ProtocolError("packet 'id' must be an integer")
    payload_size = obj.get("payloadSize")
    if payload_size is not None and (
        isinstance(payload_size, bool)
        or not isinstance(payload_size, int)
        or payload_size < 0
    ):
        raise ProtocolError("packet 'payloadSize' must be a non-negative integer")
    transfer_info = obj.get("payloadTransferInfo")
    if transfer_info is not None and (
        not isinstance(transfer_info, dict)
        or "ip" not in transfer_info
        or "port" not in transfer_info
    ):
        raise ProtocolError("packet 'payloadTransferInfo' needs ip and port")
    if packet_type == PACKET_TYPE_IDENTITY and len(raw) > MAX_IDENTITY_PACKET_SIZE:
        raise ProtocolError("identity packet exceeds size limit")
    packet = {"id": ident, "type": packet_type, "body": body}
    if payload_size is not None:
        packet["payloadSize"] = payload_size
    if transfer_info is not None:
        packet["payloadTransferInfo"] = transfer_info
    return packet


async def read_packet(
    reader: Any,
    *,
    timeout: float | None = None,
) -> dict[str, Any] | None:
    """Read one packet line; ``None`` on EOF, ``TimeoutError`` on timeout."""
    if timeout is None:
        line = await reader.readline()
    else:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    if not line:
        return None
    if len(line) > MAX_PACKET_BYTES:  # StreamReader limit safety net
        raise ProtocolError("packet too large")
    return decode_packet(line)


# ---------------------------------------------------------------------------
# Capabilities / identity
# ---------------------------------------------------------------------------

# Capability strings (plugin package names) advertised in identity packets.
CAPABILITY_PING = PACKET_TYPE_PING
CAPABILITY_BATTERY = PACKET_TYPE_BATTERY
CAPABILITY_NOTIFICATION = PACKET_TYPE_NOTIFICATION
CAPABILITY_NOTIFICATION_REQUEST = PACKET_TYPE_NOTIFICATION_REQUEST
CAPABILITY_NOTIFICATION_REPLY = PACKET_TYPE_NOTIFICATION_REPLY
CAPABILITY_NOTIFICATION_ACTION = PACKET_TYPE_NOTIFICATION_ACTION
CAPABILITY_SMS = "kdeconnect.sms"
CAPABILITY_SMS_MESSAGES = PACKET_TYPE_SMS_MESSAGES
CAPABILITY_SMS_REQUEST = PACKET_TYPE_SMS_REQUEST
CAPABILITY_RUNCOMMAND = PACKET_TYPE_RUNCOMMAND
CAPABILITY_RUNCOMMAND_OUTPUT = PACKET_TYPE_RUNCOMMAND_OUTPUT
CAPABILITY_FIND_MY_PHONE = PACKET_TYPE_FIND_MY_PHONE_REQUEST

# What this device accepts / delivers (identity packet capability lists).
DEFAULT_INCOMING_CAPABILITIES: list[str] = [
    CAPABILITY_PING,
    CAPABILITY_BATTERY,
    CAPABILITY_NOTIFICATION,
    CAPABILITY_NOTIFICATION_REQUEST,
    CAPABILITY_NOTIFICATION_REPLY,
    CAPABILITY_NOTIFICATION_ACTION,
    CAPABILITY_SMS,
    CAPABILITY_SMS_MESSAGES,
    CAPABILITY_RUNCOMMAND,
    CAPABILITY_RUNCOMMAND_OUTPUT,
]

DEFAULT_OUTGOING_CAPABILITIES: list[str] = [
    CAPABILITY_PING,
    CAPABILITY_NOTIFICATION,
    CAPABILITY_NOTIFICATION_REQUEST,
    CAPABILITY_NOTIFICATION_REPLY,
    CAPABILITY_NOTIFICATION_ACTION,
    CAPABILITY_SMS,
    CAPABILITY_SMS_REQUEST,
    CAPABILITY_RUNCOMMAND,
    CAPABILITY_RUNCOMMAND_OUTPUT,
    CAPABILITY_FIND_MY_PHONE,
]


def _normalize_capabilities(
    capabilities: dict[str, Any] | list[str] | None,
) -> list[str]:
    """Wire capability fields are JSON lists of plugin name strings."""
    if capabilities is None:
        return []
    if isinstance(capabilities, dict):
        return [name for name in capabilities if isinstance(name, str)]
    return [name for name in capabilities if isinstance(name, str)]


def make_connection_packet(
    device_id: str,
    device_name: str,
    tcp_port: int | None = None,
    *,
    target_device_id: str | None = None,
    target_protocol_version: int = PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Plaintext pre-TLS identity packet.

    The TCP handshake body carries ``targetDeviceId``/``targetProtocolVersion``
    to select one device; the UDP announce (and the inbound TCP answer)
    additionally carries ``tcpPort``.
    """
    body: dict[str, Any] = {
        "deviceId": device_id,
        "deviceName": sanitize_device_name(device_name),
        "protocolVersion": PROTOCOL_VERSION,
    }
    if tcp_port is not None:
        body["tcpPort"] = int(tcp_port)
    if target_device_id is not None:
        body["targetDeviceId"] = target_device_id
        body["targetProtocolVersion"] = target_protocol_version
    return build_packet(PACKET_TYPE_IDENTITY, body)


def make_encrypted_identity(
    device_id: str,
    device_name: str,
    *,
    device_type: str = "desktop",
    incoming_capabilities: dict[str, Any] | list[str] | None = None,
    outgoing_capabilities: dict[str, Any] | list[str] | None = None,
) -> dict[str, Any]:
    """Encrypted identity packet exchanged inside TLS after ``start_tls()``."""
    return build_packet(
        PACKET_TYPE_IDENTITY,
        {
            "deviceId": device_id,
            "deviceName": sanitize_device_name(device_name),
            "deviceType": device_type,
            "protocolVersion": PROTOCOL_VERSION,
            "incomingCapabilities": _normalize_capabilities(incoming_capabilities),
            "outgoingCapabilities": _normalize_capabilities(outgoing_capabilities),
        },
    )


def make_udp_discovery_packet(
    device_id: str,
    device_name: str,
    tcp_port: int,
) -> dict[str, Any]:
    """Build a UDP discovery broadcast packet.

    Broadcast body (port 1716): ``deviceId``/``deviceName``/
    ``protocolVersion``/``tcpPort``.
    """
    return make_connection_packet(device_id, device_name, tcp_port)


def is_valid_encrypted_identity(packet: dict[str, Any]) -> bool:
    """Fields required in the encrypted identity packet after TLS."""
    if packet["type"] != PACKET_TYPE_IDENTITY:
        return False
    body = packet["body"]
    return (
        isinstance(body.get("deviceId"), str)
        and isinstance(body.get("deviceName"), str)
        and isinstance(body.get("protocolVersion"), int)
    )


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------

def make_pair_request(timestamp_secs: int) -> dict[str, Any]:
    """Pair request carries a timestamp (unix seconds); accepts do not."""
    return build_packet(PACKET_TYPE_PAIR, {"pair": True, "timestamp": timestamp_secs})


def make_pair_accept() -> dict[str, Any]:
    """Accepting peer answers ``{"pair": true}`` without timestamp."""
    return build_packet(PACKET_TYPE_PAIR, {"pair": True})


def make_pair_unpair() -> dict[str, Any]:
    """Cancel a pending request or tear down an established pair."""
    return build_packet(PACKET_TYPE_PAIR, {"pair": False})


# ---------------------------------------------------------------------------
# Plugin packets
# ---------------------------------------------------------------------------

def make_ping_packet() -> dict[str, Any]:
    """Ping both directions: ``kdeconnect.ping`` with an empty body."""
    return build_packet(PACKET_TYPE_PING)


def make_find_my_phone_packet(*, ring: bool = True, vibrate: bool = True) -> dict[str, Any]:
    """Send a find-my-phone request (ring/vibrate) to the device."""
    return build_packet(
        PACKET_TYPE_FIND_MY_PHONE_REQUEST, {"ring": ring, "vibrate": vibrate}
    )


def make_notification_packet(
    title: str,
    content: str,
    *,
    icon: str | None = None,
    app_name: str | None = None,
    notification_id: str | None = None,
    reply_id: str | None = None,
    priority: str | None = None,
) -> dict[str, Any]:
    """Display a notification on the device (``kdeconnect.notification``)."""
    body: dict[str, Any] = {
        "type": "notification",
        "title": title,
        "content": content,
        "isNotification": True,
    }
    if icon:
        body["icon"] = icon
    if app_name:
        body["appName"] = app_name
    if notification_id:
        body["id"] = notification_id
    if reply_id:
        body["replyId"] = reply_id
    if priority:
        body["priority"] = priority
    return build_packet(PACKET_TYPE_NOTIFICATION, body)


def make_notification_request_packet() -> dict[str, Any]:
    """Ask the device to start pushing notifications (wantReply)."""
    return build_packet(PACKET_TYPE_NOTIFICATION_REQUEST, {"wantReply": True})


def make_notification_cancel_packet(notification_id: str) -> dict[str, Any]:
    """Cancel an active notification: ``cancel`` lives in the request packet."""
    return build_packet(PACKET_TYPE_NOTIFICATION_REQUEST, {"cancel": notification_id})


def make_notification_reply_packet(request_reply_id: str, message: str) -> dict[str, Any]:
    """Reply to a notification; request side carries ``requestReplyId``."""
    return build_packet(
        PACKET_TYPE_NOTIFICATION_REPLY,
        {"requestReplyId": request_reply_id, "reply": message},
    )


def make_notification_action_packet(key: str, action: str) -> dict[str, Any]:
    """Send a notification action (key + action) to the device."""
    return build_packet(PACKET_TYPE_NOTIFICATION_ACTION, {"key": key, "action": action})


def _body_of(packet: dict[str, Any]) -> dict[str, Any]:
    """Accept either a full packet or a bare body mapping."""
    if "body" in packet and isinstance(packet["body"], dict):
        return packet["body"]
    return packet


def parse_notification(packet: dict[str, Any]) -> dict[str, Any]:
    """Normalize an incoming ``kdeconnect.notification`` body."""
    body = _body_of(packet)
    return {
        "id": body.get("id", ""),
        "title": body.get("title", ""),
        "content": body.get("content", ""),
        "app_name": body.get("appName", ""),
        "app_icon": body.get("appIcon", ""),
        "type": body.get("type", ""),
        "is_notification": bool(body.get("isNotification", False)),
        "notification_id": body.get("notificationId", ""),
        "reply_id": body.get("replyId", ""),
        "reply_action": body.get("replyAction"),
        "open_browser": bool(body.get("openBrowser", False)),
        "options": body.get("options") or [],
        "urgent": bool(body.get("urgent", False)),
        "priority": body.get("priority", ""),
    }


def parse_battery(packet: dict[str, Any]) -> dict[str, Any]:
    """Normalize an incoming ``kdeconnect.battery`` push body.

    Wire fields: ``isCharging`` (bool), ``currentCharge`` (int),
    ``batteryQuantity`` (int), ``thresholdEvent`` (int).
    """
    body = _body_of(packet)
    threshold = body.get("thresholdEvent")
    return {
        "is_charging": bool(body.get("isCharging", False)),
        "current_charge": int(body.get("currentCharge", 0)),
        "battery_quantity": int(body.get("batteryQuantity", -1)),
        "threshold_event": int(threshold) if threshold is not None else 0,
    }


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------

def make_sms_request_packet(
    message_body: str,
    addresses: list[str],
    *,
    sub_id: int | None = None,
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """``kdeconnect.sms.request``: version 1, ``addresses`` of ``{"address": ...}``.

    Attachments carry ``{"fileName", "base64EncodedFile", "mimeType"}`` inline.
    """
    body: dict[str, Any] = {
        "version": SMS_REQUEST_PACKET_VERSION,
        "messageBody": message_body,
        "addresses": [{"address": a} for a in addresses],
    }
    if sub_id is not None:
        body["subID"] = sub_id
    if attachments:
        body["attachments"] = list(attachments)
    return build_packet(PACKET_TYPE_SMS_REQUEST, body)


def parse_sms_messages(packet: dict[str, Any]) -> dict[str, Any]:
    """Normalize an incoming ``kdeconnect.sms.messages`` body.

    Payload JSON (when present) is merged into the body by the transport, so
    the ``addresses``/``messages`` conversation lists are available here.
    """
    body = _body_of(packet)
    conversations: list[dict[str, Any]] = [
        c for c in (body.get("messages") or []) if isinstance(c, dict)
    ]
    unread = 0
    for conversation in conversations:
        for message in conversation.get("messages") or []:
            if isinstance(message, dict) and message.get("unread"):
                unread += 1
    return {
        "type": body.get("type", ""),
        "addresses": body.get("addresses") or [],
        "messages": conversations,
        "message_body": body.get("messageBody", ""),
        "message_id": body.get("messageId", ""),
        "timestamp": int(body.get("timestamp", 0)),
        "readable": bool(body.get("readable", False)),
        "received": bool(body.get("received", True)),
        "unread_count": unread,
    }


# ---------------------------------------------------------------------------
# Runcommand
# ---------------------------------------------------------------------------

def make_command_list_request_packet() -> dict[str, Any]:
    """Ask the peer for its advertised ``commandList``."""
    return build_packet(PACKET_TYPE_RUNCOMMAND, {"requestCommandList": True})


def make_run_command_packet(key: str) -> dict[str, Any]:
    """Run a command the peer announced in its ``commandList``."""
    return build_packet(PACKET_TYPE_RUNCOMMAND, {"key": key})


def make_stop_commands_packet(*, stop_all: bool = True) -> dict[str, Any]:
    """Ask the peer to stop running remote commands."""
    return build_packet(PACKET_TYPE_RUNCOMMAND, {"stop": True if stop_all else None})


def parse_runcommand(packet: dict[str, Any]) -> dict[str, Any]:
    """Normalize an incoming ``kdeconnect.runcommand``/``.output`` body."""
    body = _body_of(packet)
    if body.get("commandList") is not None:
        return {
            "kind": "command_list",
            "commands": {
                key: {"name": cmd.get("name", ""), "command": cmd.get("command", "")}
                for key, cmd in body["commandList"].items()
            },
        }
    if body.get("request"):
        return {
            "kind": "command_requested",
            "command": body.get("command", ""),
            "name": body.get("name", ""),
            "id": body.get("commandId") or body.get("id", ""),
        }
    if body.get("stdout") is not None or body.get("stderr") is not None:
        return {
            "kind": "output",
            "stdout": body.get("stdout") or "",
            "stderr": body.get("stderr") or "",
            "id": body.get("id", ""),
        }
    if body.get("commandStarted"):
        return {
            "kind": "started",
            "command": body.get("command", ""),
            "id": body.get("id", ""),
        }
    if body.get("commandFinished"):
        return {
            "kind": "finished",
            "success": bool(body.get("success", False)),
            "exit_code": int(body.get("exitCode", 0)),
            "id": body.get("id", ""),
        }
    return {"kind": "unknown", "body": body}


# ---------------------------------------------------------------------------
# Certificates: self-signed RSA 2048 / SHA-512, CN == deviceId
# ---------------------------------------------------------------------------

def create_identity_certificate(device_id: str) -> tuple[str, str]:
    """Build the device identity certificate per KDE Connect conventions.

    Returns ``(cert_pem, key_pem)``: RSA 2048, SHA-512 self-signed,
    ``CN=deviceId``, ``O=KDE``, ``OU=KDE Connect``, valid over a generous
    window. Peer devices trust these by pinning the cert during pairing.
    """
    if not valid_device_id(device_id):
        raise ValueError(f"invalid deviceId: {device_id!r}")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serial = secrets.randbelow(1 << 128) + 1  # well under the 160-bit cap
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KDE"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "KDE Connect"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA512())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


def load_certificate(data: str | bytes) -> x509.Certificate:
    """Load a certificate from PEM or DER bytes."""
    raw = data.encode() if isinstance(data, str) else data
    try:
        return x509.load_pem_x509_certificate(raw)
    except ValueError:
        return x509.load_der_x509_certificate(raw)


def certificate_cn(cert: x509.Certificate) -> str:
    """The certificate subject CN as a string."""
    attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attributes[0].value if attributes else ""


def certificate_pem(cert: x509.Certificate) -> str:
    """PEM encoding of a certificate (pinable as CONF_PEER_CERT)."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def verify_certificate_identity(cert: x509.Certificate, device_id: str) -> bool:
    """True if the certificate CN matches the peer deviceId."""
    return certificate_cn(cert) == device_id


# ---------------------------------------------------------------------------
# Local identity material
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocalIdentity:
    """This integration's KDE Connect peer identity and TLS material."""

    device_id: str
    device_name: str
    device_type: str
    cert_pem: str
    key_pem: str
    outgoing_capabilities: list[str] = field(
        default_factory=lambda: list(DEFAULT_OUTGOING_CAPABILITIES)
    )

    def to_config_dict(self) -> dict[str, Any]:
        """Persistable form for a config entry."""
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "cert_pem": self.cert_pem,
            "key_pem": self.key_pem,
            "outgoing_capabilities": list(self.outgoing_capabilities),
        }

    @classmethod
    def from_config_dict(cls, data: dict[str, Any]) -> LocalIdentity:
        """Rebuild from persisted config entry data."""
        return cls(
            device_id=data["device_id"],
            device_name=data["device_name"],
            device_type=data.get("device_type", "desktop"),
            cert_pem=data["cert_pem"],
            key_pem=data["key_pem"],
            outgoing_capabilities=list(
                data.get("outgoing_capabilities") or DEFAULT_OUTGOING_CAPABILITIES
            ),
        )


def create_local_identity(
    device_name: str,
    *,
    device_id: str | None = None,
    device_type: str = "desktop",
    outgoing_capabilities: list[str] | None = None,
) -> LocalIdentity:
    """Generate a self-signed identity (deviceId as cert CN, RSA 2048 cert)."""
    device_id = device_id or generate_device_id()
    cert_pem, key_pem = create_identity_certificate(device_id)
    return LocalIdentity(
        device_id=device_id,
        device_name=sanitize_device_name(device_name),
        device_type=device_type,
        cert_pem=cert_pem,
        key_pem=key_pem,
        outgoing_capabilities=list(
            outgoing_capabilities or DEFAULT_OUTGOING_CAPABILITIES
        ),
    )


# ---------------------------------------------------------------------------
# TLS contexts
# ---------------------------------------------------------------------------

def client_tls_context(
    peer_cert_pem: str | None = None,
    cert_pem: str | None = None,
    key_pem: str | None = None,
) -> ssl.SSLContext:
    """TLS client context for inbound sessions and payload connections.

    Trusted peers pin the peer certificate PEM as TLS CA (``CERT_REQUIRED``);
    hostname checks are disabled because the certificate carries the deviceId
    as CN, not a DNS name. Untrusted connections use ``CERT_NONE`` (ignore the
    self-signed TLS error) and rely on the caller verifying CN == deviceId via
    :func:`peer_certificate`. When ``cert_pem``/``key_pem`` are given, our own
    certificate is presented if the TLS server requests one.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    if peer_cert_pem:
        context.load_verify_locations(cadata=peer_cert_pem)
    else:
        context.verify_mode = ssl.CERT_NONE
    if cert_pem and key_pem:
        _load_cert_chain(context, cert_pem, key_pem)
    return context


def _load_cert_chain(
    context: ssl.SSLContext, cert_pem: str, key_pem: str
) -> None:
    """Load our certificate chain from PEM material via temporary files.

    ``ssl.SSLContext.load_cert_chain`` needs filesystem paths (BytesIO is not
    accepted), so the PEM material is written to private temp files and removed
    immediately after loading.
    """
    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
    key_fd, key_path = tempfile.mkstemp(suffix=".key")
    try:
        with os.fdopen(cert_fd, "w") as cert_file:
            Path(cert_path).chmod(0o600)
            cert_file.write(cert_pem)
        with os.fdopen(key_fd, "w") as key_file:
            Path(key_path).chmod(0o600)
            key_file.write(key_pem)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        for path in (cert_path, key_path):
            with contextlib.suppress(OSError):
                Path(path).unlink(missing_ok=True)


def server_tls_context(
    cert_pem: str,
    key_pem: str,
    peer_cert_pem: str | None = None,
) -> ssl.SSLContext:
    """TLS server context presenting our self-signed identity certificate.

    Requests and verifies the peer certificate only when a pinned peer cert
    exists; otherwise ``CERT_NONE`` so unpaired self-signed inbound peers can
    connect (deviceId match is enforced at the identity packet level).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _load_cert_chain(context, cert_pem, key_pem)
    if peer_cert_pem:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=peer_cert_pem)
    else:
        context.verify_mode = ssl.CERT_NONE
    return context


async def upgrade_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    context: ssl.SSLContext,
    timeout: float,
    *,
    server_side: bool,
) -> None:
    """Upgrade a stream connection to TLS (STARTTLS-style, like KDE Connect).

    KDE Connect exchanges a plaintext identity packet before TLS starts, and
    the TLS role is inverted relative to the TCP direction (the TCP client is
    the TLS server, the TCP server is the TLS client). Bytes that arrive after
    the packet but before the upgrade end up in the ``StreamReader`` buffer and
    would be lost by the transport upgrade, so they are written into the SSL
    protocol's incoming BIO before the handshake is awaited; otherwise the
    handshake deadlocks on already-buffered bytes.
    """
    await writer.drain()
    leftover = bytes(reader._buffer)  # noqa: SLF001
    reader._buffer.clear()  # noqa: SLF001

    loop = asyncio.get_running_loop()
    protocol = writer._protocol  # noqa: SLF001

    waiter = loop.create_future()
    ssl_protocol = sslproto.SSLProtocol(
        loop,
        protocol,
        context,
        waiter,
        server_side,
        None,
        ssl_handshake_timeout=timeout,
        call_connection_made=False,
    )
    transport = writer.transport
    transport.pause_reading()
    transport.set_protocol(ssl_protocol)
    if leftover:
        feed_cb = loop.call_soon(ssl_protocol._incoming.write, leftover)  # noqa: SLF001
    else:
        feed_cb = None
    conmade_cb = loop.call_soon(ssl_protocol.connection_made, transport)
    resume_cb = loop.call_soon(transport.resume_reading)
    try:
        await asyncio.wait_for(waiter, timeout=timeout)
    except BaseException:
        transport.close()
        conmade_cb.cancel()
        if feed_cb is not None:
            feed_cb.cancel()
        resume_cb.cancel()
        raise

    new_transport = ssl_protocol._app_transport  # noqa: SLF001
    writer._transport = new_transport  # noqa: SLF001
    protocol._replace_transport(new_transport)  # noqa: SLF001


def peer_certificate(writer: Any, device_id: str | None = None) -> str | None:
    """Return the peer certificate PEM from the TLS transport.

    ``None`` when no certificate was presented. With ``device_id`` given, the
    certificate CN must match it or ``PeerIdentityMismatch`` is raised.
    """
    ssl_object = writer.transport.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    cert_der = ssl_object.getpeercert(binary_form=True)
    if cert_der is None:
        return None
    cert = load_certificate(cert_der)
    if device_id is not None and not verify_certificate_identity(cert, device_id):
        raise PeerIdentityMismatch(
            f"peer certificate CN {certificate_cn(cert)!r} does not match "
            f"deviceId {device_id!r}"
        )
    return certificate_pem(cert)


# ---------------------------------------------------------------------------
# TCP / UDP helpers
# ---------------------------------------------------------------------------

def apply_tcp_keepalive(
    sock: socket.socket | None,
    *,
    idle: int,
    interval: int,
    count: int,
    user_timeout_ms: int,
) -> None:
    """Best-effort TCP keepalive + user timeout on a connected socket."""
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
    except (AttributeError, OSError):
        pass
    user_timeout = getattr(socket, "TCP_USER_TIMEOUT", None)
    if user_timeout is not None:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, user_timeout, user_timeout_ms)


def broadcast_addresses() -> list[str]:
    """IPv4 broadcast addresses of local interfaces (UDP announce targets)."""
    targets: list[str] = [
        addr.broadcast
        for addrs in psutil.net_if_addrs().values()
        for addr in addrs
        if addr.family == socket.AF_INET and addr.broadcast
    ]
    if "255.255.255.255" not in targets:
        targets.append("255.255.255.255")
    return targets
