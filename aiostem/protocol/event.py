from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar, Literal, Self

from pydantic import TypeAdapter

from ..exceptions import MessageError, ReplySyntaxError
from .message import Message, MessageData
from .structures import (
    HsDescAction,
    HsDescAuthType,
    HsDescFailReason,
    NetworkLivenessStatus,
    Signal,
)
from .syntax import ReplySyntax, ReplySyntaxFlag
from .utils import Base32Bytes, Base64Bytes, HexBytes

if TYPE_CHECKING:
    from collections.abc import Mapping  # noqa: F401


class EventWordInternal(StrEnum):
    """All events handled internally in this library."""

    DISCONNECT = 'DISCONNECT'


class EventWord(StrEnum):
    """All possible events to subscribe to."""

    #: Circuit status changed
    CIRC = 'CIRC'
    #: Stream status changed
    STREAM = 'STREAM'
    #: OR Connection status changed
    ORCONN = 'ORCONN'
    #: Bandwidth used in the last second
    BW = 'BW'
    #: Debug log message
    DEBUG = 'DEBUG'
    #: Info log message
    INFO = 'INFO'
    #: Notice log message
    NOTICE = 'NOTICE'
    #: Warning log message
    WARN = 'WARN'
    #: Error log message
    ERR = 'ERR'
    #: New descriptors available
    NEWDESC = 'NEWDESC'
    #: New Address mapping
    ADDRMAP = 'ADDRMAP'
    #: Descriptors uploaded to us in our role as authoritative dirserver
    AUTHDIR_NEWDESCS = 'AUTHDIR_NEWDESCS'
    #: Our descriptor changed
    DESCCHANGED = 'DESCCHANGED'
    #: General status event
    STATUS_GENERAL = 'STATUS_GENERAL'
    #: Client status event
    STATUS_CLIENT = 'STATUS_CLIENT'
    #: Server status event
    STATUS_SERVER = 'STATUS_SERVER'
    #: Our set of guard nodes has changed
    GUARD = 'GUARD'
    #: Network status has changed
    NS = 'NS'
    #: Bandwidth used on an application stream
    STREAM_BW = 'STREAM_BW'
    #: Per-country client stats
    CLIENTS_SEEN = 'CLIENTS_SEEN'
    #: New consensus networkstatus has arrived
    NEWCONSENSUS = 'NEWCONSENSUS'
    #: New circuit buildtime has been set
    BUILDTIMEOUT_SET = 'BUILDTIMEOUT_SET'
    #: Signal received
    SIGNAL = 'SIGNAL'
    #: Configuration changed
    CONF_CHANGED = 'CONF_CHANGED'
    #: Circuit status changed slightly
    CIRC_MINOR = 'CIRC_MINOR'
    #: Pluggable transport launched
    TRANSPORT_LAUNCHED = 'TRANSPORT_LAUNCHED'
    #: Bandwidth used on an OR or DIR or EXIT connection
    CONN_BW = 'CONN_BW'
    #: Bandwidth used by all streams attached to a circuit
    CIRC_BW = 'CIRC_BW'
    #: Per-circuit cell stats
    CELL_STATS = 'CELL_STATS'
    #: Token buckets refilled
    TB_EMPTY = 'TB_EMPTY'
    #: HiddenService descriptors
    HS_DESC = 'HS_DESC'
    #: HiddenService descriptors content
    HS_DESC_CONTENT = 'HS_DESC_CONTENT'
    #: Network liveness has changed
    NETWORK_LIVENESS = 'NETWORK_LIVENESS'
    #: Pluggable Transport Logs
    PT_LOG = 'PT_LOG'
    #: Pluggable Transport Status
    PT_STATUS = 'PT_STATUS'


@dataclass(kw_only=True, slots=True)
class Event(ABC):
    """Base class for all events."""

    ADAPTER: ClassVar[TypeAdapter[Self] | None] = None
    TYPE: ClassVar[EventWordInternal | EventWord | None]

    @classmethod
    def adapter(cls) -> TypeAdapter[Self]:
        """Get a cached type adapter to deserialize a reply."""
        if cls.ADAPTER is None:
            cls.ADAPTER = TypeAdapter(cls)
        return cls.ADAPTER

    @classmethod
    @abstractmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event structure from a received message."""


@dataclass(kw_only=True, slots=True)
class EventDisconnect(Event):
    """
    Structure for a `DISCONNECT` event.

    Note:
        This event is internal to :mod:`aiostem`.

    """

    TYPE = EventWordInternal.DISCONNECT

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        return cls.adapter().validate_python({})


@dataclass(kw_only=True, slots=True)
class EventSignal(Event):
    """Structure for a `SIGNAL` event."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(args_min=2, args_map=(None, 'signal'))
    TYPE = EventWord.SIGNAL
    signal: Signal

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        result = cls.SYNTAX.parse(message)
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventHsDesc(Event):
    """Structure for a `HS_DESC` event."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=5,
        args_map=(None, 'action', 'address', 'auth_type', 'hs_dir', 'descriptor_id'),
        kwargs_map={
            'REASON': 'reason',
            'REPLICA': 'replica',
            'HSDIR_INDEX': 'hs_dir_index',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE = EventWord.HS_DESC

    action: HsDescAction
    address: str | Literal['UNKNOWN']  # noqa: PYI051
    auth_type: HsDescAuthType
    descriptor_id: Base32Bytes | Base64Bytes | None = None
    hs_dir: str | Literal['UNKNOWN']  # noqa: PYI051
    hs_dir_index: HexBytes | None = None
    reason: HsDescFailReason | None = None
    replica: int | None = None

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        result = cls.SYNTAX.parse(message)
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventHsDescContent(Event):
    """Structure for a `HS_DESC_CONTENT` event."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=4,
        args_map=(None, 'address', 'descriptor_id', 'hs_dir'),
    )
    TYPE = EventWord.HS_DESC_CONTENT

    address: str | Literal['UNKNOWN']  # noqa: PYI051
    hs_dir: str | Literal['UNKNOWN']  # noqa: PYI051
    descriptor_id: Base32Bytes | Base64Bytes | None = None
    descriptor_text: str

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        if not len(message.items) or not isinstance(message.items[0], MessageData):
            msg = "Event 'HS_DESC_CONTENT' has no data attached to it!"
            raise ReplySyntaxError(msg)

        result = cls.SYNTAX.parse(message.items[0])
        descriptor = message.items[0].data
        return cls.adapter().validate_python({**result, 'descriptor_text': descriptor})


@dataclass(kw_only=True, slots=True)
class EventNetworkLiveness(Event):
    """Structure for a `NETWORK_LIVENESS` event."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=2,
        args_map=(None, 'status'),
    )
    TYPE = EventWord.NETWORK_LIVENESS

    status: NetworkLivenessStatus

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        result = cls.SYNTAX.parse(message)
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventUnknown(Event):
    """Structure for an unknown event."""

    TYPE = None

    #: Original message received for this event.
    message: Message

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        return cls.adapter().validate_python({'message': message})


_EVENT_MAP = {
    'DISCONNECT': EventDisconnect,
    'HS_DESC': EventHsDesc,
    'HS_DESC_CONTENT': EventHsDescContent,
    'NETWORK_LIVENESS': EventNetworkLiveness,
    'SIGNAL': EventSignal,
}  # type: Mapping[str, type[Event]]


def event_from_message(message: Message) -> Event:
    """
    Parse an event message to the corresponding structure.

    Args:
        message: An event message to parse.

    Raises:
        MessageError: When the message is not an event.

    Returns:
        A parsed event dataclass corresponding to the event.

    """
    if not message.is_event:
        msg = 'The provided message is not an event!'
        raise MessageError(msg)

    handler = _EVENT_MAP.get(message.keyword)
    if handler is None:
        handler = EventUnknown
    return handler.from_message(message)
