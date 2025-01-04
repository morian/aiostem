from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import (
    Mapping,
    Sequence,
    Set as AbstractSet,
)
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Literal, Self, TypeAlias, Union

from pydantic import BeforeValidator, Discriminator, Field, NonNegativeInt, Tag, TypeAdapter

from .exceptions import MessageError, ReplySyntaxError
from .reply import ReplyGetMap
from .structures import (
    CircuitBuildFlags,
    CircuitEvent,
    CircuitHiddenServiceState,
    CircuitPurpose,
    HiddenServiceAddress,
    HsDescAction,
    HsDescAuthTypeStr,
    HsDescFailReason,
    LivenessStatus,
    LogSeverity,
    LongServerName,
    Signal,
    StatusActionClient,
    StatusActionGeneral,
    StatusActionServer,
    StatusClientBootstrap,
    StatusClientCircuitNotEstablished,
    StatusClientDangerousPort,
    StatusClientDangerousSocks,
    StatusClientSocksBadHostname,
    StatusGeneralBug,
    StatusGeneralClockJumped,
    StatusGeneralClockSkew,
    StatusGeneralDangerousVersion,
    StatusGeneralTooManyConnections,
    StatusServerAcceptedServerDescriptor,
    StatusServerBadServerDescriptor,
    StatusServerCheckingReachability,
    StatusServerExternalAddress,
    StatusServerHibernationStatus,
    StatusServerNameserverStatus,
    StatusServerReachabilityFailed,
    StatusServerReachabilitySucceeded,
)
from .types import (
    AnyAddress,
    AnyHost,
    AnyPort,
    Base16Bytes,
    Base32Bytes,
    Base64Bytes,
    BoolYesNo,
    DatetimeUTC,
    TimedeltaMilliseconds,
)
from .utils import (
    Message,
    MessageData,
    ReplySyntax,
    ReplySyntaxFlag,
    TrBeforeSetToNone,
    TrBeforeStringSplit,
    TrCast,
)

if TYPE_CHECKING:
    # The following line is needed so sphinx can get EventConfChanged right.
    from .reply import ReplyMapType  # noqa: F401

logger = logging.getLogger(__package__)


class EventWordInternal(StrEnum):
    """All events handled internally in this library."""

    #: The controller has been disconnected from Tor.
    #:
    #: See Also:
    #:     :class:`EventDisconnect`
    DISCONNECT = 'DISCONNECT'


class EventWord(StrEnum):
    """All possible events to subscribe to."""

    #: Circuit status changed.
    CIRC = 'CIRC'

    #: Stream status changed.
    STREAM = 'STREAM'

    #: OR Connection status changed.
    ORCONN = 'ORCONN'

    #: Bandwidth used in the last second.
    BW = 'BW'

    #: Debug log message.
    #:
    #: See Also:
    #:     :class:`EventLogDebug`
    DEBUG = 'DEBUG'

    #: Info log message.
    #:
    #: See Also:
    #:     :class:`EventLogInfo`
    INFO = 'INFO'

    #: Notice log message.
    #:
    #: See Also:
    #:     :class:`EventLogNotice`
    NOTICE = 'NOTICE'

    #: Warning log message.
    #:
    #: See Also:
    #:     :class:`EventLogWarn`
    WARN = 'WARN'

    #: Error log message.
    #:
    #: See Also:
    #:     :class:`EventLogErr`
    ERR = 'ERR'

    #: New descriptors available.
    NEWDESC = 'NEWDESC'

    #: New Address mapping.
    #:
    #: See Also:
    #:     :class:`EventAddrMap`
    ADDRMAP = 'ADDRMAP'

    #: Descriptors uploaded to us in our role as authoritative dirserver.
    AUTHDIR_NEWDESCS = 'AUTHDIR_NEWDESCS'

    #: Our descriptor changed.
    DESCCHANGED = 'DESCCHANGED'

    #: General status event.
    #:
    #: See Also:
    #:     :class:`EventStatusGeneral`
    STATUS_GENERAL = 'STATUS_GENERAL'

    #: Client status event.
    #:
    #: See Also:
    #:     :class:`EventStatusClient`
    STATUS_CLIENT = 'STATUS_CLIENT'

    #: Server status event.
    #:
    #: See Also:
    #:     :class:`EventStatusServer`
    STATUS_SERVER = 'STATUS_SERVER'

    #: Our set of guard nodes has changed.
    GUARD = 'GUARD'

    #: Network status has changed.
    #:
    #: See Also:
    #:     :class:`EventNetworkStatus`
    NS = 'NS'

    #: Bandwidth used on an application stream.
    STREAM_BW = 'STREAM_BW'

    #: Per-country client stats.
    CLIENTS_SEEN = 'CLIENTS_SEEN'

    #: New consensus networkstatus has arrived.
    #:
    #: See Also:
    #:     :class:`EventNewConsensus`
    NEWCONSENSUS = 'NEWCONSENSUS'

    #: New circuit buildtime has been set.
    #:
    #: See Also:
    #:     :class:`EventBuildTimeoutSet`
    BUILDTIMEOUT_SET = 'BUILDTIMEOUT_SET'

    #: Signal received.
    #:
    #: See Also:
    #:     :class:`EventSignal`
    SIGNAL = 'SIGNAL'

    #: Configuration changed.
    #:
    #: See Also:
    #:     :class:`EventConfChanged`
    CONF_CHANGED = 'CONF_CHANGED'

    #: Circuit status changed slightly.
    #:
    #: See Also:
    #:     :class:`EventCircMinor`
    CIRC_MINOR = 'CIRC_MINOR'

    #: Pluggable transport launched.
    #:
    #: See Also:
    #:     :class:`EventTransportLaunched`
    TRANSPORT_LAUNCHED = 'TRANSPORT_LAUNCHED'

    #: Bandwidth used on an OR or DIR or EXIT connection.
    CONN_BW = 'CONN_BW'

    #: Bandwidth used by all streams attached to a circuit.
    #:
    #: See Also:
    #:     :class:`EventCircBW`
    CIRC_BW = 'CIRC_BW'

    #: Per-circuit cell stats.
    #:
    #: See Also:
    #:     :class:`EventCellStats`
    CELL_STATS = 'CELL_STATS'

    #: Token buckets refilled.
    #:
    #: See Also:
    #:     :class:`EventTbEmpty`
    TB_EMPTY = 'TB_EMPTY'

    #: HiddenService descriptors.
    #:
    #: See Also:
    #:     :class:`EventHsDesc`
    HS_DESC = 'HS_DESC'

    #: HiddenService descriptors content.
    #:
    #: See Also:
    #:     :class:`EventHsDescContent`
    HS_DESC_CONTENT = 'HS_DESC_CONTENT'

    #: Network liveness has changed.
    #:
    #: See Also:
    #:     :class:`EventNetworkLiveness`
    NETWORK_LIVENESS = 'NETWORK_LIVENESS'

    #: Pluggable Transport Logs.
    #:
    #: See Also:
    #:     :class:`EventPtLog`
    PT_LOG = 'PT_LOG'

    #: Pluggable Transport Status.
    #:
    #: See Also:
    #:     :class:`EventPtStatus`
    PT_STATUS = 'PT_STATUS'


@dataclass(kw_only=True, slots=True)
class Event(ABC):
    """Base class for all events."""

    #: Cached adapter used while deserializing the message.
    ADAPTER: ClassVar[TypeAdapter[Self] | None] = None

    #: Type of event this class is a parser for.
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
class EventSimple(Event):
    """An event with a simple single syntax parser."""

    #: Simple syntax to parse the message from.
    SYNTAX: ClassVar[ReplySyntax]

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        result = cls.SYNTAX.parse(message)
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventDisconnect(Event):
    """
    Structure for a :attr:`~EventWordInternal.DISCONNECT` event.

    Note:
        This event is internal to ``aiostem``.

    """

    TYPE = EventWordInternal.DISCONNECT

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        return cls.adapter().validate_python({})


@dataclass(kw_only=True, slots=True)
class EventAddrMap(EventSimple):
    """
    Structure for a :attr:`~EventWord.ADDRMAP` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#ADDRMAP

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=2,
        args_map=(None, 'original', 'replacement'),
        kwargs_map={
            None: 'expires_local',
            'EXPIRES': 'expires',
            'CACHED': 'cached',
            'STREAMID': 'stream',
        },
        flags=ReplySyntaxFlag.KW_ENABLE
        | ReplySyntaxFlag.KW_QUOTED
        | ReplySyntaxFlag.KW_OMIT_KEYS,
    )
    TYPE = EventWord.ADDRMAP

    #: Original address to replace.
    # Union is used around AnyHost to fix a weird bug with typing.get_type_hints().
    original: Union[AnyHost]  # noqa: UP007
    #: Replacement address, ``<error>`` is mapped to None.
    replacement: Annotated[Union[AnyHost, None], TrBeforeSetToNone({'<error>'})]  # noqa: UP007
    #: When this entry expires as an UTC date.
    expires: DatetimeUTC | None = None
    #: Error message when replacement is :obj:`None`.
    error: str | None = None
    #: Whether this value has been kept in cache.
    #:
    #: See Also:
    #:    https://docs.pydantic.dev/latest/api/standard_library_types/#booleans
    cached: BoolYesNo | None = None
    #: Stream identifier.
    stream: int | None = None


@dataclass(kw_only=True, slots=True)
class EventNetworkStatus(Event):
    """
    Structure for a :attr:`~EventWord.NS` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#NS

    """

    TYPE = EventWord.NS

    #: Raw content of the new network status.
    status: str

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        if not len(message.items) or not isinstance(message.items[0], MessageData):
            msg = "Event 'NS' has no data attached to it!"
            raise ReplySyntaxError(msg)

        return cls.adapter().validate_python({'status': message.items[0].data})


@dataclass(kw_only=True, slots=True)
class EventNewConsensus(Event):
    """
    Structure for a :attr:`~EventWord.NEWCONSENSUS` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#NEWCONSENSUS

    """

    TYPE = EventWord.NEWCONSENSUS

    #: Raw content of the received consensus.
    status: str

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        if not len(message.items) or not isinstance(message.items[0], MessageData):
            msg = "Event 'NEWCONSENSUS' has no data attached to it!"
            raise ReplySyntaxError(msg)

        return cls.adapter().validate_python({'status': message.items[0].data})


@dataclass(kw_only=True, slots=True)
class EventBuildTimeoutSet(EventSimple):
    """
    Structure for a :attr:`~EventWord.BUILDTIMEOUT_SET` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#BUILDTIMEOUT_SET

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=1,
        args_map=(None, 'kind'),
        kwargs_map={
            'TOTAL_TIMES': 'total_times',
            'TIMEOUT_MS': 'timeout_ms',
            'XM': 'xm',
            'ALPHA': 'alpha',
            'CUTOFF_QUANTILE': 'cutoff_quantile',
            'TIMEOUT_RATE': 'timeout_rate',
            'CLOSE_MS': 'close_ms',
            'CLOSE_RATE': 'close_rate',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE = EventWord.BUILDTIMEOUT_SET

    #: Type of event we just received.
    kind: Literal['COMPUTED', 'RESET', 'SUSPENDED', 'DISCARD', 'RESUME']
    #: Integer count of timeouts stored.
    total_times: NonNegativeInt
    #: Integer timeout in milliseconds.
    timeout_ms: TimedeltaMilliseconds
    #: Estimated integer Pareto parameter Xm in milliseconds.
    xm: TimedeltaMilliseconds
    #: Estimated floating point Paredo parameter alpha.
    alpha: float
    #: Floating point CDF quantile cutoff point for this timeout.
    cutoff_quantile: float
    #: Floating point ratio of circuits that timeout.
    timeout_rate: float
    #: How long to keep measurement circs in milliseconds.
    close_ms: TimedeltaMilliseconds
    #: Floating point ratio of measurement circuits that are closed.
    close_rate: float


@dataclass(kw_only=True, slots=True)
class EventSignal(EventSimple):
    """
    Structure for a :attr:`~EventWord.SIGNAL` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#SIGNAL

    """

    SYNTAX = ReplySyntax(args_min=2, args_map=(None, 'signal'))
    TYPE = EventWord.SIGNAL

    #: The signal received by Tor.
    signal: Signal


@dataclass(kw_only=True, slots=True)
class EventCircBW(EventSimple):
    """
    Structure for a :attr:`~EventWord.CIRC_BW` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#CIRC_BW

    """

    SYNTAX = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'ID': 'circuit',
            'TIME': 'time',
            'READ': 'read',
            'DELIVERED_READ': 'read_delivered',
            'OVERHEAD_READ': 'read_overhead',
            'WRITTEN': 'written',
            'DELIVERED_WRITTEN': 'written_delivered',
            'OVERHEAD_WRITTEN': 'written_overhead',
            'SS': 'slow_start',
            'CWND': 'cwnd',
            'RTT': 'rtt',
            'MIN_RTT': 'rtt_min',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE = EventWord.CIRC_BW

    #: Records when Tor created the bandwidth event.
    time: DatetimeUTC

    #: Number of bytes read on this circuit since the last :attr:`~EventWord.CIRC_BW` event.
    read: int
    #: Byte count for incoming delivered relay messages.
    read_delivered: int
    #: Overhead of extra unused bytes at the end of read messages.
    read_overhead: int

    #: Number of bytes written on this circuit since the last :attr:`~EventWord.CIRC_BW` event.
    written: int
    #: Byte count for outgoing delivered relay messages.
    written_delivered: int
    #: Overhead of extra unused bytes at the end of written messages.
    written_overhead: int

    #: Provides an indication if the circuit is in slow start or not.
    slow_start: bool | None = None
    #: Size of the congestion window in terms of number of cells.
    cwnd: int | None = None
    #: The ``N_EWMA`` smoothed current RTT value.
    rtt: TimedeltaMilliseconds | None = None
    #: Minimum RTT value of the circuit.
    rtt_min: TimedeltaMilliseconds | None = None


@dataclass(kw_only=True, slots=True)
class EventConfChanged(Event, ReplyGetMap):
    """
    Structure for a :attr:`~EventWord.CONF_CHANGED` event.

    Hint:
        This class behaves somehow like :class:`.ReplyGetConf`.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#CONF_CHANGED

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        flags=(
            ReplySyntaxFlag.KW_ENABLE
            | ReplySyntaxFlag.KW_OMIT_VALS
            | ReplySyntaxFlag.KW_EXTRA
            | ReplySyntaxFlag.KW_RAW
        )
    )

    TYPE = EventWord.CONF_CHANGED

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        result = {}  # type: dict[str, Any]
        if len(message.items) > 1:
            result['data'] = cls._key_value_extract(message.items[1:])
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventCircMinor(EventSimple):
    """
    Structure for a :attr:`~EventWord.CIRC_MINOR` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#CIRC_MINOR

    """

    SYNTAX = ReplySyntax(
        args_min=3,
        args_map=(None, 'circuit', 'event', 'path'),
        kwargs_map={
            'BUILD_FLAGS': 'build_flags',
            'HS_STATE': 'hs_state',
            'PURPOSE': 'purpose',
            'REND_QUERY': 'rend_query',
            'TIME_CREATED': 'time_created',
            'OLD_HS_STATE': 'old_hs_state',
            'OLD_PURPOSE': 'old_purpose',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE = EventWord.CIRC_MINOR

    #: Circuit identifier.
    circuit: int
    #: Circuit event, either ``PURPOSE_CHANGED`` or ``CANNIBALIZED``.
    event: Annotated[CircuitEvent | str, Field(union_mode='left_to_right')]
    #: Circuit path, when provided.
    path: Annotated[Sequence[LongServerName], TrBeforeStringSplit()] | None = None

    #: Circuit build flags.
    build_flags: (
        Annotated[
            AbstractSet[
                Annotated[
                    CircuitBuildFlags | str,
                    Field(union_mode='left_to_right'),
                ],
            ],
            TrBeforeStringSplit(),
        ]
        | None
    ) = None
    # Current hidden service state when applicable.
    hs_state: CircuitHiddenServiceState | None = None
    #: When this circuit was created.
    time_created: DatetimeUTC | None = None
    #: Current circuit purpose.
    purpose: CircuitPurpose | None = None
    #: Onion address related to this circuit.
    rend_query: HiddenServiceAddress | None = None
    #: Previous hidden service state when applicable.
    old_hs_state: CircuitHiddenServiceState | None = None
    #: Previous circuit purpose.
    old_purpose: CircuitPurpose | None = None


#: Describes a list of cell statistics for :class:`EventCellStats`.
CellsByType: TypeAlias = Annotated[
    Mapping[str, int],
    BeforeValidator(dict),
    TrCast(
        Annotated[
            Sequence[
                Annotated[
                    tuple[str, str],
                    TrBeforeStringSplit(maxsplit=1, separator=':'),
                ]
            ],
            TrBeforeStringSplit(separator=','),
        ]
    ),
]

#: Describes a list of cell time statistics for :class:`EventCellStats`.
MsecByType: TypeAlias = Annotated[
    Mapping[str, TimedeltaMilliseconds],
    BeforeValidator(dict),
    TrCast(
        Annotated[
            Sequence[
                Annotated[
                    tuple[str, str],
                    TrBeforeStringSplit(maxsplit=1, separator=':'),
                ]
            ],
            TrBeforeStringSplit(separator=','),
        ]
    ),
]


@dataclass(kw_only=True, slots=True)
class EventCellStats(EventSimple):
    """
    Structure for a :attr:`~EventWord.CELL_STATS` event.

    Important:
        These events are only generated if TestingTorNetwork is set.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#CELL_STATS

    """

    SYNTAX = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'ID': 'circuit',
            'InboundConn': 'inbound_conn',
            'InboundQueue': 'inbound_queue',
            'InboundAdded': 'inbound_added',
            'InboundRemoved': 'inbound_removed',
            'InboundTime': 'inbound_time',
            'OutboundConn': 'outbound_conn',
            'OutboundQueue': 'outbound_queue',
            'OutboundAdded': 'outbound_added',
            'OutboundRemoved': 'outbound_removed',
            'OutboundTime': 'outbound_time',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE = EventWord.CELL_STATS

    #: Circuit identifier only included if the circuit originates at this node.
    circuit: int | None = None

    #: InboundQueue is the identifier of the inbound circuit queue of this circuit.
    inbound_queue: int | None = None
    #: Locally unique IDs of inbound OR connection.
    inbound_conn: int | None = None
    #: Total number of cells by cell type added to inbound queue.
    inbound_added: CellsByType | None = None
    #: Total number of cells by cell type processed from inbound queue.
    inbound_removed: CellsByType | None = None
    #: Total waiting times in milliseconds of all processed cells by cell type.
    inbound_time: MsecByType | None = None

    #: OutboundQueue is the identifier of the outbound circuit queue of this circuit.
    outbound_queue: int | None = None
    #: Locally unique IDs of outbound OR connection.
    outbound_conn: int | None = None
    #: Total number of cells by cell type added to outbound queue.
    outbound_added: CellsByType | None = None
    #: Total number of cells by cell type processed from outbound queue.
    outbound_removed: CellsByType | None = None
    #: Total waiting times in milliseconds of all processed cells by cell type.
    outbound_time: MsecByType | None = None


@dataclass(kw_only=True, slots=True)
class EventConnBW(EventSimple):
    """
    Structure for a :attr:`~EventWord.CONN_BW` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#CONN_BW

    """

    SYNTAX = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'ID': 'conn_id',
            'TYPE': 'conn_type',
            'READ': 'read',
            'WRITTEN': 'written',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE = EventWord.CONN_BW

    #: Identifier for this connection.
    conn_id: int
    #: Connection type, typically ``OR`` / ``DIR`` / ``EXIT``.
    conn_type: str
    #: Number of bytes read by Tor since the last event on this connection.
    read: int
    #: Number of bytes written by Tor since the last event on this connection.
    written: int


@dataclass(kw_only=True, slots=True)
class EventTbEmpty(EventSimple):
    """
    Structure for a :attr:`~EventWord.TB_EMPTY` event.

    Important:
        These events are only generated if TestingTorNetwork is set.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#TB_EMPTY

    """

    SYNTAX = ReplySyntax(
        args_min=2,
        args_map=(None, 'bucket'),
        kwargs_map={
            'ID': 'conn_id',
            'LAST': 'last',
            'READ': 'read',
            'WRITTEN': 'written',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE = EventWord.TB_EMPTY

    #: Name of the refilled bucket that was previously empty.
    bucket: Literal['GLOBAL', 'RELAY', 'ORCONN']

    #: Connection ID, only included when :attr:`bucket` is ``ORCONN``.
    conn_id: int | None = None

    #: Duration since the last refill.
    last: TimedeltaMilliseconds

    #: Duration that the read bucket was empty since the last refill.
    read: TimedeltaMilliseconds

    #: Duration that the write bucket was empty since the last refill.
    written: TimedeltaMilliseconds


@dataclass(kw_only=True, slots=True)
class EventHsDesc(EventSimple):
    """
    Structure for a :attr:`~EventWord.HS_DESC` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#HS_DESC

    """

    SYNTAX = ReplySyntax(
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

    #: Kind of action reported in this status update.
    action: HsDescAction
    #: Onion address the report status is for (without the ``.onion`` suffix).
    address: HiddenServiceAddress | Literal['UNKNOWN']
    #: Client authentication here is always :attr:`~.HsDescAuthTypeStr.NO_AUTH`.
    auth_type: HsDescAuthTypeStr
    #: The descriptor blinded key used for the index value at the "HsDir".
    descriptor_id: Base32Bytes | Base64Bytes | None = None
    #: Hidden service directory answering this request.
    hs_dir: LongServerName | Literal['UNKNOWN']
    #: Contains the computed index of the HsDir the descriptor was uploaded to or fetched from.
    hs_dir_index: Base16Bytes | None = None
    #: If :attr:`action` is :attr:`~.HsDescAction.FAILED`, Tor SHOULD send a reason field.
    reason: HsDescFailReason | None = None
    #: Field is not used for the :attr:`~.HsDescAction.CREATED` event because v3 doesn't use
    #: the replica number in the descriptor ID computation.
    replica: int | None = None


@dataclass(kw_only=True, slots=True)
class EventHsDescContent(Event):
    """
    Structure for a :attr:`~EventWord.HS_DESC_CONTENT` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#HS_DESC_CONTENT

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=4,
        args_map=(None, 'address', 'descriptor_id', 'hs_dir'),
    )
    TYPE = EventWord.HS_DESC_CONTENT

    #: Onion address the report status is for (without the ``.onion`` suffix).
    address: HiddenServiceAddress | Literal['UNKNOWN']
    #: Hidden service directory answering this request.
    hs_dir: LongServerName | Literal['UNKNOWN']
    #: Unique identifier for the descriptor.
    descriptor_id: Base32Bytes | Base64Bytes | None = None
    #: Text content of the hidden service descriptor.
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
class EventNetworkLiveness(EventSimple):
    """
    Structure for a :attr:`~EventWord.NETWORK_LIVENESS` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#NETWORK_LIVENESS

    """

    SYNTAX = ReplySyntax(
        args_min=2,
        args_map=(None, 'status'),
    )
    TYPE = EventWord.NETWORK_LIVENESS

    #: Current network status.
    status: LivenessStatus


@dataclass(kw_only=True, slots=True)
class EventLog(Event):
    """
    Base class for any event log.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=1,
        args_map=('severity', 'message'),
        flags=ReplySyntaxFlag.POS_REMAIN,
    )

    #: Log severity.
    severity: LogSeverity
    #: Log message.
    message: str

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        result = {}  # type: dict[str | None, Any]
        if len(message.items) and isinstance(message.items[0], MessageData):
            result.update(cls.SYNTAX.parse(message.items[0]))
            result['message'] = message.items[0].data
        else:
            result.update(cls.SYNTAX.parse(message))

        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventLogDebug(EventLog):
    """
    Event parser for :attr:`~EventWord.DEBUG` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE = EventWord.DEBUG


@dataclass(kw_only=True, slots=True)
class EventLogInfo(EventLog):
    """
    Event parser for :attr:`~EventWord.INFO` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE = EventWord.INFO


@dataclass(kw_only=True, slots=True)
class EventLogNotice(EventLog):
    """
    Event parser for :attr:`~EventWord.NOTICE` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE = EventWord.NOTICE


@dataclass(kw_only=True, slots=True)
class EventLogWarn(EventLog):
    """
    Event parser for :attr:`~EventWord.WARN` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE = EventWord.WARN


@dataclass(kw_only=True, slots=True)
class EventLogErr(EventLog):
    """
    Event parser for :attr:`~EventWord.ERR` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE = EventWord.ERR


def _discriminate_status_by_action(v: Any) -> str:
    """
    Discriminate a `STATUS_*` event by its actions.

    Args:
        v: The raw value to serialize/deserialize the event.

    Returns:
        The tag correspoding to the structure to parse in the `arguments` union.

    """
    match v:
        case Mapping():
            return v['action']
        case None:
            return '__NONE__'
        case _:  # pragma: no cover
            return v.action


@dataclass(kw_only=True, slots=True)
class EventStatus(Event):
    """
    Base class for all ``STATUS_*`` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#STATUS

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=3,
        args_map=(None, 'severity', 'action', 'argstring'),
        flags=ReplySyntaxFlag.POS_REMAIN,
    )
    SUBSYNTAXES: ClassVar[Mapping[str, ReplySyntax | None]]

    #: Severity of the reported status.
    severity: Annotated[
        Literal[LogSeverity.NOTICE, LogSeverity.WARNING, LogSeverity.ERROR],
        LogSeverity,
    ]
    #: Status action reported by this event (sub-classed).
    action: StrEnum

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        result = {'arguments': None}  # type: dict[str | None, Any]
        result.update(cls.SYNTAX.parse(message))

        argstring = result.pop('argstring', '')
        action = result['action']
        if action in cls.SUBSYNTAXES:
            syntax = cls.SUBSYNTAXES[action]
            if syntax is not None:
                # `action` here is used as a discriminator.
                arguments = {'action': action}  # type: dict[str | None, Any]
                arguments.update(syntax.parse_string(argstring))
                result['arguments'] = arguments
        else:
            logger.info("No syntax handler for action '%s'.", action)
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventStatusGeneral(EventStatus):
    """
    Event parser for :attr:`~EventWord.STATUS_GENERAL` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#STATUS

    """

    SUBSYNTAXES: ClassVar[Mapping[str, ReplySyntax | None]] = {
        'BUG': ReplySyntax(
            kwargs_map={'REASON': 'reason'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'CLOCK_JUMPED': ReplySyntax(
            kwargs_map={'TIME': 'time'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'CLOCK_SKEW': ReplySyntax(
            kwargs_map={
                'SOURCE': 'source',
                'SKEW': 'skew',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'DANGEROUS_VERSION': ReplySyntax(
            kwargs_map={
                'CURRENT': 'current',
                'REASON': 'reason',
                'RECOMMENDED': 'recommended',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'DIR_ALL_UNREACHABLE': None,
        'TOO_MANY_CONNECTIONS': ReplySyntax(
            kwargs_map={'CURRENT': 'current'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
    }
    TYPE = EventWord.STATUS_GENERAL

    #: Which action this general status event is for.
    action: StatusActionGeneral

    #: Arguments associated with the :attr:`action`.
    arguments: Annotated[
        Union[  # noqa: UP007
            Annotated[StatusGeneralBug, Tag('BUG')],
            Annotated[StatusGeneralClockJumped, Tag('CLOCK_JUMPED')],
            Annotated[StatusGeneralClockSkew, Tag('CLOCK_SKEW')],
            Annotated[StatusGeneralDangerousVersion, Tag('DANGEROUS_VERSION')],
            Annotated[StatusGeneralTooManyConnections, Tag('TOO_MANY_CONNECTIONS')],
            Annotated[None, Tag('__NONE__')],
        ],
        Discriminator(_discriminate_status_by_action),
    ]


@dataclass(kw_only=True, slots=True)
class EventStatusClient(EventStatus):
    """
    Event parser for :attr:`~EventWord.STATUS_CLIENT` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#STATUS

    """

    SUBSYNTAXES: ClassVar[Mapping[str, ReplySyntax | None]] = {
        'BOOTSTRAP': ReplySyntax(
            kwargs_map={
                'COUNT': 'count',
                'HOST': 'host',
                'HOSTADDR': 'hostaddr',
                'PROGRESS': 'progress',
                'REASON': 'reason',
                'RECOMMENDATION': 'recommendation',
                'SUMMARY': 'summary',
                'TAG': 'tag',
                'WARNING': 'warning',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'ENOUGH_DIR_INFO': None,
        'NOT_ENOUGH_DIR_INFO': None,
        'CIRCUIT_ESTABLISHED': None,
        'CIRCUIT_NOT_ESTABLISHED': ReplySyntax(
            kwargs_map={'REASON': 'reason'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'CONSENSUS_ARRIVED': None,
        'DANGEROUS_PORT': ReplySyntax(
            kwargs_map={
                'PORT': 'port',
                'RESULT': 'result',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'DANGEROUS_SOCKS': ReplySyntax(
            kwargs_map={
                'PROTOCOL': 'protocol',
                'ADDRESS': 'address',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'SOCKS_UNKNOWN_PROTOCOL': None,
        'SOCKS_BAD_HOSTNAME': ReplySyntax(
            kwargs_map={'HOSTNAME': 'hostname'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
    }
    TYPE = EventWord.STATUS_CLIENT

    #: Which action this client status event is for.
    action: StatusActionClient

    #: Arguments associated with the :attr:`action`.
    arguments: Annotated[
        Union[  # noqa: UP007
            Annotated[StatusClientBootstrap, Tag('BOOTSTRAP')],
            Annotated[StatusClientCircuitNotEstablished, Tag('CIRCUIT_NOT_ESTABLISHED')],
            Annotated[StatusClientDangerousPort, Tag('DANGEROUS_PORT')],
            Annotated[StatusClientDangerousSocks, Tag('DANGEROUS_SOCKS')],
            Annotated[StatusClientSocksBadHostname, Tag('SOCKS_BAD_HOSTNAME')],
            Annotated[None, Tag('__NONE__')],
        ],
        Discriminator(_discriminate_status_by_action),
    ]


@dataclass(kw_only=True, slots=True)
class EventStatusServer(EventStatus):
    """
    Event parser for :attr:`~EventWord.STATUS_SERVER` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#STATUS

    """

    SUBSYNTAXES: ClassVar[Mapping[str, ReplySyntax | None]] = {
        'EXTERNAL_ADDRESS': ReplySyntax(
            kwargs_map={
                'ADDRESS': 'address',
                'HOSTNAME': 'hostname',
                'METHOD': 'method',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'CHECKING_REACHABILITY': ReplySyntax(
            kwargs_map={'ORADDRESS': 'or_address'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'REACHABILITY_SUCCEEDED': ReplySyntax(
            kwargs_map={'ORADDRESS': 'or_address'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'GOOD_SERVER_DESCRIPTOR': None,
        'NAMESERVER_STATUS': ReplySyntax(
            kwargs_map={
                'NS': 'ns',
                'STATUS': 'status',
                'ERR': 'err',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'NAMESERVER_ALL_DOWN': None,
        'DNS_HIJACKED': None,
        'DNS_USELESS': None,
        'BAD_SERVER_DESCRIPTOR': ReplySyntax(
            kwargs_map={
                'DIRAUTH': 'dir_auth',
                'REASON': 'reason',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'ACCEPTED_SERVER_DESCRIPTOR': ReplySyntax(
            kwargs_map={'DIRAUTH': 'dir_auth'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'REACHABILITY_FAILED': ReplySyntax(
            kwargs_map={'ORADDRESS': 'or_address'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'HIBERNATION_STATUS': ReplySyntax(
            kwargs_map={'STATUS': 'status'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
    }
    TYPE = EventWord.STATUS_SERVER

    #: Which action this server status event is for.
    action: StatusActionServer

    #: Arguments associated with the :attr:`action`.
    arguments: Annotated[
        Union[  # noqa: UP007
            Annotated[StatusServerExternalAddress, Tag('EXTERNAL_ADDRESS')],
            Annotated[StatusServerCheckingReachability, Tag('CHECKING_REACHABILITY')],
            Annotated[StatusServerReachabilitySucceeded, Tag('REACHABILITY_SUCCEEDED')],
            Annotated[StatusServerNameserverStatus, Tag('NAMESERVER_STATUS')],
            Annotated[StatusServerBadServerDescriptor, Tag('BAD_SERVER_DESCRIPTOR')],
            Annotated[StatusServerAcceptedServerDescriptor, Tag('ACCEPTED_SERVER_DESCRIPTOR')],
            Annotated[StatusServerReachabilityFailed, Tag('REACHABILITY_FAILED')],
            Annotated[StatusServerHibernationStatus, Tag('HIBERNATION_STATUS')],
            Annotated[None, Tag('__NONE__')],
        ],
        Discriminator(_discriminate_status_by_action),
    ]


@dataclass(kw_only=True, slots=True)
class EventTransportLaunched(EventSimple):
    """
    Event parser for :attr:`~EventWord.TRANSPORT_LAUNCHED` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#TRANSPORT_LAUNCHED

    """

    SYNTAX = ReplySyntax(
        args_min=5,
        args_map=(None, 'side', 'name', 'host', 'port'),
    )
    TYPE = EventWord.TRANSPORT_LAUNCHED

    #: Which side the transport was launched for.
    side: Literal['client', 'server']
    #: Name of the pluggable transport.
    name: str
    #: Host hosting the pluggable transport.
    host: AnyAddress
    #: Associated TCP port.
    port: AnyPort


@dataclass(kw_only=True, slots=True)
class EventPtLog(EventSimple):
    """
    Event parser for :attr:`~EventWord.PT_LOG` events.

    See Also:
        - https://spec.torproject.org/control-spec/replies.html#PT_LOG
        - https://spec.torproject.org/pt-spec/ipc.html#log-messages

    """

    SYNTAX = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'PT': 'program',
            'MESSAGE': 'message',
            'SEVERITY': 'severity',
        },
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED | ReplySyntaxFlag.KW_EXTRA,
    )
    TYPE = EventWord.PT_LOG

    #: Program path as defined in the ``TransportPlugin`` configuration option.
    program: str
    #: The status message that the PT sends back to the tor parent minus
    #: the ``STATUS`` string prefix.
    message: str
    #: Log severity.
    severity: LogSeverity


@dataclass(kw_only=True, slots=True)
class EventPtStatus(Event):
    """
    Event parser for :attr:`~EventWord.PT_STATUS` events.

    See Also:
        - https://spec.torproject.org/control-spec/replies.html#PT_STATUS
        - https://spec.torproject.org/pt-spec/ipc.html#status-messages

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'TRANSPORT': 'transport',
            'PT': 'program',
        },
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED | ReplySyntaxFlag.KW_EXTRA,
    )
    TYPE = EventWord.PT_STATUS

    #: Program path as defined in the ``TransportPlugin`` configuration option.
    program: str
    #: This value indicates a hint on what the PT is such as the name or the protocol used.
    transport: str
    #: All keywords reported by the underlying PT plugin, such as messages, etc...
    values: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        extract = dict(cls.SYNTAX.parse(message))
        result: dict[str, Any] = {
            key: extract.pop(key, None) for key in ('program', 'transport')
        }
        result['values'] = extract
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventUnknown(Event):
    """
    Structure for an unknown event.

    This structure is the default fallback when no event class suits the event type
    the user subscribed to.

    """

    TYPE = None

    #: Original message received for this event.
    message: Message

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event dataclass from a received message."""
        return cls.adapter().validate_python({'message': message})


_EVENT_MAP = {
    'ADDRMAP': EventAddrMap,
    'BUILDTIMEOUT_SET': EventBuildTimeoutSet,
    'DISCONNECT': EventDisconnect,
    'CONF_CHANGED': EventConfChanged,
    'CELL_STATS': EventCellStats,
    'CIRC_MINOR': EventCircMinor,
    'CIRC_BW': EventCircBW,
    'CONN_BW': EventConnBW,
    'HS_DESC': EventHsDesc,
    'HS_DESC_CONTENT': EventHsDescContent,
    'NETWORK_LIVENESS': EventNetworkLiveness,
    'NEWCONSENSUS': EventNewConsensus,
    'NS': EventNetworkStatus,
    'DEBUG': EventLogDebug,
    'INFO': EventLogInfo,
    'NOTICE': EventLogNotice,
    'WARN': EventLogWarn,
    'ERR': EventLogErr,
    'PT_LOG': EventPtLog,
    'PT_STATUS': EventPtStatus,
    'SIGNAL': EventSignal,
    'STATUS_GENERAL': EventStatusGeneral,
    'STATUS_CLIENT': EventStatusClient,
    'STATUS_SERVER': EventStatusServer,
    'TB_EMPTY': EventTbEmpty,
    'TRANSPORT_LAUNCHED': EventTransportLaunched,
}  # type: Mapping[str, type[Event]]


def event_from_message(message: Message) -> Event:
    """
    Parse an event message to the corresponding event structure.

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
