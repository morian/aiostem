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
from functools import cached_property
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Literal, Self, TypeAlias, Union

from pydantic import BeforeValidator, Discriminator, Field, NonNegativeInt, Tag, TypeAdapter

from .exceptions import MessageError, ReplySyntaxError
from .reply import ReplyGetMap
from .structures import (
    CircuitBuildFlags,
    CircuitCloseReason,
    CircuitEvent,
    CircuitHiddenServicePow,
    CircuitHiddenServiceState,
    CircuitPurpose,
    CircuitStatus,
    GuardEventStatus,
    HiddenServiceAddress,
    HiddenServiceAddressV2,
    HiddenServiceAddressV3,
    HsDescAction,
    HsDescAuthTypeStr,
    HsDescFailReason,
    HsDescV2,
    HsDescV3,
    LivenessStatus,
    LogSeverity,
    LongServerName,
    OrConnCloseReason,
    OrConnStatus,
    RemapSource,
    RouterStatus,
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
    StreamClientProtocol,
    StreamCloseReason,
    StreamPurpose,
    StreamStatus,
    StreamTarget,
    TcpAddressPort,
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
    #:
    #: See Also:
    #:     :class:`EventCirc`
    CIRC = 'CIRC'

    #: Stream status changed.
    #:
    #: See Also:
    #:     :class:`EventStream`
    STREAM = 'STREAM'

    #: OR Connection status changed.
    #:
    #: See Also:
    #:     :class:`EventOrConn`
    ORCONN = 'ORCONN'

    #: Bandwidth used in the last second.
    #:
    #: See Also:
    #:     :class:`EventBandwidth`
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
    #:
    #: See Also:
    #:     :class:`EventNewDesc`
    NEWDESC = 'NEWDESC'

    #: New Address mapping.
    #:
    #: See Also:
    #:     :class:`EventAddrMap`
    ADDRMAP = 'ADDRMAP'

    #: Descriptors uploaded to us in our role as authoritative dirserver.
    #:
    #: This event has been deprecated since Tor v0.3.3.1.
    AUTHDIR_NEWDESCS = 'AUTHDIR_NEWDESCS'

    #: Our descriptor changed.
    #:
    #: See Also:
    #:     :class:`EventDescChanged`
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
    #:
    #: See Also:
    #:     :class:`EventGuard`
    GUARD = 'GUARD'

    #: Network status has changed.
    #:
    #: See Also:
    #:     :class:`EventNetworkStatus`
    NS = 'NS'

    #: Bandwidth used on an application stream.
    #:
    #: See Also:
    #:     :class:`EventStreamBW`
    STREAM_BW = 'STREAM_BW'

    #: Per-country client stats.
    #:
    #: See Also:
    #:     :class:`EventClientsSeen`
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
        """Build an event from a received message."""
        result = cls.SYNTAX.parse(message)
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class EventDisconnect(Event):
    """
    Structure for a :attr:`~EventWordInternal.DISCONNECT` event.

    Note:
        This event is internal to ``aiostem``.

    """

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWordInternal.DISCONNECT

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event from a received message."""
        return cls.adapter().validate_python({})


@dataclass(kw_only=True, slots=True)
class EventAddrMap(EventSimple):
    """
    Structure for a :attr:`~EventWord.ADDRMAP` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#ADDRMAP

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=3,
        args_map=(None, 'original', 'replacement'),
        kwargs_map={
            None: 'expires_local',
            'error': 'error',
            'EXPIRES': 'expires',
            'CACHED': 'cached',
            'STREAMID': 'stream',
        },
        flags=ReplySyntaxFlag.KW_ENABLE
        | ReplySyntaxFlag.KW_QUOTED
        | ReplySyntaxFlag.KW_OMIT_KEYS,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.ADDRMAP

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
class EventDescChanged(EventSimple):
    """
    Structure for a :attr:`~EventWord.DESCCHANGED` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#DESCCHANGED

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(args_min=1, args_map=(None,))
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.DESCCHANGED


@dataclass(kw_only=True, slots=True)
class EventStreamBW(EventSimple):
    """
    Structure for a :attr:`~EventWord.STREAM_BW` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#STREAM_BW

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=5,
        args_map=(None, 'stream', 'written', 'read', 'time'),
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.STREAM_BW

    #: Stream identifier.
    stream: int
    #: Number of bytes read by the application since the last event on this stream.
    read: int
    #: Number of bytes written by the application since the last event on this stream.
    written: int
    #: Records when Tor created the bandwidth event.
    time: DatetimeUTC


#: Describes a list of cell statistics for :class:`EventCellStats`.
GenericStatsMap: TypeAlias = Annotated[
    Mapping[str, int],
    BeforeValidator(dict),
    TrCast(
        Annotated[
            Sequence[
                Annotated[
                    tuple[str, str],
                    TrBeforeStringSplit(maxsplit=1, separator='='),
                ]
            ],
            TrBeforeStringSplit(separator=','),
        ],
        mode='before',
    ),
]


@dataclass(kw_only=True, slots=True)
class EventCirc(EventSimple):
    """
    Structure for a :attr:`~EventWord.CIRC` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#CIRC

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=3,
        args_map=(None, 'circuit', 'status'),
        kwargs_map={
            None: 'path',
            'BUILD_FLAGS': 'build_flags',
            'HS_POW': 'hs_pow',
            'HS_STATE': 'hs_state',
            'PURPOSE': 'purpose',
            'REASON': 'reason',
            'REMOTE_REASON': 'remote_reason',
            'REND_QUERY': 'rend_query',
            'SOCKS_USERNAME': 'socks_username',
            'SOCKS_PASSWORD': 'socks_password',
            'TIME_CREATED': 'time_created',
        },
        flags=ReplySyntaxFlag.KW_ENABLE
        | ReplySyntaxFlag.KW_OMIT_KEYS
        | ReplySyntaxFlag.KW_QUOTED,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.CIRC

    #: Circuit identifier this event is triggered for.
    circuit: NonNegativeInt
    #: Circuit status reported by this event.
    status: Annotated[CircuitStatus | str, Field(union_mode='left_to_right')]

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

    #: Hidden service proof of work effort attached to this circuit.
    hs_pow: (
        Annotated[
            CircuitHiddenServicePow,
            TrBeforeStringSplit(
                dict_keys=('type', 'effort'),
                separator=',',
            ),
        ]
        | None
    ) = None

    # Current hidden service state when applicable.
    hs_state: (
        Annotated[
            CircuitHiddenServiceState | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None

    #: List of servers in this circuit, when provided.
    path: Annotated[Sequence[LongServerName], TrBeforeStringSplit()] | None = None

    #: Current circuit purpose.
    purpose: (
        Annotated[
            CircuitPurpose | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None

    #: This field is provided only for ``FAILED`` and ``CLOSED`` events.
    reason: (
        Annotated[
            CircuitCloseReason | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None

    #: Provided only when we receive a DESTROY cell or RELAY_TRUNCATE message.
    remote_reason: (
        Annotated[
            CircuitCloseReason | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None

    #: Onion address related to this circuit (if any).
    rend_query: HiddenServiceAddress | None = None
    #: Username used by a SOCKS client to connect to Tor and initiate this circuit.
    socks_username: str | None = None
    #: Password used by a SOCKS client to connect to Tor and initiate this circuit.
    socks_password: str | None = None
    #: When this circuit was created, if provided.
    time_created: DatetimeUTC | None = None


@dataclass(kw_only=True, slots=True)
class EventStream(EventSimple):
    """
    Structure for a :attr:`~EventWord.STREAM` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#STREAM

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=5,
        args_map=(None, 'stream', 'status', 'circuit', 'target'),
        kwargs_map={
            'CLIENT_PROTOCOL': 'client_protocol',
            'ISO_FIELDS': 'iso_fields',
            'NYM_EPOCH': 'nym_epoch',
            'PURPOSE': 'purpose',
            'REASON': 'reason',
            'REMOTE_REASON': 'remote_reason',
            'SESSION_GROUP': 'session_group',
            'SOURCE': 'source',
            'SOURCE_ADDR': 'source_addr',
            'SOCKS_USERNAME': 'socks_username',
            'SOCKS_PASSWORD': 'socks_password',
        },
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.STREAM

    #: Stream identifier reported in this event.
    stream: int
    #: Status of the stream event reported here.
    status: StreamStatus
    #: Circuit ID linked to this stream.
    circuit: NonNegativeInt
    #: Target address or server of this stream (or ``0`` when unattached).
    target: StreamTarget

    #: The protocol that was used by a client to initiate this stream.
    client_protocol: (
        Annotated[
            StreamClientProtocol | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None

    #: Indicates the set of STREAM event fields for which stream isolation is enabled.
    iso_fields: Annotated[AbstractSet[str], TrBeforeStringSplit()] | None = None
    #: Nym epoch that was active when a client initiated this stream.
    nym_epoch: NonNegativeInt | None = None
    #: Only for :attr:`~.StreamStatus.NEW` and :attr:`~.StreamStatus.NEWRESOLVE` events.
    purpose: Annotated[StreamPurpose | str, Field(union_mode='left_to_right')] | None = None

    #: Provided only for ``FAILED``, ``CLOSED``, and ``DETACHED`` events,
    reason: (
        Annotated[
            StreamCloseReason | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None

    #: Provided only when we receive a RELAY_END message.
    remote_reason: (
        Annotated[
            StreamCloseReason | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None

    #: Indicates the session group of the listener port that a client used for this stream.
    session_group: int | None = None
    #: Username used by a SOCKS client to connect to Tor and initiate this circuit.
    socks_username: str | None = None
    #: Password used by a SOCKS client to connect to Tor and initiate this circuit.
    socks_password: str | None = None
    #: Generally either ``CACHE`` or ``EXIT``, used with :attr:`.StreamStatus.REMAP`.
    source: Annotated[RemapSource | str, Field(union_mode='left_to_right')] | None = None
    #: Source (local) address.
    source_addr: TcpAddressPort | None = None


@dataclass(kw_only=True, slots=True)
class EventOrConn(EventSimple):
    """
    Structure for a :attr:`~EventWord.ORCONN` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#ORCONN

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=3,
        args_map=(None, 'server', 'status'),
        kwargs_map={
            'REASON': 'reason',
            'NCIRCS': 'circuit_count',
            'ID': 'conn_id',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.ORCONN

    #: Onion router server name reported in this event.
    server: LongServerName
    #: Status of the connection to the onion router.
    status: OrConnStatus
    #: When :attr:`status` is ``FAILED`` or ``CLOSED``, this is the reason why.
    reason: Annotated[OrConnCloseReason | str, Field(union_mode='left_to_right')] | None = None
    #: Counts both established and pending circuits.
    circuit_count: NonNegativeInt | None = None
    #: Connection identifier.
    conn_id: int | None = None


@dataclass(kw_only=True, slots=True)
class EventBandwidth(EventSimple):
    """
    Structure for a :attr:`~EventWord.BW` event.

    Note:
        Documentation seems to tell that there are keyword arguments on this event
        but the real implementation does not show any of them.
        These are being ignored here for now.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#BW

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=3,
        args_map=(None, 'read', 'written'),
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.BW

    #: Total amount of bytes read.
    read: int
    #: Total amount of bytes written
    written: int


@dataclass(kw_only=True, slots=True)
class EventGuard(EventSimple):
    """
    Structure for a :attr:`~EventWord.GUARD` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#GUARD

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=4,
        args_map=(None, 'type', 'name', 'status'),
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.GUARD

    #: Type of guard node, should be ``ENTRY``.
    type: str
    #: Full server name of the guard node.
    name: LongServerName
    #: Status of the guard in our event.
    status: Annotated[GuardEventStatus | str, Field(union_mode='left_to_right')]


@dataclass(kw_only=True, slots=True)
class EventNewDesc(EventSimple):
    """
    Structure for a :attr:`~EventWord.NEWDESC` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#NEWDESC

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={None: 'servers'},
        kwargs_multi={'servers'},
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_OMIT_KEYS,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.NEWDESC

    #: List of new server identifiers received.
    servers: Sequence[LongServerName] = field(default_factory=list)


@dataclass(kw_only=True, slots=True)
class EventClientsSeen(EventSimple):
    """
    Structure for a :attr:`~EventWord.CLIENTS_SEEN` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#CLIENTS_SEEN

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'TimeStarted': 'time',
            'CountrySummary': 'countries',
            'IPVersions': 'ip_versions',
        },
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.CLIENTS_SEEN

    #: When the reported summary counts started.
    time: DatetimeUTC
    #: A map of countries seen by Tor.
    countries: GenericStatsMap
    #: A map of ip versions encountered.
    ip_versions: GenericStatsMap


@dataclass(kw_only=True, slots=True)
class EventBaseNetworkStatus(Event):
    """Base class for network status events."""

    SYNTAX_P: ClassVar[ReplySyntax] = ReplySyntax(args_min=2, args_map=('policy', 'ports'))
    SYNTAX_R: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=8,
        args_map=(
            'nickname',
            'identity',
            'digest',
            'exp_date',
            'exp_time',
            'ip',
            'or_port',
            'dir_port',
        ),
    )
    SYNTAX_W: ClassVar[ReplySyntax] = ReplySyntax(
        kwargs_map={
            'Bandwidth': 'bandwidth',
            'Measured': 'bw_measured',
            'Unmeasured': 'bw_unmeasured',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )

    #: Raw content of the new network status.
    routers: Sequence[RouterStatus]

    @classmethod
    def parse_router_statuses(cls, body: str) -> Sequence[dict[str, Any]]:
        """
        Parse router statuses to raw structures.

        Args:
            body: raw text containing router statuses.

        Returns:
            A list of dictonaries required to build a router status sequence.

        """
        current = {}  # type: dict[str, Any]
        routers = []  # type: list[dict[str, Any]]
        for line in body.splitlines():
            if not len(line):
                continue

            key, *args = line.split(' ', maxsplit=1)
            match key:
                case 'a':
                    addresses = current.setdefault('addresses', [])
                    addresses.append(args[0])

                case 'p':
                    current['port_policy'] = cls.SYNTAX_P.parse_string(args[0])

                case 'r':
                    if current:
                        routers.append(current)

                    current = {}
                    current.update(cls.SYNTAX_R.parse_string(args[0]))

                case 's':
                    current['flags'] = args[0].split(' ')

                case 'w':
                    current.update(cls.SYNTAX_W.parse_string(args[0]))

                case _:  # pragma: no cover
                    content = args[0] if len(args) else '__NONE__'
                    logger.warning('Unhandled network status type %s: %s', key, content)

        if current:  # pragma: no branch
            routers.append(current)
        return routers

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event from a received message."""
        if not len(message.items) or not isinstance(message.items[0], MessageData):
            msg = "Event 'NS' has no data attached to it!"
            raise ReplySyntaxError(msg)

        routers = cls.parse_router_statuses(message.items[0].data)
        return cls.adapter().validate_python({'routers': routers})


@dataclass(kw_only=True, slots=True)
class EventNetworkStatus(EventBaseNetworkStatus):
    """
    Structure for a :attr:`~EventWord.NS` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#NS

    """

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.NS


@dataclass(kw_only=True, slots=True)
class EventNewConsensus(EventBaseNetworkStatus):
    """
    Structure for a :attr:`~EventWord.NEWCONSENSUS` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#NEWCONSENSUS

    """

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.NEWCONSENSUS


@dataclass(kw_only=True, slots=True)
class EventBuildTimeoutSet(EventSimple):
    """
    Structure for a :attr:`~EventWord.BUILDTIMEOUT_SET` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#BUILDTIMEOUT_SET

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=2,
        args_map=(None, 'type'),
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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.BUILDTIMEOUT_SET

    #: Type of event we just received.
    type: Literal['COMPUTED', 'RESET', 'SUSPENDED', 'DISCARD', 'RESUME']
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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(args_min=2, args_map=(None, 'signal'))
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.SIGNAL

    #: The signal received by Tor.
    signal: Signal


@dataclass(kw_only=True, slots=True)
class EventCircBW(EventSimple):
    """
    Structure for a :attr:`~EventWord.CIRC_BW` event.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#CIRC_BW

    """

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.CIRC_BW

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

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.CONF_CHANGED

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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=3,
        args_map=(None, 'circuit', 'event'),
        kwargs_map={
            None: 'path',
            'BUILD_FLAGS': 'build_flags',
            'HS_STATE': 'hs_state',
            'PURPOSE': 'purpose',
            'REND_QUERY': 'rend_query',
            'TIME_CREATED': 'time_created',
            'OLD_HS_STATE': 'old_hs_state',
            'OLD_PURPOSE': 'old_purpose',
        },
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_OMIT_KEYS,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.CIRC_MINOR

    #: Circuit identifier.
    circuit: NonNegativeInt
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
    hs_state: (
        Annotated[
            CircuitHiddenServiceState | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None
    #: When this circuit was created.
    time_created: DatetimeUTC | None = None

    #: Current circuit purpose.
    purpose: (
        Annotated[
            CircuitPurpose | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None

    #: Onion address related to this circuit.
    rend_query: HiddenServiceAddress | None = None

    #: Previous hidden service state when applicable.
    old_hs_state: (
        Annotated[
            CircuitHiddenServiceState | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None
    #: Previous circuit purpose.
    old_purpose: (
        Annotated[
            CircuitPurpose | str,
            Field(union_mode='left_to_right'),
        ]
        | None
    ) = None


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
        ],
        mode='before',
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
        ],
        mode='before',
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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'ID': 'circuit',
            'InboundConn': 'inbound_conn_id',
            'InboundQueue': 'inbound_queue',
            'InboundAdded': 'inbound_added',
            'InboundRemoved': 'inbound_removed',
            'InboundTime': 'inbound_time',
            'OutboundConn': 'outbound_conn_id',
            'OutboundQueue': 'outbound_queue',
            'OutboundAdded': 'outbound_added',
            'OutboundRemoved': 'outbound_removed',
            'OutboundTime': 'outbound_time',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.CELL_STATS

    #: Circuit identifier only included if the circuit originates at this node.
    circuit: NonNegativeInt | None = None

    #: InboundQueue is the identifier of the inbound circuit queue of this circuit.
    inbound_queue: int | None = None
    #: Locally unique IDs of inbound OR connection.
    inbound_conn_id: int | None = None
    #: Total number of cells by cell type added to inbound queue.
    inbound_added: CellsByType | None = None
    #: Total number of cells by cell type processed from inbound queue.
    inbound_removed: CellsByType | None = None
    #: Total waiting times in milliseconds of all processed cells by cell type.
    inbound_time: MsecByType | None = None

    #: OutboundQueue is the identifier of the outbound circuit queue of this circuit.
    outbound_queue: int | None = None
    #: Locally unique IDs of outbound OR connection.
    outbound_conn_id: int | None = None
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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.CONN_BW

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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.TB_EMPTY

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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=5,
        args_map=(None, 'action', 'address', 'auth_type', 'hs_dir'),
        kwargs_map={
            None: 'descriptor_id',
            'REASON': 'reason',
            'REPLICA': 'replica',
            'HSDIR_INDEX': 'hs_dir_index',
        },
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_OMIT_KEYS,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.HS_DESC

    #: Kind of action reported in this status update.
    action: HsDescAction
    #: Onion address the report status is for (without the ``.onion`` suffix).
    address: HiddenServiceAddress | Literal['UNKNOWN']
    #: Client authentication here is always :attr:`~.HsDescAuthTypeStr.NO_AUTH`.
    auth_type: HsDescAuthTypeStr
    #: The descriptor blinded key used for the index value at the ``HsDir``.
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


@dataclass(kw_only=True)
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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.HS_DESC_CONTENT

    #: Onion address the report status is for (without the ``.onion`` suffix).
    address: HiddenServiceAddress | Literal['UNKNOWN']
    #: Hidden service directory answering this request.
    hs_dir: LongServerName | Literal['UNKNOWN']
    #: Unique identifier for the descriptor.
    descriptor_id: Base32Bytes | Base64Bytes | None = None
    #: Text content of the hidden service descriptor.
    descriptor_text: str

    @cached_property
    def descriptor(self) -> HsDescV2 | HsDescV3:
        """Get the parsed descriptor."""
        match self.address:
            case HiddenServiceAddressV2():
                return HsDescV2.from_text(self.descriptor_text)

            case HiddenServiceAddressV3():
                return HsDescV3.from_text(self.descriptor_text)

            case _:  # pragma: no cover
                msg = 'Unhandled hidden service descriptor format.'
                raise NotImplementedError(msg)

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event from a received message."""
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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=2,
        args_map=(None, 'status'),
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.NETWORK_LIVENESS

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
        """Build an event from a received message."""
        result = {}  # type: dict[str, Any]
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

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.DEBUG


@dataclass(kw_only=True, slots=True)
class EventLogInfo(EventLog):
    """
    Event parser for :attr:`~EventWord.INFO` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.INFO


@dataclass(kw_only=True, slots=True)
class EventLogNotice(EventLog):
    """
    Event parser for :attr:`~EventWord.NOTICE` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.NOTICE


@dataclass(kw_only=True, slots=True)
class EventLogWarn(EventLog):
    """
    Event parser for :attr:`~EventWord.WARN` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.WARN


@dataclass(kw_only=True, slots=True)
class EventLogErr(EventLog):
    """
    Event parser for :attr:`~EventWord.ERR` events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#LOG

    """

    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.ERR


def _discriminate_status_by_action(v: Any) -> str:
    """
    Discriminate a `STATUS_*` event by its actions.

    Args:
        v: The raw value to serialize/deserialize the event.

    Returns:
        The tag corresponding to the structure to parse in the ``arguments`` union.

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
        """Build an event from a received message."""
        result = {'arguments': None}  # type: dict[str, Any]
        result.update(cls.SYNTAX.parse(message))

        argstring = result.pop('argstring', '')
        action = result['action']
        if action in cls.SUBSYNTAXES:
            syntax = cls.SUBSYNTAXES[action]
            if syntax is not None:
                # `action` here is used as a discriminator.
                arguments = {'action': action}  # type: dict[str, Any]
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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.STATUS_GENERAL

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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.STATUS_CLIENT

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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.STATUS_SERVER

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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=5,
        args_map=(None, 'side', 'name', 'host', 'port'),
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.TRANSPORT_LAUNCHED

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

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'PT': 'program',
            'MESSAGE': 'message',
            'SEVERITY': 'severity',
        },
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED | ReplySyntaxFlag.KW_EXTRA,
    )
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.PT_LOG

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
    TYPE: ClassVar[EventWordInternal | EventWord | None] = EventWord.PT_STATUS

    #: Program path as defined in the ``TransportPlugin`` configuration option.
    program: str
    #: This value indicates a hint on what the PT is such as the name or the protocol used.
    transport: str
    #: All keywords reported by the underlying PT plugin, such as messages, etc...
    values: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event from a received message."""
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

    TYPE: ClassVar[EventWordInternal | EventWord | None] = None

    #: Original message received for this event.
    message: Message

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build an event from a received message."""
        return cls.adapter().validate_python({'message': message})


_EVENT_MAP = {
    'ADDRMAP': EventAddrMap,
    'BUILDTIMEOUT_SET': EventBuildTimeoutSet,
    'BW': EventBandwidth,
    'DISCONNECT': EventDisconnect,
    'CIRC': EventCirc,
    'CONF_CHANGED': EventConfChanged,
    'CLIENTS_SEEN': EventClientsSeen,
    'CELL_STATS': EventCellStats,
    'CIRC_MINOR': EventCircMinor,
    'CIRC_BW': EventCircBW,
    'CONN_BW': EventConnBW,
    'DESCCHANGED': EventDescChanged,
    'GUARD': EventGuard,
    'HS_DESC': EventHsDesc,
    'HS_DESC_CONTENT': EventHsDescContent,
    'NETWORK_LIVENESS': EventNetworkLiveness,
    'NEWCONSENSUS': EventNewConsensus,
    'NEWDESC': EventNewDesc,
    'NS': EventNetworkStatus,
    'DEBUG': EventLogDebug,
    'INFO': EventLogInfo,
    'NOTICE': EventLogNotice,
    'WARN': EventLogWarn,
    'ERR': EventLogErr,
    'ORCONN': EventOrConn,
    'PT_LOG': EventPtLog,
    'PT_STATUS': EventPtStatus,
    'SIGNAL': EventSignal,
    'STATUS_GENERAL': EventStatusGeneral,
    'STATUS_CLIENT': EventStatusClient,
    'STATUS_SERVER': EventStatusServer,
    'STREAM': EventStream,
    'STREAM_BW': EventStreamBW,
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
        A parsed event corresponding to the event in the provided message.

    """
    if not message.is_event:
        msg = 'The provided message is not an event!'
        raise MessageError(msg)

    handler = _EVENT_MAP.get(message.keyword)
    if handler is None:
        handler = EventUnknown
    return handler.from_message(message)
