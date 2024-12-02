from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, ClassVar, Literal, Self, Union

from pydantic import Discriminator, Tag, TypeAdapter

from ..exceptions import MessageError, ReplySyntaxError
from .message import Message, MessageData
from .structures import (
    HsDescAction,
    HsDescAuthType,
    HsDescFailReason,
    LivenessStatus,
    LogSeverity,
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
from .syntax import ReplySyntax, ReplySyntaxFlag
from .utils import (
    AnyPort,
    Base32Bytes,
    Base64Bytes,
    HexBytes,
    HiddenServiceAddress,
    LogSeverityTransformer,
)

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
    NS = 'NS'

    #: Bandwidth used on an application stream.
    STREAM_BW = 'STREAM_BW'

    #: Per-country client stats.
    CLIENTS_SEEN = 'CLIENTS_SEEN'

    #: New consensus networkstatus has arrived.
    NEWCONSENSUS = 'NEWCONSENSUS'

    #: New circuit buildtime has been set.
    BUILDTIMEOUT_SET = 'BUILDTIMEOUT_SET'

    #: Signal received.
    #:
    #: See Also:
    #:     :class:`EventSignal`
    SIGNAL = 'SIGNAL'

    #: Configuration changed.
    CONF_CHANGED = 'CONF_CHANGED'

    #: Circuit status changed slightly.
    CIRC_MINOR = 'CIRC_MINOR'

    #: Pluggable transport launched.
    #:
    #: See Also:
    #:     :class:`EventTransportLaunched`
    TRANSPORT_LAUNCHED = 'TRANSPORT_LAUNCHED'

    #: Bandwidth used on an OR or DIR or EXIT connection.
    CONN_BW = 'CONN_BW'

    #: Bandwidth used by all streams attached to a circuit.
    CIRC_BW = 'CIRC_BW'

    #: Per-circuit cell stats.
    CELL_STATS = 'CELL_STATS'

    #: Token buckets refilled.
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
    #: Client authentication is not implemented and is always :attr:`~.HsDescAuthType.NO_AUTH`.
    auth_type: HsDescAuthType
    #: The descriptor blinded key used for the index value at the "HsDir".
    descriptor_id: Base32Bytes | Base64Bytes | None = None
    #: Hidden service directory answering this request.
    hs_dir: str | Literal['UNKNOWN']  # noqa: PYI051
    #: Contains the computed index of the HsDir the descriptor was uploaded to or fetched from.
    hs_dir_index: HexBytes | None = None
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
    hs_dir: str | Literal['UNKNOWN']  # noqa: PYI051
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
    severity: Annotated[LogSeverity, LogSeverityTransformer()]
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
        LogSeverityTransformer(),
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
            kwargs_map={
                'ORADDRESS': 'or_address',
                'DIRADDRESS': 'dir_address',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'REACHABILITY_SUCCEEDED': ReplySyntax(
            kwargs_map={
                'ORADDRESS': 'or_address',
                'DIRADDRESS': 'dir_address',
            },
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
            kwargs_map={
                'ORADDRESS': 'or_address',
                'DIRADDRESS': 'dir_address',
            },
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
    host: IPv4Address | IPv6Address
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
    severity: Annotated[LogSeverity, LogSeverityTransformer()]


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
    'DISCONNECT': EventDisconnect,
    'HS_DESC': EventHsDesc,
    'HS_DESC_CONTENT': EventHsDescContent,
    'NETWORK_LIVENESS': EventNetworkLiveness,
    'DEBUG': EventLogDebug,
    'INFO': EventLogInfo,
    'NOTICE': EventLogNotice,
    'WARN': EventLogWarn,
    'ERR': EventLogErr,
    'SIGNAL': EventSignal,
    'STATUS_GENERAL': EventStatusGeneral,
    'STATUS_CLIENT': EventStatusClient,
    'STATUS_SERVER': EventStatusServer,
    'TRANSPORT_LAUNCHED': EventTransportLaunched,
    'PT_LOG': EventPtLog,
    'PT_STATUS': EventPtStatus,
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
