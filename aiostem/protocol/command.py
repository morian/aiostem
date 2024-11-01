from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import MutableMapping, MutableSequence, MutableSet
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import ClassVar

from ..exceptions import CommandError
from .argument import Argument, ArgumentKeyword, ArgumentString, QuoteStyle  # noqa: F401
from .event import Event
from .utils import CommandSerializer


class CloseStreamReason(IntEnum):
    """
    All reasons provided to close a stream.

    See Also:
        https://spec.torproject.org/tor-spec/closing-streams.html#closing-streams

    """

    #: Catch-all for unlisted reasons.
    MISC = 1
    #: Couldn't look up hostname.
    RESOLVEFAILED = 2
    #: Remote host refused connection.
    CONNECTREFUSED = 3
    #: Relay refuses to connect to host or port.
    EXITPOLICY = 4
    #: Circuit is being destroyed.
    DESTROY = 5
    #: Anonymized TCP connection was closed.
    DONE = 6
    #: Anonymized TCP connection was closed while connecting.
    TIMEOUT = 7
    #: Routing error while attempting to contact destination.
    NOROUTE = 8
    #: Relay is temporarily hibernating.
    HIBERNATING = 9
    #: Internal error at the relay.
    INTERNAL = 10
    #: Relay has no resources to fulfill request.
    RESOURCELIMIT = 11
    #: Connection was unexpectedly reset.
    CONNRESET = 12
    #: Sent when closing connection because of Tor protocol violations.
    TORPROTOCOL = 13
    #: Client sent `RELAY_BEGIN_DIR` to a non-directory relay.
    NOTDIRECTORY = 14


class Command(StrEnum):
    """All handled command words."""

    SETCONF = 'SETCONF'
    RESETCONF = 'RESETCONF'
    GETCONF = 'GETCONF'
    SETEVENTS = 'SETEVENTS'
    AUTHENTICATE = 'AUTHENTICATE'
    SAVECONF = 'SAVECONF'
    SIGNAL = 'SIGNAL'
    MAPADDRESS = 'MAPADDRESS'
    GETINFO = 'GETINFO'
    EXTENDCIRCUIT = 'EXTENDCIRCUIT'
    SETCIRCUITPURPOSE = 'SETCIRCUITPURPOSE'
    SETROUTERPURPOSE = 'SETROUTERPURPOSE'  # obsolete as of Tor v0.2.0.8
    ATTACHSTREAM = 'ATTACHSTREAM'
    POSTDESCRIPTOR = 'POSTDESCRIPTOR'
    REDIRECTSTREAM = 'REDIRECTSTREAM'
    CLOSESTREAM = 'CLOSESTREAM'
    CLOSECIRCUIT = 'CLOSECIRCUIT'
    QUIT = 'QUIT'
    USEFEATURE = 'USEFEATURE'
    RESOLVE = 'RESOLVE'
    PROTOCOLINFO = 'PROTOCOLINFO'
    LOADCONF = 'LOADCONF'
    TAKEOWNERSHIP = 'TAKEOWNERSHIP'
    AUTHCHALLENGE = 'AUTHCHALLENGE'
    DROPGUARDS = 'DROPGUARDS'
    HSFETCH = 'HSFETCH'
    ADD_ONION = 'ADD_ONION'
    DEL_ONION = 'DEL_ONION'
    HSPOST = 'HSPOST'
    ONION_CLIENT_AUTH_ADD = 'ONION_CLIENT_AUTH_ADD'
    ONION_CLIENT_AUTH_REMOVE = 'ONION_CLIENT_AUTH_REMOVE'
    ONION_CLIENT_AUTH_VIEW = 'ONION_CLIENT_AUTH_VIEW'
    DROPOWNERSHIP = 'DROPOWNERSHIP'
    DROPTIMEOUTS = 'DROPTIMEOUTS'


class Feature(StrEnum):
    """All known features."""

    #: Same as passing 'EXTENDED' to SETEVENTS.
    EXTENDED_EVENTS = 'EXTENDED_EVENTS'
    #: Replaces ServerID with LongName in events and GETINFO results.
    VERBOSE_NAMES = 'VERBOSE_NAMES'


class Signal(StrEnum):
    """All possible signals."""

    #: Reload: reload config items.
    RELOAD = 'RELOAD'
    #: Controlled shutdown: if server is an OP, exit immediately.
    SHUTDOWN = 'SHUTDOWN'
    #: Dump stats: log information about open connections and circuits.
    DUMP = 'DUMP'
    #: Debug: switch all open logs to loglevel debug.
    DEBUG = 'DEBUG'
    #: Immediate shutdown: clean up and exit now.
    HALT = 'HALT'
    #: Forget the client-side cached IPs for all hostnames.
    CLEARDNSCACHE = 'CLEARDNSCACHE'
    #: Switch to clean circuits, so new requests don't share any circuits with old ones.
    NEWNYM = 'NEWNYM'
    #: Make Tor dump an unscheduled Heartbeat message to log.
    HEARTBEAT = 'HEARTBEAT'
    #: Tell Tor to become "dormant".
    DORMANT = 'DORMANT'
    #: Tell Tor to stop being "dormant".
    ACTIVE = 'ACTIVE'


class CircuitPurpose(StrEnum):
    """All possible purposes for circuits."""

    CONTROLLER = 'controller'
    GENERAL = 'general'
    BRIDGE = 'bridge'


class BaseCommand(ABC):
    """Base interface class for all commands."""

    command: ClassVar[Command]

    @abstractmethod
    def _serialize(self) -> CommandSerializer:
        """
        Create a new serializer for this command.

        Returns:
            A basic command serializer for this command.

        """
        return CommandSerializer(self.command)

    def serialize(self) -> str:
        """
        Serialize the command to text.

        Returns:
            Text that can be sent through the wire.

        """
        ser = self._serialize()
        return ser.serialize()


@dataclass(kw_only=True)
class CommandSetConf(BaseCommand):
    """
    Command implementation for `SETCONF`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#setconf

    """

    command: ClassVar[Command] = Command.SETCONF
    values: MutableMapping[str, int | str | None] = field(default_factory=dict)

    def _serialize(self) -> CommandSerializer:
        """Append 'SETCONF' specific arguments."""
        if len(self.values) == 0:
            msg = "No value provided for command 'SETCONF'"
            raise CommandError(msg)

        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        for key, value in self.values.items():
            args.append(ArgumentKeyword(key, value))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandResetConf(BaseCommand):
    """
    Command implementation for `RESETCONF`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#resetconf

    """

    command: ClassVar[Command] = Command.RESETCONF
    values: MutableMapping[str, int | str | None] = field(default_factory=dict)

    def _serialize(self) -> CommandSerializer:
        """Append `RESETCONF` specific arguments."""
        if len(self.values) == 0:
            msg = "No value provided for command 'RESETCONF'"
            raise CommandError(msg)

        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        for key, value in self.values.items():
            args.append(ArgumentKeyword(key, value))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandGetConf(BaseCommand):
    """
    Command implementation for `GETCONF`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#getconf

    """

    command: ClassVar[Command] = Command.GETCONF
    keywords: MutableSequence[str] = field(default_factory=list)

    def _serialize(self) -> CommandSerializer:
        """Append `GETCONF` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        for keyword in self.keywords:
            args.append(ArgumentString(keyword))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandSetEvents(BaseCommand):
    """
    Command implementation for `SETEVENTS`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#setevents

    """

    command: ClassVar[Command] = Command.SETEVENTS
    events: MutableSet[Event] = field(default_factory=set)
    extended: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append `SETEVENTS` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        if self.extended:
            args.append(ArgumentString('EXTENDED', quotes=QuoteStyle.NEVER))
        for evt in self.events:
            args.append(ArgumentString(evt, quotes=QuoteStyle.NEVER))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandAuthenticate(BaseCommand):
    """
    Command implementation for `AUTHENTICATE`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#authenticate

    """

    command: ClassVar[Command] = Command.AUTHENTICATE
    token: bytes | str | None

    def _serialize(self) -> CommandSerializer:
        """Append `AUTHENTICATE` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        match self.token:
            case bytes():
                args.append(ArgumentString(self.token.hex(), quotes=QuoteStyle.NEVER))
            case str():
                args.append(ArgumentString(self.token, quotes=QuoteStyle.ALWAYS))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandSaveConf(BaseCommand):
    """
    Command implementation for `SAVECONF`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#saveconf

    """

    command: ClassVar[Command] = Command.SAVECONF
    force: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append `SAVECONF` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        if self.force:
            args.append(ArgumentString('FORCE', quotes=QuoteStyle.NEVER))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandSignal(BaseCommand):
    """
    Command implementation for `SIGNAL`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#signal

    """

    command: ClassVar[Command] = Command.SIGNAL
    signal: Signal

    def _serialize(self) -> CommandSerializer:
        """Append `SIGNAL` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        args.append(ArgumentString(self.signal, quotes=QuoteStyle.NEVER))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandMapAddress(BaseCommand):
    """
    Command implementation for `MAPADDRESS`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#mapaddress

    """

    command: ClassVar[Command] = Command.MAPADDRESS
    addresses: MutableMapping[str, str] = field(default_factory=dict)

    def _serialize(self) -> CommandSerializer:
        """Append `MAPADDRESS` specific arguments."""
        if len(self.addresses) == 0:
            msg = "No address provided for command 'MAPADDRESS'"
            raise CommandError(msg)

        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        for key, value in self.addresses.items():
            args.append(ArgumentKeyword(key, value, quotes=QuoteStyle.NEVER_ENSURE))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandGetInfo(BaseCommand):
    """
    Command implementation for `GETINFO`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#getinfo

    """

    command: ClassVar[Command] = Command.GETINFO
    keywords: MutableSequence[str] = field(default_factory=list)

    def _serialize(self) -> CommandSerializer:
        """Append `GETINFO` specific arguments."""
        if len(self.keywords) == 0:
            msg = "No keyword provided for command 'GETINFO'"
            raise CommandError(msg)

        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        for keyword in self.keywords:
            args.append(ArgumentString(keyword))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandExtendCircuit(BaseCommand):
    """
    Command implementation for `EXTENDCIRCUIT`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#extendcircuit

    """

    command: ClassVar[Command] = Command.EXTENDCIRCUIT
    circuit: int
    server_spec: MutableSequence[str] = field(default_factory=list)
    purpose: CircuitPurpose | None = None

    def _serialize(self) -> CommandSerializer:
        """Append `EXTENDCIRCUIT` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        args.append(ArgumentString(self.circuit))
        if len(self.server_spec):
            text = ','.join(self.server_spec)
            args.append(ArgumentString(text, quotes=QuoteStyle.NEVER_ENSURE))
        if self.purpose is not None:
            args.append(ArgumentKeyword('purpose', self.purpose, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandSetCircuitPurpose(BaseCommand):
    """
    Command implementation for `SETCIRCUITPURPOSE`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#setcircuitpurpose

    """

    command: ClassVar[Command] = Command.SETCIRCUITPURPOSE
    circuit: int
    purpose: CircuitPurpose

    def _serialize(self) -> CommandSerializer:
        """Append `SETCIRCUITPURPOSE` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        args.append(ArgumentString(self.circuit, quotes=QuoteStyle.NEVER))
        args.append(ArgumentKeyword('purpose', self.purpose, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandAttachStream(BaseCommand):
    """
    Command implementation for `ATTACHSTREAM`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#attachstream

    """

    command: ClassVar[Command] = Command.ATTACHSTREAM
    stream: int
    circuit: int
    hop: int | None = None

    def _serialize(self) -> CommandSerializer:
        """Append `ATTACHSTREAM` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        args.append(ArgumentString(self.stream, quotes=QuoteStyle.NEVER))
        args.append(ArgumentString(self.circuit, quotes=QuoteStyle.NEVER))
        if self.hop is not None:
            args.append(ArgumentKeyword('HOP', self.hop, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandPostDescriptor(BaseCommand):
    """
    Command implementation for `POSTDESCRIPTOR`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#postdescriptor

    """

    command: ClassVar[Command] = Command.POSTDESCRIPTOR
    purpose: CircuitPurpose | None = None
    cache: bool | None = None
    descriptor: str

    def _serialize(self) -> CommandSerializer:
        """Append 'POSTDESCRIPTOR' specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        if self.purpose is not None:
            args.append(ArgumentKeyword('purpose', self.purpose, quotes=QuoteStyle.NEVER))
        if self.cache is not None:
            text = 'yes' if self.cache else 'no'
            args.append(ArgumentKeyword('cache', text, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        ser.body = self.descriptor
        return ser


@dataclass(kw_only=True)
class CommandRedirectStream(BaseCommand):
    """
    Command implementation for `REDIRECTSTREAM`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#redirectstream

    """

    command: ClassVar[Command] = Command.REDIRECTSTREAM
    stream: int
    address: str
    port: int | None = None

    def _serialize(self) -> CommandSerializer:
        """Append `REDIRECTSTREAM` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        args.append(ArgumentString(self.stream, quotes=QuoteStyle.NEVER))
        args.append(ArgumentString(self.address, quotes=QuoteStyle.NEVER_ENSURE))
        if self.port is not None:
            args.append(ArgumentString(self.port))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandCloseStream(BaseCommand):
    """
    Command implementation for `CLOSESTREAM`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#closestream

    """

    command: ClassVar[Command] = Command.CLOSESTREAM
    stream: int
    reason: CloseStreamReason

    def _serialize(self) -> CommandSerializer:
        """Append `CLOSESTREAM` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        args.append(ArgumentString(self.stream, quotes=QuoteStyle.NEVER))
        args.append(ArgumentString(self.reason, quotes=QuoteStyle.NEVER))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandCloseCircuit(BaseCommand):
    """
    Command implementation for `CLOSECIRCUIT`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#closecircuit

    """

    command: ClassVar[Command] = Command.CLOSECIRCUIT
    circuit: int

    #: Do not close the circuit unless it is unused.
    if_unused: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append `CLOSECIRCUIT` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        args.append(ArgumentString(self.circuit, quotes=QuoteStyle.NEVER))
        if self.if_unused:
            args.append(ArgumentString('IfUnused', quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandQuit(BaseCommand):
    """
    Command implementation for `QUIT`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#quit

    """

    command: ClassVar[Command] = Command.QUIT

    def _serialize(self) -> CommandSerializer:
        """
        Serialize a `QUIT` command.

        This command has no additional arguments.
        """
        return super()._serialize()


@dataclass(kw_only=True)
class CommandUseFeature(BaseCommand):
    """
    Command implementation for `USEFEATURE`.

    To get a list of available features please use `GETINFO features/names`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#usefeature

    """

    command: ClassVar[Command] = Command.USEFEATURE
    features: MutableSet[Feature | str] = field(default_factory=set)

    def _serialize(self) -> CommandSerializer:
        """Append `USEFEATURE` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        for feature in self.features:
            args.append(ArgumentString(feature, quotes=QuoteStyle.NEVER_ENSURE))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandResolve(BaseCommand):
    """
    Command implementation for `RESOLVE`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#resolve

    """

    command: ClassVar[Command] = Command.RESOLVE
    addresses: MutableSequence[str] = field(default_factory=list)
    reverse: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append `RESOLVE` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        if self.reverse:
            args.append(ArgumentKeyword('mode', 'reverse', quotes=QuoteStyle.NEVER))
        for address in self.addresses:
            args.append(ArgumentString(address, quotes=QuoteStyle.NEVER_ENSURE))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandProtocolInfo(BaseCommand):
    """
    Command implementation for `PROTOCOLINFO`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#protocolinfo

    """

    command: ClassVar[Command] = Command.PROTOCOLINFO
    version: int | None = None

    def _serialize(self) -> CommandSerializer:
        """Append `PROTOCOLINFO` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        if self.version is not None:
            args.append(ArgumentString(self.version, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser
