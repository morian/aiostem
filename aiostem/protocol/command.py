from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import MutableMapping, MutableSequence
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import ClassVar

from ..exceptions import CommandError
from .argument import Argument, ArgumentKeyword, ArgumentString, QuoteStyle  # noqa: F401
from .event import EventWord
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


class CommandWord(StrEnum):
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


class OnionServiceFlags(StrEnum):
    """Available flag options for command `ADD_ONION`."""

    #: The server should not include the newly generated private key as part of the response.
    DISCARD_PK = 'DiscardPK'
    #: Do not associate the newly created Onion Service to the current control connection.
    DETACH = 'Detach'
    #: Client authorization is required using the "basic" method (v2 only).
    BASIC_AUTH = 'BasicAuth'
    #: Version 3 client authorization is required (v3 only).
    V3AUTH = 'V3Auth'
    #: Add a non-anonymous Single Onion Service.
    NON_ANONYMOUS = 'NonAnonymous'
    #: Close the circuit is the maximum streams allowed is reached.
    MAX_STREAMS_CLOSE_CIRCUIT = 'MaxStreamsCloseCircuit'


class OnionAddKeyType(StrEnum):
    """All types of keys when creating an onion services."""

    #: The server should generate a key of algorithm KeyBlob.
    NEW = 'NEW'
    #: The server should use the 1024 bit RSA key provided in as KeyBlob (v2).
    RSA1024 = 'RSA1024'
    #: The server should use the ed25519 v3 key provided in as KeyBlob (v3).
    ED25519_V3 = 'ED25519-V3'


class OnionClientAuthFlags(StrEnum):
    """List of flags attached to a running onion service."""

    #: This client's credentials should be stored in the filesystem.
    PERMANENT = 'Permanent'


class OnionNewKeyType(StrEnum):
    """
    All kind of keys we can generate when creating an onion services.

    Note:
        These values are only applicable with `OnionAddKeyType.NEW`.

    """

    #: The server should generate a key using the "best" supported algorithm.
    BEST = 'BEST'
    #: The server should generate a 1024 bit RSA key.
    RSA1024 = 'RSA1024'
    #: The server should generate an ed25519 private key.
    ED25519_V3 = 'ED25519-V3'


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


class Command(ABC):
    """Base interface class for all commands."""

    command: ClassVar[CommandWord]

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
class CommandSetConf(Command):
    """
    Command implementation for `SETCONF`.

    Change the value of one or more configuration variables.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#setconf

    """

    command: ClassVar[CommandWord] = CommandWord.SETCONF
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
class CommandResetConf(Command):
    """
    Command implementation for `RESETCONF`.

    Remove all settings for a given configuration option entirely,
    assign its default value (if any), and then assign the value provided.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#resetconf

    """

    command: ClassVar[CommandWord] = CommandWord.RESETCONF
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
class CommandGetConf(Command):
    """
    Command implementation for `GETCONF`.

    Request the value of zero or more configuration variable(s).

    See Also:
        https://spec.torproject.org/control-spec/commands.html#getconf

    """

    command: ClassVar[CommandWord] = CommandWord.GETCONF
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
class CommandSetEvents(Command):
    """
    Command implementation for `SETEVENTS`.

    Request the server to inform the client about interesting events.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#setevents

    """

    command: ClassVar[CommandWord] = CommandWord.SETEVENTS
    events: set[EventWord] = field(default_factory=set)
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
class CommandAuthenticate(Command):
    """
    Command implementation for `AUTHENTICATE`.

    This command is used to authenticate to the server.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#authenticate

    """

    command: ClassVar[CommandWord] = CommandWord.AUTHENTICATE
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
class CommandSaveConf(Command):
    """
    Command implementation for `SAVECONF`.

    Instructs the server to write out its config options into its torrc.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#saveconf

    """

    command: ClassVar[CommandWord] = CommandWord.SAVECONF
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
class CommandSignal(Command):
    """
    Command implementation for `SIGNAL`.

    Send a signal to Tor.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#signal

    """

    command: ClassVar[CommandWord] = CommandWord.SIGNAL
    signal: Signal

    def _serialize(self) -> CommandSerializer:
        """Append `SIGNAL` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        args.append(ArgumentString(self.signal, quotes=QuoteStyle.NEVER))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandMapAddress(Command):
    """
    Command implementation for `MAPADDRESS`.

    The client sends this message to the server in order to tell it that future
    SOCKS requests for connections to the original address should be replaced
    with connections to the specified replacement address.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#mapaddress

    """

    command: ClassVar[CommandWord] = CommandWord.MAPADDRESS
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
class CommandGetInfo(Command):
    """
    Command implementation for `GETINFO`.

    Unlike `GETCONF`, this message is used for data that are not stored in the Tor
    configuration file, and that may be longer than a single line.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#getinfo

    """

    command: ClassVar[CommandWord] = CommandWord.GETINFO
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
class CommandExtendCircuit(Command):
    """
    Command implementation for `EXTENDCIRCUIT`.

    This request takes one of two forms: either `cicuit` is zero, in which case it is
    a request for the server to build a new circuit, or `circuit` is nonzero, in which
    case it is a request for the server to extend an existing circuit with that ID
    according to the specified path.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#extendcircuit

    """

    command: ClassVar[CommandWord] = CommandWord.EXTENDCIRCUIT
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
class CommandSetCircuitPurpose(Command):
    """
    Command implementation for `SETCIRCUITPURPOSE`.

    This changes the descriptor's purpose.

    Hints:
        See :class:`CommandPostDescriptor` for more details on `purpose`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#setcircuitpurpose

    """

    command: ClassVar[CommandWord] = CommandWord.SETCIRCUITPURPOSE
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
class CommandAttachStream(Command):
    """
    Command implementation for `ATTACHSTREAM`.

    This message informs the server that the specified stream should be associated
    with the specified circuit.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#attachstream

    """

    command: ClassVar[CommandWord] = CommandWord.ATTACHSTREAM
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
class CommandPostDescriptor(Command):
    """
    Command implementation for `POSTDESCRIPTOR`.

    This message informs the server about a new descriptor.
    If `purpose` is specified, it must be either `GENERAL`, `CONTROLLER`, or `BRIDGE`,
    else we return a 552 error.
    The default is `GENERAL`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#postdescriptor

    """

    command: ClassVar[CommandWord] = CommandWord.POSTDESCRIPTOR
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
class CommandRedirectStream(Command):
    """
    Command implementation for `REDIRECTSTREAM`.

    Tells the server to change the exit address on the specified stream.
    If Port is specified, changes the destination port as well.
    No remapping is performed on the new provided address.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#redirectstream

    """

    command: ClassVar[CommandWord] = CommandWord.REDIRECTSTREAM
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
class CommandCloseStream(Command):
    """
    Command implementation for `CLOSESTREAM`.

    Tells the server to close the specified stream.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#closestream

    """

    command: ClassVar[CommandWord] = CommandWord.CLOSESTREAM
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
class CommandCloseCircuit(Command):
    """
    Command implementation for `CLOSECIRCUIT`.

    Tells the server to close the specified circuit.
    If `if_unused` is provided, do not close the circuit unless it is unused.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#closecircuit

    """

    command: ClassVar[CommandWord] = CommandWord.CLOSECIRCUIT
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
class CommandQuit(Command):
    """
    Command implementation for `QUIT`.

    Tells the server to hang up on this controller connection.

    Note:
        This command can be used before authenticating.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#quit

    """

    command: ClassVar[CommandWord] = CommandWord.QUIT

    def _serialize(self) -> CommandSerializer:
        """
        Serialize a `QUIT` command.

        This command has no additional arguments.
        """
        return super()._serialize()


@dataclass(kw_only=True)
class CommandUseFeature(Command):
    """
    Command implementation for `USEFEATURE`.

    Adding additional features to the control protocol sometimes will break backwards
    compatibility. Initially such features are added into Tor and disabled by default.
    `USEFEATURE` can enable these additional features.

    Note:
        To get a list of available features please use `GETINFO features/names`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#usefeature

    """

    command: ClassVar[CommandWord] = CommandWord.USEFEATURE
    features: set[Feature | str] = field(default_factory=set)

    def _serialize(self) -> CommandSerializer:
        """Append `USEFEATURE` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        for feature in self.features:
            args.append(ArgumentString(feature, quotes=QuoteStyle.NEVER_ENSURE))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandResolve(Command):
    """
    Command implementation for `RESOLVE`.

    This command launches a remote hostname lookup request for every specified
    request (or reverse lookup if `reverse` is specified). Note that the request
    is done in the background: to see the answers, your controller will need to
    listen for `ADDRMAP` events.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#resolve

    """

    command: ClassVar[CommandWord] = CommandWord.RESOLVE
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
class CommandProtocolInfo(Command):
    """
    Command implementation for `PROTOCOLINFO`.

    This command tells the controller what kinds of authentication are supported.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#protocolinfo

    """

    command: ClassVar[CommandWord] = CommandWord.PROTOCOLINFO
    version: int | None = None

    def _serialize(self) -> CommandSerializer:
        """Append `PROTOCOLINFO` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        if self.version is not None:
            args.append(ArgumentString(self.version, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandLoadConf(Command):
    """
    Command implementation for `LOADCONF`.

    This command allows a controller to upload the text of a config file to Tor over
    the control port. This config file is then loaded as if it had been read from disk.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#loadconf

    """

    command: ClassVar[CommandWord] = CommandWord.LOADCONF
    text: str

    def _serialize(self) -> CommandSerializer:
        """Append `LOADCONF` specific arguments."""
        ser = super()._serialize()
        ser.body = self.text
        return ser


@dataclass(kw_only=True)
class CommandTakeOwnership(Command):
    """
    Command implementation for `TAKEOWNERSHIP`.

    This command instructs Tor to shut down when this control connection is closed.
    This command affects each control connection that sends it independently;
    if multiple control connections send the `TAKEOWNERSHIP` command to a Tor instance,
    Tor will shut down when any of those connections closes.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#takeownership

    """

    command: ClassVar[CommandWord] = CommandWord.TAKEOWNERSHIP

    def _serialize(self) -> CommandSerializer:
        """Serialize a `TAKEOWNERSHIP` command."""
        return super()._serialize()


@dataclass(kw_only=True)
class CommandAuthChallenge(Command):
    """
    Command implementation for `AUTHCHALLENGE`.

    This command is used to begin the authentication routine for the `SAFECOOKIE`
    method of authentication.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#authchallenge

    """

    NONCE_LENGTH: ClassVar[int] = 32
    command: ClassVar[CommandWord] = CommandWord.AUTHCHALLENGE
    nonce: bytes | str

    def _serialize(self) -> CommandSerializer:
        """Append `AUTHCHALLENGE` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        args.append(ArgumentString('SAFECOOKIE', quotes=QuoteStyle.NEVER))
        match self.nonce:
            case bytes():
                args.append(ArgumentString(self.nonce.hex(), quotes=QuoteStyle.NEVER))
            case str():  # pragma: no branch
                args.append(ArgumentString(self.nonce, quotes=QuoteStyle.ALWAYS))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandDropGuards(Command):
    """
    Command implementation for `DROPGUARDS`.

    Tells the server to drop all guard nodes. Do not invoke this command lightly;
    it can increase vulnerability to tracking attacks over time.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#dropguards

    """

    command: ClassVar[CommandWord] = CommandWord.DROPGUARDS

    def _serialize(self) -> CommandSerializer:
        """Serialize a `DROPGUARDS` command."""
        return super()._serialize()


@dataclass(kw_only=True)
class CommandHsFetch(Command):
    """
    Command implementation for `HSFETCH`.

    This command launches hidden service descriptor fetch(es) for the given `address`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#hsfetch

    """

    command: ClassVar[CommandWord] = CommandWord.HSFETCH
    servers: MutableSequence[str] = field(default_factory=list)
    address: str

    def _serialize(self) -> CommandSerializer:
        """Append `HSFETCH` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        args.append(ArgumentString(self.address, quotes=QuoteStyle.NEVER_ENSURE))
        for server in self.servers:
            args.append(ArgumentKeyword('SERVER', server, quotes=QuoteStyle.NEVER_ENSURE))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandAddOnion(Command):
    """
    Command implementation for `ADD_ONION`.

    Tells the server to create a new Onion ("Hidden") Service, with the specified
    private key and algorithm.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#add_onion

    """

    command: ClassVar[CommandWord] = CommandWord.ADD_ONION
    key_type: OnionAddKeyType
    key: OnionNewKeyType | str
    flags: set[OnionServiceFlags] = field(default_factory=set)
    max_streams: int | None = None
    #: As in arguments to HiddenServicePort ("port,target")
    ports: MutableSequence[str] = field(default_factory=list)
    #: Syntax: `ClientName:ClientBlob`
    client_auth: MutableSequence[str] = field(default_factory=list)
    #: Syntax: base32-encoded x25519 public key with only the key part.
    client_auth_v3: MutableSequence[str] = field(default_factory=list)

    def _serialize(self) -> CommandSerializer:
        """Append `ADD_ONION` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        do_generate = bool(self.key_type == OnionAddKeyType.NEW)
        has_keyblob = bool(not isinstance(self.key, OnionNewKeyType))
        if do_generate == has_keyblob:
            msg = "Incompatible options for 'key_type' and 'key'."
            raise CommandError(msg)

        if not len(self.ports):
            msg = 'You must specify one or more virtual ports.'
            raise CommandError(msg)

        key = f'{self.key_type.value}:{self.key}'
        args.append(ArgumentString(key, quotes=QuoteStyle.NEVER_ENSURE))
        if len(self.flags):
            flags = ','.join(self.flags)
            args.append(ArgumentKeyword('Flags', flags, quotes=QuoteStyle.NEVER))
        if self.max_streams is not None:
            kwarg = ArgumentKeyword('MaxStreams', self.max_streams, quotes=QuoteStyle.NEVER)
            args.append(kwarg)
        for port in self.ports:
            args.append(ArgumentKeyword('Port', port, quotes=QuoteStyle.NEVER_ENSURE))
        for auth in self.client_auth:
            args.append(ArgumentKeyword('ClientAuth', auth, quotes=QuoteStyle.NEVER_ENSURE))
        for auth in self.client_auth_v3:
            args.append(ArgumentKeyword('ClientAuthV3', auth, quotes=QuoteStyle.NEVER_ENSURE))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandDelOnion(Command):
    """
    Command implementation for `DEL_ONION`.

    Tells the server to remove an Onion ("Hidden") Service, that was previously created
    via an `ADD_ONION` command. It is only possible to remove Onion Services that were
    created on the same control connection as the `DEL_ONION` command, and those that belong
    to no control connection in particular (The `DETACH` flag was specified at creation).

    See Also:
        https://spec.torproject.org/control-spec/commands.html#del_onion

    """

    command: ClassVar[CommandWord] = CommandWord.DEL_ONION
    #: This is the v2 or v3 address without the `.onion` suffix.
    address: str

    def _serialize(self) -> CommandSerializer:
        """Append `DEL_ONION` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        args.append(ArgumentString(self.address, quotes=QuoteStyle.NEVER_ENSURE))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandHsPost(Command):
    """
    Command implementation for `HSPOST`.

    This command launches a hidden service descriptor upload to the specified HSDirs.
    If one or more Server arguments are provided, an upload is triggered on each of
    them in parallel. If no Server options are provided, it behaves like a normal HS
    descriptor upload and will upload to the set of responsible HS directories.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#hspost

    """

    command: ClassVar[CommandWord] = CommandWord.HSPOST
    servers: MutableSequence[str] = field(default_factory=list)
    address: str | None = None
    descriptor: str

    def _serialize(self) -> CommandSerializer:
        """Append `HSPOST` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        for server in self.servers:
            args.append(ArgumentKeyword('SERVER', server, quotes=QuoteStyle.NEVER_ENSURE))
        if self.address is not None:
            kwarg = ArgumentKeyword('HSADDRESS', self.address, quotes=QuoteStyle.NEVER_ENSURE)
            args.append(kwarg)
        ser.arguments.extend(args)
        ser.body = self.descriptor
        return ser


@dataclass(kw_only=True)
class CommandOnionClientAuthAdd(Command):
    """
    Command implementation for `ONION_CLIENT_AUTH_ADD`.

    Tells the connected Tor to add client-side v3 client auth credentials for the onion
    service with `address`. The `key` is the x25519 private key that should be used for
    this client, and `nickname` is an optional nickname for the client.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#onion_client_auth_add

    """

    command: ClassVar[CommandWord] = CommandWord.ONION_CLIENT_AUTH_ADD
    #: V3 onion address without the `.onion` suffix.
    address: str
    #: Base64 encoding of x25519 key.
    key: str
    #: An optional nickname for the client.
    nickname: str | None = None
    #: This client's credentials should be stored in the filesystem.
    flags: set[OnionClientAuthFlags] = field(default_factory=set)

    def _serialize(self) -> CommandSerializer:
        """Append `ONION_CLIENT_AUTH_ADD` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]

        args.append(ArgumentString(self.address, quotes=QuoteStyle.NEVER_ENSURE))
        args.append(ArgumentString(f'x25519:{self.key}', quotes=QuoteStyle.NEVER_ENSURE))

        if self.nickname is not None:
            kwarg = ArgumentKeyword(
                'ClientName', self.nickname, quotes=QuoteStyle.NEVER_ENSURE
            )
            args.append(kwarg)

        if len(self.flags):
            flags = ','.join(self.flags)
            args.append(ArgumentKeyword('Flags', flags, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandOnionClientAuthRemove(Command):
    """
    Command implementation for `ONION_CLIENT_AUTH_REMOVE`.

    Tells the connected Tor to remove the client-side v3 client auth credentials
    for the onion service with `address`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#onion_client_auth_remove

    """

    command: ClassVar[CommandWord] = CommandWord.ONION_CLIENT_AUTH_REMOVE
    #: V3 onion address without the `.onion` suffix.
    address: str

    def _serialize(self) -> CommandSerializer:
        """Append `ONION_CLIENT_AUTH_REMOVE` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        args.append(ArgumentString(self.address, quotes=QuoteStyle.NEVER_ENSURE))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandOnionClientAuthView(Command):
    """
    Command implementation for `ONION_CLIENT_AUTH_VIEW`.

    Tells the connected Tor to list all the stored client-side v3 client auth credentials
    for `address`. If no `address` is provided, list all the stored client-side v3 client
    auth credentials.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#onion_client_auth_view

    """

    command: ClassVar[CommandWord] = CommandWord.ONION_CLIENT_AUTH_VIEW
    #: V3 onion address without the `.onion` suffix.
    address: str | None = None

    def _serialize(self) -> CommandSerializer:
        """Append `ONION_CLIENT_AUTH_VIEW` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[Argument]
        if self.address is not None:
            args.append(ArgumentString(self.address, quotes=QuoteStyle.NEVER_ENSURE))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandDropOwnership(Command):
    """
    Command implementation for `DROPOWNERSHIP`.

    This command instructs Tor to relinquish ownership of its control connection.
    As such tor will not shut down when this control connection is closed.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#dropownership

    """

    command: ClassVar[CommandWord] = CommandWord.DROPOWNERSHIP

    def _serialize(self) -> CommandSerializer:
        """Serialize a `DROPOWNERSHIP` command."""
        return super()._serialize()


@dataclass(kw_only=True)
class CommandDropTimeouts(Command):
    """
    Command implementation for `DROPTIMEOUTS`.

    Tells the server to drop all circuit build times. Do not invoke this command lightly;
    it can increase vulnerability to tracking attacks over time.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#droptimeouts

    """

    command: ClassVar[CommandWord] = CommandWord.DROPTIMEOUTS

    def _serialize(self) -> CommandSerializer:
        """Serialize a `DROPTIMEOUTS` command."""
        return super()._serialize()
