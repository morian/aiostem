from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from base64 import b32encode, standard_b64encode
from collections.abc import (
    MutableMapping,
    MutableSequence,
    Set as AbstractSet,
)
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar, Literal

from ..exceptions import CommandError
from .argument import ArgumentKeyword, ArgumentString, QuoteStyle
from .event import EventWord
from .structures import (
    CircuitPurpose,
    CloseStreamReason,
    Feature,
    OnionClientAuthFlags,
    OnionClientAuthKeyType,
    OnionServiceFlags,
    OnionServiceKeyType,
    Signal,
)
from .utils import (
    Base32Bytes,
    Base64Bytes,
    CommandSerializer,
    HiddenServiceAddress,
    HiddenServiceAddressV3,
)


class CommandWord(StrEnum):
    """All handled command words."""

    #: Change the value of one or more configuration variables.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.set_conf`
    #:     - Command implementation: :class:`CommandSetConf`
    #:     - Reply implementation: :class:`.ReplySetConf`
    SETCONF = 'SETCONF'

    #: Remove all settings for a given configuration option entirely.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.reset_conf`
    #:     - Command implementation: :class:`CommandResetConf`
    #:     - Reply implementation: :class:`.ReplyResetConf`
    RESETCONF = 'RESETCONF'

    #: Request the value of zero or more configuration variable(s).
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.get_conf`
    #:     - Command implementation: :class:`CommandGetConf`
    #:     - Reply implementation: :class:`.ReplyGetConf`
    GETCONF = 'GETCONF'

    #: Request the server to inform the client about interesting events.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.set_events`
    #:     - Command implementation: :class:`CommandSetEvents`
    #:     - Reply implementation: :class:`.ReplySetEvents`
    SETEVENTS = 'SETEVENTS'

    #: Used to authenticate to the server.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.authenticate`
    #:     - Command implementation: :class:`CommandAuthenticate`
    #:     - Reply implementation: :class:`.ReplyAuthenticate`
    AUTHENTICATE = 'AUTHENTICATE'

    #: Instructs the server to write out its config options into its ``torrc``.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.save_conf`
    #:     - Command implementation: :class:`CommandSaveConf`
    #:     - Reply implementation: :class:`.ReplySaveConf`
    SAVECONF = 'SAVECONF'

    #: Send a signal to the server.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.signal`
    #:     - Command implementation: :class:`CommandSignal`
    #:     - Reply implementation: :class:`.ReplySignal`
    SIGNAL = 'SIGNAL'

    #: Tell the server to replace addresses on future SOCKS requests.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.map_address`
    #:     - Command implementation: :class:`CommandMapAddress`
    #:     - Reply implementation: :class:`.ReplyMapAddress`
    MAPADDRESS = 'MAPADDRESS'

    #: Get server information.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.get_info`
    #:     - Command implementation: :class:`CommandGetInfo`
    #:     - Reply implementation: :class:`.ReplyGetInfo`
    GETINFO = 'GETINFO'

    #: Build a new or extend an existing circuit.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandExtendCircuit`
    #:     - Reply implementation: :class:`.ReplyExtendCircuit`
    EXTENDCIRCUIT = 'EXTENDCIRCUIT'

    #: Change the purpose of a circuit.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandSetCircuitPurpose`
    #:     - Reply implementation: :class:`.ReplySetCircuitPurpose`
    SETCIRCUITPURPOSE = 'SETCIRCUITPURPOSE'

    #: Not implemented because it was marked as obsolete as of ``Tor v0.2.0.8``.
    SETROUTERPURPOSE = 'SETROUTERPURPOSE'

    #: Request that the specified stream should be associated with the specified circuit.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandAttachStream`
    #:     - Reply implementation: :class:`.ReplyAttachStream`
    ATTACHSTREAM = 'ATTACHSTREAM'

    #: This message informs the server about a new descriptor.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandPostDescriptor`
    #:     - Reply implementation: :class:`.ReplyPostDescriptor`
    POSTDESCRIPTOR = 'POSTDESCRIPTOR'

    #: Tells the server to change the exit address on the specified stream.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandRedirectStream`
    #:     - Reply implementation: :class:`.ReplyRedirectStream`
    REDIRECTSTREAM = 'REDIRECTSTREAM'

    #: Tells the server to close the specified stream.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandCloseStream`
    #:     - Reply implementation: :class:`.ReplyCloseStream`
    CLOSESTREAM = 'CLOSESTREAM'

    #: Tells the server to close the specified circuit.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandCloseCircuit`
    #:     - Reply implementation: :class:`.ReplyCloseCircuit`
    CLOSECIRCUIT = 'CLOSECIRCUIT'

    #: Tells the server to hang up on this controller connection.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.quit`
    #:     - Command implementation: :class:`CommandQuit`
    #:     - Reply implementation: :class:`.ReplyQuit`
    QUIT = 'QUIT'

    #: Enable additional features.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandUseFeature`
    #:     - Reply implementation: :class:`.ReplyUseFeature`
    USEFEATURE = 'USEFEATURE'

    #: This command launches a remote hostname lookup request for every specified request.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandResolve`
    #:     - Reply implementation: :class:`.ReplyResolve`
    RESOLVE = 'RESOLVE'

    #: This command tells the controller what kinds of authentication are supported.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.protocol_info`
    #:     - Command implementation: :class:`CommandProtocolInfo`
    #:     - Reply implementation: :class:`.ReplyProtocolInfo`
    PROTOCOLINFO = 'PROTOCOLINFO'

    #: This command allows to upload the text of a config file to Tor over the control port.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.load_conf`
    #:     - Command implementation: :class:`CommandLoadConf`
    #:     - Reply implementation: :class:`.ReplyLoadConf`
    LOADCONF = 'LOADCONF'

    #: Instructs Tor to shut down when this control connection is closed.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandTakeOwnership`
    #:     - Reply implementation: :class:`.ReplyTakeOwnership`
    TAKEOWNERSHIP = 'TAKEOWNERSHIP'

    #: Begin the authentication routine for the SAFECOOKIE method.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.auth_challenge`
    #:     - Command implementation: :class:`CommandAuthChallenge`
    #:     - Reply implementation: :class:`.ReplyAuthChallenge`
    AUTHCHALLENGE = 'AUTHCHALLENGE'

    #: Tells the server to drop all guard nodes.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.drop_guards`
    #:     - Command implementation: :class:`CommandDropGuards`
    #:     - Reply implementation: :class:`.ReplyDropGuards`
    DROPGUARDS = 'DROPGUARDS'

    #: Launches hidden service descriptor fetch(es).
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.hs_fetch`
    #:     - Command implementation: :class:`CommandHsFetch`
    #:     - Reply implementation: :class:`.ReplyHsFetch`
    HSFETCH = 'HSFETCH'

    #: Tells the server to create a new onion "hidden" service.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandAddOnion`
    #:     - Reply implementation: :class:`.ReplyAddOnion`
    ADD_ONION = 'ADD_ONION'

    #: Tells the server to remove an onion "hidden" service.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandDelOnion`
    #:     - Reply implementation: :class:`.ReplyDelOnion`
    DEL_ONION = 'DEL_ONION'

    #: This command launches a hidden service descriptor upload to the specified HSDirs.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandHsPost`
    #:     - Reply implementation: :class:`.ReplyHsPost`
    HSPOST = 'HSPOST'

    #: Add client-side v3 client auth credentials for a onion service.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandOnionClientAuthAdd`
    #:     - Reply implementation: :class:`.ReplyOnionClientAuthAdd`
    ONION_CLIENT_AUTH_ADD = 'ONION_CLIENT_AUTH_ADD'

    #: Remove client-side v3 client auth credentials for a onion service.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandOnionClientAuthRemove`
    #:     - Reply implementation: :class:`.ReplyOnionClientAuthRemove`
    ONION_CLIENT_AUTH_REMOVE = 'ONION_CLIENT_AUTH_REMOVE'

    #: List client-side v3 client auth credentials for a onion service.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandOnionClientAuthView`
    #:     - Reply implementation: :class:`.ReplyOnionClientAuthView`
    ONION_CLIENT_AUTH_VIEW = 'ONION_CLIENT_AUTH_VIEW'

    #: This command instructs Tor to relinquish ownership of its control connection.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandDropOwnership`
    #:     - Reply implementation: :class:`.ReplyDropOwnership`
    DROPOWNERSHIP = 'DROPOWNERSHIP'

    #: Tells the server to drop all circuit build times.
    #:
    #: See Also:
    #:     - Command implementation: :class:`CommandDropTimeouts`
    #:     - Reply implementation: :class:`.ReplyDropTimeouts`
    DROPTIMEOUTS = 'DROPTIMEOUTS'


class Command(ABC):
    """Base class for all commands."""

    #: Command word this command is for.
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
            Text that can be sent to Tor's control port.

        """
        ser = self._serialize()
        return ser.serialize()


@dataclass(kw_only=True)
class CommandSetConf(Command):
    """
    Command implementation for :attr:`~CommandWord.SETCONF`.

    Change the value of one or more configuration variables.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#setconf

    """

    command: ClassVar[CommandWord] = CommandWord.SETCONF

    #: All the configuration values you want to set.
    values: MutableMapping[str, MutableSequence[int | str] | int | str | None] = field(
        default_factory=dict,
    )

    def _serialize(self) -> CommandSerializer:
        """Append ``SETCONF`` specific arguments."""
        if len(self.values) == 0:
            msg = f"No value provided for command '{self.command.value}'"
            raise CommandError(msg)

        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        for key, value in self.values.items():
            if isinstance(value, MutableSequence):
                for item in value:
                    args.append(ArgumentKeyword(key, item))
            else:
                args.append(ArgumentKeyword(key, value))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandResetConf(CommandSetConf):
    """
    Command implementation for :attr:`~CommandWord.RESETCONF`.

    Remove all settings for a given configuration option entirely,
    assign its default value (if any), and then assign the value provided.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#resetconf

    """

    command: ClassVar[CommandWord] = CommandWord.RESETCONF


@dataclass(kw_only=True)
class CommandGetConf(Command):
    """
    Command implementation for :attr:`~CommandWord.GETCONF`.

    Request the value of zero or more configuration variable(s).

    See Also:
        https://spec.torproject.org/control-spec/commands.html#getconf

    """

    command: ClassVar[CommandWord] = CommandWord.GETCONF

    #: List of configuration keys to request (duplicates mean duplicate answers).
    keywords: MutableSequence[str] = field(default_factory=list)

    def _serialize(self) -> CommandSerializer:
        """Append ``GETCONF`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        for keyword in self.keywords:
            args.append(ArgumentString(keyword))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandSetEvents(Command):
    """
    Command implementation for :attr:`~CommandWord.SETEVENTS`.

    Request the server to inform the client about interesting events.

    See Also:
        - https://spec.torproject.org/control-spec/commands.html#setevents
        - :meth:`.Controller.add_event_handler`

    """

    command: ClassVar[CommandWord] = CommandWord.SETEVENTS

    #: Set of event names to receive the corresponding events.
    events: set[EventWord] = field(default_factory=set)

    def _serialize(self) -> CommandSerializer:
        """Append ``SETEVENTS`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        for evt in self.events:
            args.append(ArgumentString(evt, safe=True))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandAuthenticate(Command):
    """
    Command implementation for :attr:`~CommandWord.AUTHENTICATE`.

    This command is used to authenticate to the server.

    See Also:
        - https://spec.torproject.org/control-spec/commands.html#authenticate
        - :meth:`.Controller.authenticate` and :attr:`.Controller.authenticated`.

    """

    command: ClassVar[CommandWord] = CommandWord.AUTHENTICATE

    #: Password or token used to authenticate with the server.
    token: bytes | str | None

    def _serialize(self) -> CommandSerializer:
        """Append ``AUTHENTICATE`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        match self.token:
            case bytes():
                args.append(ArgumentKeyword(None, self.token.hex(), quotes=QuoteStyle.NEVER))
            case str():
                args.append(ArgumentKeyword(None, self.token, quotes=QuoteStyle.ALWAYS))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandSaveConf(Command):
    """
    Command implementation for :attr:`~CommandWord.SAVECONF`.

    Instructs the server to write out its configuration options into ``torrc``.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#saveconf

    """

    command: ClassVar[CommandWord] = CommandWord.SAVECONF

    #: If ``%include`` is used on ``torrc``, ``SAVECONF`` will not write the configuration
    #: to disk.  When set, the configuration will be overwritten even if %include is used.
    #: You can find out whether this flag is needed using ``config-can-saveconf`` on
    #: :class:`CommandGetInfo`.
    force: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append ``SAVECONF`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        if self.force:
            # Flags are treated as keywords with no value.
            args.append(ArgumentKeyword('FORCE', None))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandSignal(Command):
    """
    Command implementation for :attr:`~CommandWord.SIGNAL`.

    Send a signal to Tor.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#signal

    """

    command: ClassVar[CommandWord] = CommandWord.SIGNAL

    #: The signal to send to Tor.
    signal: Signal

    def _serialize(self) -> CommandSerializer:
        """Append ``SIGNAL`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(self.signal, safe=True))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandMapAddress(Command):
    """
    Command implementation for :attr:`~CommandWord.MAPADDRESS`.

    The client sends this message to the server in order to tell it that future
    SOCKS requests for connections to the original address should be replaced
    with connections to the specified replacement address.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#mapaddress

    """

    command: ClassVar[CommandWord] = CommandWord.MAPADDRESS

    #: Map of addresses to remap on socks requests.
    addresses: MutableMapping[str, str] = field(default_factory=dict)

    def _serialize(self) -> CommandSerializer:
        """Append ``MAPADDRESS`` specific arguments."""
        if len(self.addresses) == 0:
            msg = "No address provided for command 'MAPADDRESS'"
            raise CommandError(msg)

        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        for key, value in self.addresses.items():
            args.append(ArgumentKeyword(key, value, quotes=QuoteStyle.NEVER_ENSURE))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandGetInfo(Command):
    """
    Command implementation for :attr:`~CommandWord.GETINFO`.

    Unlike :attr:`~CommandWord.GETCONF` this message is used for data that are not stored
    in the Tor configuration file, and that may be longer than a single line.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#getinfo

    """

    command: ClassVar[CommandWord] = CommandWord.GETINFO

    #: List of keywords to request the value from. One or more must be provided.
    keywords: MutableSequence[str] = field(default_factory=list)

    def _serialize(self) -> CommandSerializer:
        """Append ``GETINFO`` specific arguments."""
        if len(self.keywords) == 0:
            msg = "No keyword provided for command 'GETINFO'"
            raise CommandError(msg)

        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        for keyword in self.keywords:
            args.append(ArgumentString(keyword))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandExtendCircuit(Command):
    """
    Command implementation for :attr:`~CommandWord.EXTENDCIRCUIT`.

    This request takes one of two forms: either :attr:`circuit` is zero, in which case it is
    a request for the server to build a new circuit, or :attr:`circuit` is nonzero, in which
    case it is a request for the server to extend an existing circuit with that ID
    according to the specified path provided in :attr:`server_spec`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#extendcircuit

    """

    command: ClassVar[CommandWord] = CommandWord.EXTENDCIRCUIT

    #: Circuit identifier to extend, ``0`` to create a new circuit.
    circuit: int
    #: Optional list of servers to extend the circuit onto.
    server_spec: MutableSequence[str] = field(default_factory=list)
    #: Circuit purpose or :obj:`None` to use a default purpose.
    purpose: CircuitPurpose | None = None

    def _serialize(self) -> CommandSerializer:
        """Append ``EXTENDCIRCUIT`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(self.circuit, safe=True))
        if len(self.server_spec):
            text = ','.join(self.server_spec)
            args.append(ArgumentString(text))
        if self.purpose is not None:
            args.append(ArgumentKeyword('purpose', self.purpose, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandSetCircuitPurpose(Command):
    """
    Command implementation for :attr:`~CommandWord.SETCIRCUITPURPOSE`.

    This changes the descriptor's purpose.

    Hints:
        See :class:`CommandPostDescriptor` for more details on :attr:`purpose`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#setcircuitpurpose

    """

    command: ClassVar[CommandWord] = CommandWord.SETCIRCUITPURPOSE

    #: Circuit ID to set the purpose on.
    circuit: int
    #: Set purpose of the provided circuit.
    purpose: CircuitPurpose

    def _serialize(self) -> CommandSerializer:
        """Append ``SETCIRCUITPURPOSE`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(self.circuit, safe=True))
        args.append(ArgumentKeyword('purpose', self.purpose, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandAttachStream(Command):
    """
    Command implementation for :attr:`~CommandWord.ATTACHSTREAM`.

    This message informs the server that the specified :attr:`stream` should
    be associated with the :attr:`circuit`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#attachstream

    """

    command: ClassVar[CommandWord] = CommandWord.ATTACHSTREAM

    #: Stream to associate to the provided circuit.
    stream: int

    #: Circuit identifier to attach the stream onto.
    circuit: int

    #: When set, Tor will choose the HopNumth hop in the circuit as the exit node,
    #: rather that the last node in the circuit. Hops are 1-indexed; generally,
    #: it is not permitted to attach to hop 1.
    hop: int | None = None

    def _serialize(self) -> CommandSerializer:
        """Append ``ATTACHSTREAM`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(self.stream, safe=True))
        args.append(ArgumentString(self.circuit, safe=True))
        if self.hop is not None:
            args.append(ArgumentKeyword('HOP', self.hop, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandPostDescriptor(Command):
    """
    Command implementation for :attr:`~CommandWord.POSTDESCRIPTOR`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#postdescriptor

    """

    command: ClassVar[CommandWord] = CommandWord.POSTDESCRIPTOR

    #: If specified must be :attr:`~.CircuitPurpose.GENERAL`,
    #: :attr:`~.CircuitPurpose.CONTROLLER`, :attr:`~.CircuitPurpose.BRIDGE`,
    #: default is :attr:`~.CircuitPurpose.GENERAL`.
    purpose: CircuitPurpose | None = None
    #: Cache the provided descriptor internally.
    cache: bool | None = None
    #: Descriptor content.
    descriptor: str

    def _serialize(self) -> CommandSerializer:
        """Append ``POSTDESCRIPTOR`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

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
    Command implementation for :attr:`~CommandWord.REDIRECTSTREAM`.

    Tells the server to change the exit address on the specified stream.
    If :attr:`port` is specified, changes the destination port as well.

    No remapping is performed on the new provided address.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#redirectstream

    """

    command: ClassVar[CommandWord] = CommandWord.REDIRECTSTREAM

    #: Stream identifier to redirect.
    stream: int
    #: Destination address to redirect it to.
    address: str
    #: Optional port to redirect the stream to.
    port: int | None = None

    def _serialize(self) -> CommandSerializer:
        """Append ``REDIRECTSTREAM`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(self.stream, safe=True))
        args.append(ArgumentString(self.address))
        if self.port is not None:
            args.append(ArgumentString(self.port, safe=True))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandCloseStream(Command):
    """
    Command implementation for :attr:`~CommandWord.CLOSESTREAM`.

    Tells the server to close the specified :attr:`stream`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#closestream

    """

    command: ClassVar[CommandWord] = CommandWord.CLOSESTREAM

    #: Identifier to the stream to close.
    stream: int
    #: Provide a reason for the stream to be closed.
    reason: CloseStreamReason

    def _serialize(self) -> CommandSerializer:
        """Append ``CLOSESTREAM`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(self.stream, safe=True))
        args.append(ArgumentString(self.reason, safe=True))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandCloseCircuit(Command):
    """
    Command implementation for :attr:`~CommandWord.CLOSECIRCUIT`.

    Tells the server to close the specified circuit.

    When :attr:`if_unused` is :obj:`True`, do not close the circuit unless it is unused.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#closecircuit

    """

    command: ClassVar[CommandWord] = CommandWord.CLOSECIRCUIT

    #: Circuit identifier to close.
    circuit: int

    #: Do not close the circuit unless it is unused.
    if_unused: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append `CLOSECIRCUIT` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(self.circuit, safe=True))
        if self.if_unused:
            args.append(ArgumentKeyword('IfUnused', None))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandQuit(Command):
    """
    Command implementation for :attr:`~CommandWord.QUIT`.

    Tells the server to hang up on this controller connection.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#quit

    """

    command: ClassVar[CommandWord] = CommandWord.QUIT

    def _serialize(self) -> CommandSerializer:
        """
        Serialize a ``QUIT`` command.

        This command has no additional arguments.
        """
        return super()._serialize()


@dataclass(kw_only=True)
class CommandUseFeature(Command):
    """
    Command implementation for :attr:`~CommandWord.USEFEATURE`.

    Adding additional features to the control protocol sometimes will break backwards
    compatibility. Initially such features are added into Tor and disabled by default.
    :attr:`~CommandWord.USEFEATURE` can enable these additional features.

    Note:
        To get a list of available features please use ``features/names``
        with :class:`CommandGetInfo`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#usefeature

    """

    command: ClassVar[CommandWord] = CommandWord.USEFEATURE

    #: Set of features to enable.
    features: set[Feature | str] = field(default_factory=set)

    def _serialize(self) -> CommandSerializer:
        """Append `USEFEATURE` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        for feature in self.features:
            args.append(ArgumentString(feature))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandResolve(Command):
    """
    Command implementation for :attr:`~CommandWord.RESOLVE`.

    This command launches a remote hostname lookup request for every specified
    request (or reverse lookup if :attr:`reverse` is specified).
    Note that the request is done in the background: to see the answers, your controller
    will need to listen for :attr:`.EventWord.ADDRMAP` events.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#resolve

    """

    command: ClassVar[CommandWord] = CommandWord.RESOLVE

    #: List of addresses get a resolution for.
    addresses: MutableSequence[str] = field(default_factory=list)
    #: Whether we should perform a reverse lookup resolution.
    reverse: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append ``RESOLVE`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        if self.reverse:
            args.append(ArgumentKeyword('mode', 'reverse', quotes=QuoteStyle.NEVER))
        for address in self.addresses:
            # These are marked as keywords in `src/feature/control/control_cmd.c`.
            args.append(ArgumentKeyword(address, None))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandProtocolInfo(Command):
    """
    Command implementation for :attr:`~CommandWord.PROTOCOLINFO`.

    This command tells the controller what kinds of authentication are supported.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#protocolinfo

    """

    command: ClassVar[CommandWord] = CommandWord.PROTOCOLINFO

    #: Optional version to request information for (ignored by Tor at the moment).
    version: int | None = None

    def _serialize(self) -> CommandSerializer:
        """Append ``PROTOCOLINFO`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        if self.version is not None:
            args.append(ArgumentString(self.version, safe=True))

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandLoadConf(Command):
    """
    Command implementation for :attr:`~CommandWord.LOADCONF`.

    This command allows a controller to upload the text of a config file to Tor over
    the control port. This config file is then loaded as if it had been read from disk.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#loadconf

    """

    command: ClassVar[CommandWord] = CommandWord.LOADCONF

    #: Raw configuration text to load.
    text: str

    def _serialize(self) -> CommandSerializer:
        """Append ``LOADCONF`` specific arguments."""
        ser = super()._serialize()
        ser.body = self.text
        return ser


@dataclass(kw_only=True)
class CommandTakeOwnership(Command):
    """
    Command implementation for :attr:`~CommandWord.TAKEOWNERSHIP`.

    This command instructs Tor to shut down when this control connection is closed.
    It affects each control connection that sends it independently; if multiple control
    connections send the :attr:`~CommandWord.TAKEOWNERSHIP` command to a Tor instance,
    Tor will shut down when any of those connections closes.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#takeownership

    """

    command: ClassVar[CommandWord] = CommandWord.TAKEOWNERSHIP

    def _serialize(self) -> CommandSerializer:
        """Serialize a ``TAKEOWNERSHIP`` command."""
        return super()._serialize()


@dataclass(kw_only=True)
class CommandAuthChallenge(Command):
    """
    Command implementation for :attr:`~CommandWord.AUTHCHALLENGE`.

    This command is used to begin the authentication routine for the
    :attr:`~.AuthMethod.SAFECOOKIE` authentication method.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#authchallenge

    """

    #: Length of the nonce we expect to receive (when :class:`bytes`).
    NONCE_LENGTH: ClassVar[int] = 32

    command: ClassVar[CommandWord] = CommandWord.AUTHCHALLENGE

    #: Nonce value, a new one is generated when none is provided.
    nonce: bytes | str | None

    @classmethod
    def generate_nonce(cls) -> bytes:
        """Generate a nonce value of 32 bytes."""
        return secrets.token_bytes(cls.NONCE_LENGTH)

    def _serialize(self) -> CommandSerializer:
        """Append ``AUTHCHALLENGE`` specific arguments."""
        # Generate a nonce while serializing as we need one!
        if self.nonce is None:
            self.nonce = self.generate_nonce()

        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString('SAFECOOKIE', safe=True))

        match self.nonce:
            case bytes():
                args.append(ArgumentKeyword(None, self.nonce.hex(), quotes=QuoteStyle.NEVER))
            case str():  # pragma: no branch
                args.append(ArgumentKeyword(None, self.nonce, quotes=QuoteStyle.ALWAYS))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandDropGuards(Command):
    """
    Command implementation for :attr:`~CommandWord.DROPGUARDS`.

    Tells the server to drop all guard nodes.

    Warning:
        Do not invoke this command lightly; it can increase vulnerability to
        tracking attacks over time.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#dropguards

    """

    command: ClassVar[CommandWord] = CommandWord.DROPGUARDS

    def _serialize(self) -> CommandSerializer:
        """Serialize a ``DROPGUARDS`` command."""
        return super()._serialize()


@dataclass(kw_only=True)
class CommandHsFetch(Command):
    """
    Command implementation for :attr:`~CommandWord.HSFETCH`.

    This command launches hidden service descriptor fetch(es) for the given :attr:`address`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#hsfetch

    """

    command: ClassVar[CommandWord] = CommandWord.HSFETCH

    #: Optional list of servers to contact for a hidden service descriptor.
    servers: MutableSequence[str] = field(default_factory=list)

    #: Onion address (v2 or v3) to request a descriptor for, without the ``.onion`` suffix.
    address: HiddenServiceAddress

    def _serialize(self) -> CommandSerializer:
        """Append ``HSFETCH`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(self.address, safe=True))
        for server in self.servers:
            args.append(ArgumentKeyword('SERVER', server, quotes=QuoteStyle.NEVER_ENSURE))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandAddOnion(Command):
    """
    Command implementation for :attr:`~CommandWord.ADD_ONION`.

    Tells Tor to create a new onion "hidden" Service, with the specified private key
    and algorithm.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#add_onion

    """

    command: ClassVar[CommandWord] = CommandWord.ADD_ONION

    #: Type of service key to use (or ``NEW``).
    key_type: OnionServiceKeyType | Literal['NEW']

    #: The key as :class:`bytes` or :class:`str`, or the type of key to generate.
    key: OnionServiceKeyType | Literal['BEST'] | bytes | str  # noqa: PYI051

    #: Set of boolean options to attach to this service.
    flags: set[OnionServiceFlags] = field(default_factory=set)

    #: Optional number between 0 and 65535 which is the maximum streams that can be
    #: attached on a rendezvous circuit. Setting it to 0 means unlimited which is
    #: also the default behavior.
    max_streams: int | None = None

    #: As in an arguments to config ``HiddenServicePort``, ``port,target``.
    ports: MutableSequence[str] = field(default_factory=list)

    #: Syntax is ``ClientName:ClientBlob``.
    client_auth: MutableSequence[str] = field(default_factory=list)

    #: String syntax is a base32-encoded x25519 public key with only the key part.
    client_auth_v3: MutableSequence[Base32Bytes | str] = field(default_factory=list)

    def _serialize_client_auth_v3_key(self, client: Base32Bytes | str) -> str:
        """Serialize a client key to a string."""
        match client:
            case bytes():
                auth_data = b32encode(client).decode('ascii').rstrip('=')
            case str():  # pragma: no branch
                auth_data = client
        return auth_data

    def _serialize_service_key(self) -> str:
        """Serialize the service key to a string."""
        if isinstance(self.key_type, OnionServiceKeyType):
            key_type = self.key_type.value
        else:
            key_type = self.key_type

        match self.key:
            case OnionServiceKeyType():
                key_data = self.key.value
            case bytes():
                key_data = standard_b64encode(self.key).decode('ascii').rstrip('=')
            case str():  # pragma: no branch
                key_data = self.key

        return f'{key_type}:{key_data}'

    def _serialize(self) -> CommandSerializer:
        """Append ``ADD_ONION`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        do_generate = bool(self.key_type == 'NEW')
        has_keyblob = bool(
            not isinstance(self.key, OnionServiceKeyType) and self.key != 'BEST'
        )
        if do_generate == has_keyblob:
            msg = "Incompatible options for 'key_type' and 'key'."
            raise CommandError(msg)

        if not len(self.ports):
            msg = 'You must specify one or more virtual ports.'
            raise CommandError(msg)

        key_spec = self._serialize_service_key()
        args.append(ArgumentString(key_spec))

        # Automatically set the V3 authentication when applicable.
        if len(self.client_auth_v3):
            self.flags.add(OnionServiceFlags.V3AUTH)

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
        for auth_v3 in self.client_auth_v3:
            key_spec = self._serialize_client_auth_v3_key(auth_v3)
            kwarg = ArgumentKeyword('ClientAuthV3', key_spec, quotes=QuoteStyle.NEVER_ENSURE)
            args.append(kwarg)

        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandDelOnion(Command):
    """
    Command implementation for :attr:`~CommandWord.DEL_ONION`.

    Tells the server to remove an Onion "hidden" Service, that was previously created
    trough :class:`CommandAddOnion`. It is only possible to remove onion services that were
    created on the same control connection as the :attr:`~CommandWord.DEL_ONION` command, and
    those that belong to no control connection in particular
    (the :attr:`~.OnionServiceFlags.DETACH` flag was specified upon creation).

    See Also:
        https://spec.torproject.org/control-spec/commands.html#del_onion

    """

    command: ClassVar[CommandWord] = CommandWord.DEL_ONION

    #: This is the v2 or v3 address without the ``.onion`` suffix.
    address: HiddenServiceAddress

    def _serialize(self) -> CommandSerializer:
        """Append ``DEL_ONION`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(self.address))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandHsPost(Command):
    """
    Command implementation for :attr:`~CommandWord.HSPOST`.

    This command launches a hidden service descriptor upload to the specified HSDirs.
    If one or more Server arguments are provided, an upload is triggered on each of
    them in parallel. If no Server options are provided, it behaves like a normal HS
    descriptor upload and will upload to the set of responsible HS directories.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#hspost

    """

    command: ClassVar[CommandWord] = CommandWord.HSPOST

    #: List of servers to upload the descriptor to (if any is provided).
    servers: MutableSequence[str] = field(default_factory=list)
    #: This is the optional v2 or v3 address without the ``.onion`` suffix.
    address: HiddenServiceAddress | None = None
    #: Descriptor content as raw text.
    descriptor: str

    def _serialize(self) -> CommandSerializer:
        """Append ``HSPOST`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
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
    Command implementation for :attr:`~CommandWord.ONION_CLIENT_AUTH_ADD`.

    Tells the connected Tor to add client-side v3 client auth credentials for the onion
    service with :attr:`address`. The :attr:`key` is the x25519 private key that should
    be used for this client, and :attr:`nickname` is an optional nickname for the client.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#onion_client_auth_add

    """

    command: ClassVar[CommandWord] = CommandWord.ONION_CLIENT_AUTH_ADD

    #: V3 onion address without the ``.onion`` suffix.
    address: HiddenServiceAddressV3

    #: Key type is currently set to :attr:`~.OnionClientAuthKeyType.X25519`.
    key_type: OnionClientAuthKeyType = OnionClientAuthKeyType.X25519
    #: The private ``x25519`` key as bytes or as a string of base64 encoded bytes.
    key: Base64Bytes | str
    #: An optional nickname for the client.
    nickname: str | None = None
    #: Whether this client's credentials should be stored on the file system.
    flags: AbstractSet[OnionClientAuthFlags] = field(default_factory=set)

    def _serialize(self) -> CommandSerializer:
        """Append ``ONION_CLIENT_AUTH_ADD`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(self.address))

        match self.key:
            case bytes():
                key_data = standard_b64encode(self.key).decode('ascii').rstrip('=')
            case str():  # pragma: no branch
                key_data = self.key

        args.append(ArgumentString(f'{self.key_type.value}:{key_data}'))

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
    Command implementation for :attr:`~CommandWord.ONION_CLIENT_AUTH_REMOVE`.

    Tells the connected Tor to remove the client-side v3 client auth credentials
    for the onion service with :attr:`address`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#onion_client_auth_remove

    """

    command: ClassVar[CommandWord] = CommandWord.ONION_CLIENT_AUTH_REMOVE

    #: V3 onion address without the ``.onion`` suffix.
    address: HiddenServiceAddressV3

    def _serialize(self) -> CommandSerializer:
        """Append ``ONION_CLIENT_AUTH_REMOVE`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(self.address))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandOnionClientAuthView(Command):
    """
    Command implementation for :attr:`~CommandWord.ONION_CLIENT_AUTH_VIEW`.

    Tells the connected Tor to list all the stored client-side v3 client auth credentials
    for :attr:`address`. If no :attr:`address` is provided, list all the stored client-side
    v3 client auth credentials.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#onion_client_auth_view

    """

    command: ClassVar[CommandWord] = CommandWord.ONION_CLIENT_AUTH_VIEW

    #: V3 onion address without the ``.onion`` suffix.
    address: HiddenServiceAddress | None = None

    def _serialize(self) -> CommandSerializer:
        """Append ``ONION_CLIENT_AUTH_VIEW`` specific arguments."""
        ser = super()._serialize()
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        if self.address is not None:
            args.append(ArgumentString(self.address))
        ser.arguments.extend(args)
        return ser


@dataclass(kw_only=True)
class CommandDropOwnership(Command):
    """
    Command implementation for :attr:`~CommandWord.DROPOWNERSHIP`.

    This command instructs Tor to relinquish ownership of its control connection.
    As such tor will not shut down when this control connection is closed.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#dropownership

    """

    command: ClassVar[CommandWord] = CommandWord.DROPOWNERSHIP

    def _serialize(self) -> CommandSerializer:
        """Serialize a ``DROPOWNERSHIP`` command."""
        return super()._serialize()


@dataclass(kw_only=True)
class CommandDropTimeouts(Command):
    """
    Command implementation for :attr:`~CommandWord.DROPTIMEOUTS`.

    Tells the server to drop all circuit build times.

    Warning:
        Do not invoke this command lightly; it can increase vulnerability
        to tracking attacks over time.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#droptimeouts

    """

    command: ClassVar[CommandWord] = CommandWord.DROPTIMEOUTS

    def _serialize(self) -> CommandSerializer:
        """Serialize a ``DROPTIMEOUTS`` command."""
        return super()._serialize()
