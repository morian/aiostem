from __future__ import annotations

import secrets
from collections.abc import Mapping, MutableMapping, MutableSequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Literal, Union

from pydantic import Discriminator, NonNegativeInt, Tag, TypeAdapter
from pydantic_core import core_schema

from .event import EventWord
from .exceptions import CommandError
from .structures import (
    CircuitPurpose,
    DescriptorPurpose,
    Feature,
    HiddenServiceAddress,
    HiddenServiceAddressV3,
    HsDescClientAuthV2,
    HsDescClientAuthV3,
    LongServerName,
    OnionClientAuthFlags,
    OnionClientAuthKey,
    OnionServiceFlags,
    OnionServiceKey,
    OnionServiceNewKey,
    OnionServiceNewKeyStruct,
    Signal,
    StreamCloseReasonInt,
    VirtualPort,
)
from .types import AnyHost, AnyPort, Base16Bytes, BoolYesNo
from .utils import (
    ArgumentKeyword,
    ArgumentString,
    QuoteStyle,
    Self,
    StrEnum,
    TrBeforeStringSplit,
)

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler
    from pydantic_core.core_schema import CoreSchema, SerializerFunctionWrapHandler


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
    #:     - Controller method: :meth:`.Controller.extend_circuit`
    #:     - Command implementation: :class:`CommandExtendCircuit`
    #:     - Reply implementation: :class:`.ReplyExtendCircuit`
    EXTENDCIRCUIT = 'EXTENDCIRCUIT'

    #: Change the purpose of a circuit.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.set_circuit_purpose`
    #:     - Command implementation: :class:`CommandSetCircuitPurpose`
    #:     - Reply implementation: :class:`.ReplySetCircuitPurpose`
    SETCIRCUITPURPOSE = 'SETCIRCUITPURPOSE'

    #: Not implemented because it was marked as obsolete as of ``Tor v0.2.0.8``.
    SETROUTERPURPOSE = 'SETROUTERPURPOSE'

    #: Request that the specified stream should be associated with the specified circuit.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.attach_stream`
    #:     - Command implementation: :class:`CommandAttachStream`
    #:     - Reply implementation: :class:`.ReplyAttachStream`
    ATTACHSTREAM = 'ATTACHSTREAM'

    #: This message informs the server about a new router descriptor.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.post_descriptor`
    #:     - Command implementation: :class:`CommandPostDescriptor`
    #:     - Reply implementation: :class:`.ReplyPostDescriptor`
    POSTDESCRIPTOR = 'POSTDESCRIPTOR'

    #: Tells the server to change the exit address on the specified stream.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.redirect_stream`
    #:     - Command implementation: :class:`CommandRedirectStream`
    #:     - Reply implementation: :class:`.ReplyRedirectStream`
    REDIRECTSTREAM = 'REDIRECTSTREAM'

    #: Tells the server to close the specified stream.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.close_stream`
    #:     - Command implementation: :class:`CommandCloseStream`
    #:     - Reply implementation: :class:`.ReplyCloseStream`
    CLOSESTREAM = 'CLOSESTREAM'

    #: Tells the server to close the specified circuit.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.close_circuit`
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
    #:     - Controller method: :meth:`.Controller.resolve`
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
    #:     - Controller method: :meth:`.Controller.take_ownership`
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
    #:     - Controller method: :meth:`.Controller.add_onion`
    #:     - Command implementation: :class:`CommandAddOnion`
    #:     - Reply implementation: :class:`.ReplyAddOnion`
    ADD_ONION = 'ADD_ONION'

    #: Tells the server to remove an onion "hidden" service.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.del_onion`
    #:     - Command implementation: :class:`CommandDelOnion`
    #:     - Reply implementation: :class:`.ReplyDelOnion`
    DEL_ONION = 'DEL_ONION'

    #: This command launches a hidden service descriptor upload to the specified HSDirs.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.hs_post`
    #:     - Command implementation: :class:`CommandHsPost`
    #:     - Reply implementation: :class:`.ReplyHsPost`
    HSPOST = 'HSPOST'

    #: Add client-side v3 client auth credentials for a onion service.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.onion_client_auth_add`
    #:     - Command implementation: :class:`CommandOnionClientAuthAdd`
    #:     - Reply implementation: :class:`.ReplyOnionClientAuthAdd`
    ONION_CLIENT_AUTH_ADD = 'ONION_CLIENT_AUTH_ADD'

    #: Remove client-side v3 client auth credentials for a onion service.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.onion_client_auth_remove`
    #:     - Command implementation: :class:`CommandOnionClientAuthRemove`
    #:     - Reply implementation: :class:`.ReplyOnionClientAuthRemove`
    ONION_CLIENT_AUTH_REMOVE = 'ONION_CLIENT_AUTH_REMOVE'

    #: List client-side v3 client auth credentials for a onion service.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.onion_client_auth_view`
    #:     - Command implementation: :class:`CommandOnionClientAuthView`
    #:     - Reply implementation: :class:`.ReplyOnionClientAuthView`
    ONION_CLIENT_AUTH_VIEW = 'ONION_CLIENT_AUTH_VIEW'

    #: This command instructs Tor to relinquish ownership of its control connection.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.drop_ownership`
    #:     - Command implementation: :class:`CommandDropOwnership`
    #:     - Reply implementation: :class:`.ReplyDropOwnership`
    DROPOWNERSHIP = 'DROPOWNERSHIP'

    #: Tells the server to drop all circuit build times.
    #:
    #: See Also:
    #:     - Controller method: :meth:`.Controller.drop_timeouts`
    #:     - Command implementation: :class:`CommandDropTimeouts`
    #:     - Reply implementation: :class:`.ReplyDropTimeouts`
    DROPTIMEOUTS = 'DROPTIMEOUTS'


class CommandSerializer:
    """Helper class used to serialize an existing command."""

    #: End of line to use while serializing a command.
    END_OF_LINE: ClassVar[str] = '\r\n'

    def __init__(self, name: CommandWord) -> None:
        """
        Create a new command serializer.

        This is used internally by :meth:`.Command.serialize`.

        Args:
            name: The command name.

        """
        self._body = None  # type: str | None
        self._command = name
        self._arguments = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

    def serialize(self) -> str:
        """
        Serialize the arguments to a string.

        Returns:
            Text that can be pushed to the server.

        """
        # Build the header line.
        args = [self._command.value]
        for argument in self._arguments:
            args.append(str(argument))

        header = ' '.join(args)
        # Check for command injection in case some user-controlled values went through.
        if any(c in header for c in '\r\v\n'):
            msg = 'Command injection was detected and prevented'
            raise CommandError(msg)
        lines = [header]

        # Include the potential body, if applicable.
        if self._body is None:
            prefix = ''
        else:
            for line in self._body.splitlines():
                if line.startswith('.'):
                    line = '.' + line
                lines.append(line)
            lines.append('.')
            prefix = '+'
        return prefix + self.END_OF_LINE.join(lines) + self.END_OF_LINE

    @property
    def command(self) -> CommandWord:
        """Get the command name for the underlying command."""
        return self._command

    @property
    def arguments(self) -> MutableSequence[ArgumentKeyword | ArgumentString]:
        """Get the list of command arguments."""
        return self._arguments

    @property
    def body(self) -> str | None:
        """Get the command body, if any."""
        return self._body

    @body.setter
    def body(self, body: str) -> None:
        """
        Set the command body.

        Args:
            body: The new body content for the command.

        """
        self._body = body


class Command:
    """Base class for all commands."""

    #: Cached adapter used while serializing the command.
    ADAPTER: ClassVar[TypeAdapter[Self] | None] = None

    #: Command word this command is for.
    command: ClassVar[CommandWord]

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Create a pydantic validator and serializer for this structure."""
        # Is there another way to simply wrap an existing schema?
        # We simply need to add a custom serializer on top of the existing one.
        return core_schema.union_schema(
            choices=[handler(source)],
            serialization=core_schema.wrap_serializer_function_ser_schema(
                function=cls._pydantic_serializer,
                schema=handler(source),
                return_schema=core_schema.str_schema(),
            ),
        )

    @classmethod
    def _pydantic_serializer(cls, item: Self, to_dict: SerializerFunctionWrapHandler) -> str:
        """
        Serialize the provided command to a nice string.

        This method is the one used by pydantic during serialization.
        Here ``to_dict`` is a function used to call the inner (original) serializer,
        which provides a nice dictionary with all of our fields already serializer.

        """
        return item.serialize_from_struct(to_dict(item))

    @classmethod
    def adapter(cls) -> TypeAdapter[Self]:
        """Get a cached type adapter to serialize a command."""
        if cls.ADAPTER is None:
            cls.ADAPTER = TypeAdapter(cls)
        return cls.ADAPTER

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """
        Serialize the command to text.

        This command is not intended to be called by the end user.

        Args:
            struct: a dictionary serialization for this structure.

        Returns:
            Text that can be sent to Tor's control port.

        """
        return CommandSerializer(self.command).serialize()

    def serialize(self) -> str:
        """Serialize this command to a string."""
        return self.adapter().dump_python(self)


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``SETCONF`` specific arguments."""
        values = struct['values']
        if len(values) == 0:
            msg = f"No value provided for command '{self.command.value}'"
            raise CommandError(msg)

        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        for key, value in values.items():
            if isinstance(value, MutableSequence):
                for item in value:
                    args.append(ArgumentKeyword(key, item))
            else:
                args.append(ArgumentKeyword(key, value))
        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``GETCONF`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        for keyword in struct['keywords']:
            args.append(ArgumentString(keyword))
        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``SETEVENTS`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        for evt in struct['events']:
            args.append(ArgumentString(evt, safe=True))
        ser.arguments.extend(args)
        return ser.serialize()


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
    token: Base16Bytes | str | None = None

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``AUTHENTICATE`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        # Here we need to have the original type for serialization.
        token = struct['token']
        match self.token:
            case bytes():
                args.append(ArgumentKeyword(None, token, quotes=QuoteStyle.NEVER))
            case str():
                args.append(ArgumentKeyword(None, token, quotes=QuoteStyle.ALWAYS))
        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``SAVECONF`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        if struct['force'] is True:
            # Flags are treated as keywords with no value.
            args.append(ArgumentKeyword('FORCE', None))
        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``SIGNAL`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(struct['signal'], safe=True))
        ser.arguments.extend(args)
        return ser.serialize()


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
    addresses: MutableMapping[Union[AnyHost], Union[AnyHost]] = field(default_factory=dict)  # noqa: UP007

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``MAPADDRESS`` specific arguments."""
        addresses = struct['addresses']
        if len(addresses) == 0:
            msg = "No address provided for command 'MAPADDRESS'"
            raise CommandError(msg)

        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        for key, value in addresses.items():
            args.append(ArgumentKeyword(key, value, quotes=QuoteStyle.NEVER_ENSURE))

        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``GETINFO`` specific arguments."""
        keywords = struct['keywords']
        if len(keywords) == 0:
            msg = "No keyword provided for command 'GETINFO'"
            raise CommandError(msg)

        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        for keyword in keywords:
            args.append(ArgumentString(keyword))

        ser.arguments.extend(args)
        return ser.serialize()


@dataclass(kw_only=True)
class CommandExtendCircuit(Command):
    """
    Command implementation for :attr:`~CommandWord.EXTENDCIRCUIT`.

    This request takes one of two forms: either :attr:`circuit` is zero, in which case it is
    a request for the server to build a new circuit, or :attr:`circuit` is nonzero, in which
    case it is a request for the server to extend an existing circuit with that ID
    according to the specified path provided in :attr:`servers`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#extendcircuit

    """

    command: ClassVar[CommandWord] = CommandWord.EXTENDCIRCUIT

    #: Circuit identifier to extend, ``0`` to create a new circuit.
    circuit: int

    #: List of servers to extend the circuit onto (or no server).
    servers: Annotated[
        MutableSequence[LongServerName],
        TrBeforeStringSplit(),
    ] = field(default_factory=list)

    #: Circuit purpose or :obj:`None` to use a default purpose.
    purpose: Literal[CircuitPurpose.CONTROLLER, CircuitPurpose.GENERAL] | None = None

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``EXTENDCIRCUIT`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        circuit = struct['circuit']
        args.append(ArgumentString(circuit, safe=True))

        servers = struct['servers']
        if servers:
            args.append(ArgumentString(servers))

        purpose = struct['purpose']
        if purpose is not None:
            args.append(ArgumentKeyword('purpose', purpose, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser.serialize()


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
    purpose: Literal[CircuitPurpose.CONTROLLER, CircuitPurpose.GENERAL]

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``SETCIRCUITPURPOSE`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(struct['circuit'], safe=True))
        args.append(ArgumentKeyword('purpose', struct['purpose'], quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``ATTACHSTREAM`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(struct['stream'], safe=True))
        args.append(ArgumentString(struct['circuit'], safe=True))

        hop = struct['hop']
        if hop is not None:
            args.append(ArgumentKeyword('HOP', hop, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser.serialize()


@dataclass(kw_only=True)
class CommandPostDescriptor(Command):
    """
    Command implementation for :attr:`~CommandWord.POSTDESCRIPTOR`.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#postdescriptor

    """

    command: ClassVar[CommandWord] = CommandWord.POSTDESCRIPTOR

    #: Purpose of the provided descriptor.
    purpose: DescriptorPurpose | None = None

    #: Cache the provided descriptor internally.
    cache: BoolYesNo | None = None

    #: Descriptor content.
    descriptor: str

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``POSTDESCRIPTOR`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        purpose = struct['purpose']
        if purpose is not None:
            args.append(ArgumentKeyword('purpose', purpose, quotes=QuoteStyle.NEVER))

        cache = struct['cache']
        if cache is not None:
            args.append(ArgumentKeyword('cache', cache, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        ser.body = struct['descriptor']
        return ser.serialize()


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
    address: Union[AnyHost]  # noqa: UP007
    #: Optional port to redirect the stream to.
    port: AnyPort | None = None

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``REDIRECTSTREAM`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(struct['stream'], safe=True))
        args.append(ArgumentString(struct['address']))

        port = struct['port']
        if port is not None:
            args.append(ArgumentString(port, safe=True))

        ser.arguments.extend(args)
        return ser.serialize()


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
    reason: StreamCloseReasonInt

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``CLOSESTREAM`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(struct['stream'], safe=True))
        args.append(ArgumentString(struct['reason'], safe=True))
        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``CLOSECIRCUIT`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(struct['circuit'], safe=True))

        if struct['if_unused'] is True:
            args.append(ArgumentKeyword('IfUnused', None))

        ser.arguments.extend(args)
        return ser.serialize()


@dataclass(kw_only=True)
class CommandQuit(Command):
    """
    Command implementation for :attr:`~CommandWord.QUIT`.

    Tells the server to hang up on this controller connection.

    See Also:
        https://spec.torproject.org/control-spec/commands.html#quit

    """

    command: ClassVar[CommandWord] = CommandWord.QUIT


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``USEFEATURE`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        for feature in struct['features']:
            args.append(ArgumentString(feature))
        ser.arguments.extend(args)
        return ser.serialize()


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
    addresses: MutableSequence[Union[AnyHost]] = field(default_factory=list)  # noqa: UP007
    #: Whether we should perform a reverse lookup resolution.
    reverse: bool = False

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``RESOLVE`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        if struct['reverse'] is True:
            args.append(ArgumentKeyword('mode', 'reverse', quotes=QuoteStyle.NEVER))
        for address in struct['addresses']:
            # These are marked as keywords in `src/feature/control/control_cmd.c`.
            args.append(ArgumentKeyword(address, None))

        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``PROTOCOLINFO`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        version = struct['version']
        if version is not None:
            args.append(ArgumentString(version, safe=True))

        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``LOADCONF`` specific arguments."""
        ser = CommandSerializer(self.command)
        ser.body = struct['text']
        return ser.serialize()


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
    nonce: Base16Bytes | str

    @classmethod
    def generate_nonce(cls) -> bytes:
        """Generate a nonce value of 32 bytes."""
        return secrets.token_bytes(cls.NONCE_LENGTH)

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``AUTHCHALLENGE`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString('SAFECOOKIE', safe=True))

        # Here we need to have the original type for serialization.
        nonce = struct['nonce']
        match self.nonce:
            case bytes():
                args.append(ArgumentKeyword(None, nonce, quotes=QuoteStyle.NEVER))
            case str():  # pragma: no branch
                args.append(ArgumentKeyword(None, nonce, quotes=QuoteStyle.ALWAYS))
        ser.arguments.extend(args)
        return ser.serialize()


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
    servers: MutableSequence[LongServerName] = field(default_factory=list)

    #: Onion address (v2 or v3) to request a descriptor for, without the ``.onion`` suffix.
    address: HiddenServiceAddress

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``HSFETCH`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(struct['address'], safe=True))
        for server in struct['servers']:
            args.append(ArgumentKeyword('SERVER', server, quotes=QuoteStyle.NEVER_ENSURE))
        ser.arguments.extend(args)
        return ser.serialize()


def _onion_add_get_key_tag(v: Any) -> str:
    """Determine which kind of key we are using (existing or new)."""
    match v:
        case str():
            if v.startswith('NEW:'):
                return 'new'
        case OnionServiceNewKeyStruct():
            return 'new'
    return 'key'


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

    #: The service key, either provided directly of generated by Tor.
    key: Annotated[
        Union[  # noqa: UP007
            Annotated[OnionServiceKey, Tag('key')],
            Annotated[OnionServiceNewKey, Tag('new')],
        ],
        Discriminator(_onion_add_get_key_tag),
    ]

    #: Set of boolean options to attach to this service.
    flags: Annotated[set[OnionServiceFlags], TrBeforeStringSplit()] = field(
        default_factory=set
    )

    #: Optional number between 0 and 65535 which is the maximum streams that can be
    #: attached on a rendezvous circuit. Setting it to 0 means unlimited which is
    #: also the default behavior.
    max_streams: NonNegativeInt | None = None

    #: As in an arguments to config ``HiddenServicePort``, ``port,target``.
    ports: MutableSequence[VirtualPort] = field(default_factory=list)

    #: Client authentications for Onion V2, syntax is ``ClientName[:ClientBlob]``.
    client_auth: MutableSequence[HsDescClientAuthV2] = field(default_factory=list)

    #: String syntax is a base32-encoded ``x25519`` public key with only the key part.
    client_auth_v3: MutableSequence[HsDescClientAuthV3] = field(default_factory=list)

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``ADD_ONION`` specific arguments."""
        ports = struct['ports']
        if not len(ports):
            msg = 'You must specify one or more virtual ports.'
            raise CommandError(msg)

        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(struct['key']))

        flags = struct['flags']
        if len(flags):
            args.append(ArgumentKeyword('Flags', flags, quotes=QuoteStyle.NEVER))

        max_streams = struct['max_streams']
        if max_streams is not None:
            kwarg = ArgumentKeyword('MaxStreams', max_streams, quotes=QuoteStyle.NEVER)
            args.append(kwarg)

        for port in ports:
            args.append(ArgumentKeyword('Port', port, quotes=QuoteStyle.NEVER_ENSURE))

        for auth in struct['client_auth']:
            args.append(ArgumentKeyword('ClientAuth', auth, quotes=QuoteStyle.NEVER_ENSURE))

        for auth in struct['client_auth_v3']:
            args.append(ArgumentKeyword('ClientAuthV3', auth, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``DEL_ONION`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(struct['address']))
        ser.arguments.extend(args)
        return ser.serialize()


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
    servers: MutableSequence[LongServerName] = field(default_factory=list)
    #: This is the optional v2 or v3 address without the ``.onion`` suffix.
    address: HiddenServiceAddress | None = None
    #: Descriptor content as raw text.
    descriptor: str

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``HSPOST`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        for server in struct['servers']:
            args.append(ArgumentKeyword('SERVER', server, quotes=QuoteStyle.NEVER_ENSURE))

        address = struct['address']
        if address is not None:
            kwarg = ArgumentKeyword('HSADDRESS', address, quotes=QuoteStyle.NEVER_ENSURE)
            args.append(kwarg)

        ser.arguments.extend(args)
        ser.body = struct['descriptor']
        return ser.serialize()


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

    #: The private ``x25519`` key used to authenticate to :attr:`address`.
    key: OnionClientAuthKey

    #: An optional nickname for the client.
    nickname: str | None = None

    #: Whether this client's credentials should be stored on the file system.
    flags: Annotated[set[OnionClientAuthFlags], TrBeforeStringSplit()] = field(
        default_factory=set
    )

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``ONION_CLIENT_AUTH_ADD`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

        args.append(ArgumentString(struct['address']))
        args.append(ArgumentString(struct['key']))

        nickname = struct['nickname']
        if nickname is not None:
            kwarg = ArgumentKeyword('ClientName', nickname, quotes=QuoteStyle.NEVER_ENSURE)
            args.append(kwarg)

        flags = struct['flags']
        if len(flags):
            args.append(ArgumentKeyword('Flags', flags, quotes=QuoteStyle.NEVER))

        ser.arguments.extend(args)
        return ser.serialize()


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

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``ONION_CLIENT_AUTH_REMOVE`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        args.append(ArgumentString(struct['address']))
        ser.arguments.extend(args)
        return ser.serialize()


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
    address: HiddenServiceAddressV3 | None = None

    def serialize_from_struct(self, struct: Mapping[str, Any]) -> str:
        """Append ``ONION_CLIENT_AUTH_VIEW`` specific arguments."""
        ser = CommandSerializer(self.command)
        args = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]
        address = struct['address']
        if address is not None:
            args.append(ArgumentString(address))
        ser.arguments.extend(args)
        return ser.serialize()


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
