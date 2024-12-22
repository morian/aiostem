from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, MutableSequence
from contextlib import AsyncExitStack, suppress
from typing import TYPE_CHECKING, TypeAlias, cast

from pydantic import RootModel

from .command import (
    Command,
    CommandAuthChallenge,
    CommandAuthenticate,
    CommandDropGuards,
    CommandDropOwnership,
    CommandDropTimeouts,
    CommandGetConf,
    CommandGetInfo,
    CommandHsFetch,
    CommandLoadConf,
    CommandMapAddress,
    CommandProtocolInfo,
    CommandQuit,
    CommandResetConf,
    CommandResolve,
    CommandSaveConf,
    CommandSetConf,
    CommandSetEvents,
    CommandSignal,
    CommandTakeOwnership,
)
from .connector import (
    DEFAULT_CONTROL_HOST,
    DEFAULT_CONTROL_PATH,
    DEFAULT_CONTROL_PORT,
    ControlConnector,
    ControlConnectorPath,
    ControlConnectorPort,
)
from .event import Event, EventWord, EventWordInternal, event_from_message
from .exceptions import CommandError, ControllerError
from .reply import (
    ReplyAuthChallenge,
    ReplyAuthenticate,
    ReplyDropGuards,
    ReplyDropOwnership,
    ReplyDropTimeouts,
    ReplyGetConf,
    ReplyGetInfo,
    ReplyHsFetch,
    ReplyLoadConf,
    ReplyMapAddress,
    ReplyProtocolInfo,
    ReplyQuit,
    ReplyResetConf,
    ReplyResolve,
    ReplySaveConf,
    ReplySetConf,
    ReplySetEvents,
    ReplySignal,
    ReplyTakeOwnership,
)
from .structures import HiddenServiceAddress, LongServerName, Signal
from .utils import Message, messages_from_stream

if TYPE_CHECKING:
    from collections.abc import (  # noqa: F401
        Iterable,
        Mapping,
        MutableMapping,
        Set as AbstractSet,
    )
    from types import TracebackType
    from typing import Self

    from .types import AnyHost


_EVENTS_TOR = frozenset(EventWord)
_EVENTS_INTERNAL = frozenset(EventWordInternal)
logger = logging.getLogger(__package__)

#: Alias for event callbacks registered with :meth:`Controller.add_event_handler`.
EventCallbackType: TypeAlias = Callable[[Event], Awaitable[None] | None]


class Controller:
    """Client controller for Tor's control socket."""

    def __init__(self, connector: ControlConnector) -> None:
        """
        Initialize a new controller from a provided :class:`.ControlConnector`.

        Notes:
            You may want to alternatively use one of the following methods:
                - :meth:`Controller.from_path`
                - :meth:`Controller.from_port`

        Args:
            connector: the connector to the control socket.

        """
        self._evt_callbacks = {}  # type: MutableMapping[str, list[EventCallbackType]]
        self._events_lock = asyncio.Lock()
        self._request_lock = asyncio.Lock()
        self._authenticated = False
        self._context = None  # type: AsyncExitStack | None
        self._connected = False
        self._connector = connector
        self._protoinfo = None  # type: ReplyProtocolInfo | None
        self._replies = None  # type: asyncio.Queue[Message | None] | None
        self._writer = None  # type: asyncio.StreamWriter | None

    async def __aenter__(self) -> Self:
        """
        Enter Controller's context, connect to the target.

        Raises:
            RuntimeError: when the context has already been entered.

        Returns:
            A connected controller (the same exact instance).

        """
        if self.entered:
            msg = 'Controller is already entered!'
            raise RuntimeError(msg)

        context = await AsyncExitStack().__aenter__()
        try:
            reader, writer = await self._connector.connect()
            context.push_async_callback(writer.wait_closed)
            context.callback(writer.close)

            replies = asyncio.Queue()  # type: asyncio.Queue[Message | None]
            rdtask = asyncio.create_task(
                self._reader_task(reader, replies),
                name='aiostem.controller.reader',
            )

            async def cancel_reader(task: asyncio.Task[None]) -> None:
                task.cancel('Controller is closing')
                await asyncio.gather(task, return_exceptions=True)

            context.push_async_callback(cancel_reader, rdtask)
        except BaseException:
            await context.aclose()
            raise
        else:
            self._context = context
            self._connected = True
            self._replies = replies
            self._writer = writer
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """
        Exit the controller's context and close the underlying socket.

        Returns:
            :obj:`False` to let any exception flow through the call stack.

        """
        context = self._context
        try:
            if context is not None:
                # Can arise while closing an underlying UNIX socket
                with suppress(BrokenPipeError):
                    await context.__aexit__(exc_type, exc_val, exc_tb)
        finally:
            self._authenticated = False
            self._connected = False
            self._context = None
            self._evt_callbacks.clear()
            self._protoinfo = None
            self._replies = None
            self._writer = None

        # Do not prevent the original exception from going further.
        return False

    @classmethod
    def from_port(
        cls,
        host: str = DEFAULT_CONTROL_HOST,
        port: int = DEFAULT_CONTROL_PORT,
    ) -> Controller:
        """
        Create a new controller for a remote TCP host/port.

        USE EXAMPLE::

            async with Controller.from_port('10.0.0.1', 9051) as controller:
                await controller.authenticate('password')
                ...

        Args:
            host: ip address or hostname to the control host.
            port: TCP port to connect to.

        Returns:
            A controller for the target TCP host and port.

        """
        return cls(ControlConnectorPort(host, port))

    @classmethod
    def from_path(cls, path: str = DEFAULT_CONTROL_PATH) -> Controller:
        """
        Create a new controller for a local unix socket.

        USE EXAMPLE::

            async with Controller.from_path('/run/tor/control.sock') as controller:
                await controller.authenticate()
                ...

        Args:
            path: path to the unix socket on the filesystem.

        Returns:
            A controller for the target unix socket.

        """
        return cls(ControlConnectorPath(path))

    @property
    def authenticated(self) -> bool:
        """Tell whether we are correctly authenticated."""
        return bool(self.connected and self._authenticated)

    @property
    def connected(self) -> bool:
        """Tell whether we are connected to the remote socket."""
        return bool(self._connected and self._writer is not None and self._replies is not None)

    @property
    def entered(self) -> bool:
        """Tell whether the context manager is entered."""
        return bool(self._context is not None)

    @staticmethod
    def _str_event_to_enum(event: str) -> EventWord | EventWordInternal:
        """
        Convert a textual event name to its enum equivalent.

        Args:
            event: a textual representation of the event.

        Raises:
            CommandError: when the event name does not exit.

        Returns:
            The corresponding enum event.

        """
        event = event.upper()
        if event in _EVENTS_TOR:
            return EventWord(event)
        if event in _EVENTS_INTERNAL:
            return EventWordInternal(event)
        msg = f"Unknown event '{event}'"
        raise CommandError(msg)

    @staticmethod
    def _str_signal_to_enum(signal: str) -> Signal:
        """
        Convert a textual signal name to its enum equivalent.

        Args:
            signal: a textual representation of the signal.

        Raises:
            CommandError: when the signal name does not exit.

        Returns:
            The corresponding enum signal.

        """
        try:
            return Signal(signal)
        except ValueError:
            msg = f"Unknown signal '{signal}'"
            raise CommandError(msg) from None

    async def _notify_disconnect(self) -> None:
        """
        Generate a `DISCONNECT` event.

        The goal here is to tell everyone that we are now disconnected from the remote socket.
        This is a fake event simply used to call all the registered callbacks and provide a
        way to gently tell the end user that we are no longer capable of handling anything.
        """
        await self._on_event_received(Message(status=650, header='DISCONNECT'))

    async def _on_event_received(self, message: Message) -> None:
        """
        Handle a newly received event.

        This method finds and call the appropriate callbacks, if any.

        Args:
            message: the raw event message.

        """
        try:
            event = event_from_message(message)
        except Exception:
            logger.exception('Unable to handle a received event.')
        else:
            keyword = message.keyword
            for callback in self._evt_callbacks.get(keyword, []):
                # We do not care about exceptions in the event callback.
                try:
                    coro = callback(event)
                    if asyncio.iscoroutine(coro):
                        await coro
                except Exception:
                    logger.exception("Error while handling callback for '%s'", keyword)

    async def _reader_task(
        self,
        reader: asyncio.StreamReader,
        replies: asyncio.Queue[Message | None],
    ) -> None:
        """
        Read messages from the control socket and dispatch them.

        Args:
            reader: raw StreamReader from :mod:`asyncio`.
            replies: the queue of command replies.

        """
        try:
            async for message in messages_from_stream(reader):
                if message.is_event:
                    await self._on_event_received(message)
                else:
                    await replies.put(message)
        finally:
            self._connected = False
            # This is needed here because we may be stuck waiting on a reply.
            with suppress(asyncio.QueueFull):
                replies.put_nowait(None)
            await self._notify_disconnect()

    async def add_event_handler(
        self,
        event: EventWord | EventWordInternal | str,
        callback: EventCallbackType,
    ) -> None:
        """
        Register a callback function to be called when an event message is received.

        Notes:
            - A special event :attr:`~.event.EventWordInternal.DISCONNECT` is handled
              internally by this library and can be registered here to be notified of any
              disconnection from the control socket.
            - Multiple callbacks can be set for a single event.
              If so, they are called in the order they were registered.

        USE EXAMPLE::

            def client_status_callback(event: EventStatusClient):
                print(event)

            async with Controller.from_path('/run/tor/control.sock') as controller:
                await controller.authenticate()
                await controller.add_event_handler('STATUS_CLIENT', client_status_callback)
                ...

        See Also:
            https://spec.torproject.org/control-spec/replies.html#asynchronous-events

        Args:
            event: Name of the event linked to the callback.
            callback: A function or coroutine to be called when the event occurs.

        Raises:
            CommandError: When the event name does not exit.
            ReplyStatusError: When the event could not be registered.

        """
        if not isinstance(event, EventWord | EventWordInternal):
            event = self._str_event_to_enum(event)

        async with self._events_lock:
            listeners = self._evt_callbacks.setdefault(event.value, [])
            try:
                # Tell Tor that we are now interested in this event.
                if not len(listeners) and isinstance(event, EventWord):
                    keys = frozenset(self._evt_callbacks.keys())
                    reals = keys.difference(EventWordInternal)
                    events = frozenset(map(EventWord, reals))

                    reply = await self.set_events(events)
                    reply.raise_for_status()
            except BaseException:
                if not len(listeners):  # pragma: no branch
                    self._evt_callbacks.pop(event)
                raise
            else:
                listeners.append(callback)

    async def del_event_handler(
        self,
        event: EventWord | EventWordInternal | str,
        callback: EventCallbackType,
    ) -> None:
        """
        Unregister a previously registered callback function.

        Args:
            event: Name of the event linked to the callback.
            callback: A function or coroutine to be removed from the event list.

        """
        if not isinstance(event, EventWord | EventWordInternal):
            event = self._str_event_to_enum(event)

        async with self._events_lock:
            listeners = self._evt_callbacks.get(event, [])
            if callback in listeners:
                backup_listeners = listeners.copy()
                listeners.remove(callback)
                try:
                    if not len(listeners):
                        self._evt_callbacks.pop(event.value)
                        if isinstance(event, EventWord):
                            keys = frozenset(self._evt_callbacks.keys())
                            reals = keys.difference(EventWordInternal)
                            events = frozenset(map(EventWord, reals))
                            await self.set_events(events)
                except BaseException:
                    # Restore the original callbacks on error.
                    self._evt_callbacks[event.value] = backup_listeners
                    raise

    async def request(self, command: Command) -> Message:
        """
        Send any kind of command to the controller.

        This method is the underlying call of any other command.

        It can be used to send custom subclass of :class:`.Command`, and get the
        raw :class:`.Message` corresponding to the response. This :class:`.Message`
        can then be parsed by an appropriate :class:`.Reply`.

        Important:
            A single command can run at any time due to an internal lock.

        Args:
            command: The command we want to send to Tor.

        Raises:
            ControllerError: When the controller is not connected.

        Returns:
            The corresponding reply message from the remote daemon.

        """
        async with self._request_lock:
            # if self._replies is None or self._writer is None:
            if not self.connected:
                msg = 'Controller is not connected!'
                raise ControllerError(msg)

            # Casts are valid here since we check `self.connected`.
            replies = cast(asyncio.Queue[Message | None], self._replies)
            writer = cast(asyncio.StreamWriter, self._writer)

            frame = command.serialize()
            writer.write(frame.encode('ascii'))
            await writer.drain()

        resp = await replies.get()
        replies.task_done()

        # This is very hard to test here, let's not cover these few lines.
        if resp is None:  # pragma: no cover
            msg = 'Controller has disconnected!'
            raise ControllerError(msg)
        return resp

    async def auth_challenge(self, nonce: bytes | str | None = None) -> ReplyAuthChallenge:
        """
        Start the authentication for :attr:`~.structures.AuthMethod.SAFECOOKIE`.

        When no ``nonce`` is provided, once is generated and provided back in the reply.
        While this is obviously not part of the original reply from the server, it is
        added to the reply structure for convenience.

        Warning:
            This method is not meant to be called by the end-user but is rather
            used internally by :meth:`authenticate`.

        Note:
            This command can be sent while not authenticated (but only once).

        Args:
            nonce: 32 random bytes (optional).

        Returns:
            An authentication challenge reply.

        """
        command = CommandAuthChallenge(nonce=nonce)
        message = await self.request(command)
        reply = ReplyAuthChallenge.from_message(message)
        if reply.data is not None:
            reply.data.client_nonce = command.nonce
        return reply

    async def authenticate(self, password: str | None = None) -> ReplyAuthenticate:
        """
        Authenticate to Tor's controller.

        Note:
            Available authentications are provided by :meth:`protocol_info`.

        Important:
            Authentication methods are tried in the following order (when available):
                - ``NULL``: authentication is automatically granted
                - ``HASHEDPASSWORD``: password authentication (when a password is provided)
                - ``SAFECOOKIE``: proof that we can read the cookie file
                - ``COOKIE``: provide the content of the cookie file

        See Also:
            :class:`.structures.AuthMethod`

        Args:
            password: Optional password for method
                :attr:`~.structures.AuthMethod.HASHEDPASSWORD`.

        Raises:
            ControllerError: When no known authentication method was found.

        Returns:
            The authentication reply (you should check the status here).

        """
        protoinfo = await self.protocol_info()
        protoinfo.raise_for_status()

        methods = set()  # type: set[str]
        if protoinfo.data is not None:  # pragma: no branch
            methods.update(protoinfo.data.auth_methods)

        # No password was provided, we can't authenticate with this method.
        if password is None:
            methods.discard('HASHEDPASSWORD')

        # Here we suppose that the user prefers a password authentication when
        # a password is provided (the cookie file may not be readable).
        if 'NULL' in methods:
            token = None  # type: bytes | None
        elif 'HASHEDPASSWORD' in methods:
            token = password.encode()  # type: ignore[union-attr]
        elif 'SAFECOOKIE' in methods:
            cookie = await protoinfo.read_cookie_file()
            challenge = await self.auth_challenge()
            challenge.raise_for_server_hash_error(cookie)
            token = challenge.build_client_hash(cookie)
        elif 'COOKIE' in methods:
            token = await protoinfo.read_cookie_file()
        else:
            msg = 'No compatible authentication method found!'
            raise ControllerError(msg)

        command = CommandAuthenticate(token=token)
        message = await self.request(command)
        reply = ReplyAuthenticate.from_message(message)
        self._authenticated = reply.is_success
        return reply

    async def drop_guards(self) -> ReplyDropGuards:
        """
        Tell the server to drop all guard nodes.

        Warning:
            Do not invoke this command lightly; it can increase vulnerability
            to tracking attacks over time.

        Returns:
            A simple drop-guards reply where only the status is relevant.

        """
        command = CommandDropGuards()
        message = await self.request(command)
        return ReplyDropGuards.from_message(message)

    async def drop_ownership(self) -> ReplyDropOwnership:
        """
        Relinquish ownership of this control connection.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#dropownership

        Hint:
            This ownership can be taken using :meth:`take_ownership`.

        Returns:
            A simple drop-ownership reply where only the status is relevant.

        """
        command = CommandDropOwnership()
        message = await self.request(command)
        return ReplyDropOwnership.from_message(message)

    async def drop_timeouts(self) -> ReplyDropTimeouts:
        """
        Tells the server to drop all circuit build times.

        Warning:
            Do not invoke this command lightly; it can increase vulnerability
            to tracking attacks over time.

        Note:
            Tor also emits the ``BUILDTIMEOUT_SET RESET`` event rigth after the reply.

        Returns:
            A simple drop-timeouts reply where only the status is relevant.

        """
        command = CommandDropTimeouts()
        message = await self.request(command)
        return ReplyDropTimeouts.from_message(message)

    async def get_conf(self, *args: str) -> ReplyGetConf:
        """
        Request the value of zero or move configuration variable(s).

        Note that you can request the same key multiple times, and some configuration
        entries can provide multiple values. When any of this happens, the result
        dictionary provides a :class:`~typing.Sequence` of strings as its value.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#getconf

        Args:
            args: A list of configuration variables to request.

        Returns:
            A reply containing the corresponding values (when successful).

        """
        command = CommandGetConf(keywords=[*args])
        message = await self.request(command)
        return ReplyGetConf.from_message(message)

    async def get_info(self, *args: str) -> ReplyGetInfo:
        """
        Request for Tor daemon information.

        Note that you can request the same key multiple times. When this happens, the result
        dictionary provides a :class:`~typing.Sequence` of strings as its value.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#getinfo

        Args:
            args: A list of information data to request.

        Returns:
            A reply containing the corresponding values (when successful).

        """
        command = CommandGetInfo(keywords=[*args])
        message = await self.request(command)
        return ReplyGetInfo.from_message(message)

    async def hs_fetch(
        self,
        address: HiddenServiceAddress | str,
        servers: Iterable[LongServerName | str] | None = None,
    ) -> ReplyHsFetch:
        """
        Request a hidden service descriptor fetch.

        The result does not contain the descriptor, which is provided asynchronously through
        events such as :attr:`~.EventWord.HS_DESC` or :attr:`~.EventWord.HS_DESC_CONTENT`.

        Args:
            address: The hidden service address to request.
            servers: An optional list of servers to query.

        Returns:
            A simple hsfetch reply where only the status is relevant.

        """
        # See https://github.com/pydantic/pydantic/discussions/7094#discussioncomment-8486007
        addr = RootModel[HiddenServiceAddress].model_validate(address).root
        command = CommandHsFetch(address=addr)
        if servers is not None:
            for server in servers:
                if isinstance(server, str):
                    server = LongServerName.from_string(server)
                command.servers.append(server)
        message = await self.request(command)
        return ReplyHsFetch.from_message(message)

    async def load_conf(self, text: str) -> ReplyLoadConf:
        """
        Upload and replace the content of a config file.

        This command allows a controller to upload the text of a config file to Tor over
        the control port. This config file is then loaded as if it had been read from disk.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#loadconf

        Returns:
            A simple reply with only a status.

        """
        command = CommandLoadConf(text=text)
        message = await self.request(command)
        return ReplyLoadConf.from_message(message)

    async def map_address(self, addresses: Mapping[AnyHost, AnyHost]) -> ReplyMapAddress:
        """
        Map provided addresses with their replacement.

        The client tells the server that future SOCKS requests for connections to any
        original address provided here should be replaced with a connection to the
        specificed replacement address.

        The client may decline to provide a replacement address and instead provide
        a special address. This means that the server should choose the original
        address itself.

        - For IPv4: ``0.0.0.0``
        - For IPv6: ``::0``
        - For hostname: ``.``

        Mapping values can be read using :meth:`get_info` with ``address-mappings/control``.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#mapaddress

        Args:
            addresses: A map of addresses to remap on socks requests.

        Returns:
            A list of individual replies for each map request.

            Note that some values can be rejected and others can be accepted, which means
            that you should check each individual value.

        """
        command = CommandMapAddress()
        command.addresses.update(addresses)
        message = await self.request(command)
        return ReplyMapAddress.from_message(message)

    async def protocol_info(self, version: int | None = None) -> ReplyProtocolInfo:
        """
        Get control protocol information from Tor.

        This command is performed as part of the authentication process in order to find out
        all supported authentication methods (see :class:`~.structures.AuthMethod`).

        The ``version`` is supposed to set to ``1`` but Tor currently does not care.

        Note:
            The command result is cached when unauthenticated as we can only send this
            command once in this situation.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#protocolinfo

        Args:
            version: Protocol version to ask for when provided.

        Returns:
            A completed protocol info reply from Tor.

        """
        if self.authenticated or self._protoinfo is None:
            command = CommandProtocolInfo(version=version)
            message = await self.request(command)
            self._protoinfo = ReplyProtocolInfo.from_message(message)
        return self._protoinfo

    async def reset_conf(
        self,
        items: Mapping[str, MutableSequence[int | str] | int | str | None],
    ) -> ReplyResetConf:
        """
        Change or reset configuration entries on the remote server.

        Notes:
            - When :obj:`None` is provided, all values are reset to their default.
            - When :class:`list`, multiple values are assigned.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#resetconf

        Args:
            items: a map of configuration entries to apply or reset.

        Returns:
            A simple resetconf reply where only the status is relevant.

        """
        command = CommandResetConf()
        command.values.update(items)
        message = await self.request(command)
        return ReplyResetConf.from_message(message)

    async def resolve(
        self,
        addresses: Iterable[AnyHost],
        *,
        reverse: bool = False,
    ) -> ReplyResolve:
        """
        Launch a remote hostname lookup request for every specified request.

        Note:
            The result is not provided along with the reply here but can be caught
            using the :attr:`~.EventWord.ADDRMAP`.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#resolve

        Args:
            addresses: List of addresses to launch a resolve request for.

        Keyword Arguments:
            reverse: Whether to perform a reverse DNS lookup.

        Returns:
            A simple resolve reply where only the status is relevant.

        """
        command = CommandResolve(reverse=reverse)
        command.addresses.extend(addresses)
        message = await self.request(command)
        return ReplyResolve.from_message(message)

    async def save_conf(self, *, force: bool = False) -> ReplySaveConf:
        """
        Instructs the server to write out its configuration options into ``torrc``.

        If ``%include`` is used on ``torrc``, ``SAVECONF`` will not write the configuration
        to disk.  When set, the configuration will be overwritten even if %include is used.
        You can find out whether this flag is needed using ``config-can-saveconf`` on
        :class:`.CommandGetInfo`.

        Keyword Arguments:
            force: force write the configuration to disk.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#saveconf

        Returns:
            A simple reply with only a status.

        """
        command = CommandSaveConf(force=force)
        message = await self.request(command)
        return ReplySaveConf.from_message(message)

    async def set_conf(
        self,
        items: Mapping[str, MutableSequence[int | str] | int | str | None],
    ) -> ReplySetConf:
        """
        Change configuration entries on the remote server.

        Notes:
            - When :obj:`None` is provided, all values are removed.
            - When :class:`list`, multiple values are assigned.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#setconf

        Args:
            items: a map of new configuration entries to apply or clear.

        Returns:
            A simple setconf reply where only the status is relevant.

        """
        command = CommandSetConf()
        command.values.update(items)
        message = await self.request(command)
        return ReplySetConf.from_message(message)

    async def set_events(self, events: AbstractSet[EventWord]) -> ReplySetEvents:
        """
        Set the list of events that we subscribe to.

        Warning:
            This method should not probably be called by the end-user.
            Please see :meth:`add_event_handler` instead.

        Args:
            events: a set of events to subscribe to.

        Returns:
            A simple setevents reply where only the status is relevant.

        """
        command = CommandSetEvents()
        command.events.update(events)
        message = await self.request(command)
        return ReplySetEvents.from_message(message)

    async def signal(self, signal: Signal | str) -> ReplySignal:
        """
        Send a signal to the controller.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#signal

        Args:
            signal: name of the signal to send.

        Returns:
            A simple signal reply where only the status is relevant.

        """
        if not isinstance(signal, Signal):
            signal = self._str_signal_to_enum(signal)

        command = CommandSignal(signal=signal)
        message = await self.request(command)
        return ReplySignal.from_message(message)

    async def take_ownership(self) -> ReplyTakeOwnership:
        """
        Instructs Tor to shut down when this control connection is closed.

        Hint:
            This ownership can be dropped with :meth:`drop_ownership`.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#takeownership

        Returns:
            A simple take-ownership reply where only the status is relevant.

        """
        command = CommandTakeOwnership()
        message = await self.request(command)
        return ReplyTakeOwnership.from_message(message)

    async def quit(self) -> ReplyQuit:
        """
        Tells the server to hang up on this controller connection.

        Returns:
            A simple quit reply where only the status is relevant.

        """
        message = await self.request(CommandQuit())
        return ReplyQuit.from_message(message)
