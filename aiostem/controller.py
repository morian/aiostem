from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Callable
from contextlib import AsyncExitStack, suppress
from typing import TYPE_CHECKING, Any, TypeAlias, cast, overload

from . import (
    event as e,
    reply as r,
)
from .connector import (
    DEFAULT_CONTROL_HOST,
    DEFAULT_CONTROL_PATH,
    DEFAULT_CONTROL_PORT,
    ControlConnector,
    ControlConnectorPath,
    ControlConnectorPort,
)
from .exceptions import CommandError, ControllerError
from .message import Message
from .protocol import (
    Command,
    CommandAuthChallenge,
    CommandAuthenticate,
    CommandDropGuards,
    CommandGetConf,
    CommandGetInfo,
    CommandHsFetch,
    CommandProtocolInfo,
    CommandQuit,
    CommandSetConf,
    CommandSetEvents,
    CommandSignal,
    EventWord,
    EventWordInternal,
    Signal,
)
from .util import hs_address_strip_tld

if TYPE_CHECKING:
    from collections.abc import (  # noqa: F401
        Iterable,
        Mapping,
        MutableMapping,
        Set as AbstractSet,
    )
    from types import TracebackType
    from typing import Self


_EVENTS_TOR = frozenset(EventWord)
_EVENTS_INTERNAL = frozenset(EventWordInternal)
EventCallbackType: TypeAlias = Callable[[e.Event], Any]
logger = logging.getLogger(__package__)


class Controller:
    """Client controller for Tor's control socket."""

    def __init__(self, connector: ControlConnector) -> None:
        """
        Initialize a new controller from a provided connector.

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
        self._protoinfo = None  # type: r.ProtocolInfoReply | None
        self._replies = None  # type: asyncio.Queue[Message | None] | None
        self._writer = None  # type: asyncio.StreamWriter | None

    async def __aenter__(self) -> Self:
        """
        Enter Controller's context, connect to the target.

        Raises:
            RuntimeError: when the context has already been entered

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

        Args:
            path: path to the unix socket on the local filesystem.

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
        except KeyError:
            msg = f"Unknown signal '{signal}'"
            raise CommandError(msg) from None

    async def _notify_disconnect(self) -> None:
        """
        Generate a `DISCONNECT` event.

        The goal here is to tell everyone that we are now disconnected from the remote socket.
        This is a fake event simply used to call all the registered callbacks and provide a
        way to gently tell the end user that we are no longer capable of handling anything.
        """
        message = Message('650 DISCONNECT')
        await self._on_event_received(message)

    async def _on_event_received(self, message: Message) -> None:
        """
        Handle a newly received event.

        This method finds and call the appropriate callbacks, if any.

        Args:
            message: the raw event message.

        """
        name = message.event_type
        if name is not None:  # pragma: no branch
            event = e.event_parser(message)

            for callback in self._evt_callbacks.get(name, []):
                # We do not care about exceptions in the event callback.
                try:
                    coro = callback(event)
                    if asyncio.iscoroutine(coro):
                        await coro
                except Exception:  # pragma: no cover
                    logger.exception("Error handling callback for '%s'", name)

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
            message = Message()

            while line := await reader.readline():
                message.add_line(line.decode('ascii'))
                if message.parsed:
                    if message.is_event:
                        await self._on_event_received(message)
                    else:
                        await replies.put(message)

                    message = Message()
        finally:
            self._connected = False
            # This is needed here because we may be stuck waiting on a reply.
            with suppress(asyncio.QueueFull):
                replies.put_nowait(None)
            await self._notify_disconnect()

    async def _request(self, command: Command) -> Message:
        """
        Send any kind of command to the controller.

        Note:
            A single command can run at once due to an internal lock.

        Args:
            command: the command we want to send to Tor.

        Raises:
            ControllerError: when the controller is not connected.

        Returns:
            The corresponding reply from the remote daemon.

        """
        async with self._request_lock:
            # if self._replies is None or self._writer is None:
            if not self.connected:
                msg = 'Controller is not connected!'
                raise ControllerError(msg)

            # Casts are valid here since we check `self.connected`.
            replies = cast(asyncio.Queue[Message | None], self._replies)
            writer = cast(asyncio.StreamWriter, self._writer)

            query = command.serialize()
            writer.write(query.encode('ascii'))
            await writer.drain()

            resp = await replies.get()
            replies.task_done()

        if resp is None:  # pragma: no cover
            msg = 'Controller has disconnected!'
            raise ControllerError(msg)
        return resp

    async def auth_challenge(self, nonce: bytes | str | None = None) -> r.AuthChallengeReply:
        """
        Start the authentication routine for the `SAFECOOKIE` method.

        Note:
            This method is not meant to be called by the end-user but is rather
            used internally by :meth:`authenticate`.

        Args:
            nonce: an optional 32 bytes hexadecimal random value.

        Returns:
            A :class:`AuthChallengeReply` object.

        """
        if nonce is None:
            nonce = secrets.token_bytes(CommandAuthChallenge.NONCE_LENGTH)
        command = CommandAuthChallenge(nonce=nonce)
        return await self.request(command)

    async def authenticate(self, password: str | None = None) -> r.AuthenticateReply:
        """
        Authenticate to Tor's controller.

        Note:
            Authentication methods are tries in the following order (when available):
                - `NULL`: no authentication
                - `HASHEDPASSWORD`: password authentication (when a password is provided)
                - `SAFECOOKIE`: proof that we can read the cookie file
                - `COOKIE`: provide the content of the cookie file

        Args:
            password: an optional password for the `HASHEDPASSWORD` method.

        Raises:
            ControllerError: when no authentication method is found.

        Returns:
            The authentication result.

        """
        protoinfo = await self.protocol_info()
        methods = set(protoinfo.methods)

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
            cookie = await protoinfo.cookie_file_read()
            if cookie is not None:
                challenge = await self.auth_challenge()
                challenge.raise_for_server_hash_error(cookie)
                token = challenge.client_token_build(cookie)
        elif 'COOKIE' in methods:
            token = await protoinfo.cookie_file_read()
        else:
            msg = 'No compatible authentication method found!'
            raise ControllerError(msg)

        command = CommandAuthenticate(token=token)
        reply = await self.request(command)
        self._authenticated = bool(reply.status == 250)
        return reply

    async def drop_guards(self) -> r.DropGuardsReply:
        """
        Tell the server to drop all guard nodes.

        Important:
            Do not invoke this command lightly; it can increase vulnerability
            to tracking attacks over time.

        Returns:
            The simple response.

        """
        command = CommandDropGuards()
        return await self.request(command)

    async def add_event_handler(
        self,
        event: EventWord | EventWordInternal | str,
        callback: EventCallbackType,
    ) -> None:
        """
        Register a callback function to be called when an event message is received.

        A special event `DISCONNECT` is produced by this library and can be registered
        here to be notified of any disconnection from the control socket.

        Note:
            Multiple callbacks can be set for a single event.
            If so, they are called in the registering order.

        See Also:
            https://spec.torproject.org/control-spec/replies.html#asynchronous-events

        Args:
            event: name of the event linked to the callback.
            callback: a function or coroutine to be called when the event occurs.

        Raises:
            CommandError: when the event name does not exit.

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
                    await self.set_events(events)
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
            event: name of the event linked to the callback.
            callback: a function or coroutine to be removed from the event list.

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

    async def get_conf(self, *args: str) -> r.GetConfReply:
        """
        Request the value of zero or move configuration variable(s).

        See Also:
            https://spec.torproject.org/control-spec/commands.html#getconf

        Args:
            args: a list of configuration variables to request.

        Returns:
            A reply containing the corresponding values.

        """
        command = CommandGetConf(keywords=[*args])
        return await self.request(command)

    async def get_info(self, *args: str) -> r.GetInfoReply:
        """
        Request for Tor daemon information.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#getinfo

        Args:
            args: a list of information data to request.

        Returns:
            A reply containing the corresponding values.

        """
        command = CommandGetInfo(keywords=[*args])
        return await self.request(command)

    async def protocol_info(self, version: int | None = None) -> r.ProtocolInfoReply:
        """
        Get control protocol information from the remote Tor process.

        This command is performed as part of the authentication process in order to get
        all supported authentication methods.

        Note:
            The command result is cached when not authenticated since we can only send
            this command once in this situation.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#protocolinfo

        Args:
            version: protocol version to ask for, should be 1.

        Returns:
            A completed reply from Tor.

        """
        if self.authenticated or not self._protoinfo:
            command = CommandProtocolInfo(version=version)
            self._protoinfo = await self.request(command)
        return self._protoinfo

    async def hs_fetch(
        self,
        address: str,
        servers: Iterable[str] | None = None,
    ) -> r.HsFetchReply:
        """
        Request a hidden service descriptor fetch.

        The result does not contain the descriptor, which is provided asynchronously
        through events such as `HS_DESC` and `HS_DESC_CONTENT`.

        Args:
            address: the hidden service address to request.
            servers: an optional list of servers to query.

        Returns:
            Whether the request was sent successfully.

        """
        address = hs_address_strip_tld(address.lower())
        command = CommandHsFetch(address=address)
        if servers is not None:
            command.servers.extend(servers)
        return await self.request(command)

    @overload
    async def request(self, command: CommandAuthenticate) -> r.AuthenticateReply: ...

    @overload
    async def request(self, command: CommandAuthChallenge) -> r.AuthChallengeReply: ...

    @overload
    async def request(self, command: CommandDropGuards) -> r.DropGuardsReply: ...

    @overload
    async def request(self, command: CommandGetConf) -> r.GetConfReply: ...

    @overload
    async def request(self, command: CommandGetInfo) -> r.GetInfoReply: ...

    @overload
    async def request(self, command: CommandHsFetch) -> r.HsFetchReply: ...

    @overload
    async def request(self, command: CommandProtocolInfo) -> r.ProtocolInfoReply: ...

    @overload
    async def request(self, command: CommandQuit) -> r.QuitReply: ...

    @overload
    async def request(self, command: CommandSetConf) -> r.SetConfReply: ...

    @overload
    async def request(self, command: CommandSetEvents) -> r.SetEventsReply: ...

    @overload
    async def request(self, command: CommandSignal) -> r.SignalReply: ...

    async def request(self, command: Command) -> r.Reply:
        """
        Send a provided command to the controller.

        The command is first serialized, sent to the controller and we get back
        a raw message that is then transformed into the appropriate reply.

        For typing purposes, this method is overloaded with all the available
        commands and returning their corresponding responses.

        Args:
            command: the command to send to Tor.

        Returns:
            The corresponding reply.

        """
        message = await self._request(command)
        return r.reply_parser(command, message)

    async def set_conf(self, items: Mapping[str, Any]) -> r.SetConfReply:
        """
        Change configuration entries on the remote server.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#setconf

        Args:
            items: a map of new configuration entries to apply.

        Returns:
            A simple response that tells if everything went well.

        """
        command = CommandSetConf()
        command.values.update(items)
        return await self.request(command)

    async def set_events(
        self,
        events: AbstractSet[EventWord],
        *,
        extended: bool = False,
    ) -> r.SetEventsReply:
        """
        Set the list of events that we subscribe to.

        Important:
            This method should not probably be called by the end-user.
            Please see :meth:`add_event_handler` instead.

        Args:
            events: a list of events to subscribe to.

        Keyword Args:
            extended: Tor may provide extra information with events for this connection.

        Returns:
            A simple response.

        """
        command = CommandSetEvents(extended=extended)
        command.events.update(events)
        return await self.request(command)

    async def signal(self, signal: Signal | str) -> r.SignalReply:
        """
        Send a signal to the controller.

        See Also:
            https://spec.torproject.org/control-spec/commands.html#signal

        Args:
            signal: name of the signal to send.

        Returns:
            A simple response.

        """
        if not isinstance(signal, Signal):
            signal = self._str_signal_to_enum(signal)

        command = CommandSignal(signal=signal)
        return await self.request(command)

    async def quit(self) -> r.QuitReply:
        """
        Tells the server to hang up on this controller connection.

        Returns:
            A simple response.

        """
        return await self.request(CommandQuit())
