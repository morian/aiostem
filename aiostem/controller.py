from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterable
from contextlib import AsyncExitStack, suppress
from typing import TYPE_CHECKING, Any, TypeAlias, cast, overload

from . import (
    event as e,
    query as q,
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
from .exception import AiostemError, ControllerError
from .message import Message
from .util import hs_address_strip_tld

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Self

    from .command import Command


DEFAULT_PROTOCOL_VERSION = q.ProtocolInfoQuery.DEFAULT_PROTOCOL_VERSION
EventCallbackType: TypeAlias = Callable[[e.Event], Any]
logger = logging.getLogger(__package__)


class Controller:
    """Client controller for Tor's control socket."""

    def __init__(self, connector: ControlConnector) -> None:
        """Initialize a new controller from a provided connector."""
        self._evt_callbacks = {}  # type: dict[str, list[EventCallbackType]]
        self._events_lock = asyncio.Lock()
        self._request_lock = asyncio.Lock()
        self._authenticated = False
        self._context = None  # type: AsyncExitStack | None
        self._connected = False
        self._connector = connector
        self._protoinfo = None  # type: r.ProtocolInfoReply | None
        self._rqueue = None  # type: asyncio.Queue[Message | None] | None
        self._rdtask = None  # type: asyncio.Task[None] | None
        self._writer = None  # type: asyncio.StreamWriter | None

    @classmethod
    def from_port(
        cls,
        host: str = DEFAULT_CONTROL_HOST,
        port: int = DEFAULT_CONTROL_PORT,
    ) -> Controller:
        """Create a new Controller from a TCP port."""
        return cls(ControlConnectorPort(host, port))

    @classmethod
    def from_path(cls, path: str = DEFAULT_CONTROL_PATH) -> Controller:
        """Create a new Controller from a UNIX socket path."""
        return cls(ControlConnectorPath(path))

    @property
    def authenticated(self) -> bool:
        """Tell whether we are correctly authenticated."""
        return bool(self.connected and self._authenticated)

    @property
    def connected(self) -> bool:
        """Tell whether we are connected to the remote socket."""
        return bool(self._connected and self._writer is not None and self._rqueue is not None)

    @property
    def entered(self) -> bool:
        """Tell whether the context manager is entered."""
        return bool(self._context is not None)

    async def __aenter__(self) -> Self:
        """Enter Controller's context, connect to the target."""
        if self.entered:
            raise RuntimeError('Controller is already entered!')

        context = await AsyncExitStack().__aenter__()
        try:
            reader, writer = await self._connector.connect()
            context.push_async_callback(writer.wait_closed)
            context.callback(writer.close)

            rqueue = asyncio.Queue()  # type: asyncio.Queue[Message | None]
            rdtask = asyncio.create_task(
                self._reader_task(reader, rqueue),
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
            self._rqueue = rqueue
            self._rdtask = rdtask
            self._writer = writer
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """Exit Controller's context."""
        context = self._context
        try:
            if context is not None:
                # Can arise while closing an underlying UNIX socket
                with suppress(BrokenPipeError):
                    await context.__aexit__(exc_type, exc_val, exc_tb)
        finally:
            self._evt_callbacks.clear()
            self._authenticated = False
            self._connected = False
            self._protoinfo = None
            self._rdtask = None
            self._rqueue = None
            self._writer = None
            self._context = None

        # Do not prevent the original exception from going further.
        return False

    async def _handle_event(self, message: Message) -> None:
        """Handle the new received event (find and call the callbacks)."""
        name = message.event_type
        if name is not None:  # pragma: no branch
            event = e.event_parser(message)

            for callback in self._evt_callbacks.get(name, []):
                # We do not care about exceptions in the event callback.
                try:
                    coro = callback(event)
                    if asyncio.iscoroutine(coro):
                        await coro
                except Exception as exc:  # pragma: no cover
                    logger.error("Error handling callback for '%s': %s", name, str(exc))

    async def _notify_disconnect(self) -> None:
        """Generate a DISCONNECT event to tell everyone that we are now disconnected."""
        await self._handle_event(Message('650 DISCONNECT'))

    async def _reader_task(
        self,
        reader: asyncio.StreamReader,
        rqueue: asyncio.Queue[Message | None],
    ) -> None:
        """Read from the socket and dispatch all contents."""
        try:
            message = Message()

            while line := await reader.readline():
                message.add_line(line.decode('ascii'))
                if message.parsed:
                    if message.is_event:
                        await self._handle_event(message)
                    else:
                        await rqueue.put(message)

                    message = Message()
        finally:
            self._connected = False
            with suppress(asyncio.QueueFull):
                rqueue.put_nowait(None)
            await self._notify_disconnect()

    async def _request(self, command: Command) -> Message:
        """Send any kind of command to the controller.

        A reply is dequeued and expected.
        """
        async with self._request_lock:
            # if self._rqueue is None or self._writer is None:
            if not self.connected:
                raise ControllerError('Controller is not connected!')

            # Casts are valid here since we check `self.connected`.
            rqueue = cast(asyncio.Queue[Message | None], self._rqueue)

            writer = cast(asyncio.StreamWriter, self._writer)
            writer.write(str(command).encode('ascii'))
            await writer.drain()

            resp = await rqueue.get()
            rqueue.task_done()

        if resp is None:  # pragma: no cover
            raise ControllerError('Controller has disconnected!')
        return resp

    async def auth_challenge(self, nonce: bytes | None = None) -> r.AuthChallengeReply:
        """Query Tor's controller so we perform a SAFECOOKIE authentication method.

        This method is not meant to be called directly but is used by `authenticate`
        when 'SAFECOOKIE' is the chosen authentication method.
        """
        query = q.AuthChallengeQuery(nonce)
        return await self.request(query)

    async def authenticate(self, password: str | None = None) -> r.AuthenticateReply:
        """Authenticate to Tor's controller.

        When no password is provided, cookie authentications are attempted.
        """
        protoinfo = await self.protocol_info()
        methods = set(protoinfo.methods)

        if password is None:
            methods.discard('HASHEDPASSWORD')

        # These methods are expose here by preference order.
        #   NULL            (no authentication, take it when available)
        #   HASHEDPASSWORD  (password authentication)
        #   SAFECOOKIE      (proof that we can read to cookie)
        #   COOKIE          (found a cookie, please take it)
        #
        # Here we suppose that the user prefers a password authentication when
        # a password is provided (the cookie file may not be readable!).
        if 'NULL' in methods:
            token_bytes = None  # type: bytes | None
        elif 'HASHEDPASSWORD' in methods:
            token_bytes = password.encode()  # type: ignore[union-attr]
        elif 'SAFECOOKIE' in methods:
            cookie = await protoinfo.cookie_file_read()
            if cookie is not None:
                challenge = await self.auth_challenge()
                challenge.raise_for_server_hash_error(cookie)
                token_bytes = challenge.client_token_build(cookie)
        elif 'COOKIE' in methods:
            token_bytes = await protoinfo.cookie_file_read()
        else:
            raise ControllerError('No compatible authentication method found!')

        token = token_bytes.hex() if token_bytes is not None else None
        query = q.AuthenticateQuery(token)
        reply = await self.request(query)
        self._authenticated = bool(reply.status == 250)
        return reply

    async def close(self) -> None:
        """Close this connection and reset the controller."""
        await self.__aexit__(None, None, None)

    async def connect(self) -> None:
        """Connect Tor's control socket."""
        await self.__aenter__()

    async def drop_guards(self) -> r.DropGuardsReply:
        """Send a 'DROPGUARDS' command to the controller."""
        return await self.request(q.DropGuardsQuery())

    async def event_subscribe(self, event: str, callback: EventCallbackType) -> None:
        """Register a callback to be called when `event` triggers."""
        async with self._events_lock:
            listeners = self._evt_callbacks.setdefault(event, [])
            try:
                if not listeners and event not in e.EVENTS_INTERNAL:
                    await self.set_events(self._evt_callbacks.keys())
                listeners.append(callback)
            except AiostemError:
                if not len(listeners):  # pragma: no branch
                    self._evt_callbacks.pop(event)
                raise

    async def event_unsubscribe(self, event: str, callback: EventCallbackType) -> None:
        """Unsubscribe `callable` from the event handler for `event`."""
        async with self._events_lock:
            listeners = self._evt_callbacks.get(event, [])
            if callback in listeners:
                backup_listeners = listeners.copy()
                listeners.remove(callback)

                try:
                    if not len(listeners):  # pragma: no branch
                        self._evt_callbacks.pop(event)
                        if event not in e.EVENTS_INTERNAL:
                            await self.set_events(self._evt_callbacks.keys())
                except AiostemError:  # pragma: no cover
                    self._evt_callbacks[event] = backup_listeners
                    raise

    async def get_conf(self, *args: str) -> r.GetConfReply:
        """Get configuration items from the remote server."""
        query = q.GetConfQuery(*args)
        return await self.request(query)

    async def get_info(self, *args: str) -> r.GetInfoReply:
        """Get information from the remote server."""
        query = q.GetInfoQuery(*args)
        return await self.request(query)

    async def hs_fetch(self, address: str, servers: list[str] | None = None) -> r.HsFetchReply:
        """Request a hidden service descriptor fetch.

        The result does not contain the descriptor, which is provided asynchronously
        through events (HS_DESC and HS_DESC_CONTENT).
        """
        if servers is None:
            servers = []
        address = hs_address_strip_tld(address.lower())
        query = q.HsFetchQuery(address, servers)
        return await self.request(query)

    async def protocol_info(
        self,
        version: int = DEFAULT_PROTOCOL_VERSION,
    ) -> r.ProtocolInfoReply:
        """Get control protocol information from the remote Tor process.

        Default version is 1, this is the only version supported by Tor.
        """
        if self.authenticated or not self._protoinfo:
            query = q.ProtocolInfoQuery(version)
            self._protoinfo = await self.request(query)
        return self._protoinfo

    @overload
    async def request(self, query: q.AuthenticateQuery) -> r.AuthenticateReply: ...

    @overload
    async def request(self, query: q.AuthChallengeQuery) -> r.AuthChallengeReply: ...

    @overload
    async def request(self, query: q.DropGuardsQuery) -> r.DropGuardsReply: ...

    @overload
    async def request(self, query: q.GetConfQuery) -> r.GetConfReply: ...

    @overload
    async def request(self, query: q.GetInfoQuery) -> r.GetInfoReply: ...

    @overload
    async def request(self, query: q.HsFetchQuery) -> r.HsFetchReply: ...

    @overload
    async def request(self, query: q.ProtocolInfoQuery) -> r.ProtocolInfoReply: ...

    @overload
    async def request(self, query: q.QuitQuery) -> r.QuitReply: ...

    @overload
    async def request(self, query: q.SetConfQuery) -> r.SetConfReply: ...

    @overload
    async def request(self, query: q.SetEventsQuery) -> r.SetEventsReply: ...

    @overload
    async def request(self, query: q.SignalQuery) -> r.SignalReply: ...

    async def request(self, query: q.Query) -> r.Reply:
        """Perform a provided `query` and returns the appropriate response."""
        message = await self._request(query.command)
        return r.reply_parser(query, message)

    async def set_conf(self, items: dict[str, Any]) -> r.SetConfReply:
        """Set configuration items to the remote server."""
        query = q.SetConfQuery(items)
        return await self.request(query)

    async def set_events(self, events: Iterable[str]) -> r.SetEventsReply:
        """Set the list of events that we subscribe to.

        This method should probably not be called directly, see event_subscribe.
        """
        # Remove internal events from the list in our request to the controller.
        events = set(events).difference(e.EVENTS_INTERNAL)
        query = q.SetEventsQuery(events)
        return await self.request(query)

    async def signal(self, signal: str) -> r.SignalReply:
        """Send a SIGNAL command to the controller."""
        return await self.request(q.SignalQuery(signal))

    async def quit(self) -> r.QuitReply:
        """Send a QUIT command to the controller."""
        return await self.request(q.QuitQuery())
