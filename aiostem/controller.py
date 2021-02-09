# -*- coding: utf-8 -*-

import asyncio

from types import TracebackType
from typing import Callable, Dict, Iterable, List, Optional, Type

import aiostem.event as e
import aiostem.question as q
import aiostem.response as r

from aiostem.command import Command
from aiostem.connector import (
    ControlConnector,
    ControlConnectorPath,
    ControlConnectorPort,
    DEFAULT_CONTROL_HOST,
    DEFAULT_CONTROL_PATH,
    DEFAULT_CONTROL_PORT,
)
from aiostem.exception import AiostemError, ControllerError
from aiostem.message import Message
from aiostem.util import hs_address_strip_tld


DEFAULT_PROTOCOL_VERSION = q.ProtocolInfoQuery.DEFAULT_PROTOCOL_VERSION


class Controller:
    """ Client controller for Tor's control socket.
    """

    def __init__(self, connector: ControlConnector) -> None:
        self._evt_callbacks = {}  # type: Dict[str, List[Callable]]
        self._request_lock = asyncio.Lock()
        self._events_lock = asyncio.Lock()
        self._authenticated = False
        self._connected = False
        self._connector = connector
        self._protoinfo = None    # type: Optional[r.ProtocolInfoReply]
        self._rqueue = None       # type: Optional[asyncio.Queue]
        self._rdtask = None       # type: Optional[asyncio.Task]
        self._writer = None       # type: Optional[asyncio.StreamWriter]

    @classmethod
    def from_port(cls, host: str = DEFAULT_CONTROL_HOST,
                  port: int = DEFAULT_CONTROL_PORT) -> 'Controller':
        """ Create a new Controller from a TCP port.
        """
        return cls(ControlConnectorPort(host, port))

    @classmethod
    def from_path(cls, path: str = DEFAULT_CONTROL_PATH) -> 'Controller':
        """ Create a new Controller from a UNIX socket path.
        """
        return cls(ControlConnectorPath(path))

    @property
    def authenticated(self) -> bool:
        """ Whether we are correctly authenticated.
        """
        return bool(self.connected and self._authenticated)

    @property
    def connected(self) -> bool:
        """ Whether we are connected to the remote socket.
        """
        return self._connected

    async def __aenter__(self) -> 'Controller':
        """ Enter Controller's context, connect to the target.
        """
        await self.connect()
        return self

    async def __aexit__(self, etype: Optional[Type[BaseException]],
                        evalue: Optional[BaseException],
                        traceback: Optional[TracebackType]) -> None:
        """ Exit Controller's context.
        """
        await self.close()

    async def _handle_event(self, message: Message) -> None:
        """ Handle the new received event (find and call the callbacks).
        """
        name = message.event_type
        event = e.event_parser(message)

        for callback in self._evt_callbacks.get(name, []):
            # We do not care about exceptions in the event callback.
            try:
                await callback(event)
            except Exception:
                pass

    async def _notify_disconnect(self) -> None:
        """ Generate a DISCONNECT event to tell everyone that we are now disconnected.
        """
        message = Message()
        message.add_line('650 DISCONNECT\r\n')
        await self._handle_event(message)

    async def _reader_task(self, reader: asyncio.StreamReader) -> None:
        """ Read from the socket and dispatch all contents.
        """
        try:
            message = Message()

            while True:
                line = await reader.readline()
                if not line:
                    break

                line = line.decode('ascii')
                message.add_line(line)
                if message.parsed:
                    if message.is_event:
                        await self._handle_event(message)
                    else:
                        await self._rqueue.put(message)
                    message = Message()
        finally:
            try:
                self._connected = False
                self._rqueue.put_nowait(None)
                await self._notify_disconnect()
            except asyncio.QueueFull:
                pass

    async def auth_challenge(self, nonce: Optional[bytes] = None) -> r.AuthChallengeReply:
        """ Query Tor's controller so we perform a SAFECOOKIE authentication method.

            This method is not meant to be called directly but is used by `authenticate`
            when 'SAFECOOKIE' is the chosen authentication method.
        """
        query = q.AuthChallengeQuery(nonce)
        return await self.request(query)

    async def authenticate(self, password: Optional[str] = None) -> r.AuthenticateReply:
        """ Authenticate to Tor's controller.
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
            token = None
        elif 'HASHEDPASSWORD' in methods:
            token = password.encode()
        elif 'SAFECOOKIE' in methods:
            cookie = await protoinfo.cookie_file_read()
            challenge = await self.auth_challenge()
            challenge.raise_for_server_hash_error(cookie)
            token = challenge.client_token_build(cookie)
        elif 'COOKIE' in methods:
            token = await protoinfo.cookie_file_read()
        else:
            raise ControllerError("No compatible authentication method found!")

        if token is not None:
            token = token.hex()
        query = q.AuthenticateQuery(token)
        reply = await self.request(query)
        self._authenticated = bool(reply.status == 250)
        return reply

    async def hs_fetch(self, address: str, servers: List[str] = []) -> r.HsFetchReply:
        """ Request a hidden service descriptor fetch.

            The result does not contain the descriptor, which is provided asynchronously
            through events (HS_DESC and HS_DESC_CONTENT).
        """
        address = hs_address_strip_tld(address.lower())
        query = q.HsFetchQuery(address, servers)
        return await self.request(query)

    async def request_command(self, command: Command) -> Message:
        """ Send any kind of command to the controller.
            A reply is dequeued and expected.
        """
        async with self._request_lock:
            if not self.connected:
                raise ControllerError("Controller is not connected!")

            payload = str(command).encode('ascii')
            self._writer.write(payload)
            await self._writer.drain()

            rep = await self._rqueue.get()

        self._rqueue.task_done()
        if rep is None:
            raise ControllerError("Controller has disconnected!")
        return rep

    async def request(self, query: q.Query) -> r.Reply:
        """ Perform a provided `query` and returns the appropriate response.
        """
        message = await self.request_command(query.command)
        return r.reply_parser(query, message)

    async def close(self) -> None:
        """ Close this connection and reset the controller.
        """
        writer = self._writer
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except BrokenPipeError:
                pass  # can arise while closing underlying UNIX socket
        self._writer = None

        rdtask = self._rdtask
        if rdtask is not None:
            rdtask.cancel()
            try:
                await rdtask
            except asyncio.CancelledError:
                pass
        self._rdtask = None

        self._evt_callbacks = {}
        self._authenticated = False
        self._connected = False
        self._protoinfo = None
        self._rqueue = None

    async def connect(self) -> None:
        """ Connect Tor's control socket.
        """
        reader, writer = await self._connector.connect()
        rqueue = asyncio.Queue()
        rdtask = asyncio.create_task(self._reader_task(reader))

        self._connected = True
        self._rqueue = rqueue
        self._rdtask = rdtask
        self._writer = writer

    async def set_events(self, events: Iterable[str], extended: bool = False) -> r.SetEventsReply:
        """ Set the list of events that we subscribe to.
            This method should probably not be called directly, see event_subscribe.
        """
        # Remove internal events from the list in our request to the controller.
        events = set(events).difference(e.EVENTS_INTERNAL)
        query = q.SetEventsQuery(events, extended)
        return await self.request(query)

    async def event_subscribe(self, event: str, callback: Callable) -> None:
        """ Register a callback to be called when `event` triggers.
        """
        async with self._events_lock:
            listeners = self._evt_callbacks.setdefault(event, [])
            try:
                if not listeners and event not in e.EVENTS_INTERNAL:
                    await self.set_events(self._evt_callbacks.keys())
                listeners.append(callback)
            except AiostemError:
                if not len(listeners):
                    self._evt_callbacks.pop(event)
                raise

    async def event_unsubscribe(self, event: str, callback: Callable) -> None:
        """ Unsubscribe `callable` from the event handler for `event`.
        """
        async with self._events_lock:
            listeners = self._evt_callbacks.get(event, [])
            if callback in listeners:
                backup_listeners = listeners.copy()
                listeners.remove(callback)

                try:
                    if not len(listeners):
                        self._evt_callbacks.pop(event)
                        if event not in e.EVENTS_INTERNAL:
                            await self.set_events(self._evt_callbacks.keys())
                except AiostemError:
                    self._evt_callbacks[event] = backup_listeners
                    raise

    async def protocol_info(self, version: int = DEFAULT_PROTOCOL_VERSION) -> r.ProtocolInfoReply:
        """ Get control protocol information from the remote Tor process.
            Default version is 1, this is the only version supported by Tor.
        """
        if self.authenticated or not self._protoinfo:
            query = q.ProtocolInfoQuery(version)
            self._protoinfo = await self.request(query)
        return self._protoinfo

    async def signal(self, signal: str) -> r.SignalReply:
        """ Send a SIGNAL command to the controller.
        """
        return await self.request(q.SignalQuery(signal))

    async def quit(self) -> r.QuitReply:
        """ Send a QUIT command to the controller.
        """
        return await self.request(q.QuitQuery())
# End of class Controller.
