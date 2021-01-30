# -*- coding: utf-8 -*-

import asyncio

from types import TracebackType
from typing import Optional, Type

from aiostem.command import Command
from aiostem.connector import (
    ControlConnector,
    ControlConnectorPath,
    ControlConnectorPort,
    DEFAULT_CONTROL_HOST,
    DEFAULT_CONTROL_PATH,
    DEFAULT_CONTROL_PORT,
)
from aiostem.exception import ControllerError
from aiostem.message import Message
from aiostem.question import AuthChallengeQuery, AuthenticateQuery, ProtocolInfoQuery, QuitQuery
from aiostem.response import AuthChallengeReply, AuthenticateReply, ProtocolInfoReply, QuitReply


DEFAULT_PROTOCOL_VERSION = ProtocolInfoQuery.DEFAULT_PROTOCOL_VERSION


class Controller:
    """ Client controller for Tor's control socket.
    """

    def __init__(self, connector: ControlConnector) -> None:
        self._request_lock = asyncio.Lock()
        self._authenticated = False
        self._connected = False
        self._connector = connector
        self._protoinfo = None  # type: Optional[ProtocolInfoReply]
        self._rqueue = None     # type: Optional[asyncio.Queue]
        self._rdtask = None     # type: Optional[asyncio.Task]
        self._writer = None     # type: Optional[asyncio.StreamWriter]

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

    async def _reader_task(self, reader) -> None:
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
                        print("READER: skipping event message")
                    else:
                        await self._rqueue.put(message)
                    message = Message()
        finally:
            try:
                self._connected = False
                self._rqueue.put_nowait(None)
            except asyncio.QueueFull:
                pass

    async def auth_challenge(self, nonce: Optional[bytes] = None) -> AuthChallengeReply:
        """ Query Tor's controller so we perform a SAFECOOKIE authentication method.
        """
        query = AuthChallengeQuery(nonce)
        message = await self.request(query.command)
        return AuthChallengeReply(query, message)

    async def authenticate(self, password: Optional[str] = None) -> AuthenticateReply:
        """ Authenticate to Tor's controller.
            When no password is provided, cookie authentications are attempted.
        """
        protoinfo = await self.protocol_info()
        methods = set(protoinfo.methods)

        if password is None:
            methods.discard('HASHEDPASSWORD')

        # These methods are expose here by preference order.
        #   NULL            (no authentication, take it when available)
        #   SAFECOOKIE      (proof that we can read to cookie)
        #   COOKIE          (found a cookie, please take it)
        #   HASHEDPASSWORD  (password authentication)
        if 'NULL' in methods:
            token = None
        elif 'SAFECOOKIE' in methods:
            cookie = await protoinfo.cookie_file_read()
            challenge = await self.auth_challenge()
            challenge.raise_for_server_hash_error(cookie)
            token = challenge.client_token_build(cookie)
        elif 'COOKIE' in methods:
            token = await protoinfo.cookie_file_read()
        elif 'HASHEDPASSWORD' in methods:
            token = password.encode()
        else:
            raise ControllerError("No compatible authentication method found!")

        if token is not None:
            token = token.hex()
        query = AuthenticateQuery(token)
        message = await self.request(query.command)
        return AuthenticateReply(query, message)

    async def request(self, command: Command) -> Message:
        """ Send any kind of command to the controller.
            A reply is dequeued and expected.
        """
        if not self.connected:
            raise ControllerError("Controller is not connected!")

        async with self._request_lock:
            payload = str(command).encode('ascii')
            self._writer.write(payload)
            await self._writer.drain()

            rep = await self._rqueue.get()

        self._rqueue.task_done()
        if rep is None:
            raise ControllerError("Controller has disconnected!")
        return rep

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

        self._authenticated = False
        self._connected = False
        self._protoinfo = None
        self._rdtask = None
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

    async def protocol_info(self, version: int = DEFAULT_PROTOCOL_VERSION) -> ProtocolInfoReply:
        """ Get control protocol information from the remote Tor process.
            Default version is 1, this is the only version supported by Tor.
        """
        if self.authenticated or not self._protoinfo:
            query = ProtocolInfoQuery(version)
            message = await self.request(query.command)
            self._protoinfo = ProtocolInfoReply(query, message)
        return self._protoinfo

    async def quit(self) -> None:
        """ Send a QUIT command to the controller.
        """
        query = QuitQuery()
        message = await self.request(query.command)
        return QuitReply(query, message)
# End of class Controller.
