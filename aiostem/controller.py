# -*- coding: utf-8 -*-

import asyncio

from types import TracebackType
from typing import Optional, Tuple, Type


DEFAULT_CONTROL_PATH: str = '/var/run/tor/control'
DEFAULT_CONTROL_HOST: str = '127.0.0.1'
DEFAULT_CONTROL_PORT: int = 9051


class ControlConnector:
    """ Common class for all socket types used by the controller.
    """

    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """ Connect this socket asynchronously.
        """
        raise NotImplementedError('connect() must be implemented by the ControlConnector subclass')
# End of class ControlConnector.


class ControlConnectorPort(ControlConnector):
    """ Control socket based on a local or remote TCP port.
    """

    def __init__(self, host: str = DEFAULT_CONTROL_HOST, port: int = DEFAULT_CONTROL_PORT) -> None:
        self._host = host
        self._port = port

    @property
    def host(self) -> str:
        """ IP address to Tor's control port.
        """
        return self._host

    @property
    def port(self) -> int:
        """ TCP port used to join this control port.
        """
        return self._port

    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """ Connect this socket asynchronously.
        """
        return await asyncio.open_connection(self.host, self.port)
# End of class ControlConnectorPort.


class ControlConnectorPath(ControlConnector):
    """ Control socket based on a local UNIX path.
    """

    def __init__(self, path: str = DEFAULT_CONTROL_PATH) -> None:
        self._path = path

    def path(self) -> str:
        """ Get the path provided to connect to Tor's control port.
        """
        return self._path

    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """ Connect this socket asynchronously.
        """
        return await asyncio.open_unix_connection(self.path)
# End of class ControlConnectorPath.


class Controller:
    """ Client controller for Tor's control socket.
    """

    def __init__(self, connector: ControlConnector) -> None:
        self._request_lock = asyncio.Lock()
        self._connector = connector
        self._replies = asyncio.Queue()
        self._rdtask = None  # type: Optional[asyncio.Task]
        self._writer = None  # type: Optional[asyncio.StreamWriter]

    @classmethod
    def from_port(cls, host: str = DEFAULT_CONTROL_HOST,
                  port: int = DEFAULT_CONTROL_PORT) -> 'Controller':
        """ Create a new Controller from a TCP port.
        """
        connector = ControlConnectorPort(host, port)
        return cls(connector)

    @classmethod
    def from_path(cls, path: str = DEFAULT_CONTROL_PATH) -> 'Controller':
        """ Create a new Controller from a UNIX socket path.
        """
        connector = ControlConnectorPath(path)
        return cls(connector)

    @property
    def connected(self) -> bool:
        """ Whether we are connected to the remote socket.
        """
        return self._rdtask.done()

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

    async def _reader_main(self, reader):
        """ Read from the socket and dispatch all contents.
        """
        while True:
            line = await reader.readline()
            if not len(line):
                print("READER: EOF!")
                break
            print("READER: " + line.decode())

    async def connect(self) -> None:
        """ Connect Tor's control socket.
        """
        reader, writer = await self._connector.connect()
        rdtask = asyncio.create_task(self._reader_main(reader))
        self._rdtask = rdtask
        self._writer = writer

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
# End of class Controller.
