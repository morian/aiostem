# -*- coding: utf-8 -*-

import asyncio

from types import TracebackType
from typing import Optional, Tuple, Type


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

    def __init__(self, address: str = '127.0.0.1', port: int = 9051) -> None:
        self._address = address
        self._port = port

    @property
    def address(self) -> str:
        """ IP address to Tor's control port.
        """
        return self._address

    @property
    def port(self) -> int:
        """ TCP port used to join this control port.
        """
        return self._port

    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """ Connect this socket asynchronously.
        """
        return await asyncio.open_connection(self.address, self.port)
# End of class ControlConnectorPort.


class ControlConnectorFile(ControlConnector):
    """ Control socket based on a local UNIX path.
    """

    def __init__(self, path: str = '/var/run/tor/control') -> None:
        self._path = path

    def path(self) -> str:
        """ Get the path provided to connect to Tor's control port.
        """
        return self._path

    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """ Connect this socket asynchronously.
        """
        return await asyncio.open_unix_connection(self.path)
# End of class ControlConnectorFile.


class Controller:
    """ Client controller for Tor's control socket.
    """

    def __init__(self, connector: ControlConnector) -> None:
        self._connector = connector
        self._reader = None
        self._writer = None

    async def __aenter__(self) -> 'Controller':
        await self.connect()
        return self

    async def __aexit__(self, etype: Optional[Type[BaseException]],
                        evalue: Optional[BaseException],
                        traceback: Optional[TracebackType]) -> None:
        await self.close()

    async def connect(self) -> None:
        """ Connect to the real socket.
        """
        reader, writer = await self._connector.connect()
        self._reader = reader
        self._writer = writer

    async def close(self) -> None:
        """ Close this connection and reset the controller.
        """
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except BrokenPipeError:
                pass

        self._reader = None
        self._writer = None
# End of class Controller
