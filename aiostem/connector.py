# -*- coding: utf-8 -*-

import asyncio

from typing import Tuple


DEFAULT_CONTROL_PATH: str = '/var/run/tor/control'
DEFAULT_CONTROL_HOST: str = '127.0.0.1'
DEFAULT_CONTROL_PORT: int = 9051


class ControlConnector:
    """ Common class for all socket types used by the controller.
    """

    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """ Connect this socket asynchronously.
        """
        raise NotImplementedError('connect() must be implemented by ControlConnector subclass')
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
