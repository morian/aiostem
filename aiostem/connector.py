from __future__ import annotations

import asyncio
from abc import abstractmethod

DEFAULT_CONTROL_PATH: str = '/var/run/tor/control'
DEFAULT_CONTROL_HOST: str = '127.0.0.1'
DEFAULT_CONTROL_PORT: int = 9051


class ControlConnector:
    """
    Base class for all connector types used by the controller.

    These are simply helper classes providing a pair of :class:`asyncio.StreamReader`
    and :class:`asyncio.StreamWriter` needed to perform actions on the target control
    port.

    """

    @abstractmethod
    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Open an asynchronous connection to the target control port.

        Returns:
            A tuple of :class:`asyncio.StreamReader` and :class:`asyncio.StreamWriter`.

        """


class ControlConnectorPort(ControlConnector):
    """Tor connector using a local or report TCP port."""

    def __init__(
        self,
        host: str = DEFAULT_CONTROL_HOST,
        port: int = DEFAULT_CONTROL_PORT,
    ) -> None:
        """
        Create a controller connector using a TCP host and port.

        Args:
            host: ip address or hostname to the control host
            port: TCP port to connect to

        """
        self._host = host
        self._port = port

    @property
    def host(self) -> str:
        """IP address or host name to Tor's control port."""
        return self._host

    @property
    def port(self) -> int:
        """TCP port used to reach the control port."""
        return self._port

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Open an asynchronous connection to the target's TCP port.

        Returns:
            A tuple of :class:`asyncio.StreamReader` and :class:`asyncio.StreamWriter`.

        """
        return await asyncio.open_connection(self.host, self.port)


class ControlConnectorPath(ControlConnector):
    """Tor connector using a local unix socket."""

    def __init__(self, path: str = DEFAULT_CONTROL_PATH) -> None:
        """
        Create a controller connector using a local unix socket.

        Args:
            path: path to the unix socket on the local filesystem

        """
        self._path = path

    @property
    def path(self) -> str:
        """Get the path to the local unix socket to Tor's control port."""
        return self._path

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Open an asynchronous connection to the target unix socket.

        Returns:
            A tuple of :class:`asyncio.StreamReader` and :class:`asyncio.StreamWriter`.

        """
        return await asyncio.open_unix_connection(self.path)
