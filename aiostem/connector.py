from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod

#: Default path when connecting to a controller through an UNIX socket.
DEFAULT_CONTROL_PATH: str = '/var/run/tor/control'
#: Default host value when connecting to a TCP controller.
DEFAULT_CONTROL_HOST: str = '127.0.0.1'
#: Default port value when connecting to a TCP controller.
DEFAULT_CONTROL_PORT: int = 9051


class ControlConnector(ABC):
    """
    Base class for all connector types used by the controller.

    These are simply helper classes providing a pair of reader and writer needed
    to perform actions on the target control port.

    """

    @abstractmethod
    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Open an asynchronous connection to the target control port.

        Returns:
            A tuple forming a full-duplex asyncio stream.

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

        Hint:
            Use :meth:`.Controller.from_port` for an automated use of this class.

        Args:
            host: IP address or hostname to the control host.
            port: TCP port to connect to.

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
            A tuple forming a full-duplex asyncio stream.

        """
        return await asyncio.open_connection(self.host, self.port)


class ControlConnectorPath(ControlConnector):
    """Tor connector using a local unix socket."""

    def __init__(self, path: str = DEFAULT_CONTROL_PATH) -> None:
        """
        Create a controller connector using a local unix socket.

        Hint:
            Use :meth:`.Controller.from_path` for an automated use of this class.

        Args:
            path: Path to the unix socket on the local file system.

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
            A tuple forming a full-duplex asyncio stream.

        """
        return await asyncio.open_unix_connection(self.path)
