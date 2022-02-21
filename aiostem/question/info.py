from __future__ import annotations

from typing import ClassVar

from aiostem.command import Command
from aiostem.question.base import Query


class BaseInfoQuery(Query):
    """Any kind of query like GETCONF or GETINFO."""

    def __init__(self, *args: str) -> None:
        """Build a GETINFO query."""
        self._keys = args

    def __repr__(self) -> str:
        """Representation of this query."""
        return '<{} {}>'.format(self.COMMAND_NAME, ' '.join(self.keys))

    @property
    def command(self) -> Command:
        """Build a command that is suitable to transmit over the control socket."""
        cmd = Command(self.COMMAND_NAME)
        for key in self.keys:
            cmd.add_arg(key)
        return cmd

    @property
    def keys(self) -> tuple[str, ...]:
        """List of keys requested in this command."""
        return self._keys


class GetConfQuery(BaseInfoQuery):
    """Create a query to get any kind of server configuration item."""

    COMMAND_NAME: ClassVar[str] = 'GETCONF'


class GetInfoQuery(BaseInfoQuery):
    """Create a query to get any kind of server information."""

    COMMAND_NAME: ClassVar[str] = 'GETINFO'


class ProtocolInfoQuery(Query):
    """Create a query for the protocol info command."""

    COMMAND_NAME: ClassVar[str] = 'PROTOCOLINFO'
    DEFAULT_PROTOCOL_VERSION: ClassVar[int] = 1

    def __init__(self, version: int = DEFAULT_PROTOCOL_VERSION) -> None:
        """Build a PROTOCOLINFO query."""
        self._version = version

    def __repr__(self) -> str:
        """Representation of this query."""
        return "<{} version='{}'>".format(self.COMMAND_NAME, self.version)

    @property
    def command(self) -> Command:
        """Convert this query object to a command suitable for `Controller.request()`."""
        cmd = Command(self.COMMAND_NAME)
        cmd.add_arg(str(self.version))
        return cmd

    @property
    def version(self) -> int:
        """Protocol info version requested."""
        return self._version
