from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from ..command import Command
from .base import Query

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class HsFetchQuery(Query):
    """Build a Hidden service fetch query."""

    COMMAND_NAME: ClassVar[str] = 'HSFETCH'

    def __init__(self, address: str, servers: Iterable[str] | None = None) -> None:
        """Initialize a new HSFETCH query."""
        if servers is None:
            servers = []
        self._address = address
        self._servers = servers

    @property
    def command(self) -> Command:
        """Build the real command that will be used."""
        cmd = Command(self.COMMAND_NAME)
        cmd.add_arg(self._address)
        for server in self._servers:
            cmd.add_kwarg('SERVER', server)
        return cmd

    @property
    def address(self) -> str:
        """
        Address of the onion domain to look for.

        v2 addresses are 16 x base32 characters
        v3 addresses are 56 x base32 characters
        Additionally, this can also be in format `v2-descid`.
        """
        return self._address

    @property
    def servers(self) -> Sequence[str]:
        """List of servers to request for this address."""
        return list(self._servers)
