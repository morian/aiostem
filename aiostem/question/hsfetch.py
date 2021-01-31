# -*- coding: utf-8 -*-

from aiostem.command import Command
from aiostem.question.base import Query
from typing import List


class HsFetchQuery(Query):
    """ Build a Hidden service fetch query.
    """

    COMMAND_NAME: str = 'HSFETCH'

    def __init__(self, address: str, servers: List[str] = []) -> None:
        self._address = address
        self._servers = servers

    @property
    def command(self) -> Command:
        """ Build the real command that will be sent.
        """
        cmd = Command(self.COMMAND_NAME)
        cmd.add_arg(self.address)
        for server in self.servers:
            cmd.add_kwarg('SERVER', server)
        return cmd

    @property
    def address(self) -> str:
        """ Address of the onion domain to look for.
              v2 addresses are 16 x base32 characters
              v3 addresses are 56 x base32 characters

            Additionally, this can also be in format `v2-descid`.
        """
        return self._address

    @property
    def servers(self) -> List[str]:
        """ List of servers to request for this address.
        """
        return self._servers
# End of class HsFetchQuery.
