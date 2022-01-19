from aiostem.command import Command
from aiostem.question.base import Query


class ProtocolInfoQuery(Query):
    """Create a query for the protocol info command."""

    COMMAND_NAME: str = 'PROTOCOLINFO'
    DEFAULT_PROTOCOL_VERSION: int = 1

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
